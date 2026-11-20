//! The SQLite-backed store.

use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use async_trait::async_trait;
use rune_vectorstore::{Filter, Hit, Metric, Options, Query, Record, StoreError, VectorStore};
use rusqlite::{
    Connection, OpenFlags, OptionalExtension, Transaction, TransactionBehavior, params,
};
use serde_json::Value;

use crate::check::{self, Candidate, TopK};
use crate::filter::{self, Param};

/// Name of the table that records each collection's metric and dimension.
const COLLECTIONS: &str = "rune_vectorstore_collections";

/// Configuration for [`SqliteVectorStore`].
///
/// # Example
///
/// ```
/// use rune_vectorstore::Metric;
/// use rune_vectorstore_sqlite::SqliteConfig;
///
/// let config = SqliteConfig::new("docs")
///     .with_metric(Metric::DotProduct)
///     .with_dimension(384)
///     .with_read_connections(2);
/// assert_eq!(config.table, "docs");
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct SqliteConfig {
    /// Table holding the records. An identifier: ASCII letters, digits and
    /// `_`, not starting with a digit, at most 63 bytes, not `sqlite_*`.
    pub table: String,
    /// Similarity metric. Default [`Metric::Cosine`].
    pub metric: Metric,
    /// Required vector dimension; `None` fixes it on the first insert.
    pub dimension: Option<usize>,
    /// Extra read-only connections for queries on a file database, so reads
    /// run in parallel with each other and with writes (WAL). Default 4.
    /// In-memory databases always use the single writer connection.
    pub read_connections: usize,
    /// Rows read per step of an exact scan. Default 4096.
    pub scan_chunk_rows: usize,
    /// How long to wait on a lock held by another connection. Default 5 s.
    pub busy_timeout: Duration,
}

impl SqliteConfig {
    /// Default configuration for `table`.
    #[must_use]
    pub fn new(table: impl Into<String>) -> Self {
        Self {
            table: table.into(),
            metric: Metric::Cosine,
            dimension: None,
            read_connections: 4,
            scan_chunk_rows: 4096,
            busy_timeout: Duration::from_secs(5),
        }
    }

    /// Take the metric and dimension from in-memory store [`Options`]. The
    /// index kind is ignored: search here is always exact.
    #[must_use]
    pub const fn with_options(mut self, options: &Options) -> Self {
        self.metric = options.metric;
        self.dimension = options.dimension;
        self
    }

    /// Set the metric.
    #[must_use]
    pub const fn with_metric(mut self, metric: Metric) -> Self {
        self.metric = metric;
        self
    }

    /// Require vectors of this dimension.
    #[must_use]
    pub const fn with_dimension(mut self, dimension: usize) -> Self {
        self.dimension = Some(dimension);
        self
    }

    /// Set the number of read-only query connections.
    #[must_use]
    pub const fn with_read_connections(mut self, n: usize) -> Self {
        self.read_connections = n;
        self
    }

    /// Set the rows read per scan step (at least 1).
    #[must_use]
    pub const fn with_scan_chunk_rows(mut self, rows: usize) -> Self {
        self.scan_chunk_rows = rows;
        self
    }

    /// Set the busy timeout.
    #[must_use]
    pub const fn with_busy_timeout(mut self, timeout: Duration) -> Self {
        self.busy_timeout = timeout;
        self
    }
}

/// Check that `name` is a plain SQL identifier, safe to quote into SQL.
pub fn check_identifier(name: &str) -> Result<(), StoreError> {
    let mut chars = name.chars();
    let ok = name.len() <= 63
        && chars
            .next()
            .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
        && !name.to_ascii_lowercase().starts_with("sqlite_")
        && !name.eq_ignore_ascii_case(COLLECTIONS);
    if ok {
        Ok(())
    } else {
        Err(StoreError::Backend(
            "table name must be a plain identifier: ASCII letters, digits and '_', \
             not starting with a digit, at most 63 bytes, not reserved"
                .into(),
        ))
    }
}

/// An embedded, single-file [`VectorStore`] on SQLite.
///
/// Records live in one table (`pk`, `id`, `vector` as a little-endian `f32`
/// BLOB, `norm`, `content`, `metadata` as JSON text). Search is exact: a
/// streaming scan scores every row passing the metadata pre-filter and keeps
/// the best `top_k` in a bounded heap, so memory is `O(top_k + dimension)`
/// whatever the table size. Results, scores and filter semantics match
/// [`InMemoryVectorStore`](rune_vectorstore::InMemoryVectorStore) with a
/// flat index.
///
/// # Scale
///
/// Every query reads every row, so cost grows linearly: about 80 ms per
/// 100 000 vectors of 384 dimensions on one core in a release build, and
/// proportionally more for larger vectors. A metadata filter saves the
/// scoring but not the read, so it barely helps. That is comfortable up to
/// a few hundred thousand records at modest query rates; beyond that, use
/// an approximate index (pgvector, Qdrant, or the in-memory HNSW).
///
/// # Concurrency
///
/// The database runs in WAL mode. Writes go through one connection; file
/// databases get [`SqliteConfig::read_connections`] read-only connections,
/// so queries run in parallel with each other and with writes. With the
/// `tokio` feature (on by default) blocking work runs on tokio's blocking
/// pool when called inside a tokio runtime; elsewhere it runs inline.
///
/// # Example
///
/// ```
/// use rune_vectorstore::{Filter, Query, Record, VectorStore};
/// use rune_vectorstore_sqlite::{SqliteConfig, SqliteVectorStore};
///
/// # tokio_test::block_on(async {
/// let store = SqliteVectorStore::open_in_memory(SqliteConfig::new("docs"))?;
/// store.upsert(vec![
///     Record::new("fr", vec![1.0, 0.0]).with_content("Paris").with_meta("lang", "fr"),
///     Record::new("de", vec![0.0, 1.0]).with_content("Berlin").with_meta("lang", "de"),
/// ]).await?;
///
/// let hits = store.query(&Query::new(vec![0.9, 0.2], 1)).await?;
/// assert_eq!(hits[0].record.content, "Paris");
///
/// let german = Query::new(vec![0.9, 0.2], 1).with_filter(Filter::eq("lang", "de"));
/// assert_eq!(store.query(&german).await?[0].record.content, "Berlin");
/// # Ok::<(), rune_vectorstore::StoreError>(())
/// # }).unwrap();
/// ```
#[derive(Clone)]
pub struct SqliteVectorStore {
    inner: Arc<Inner>,
}

impl std::fmt::Debug for SqliteVectorStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SqliteVectorStore")
            .field("table", &self.inner.table)
            .field("metric", &self.inner.metric)
            .finish_non_exhaustive()
    }
}

struct Inner {
    table: String,
    metric: Metric,
    /// Cached dimension; 0 while unset. Once set it never changes.
    dimension: AtomicUsize,
    chunk: usize,
    writer: Mutex<Connection>,
    readers: Vec<Mutex<Connection>>,
    next_reader: AtomicUsize,
    sql: Statements,
}

/// SQL text with the (validated) table name filled in.
struct Statements {
    upsert: String,
    delete: String,
    get: String,
    by_pk: String,
    count: String,
    clear: String,
    scan_head: String,
    table: String,
}

impl Statements {
    fn new(table: &str) -> Self {
        let t = format!("\"{table}\"");
        Self {
            upsert: format!(
                "INSERT INTO {t} (id, vector, norm, content, metadata) VALUES (?1, ?2, ?3, ?4, ?5) \
                 ON CONFLICT(id) DO UPDATE SET vector = excluded.vector, norm = excluded.norm, \
                 content = excluded.content, metadata = excluded.metadata"
            ),
            delete: format!("DELETE FROM {t} WHERE id = ?1"),
            get: format!("SELECT id, vector, content, metadata FROM {t} WHERE id = ?1"),
            by_pk: format!("SELECT id, vector, content, metadata FROM {t} WHERE pk = ?1"),
            count: format!("SELECT count(*) FROM {t}"),
            clear: format!("DELETE FROM {t}"),
            scan_head: format!("SELECT pk, id, vector, norm, metadata FROM {t} WHERE pk > ?1 AND "),
            table: t,
        }
    }
}

fn backend(e: &rusqlite::Error) -> StoreError {
    StoreError::Backend(format!("sqlite: {e}"))
}

fn lock(m: &Mutex<Connection>) -> Result<MutexGuard<'_, Connection>, StoreError> {
    m.lock().map_err(|_| StoreError::Poisoned)
}

const fn metric_name(m: Metric) -> &'static str {
    match m {
        Metric::Cosine => "cosine",
        Metric::DotProduct => "dot",
        _ => "l2",
    }
}

fn to_dim(stored: Option<i64>) -> Result<Option<usize>, StoreError> {
    stored
        .map(|d| usize::try_from(d).ok().filter(|&d| d > 0))
        .map(|d| d.ok_or_else(|| StoreError::Backend("stored dimension is invalid".into())))
        .transpose()
}

impl SqliteVectorStore {
    /// Open (or create) a database file and the collection `config.table`.
    ///
    /// # Errors
    ///
    /// [`StoreError::Backend`] for an invalid table name, an unopenable
    /// file, or a collection created earlier with another metric;
    /// [`StoreError::DimensionMismatch`] if it was created with another
    /// dimension.
    pub fn open(path: impl AsRef<Path>, config: SqliteConfig) -> Result<Self, StoreError> {
        let path = path.as_ref();
        check_identifier(&config.table)?;
        let writer = Connection::open(path).map_err(|e| backend(&e))?;
        Self::setup(&writer, &config, true)?;
        let mut readers = Vec::with_capacity(config.read_connections);
        for _ in 0..config.read_connections {
            let flags = OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX;
            let reader = Connection::open_with_flags(path, flags).map_err(|e| backend(&e))?;
            Self::setup(&reader, &config, false)?;
            readers.push(Mutex::new(reader));
        }
        Self::finish(writer, readers, config)
    }

    /// Create a private in-memory database (for tests and scratch work).
    ///
    /// # Errors
    ///
    /// As for [`open`](Self::open).
    pub fn open_in_memory(config: SqliteConfig) -> Result<Self, StoreError> {
        check_identifier(&config.table)?;
        let writer = Connection::open_in_memory().map_err(|e| backend(&e))?;
        Self::setup(&writer, &config, true)?;
        Self::finish(writer, Vec::new(), config)
    }

    fn setup(conn: &Connection, config: &SqliteConfig, write: bool) -> Result<(), StoreError> {
        conn.busy_timeout(config.busy_timeout)
            .map_err(|e| backend(&e))?;
        // Do not run SQL functions or virtual tables from views, triggers or
        // defaults planted in an untrusted database file.
        conn.pragma_update(None, "trusted_schema", "OFF")
            .map_err(|e| backend(&e))?;
        if !write {
            return Ok(());
        }
        // `journal_mode` reports the resulting mode (memory for :memory:).
        let _: String = conn
            .query_row("PRAGMA journal_mode = WAL", [], |r| r.get(0))
            .map_err(|e| backend(&e))?;
        conn.pragma_update(None, "synchronous", "NORMAL")
            .map_err(|e| backend(&e))?;
        let t = format!("\"{}\"", config.table);
        conn.execute_batch(&format!(
            "CREATE TABLE IF NOT EXISTS {COLLECTIONS} (
                 name TEXT PRIMARY KEY NOT NULL,
                 metric TEXT NOT NULL,
                 dimension INTEGER
             );
             CREATE TABLE IF NOT EXISTS {t} (
                 pk INTEGER PRIMARY KEY,
                 id TEXT NOT NULL UNIQUE,
                 vector BLOB NOT NULL,
                 norm REAL NOT NULL,
                 content TEXT NOT NULL,
                 metadata TEXT NOT NULL
             );"
        ))
        .map_err(|e| backend(&e))?;
        let dim = config
            .dimension
            .map(i64::try_from)
            .transpose()
            .map_err(|_| StoreError::Backend("dimension does not fit a SQLite integer".into()))?;
        conn.execute(
            &format!(
                "INSERT OR IGNORE INTO {COLLECTIONS} (name, metric, dimension) VALUES (?1, ?2, ?3)"
            ),
            params![config.table, metric_name(config.metric), dim],
        )
        .map_err(|e| backend(&e))?;
        let (metric, stored): (String, Option<i64>) = conn
            .query_row(
                &format!("SELECT metric, dimension FROM {COLLECTIONS} WHERE name = ?1"),
                [&config.table],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .map_err(|e| backend(&e))?;
        if metric != metric_name(config.metric) {
            return Err(StoreError::Backend(format!(
                "collection was created with the {metric} metric, not {}",
                metric_name(config.metric)
            )));
        }
        match (to_dim(stored)?, config.dimension) {
            (Some(have), Some(want)) if have != want => Err(StoreError::DimensionMismatch {
                expected: have,
                actual: want,
            }),
            (None, Some(_)) => conn
                .execute(
                    &format!("UPDATE {COLLECTIONS} SET dimension = ?2 WHERE name = ?1"),
                    params![config.table, dim],
                )
                .map(drop)
                .map_err(|e| backend(&e)),
            _ => Ok(()),
        }
    }

    fn finish(
        writer: Connection,
        readers: Vec<Mutex<Connection>>,
        config: SqliteConfig,
    ) -> Result<Self, StoreError> {
        let inner = Inner {
            sql: Statements::new(&config.table),
            table: config.table,
            metric: config.metric,
            dimension: AtomicUsize::new(0),
            chunk: config.scan_chunk_rows.clamp(1, 1 << 20),
            writer: Mutex::new(writer),
            readers,
            next_reader: AtomicUsize::new(0),
        };
        let conn = lock(&inner.writer)?;
        let dim = inner.load_dimension(&conn)?;
        drop(conn);
        inner.dimension.store(dim.unwrap_or(0), Ordering::Relaxed);
        Ok(Self {
            inner: Arc::new(inner),
        })
    }

    /// The store's metric.
    #[must_use]
    pub fn metric(&self) -> Metric {
        self.inner.metric
    }

    /// The table name.
    #[must_use]
    pub fn table(&self) -> &str {
        &self.inner.table
    }

    /// The vector dimension, once fixed by the config or the first insert.
    #[must_use]
    pub fn dimension(&self) -> Option<usize> {
        match self.inner.dimension.load(Ordering::Relaxed) {
            0 => None,
            d => Some(d),
        }
    }

    /// Remove every record matching `filter`; returns how many were removed.
    ///
    /// # Errors
    ///
    /// [`StoreError::InvalidFilter`] for a malformed filter,
    /// [`StoreError::Backend`] on database errors.
    pub async fn delete_where(&self, filter: &Filter) -> Result<usize, StoreError> {
        filter.validate()?;
        let filter = filter.clone();
        self.run(move |inner| inner.delete_where(&filter)).await
    }

    /// Remove every record. The dimension stays fixed.
    ///
    /// # Errors
    ///
    /// [`StoreError::Backend`] on database errors.
    pub async fn clear(&self) -> Result<(), StoreError> {
        self.run(|inner| {
            let conn = lock(&inner.writer)?;
            conn.execute(&inner.sql.clear, [])
                .map(drop)
                .map_err(|e| backend(&e))
        })
        .await
    }

    /// Run blocking database work: on tokio's blocking pool inside a tokio
    /// runtime (feature `tokio`), inline otherwise.
    #[cfg_attr(
        not(feature = "tokio"),
        allow(
            clippy::unused_async,
            clippy::unused_async_trait_impl,
            reason = "awaits only with the tokio feature"
        )
    )]
    async fn run<T, F>(&self, f: F) -> Result<T, StoreError>
    where
        T: Send + 'static,
        F: FnOnce(&Inner) -> Result<T, StoreError> + Send + 'static,
    {
        #[cfg(feature = "tokio")]
        if tokio::runtime::Handle::try_current().is_ok() {
            let inner = Arc::clone(&self.inner);
            return tokio::task::spawn_blocking(move || f(&inner))
                .await
                .map_err(|_| StoreError::Backend("blocking task failed".into()))?;
        }
        f(&self.inner)
    }
}

// Guards stay alive as long as the transactions and statements borrowing them.
#[allow(clippy::significant_drop_tightening)]
impl Inner {
    fn load_dimension(&self, conn: &Connection) -> Result<Option<usize>, StoreError> {
        let stored: Option<i64> = conn
            .query_row(
                &format!("SELECT dimension FROM {COLLECTIONS} WHERE name = ?1"),
                [&self.table],
                |r| r.get(0),
            )
            .optional()
            .map_err(|e| backend(&e))?
            .flatten();
        to_dim(stored)
    }

    fn dimension(&self, conn: &Connection) -> Result<Option<usize>, StoreError> {
        match self.dimension.load(Ordering::Relaxed) {
            0 => {
                // Another process may have fixed it since we opened.
                let d = self.load_dimension(conn)?;
                if let Some(d) = d {
                    self.dimension.store(d, Ordering::Relaxed);
                }
                Ok(d)
            }
            d => Ok(Some(d)),
        }
    }

    /// A read connection: a free reader if any, else the next in turn, else
    /// the writer (in-memory databases).
    fn reader(&self) -> Result<MutexGuard<'_, Connection>, StoreError> {
        if self.readers.is_empty() {
            return lock(&self.writer);
        }
        for r in &self.readers {
            if let Ok(guard) = r.try_lock() {
                return Ok(guard);
            }
        }
        let i = self.next_reader.fetch_add(1, Ordering::Relaxed) % self.readers.len();
        lock(&self.readers[i])
    }

    fn upsert(&self, records: &[Record]) -> Result<(), StoreError> {
        let mut conn = lock(&self.writer)?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|e| backend(&e))?;
        let current = self.dimension(&tx)?;
        let (dim, norms) = check::check_batch(self.metric, current, records)?;
        if current.is_none()
            && let Some(d) = dim
        {
            let d = i64::try_from(d).map_err(|_| {
                StoreError::Backend("dimension does not fit a SQLite integer".into())
            })?;
            tx.execute(
                &format!("UPDATE {COLLECTIONS} SET dimension = ?2 WHERE name = ?1"),
                params![self.table, d],
            )
            .map_err(|e| backend(&e))?;
        }
        {
            let mut stmt = tx
                .prepare_cached(&self.sql.upsert)
                .map_err(|e| backend(&e))?;
            let mut blob = Vec::new();
            for (r, n) in records.iter().zip(norms) {
                encode_vector(&r.vector, &mut blob);
                let meta = serde_json::to_string(&r.metadata)
                    .map_err(|e| StoreError::Backend(format!("metadata: {e}")))?;
                stmt.execute(params![r.id, blob, f64::from(n), r.content, meta])
                    .map_err(|e| backend(&e))?;
            }
        }
        tx.commit().map_err(|e| backend(&e))?;
        if current.is_none()
            && let Some(d) = dim
        {
            self.dimension.store(d, Ordering::Relaxed);
        }
        Ok(())
    }

    fn delete(&self, ids: &[String]) -> Result<usize, StoreError> {
        let mut conn = lock(&self.writer)?;
        let tx = conn.transaction().map_err(|e| backend(&e))?;
        let mut removed = 0;
        {
            let mut stmt = tx
                .prepare_cached(&self.sql.delete)
                .map_err(|e| backend(&e))?;
            for id in ids {
                removed += stmt.execute([id]).map_err(|e| backend(&e))?;
            }
        }
        tx.commit().map_err(|e| backend(&e))?;
        Ok(removed)
    }

    fn delete_where(&self, filter: &Filter) -> Result<usize, StoreError> {
        let mut conn = lock(&self.writer)?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|e| backend(&e))?;
        let compiled = filter::compile(filter, "metadata", 1);
        let doomed = {
            let sql = format!(
                "SELECT pk, metadata FROM {} WHERE {}",
                self.sql.table, compiled.sql
            );
            let mut stmt = tx.prepare(&sql).map_err(|e| backend(&e))?;
            let mut rows = stmt
                .query(rusqlite::params_from_iter(&compiled.params))
                .map_err(|e| backend(&e))?;
            let mut doomed = Vec::new();
            while let Some(row) = rows.next().map_err(|e| backend(&e))? {
                let pk: i64 = row.get(0).map_err(|e| backend(&e))?;
                let meta = row.get_ref(1).map_err(|e| backend(&e))?;
                let meta = meta.as_str().map_err(|e| backend(&e.into()))?;
                if filter.is_empty() || matches(filter, meta)? {
                    doomed.push(pk);
                }
            }
            doomed
        };
        {
            let mut stmt = tx
                .prepare_cached(&format!("DELETE FROM {} WHERE pk = ?1", self.sql.table))
                .map_err(|e| backend(&e))?;
            for pk in &doomed {
                stmt.execute([pk]).map_err(|e| backend(&e))?;
            }
        }
        tx.commit().map_err(|e| backend(&e))?;
        Ok(doomed.len())
    }

    fn get(&self, id: &str) -> Result<Option<Record>, StoreError> {
        let conn = self.reader()?;
        let mut stmt = conn
            .prepare_cached(&self.sql.get)
            .map_err(|e| backend(&e))?;
        stmt.query_row([id], |r| read_record(r, true))
            .optional()
            .map_err(|e| backend(&e))?
            .transpose()
    }

    fn len(&self) -> Result<usize, StoreError> {
        let conn = self.reader()?;
        let n: i64 = conn
            .query_row(&self.sql.count, [], |r| r.get(0))
            .map_err(|e| backend(&e))?;
        usize::try_from(n).map_err(|_| StoreError::Backend("negative count".into()))
    }

    fn query_all(&self, queries: &[Query]) -> Result<Vec<Vec<Hit>>, StoreError> {
        let mut conn = self.reader()?;
        let dim = self.dimension(&conn)?;
        let tx = conn.transaction().map_err(|e| backend(&e))?;
        let mut out = Vec::with_capacity(queries.len());
        for q in queries {
            out.push(self.query(&tx, dim, q)?);
        }
        tx.finish().map_err(|e| backend(&e))?;
        Ok(out)
    }

    fn query(
        &self,
        tx: &Transaction<'_>,
        dim: Option<usize>,
        q: &Query,
    ) -> Result<Vec<Hit>, StoreError> {
        check::check_query(q)?;
        let qn = check::check_query_vector(self.metric, dim, &q.vector)?;
        if q.top_k == 0 {
            return Ok(Vec::new());
        }
        let Some(dim) = dim else {
            return Ok(Vec::new()); // nothing was ever inserted
        };
        let top = self.scan(tx, dim, qn, q)?;
        let mut stmt = tx
            .prepare_cached(&self.sql.by_pk)
            .map_err(|e| backend(&e))?;
        let mut hits = Vec::new();
        for c in top.into_vec() {
            let record = stmt
                .query_row([c.data], |r| read_record(r, q.include_vectors))
                .map_err(|e| backend(&e))??;
            hits.push(Hit::new(c.score, record));
        }
        check::sort_hits(&mut hits);
        Ok(hits)
    }

    /// The exact scan: keyset-paginated chunks, a reused decode buffer and a
    /// bounded heap. Only rows that would enter the heap copy their id and
    /// have their metadata re-checked.
    fn scan(
        &self,
        tx: &Transaction<'_>,
        dim: usize,
        qn: f32,
        q: &Query,
    ) -> Result<TopK<i64>, StoreError> {
        let filtered = !q.filter.is_empty();
        let compiled = filter::compile(&q.filter, "metadata", 3);
        let sql = format!(
            "{}({}) ORDER BY pk LIMIT ?2",
            self.sql.scan_head, compiled.sql
        );
        let mut stmt = tx.prepare_cached(&sql).map_err(|e| backend(&e))?;
        let chunk = i64::try_from(self.chunk).unwrap_or(i64::MAX);
        let mut binds: Vec<Param> = Vec::with_capacity(compiled.params.len() + 2);
        binds.extend([Param::Int(i64::MIN), Param::Int(chunk)]);
        binds.extend(compiled.params);
        let mut top = TopK::new(q.top_k);
        let mut buf = vec![0f32; dim];
        loop {
            let mut rows = stmt
                .query(rusqlite::params_from_iter(&binds))
                .map_err(|e| backend(&e))?;
            let mut seen = 0usize;
            let mut last = None;
            while let Some(row) = rows.next().map_err(|e| backend(&e))? {
                seen += 1;
                let pk: i64 = row.get(0).map_err(|e| backend(&e))?;
                last = Some(pk);
                let blob = row.get_ref(2).map_err(|e| backend(&e))?;
                decode_vector(blob.as_blob().map_err(|e| backend(&e.into()))?, &mut buf)?;
                #[allow(clippy::cast_possible_truncation, reason = "norms are stored from f32")]
                let n = row.get::<_, f64>(3).map_err(|e| backend(&e))? as f32;
                let s = check::score(self.metric, &q.vector, qn, &buf, n);
                if !check::passes(q, s) {
                    continue;
                }
                let id = row.get_ref(1).map_err(|e| backend(&e))?;
                let id = id.as_str().map_err(|e| backend(&e.into()))?;
                if !top.admits(s, id) {
                    continue;
                }
                if filtered {
                    let meta = row.get_ref(4).map_err(|e| backend(&e))?;
                    if !matches(&q.filter, meta.as_str().map_err(|e| backend(&e.into()))?)? {
                        continue;
                    }
                }
                top.push(Candidate {
                    score: s,
                    id: id.to_owned(),
                    data: pk,
                });
            }
            match last {
                Some(pk) if seen >= self.chunk => binds[0] = Param::Int(pk),
                _ => return Ok(top),
            }
        }
    }
}

/// Exact filter check on stored metadata JSON.
fn matches(filter: &Filter, meta: &str) -> Result<bool, StoreError> {
    let map: std::collections::BTreeMap<String, Value> = serde_json::from_str(meta)
        .map_err(|e| StoreError::Backend(format!("stored metadata is not a JSON object: {e}")))?;
    Ok(filter.matches_metadata(&map))
}

fn encode_vector(v: &[f32], out: &mut Vec<u8>) {
    out.clear();
    out.reserve(v.len() * 4);
    for x in v {
        out.extend_from_slice(&x.to_le_bytes());
    }
}

fn decode_vector(blob: &[u8], out: &mut [f32]) -> Result<(), StoreError> {
    if blob.len() != out.len() * 4 {
        return Err(StoreError::Backend(format!(
            "stored vector has {} bytes, expected {}",
            blob.len(),
            out.len() * 4
        )));
    }
    let (words, _) = blob.as_chunks::<4>();
    for (x, b) in out.iter_mut().zip(words) {
        *x = f32::from_le_bytes(*b);
    }
    Ok(())
}

/// Read `id, vector, content, metadata`.
fn read_record(
    row: &rusqlite::Row<'_>,
    with_vector: bool,
) -> rusqlite::Result<Result<Record, StoreError>> {
    let id: String = row.get(0)?;
    let vector = if with_vector {
        let blob = row.get_ref(1)?.as_blob()?;
        let mut v = vec![0f32; blob.len() / 4];
        if let Err(e) = decode_vector(blob, &mut v) {
            return Ok(Err(e));
        }
        v
    } else {
        Vec::new()
    };
    let content: String = row.get(2)?;
    let meta = row.get_ref(3)?.as_str()?;
    let metadata = match serde_json::from_str(meta) {
        Ok(m) => m,
        Err(e) => {
            return Ok(Err(StoreError::Backend(format!(
                "stored metadata is not a JSON object: {e}"
            ))));
        }
    };
    let mut record = Record::new(id, vector).with_content(content);
    record.metadata = metadata;
    Ok(Ok(record))
}

#[async_trait]
impl VectorStore for SqliteVectorStore {
    async fn upsert(&self, records: Vec<Record>) -> Result<(), StoreError> {
        if records.is_empty() {
            return Ok(());
        }
        self.run(move |inner| inner.upsert(&records)).await
    }

    async fn query(&self, query: &Query) -> Result<Vec<Hit>, StoreError> {
        check::check_query(query)?;
        let q = query.clone();
        let mut out = self
            .run(move |inner| inner.query_all(std::slice::from_ref(&q)))
            .await?;
        Ok(out.pop().unwrap_or_default())
    }

    async fn delete(&self, ids: &[&str]) -> Result<usize, StoreError> {
        if ids.is_empty() {
            return Ok(0);
        }
        let ids: Vec<String> = ids.iter().map(|&s| s.to_owned()).collect();
        self.run(move |inner| inner.delete(&ids)).await
    }

    async fn get(&self, id: &str) -> Result<Option<Record>, StoreError> {
        let id = id.to_owned();
        self.run(move |inner| inner.get(&id)).await
    }

    async fn len(&self) -> Result<usize, StoreError> {
        self.run(Inner::len).await
    }

    async fn query_batch(&self, queries: &[Query]) -> Result<Vec<Vec<Hit>>, StoreError> {
        for q in queries {
            check::check_query(q)?;
        }
        let qs = queries.to_vec();
        self.run(move |inner| inner.query_all(&qs)).await
    }
}
