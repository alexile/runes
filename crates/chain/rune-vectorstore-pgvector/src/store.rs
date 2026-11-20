//! The Postgres + pgvector store.

use std::collections::BTreeMap;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use deadpool_postgres::{Manager, Pool, PoolError, Runtime};
use rune_vectorstore::{Filter, Hit, Metric, Query, Record, StoreError, Value, VectorStore};
use tokio_postgres::types::ToSql;

use crate::check;
use crate::sql::{self, Param, PgIndex, Statements};

/// Configuration for [`PgVectorStore`].
///
/// # Example
///
/// ```
/// use rune_vectorstore::Metric;
/// use rune_vectorstore_pgvector::{PgIndex, PgVectorConfig};
///
/// let config = PgVectorConfig::new("docs", 1536)
///     .with_schema("rag")
///     .with_metric(Metric::Cosine)
///     .with_index(PgIndex::Hnsw { m: 16, ef_construction: 64 })
///     .with_ef_search(100);
/// assert_eq!(config.dimension, 1536);
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct PgVectorConfig {
    /// Schema holding the table; `None` uses the search path.
    pub schema: Option<String>,
    /// Table name. Identifiers are ASCII letters, digits and `_`, not
    /// starting with a digit or `pg_`, at most 63 bytes.
    pub table: String,
    /// Index name; default `{table}_{hnsw|ivfflat}_{cosine|ip|l2}_idx`.
    pub index_name: Option<String>,
    /// Vector dimension (the column is `vector(dimension)`).
    pub dimension: usize,
    /// Similarity metric. Default [`Metric::Cosine`].
    pub metric: Metric,
    /// Vector index. Default HNSW with pgvector's defaults.
    pub index: PgIndex,
    /// HNSW search breadth (`hnsw.ef_search`) unless a query sets its own.
    /// `None` keeps the server setting (40 by default). Always raised to at
    /// least `top_k` and capped at 1000.
    pub ef_search: Option<usize>,
    /// `IVFFlat` lists probed per query (`ivfflat.probes`). `None` keeps the
    /// server setting (1 by default).
    pub probes: Option<u32>,
    /// Use pgvector's iterative index scans (0.8.0 or later) for filtered
    /// queries and for `top_k` above 1000, so a selective filter still
    /// returns `top_k` rows. Default `true`.
    pub iterative_scan: bool,
    /// Run `CREATE EXTENSION IF NOT EXISTS vector` during setup. Default
    /// `true`; turn it off when the role may not create extensions and
    /// pgvector is already installed.
    pub create_extension: bool,
    /// Rows per upsert statement. Default 500.
    pub upsert_batch_rows: usize,
    /// Pool size for [`PgVectorStore::connect`]. Default 8.
    pub max_connections: usize,
    /// Connect and pool-wait timeout for [`PgVectorStore::connect`].
    /// Default 10 s.
    pub connect_timeout: Duration,
}

impl PgVectorConfig {
    /// Default configuration for `table` holding `dimension`-sized vectors.
    #[must_use]
    pub fn new(table: impl Into<String>, dimension: usize) -> Self {
        Self {
            schema: None,
            table: table.into(),
            index_name: None,
            dimension,
            metric: Metric::Cosine,
            index: PgIndex::default(),
            ef_search: None,
            probes: None,
            iterative_scan: true,
            create_extension: true,
            upsert_batch_rows: 500,
            max_connections: 8,
            connect_timeout: Duration::from_secs(10),
        }
    }

    /// Put the table in `schema` (which must exist).
    #[must_use]
    pub fn with_schema(mut self, schema: impl Into<String>) -> Self {
        self.schema = Some(schema.into());
        self
    }

    /// Name the vector index.
    #[must_use]
    pub fn with_index_name(mut self, name: impl Into<String>) -> Self {
        self.index_name = Some(name.into());
        self
    }

    /// Set the metric.
    #[must_use]
    pub const fn with_metric(mut self, metric: Metric) -> Self {
        self.metric = metric;
        self
    }

    /// Choose the vector index.
    #[must_use]
    pub const fn with_index(mut self, index: PgIndex) -> Self {
        self.index = index;
        self
    }

    /// Set the default HNSW search breadth.
    #[must_use]
    pub const fn with_ef_search(mut self, ef: usize) -> Self {
        self.ef_search = Some(ef);
        self
    }

    /// Set the `IVFFlat` probes per query.
    #[must_use]
    pub const fn with_probes(mut self, probes: u32) -> Self {
        self.probes = Some(probes);
        self
    }

    /// Turn iterative index scans on or off.
    #[must_use]
    pub const fn with_iterative_scan(mut self, on: bool) -> Self {
        self.iterative_scan = on;
        self
    }

    /// Choose whether setup creates the extension.
    #[must_use]
    pub const fn with_create_extension(mut self, on: bool) -> Self {
        self.create_extension = on;
        self
    }

    /// Set the rows per upsert statement (at least 1).
    #[must_use]
    pub const fn with_upsert_batch_rows(mut self, rows: usize) -> Self {
        self.upsert_batch_rows = rows;
        self
    }

    /// Set the pool size used by [`PgVectorStore::connect`].
    #[must_use]
    pub const fn with_max_connections(mut self, n: usize) -> Self {
        self.max_connections = n;
        self
    }

    /// Set the connect timeout used by [`PgVectorStore::connect`].
    #[must_use]
    pub const fn with_connect_timeout(mut self, timeout: Duration) -> Self {
        self.connect_timeout = timeout;
        self
    }
}

/// A [`VectorStore`] on Postgres with the pgvector extension.
///
/// Records live in one table: `id text PRIMARY KEY`, `embedding
/// vector(dimension)`, `content text`, `metadata jsonb`. Queries order by
/// the pgvector distance operator for the metric (`<=>` cosine, `<#>`
/// inner product, `<->` L2), so an HNSW or `IVFFlat` index built with the
/// matching operator class serves them. Scores follow the
/// [`Metric`] convention: `1 - distance` for cosine, the inner product for
/// dot, and the negated distance for L2.
///
/// # Filters
///
/// [`Filter`]s compile to `jsonb` conditions with every key and value
/// bound as a parameter; the semantics are those of the in-memory store
/// (array fields match any element, ranges compare numbers with numbers and
/// strings with strings byte-wise). One difference: Postgres compares JSON
/// numbers as exact decimals, while the in-memory store goes through `f64`
/// when either side is a float, and also treats `1` and `1.0` as equal
/// inside nested arrays. With an approximate index, filtered queries use
/// iterative scans (see [`PgVectorConfig::iterative_scan`]).
///
/// # Errors
///
/// Database failures map to [`StoreError::Backend`]. Messages carry the
/// Postgres error code and text, never the connection string or password.
///
/// # Example
///
/// ```no_run
/// use rune_vectorstore::{Filter, Query, Record, VectorStore};
/// use rune_vectorstore_pgvector::{PgVectorConfig, PgVectorStore};
///
/// # async fn demo() -> Result<(), rune_vectorstore::StoreError> {
/// let url = std::env::var("DATABASE_URL").unwrap();
/// let store = PgVectorStore::connect(&url, PgVectorConfig::new("docs", 3)).await?;
/// store.upsert(vec![
///     Record::new("a", vec![1.0, 0.0, 0.0]).with_content("Rust").with_meta("lang", "en"),
///     Record::new("b", vec![0.0, 1.0, 0.0]).with_content("Rouille").with_meta("lang", "fr"),
/// ]).await?;
/// let q = Query::new(vec![0.9, 0.1, 0.0], 5).with_filter(Filter::eq("lang", "fr"));
/// let hits = store.query(&q).await?;
/// assert_eq!(hits[0].record.id, "b");
/// # Ok(())
/// # }
/// ```
#[derive(Clone)]
pub struct PgVectorStore {
    inner: Arc<Inner>,
}

struct Inner {
    pool: Pool,
    stmts: Statements,
    upsert_sql: String,
    config: PgVectorConfig,
    /// Strings that must never appear in an error message.
    secrets: Vec<String>,
}

impl std::fmt::Debug for PgVectorStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PgVectorStore")
            .field("table", &self.inner.stmts.table)
            .field("metric", &self.inner.config.metric)
            .field("dimension", &self.inner.config.dimension)
            .field("index", &self.inner.config.index)
            .finish_non_exhaustive()
    }
}

/// Replace every secret in `msg`.
fn redact(mut msg: String, secrets: &[String]) -> String {
    for s in secrets.iter().filter(|s| !s.is_empty()) {
        msg = msg.replace(s.as_str(), "***");
    }
    msg
}

fn pg_error(e: &tokio_postgres::Error, secrets: &[String]) -> StoreError {
    let msg = e.as_db_error().map_or_else(
        || format!("postgres: {e}"),
        |db| format!("postgres {}: {}", db.code().code(), db.message()),
    );
    StoreError::Backend(redact(msg, secrets))
}

fn pool_error(e: PoolError, secrets: &[String]) -> StoreError {
    match e {
        PoolError::Backend(e) => pg_error(&e, secrets),
        PoolError::Timeout(_) => {
            StoreError::Backend("postgres: timed out getting a connection".into())
        }
        PoolError::Closed => StoreError::Backend("postgres: pool is closed".into()),
        other => StoreError::Backend(redact(format!("postgres pool: {other}"), secrets)),
    }
}

/// Postgres text and jsonb cannot hold NUL characters.
fn check_nul(r: &Record) -> Result<(), StoreError> {
    let bad = r.id.contains('\0')
        || r.content.contains('\0')
        || r.metadata
            .iter()
            .any(|(k, v)| k.contains('\0') || sql::has_nul(v));
    if bad {
        return Err(StoreError::Backend(format!(
            "record {:?} contains a NUL character, which Postgres text cannot store",
            r.id
        )));
    }
    Ok(())
}

impl PgVectorStore {
    /// Wrap an existing pool. No I/O: call [`ensure_schema`](Self::ensure_schema)
    /// to create the table and index, or rely on them existing.
    ///
    /// # Errors
    ///
    /// [`StoreError::Backend`] for an invalid identifier or dimension.
    pub fn new(pool: Pool, config: PgVectorConfig) -> Result<Self, StoreError> {
        Self::build(pool, config, Vec::new())
    }

    fn build(pool: Pool, config: PgVectorConfig, secrets: Vec<String>) -> Result<Self, StoreError> {
        let stmts = Statements::new(
            config.schema.as_deref(),
            &config.table,
            config.index_name.as_deref(),
            config.metric,
            config.dimension,
            config.index,
        )?;
        Ok(Self {
            inner: Arc::new(Inner {
                upsert_sql: stmts.upsert(),
                pool,
                stmts,
                config,
                secrets,
            }),
        })
    }

    /// Connect with a libpq-style URL or key/value string, then run
    /// [`ensure_schema`](Self::ensure_schema).
    ///
    /// Without the `rustls` feature connections are plain TCP (or Unix
    /// sockets), and `sslmode=require` fails. With it, TLS is used as the
    /// URL's `sslmode` asks, verified against the webpki roots.
    ///
    /// # Errors
    ///
    /// [`StoreError::Backend`] if the string does not parse (the string is
    /// never echoed), the server cannot be reached, or setup fails.
    pub async fn connect(url: &str, config: PgVectorConfig) -> Result<Self, StoreError> {
        let mut pg = tokio_postgres::Config::from_str(url)
            .map_err(|_| StoreError::Backend("invalid Postgres connection string".into()))?;
        if pg.get_connect_timeout().is_none() {
            pg.connect_timeout(config.connect_timeout);
        }
        let mut secrets = vec![url.to_owned()];
        if let Some(pw) = pg.get_password() {
            secrets.push(String::from_utf8_lossy(pw).into_owned());
        }
        let manager = manager(pg)?;
        let pool = Pool::builder(manager)
            .max_size(config.max_connections.max(1))
            .runtime(Runtime::Tokio1)
            .create_timeout(Some(config.connect_timeout))
            .wait_timeout(Some(config.connect_timeout))
            .build()
            .map_err(|_| StoreError::Backend("could not build the connection pool".into()))?;
        let store = Self::build(pool, config, secrets)?;
        store.ensure_schema().await?;
        Ok(store)
    }

    /// Create the extension (if configured), table and index when missing,
    /// and check that an existing table has the configured dimension.
    /// Concurrent callers are serialized with an advisory lock.
    ///
    /// # Errors
    ///
    /// [`StoreError::DimensionMismatch`] if the table exists with another
    /// dimension; [`StoreError::Backend`] on database errors.
    pub async fn ensure_schema(&self) -> Result<(), StoreError> {
        let inner = &self.inner;
        let secrets = &inner.secrets;
        let mut client = inner.pool.get().await.map_err(|e| pool_error(e, secrets))?;
        let tx = client
            .transaction()
            .await
            .map_err(|e| pg_error(&e, secrets))?;
        tx.execute(
            "SELECT pg_advisory_xact_lock(hashtext($1::text))",
            &[&inner.stmts.regclass],
        )
        .await
        .map_err(|e| pg_error(&e, secrets))?;
        for ddl in inner.stmts.create(inner.config.create_extension) {
            tx.batch_execute(&ddl)
                .await
                .map_err(|e| pg_error(&e, secrets))?;
        }
        let row = tx
            .query_one(Statements::column_dimension(), &[&inner.stmts.regclass])
            .await
            .map_err(|e| pg_error(&e, secrets))?;
        let have: i32 = row.get(0);
        let want = inner.config.dimension;
        if usize::try_from(have).ok() != Some(want) {
            return Err(StoreError::DimensionMismatch {
                expected: usize::try_from(have).unwrap_or(0),
                actual: want,
            });
        }
        tx.commit().await.map_err(|e| pg_error(&e, secrets))
    }

    /// The pool, for running your own SQL alongside the store.
    #[must_use]
    pub fn pool(&self) -> &Pool {
        &self.inner.pool
    }

    /// The store's metric.
    #[must_use]
    pub fn metric(&self) -> Metric {
        self.inner.config.metric
    }

    /// The vector dimension.
    #[must_use]
    pub fn dimension(&self) -> usize {
        self.inner.config.dimension
    }

    /// The quoted, qualified table name.
    #[must_use]
    pub fn table(&self) -> &str {
        &self.inner.stmts.table
    }

    /// Remove every record matching `filter`; returns how many were removed.
    ///
    /// # Errors
    ///
    /// [`StoreError::InvalidFilter`] for a malformed filter,
    /// [`StoreError::Backend`] on database errors.
    pub async fn delete_where(&self, filter: &Filter) -> Result<usize, StoreError> {
        let (sql, params) = self.inner.stmts.delete_where(filter)?;
        let params = to_sql(&params);
        let client = self.client().await?;
        let n = client
            .execute(sql.as_str(), &refs(&params))
            .await
            .map_err(|e| self.err(&e))?;
        Ok(usize::try_from(n).unwrap_or(usize::MAX))
    }

    /// Remove every record.
    ///
    /// # Errors
    ///
    /// [`StoreError::Backend`] on database errors.
    pub async fn clear(&self) -> Result<(), StoreError> {
        let client = self.client().await?;
        client
            .execute(self.inner.stmts.clear().as_str(), &[])
            .await
            .map(drop)
            .map_err(|e| self.err(&e))
    }

    async fn client(&self) -> Result<deadpool_postgres::Object, StoreError> {
        self.inner
            .pool
            .get()
            .await
            .map_err(|e| pool_error(e, &self.inner.secrets))
    }

    fn err(&self, e: &tokio_postgres::Error) -> StoreError {
        pg_error(e, &self.inner.secrets)
    }

    /// Per-query planner settings (`set_config(.., true)`, so they last for
    /// one transaction).
    fn settings(&self, q: &Query) -> Vec<(&'static str, String)> {
        let c = &self.inner.config;
        let iterative = c.iterative_scan && (!q.filter.is_empty() || q.top_k > 1000);
        let mut out = Vec::new();
        match c.index {
            PgIndex::Hnsw { .. } => {
                let ef = q.ef_search.or(c.ef_search);
                if ef.is_some() || q.top_k > 40 {
                    let ef = ef.unwrap_or(40).max(q.top_k).clamp(1, 1000);
                    out.push(("hnsw.ef_search", ef.to_string()));
                }
                if iterative {
                    out.push(("hnsw.iterative_scan", "strict_order".into()));
                }
            }
            PgIndex::IvfFlat { .. } => {
                if let Some(p) = c.probes {
                    out.push(("ivfflat.probes", p.max(1).to_string()));
                }
                if iterative {
                    out.push(("ivfflat.iterative_scan", "relaxed_order".into()));
                }
            }
            PgIndex::None => {}
        }
        out
    }

    async fn run_query(&self, q: &Query) -> Result<Vec<Hit>, StoreError> {
        check::check_query(q)?;
        let metric = self.inner.config.metric;
        check::check_query_vector(metric, Some(self.inner.config.dimension), &q.vector)?;
        if q.top_k == 0 {
            return Ok(Vec::new());
        }
        let (sql, fparams) = self.inner.stmts.query(&q.filter, q.include_vectors)?;
        let limit = i64::try_from(q.top_k).unwrap_or(i64::MAX);
        let fparams = to_sql(&fparams);
        let mut params: Vec<&(dyn ToSql + Sync)> = vec![&q.vector, &limit];
        params.extend(refs(&fparams));
        let settings = self.settings(q);
        let mut client = self.client().await?;
        let rows = if settings.is_empty() {
            client.query(sql.as_str(), &params).await
        } else {
            let tx = client.transaction().await.map_err(|e| self.err(&e))?;
            let (names, values): (Vec<&str>, Vec<String>) = settings.into_iter().unzip();
            tx.execute(
                "SELECT set_config(n, v, true) FROM unnest($1::text[], $2::text[]) AS s(n, v)",
                &[&names, &values],
            )
            .await
            .map_err(|e| self.err(&e))?;
            let rows = tx.query(sql.as_str(), &params).await;
            if rows.is_ok() {
                tx.commit().await.map_err(|e| self.err(&e))?;
            }
            rows
        }
        .map_err(|e| self.err(&e))?;
        let mut hits = Vec::with_capacity(rows.len());
        for row in &rows {
            let distance: f64 = row.try_get(4).map_err(|e| self.err(&e))?;
            let score = sql::score(metric, distance);
            if check::passes(q, score) {
                hits.push(Hit::new(score, self.record(row)?));
            }
        }
        check::sort_hits(&mut hits);
        Ok(hits)
    }

    /// Decode `id, content, metadata, vector`.
    fn record(&self, row: &tokio_postgres::Row) -> Result<Record, StoreError> {
        let id: String = row.try_get(0).map_err(|e| self.err(&e))?;
        let content: String = row.try_get(1).map_err(|e| self.err(&e))?;
        let metadata: Value = row.try_get(2).map_err(|e| self.err(&e))?;
        let vector: Option<Vec<f32>> = row.try_get(3).map_err(|e| self.err(&e))?;
        let Value::Object(map) = metadata else {
            return Err(StoreError::Backend(
                "stored metadata is not a JSON object".into(),
            ));
        };
        let mut r = Record::new(id, vector.unwrap_or_default()).with_content(content);
        r.metadata = map.into_iter().collect::<BTreeMap<_, _>>();
        Ok(r)
    }
}

#[cfg(feature = "rustls")]
fn manager(pg: tokio_postgres::Config) -> Result<Manager, StoreError> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let roots = rustls::RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };
    let tls = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|_| StoreError::Backend("could not set up TLS".into()))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(Manager::new(
        pg,
        tokio_postgres_rustls::MakeRustlsConnect::new(tls),
    ))
}

#[cfg(not(feature = "rustls"))]
#[allow(
    clippy::unnecessary_wraps,
    reason = "same signature as the TLS version"
)]
fn manager(pg: tokio_postgres::Config) -> Result<Manager, StoreError> {
    Ok(Manager::new(pg, tokio_postgres::NoTls))
}

fn to_sql(params: &[Param]) -> Vec<Box<dyn ToSql + Sync + Send>> {
    params
        .iter()
        .map(|p| -> Box<dyn ToSql + Sync + Send> {
            match p {
                Param::Text(s) => Box::new(s.clone()),
                Param::Json(v) => Box::new(v.clone()),
            }
        })
        .collect()
}

fn refs(params: &[Box<dyn ToSql + Sync + Send>]) -> Vec<&(dyn ToSql + Sync)> {
    params
        .iter()
        .map(|p| p.as_ref() as &(dyn ToSql + Sync))
        .collect()
}

#[async_trait]
impl VectorStore for PgVectorStore {
    async fn upsert(&self, records: Vec<Record>) -> Result<(), StoreError> {
        let c = &self.inner.config;
        check::check_batch(c.metric, Some(c.dimension), &records)?;
        records.iter().try_for_each(check_nul)?;
        if records.is_empty() {
            return Ok(());
        }
        let mut client = self.client().await?;
        let tx = client.transaction().await.map_err(|e| self.err(&e))?;
        let stmt = tx
            .prepare_cached(&self.inner.upsert_sql)
            .await
            .map_err(|e| self.err(&e))?;
        for chunk in records.chunks(c.upsert_batch_rows.max(1)) {
            let ids: Vec<&str> = chunk.iter().map(|r| r.id.as_str()).collect();
            let vectors: Vec<f32> = chunk
                .iter()
                .flat_map(|r| r.vector.iter().copied())
                .collect();
            let contents: Vec<&str> = chunk.iter().map(|r| r.content.as_str()).collect();
            let metas: Vec<Value> = chunk
                .iter()
                .map(|r| {
                    Value::Object(
                        r.metadata
                            .iter()
                            .map(|(k, v)| (k.clone(), v.clone()))
                            .collect(),
                    )
                })
                .collect();
            tx.execute(&stmt, &[&ids, &vectors, &contents, &metas])
                .await
                .map_err(|e| self.err(&e))?;
        }
        tx.commit().await.map_err(|e| self.err(&e))
    }

    async fn query(&self, query: &Query) -> Result<Vec<Hit>, StoreError> {
        self.run_query(query).await
    }

    async fn delete(&self, ids: &[&str]) -> Result<usize, StoreError> {
        // Ids with NUL cannot be stored, so they cannot be deleted either.
        let ids: Vec<&str> = ids
            .iter()
            .copied()
            .filter(|id| !id.contains('\0'))
            .collect();
        if ids.is_empty() {
            return Ok(0);
        }
        let client = self.client().await?;
        let n = client
            .execute(self.inner.stmts.delete().as_str(), &[&ids])
            .await
            .map_err(|e| self.err(&e))?;
        Ok(usize::try_from(n).unwrap_or(usize::MAX))
    }

    async fn get(&self, id: &str) -> Result<Option<Record>, StoreError> {
        if id.contains('\0') {
            return Ok(None);
        }
        let client = self.client().await?;
        let row = client
            .query_opt(self.inner.stmts.get().as_str(), &[&id])
            .await
            .map_err(|e| self.err(&e))?;
        row.map(|r| self.record(&r)).transpose()
    }

    async fn len(&self) -> Result<usize, StoreError> {
        let client = self.client().await?;
        let row = client
            .query_one(self.inner.stmts.count().as_str(), &[])
            .await
            .map_err(|e| self.err(&e))?;
        let n: i64 = row.try_get(0).map_err(|e| self.err(&e))?;
        Ok(usize::try_from(n).unwrap_or(0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redaction_hides_every_secret() {
        let secrets = vec![
            "postgres://u:hunter2@db:5432/x".to_owned(),
            "hunter2".to_owned(),
            String::new(),
        ];
        let msg = redact(
            "failed for postgres://u:hunter2@db:5432/x (pw hunter2)".into(),
            &secrets,
        );
        assert!(!msg.contains("hunter2"));
        assert_eq!(msg, "failed for *** (pw ***)");
    }

    #[test]
    fn nul_records_are_refused() {
        assert!(check_nul(&Record::new("a\0", vec![1.0])).is_err());
        assert!(check_nul(&Record::new("a", vec![1.0]).with_content("\0")).is_err());
        assert!(check_nul(&Record::new("a", vec![1.0]).with_meta("k\0", 1)).is_err());
        assert!(
            check_nul(
                &Record::new("a", vec![1.0]).with_meta("k", serde_json::json!({"x": ["\0"]}))
            )
            .is_err()
        );
        assert!(check_nul(&Record::new("a", vec![1.0]).with_meta("k", "v")).is_ok());
    }
}
