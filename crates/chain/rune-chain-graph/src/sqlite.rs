//! A SQLite checkpointer (feature `sqlite`).

use std::path::Path;
use std::sync::{Arc, Mutex, PoisonError};

use async_trait::async_trait;
use rusqlite::{Connection, OptionalExtension, params};

use crate::checkpoint::{Checkpoint, Checkpointer, DEFAULT_MAX_CHECKPOINT_BYTES};
use crate::error::GraphError;

/// Checkpoints in a SQLite database (`LangGraph`'s `SqliteSaver`).
///
/// Each checkpoint is one JSON row keyed by `(thread_id, id)`. Calls run on
/// Tokio's blocking pool. Rows larger than the read cap (default 16 MiB) are
/// refused on read, so a tampered database cannot make the reader allocate
/// without bound.
///
/// ```rust
/// # tokio_test::block_on(async {
/// use rune_chain_graph::{Checkpointer, SqliteCheckpointer};
///
/// let store = SqliteCheckpointer::in_memory().unwrap();
/// assert!(store.get("thread-1", None).await.unwrap().is_none());
/// # });
/// ```
#[derive(Debug, Clone)]
pub struct SqliteCheckpointer {
    conn: Arc<Mutex<Connection>>,
    max_row_bytes: usize,
}

fn db_err(e: &rusqlite::Error) -> GraphError {
    GraphError::Checkpoint(format!("sqlite: {e}"))
}

impl SqliteCheckpointer {
    /// Open (or create) the database at `path`.
    ///
    /// # Errors
    ///
    /// The file cannot be opened or the table cannot be created.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, GraphError> {
        Self::from_connection(Connection::open(path).map_err(|e| db_err(&e))?)
    }

    /// A private in-memory database, handy for tests.
    ///
    /// # Errors
    ///
    /// SQLite could not create it.
    pub fn in_memory() -> Result<Self, GraphError> {
        Self::from_connection(Connection::open_in_memory().map_err(|e| db_err(&e))?)
    }

    /// Use an existing connection; creates the `graph_checkpoints` table if
    /// needed.
    ///
    /// # Errors
    ///
    /// The table cannot be created.
    pub fn from_connection(conn: Connection) -> Result<Self, GraphError> {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS graph_checkpoints (
                thread_id TEXT NOT NULL,
                id TEXT NOT NULL,
                data TEXT NOT NULL,
                PRIMARY KEY (thread_id, id)
            ) WITHOUT ROWID;",
        )
        .map_err(|e| db_err(&e))?;
        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
            max_row_bytes: DEFAULT_MAX_CHECKPOINT_BYTES,
        })
    }

    /// Refuse to read rows above `bytes` (default 16 MiB).
    #[must_use]
    pub const fn max_row_bytes(mut self, bytes: usize) -> Self {
        self.max_row_bytes = bytes;
        self
    }

    async fn with_conn<T: Send + 'static>(
        &self,
        f: impl FnOnce(&Connection) -> Result<T, GraphError> + Send + 'static,
    ) -> Result<T, GraphError> {
        let conn = Arc::clone(&self.conn);
        let run = move || f(&conn.lock().unwrap_or_else(PoisonError::into_inner));
        match tokio::runtime::Handle::try_current() {
            Ok(handle) => handle
                .spawn_blocking(run)
                .await
                .map_err(|e| GraphError::Checkpoint(format!("sqlite task failed: {e}")))?,
            Err(_) => run(),
        }
    }
}

fn too_large(len: i64, max: usize) -> GraphError {
    GraphError::CheckpointTooLarge {
        size: usize::try_from(len).unwrap_or(usize::MAX),
        limit: max,
    }
}

fn decode(data: &str, max: usize) -> Result<Checkpoint, GraphError> {
    if data.len() > max {
        return Err(GraphError::CheckpointTooLarge {
            size: data.len(),
            limit: max,
        });
    }
    Ok(serde_json::from_str(data)?)
}

#[async_trait]
impl Checkpointer for SqliteCheckpointer {
    async fn put(&self, checkpoint: &Checkpoint) -> Result<(), GraphError> {
        let data = serde_json::to_string(checkpoint)?;
        let thread = checkpoint.thread_id.clone();
        let id = checkpoint.id.clone();
        self.with_conn(move |c| {
            c.execute(
                "INSERT OR REPLACE INTO graph_checkpoints (thread_id, id, data) VALUES (?1, ?2, ?3)",
                params![thread, id, data],
            )
            .map_err(|e| db_err(&e))?;
            Ok(())
        })
        .await
    }

    async fn get(
        &self,
        thread_id: &str,
        checkpoint_id: Option<&str>,
    ) -> Result<Option<Checkpoint>, GraphError> {
        let thread = thread_id.to_owned();
        let id = checkpoint_id.map(str::to_owned);
        let max = self.max_row_bytes;
        let row: Option<(i64, Option<String>)> = self
            .with_conn(move |c| {
                let sql = if id.is_some() {
                    "SELECT length(data), CASE WHEN length(data) <= ?3 THEN data END
                     FROM graph_checkpoints WHERE thread_id = ?1 AND id = ?2"
                } else {
                    "SELECT length(data), CASE WHEN length(data) <= ?3 THEN data END
                     FROM graph_checkpoints WHERE thread_id = ?1 AND (?2 IS NULL)
                     ORDER BY id DESC LIMIT 1"
                };
                c.query_row(
                    sql,
                    params![thread, id, i64::try_from(max).unwrap_or(i64::MAX)],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()
                .map_err(|e| db_err(&e))
            })
            .await?;
        match row {
            None => Ok(None),
            Some((_, Some(data))) => decode(&data, max).map(Some),
            Some((len, None)) => Err(too_large(len, max)),
        }
    }

    async fn list(&self, thread_id: &str, limit: usize) -> Result<Vec<Checkpoint>, GraphError> {
        let thread = thread_id.to_owned();
        let max = self.max_row_bytes;
        let rows: Vec<(i64, Option<String>)> = self
            .with_conn(move |c| {
                let mut stmt = c
                    .prepare(
                        "SELECT length(data), CASE WHEN length(data) <= ?3 THEN data END
                         FROM graph_checkpoints WHERE thread_id = ?1
                         ORDER BY id DESC LIMIT ?2",
                    )
                    .map_err(|e| db_err(&e))?;
                let rows = stmt
                    .query_map(
                        params![
                            thread,
                            i64::try_from(limit).unwrap_or(i64::MAX),
                            i64::try_from(max).unwrap_or(i64::MAX)
                        ],
                        |r| Ok((r.get(0)?, r.get(1)?)),
                    )
                    .map_err(|e| db_err(&e))?;
                rows.collect::<Result<Vec<_>, _>>().map_err(|e| db_err(&e))
            })
            .await?;
        rows.into_iter()
            .map(|(len, data)| data.map_or_else(|| Err(too_large(len, max)), |d| decode(&d, max)))
            .collect()
    }
}
