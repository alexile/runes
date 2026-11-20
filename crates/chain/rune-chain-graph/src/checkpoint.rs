//! Checkpoints: persisted snapshots of a thread's state between supersteps.

use std::collections::{BTreeMap, HashMap};
use std::sync::{Mutex, PoisonError};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::{GraphError, Interrupt};

/// Default cap on one serialized checkpoint: 16 MiB.
pub const DEFAULT_MAX_CHECKPOINT_BYTES: usize = 16 * 1024 * 1024;
/// Longest accepted thread id, in bytes.
pub const MAX_THREAD_ID_LEN: usize = 256;

/// What wrote a checkpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum CheckpointSource {
    /// The start of a run, after its input was applied.
    Input,
    /// The end of a superstep (or a pause inside one).
    Loop,
    /// [`CompiledGraph::update_state`](crate::CompiledGraph::update_state).
    Update,
}

/// A snapshot of one thread between supersteps.
///
/// State and pending tasks are stored as JSON so checkpointers need not know
/// the state type. Ids are zero-padded counters, so they sort in creation
/// order within a thread.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct Checkpoint {
    /// Conversation / run thread.
    pub thread_id: String,
    /// Unique within the thread; later checkpoints sort after earlier ones.
    pub id: String,
    /// The checkpoint this one continues from. Replaying from an old
    /// checkpoint forks the history, so this is not always the previous id.
    pub parent_id: Option<String>,
    /// Supersteps completed on this thread.
    pub step: usize,
    /// The serialized state.
    pub state: Value,
    /// Nodes that run next, in order. Empty when the run finished.
    pub next: Vec<String>,
    /// The serialized pending tasks behind `next`.
    pub tasks: Value,
    /// Set when the run paused here.
    pub interrupt: Option<Interrupt>,
    /// What wrote it.
    pub source: CheckpointSource,
    /// Unix time in milliseconds.
    pub created_at_ms: u64,
}

impl Checkpoint {
    /// Format a sequence number as a checkpoint id.
    #[must_use]
    pub fn format_id(seq: u64) -> String {
        format!("{seq:020}")
    }

    /// The sequence number behind a runner-made id.
    #[must_use]
    pub fn seq(&self) -> Option<u64> {
        self.id.parse().ok()
    }
}

/// Storage for checkpoints, keyed by thread id and checkpoint id.
///
/// Implementations must return the checkpoint with the greatest id for
/// `get(thread, None)`, and `list` newest first.
#[async_trait]
pub trait Checkpointer: Send + Sync {
    /// Store `checkpoint`, replacing one with the same thread and id.
    async fn put(&self, checkpoint: &Checkpoint) -> Result<(), GraphError>;

    /// The checkpoint `checkpoint_id` of `thread_id`, or the latest one when
    /// `checkpoint_id` is `None`.
    async fn get(
        &self,
        thread_id: &str,
        checkpoint_id: Option<&str>,
    ) -> Result<Option<Checkpoint>, GraphError>;

    /// Up to `limit` checkpoints of `thread_id`, newest first.
    async fn list(&self, thread_id: &str, limit: usize) -> Result<Vec<Checkpoint>, GraphError>;
}

#[async_trait]
impl<C: Checkpointer + ?Sized> Checkpointer for std::sync::Arc<C> {
    async fn put(&self, checkpoint: &Checkpoint) -> Result<(), GraphError> {
        (**self).put(checkpoint).await
    }
    async fn get(
        &self,
        thread_id: &str,
        checkpoint_id: Option<&str>,
    ) -> Result<Option<Checkpoint>, GraphError> {
        (**self).get(thread_id, checkpoint_id).await
    }
    async fn list(&self, thread_id: &str, limit: usize) -> Result<Vec<Checkpoint>, GraphError> {
        (**self).list(thread_id, limit).await
    }
}

/// Checkpoints in process memory (`LangGraph`'s `MemorySaver`).
///
/// History per thread is unbounded unless capped with
/// [`max_per_thread`](Self::max_per_thread), which drops the oldest.
#[derive(Debug, Default)]
pub struct InMemoryCheckpointer {
    threads: Mutex<HashMap<String, BTreeMap<String, Checkpoint>>>,
    max_per_thread: Option<usize>,
}

impl InMemoryCheckpointer {
    /// An empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Keep at most `n` checkpoints per thread (at least 1).
    #[must_use]
    pub fn max_per_thread(mut self, n: usize) -> Self {
        self.max_per_thread = Some(n.max(1));
        self
    }

    /// Thread ids with at least one checkpoint.
    #[must_use]
    pub fn threads(&self) -> Vec<String> {
        let mut ids: Vec<String> = self.lock().keys().cloned().collect();
        ids.sort_unstable();
        ids
    }

    /// Forget a thread.
    pub fn delete_thread(&self, thread_id: &str) {
        self.lock().remove(thread_id);
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, BTreeMap<String, Checkpoint>>> {
        self.threads.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

#[async_trait]
impl Checkpointer for InMemoryCheckpointer {
    async fn put(&self, checkpoint: &Checkpoint) -> Result<(), GraphError> {
        let mut threads = self.lock();
        let history = threads.entry(checkpoint.thread_id.clone()).or_default();
        history.insert(checkpoint.id.clone(), checkpoint.clone());
        if let Some(max) = self.max_per_thread {
            while history.len() > max {
                history.pop_first();
            }
        }
        drop(threads);
        Ok(())
    }

    async fn get(
        &self,
        thread_id: &str,
        checkpoint_id: Option<&str>,
    ) -> Result<Option<Checkpoint>, GraphError> {
        let threads = self.lock();
        let found = threads.get(thread_id).and_then(|history| {
            checkpoint_id.map_or_else(
                || history.values().next_back().cloned(),
                |id| history.get(id).cloned(),
            )
        });
        drop(threads);
        Ok(found)
    }

    async fn list(&self, thread_id: &str, limit: usize) -> Result<Vec<Checkpoint>, GraphError> {
        let threads = self.lock();
        Ok(threads
            .get(thread_id)
            .map(|h| h.values().rev().take(limit).cloned().collect())
            .unwrap_or_default())
    }
}

/// Serialized size of `value`, without keeping the bytes.
pub fn json_size<T: Serialize>(value: &T) -> Result<usize, GraphError> {
    struct Count(usize);
    impl std::io::Write for Count {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0 += buf.len();
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut count = Count(0);
    serde_json::to_writer(&mut count, value)?;
    Ok(count.0)
}

/// Reject thread ids that are empty, too long or contain control characters.
pub fn check_thread_id(thread_id: &str) -> Result<(), GraphError> {
    if thread_id.is_empty()
        || thread_id.len() > MAX_THREAD_ID_LEN
        || thread_id.chars().any(char::is_control)
    {
        return Err(GraphError::InvalidInput(format!(
            "thread id must be 1-{MAX_THREAD_ID_LEN} bytes without control characters"
        )));
    }
    Ok(())
}
