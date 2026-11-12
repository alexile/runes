//! Replay protection: remember accepted message keys until their timestamp
//! falls out of the tolerance window.

use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Mutex, PoisonError};

/// Boxed future returned by [`ReplayStore::check_and_insert`].
pub type ReplayFuture<'a> =
    Pin<Box<dyn Future<Output = Result<bool, ReplayStoreError>> + Send + 'a>>;

/// Storage for keys of messages that were already accepted.
///
/// Implement this over Redis or a database when several instances share the
/// same webhook endpoint. The in-process default is [`MemoryReplayStore`].
pub trait ReplayStore: Send + Sync + 'static {
    /// Records `key` until `expires_at` (unix seconds).
    ///
    /// Must be atomic: returns `Ok(true)` if the key was new and is now
    /// stored, `Ok(false)` if it was already present and not expired.
    fn check_and_insert(&self, key: &str, expires_at: i64) -> ReplayFuture<'_>;
}

/// The replay store failed. Requests are refused (fail closed).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ReplayStoreError;

impl fmt::Display for ReplayStoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("replay store error")
    }
}

impl std::error::Error for ReplayStoreError {}

/// Bounded in-memory [`ReplayStore`].
///
/// Expired keys are dropped lazily. When full, the oldest key is evicted, so
/// size `capacity` above the number of messages you expect inside one
/// tolerance window (default 10 000). Not shared between processes.
pub struct MemoryReplayStore {
    capacity: usize,
    inner: Mutex<Inner>,
}

#[derive(Default)]
struct Inner {
    seen: HashMap<String, i64>,
    order: VecDeque<String>,
}

impl MemoryReplayStore {
    /// Default capacity.
    pub const DEFAULT_CAPACITY: usize = 10_000;

    /// A store holding at most `capacity` keys (minimum 1).
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity: capacity.max(1),
            inner: Mutex::new(Inner::default()),
        }
    }

    /// Number of keys currently held.
    #[must_use]
    pub fn len(&self) -> usize {
        self.lock().seen.len()
    }

    /// Whether the store is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Synchronous core of [`ReplayStore::check_and_insert`], with an explicit
    /// clock.
    pub(crate) fn insert_at(&self, key: &str, expires_at: i64, now: i64) -> bool {
        let mut inner = self.lock();
        if let Some(&exp) = inner.seen.get(key)
            && exp > now
        {
            return false;
        }
        if inner.seen.len() >= self.capacity {
            inner.seen.retain(|_, exp| *exp > now);
            let Inner { seen, order } = &mut *inner;
            order.retain(|k| seen.contains_key(k));
        }
        while inner.seen.len() >= self.capacity {
            let Some(oldest) = inner.order.pop_front() else {
                break;
            };
            inner.seen.remove(&oldest);
        }
        if inner.seen.insert(key.to_owned(), expires_at).is_none() {
            inner.order.push_back(key.to_owned());
        }
        true
    }
}

impl Default for MemoryReplayStore {
    fn default() -> Self {
        Self::new(Self::DEFAULT_CAPACITY)
    }
}

impl fmt::Debug for MemoryReplayStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MemoryReplayStore")
            .field("capacity", &self.capacity)
            .field("len", &self.len())
            .finish_non_exhaustive()
    }
}

impl ReplayStore for MemoryReplayStore {
    fn check_and_insert(&self, key: &str, expires_at: i64) -> ReplayFuture<'_> {
        let fresh = self.insert_at(key, expires_at, crate::verifier::now_unix());
        Box::pin(async move { Ok(fresh) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn second_insert_is_a_replay() {
        let store = MemoryReplayStore::new(10);
        assert!(store.insert_at("a", 100, 0));
        assert!(!store.insert_at("a", 100, 50));
        // Expired entries can be reused.
        assert!(store.insert_at("a", 300, 100));
    }

    #[test]
    fn capacity_is_bounded() {
        let store = MemoryReplayStore::new(3);
        for i in 0..10 {
            assert!(store.insert_at(&i.to_string(), 1_000, 0));
        }
        assert_eq!(store.len(), 3);
        // Most recent keys are kept.
        assert!(!store.insert_at("9", 1_000, 0));
    }

    #[test]
    fn expired_entries_are_purged_before_evicting() {
        let store = MemoryReplayStore::new(2);
        assert!(store.insert_at("old", 10, 0));
        assert!(store.insert_at("live", 1_000, 0));
        assert!(store.insert_at("new", 1_000, 20));
        assert!(!store.insert_at("live", 1_000, 20));
    }
}
