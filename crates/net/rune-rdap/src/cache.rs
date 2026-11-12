//! A small TTL cache, sans I/O: callers pass the current time.

use std::collections::HashMap;
use std::time::{Duration, Instant};

/// A bounded map from string keys to values that expire.
///
/// When full, inserting first drops expired entries and then the entry
/// closest to expiry.
///
/// ```
/// use std::time::{Duration, Instant};
/// use rune_rdap::cache::TtlCache;
///
/// let mut cache = TtlCache::new(16);
/// let t0 = Instant::now();
/// cache.insert("k", 1, Duration::from_secs(60), t0);
/// assert_eq!(cache.get("k", t0 + Duration::from_secs(59)), Some(&1));
/// assert_eq!(cache.get("k", t0 + Duration::from_secs(60)), None);
/// ```
#[derive(Debug, Clone)]
pub struct TtlCache<V> {
    capacity: usize,
    entries: HashMap<String, (Instant, V)>,
}

impl<V> TtlCache<V> {
    /// A cache of at most `capacity` entries (0 disables caching).
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            entries: HashMap::new(),
        }
    }

    /// The live value for `key` at `now`.
    #[must_use]
    pub fn get(&self, key: &str, now: Instant) -> Option<&V> {
        self.entries
            .get(key)
            .filter(|(expires, _)| *expires > now)
            .map(|(_, v)| v)
    }

    /// Stores `value` for `ttl` from `now`. A zero `ttl` stores nothing
    /// (and drops any older value).
    pub fn insert(&mut self, key: impl Into<String>, value: V, ttl: Duration, now: Instant) {
        let key = key.into();
        let Some(expires) = now.checked_add(ttl).filter(|_| !ttl.is_zero()) else {
            self.entries.remove(&key);
            return;
        };
        if self.capacity == 0 {
            return;
        }
        if !self.entries.contains_key(&key) && self.entries.len() >= self.capacity {
            self.entries.retain(|_, (at, _)| *at > now);
            if self.entries.len() >= self.capacity
                && let Some(oldest) = self
                    .entries
                    .iter()
                    .min_by_key(|(_, (at, _))| *at)
                    .map(|(k, _)| k.clone())
            {
                self.entries.remove(&oldest);
            }
        }
        self.entries.insert(key, (expires, value));
    }

    /// Removes `key`.
    pub fn remove(&mut self, key: &str) -> Option<V> {
        self.entries.remove(key).map(|(_, v)| v)
    }

    /// Removes everything.
    pub fn clear(&mut self) {
        self.entries.clear();
    }

    /// The number of stored entries, expired ones included.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether nothing is stored.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn evicts_when_full() {
        let s = Duration::from_secs;
        let t0 = Instant::now();
        let mut c = TtlCache::new(2);
        c.insert("a", 1, s(10), t0);
        c.insert("b", 2, s(20), t0);
        c.insert("c", 3, s(30), t0);
        assert_eq!(c.len(), 2);
        assert_eq!(c.get("a", t0), None, "closest to expiry goes first");
        assert_eq!(c.get("c", t0), Some(&3));
        // Expired entries make room before live ones are evicted.
        c.insert("d", 4, s(5), t0 + s(25));
        assert_eq!(c.get("c", t0 + s(25)), Some(&3));
        assert_eq!(c.get("d", t0 + s(25)), Some(&4));
    }

    #[test]
    fn zero_ttl_and_capacity() {
        let t0 = Instant::now();
        let mut c = TtlCache::new(0);
        c.insert("a", 1, Duration::from_secs(1), t0);
        assert!(c.is_empty());
        let mut c = TtlCache::new(4);
        c.insert("a", 1, Duration::from_secs(1), t0);
        c.insert("a", 2, Duration::ZERO, t0);
        assert!(c.is_empty());
        c.insert("a", 1, Duration::MAX, t0);
        assert!(c.is_empty(), "an unrepresentable expiry is not cached");
        c.insert("b", 1, Duration::from_secs(1), t0);
        assert_eq!(c.remove("b"), Some(1));
        c.insert("b", 1, Duration::from_secs(1), t0);
        c.clear();
        assert!(c.is_empty());
    }
}
