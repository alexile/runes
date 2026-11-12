//! Idempotency/dedup filter over a keyed, windowed stream.
//!
//! Tracks the most recent time each key was seen and reports whether a new
//! occurrence falls inside a trailing time window — the classic building block for
//! at-least-once delivery systems that need at-most-once processing downstream
//! (retried webhooks, redelivered queue messages, flaky sensor uplinks).
//!
//! # Features
//!
//! - [`Dedupe::check`] — records a key/time pair and reports whether it's a duplicate.
//! - Explicit `Instant` input (no internal clock), so behavior is fully deterministic
//!   and testable.
//! - Lazy expiry: stale entries are purged as part of `check`, so memory stays bounded
//!   by the number of *distinct* keys seen within the trailing window, not the total
//!   number of events ever processed.
//!
//! # Quick Start
//!
//! ```rust
//! use rune_dedupe::Dedupe;
//! use std::time::{Duration, Instant};
//!
//! let start = Instant::now();
//! let mut dedupe = Dedupe::new(Duration::from_secs(60));
//!
//! assert!(dedupe.check("msg-1", start), "first time seeing this key");
//! assert!(!dedupe.check("msg-1", start + Duration::from_secs(1)), "duplicate within window");
//! assert!(dedupe.check("msg-1", start + Duration::from_secs(61)), "window elapsed, not a duplicate");
//! ```
//!
//! # CLI
//!
//! ```bash
//! rune-dedupe --window-secs 60 keys.txt
//! cat keys.txt | rune-dedupe --window-secs 60 -
//! ```

use std::collections::HashMap;
use std::hash::Hash;
use std::time::{Duration, Instant};

/// A deduplicator over keys of type `K`, tracking a trailing `window` of time.
pub struct Dedupe<K> {
    window: Duration,
    seen: HashMap<K, Instant>,
}

impl<K: Eq + Hash + Clone> Dedupe<K> {
    /// Creates a deduplicator that treats a key as a duplicate if it was last seen
    /// within `window` of the current check.
    #[must_use]
    pub fn new(window: Duration) -> Self {
        Self {
            window,
            seen: HashMap::new(),
        }
    }

    /// Checks `key` at time `at`. Returns `true` if this is the first time `key` has
    /// been seen within the trailing window (records it), or `false` if it's a
    /// duplicate (seen within the window already — its expiry is *not* reset).
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_dedupe::Dedupe;
    /// use std::time::{Duration, Instant};
    ///
    /// let start = Instant::now();
    /// let mut dedupe = Dedupe::new(Duration::from_secs(10));
    /// assert!(dedupe.check("a", start));
    /// assert!(!dedupe.check("a", start + Duration::from_secs(5)));
    /// ```
    pub fn check(&mut self, key: K, at: Instant) -> bool {
        self.purge_expired(at);

        match self.seen.get(&key) {
            Some(&last_seen) if at.saturating_duration_since(last_seen) <= self.window => false,
            _ => {
                self.seen.insert(key, at);
                true
            }
        }
    }

    /// Number of distinct keys currently tracked (i.e. seen within the trailing window
    /// as of the last `check` call).
    #[must_use]
    pub fn len(&self) -> usize {
        self.seen.len()
    }

    /// Whether no keys are currently tracked.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }

    fn purge_expired(&mut self, now: Instant) {
        let window = self.window;
        self.seen
            .retain(|_, &mut last_seen| now.saturating_duration_since(last_seen) <= window);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_occurrence_is_not_a_duplicate() {
        let mut dedupe = Dedupe::new(Duration::from_secs(10));
        assert!(dedupe.check("a", Instant::now()));
    }

    #[test]
    fn immediate_repeat_is_a_duplicate() {
        let start = Instant::now();
        let mut dedupe = Dedupe::new(Duration::from_secs(10));
        assert!(dedupe.check("a", start));
        assert!(!dedupe.check("a", start + Duration::from_millis(1)));
    }

    #[test]
    fn repeat_after_window_elapsed_is_not_a_duplicate() {
        let start = Instant::now();
        let mut dedupe = Dedupe::new(Duration::from_secs(10));
        assert!(dedupe.check("a", start));
        assert!(dedupe.check("a", start + Duration::from_secs(11)));
    }

    #[test]
    fn repeat_exactly_at_window_boundary_is_still_a_duplicate() {
        let start = Instant::now();
        let mut dedupe = Dedupe::new(Duration::from_secs(10));
        assert!(dedupe.check("a", start));
        assert!(!dedupe.check("a", start + Duration::from_secs(10)));
    }

    #[test]
    fn distinct_keys_tracked_independently() {
        let start = Instant::now();
        let mut dedupe = Dedupe::new(Duration::from_secs(10));
        assert!(dedupe.check("a", start));
        assert!(dedupe.check("b", start));
        assert!(!dedupe.check("a", start + Duration::from_secs(1)));
        assert!(!dedupe.check("b", start + Duration::from_secs(1)));
    }

    #[test]
    fn duplicate_check_does_not_reset_expiry() {
        let start = Instant::now();
        let mut dedupe = Dedupe::new(Duration::from_secs(10));
        assert!(dedupe.check("a", start));
        assert!(
            !dedupe.check("a", start + Duration::from_secs(5)),
            "still a duplicate"
        );
        // Expiry should still be relative to the original `start`, not the check at +5s.
        assert!(
            dedupe.check("a", start + Duration::from_secs(11)),
            "window elapsed from original insert"
        );
    }

    #[test]
    fn purge_keeps_memory_bounded_and_fresh_keys_unaffected() {
        let start = Instant::now();
        let mut dedupe = Dedupe::new(Duration::from_secs(10));

        for i in 0..1000 {
            dedupe.check(i, start);
        }
        assert_eq!(dedupe.len(), 1000);

        // Long after the window: a fresh key still behaves correctly, and the purge
        // sweeps out all the now-expired entries instead of growing forever.
        let far_future = start + Duration::from_secs(1000);
        assert!(dedupe.check(999_999, far_future));
        assert_eq!(
            dedupe.len(),
            1,
            "all expired entries purged, only the fresh key remains"
        );
    }

    #[test]
    fn empty_dedupe_reports_empty() {
        let dedupe: Dedupe<&str> = Dedupe::new(Duration::from_secs(10));
        assert!(dedupe.is_empty());
        assert_eq!(dedupe.len(), 0);
    }

    // ── Window boundaries ────────────────────────────────────────────────────

    #[test]
    fn one_nanosecond_past_window_is_fresh() {
        let start = Instant::now();
        let window = Duration::from_secs(10);
        let mut dedupe = Dedupe::new(window);
        assert!(dedupe.check("a", start));
        assert!(!dedupe.check("a", start + window));
        assert!(dedupe.check("a", start + window + Duration::from_nanos(1)));
    }

    #[test]
    fn zero_window_only_dedupes_same_instant() {
        let start = Instant::now();
        let mut dedupe = Dedupe::new(Duration::ZERO);
        assert!(dedupe.check("a", start));
        assert!(!dedupe.check("a", start));
        assert!(dedupe.check("a", start + Duration::from_nanos(1)));
    }

    #[test]
    fn earlier_timestamp_is_treated_as_duplicate() {
        // Clock skew: a check "before" the recorded time is within the window.
        let earlier = Instant::now();
        let later = earlier + Duration::from_secs(50);
        let mut dedupe = Dedupe::new(Duration::from_secs(1));
        assert!(dedupe.check("a", later));
        assert!(!dedupe.check("a", earlier));
    }

    #[test]
    fn reaccepted_key_starts_a_new_window() {
        let start = Instant::now();
        let mut dedupe = Dedupe::new(Duration::from_secs(10));
        assert!(dedupe.check("a", start));
        let again = start + Duration::from_secs(11);
        assert!(dedupe.check("a", again));
        assert!(!dedupe.check("a", again + Duration::from_secs(10)));
        assert!(dedupe.check("a", again + Duration::from_secs(11)));
    }

    #[test]
    fn purge_is_per_key() {
        let start = Instant::now();
        let mut dedupe = Dedupe::new(Duration::from_secs(10));
        dedupe.check("old", start);
        dedupe.check("new", start + Duration::from_secs(8));
        // At +12s "old" expired, "new" has not.
        assert!(dedupe.check("other", start + Duration::from_secs(12)));
        assert_eq!(dedupe.len(), 2);
        assert!(!dedupe.check("new", start + Duration::from_secs(12)));
    }
}
