//! Liveness tracking for a keyed stream of heartbeat pings.
//!
//! Fleets of devices, workers, or connections each send periodic pings under
//! their own key. `HeartbeatMonitor` records the last-seen time per key and,
//! given a point in time, reports which previously-seen keys have gone silent
//! for longer than the configured timeout.
//!
//! A key that has never pinged is not "missing" — it's simply unknown. Only
//! keys that pinged at least once and then exceeded the timeout are reported.
//!
//! Time is passed in explicitly rather than read from the system clock, so
//! callers (and tests) stay fully deterministic.
//!
//! # Features
//!
//! - [`HeartbeatMonitor::ping`] — record a liveness signal for a key at a given time.
//! - [`HeartbeatMonitor::missing`] — the keys silent for longer than the timeout,
//!   as of a given time.
//!
//! # Quick Start
//!
//! ```rust
//! use rune_heartbeat::HeartbeatMonitor;
//! use std::time::{Duration, Instant};
//!
//! let start = Instant::now();
//! let mut monitor = HeartbeatMonitor::new(Duration::from_secs(5));
//! monitor.ping("device-1", start);
//!
//! assert!(monitor.missing(start + Duration::from_secs(1)).is_empty());
//! assert_eq!(monitor.missing(start + Duration::from_secs(6)), vec!["device-1"]);
//! ```
//!
//! # CLI
//!
//! ```bash
//! printf 'device-1 0\ndevice-2 100\n' | rune-heartbeat --timeout-ms 500 --now-ms 700
//! ```

use std::collections::HashMap;
use std::hash::Hash;
use std::time::{Duration, Instant};

/// Tracks last-seen times per key and reports which keys have gone silent.
pub struct HeartbeatMonitor<K> {
    timeout: Duration,
    last_seen: HashMap<K, Instant>,
}

impl<K: Eq + Hash + Clone> HeartbeatMonitor<K> {
    /// Creates a monitor that considers a key missing once more than `timeout`
    /// has elapsed since its last ping.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_heartbeat::HeartbeatMonitor;
    /// use std::time::Duration;
    ///
    /// let monitor = HeartbeatMonitor::<&str>::new(Duration::from_secs(30));
    /// ```
    #[must_use]
    pub fn new(timeout: Duration) -> Self {
        Self {
            timeout,
            last_seen: HashMap::new(),
        }
    }

    /// Records a liveness signal for `key` at time `at`. Overwrites any earlier
    /// recorded time for the same key.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_heartbeat::HeartbeatMonitor;
    /// use std::time::{Duration, Instant};
    ///
    /// let mut monitor = HeartbeatMonitor::new(Duration::from_secs(5));
    /// monitor.ping("device-1", Instant::now());
    /// ```
    pub fn ping(&mut self, key: K, at: Instant) {
        self.last_seen.insert(key, at);
    }

    /// Returns the keys that have pinged at least once but whose last ping is
    /// more than `timeout` before `now`. Order is unspecified.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_heartbeat::HeartbeatMonitor;
    /// use std::time::{Duration, Instant};
    ///
    /// let start = Instant::now();
    /// let mut monitor = HeartbeatMonitor::new(Duration::from_secs(1));
    /// monitor.ping("a", start);
    /// assert!(monitor.missing(start + Duration::from_millis(500)).is_empty());
    /// ```
    #[must_use]
    pub fn missing(&self, now: Instant) -> Vec<K> {
        self.last_seen
            .iter()
            .filter(|&(_, &last)| now.duration_since(last) >= self.timeout)
            .map(|(key, _)| key.clone())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_not_missing_before_timeout() {
        let start = Instant::now();
        let mut monitor = HeartbeatMonitor::new(Duration::from_secs(5));
        monitor.ping("a", start);
        assert_eq!(
            monitor.missing(start + Duration::from_secs(4)),
            [] as [&str; 0]
        );
    }

    #[test]
    fn key_missing_after_timeout() {
        let start = Instant::now();
        let mut monitor = HeartbeatMonitor::new(Duration::from_secs(5));
        monitor.ping("a", start);
        assert_eq!(monitor.missing(start + Duration::from_secs(6)), vec!["a"]);
    }

    #[test]
    fn key_missing_exactly_at_timeout_boundary() {
        let start = Instant::now();
        let mut monitor = HeartbeatMonitor::new(Duration::from_secs(5));
        monitor.ping("a", start);
        assert_eq!(monitor.missing(start + Duration::from_secs(5)), vec!["a"]);
    }

    #[test]
    fn multiple_keys_with_different_last_ping_times() {
        let start = Instant::now();
        let mut monitor = HeartbeatMonitor::new(Duration::from_secs(5));
        monitor.ping("stale", start);
        monitor.ping("fresh", start + Duration::from_secs(4));

        let missing = monitor.missing(start + Duration::from_secs(6));
        assert_eq!(missing, vec!["stale"]);
    }

    #[test]
    fn re_ping_resets_liveness() {
        let start = Instant::now();
        let mut monitor = HeartbeatMonitor::new(Duration::from_secs(5));
        monitor.ping("a", start);
        monitor.ping("a", start + Duration::from_secs(3));

        assert_eq!(
            monitor.missing(start + Duration::from_secs(6)),
            [] as [&str; 0]
        );
    }

    #[test]
    fn unknown_key_is_never_reported_missing() {
        let start = Instant::now();
        let monitor = HeartbeatMonitor::<&str>::new(Duration::from_secs(5));
        assert_eq!(
            monitor.missing(start + Duration::from_secs(100)),
            [] as [&str; 0]
        );
    }
}
