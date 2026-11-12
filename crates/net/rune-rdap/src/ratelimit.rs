//! A per-host request spacer, sans I/O: it is told the time and answers
//! how long to wait.

use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Hosts tracked before idle ones are dropped.
const PRUNE_AT: usize = 1024;

/// Spaces requests to each host at least `interval` apart, and holds a
/// host back after it answered `429 Too Many Requests`.
///
/// ```
/// use std::time::{Duration, Instant};
/// use rune_rdap::ratelimit::RateLimiter;
///
/// let mut limiter = RateLimiter::new(Duration::from_secs(1));
/// let t0 = Instant::now();
/// assert_eq!(limiter.reserve("rdap.arin.net", t0), Duration::ZERO);
/// assert_eq!(limiter.reserve("rdap.arin.net", t0), Duration::from_secs(1));
/// assert_eq!(limiter.reserve("rdap.db.ripe.net", t0), Duration::ZERO);
/// ```
#[derive(Debug, Clone)]
pub struct RateLimiter {
    interval: Duration,
    next: HashMap<String, Instant>,
}

impl RateLimiter {
    /// A limiter that spaces requests to one host by `interval`
    /// (`Duration::ZERO` disables spacing; `429` hold-offs still apply).
    #[must_use]
    pub fn new(interval: Duration) -> Self {
        Self {
            interval,
            next: HashMap::new(),
        }
    }

    /// The spacing between requests to one host.
    #[must_use]
    pub const fn interval(&self) -> Duration {
        self.interval
    }

    /// Books the next slot for `host` and returns how long to wait from
    /// `now` until it.
    pub fn reserve(&mut self, host: &str, now: Instant) -> Duration {
        if self.next.len() >= PRUNE_AT {
            self.next.retain(|_, at| *at > now);
        }
        let host = host.to_ascii_lowercase();
        let slot = self.next.get(&host).map_or(now, |&at| at.max(now));
        self.next
            .insert(host, slot.checked_add(self.interval).unwrap_or(slot));
        slot.saturating_duration_since(now)
    }

    /// Holds `host` back until at least `until` (after a `429`).
    pub fn defer(&mut self, host: &str, until: Instant) {
        let entry = self.next.entry(host.to_ascii_lowercase()).or_insert(until);
        *entry = (*entry).max(until);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spaces_and_defers() {
        let s = Duration::from_secs;
        let mut l = RateLimiter::new(s(2));
        let t0 = Instant::now();
        assert_eq!(l.reserve("A", t0), Duration::ZERO);
        assert_eq!(l.reserve("a", t0), s(2));
        assert_eq!(l.reserve("a", t0 + s(1)), s(3));
        // Idle long enough: no wait.
        assert_eq!(l.reserve("a", t0 + s(60)), Duration::ZERO);
        l.defer("a", t0 + s(100));
        assert_eq!(l.reserve("a", t0 + s(61)), s(39));
        // A defer earlier than the booked slot changes nothing.
        l.defer("a", t0);
        assert_eq!(l.reserve("a", t0 + s(100)), s(2));
    }

    #[test]
    fn zero_interval_and_pruning() {
        let mut l = RateLimiter::new(Duration::ZERO);
        let t0 = Instant::now();
        for i in 0..2 * PRUNE_AT {
            assert_eq!(l.reserve(&i.to_string(), t0), Duration::ZERO);
        }
        assert!(l.next.len() <= PRUNE_AT + 1);
    }
}
