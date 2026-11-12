//! Dead-letter queue with configurable backoff retry for failed sink writes.
//!
//! When a write to a downstream sink fails, [`RetryQueue`] schedules it for another
//! attempt after a delay determined by a [`BackoffPolicy`], up to a configurable
//! maximum number of attempts. Items that exhaust their attempts are routed to a
//! dead-letter list instead of being rescheduled. Time is always passed in explicitly
//! (`std::time::Instant`), so the queue is fully deterministic and easy to test —
//! it never calls `Instant::now()` internally.
//!
//! # Features
//!
//! - [`BackoffPolicy::Fixed`] and [`BackoffPolicy::Exponential`] (with a cap).
//! - [`RetryQueue::push`] — schedule a failed item for retry, or dead-letter it if
//!   its attempt count has exhausted `max_attempts`.
//! - [`RetryQueue::ready`] — drain every item whose scheduled retry time has arrived.
//! - [`RetryQueue::dead_letters`] / [`RetryQueue::drain_dead_letters`] — inspect or
//!   drain items that gave up.
//!
//! # Quick Start
//!
//! ```rust
//! use rune_retry_queue::{BackoffPolicy, RetryQueue};
//! use std::time::{Duration, Instant};
//!
//! let mut queue = RetryQueue::new(BackoffPolicy::Fixed(Duration::from_secs(1)), 3);
//! let t0 = Instant::now();
//!
//! queue.push("payload", 0, t0);
//! assert!(queue.ready(t0).is_empty(), "not due yet");
//!
//! let due = queue.ready(t0 + Duration::from_secs(1));
//! assert_eq!(due, vec![("payload", 0)]);
//! ```
//!
//! # CLI
//!
//! ```bash
//! rune-retry-queue --policy fixed --delay-ms 1000 --max-attempts 3
//! ```

use std::cmp::Ordering;
use std::collections::BinaryHeap;
use std::collections::binary_heap::PeekMut;
use std::time::{Duration, Instant};

/// A retry-delay schedule.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum BackoffPolicy {
    /// Always wait the same duration before retrying.
    Fixed(Duration),
    /// Wait `base * factor^attempt`, capped at `max`.
    Exponential {
        /// Delay for attempt `0`.
        base: Duration,
        /// Multiplier applied per attempt.
        factor: f64,
        /// Upper bound on the computed delay.
        max: Duration,
    },
}

impl BackoffPolicy {
    /// Computes the delay before retrying, given a 0-indexed `attempt` number
    /// (the attempt that just failed; `0` is the first attempt).
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_retry_queue::BackoffPolicy;
    /// use std::time::Duration;
    ///
    /// let policy = BackoffPolicy::Exponential {
    ///     base: Duration::from_secs(1),
    ///     factor: 2.0,
    ///     max: Duration::from_secs(10),
    /// };
    /// assert_eq!(policy.delay_for(0), Duration::from_secs(1));
    /// assert_eq!(policy.delay_for(1), Duration::from_secs(2));
    /// assert_eq!(policy.delay_for(10), Duration::from_secs(10)); // capped
    /// ```
    #[allow(
        clippy::cast_possible_wrap,
        reason = "attempt counts and delays are small; float-to-int `as` saturates"
    )]
    #[must_use]
    pub fn delay_for(&self, attempt: u32) -> Duration {
        match self {
            Self::Fixed(delay) => *delay,
            Self::Exponential { base, factor, max } => {
                let multiplier = factor.powi(attempt as i32);
                let scaled_secs = (base.as_secs_f64() * multiplier).max(0.0);
                let capped_secs = scaled_secs.min(max.as_secs_f64());
                Duration::from_secs_f64(capped_secs)
            }
        }
    }
}

struct Entry<T> {
    scheduled_at: Instant,
    attempt: u32,
    item: T,
}

impl<T> PartialEq for Entry<T> {
    fn eq(&self, other: &Self) -> bool {
        self.scheduled_at == other.scheduled_at
    }
}

impl<T> Eq for Entry<T> {}

impl<T> PartialOrd for Entry<T> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<T> Ord for Entry<T> {
    fn cmp(&self, other: &Self) -> Ordering {
        // Reversed so `BinaryHeap` (a max-heap) pops the earliest `scheduled_at` first.
        other.scheduled_at.cmp(&self.scheduled_at)
    }
}

/// A retry schedule plus a dead-letter list, driven entirely by explicit `Instant`s.
pub struct RetryQueue<T> {
    backoff: BackoffPolicy,
    max_attempts: u32,
    scheduled: BinaryHeap<Entry<T>>,
    dead_letters: Vec<T>,
}

impl<T> RetryQueue<T> {
    /// Creates an empty queue with the given backoff policy and attempt cap.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_retry_queue::{BackoffPolicy, RetryQueue};
    /// use std::time::Duration;
    ///
    /// let queue: RetryQueue<&str> =
    ///     RetryQueue::new(BackoffPolicy::Fixed(Duration::from_secs(1)), 5);
    /// assert!(queue.dead_letters().is_empty());
    /// ```
    #[must_use]
    pub const fn new(backoff: BackoffPolicy, max_attempts: u32) -> Self {
        Self {
            backoff,
            max_attempts,
            scheduled: BinaryHeap::new(),
            dead_letters: Vec::new(),
        }
    }

    /// Pushes a failed `item` that had just made attempt number `attempt` (0-indexed).
    ///
    /// If `attempt >= max_attempts`, the item goes straight to the dead-letter list.
    /// Otherwise it's scheduled to retry at `now + backoff.delay_for(attempt)`.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_retry_queue::{BackoffPolicy, RetryQueue};
    /// use std::time::{Duration, Instant};
    ///
    /// let mut queue = RetryQueue::new(BackoffPolicy::Fixed(Duration::from_millis(10)), 1);
    /// let t0 = Instant::now();
    /// queue.push("exhausted", 1, t0); // attempt == max_attempts
    /// assert_eq!(queue.dead_letters(), &["exhausted"]);
    /// ```
    pub fn push(&mut self, item: T, attempt: u32, now: Instant) {
        if attempt >= self.max_attempts {
            self.dead_letters.push(item);
            return;
        }
        let scheduled_at = now + self.backoff.delay_for(attempt);
        self.scheduled.push(Entry {
            scheduled_at,
            attempt,
            item,
        });
    }

    /// Drains and returns every item whose scheduled retry time is at or before `now`,
    /// paired with the attempt count it was scheduled with. Callers should re-push
    /// with `attempt + 1` if the retry fails again.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_retry_queue::{BackoffPolicy, RetryQueue};
    /// use std::time::{Duration, Instant};
    ///
    /// let mut queue = RetryQueue::new(BackoffPolicy::Fixed(Duration::from_secs(1)), 3);
    /// let t0 = Instant::now();
    /// queue.push("a", 0, t0);
    /// assert!(queue.ready(t0).is_empty());
    /// assert_eq!(queue.ready(t0 + Duration::from_secs(1)), vec![("a", 0)]);
    /// ```
    pub fn ready(&mut self, now: Instant) -> Vec<(T, u32)> {
        let mut due = Vec::new();
        while let Some(top) = self.scheduled.peek_mut() {
            if top.scheduled_at > now {
                break;
            }
            let entry = PeekMut::pop(top);
            due.push((entry.item, entry.attempt));
        }
        due
    }

    /// Items that exhausted `max_attempts`, in the order they were dead-lettered.
    #[must_use]
    pub fn dead_letters(&self) -> &[T] {
        &self.dead_letters
    }

    /// Removes and returns all dead-lettered items.
    pub fn drain_dead_letters(&mut self) -> Vec<T> {
        std::mem::take(&mut self.dead_letters)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_backoff_not_ready_before_delay() {
        let mut queue = RetryQueue::new(BackoffPolicy::Fixed(Duration::from_secs(1)), 3);
        let t0 = Instant::now();
        queue.push("a", 0, t0);
        assert_eq!(queue.ready(t0), [] as [(&str, u32); 0]);
        assert_eq!(
            queue.ready(t0 + Duration::from_millis(999)),
            [] as [(&str, u32); 0]
        );
    }

    #[test]
    fn fixed_backoff_ready_after_delay() {
        let mut queue = RetryQueue::new(BackoffPolicy::Fixed(Duration::from_secs(1)), 3);
        let t0 = Instant::now();
        queue.push("a", 0, t0);
        assert_eq!(queue.ready(t0 + Duration::from_secs(1)), vec![("a", 0)]);
    }

    #[test]
    fn exponential_backoff_grows_and_caps() {
        let policy = BackoffPolicy::Exponential {
            base: Duration::from_secs(1),
            factor: 2.0,
            max: Duration::from_secs(10),
        };
        assert_eq!(policy.delay_for(0), Duration::from_secs(1));
        assert_eq!(policy.delay_for(1), Duration::from_secs(2));
        assert_eq!(policy.delay_for(2), Duration::from_secs(4));
        assert_eq!(policy.delay_for(3), Duration::from_secs(8));
        assert_eq!(
            policy.delay_for(4),
            Duration::from_secs(10),
            "capped at max"
        );
        assert_eq!(
            policy.delay_for(10),
            Duration::from_secs(10),
            "stays capped"
        );
    }

    #[test]
    fn attempt_at_or_above_max_goes_straight_to_dead_letters() {
        let mut queue = RetryQueue::new(BackoffPolicy::Fixed(Duration::from_secs(1)), 3);
        let t0 = Instant::now();
        queue.push("exhausted", 3, t0);
        assert_eq!(queue.dead_letters(), &["exhausted"]);
        assert_eq!(
            queue.ready(t0 + Duration::from_secs(100)),
            [] as [(&str, u32); 0]
        );
    }

    #[test]
    fn attempt_below_max_is_scheduled_not_dead_lettered() {
        let mut queue = RetryQueue::new(BackoffPolicy::Fixed(Duration::from_secs(1)), 3);
        let t0 = Instant::now();
        queue.push("retry-me", 2, t0);
        assert_eq!(queue.dead_letters(), [] as [&str; 0]);
        assert_eq!(
            queue.ready(t0 + Duration::from_secs(1)),
            vec![("retry-me", 2)]
        );
    }

    #[test]
    fn ready_only_returns_due_items_leaving_others_queued() {
        let mut queue = RetryQueue::new(BackoffPolicy::Fixed(Duration::from_secs(2)), 5);
        let t0 = Instant::now();
        queue.push("soon", 0, t0);
        queue.push("later", 0, t0 + Duration::from_secs(5));

        let due = queue.ready(t0 + Duration::from_secs(2));
        assert_eq!(due, vec![("soon", 0)]);

        assert_eq!(
            queue.ready(t0 + Duration::from_secs(3)),
            [] as [(&str, u32); 0]
        );

        let due_later = queue.ready(t0 + Duration::from_secs(7));
        assert_eq!(due_later, vec![("later", 0)]);
    }

    #[test]
    fn multiple_ready_items_returned_together() {
        let mut queue = RetryQueue::new(BackoffPolicy::Fixed(Duration::from_secs(1)), 5);
        let t0 = Instant::now();
        queue.push("a", 0, t0);
        queue.push("b", 0, t0);
        queue.push("c", 0, t0 + Duration::from_secs(10)); // stays queued

        let mut due = queue.ready(t0 + Duration::from_secs(1));
        due.sort_by_key(|(item, _)| *item);
        assert_eq!(due, vec![("a", 0), ("b", 0)]);
    }

    #[test]
    fn drain_dead_letters_empties_the_list() {
        let mut queue = RetryQueue::new(BackoffPolicy::Fixed(Duration::from_secs(1)), 1);
        let t0 = Instant::now();
        queue.push("x", 1, t0);
        queue.push("y", 1, t0);
        let drained = queue.drain_dead_letters();
        assert_eq!(drained, vec!["x", "y"]);
        assert_eq!(queue.dead_letters(), [] as [&str; 0]);
    }
}
