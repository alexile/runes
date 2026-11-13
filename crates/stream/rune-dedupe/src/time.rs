//! Clock abstraction shared by every deduplicator in the crate.

use std::time::{Duration, Instant, SystemTime};

/// A point in time the deduplicators can measure distances between.
///
/// Implemented for [`Instant`] (processing time, in-process only),
/// [`SystemTime`] (wall clock, serializable) and the integer types `i64` and
/// `u64`, which are read as **milliseconds**. `i64` milliseconds is the same
/// representation `rune-watermark` uses for event time, so its watermarks can be
/// passed straight to [`EventTimeDedupe::advance_watermark`](crate::EventTimeDedupe::advance_watermark).
///
/// # Example
///
/// ```rust
/// use rune_dedupe::Timestamp;
/// use std::time::Duration;
///
/// assert_eq!(1_500_i64.saturating_since(1_000), Duration::from_millis(500));
/// assert_eq!(1_000_i64.saturating_since(1_500), Duration::ZERO);
/// ```
pub trait Timestamp: Copy + Ord {
    /// How much later `self` is than `earlier`, or zero if `self` is not later.
    fn saturating_since(self, earlier: Self) -> Duration;
}

impl Timestamp for Instant {
    fn saturating_since(self, earlier: Self) -> Duration {
        self.saturating_duration_since(earlier)
    }
}

impl Timestamp for SystemTime {
    fn saturating_since(self, earlier: Self) -> Duration {
        self.duration_since(earlier).unwrap_or(Duration::ZERO)
    }
}

impl Timestamp for i64 {
    fn saturating_since(self, earlier: Self) -> Duration {
        if self <= earlier {
            Duration::ZERO
        } else {
            Duration::from_millis(self.abs_diff(earlier))
        }
    }
}

impl Timestamp for u64 {
    fn saturating_since(self, earlier: Self) -> Duration {
        Duration::from_millis(self.saturating_sub(earlier))
    }
}

/// Whether `a` and `b` are at most `window` apart, in either direction.
pub fn within<T: Timestamp>(a: T, b: T, window: Duration) -> bool {
    a.saturating_since(b) <= window && b.saturating_since(a) <= window
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn integer_millis_saturate() {
        assert_eq!(
            i64::MAX.saturating_since(i64::MIN),
            Duration::from_millis(u64::MAX)
        );
        assert_eq!(5_u64.saturating_since(9), Duration::ZERO);
        assert_eq!(9_u64.saturating_since(5), Duration::from_millis(4));
    }

    #[test]
    fn system_time_saturates() {
        let now = SystemTime::now();
        let later = now + Duration::from_secs(3);
        assert_eq!(later.saturating_since(now), Duration::from_secs(3));
        assert_eq!(now.saturating_since(later), Duration::ZERO);
    }

    #[test]
    fn within_is_symmetric() {
        let w = Duration::from_millis(10);
        assert!(within(0_i64, 10, w));
        assert!(within(10_i64, 0, w));
        assert!(!within(0_i64, 11, w));
        assert!(!within(11_i64, 0, w));
    }
}
