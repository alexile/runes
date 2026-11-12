//! Late-arrival/watermark tracking for out-of-order event streams.
//!
//! A watermark is a moving lower bound on event time: "no event with a timestamp
//! before this point should still be coming." `WatermarkTracker` maintains that
//! bound as `max_ts_seen - allowed_lateness`, and classifies each newly observed
//! timestamp as on-time or late relative to the watermark at the moment it arrives.
//!
//! # Features
//!
//! - [`WatermarkTracker::observe`] — feed one timestamp, get back its [`Lateness`].
//! - [`WatermarkTracker::watermark`] — read the current watermark without observing.
//! - Configurable allowed lateness, including `0` for strict monotonic enforcement.
//!
//! # Quick Start
//!
//! ```rust
//! use rune_watermark::{WatermarkTracker, Lateness};
//!
//! let mut tracker = WatermarkTracker::new(1_000);
//!
//! assert_eq!(tracker.observe(5_000), Lateness::OnTime);
//! assert_eq!(tracker.observe(6_000), Lateness::OnTime);
//!
//! // watermark is now 6_000 - 1_000 = 5_000; this event arrives behind it.
//! assert_eq!(tracker.observe(4_000), Lateness::Late { by_ms: 1_000 });
//! ```
//!
//! # CLI
//!
//! ```bash
//! rune-watermark --allowed-lateness 1000 timestamps.txt
//! cat timestamps.txt | rune-watermark --allowed-lateness 1000 -
//! ```

/// Whether an observed timestamp arrived on time or behind the current watermark.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lateness {
    /// The timestamp was at or ahead of the watermark when observed.
    OnTime,
    /// The timestamp was behind the watermark by `by_ms` milliseconds when observed.
    Late {
        /// How many milliseconds behind the watermark this event arrived.
        by_ms: i64,
    },
}

/// Tracks a moving watermark over a stream of millisecond timestamps.
///
/// The watermark is `max_ts_seen - allowed_lateness_ms`. It only ever moves forward:
/// observing a timestamp behind the current watermark reports it as late but does not
/// move the watermark backward, and does not raise `max_ts_seen`.
pub struct WatermarkTracker {
    allowed_lateness_ms: i64,
    max_ts_seen: Option<i64>,
}

impl WatermarkTracker {
    /// Creates a tracker with the given allowed lateness, in milliseconds.
    ///
    /// An `allowed_lateness_ms` of `0` makes the watermark equal to `max_ts_seen`,
    /// so any timestamp not greater than or equal to the running maximum is late —
    /// i.e. strict monotonic enforcement.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_watermark::WatermarkTracker;
    ///
    /// let tracker = WatermarkTracker::new(500);
    /// assert_eq!(tracker.watermark(), None);
    /// ```
    #[must_use]
    pub const fn new(allowed_lateness_ms: i64) -> Self {
        Self {
            allowed_lateness_ms,
            max_ts_seen: None,
        }
    }

    /// Returns the current watermark, or `None` if no timestamp has been observed yet.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_watermark::WatermarkTracker;
    ///
    /// let mut tracker = WatermarkTracker::new(100);
    /// tracker.observe(1_000);
    /// assert_eq!(tracker.watermark(), Some(900));
    /// ```
    #[must_use]
    pub fn watermark(&self) -> Option<i64> {
        self.max_ts_seen
            .map(|max_ts| max_ts.saturating_sub(self.allowed_lateness_ms))
    }

    /// Observes one timestamp and classifies it relative to the watermark *before*
    /// this observation is applied.
    ///
    /// If `ts_ms` is a new high, `max_ts_seen` (and therefore the watermark) advances.
    /// A late timestamp never moves the watermark backward and never lowers
    /// `max_ts_seen`.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_watermark::{WatermarkTracker, Lateness};
    ///
    /// let mut tracker = WatermarkTracker::new(0);
    /// assert_eq!(tracker.observe(10), Lateness::OnTime);
    /// assert_eq!(tracker.observe(9), Lateness::Late { by_ms: 1 });
    /// ```
    pub fn observe(&mut self, ts_ms: i64) -> Lateness {
        let lateness = match self.watermark() {
            Some(wm) if ts_ms < wm => Lateness::Late {
                by_ms: wm.saturating_sub(ts_ms),
            },
            _ => Lateness::OnTime,
        };

        let is_new_high = self.max_ts_seen.is_none_or(|max_ts| ts_ms > max_ts);
        if is_new_high {
            self.max_ts_seen = Some(ts_ms);
        }

        lateness
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fresh_tracker_has_no_watermark() {
        let tracker = WatermarkTracker::new(1_000);
        assert_eq!(tracker.watermark(), None);
    }

    #[test]
    fn monotonic_stream_is_always_on_time() {
        let mut tracker = WatermarkTracker::new(1_000);
        for ts in [0, 100, 200, 5_000, 10_000] {
            assert_eq!(tracker.observe(ts), Lateness::OnTime);
        }
    }

    #[test]
    fn late_event_reports_correct_by_ms() {
        let mut tracker = WatermarkTracker::new(1_000);
        tracker.observe(5_000);
        tracker.observe(6_000);
        // watermark = 6_000 - 1_000 = 5_000
        assert_eq!(tracker.observe(4_000), Lateness::Late { by_ms: 1_000 });
        assert_eq!(tracker.observe(4_999), Lateness::Late { by_ms: 1 });
    }

    #[test]
    fn watermark_only_moves_forward() {
        let mut tracker = WatermarkTracker::new(1_000);
        tracker.observe(5_000);
        assert_eq!(tracker.watermark(), Some(4_000));

        tracker.observe(1_000); // late, well behind watermark
        assert_eq!(
            tracker.watermark(),
            Some(4_000),
            "late event must not move watermark"
        );

        tracker.observe(6_000);
        assert_eq!(tracker.watermark(), Some(5_000));
    }

    #[test]
    fn zero_allowed_lateness_is_strict_monotonic() {
        let mut tracker = WatermarkTracker::new(0);
        assert_eq!(tracker.observe(10), Lateness::OnTime);
        assert_eq!(
            tracker.observe(10),
            Lateness::OnTime,
            "equal to watermark is on time"
        );
        assert_eq!(tracker.observe(9), Lateness::Late { by_ms: 1 });
        assert_eq!(tracker.observe(11), Lateness::OnTime);
    }

    #[test]
    fn late_event_does_not_raise_max_ts_seen() {
        let mut tracker = WatermarkTracker::new(0);
        tracker.observe(100);
        tracker.observe(50);
        assert_eq!(tracker.watermark(), Some(100));
    }

    #[test]
    fn first_observation_is_always_on_time() {
        let mut tracker = WatermarkTracker::new(1_000_000);
        assert_eq!(tracker.observe(-999_999_999), Lateness::OnTime);
    }

    // ── Advancement / boundaries ─────────────────────────────────────────────

    #[test]
    fn event_exactly_at_watermark_is_on_time() {
        let mut tracker = WatermarkTracker::new(100);
        tracker.observe(1_000);
        assert_eq!(tracker.watermark(), Some(900));
        assert_eq!(tracker.observe(900), Lateness::OnTime);
        assert_eq!(tracker.observe(899), Lateness::Late { by_ms: 1 });
    }

    #[test]
    fn on_time_but_older_event_does_not_move_watermark() {
        let mut tracker = WatermarkTracker::new(100);
        tracker.observe(1_000);
        assert_eq!(tracker.observe(950), Lateness::OnTime);
        assert_eq!(tracker.watermark(), Some(900));
    }

    #[test]
    fn watermark_advances_by_jump_size() {
        let mut tracker = WatermarkTracker::new(10);
        tracker.observe(0);
        assert_eq!(tracker.watermark(), Some(-10));
        tracker.observe(5_000);
        assert_eq!(tracker.watermark(), Some(4_990));
        assert_eq!(tracker.observe(0), Lateness::Late { by_ms: 4_990 });
    }

    #[test]
    fn negative_timestamps_are_ordinary() {
        let mut tracker = WatermarkTracker::new(5);
        assert_eq!(tracker.observe(-100), Lateness::OnTime);
        assert_eq!(tracker.watermark(), Some(-105));
        assert_eq!(tracker.observe(-110), Lateness::Late { by_ms: 5 });
    }

    #[test]
    fn extreme_timestamps_saturate_instead_of_overflowing() {
        // Regression: `max_ts - lateness` and `wm - ts` overflowed.
        let mut tracker = WatermarkTracker::new(1_000);
        assert_eq!(tracker.observe(i64::MIN), Lateness::OnTime);
        assert_eq!(tracker.watermark(), Some(i64::MIN));

        let mut tracker = WatermarkTracker::new(0);
        tracker.observe(i64::MAX);
        assert_eq!(
            tracker.observe(i64::MIN),
            Lateness::Late { by_ms: i64::MAX }
        );
    }
}
