//! Replay a recorded position trace at a configurable speed multiplier.
//!
//! Demo and test scenarios often want to replay a recorded GPS trace as if a
//! device were moving live, but faster (or slower) than it originally moved.
//! [`TraceReplay`] wraps any iterator of already-parsed [`TracePoint`]s and
//! sleeps the appropriately compressed real-time delay between points based on
//! the gap between their timestamps, yielding each point in turn — so a
//! downstream sink sees the same pacing it would from a live feed, at whatever
//! speed multiplier you choose.
//!
//! # Features
//!
//! - [`delay_for`] — the pure timing function: given two timestamps and a speed
//!   multiplier, the real-time delay to sleep before emitting the second point.
//! - [`TraceReplay`] — an iterator adapter that applies [`delay_for`]
//!   automatically between points from any source iterator.
//!
//! # Quick Start
//!
//! ```rust
//! use rune_trace_replay::{TracePoint, TraceReplay};
//!
//! let points = vec![
//!     TracePoint { ts_ms: 0, lat: 60.17, lon: 24.94 },
//!     TracePoint { ts_ms: 10, lat: 60.18, lon: 24.95 },
//! ];
//! let replay = TraceReplay::new(points.into_iter(), 1000.0);
//! let replayed: Vec<_> = replay.collect();
//! assert_eq!(replayed.len(), 2);
//! ```
//!
//! # CLI
//!
//! ```bash
//! rune-trace-replay --speed 10 trace.csv
//! ```

use std::time::Duration;

/// Computes the real-time delay to sleep before emitting the current point,
/// given the previous point's timestamp, the current point's timestamp (both in
/// milliseconds), and a speed multiplier.
///
/// `speed = 1.0` replays in real time. `speed = 10.0` replays ten times faster (a
/// tenth of the original delay). A non-positive `speed`, or a non-positive
/// (including out-of-order) timestamp delta, yields [`Duration::ZERO`] rather
/// than panicking or producing a negative delay.
///
/// # Example
///
/// ```rust
/// use rune_trace_replay::delay_for;
/// use std::time::Duration;
///
/// assert_eq!(delay_for(0, 1000, 1.0), Duration::from_secs(1));
/// assert_eq!(delay_for(0, 1000, 10.0), Duration::from_millis(100));
/// assert_eq!(delay_for(1000, 500, 1.0), Duration::ZERO); // out of order
/// assert_eq!(delay_for(0, 1000, 0.0), Duration::ZERO); // non-positive speed
/// ```
#[allow(
    clippy::cast_precision_loss,
    reason = "counts and indices stay far below 2^52, so the f64 conversion is exact"
)]
#[must_use]
pub fn delay_for(prev_ts_ms: i64, curr_ts_ms: i64, speed: f64) -> Duration {
    let delta_ms = curr_ts_ms - prev_ts_ms;
    if delta_ms <= 0 || speed <= 0.0 {
        return Duration::ZERO;
    }
    let compressed_secs = (delta_ms as f64 / speed) / 1000.0;
    Duration::from_secs_f64(compressed_secs)
}

/// A single recorded position, timestamped in milliseconds.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct TracePoint {
    /// Timestamp in Unix milliseconds.
    pub ts_ms: i64,
    /// Latitude in degrees.
    pub lat: f64,
    /// Longitude in degrees.
    pub lon: f64,
}

/// Iterator adapter that yields points from `inner` in order, sleeping between
/// them to replay the original pacing at a chosen speed multiplier.
pub struct TraceReplay<I> {
    inner: I,
    speed: f64,
    prev_ts: Option<i64>,
}

impl<I: Iterator<Item = TracePoint>> TraceReplay<I> {
    /// Wraps `inner`, replaying its points at `speed` times real-time.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_trace_replay::TraceReplay;
    ///
    /// let replay = TraceReplay::new(std::iter::empty(), 5.0);
    /// assert_eq!(replay.count(), 0);
    /// ```
    pub const fn new(inner: I, speed: f64) -> Self {
        Self {
            inner,
            speed,
            prev_ts: None,
        }
    }
}

impl<I: Iterator<Item = TracePoint>> Iterator for TraceReplay<I> {
    type Item = TracePoint;

    fn next(&mut self) -> Option<Self::Item> {
        let point = self.inner.next()?;
        if let Some(prev) = self.prev_ts {
            std::thread::sleep(delay_for(prev, point.ts_ms, self.speed));
        }
        self.prev_ts = Some(point.ts_ms);
        Some(point)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    #[test]
    fn delay_for_real_time() {
        assert_eq!(delay_for(0, 1000, 1.0), Duration::from_secs(1));
    }

    #[test]
    fn delay_for_compresses_with_speed() {
        assert_eq!(delay_for(0, 1000, 10.0), Duration::from_millis(100));
        assert_eq!(delay_for(0, 2000, 4.0), Duration::from_millis(500));
    }

    #[test]
    fn delay_for_non_positive_speed_is_zero() {
        assert_eq!(delay_for(0, 1000, 0.0), Duration::ZERO);
        assert_eq!(delay_for(0, 1000, -5.0), Duration::ZERO);
    }

    #[test]
    fn delay_for_out_of_order_timestamps_is_zero() {
        assert_eq!(delay_for(1000, 500, 1.0), Duration::ZERO);
        assert_eq!(delay_for(1000, 1000, 1.0), Duration::ZERO);
    }

    #[test]
    fn replay_yields_points_in_source_order() {
        let points = vec![
            TracePoint {
                ts_ms: 0,
                lat: 1.0,
                lon: 1.0,
            },
            TracePoint {
                ts_ms: 5,
                lat: 2.0,
                lon: 2.0,
            },
            TracePoint {
                ts_ms: 10,
                lat: 3.0,
                lon: 3.0,
            },
        ];
        let replay = TraceReplay::new(points.clone().into_iter(), 1000.0);
        let replayed: Vec<_> = replay.collect();
        assert_eq!(replayed, points);
    }

    #[test]
    fn high_speed_replay_completes_near_instantly() {
        let points = vec![
            TracePoint {
                ts_ms: 0,
                lat: 0.0,
                lon: 0.0,
            },
            TracePoint {
                ts_ms: 60_000,
                lat: 1.0,
                lon: 1.0,
            },
        ];
        let start = Instant::now();
        let replay = TraceReplay::new(points.into_iter(), 1_000_000.0);
        let _: Vec<_> = replay.collect();
        assert!(start.elapsed() < Duration::from_millis(200));
    }

    #[test]
    fn empty_source_yields_no_points() {
        let replay: TraceReplay<std::vec::IntoIter<TracePoint>> =
            TraceReplay::new(Vec::new().into_iter(), 1.0);
        assert_eq!(replay.count(), 0);
    }

    #[test]
    fn single_point_yields_immediately() {
        let points = vec![TracePoint {
            ts_ms: 0,
            lat: 0.0,
            lon: 0.0,
        }];
        let start = Instant::now();
        let replay = TraceReplay::new(points.into_iter(), 1.0);

        assert_eq!(replay.count(), 1);
        assert!(start.elapsed() < Duration::from_millis(50));
    }
}
