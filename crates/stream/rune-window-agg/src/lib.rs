//! Tumbling, sliding, and session window aggregation over a timestamped stream.
//!
//! Feed `(timestamp, value)` pairs in non-decreasing timestamp order via [`push`](WindowAggregator::push);
//! windows that can no longer receive new data (because the timestamp watermark has
//! moved past their end) are closed and returned automatically. Call
//! [`flush`](WindowAggregator::flush) at stream end to collect whatever windows are
//! still open.
//!
//! # Features
//!
//! - [`WindowKind::Tumbling`] — fixed, non-overlapping buckets aligned to `size_ms`.
//! - [`WindowKind::Sliding`] — overlapping buckets of width `size_ms`, spaced `step_ms`
//!   apart, implemented as multiple concurrently-accumulating tumbling-style buckets.
//! - [`WindowKind::Session`] — a window stays open while consecutive events are within
//!   `gap_ms` of each other; a longer gap closes it and starts a new one.
//!
//! Timestamps are assumed non-decreasing across calls to `push`: closing decisions are
//! driven by a watermark (the highest timestamp seen so far), so out-of-order input can
//! cause a window to close before a genuinely late event for it arrives. For streams
//! that need to tolerate out-of-order arrival, reorder first (see `rune-reorder`).
//!
//! # Quick Start
//!
//! ```rust
//! use rune_window_agg::{WindowAggregator, WindowKind};
//!
//! let mut agg = WindowAggregator::new(WindowKind::Tumbling { size_ms: 10 });
//! assert!(agg.push(0, 1.0).is_empty());
//! assert!(agg.push(5, 2.0).is_empty());
//! let closed = agg.push(12, 3.0); // crossing into the next bucket closes the first
//! assert_eq!(closed.len(), 1);
//! assert_eq!(closed[0].sum, 3.0);
//! assert_eq!(closed[0].count, 2);
//! ```
//!
//! # CLI
//!
//! ```bash
//! rune-window-agg --size-ms 60000 readings.csv
//! cat readings.csv | rune-window-agg --size-ms 60000 -
//! ```

use std::collections::BTreeMap;

/// Which windowing strategy a [`WindowAggregator`] uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WindowKind {
    /// Fixed, non-overlapping windows of `size_ms`, aligned to multiples of `size_ms`.
    Tumbling {
        /// Width of each window, in milliseconds. Must be positive.
        size_ms: i64,
    },
    /// Overlapping windows of width `size_ms`, starting every `step_ms`.
    Sliding {
        /// Width of each window, in milliseconds. Must be positive.
        size_ms: i64,
        /// Spacing between consecutive window starts, in milliseconds. Must be positive.
        step_ms: i64,
    },
    /// A window stays open while consecutive events are within `gap_ms` of each other.
    Session {
        /// Maximum gap between consecutive events before the session closes. Must be positive.
        gap_ms: i64,
    },
}

/// The aggregate of one closed window.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct WindowResult {
    /// Inclusive start of the window, in milliseconds.
    pub start_ms: i64,
    /// Exclusive end of the window, in milliseconds (tumbling/sliding); for session
    /// windows, the timestamp of the last event that fell in the session.
    pub end_ms: i64,
    /// Number of values aggregated.
    pub count: usize,
    /// Sum of all values.
    pub sum: f64,
    /// Minimum value seen.
    pub min: f64,
    /// Maximum value seen.
    pub max: f64,
}

#[derive(Clone, Copy)]
struct Accumulator {
    start_ms: i64,
    end_ms: i64,
    count: usize,
    sum: f64,
    min: f64,
    max: f64,
}

impl Accumulator {
    const fn new(start_ms: i64, end_ms: i64, value: f64) -> Self {
        Self {
            start_ms,
            end_ms,
            count: 1,
            sum: value,
            min: value,
            max: value,
        }
    }

    fn push(&mut self, value: f64) {
        self.count += 1;
        self.sum += value;
        self.min = self.min.min(value);
        self.max = self.max.max(value);
    }

    const fn finish(&self) -> WindowResult {
        WindowResult {
            start_ms: self.start_ms,
            end_ms: self.end_ms,
            count: self.count,
            sum: self.sum,
            min: self.min,
            max: self.max,
        }
    }
}

/// Stateful tumbling/sliding/session window aggregator. See the module docs for the
/// closing semantics of each [`WindowKind`].
pub struct WindowAggregator {
    kind: WindowKind,
    buckets: BTreeMap<i64, Accumulator>,
    watermark: i64,
    seen_any: bool,
    session: Option<Accumulator>,
}

impl WindowAggregator {
    /// Creates a new aggregator using the given windowing strategy.
    #[must_use]
    pub const fn new(kind: WindowKind) -> Self {
        Self {
            kind,
            buckets: BTreeMap::new(),
            watermark: 0,
            seen_any: false,
            session: None,
        }
    }

    /// Feeds one `(ts_ms, value)` pair in. Returns any windows that closed as a result
    /// (0, 1, or more — a tumbling aggregator that skips several empty buckets at once
    /// can close more than one).
    pub fn push(&mut self, ts_ms: i64, value: f64) -> Vec<WindowResult> {
        match self.kind {
            WindowKind::Tumbling { size_ms } => self.push_tumbling(size_ms, ts_ms, value),
            WindowKind::Sliding { size_ms, step_ms } => {
                self.push_sliding(size_ms, step_ms, ts_ms, value)
            }
            WindowKind::Session { gap_ms } => self.push_session(gap_ms, ts_ms, value),
        }
    }

    fn push_tumbling(&mut self, size_ms: i64, ts_ms: i64, value: f64) -> Vec<WindowResult> {
        let bucket = ts_ms.div_euclid(size_ms);
        let start = bucket * size_ms;
        let end = start + size_ms;
        self.buckets
            .entry(bucket)
            .and_modify(|acc| acc.push(value))
            .or_insert_with(|| Accumulator::new(start, end, value));

        if !self.seen_any || bucket > self.watermark {
            self.watermark = bucket;
            self.seen_any = true;
        }

        let watermark = self.watermark;
        self.drain_closed(|acc| acc.start_ms.div_euclid(size_ms) < watermark)
    }

    fn push_sliding(
        &mut self,
        size_ms: i64,
        step_ms: i64,
        ts_ms: i64,
        value: f64,
    ) -> Vec<WindowResult> {
        let k_max = ts_ms.div_euclid(step_ms);
        let k_min = (ts_ms - size_ms).div_euclid(step_ms) + 1;

        for k in k_min..=k_max {
            let start = k * step_ms;
            let end = start + size_ms;
            self.buckets
                .entry(k)
                .and_modify(|acc| acc.push(value))
                .or_insert_with(|| Accumulator::new(start, end, value));
        }

        if !self.seen_any || ts_ms > self.watermark {
            self.watermark = ts_ms;
            self.seen_any = true;
        }

        let watermark = self.watermark;
        self.drain_closed(|acc| acc.end_ms <= watermark)
    }

    fn push_session(&mut self, gap_ms: i64, ts_ms: i64, value: f64) -> Vec<WindowResult> {
        match &mut self.session {
            None => {
                self.session = Some(Accumulator::new(ts_ms, ts_ms, value));
                Vec::new()
            }
            Some(acc) if ts_ms.saturating_sub(acc.end_ms) > gap_ms => {
                let closed = acc.finish();
                self.session = Some(Accumulator::new(ts_ms, ts_ms, value));
                vec![closed]
            }
            Some(acc) => {
                acc.push(value);
                // Out-of-order input may land inside the session: widen it,
                // never shrink it.
                acc.start_ms = acc.start_ms.min(ts_ms);
                acc.end_ms = acc.end_ms.max(ts_ms);
                Vec::new()
            }
        }
    }

    fn drain_closed(&mut self, should_close: impl Fn(&Accumulator) -> bool) -> Vec<WindowResult> {
        let closed_keys: Vec<i64> = self
            .buckets
            .iter()
            .filter(|(_, acc)| should_close(acc))
            .map(|(&k, _)| k)
            .collect();

        closed_keys
            .into_iter()
            .filter_map(|k| self.buckets.remove(&k))
            .map(|acc| acc.finish())
            .collect()
    }

    /// Closes and returns every window still open, in ascending start-time order.
    /// Call at stream end so no partial window is silently dropped.
    pub fn flush(&mut self) -> Vec<WindowResult> {
        if matches!(self.kind, WindowKind::Session { .. }) {
            return self
                .session
                .take()
                .map(|acc| vec![acc.finish()])
                .unwrap_or_default();
        }

        let mut results: Vec<WindowResult> =
            self.buckets.values().map(Accumulator::finish).collect();
        self.buckets.clear();
        results.sort_by_key(|r| r.start_ms);
        results
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tumbling_buckets_aggregate_and_close_in_order() {
        let mut agg = WindowAggregator::new(WindowKind::Tumbling { size_ms: 10 });

        assert_eq!(agg.push(0, 1.0), [] as [WindowResult; 0]);
        assert_eq!(agg.push(5, 2.0), [] as [WindowResult; 0]);

        let closed = agg.push(12, 3.0);
        assert_eq!(closed.len(), 1);
        assert_eq!(
            closed[0],
            WindowResult {
                start_ms: 0,
                end_ms: 10,
                count: 2,
                sum: 3.0,
                min: 1.0,
                max: 2.0
            }
        );

        let closed = agg.push(25, 4.0);
        assert_eq!(closed.len(), 1);
        assert_eq!(
            closed[0],
            WindowResult {
                start_ms: 10,
                end_ms: 20,
                count: 1,
                sum: 3.0,
                min: 3.0,
                max: 3.0
            }
        );
    }

    #[test]
    fn tumbling_flush_closes_trailing_window() {
        let mut agg = WindowAggregator::new(WindowKind::Tumbling { size_ms: 10 });
        agg.push(0, 1.0);
        agg.push(5, 2.0);

        let flushed = agg.flush();
        assert_eq!(flushed.len(), 1);
        assert_eq!(
            flushed[0],
            WindowResult {
                start_ms: 0,
                end_ms: 10,
                count: 2,
                sum: 3.0,
                min: 1.0,
                max: 2.0
            }
        );
        assert!(agg.flush().is_empty(), "flush drains fully");
    }

    #[test]
    fn min_max_sum_count_correctness() {
        let mut agg = WindowAggregator::new(WindowKind::Tumbling { size_ms: 100 });
        for value in [1.0, 2.0, 3.0, 4.0, 5.0] {
            agg.push(0, value);
        }
        let flushed = agg.flush();
        assert_eq!(flushed.len(), 1);
        assert_eq!(flushed[0].count, 5);
        assert_eq!(flushed[0].sum, 15.0);
        assert_eq!(flushed[0].min, 1.0);
        assert_eq!(flushed[0].max, 5.0);
    }

    #[test]
    fn session_merges_within_gap_and_splits_on_gap() {
        let mut agg = WindowAggregator::new(WindowKind::Session { gap_ms: 5 });

        assert_eq!(agg.push(0, 1.0), [] as [WindowResult; 0]);
        assert!(agg.push(3, 2.0).is_empty(), "within gap, merges");

        let closed = agg.push(20, 3.0);
        assert_eq!(closed.len(), 1, "gap exceeded, prior session closes");
        assert_eq!(
            closed[0],
            WindowResult {
                start_ms: 0,
                end_ms: 3,
                count: 2,
                sum: 3.0,
                min: 1.0,
                max: 2.0
            }
        );
    }

    #[test]
    fn session_flush_closes_open_session() {
        let mut agg = WindowAggregator::new(WindowKind::Session { gap_ms: 5 });
        agg.push(0, 1.0);
        agg.push(3, 2.0);
        agg.push(20, 3.0);

        let flushed = agg.flush();
        assert_eq!(flushed.len(), 1);
        assert_eq!(
            flushed[0],
            WindowResult {
                start_ms: 20,
                end_ms: 20,
                count: 1,
                sum: 3.0,
                min: 3.0,
                max: 3.0
            }
        );
    }

    #[test]
    fn session_multiple_splits_in_sequence() {
        let mut agg = WindowAggregator::new(WindowKind::Session { gap_ms: 5 });
        agg.push(0, 1.0);
        let first_close = agg.push(10, 2.0);
        let second_close = agg.push(20, 3.0);

        assert_eq!(first_close.len(), 1);
        assert_eq!(first_close[0].start_ms, 0);
        assert_eq!(second_close.len(), 1);
        assert_eq!(second_close[0].start_ms, 10);
    }

    #[test]
    fn sliding_produces_overlapping_windows_with_correct_aggregates() {
        let mut agg = WindowAggregator::new(WindowKind::Sliding {
            size_ms: 10,
            step_ms: 5,
        });

        assert_eq!(agg.push(10, 1.0), [] as [WindowResult; 0]);

        let closed = agg.push(17, 2.0);
        assert_eq!(closed.len(), 1);
        assert_eq!(
            closed[0],
            WindowResult {
                start_ms: 5,
                end_ms: 15,
                count: 1,
                sum: 1.0,
                min: 1.0,
                max: 1.0
            }
        );

        let mut flushed = agg.flush();
        flushed.sort_by_key(|r| r.start_ms);
        assert_eq!(flushed.len(), 2);
        assert_eq!(
            flushed[0],
            WindowResult {
                start_ms: 10,
                end_ms: 20,
                count: 2,
                sum: 3.0,
                min: 1.0,
                max: 2.0
            }
        );
        assert_eq!(
            flushed[1],
            WindowResult {
                start_ms: 15,
                end_ms: 25,
                count: 1,
                sum: 2.0,
                min: 2.0,
                max: 2.0
            }
        );
    }

    #[test]
    fn empty_flush_returns_empty() {
        let mut agg = WindowAggregator::new(WindowKind::Tumbling { size_ms: 10 });
        assert_eq!(agg.flush(), [] as [WindowResult; 0]);
    }

    // ── Window boundaries ────────────────────────────────────────────────────

    fn starts(results: &[WindowResult]) -> Vec<(i64, i64, usize)> {
        results
            .iter()
            .map(|r| (r.start_ms, r.end_ms, r.count))
            .collect()
    }

    #[test]
    fn tumbling_end_is_exclusive() {
        let mut agg = WindowAggregator::new(WindowKind::Tumbling { size_ms: 10 });
        assert_eq!(agg.push(9, 1.0), [] as [WindowResult; 0]);
        // ts == 10 belongs to [10, 20) and closes [0, 10).
        assert_eq!(starts(&agg.push(10, 1.0)), vec![(0, 10, 1)]);
        assert_eq!(starts(&agg.flush()), vec![(10, 20, 1)]);
    }

    #[test]
    fn tumbling_negative_timestamps_floor_to_bucket() {
        let mut agg = WindowAggregator::new(WindowKind::Tumbling { size_ms: 10 });
        agg.push(-15, 1.0);
        agg.push(-11, 1.0);
        assert_eq!(starts(&agg.push(-1, 1.0)), vec![(-20, -10, 2)]);
        assert_eq!(starts(&agg.flush()), vec![(-10, 0, 1)]);
    }

    #[test]
    fn tumbling_skipping_empty_buckets_emits_only_populated_ones() {
        let mut agg = WindowAggregator::new(WindowKind::Tumbling { size_ms: 10 });
        agg.push(3, 1.0);
        // Jumping ahead several buckets closes the old one; no empty windows.
        assert_eq!(starts(&agg.push(57, 1.0)), vec![(0, 10, 1)]);
        assert_eq!(starts(&agg.flush()), vec![(50, 60, 1)]);
    }

    #[test]
    fn tumbling_same_bucket_never_closes_early() {
        let mut agg = WindowAggregator::new(WindowKind::Tumbling { size_ms: 100 });
        for ts in 0..100 {
            assert_eq!(agg.push(ts, 1.0), [] as [WindowResult; 0]);
        }
        assert_eq!(starts(&agg.flush()), vec![(0, 100, 100)]);
    }

    #[test]
    fn sliding_window_membership_and_close_boundary() {
        // size 10, step 5: ts 7 is in [0,10) and [5,15).
        let mut agg = WindowAggregator::new(WindowKind::Sliding {
            size_ms: 10,
            step_ms: 5,
        });
        assert_eq!(agg.push(7, 1.0), [] as [WindowResult; 0]);
        // ts 10 closes [0,10) (end exclusive) and joins [5,15) and [10,20).
        assert_eq!(starts(&agg.push(10, 2.0)), vec![(0, 10, 1)]);
        let rest = agg.flush();
        assert_eq!(starts(&rest), vec![(5, 15, 2), (10, 20, 1)]);
        assert_eq!(rest[0].sum, 3.0);
    }

    #[test]
    fn sliding_with_step_larger_than_size_leaves_gaps() {
        // Hopping windows [0,5), [10,15), …: ts 7 falls in no window.
        let mut agg = WindowAggregator::new(WindowKind::Sliding {
            size_ms: 5,
            step_ms: 10,
        });
        agg.push(2, 1.0);
        // ts 7 joins no window but advances the watermark past [0,5).
        let closed = agg.push(7, 100.0);
        assert_eq!(starts(&closed), vec![(0, 5, 1)]);
        assert_eq!(closed[0].sum, 1.0);
        assert_eq!(agg.push(12, 1.0), [] as [WindowResult; 0]);
        assert_eq!(starts(&agg.flush()), vec![(10, 15, 1)]);
    }

    #[test]
    fn sliding_closes_multiple_windows_in_start_order() {
        let mut agg = WindowAggregator::new(WindowKind::Sliding {
            size_ms: 6,
            step_ms: 2,
        });
        agg.push(5, 1.0); // windows starting 0, 2, 4
        let closed = agg.push(100, 1.0);
        assert_eq!(starts(&closed), vec![(0, 6, 1), (2, 8, 1), (4, 10, 1)]);
    }

    #[test]
    fn session_gap_boundary_is_inclusive() {
        let mut agg = WindowAggregator::new(WindowKind::Session { gap_ms: 5 });
        agg.push(0, 1.0);
        // Exactly gap_ms later: same session.
        assert_eq!(agg.push(5, 1.0), [] as [WindowResult; 0]);
        // gap_ms + 1 later: new session.
        assert_eq!(starts(&agg.push(11, 1.0)), vec![(0, 5, 2)]);
        assert_eq!(starts(&agg.flush()), vec![(11, 11, 1)]);
    }

    #[test]
    fn session_late_event_does_not_shrink_session() {
        // Regression: an earlier timestamp inside a session moved `end_ms`
        // backwards, so the next event was measured from the wrong end.
        let mut agg = WindowAggregator::new(WindowKind::Session { gap_ms: 10 });
        agg.push(0, 1.0);
        agg.push(10, 1.0);
        agg.push(5, 1.0); // out of order, still inside [0, 10]
        assert!(agg.push(18, 1.0).is_empty(), "18 is within 10ms of 10");
        assert_eq!(starts(&agg.flush()), vec![(0, 18, 4)]);
    }

    #[test]
    fn session_extreme_timestamps_do_not_overflow() {
        let mut agg = WindowAggregator::new(WindowKind::Session { gap_ms: 10 });
        agg.push(i64::MAX, 1.0);
        assert_eq!(agg.push(i64::MIN, 1.0), [] as [WindowResult; 0]);
        let mut agg = WindowAggregator::new(WindowKind::Session { gap_ms: 10 });
        agg.push(i64::MIN, 1.0);
        assert_eq!(agg.push(i64::MAX, 1.0).len(), 1);
    }

    #[test]
    fn flush_resets_state() {
        let mut agg = WindowAggregator::new(WindowKind::Tumbling { size_ms: 10 });
        agg.push(1, 1.0);
        assert_eq!(agg.flush().len(), 1);
        assert_eq!(agg.flush(), [] as [WindowResult; 0]);
    }
}
