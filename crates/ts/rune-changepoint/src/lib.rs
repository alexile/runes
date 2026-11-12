//! CUSUM-style changepoint detection over a numeric series.
//!
//! Implements the classic two-sided cumulative sum (CUSUM) control chart: two
//! running accumulators track sustained drift above (`pos`) or below (`neg`)
//! a `target` value, each accumulator resetting whenever it would go
//! negative. A small `drift` allowance keeps normal noise from slowly
//! accumulating into a false signal; once an accumulator exceeds `threshold`,
//! a changepoint is signalled and that accumulator resets to zero.
//!
//! # Quick Start
//!
//! ```rust
//! use rune_changepoint::{Cusum, ChangeDirection};
//!
//! let mut cusum = Cusum::new(0.0, 5.0, 0.5);
//! let mut signalled = None;
//! for x in [0.0, 0.0, 0.0, 3.0, 3.0, 3.0, 3.0] {
//!     if let Some(direction) = cusum.update(x) {
//!         signalled = Some(direction);
//!         break;
//!     }
//! }
//! assert_eq!(signalled, Some(ChangeDirection::Up));
//! ```
//!
//! # CLI
//!
//! ```bash
//! rune-changepoint --target 0 --threshold 5 --drift 0.5 0 0 0 3 3 3 3
//! ```

#![cfg_attr(not(any(feature = "std", test)), no_std)]

extern crate alloc;

use alloc::vec::Vec;

/// Which direction a detected changepoint moved: a sustained rise or fall
/// relative to `target`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChangeDirection {
    /// The mean shifted upwards.
    Up,
    /// The mean shifted downwards.
    Down,
}

/// Incremental two-sided CUSUM changepoint detector.
pub struct Cusum {
    target: f64,
    threshold: f64,
    drift: f64,
    pos: f64,
    neg: f64,
}

impl Cusum {
    /// Creates a new detector.
    ///
    /// - `target`: the expected/baseline value of the series.
    /// - `threshold`: how far the cumulative sum must drift before a
    ///   changepoint is signalled.
    /// - `drift`: a small allowance subtracted from each increment, so
    ///   ordinary noise around `target` doesn't slowly accumulate into a
    ///   false signal.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_changepoint::Cusum;
    ///
    /// let cusum = Cusum::new(0.0, 5.0, 0.5);
    /// ```
    #[must_use]
    pub const fn new(target: f64, threshold: f64, drift: f64) -> Self {
        Self {
            target,
            threshold,
            drift,
            pos: 0.0,
            neg: 0.0,
        }
    }

    /// Feeds one new observation. Returns `Some(direction)` if this
    /// observation pushed the corresponding accumulator past `threshold`, in
    /// which case that accumulator resets to `0.0`.
    ///
    /// A `NaN` observation is treated as missing: it returns `None` and
    /// leaves both accumulators untouched (rather than silently resetting the
    /// evidence gathered so far).
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_changepoint::Cusum;
    ///
    /// let mut cusum = Cusum::new(0.0, 1.0, 0.1);
    /// assert_eq!(cusum.update(0.0), None);
    /// ```
    pub fn update(&mut self, x: f64) -> Option<ChangeDirection> {
        if x.is_nan() {
            return None;
        }
        self.pos = (self.pos + x - self.target - self.drift).max(0.0);
        self.neg = (self.neg + self.target - x - self.drift).max(0.0);

        if self.pos > self.threshold {
            self.pos = 0.0;
            Some(ChangeDirection::Up)
        } else if self.neg > self.threshold {
            self.neg = 0.0;
            Some(ChangeDirection::Down)
        } else {
            None
        }
    }
}

/// Runs a fresh [`Cusum`] detector over a whole series at once, returning
/// every `(index, direction)` changepoint found.
///
/// # Example
///
/// ```rust
/// use rune_changepoint::{detect, ChangeDirection};
///
/// let data = [0.0, 0.0, 0.0, 3.0, 3.0, 3.0, 3.0];
/// let changes = detect(&data, 0.0, 5.0, 0.5);
/// assert_eq!(changes[0].1, ChangeDirection::Up);
/// ```
#[must_use]
pub fn detect(
    data: &[f64],
    target: f64,
    threshold: f64,
    drift: f64,
) -> Vec<(usize, ChangeDirection)> {
    let mut cusum = Cusum::new(target, threshold, drift);
    data.iter()
        .enumerate()
        .filter_map(|(i, &x)| cusum.update(x).map(|direction| (i, direction)))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flat_series_never_signals() {
        let mut cusum = Cusum::new(0.0, 5.0, 0.5);
        for _ in 0..100 {
            assert_eq!(cusum.update(0.0), None);
        }
    }

    #[test]
    fn step_up_is_detected() {
        let data = [0.0, 0.0, 0.0, 3.0, 3.0, 3.0, 3.0];
        let changes = detect(&data, 0.0, 5.0, 0.5);
        assert_ne!(changes, [] as [(usize, ChangeDirection); 0]);
        assert_eq!(changes[0].1, ChangeDirection::Up);
        assert!(changes[0].0 >= 3, "changepoint should be at/after the step");
    }

    #[test]
    fn step_down_is_detected() {
        let data = [0.0, 0.0, 0.0, -3.0, -3.0, -3.0, -3.0];
        let changes = detect(&data, 0.0, 5.0, 0.5);
        assert_ne!(changes, [] as [(usize, ChangeDirection); 0]);
        assert_eq!(changes[0].1, ChangeDirection::Down);
    }

    #[test]
    fn higher_threshold_reduces_sensitivity() {
        let data = [0.0, 0.0, 0.0, 1.0, 1.0, 1.0, 1.0, 1.0];
        let sensitive = detect(&data, 0.0, 1.0, 0.1);
        let strict = detect(&data, 0.0, 100.0, 0.1);
        assert_ne!(sensitive, [] as [(usize, ChangeDirection); 0]);
        assert_eq!(strict, [] as [(usize, ChangeDirection); 0]);
    }

    #[test]
    fn accumulator_resets_after_signal() {
        let data = [0.0, 0.0, 0.0, 5.0, 5.0, 5.0, 5.0, 5.0, 5.0, 5.0, 5.0];
        let changes = detect(&data, 0.0, 5.0, 0.5);
        // A sustained step should be able to signal more than once as the
        // accumulator resets and re-climbs.
        assert_ne!(changes, [] as [(usize, ChangeDirection); 0]);
    }

    /// Hand-computed reference trace (target 0, threshold 5, drift 0.5):
    /// `pos` = 0, 0, 0, 2.5, 5.0, 7.5 (> 5: signal, reset), 2.5.
    #[test]
    fn step_up_exact_index() {
        let data = [0.0, 0.0, 0.0, 3.0, 3.0, 3.0, 3.0];
        assert_eq!(detect(&data, 0.0, 5.0, 0.5), vec![(5, ChangeDirection::Up)]);
    }

    /// Sustained step of +5 with threshold 5 and drift 0.5: each sample adds
    /// 4.5, so the accumulator crosses on every second sample after a reset.
    #[test]
    fn sustained_step_signals_periodically() {
        let data = [0.0, 0.0, 0.0, 5.0, 5.0, 5.0, 5.0, 5.0, 5.0, 5.0, 5.0];
        let changes = detect(&data, 0.0, 5.0, 0.5);
        let idx: Vec<usize> = changes.iter().map(|c| c.0).collect();
        assert_eq!(idx, vec![4, 6, 8, 10]);
        assert!(changes.iter().all(|c| c.1 == ChangeDirection::Up));
    }

    #[test]
    fn up_then_down_reference() {
        // target 10, threshold 3, drift 0: +2 twice (pos 4 at index 2), then
        // back to baseline, then -4 (neg 4 at index 4).
        let data = [10.0, 12.0, 12.0, 10.0, 6.0];
        assert_eq!(
            detect(&data, 10.0, 3.0, 0.0),
            vec![(2, ChangeDirection::Up), (4, ChangeDirection::Down)]
        );
    }

    #[test]
    fn empty_and_single_point() {
        assert_eq!(detect(&[], 0.0, 1.0, 0.0), vec![]);
        assert_eq!(detect(&[0.5], 0.0, 1.0, 0.0), vec![]);
        assert_eq!(
            detect(&[2.0], 0.0, 1.0, 0.0),
            vec![(0, ChangeDirection::Up)]
        );
    }

    /// Regression: `NaN.max(0.0)` is `0.0`, so a missing sample used to wipe
    /// both accumulators and delay detection.
    #[test]
    fn nan_does_not_reset_accumulators() {
        let mut cusum = Cusum::new(0.0, 2.0, 0.0);
        assert_eq!(cusum.update(1.5), None);
        assert_eq!(cusum.update(f64::NAN), None);
        assert_eq!(cusum.update(1.5), Some(ChangeDirection::Up));
    }

    #[test]
    fn zero_drift_still_requires_crossing_threshold() {
        let mut cusum = Cusum::new(0.0, 2.0, 0.0);
        assert_eq!(cusum.update(1.0), None); // pos = 1, not > 2
        assert_eq!(cusum.update(1.0), None); // pos = 2, still not strictly > 2
        assert_eq!(cusum.update(1.0), Some(ChangeDirection::Up)); // pos = 3, crosses
    }
}
