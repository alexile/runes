//! Resample an irregularly-sampled timestamped series onto a fixed interval grid.
//!
//! Sensors and event streams rarely produce evenly-spaced samples. This crate takes
//! `(timestamp_ms, value)` pairs and produces a new series sampled at a constant
//! `interval_ms`, filling each grid point from the surrounding real samples.
//!
//! # Features
//!
//! - [`resample`] — linear-fill resampling (the common case).
//! - [`resample_with`] — same, with a choice of [`FillMethod`]: linear
//!   interpolation, step-hold from the previous sample, or step-hold from the next.
//!
//! # Quick Start
//!
//! ```rust
//! use rune_resample::resample;
//!
//! let points = [(0, 0.0), (1000, 10.0), (3000, 30.0)];
//! let grid = resample(&points, 1000);
//! assert_eq!(grid, vec![(0, 0.0), (1000, 10.0), (2000, 20.0), (3000, 30.0)]);
//! ```
//!
//! # CLI
//!
//! ```bash
//! rune-resample --points "0,0;1000,10;3000,30" --interval-ms 1000
//! ```

/// How to fill a grid point between two real samples.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FillMethod {
    /// Linear interpolation between the bracketing samples.
    Linear,
    /// Hold the value of the most recent sample at or before the grid point.
    PreviousValue,
    /// Hold the value of the next sample at or after the grid point.
    NextValue,
}

#[allow(
    clippy::cast_precision_loss,
    reason = "counts and indices stay far below 2^52, so the f64 conversion is exact"
)]
fn linear_at(points: &[(i64, f64)], at: i64) -> Option<f64> {
    match points.len() {
        0 => None,
        1 => (points[0].0 == at).then_some(points[0].1),
        n => {
            if at < points[0].0 || at > points[n - 1].0 {
                return None;
            }
            points.windows(2).find_map(|w| {
                let (x0, y0) = w[0];
                let (x1, y1) = w[1];
                if at < x0 || at > x1 {
                    return None;
                }
                // Sample timestamps return their own value exactly: the
                // interpolation formula does not round-trip to `y1`.
                if at == x0 || x1 == x0 {
                    Some(y0)
                } else if at == x1 {
                    Some(y1)
                } else {
                    // Widen before subtracting: timestamps near the i64 limits
                    // would overflow a plain `i64` difference.
                    let t = (i128::from(at) - i128::from(x0)) as f64
                        / (i128::from(x1) - i128::from(x0)) as f64;
                    Some(t.mul_add(y1 - y0, y0))
                }
            })
        }
    }
}

fn sample_at(points: &[(i64, f64)], at: i64, method: FillMethod) -> Option<f64> {
    match method {
        FillMethod::Linear => linear_at(points, at),
        FillMethod::PreviousValue => points
            .iter()
            .rev()
            .find(|(ts, _)| *ts <= at)
            .map(|&(_, v)| v),
        FillMethod::NextValue => points.iter().find(|(ts, _)| *ts >= at).map(|&(_, v)| v),
    }
}

/// Resamples `points` (sorted by timestamp) onto a fixed `interval_ms` grid, using
/// linear interpolation. Equivalent to `resample_with(points, interval_ms, FillMethod::Linear)`.
///
/// # Example
///
/// ```rust
/// use rune_resample::resample;
///
/// let points = [(0, 0.0), (2000, 20.0)];
/// assert_eq!(resample(&points, 1000), vec![(0, 0.0), (1000, 10.0), (2000, 20.0)]);
/// ```
#[must_use]
pub fn resample(points: &[(i64, f64)], interval_ms: i64) -> Vec<(i64, f64)> {
    resample_with(points, interval_ms, FillMethod::Linear)
}

/// Resamples `points` (sorted by timestamp) onto a fixed `interval_ms` grid spanning
/// from the first to the last timestamp, using the given [`FillMethod`].
///
/// Returns an empty vector if `points` is empty or `interval_ms` is not positive.
/// The grid stops at the last timestamp, or earlier if the next grid point
/// would overflow `i64`. Linear fill propagates a `NaN` sample value into the
/// grid points between its neighbours; step fills copy it as-is.
///
/// # Example
///
/// ```rust
/// use rune_resample::{resample_with, FillMethod};
///
/// let points = [(0, 1.0), (1000, 2.0), (2500, 3.0)];
/// let grid = resample_with(&points, 1000, FillMethod::PreviousValue);
/// assert_eq!(grid, vec![(0, 1.0), (1000, 2.0), (2000, 2.0)]);
/// ```
#[must_use]
pub fn resample_with(
    points: &[(i64, f64)],
    interval_ms: i64,
    method: FillMethod,
) -> Vec<(i64, f64)> {
    if points.is_empty() || interval_ms <= 0 {
        return Vec::new();
    }
    let start = points[0].0;
    let end = points[points.len() - 1].0;

    let mut out = Vec::new();
    let mut t = start;
    while t <= end {
        if let Some(v) = sample_at(points, t, method) {
            out.push((t, v));
        }
        match t.checked_add(interval_ms) {
            Some(next) => t = next,
            None => break,
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn regular_interval_passthrough() {
        let points = [(0, 0.0), (1000, 1.0), (2000, 2.0)];
        assert_eq!(resample(&points, 1000), points.to_vec());
    }

    #[test]
    fn irregular_input_linear_fill() {
        let points = [(0, 0.0), (3000, 30.0)];
        let grid = resample(&points, 1000);
        assert_eq!(
            grid,
            vec![(0, 0.0), (1000, 10.0), (2000, 20.0), (3000, 30.0)]
        );
    }

    #[test]
    fn previous_value_step() {
        let points = [(0, 1.0), (1500, 2.0)];
        let grid = resample_with(&points, 1000, FillMethod::PreviousValue);
        assert_eq!(grid, vec![(0, 1.0), (1000, 1.0)]);
    }

    #[test]
    fn next_value_step() {
        let points = [(0, 1.0), (1500, 2.0)];
        let grid = resample_with(&points, 1000, FillMethod::NextValue);
        assert_eq!(grid, vec![(0, 1.0), (1000, 2.0)]);
    }

    #[test]
    fn empty_input_is_empty_output() {
        assert_eq!(resample(&[], 1000), Vec::new());
    }

    #[test]
    fn single_point_input_yields_single_grid_point() {
        let points = [(500, 7.0)];
        assert_eq!(resample(&points, 1000), vec![(500, 7.0)]);
    }

    /// Regression: the grid cursor used to overflow (panic in debug, endless
    /// loop in release) when the series ended near `i64::MAX`.
    #[test]
    fn grid_near_i64_max_terminates() {
        let points = [(i64::MAX - 2500, 0.0), (i64::MAX, 1.0)];
        let grid = resample_with(&points, 1000, FillMethod::PreviousValue);
        assert_eq!(
            grid,
            vec![
                (i64::MAX - 2500, 0.0),
                (i64::MAX - 1500, 0.0),
                (i64::MAX - 500, 0.0)
            ]
        );
    }

    /// Regression: `x1 - x0` used to overflow for a span wider than `i64::MAX`.
    #[test]
    fn linear_fill_across_full_i64_range() {
        let points = [(i64::MIN, 0.0), (i64::MAX, 1.0)];
        let grid = resample(&points, i64::MAX);
        assert_eq!(grid.len(), 3);
        assert_eq!(grid[0], (i64::MIN, 0.0));
        assert!((grid[1].1 - 0.5).abs() < 1e-12);
        assert_eq!(grid[1].0, -1);
    }

    #[test]
    fn negative_timestamps() {
        let points = [(-2000, -2.0), (0, 0.0)];
        assert_eq!(
            resample(&points, 500),
            vec![
                (-2000, -2.0),
                (-1500, -1.5),
                (-1000, -1.0),
                (-500, -0.5),
                (0, 0.0)
            ]
        );
    }

    /// Hand-computed reference on samples at 0 s, 0.4 s and 2.5 s: at 2 s the
    /// linear fill is `3 + 7 * 1600 / 2100`.
    #[test]
    fn fill_methods_reference_on_irregular_input() {
        let points = [(0, 1.0), (400, 3.0), (2500, 10.0)];
        assert_eq!(
            resample_with(&points, 1000, FillMethod::PreviousValue),
            vec![(0, 1.0), (1000, 3.0), (2000, 3.0)]
        );
        assert_eq!(
            resample_with(&points, 1000, FillMethod::NextValue),
            vec![(0, 1.0), (1000, 10.0), (2000, 10.0)]
        );
        let linear = resample(&points, 1000);
        let want = [(0, 1.0), (1000, 5.0), (2000, 8.333_333_333_333_334)];
        for ((t, v), (wt, wv)) in linear.iter().zip(want) {
            assert_eq!(*t, wt);
            assert!((v - wv).abs() < 1e-9, "t={t}: got {v}, want {wv}");
        }
    }

    /// Regression: a grid point landing on a sample used `y0 + 1.0 * (y1 - y0)`,
    /// which is not bit-exact `y1`.
    #[test]
    fn grid_point_on_sample_is_bit_exact() {
        let points = [(0, -968.334_830_125_686_5), (1000, 477.456_612_695_724_9)];
        assert_eq!(resample(&points, 1000)[1], (1000, 477.456_612_695_724_9));
    }

    #[test]
    fn duplicate_timestamps_do_not_divide_by_zero() {
        let points = [(0, 1.0), (1000, 2.0), (1000, 4.0), (2000, 4.0)];
        assert_eq!(
            resample(&points, 1000),
            vec![(0, 1.0), (1000, 2.0), (2000, 4.0)]
        );
    }

    #[test]
    fn nan_value_propagates_only_to_adjacent_linear_segments() {
        let points = [(0, 0.0), (1000, f64::NAN), (2000, 2.0), (3000, 3.0)];
        let grid = resample(&points, 500);
        assert!(grid[1].1.is_nan()); // 500 ms, between 0 and the NaN sample
        assert_eq!(grid[5], (2500, 2.5));
    }

    #[test]
    fn unsorted_input_yields_empty_grid() {
        let points = [(2000, 1.0), (0, 0.0)];
        assert_eq!(resample(&points, 1000), Vec::new());
    }

    #[test]
    fn non_positive_interval_yields_empty() {
        let points = [(0, 0.0), (1000, 1.0)];
        assert_eq!(resample(&points, 0), Vec::new());
        assert_eq!(resample(&points, -100), Vec::new());
    }
}
