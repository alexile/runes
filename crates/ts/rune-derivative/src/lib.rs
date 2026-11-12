//! Rate-of-change (derivative) and cumulative (integral) calculation over a
//! timestamped numeric series.
//!
//! Points are `(ts_ms, value)` pairs sorted ascending by timestamp. The derivative
//! is a simple finite difference between consecutive points, expressed in
//! value-per-second; the integral uses the trapezoidal rule, expressed in
//! value-seconds.
//!
//! # Features
//!
//! - [`derivative`] — per-interval rate of change, one point per consecutive pair.
//! - [`integral`] — total trapezoidal-rule area under the series.
//! - [`cumulative_integral`] — running trapezoidal integral, one output per input point.
//!
//! # Quick Start
//!
//! ```rust
//! use rune_derivative::derivative;
//!
//! // v = t: a straight ramp, so the rate of change is a constant 1.0 units/sec.
//! let points = vec![(0, 0.0), (1000, 1.0), (2000, 2.0)];
//! let rates = derivative(&points);
//! assert_eq!(rates.len(), 2);
//! assert!((rates[0].1 - 1.0).abs() < 1e-9);
//! assert!((rates[1].1 - 1.0).abs() < 1e-9);
//! ```
//!
//! # CLI
//!
//! ```bash
//! rune-derivative series.csv
//! ```

/// Computes the rate of change between each consecutive pair of points.
///
/// Each output point is `(ts, rate)` where `rate = (v2 - v1) / dt_seconds` and `ts`
/// is the timestamp of the *second* point in the pair. Returns one fewer point than
/// the input; returns an empty vector for inputs of length 0 or 1.
///
/// # Example
///
/// ```rust
/// use rune_derivative::derivative;
///
/// let points = vec![(0, 10.0), (1000, 10.0)]; // constant series
/// let rates = derivative(&points);
/// assert!((rates[0].1).abs() < 1e-9);
/// ```
#[allow(
    clippy::cast_precision_loss,
    reason = "counts and indices stay far below 2^52, so the f64 conversion is exact"
)]
#[must_use]
pub fn derivative(points: &[(i64, f64)]) -> Vec<(i64, f64)> {
    if points.len() < 2 {
        return Vec::new();
    }
    points
        .windows(2)
        .map(|pair| {
            let (t1, v1) = pair[0];
            let (t2, v2) = pair[1];
            let dt_secs = (t2 - t1) as f64 / 1000.0;
            let rate = if dt_secs == 0.0 {
                0.0
            } else {
                (v2 - v1) / dt_secs
            };
            (t2, rate)
        })
        .collect()
}

/// Computes the total trapezoidal-rule integral of the series, in value-seconds.
///
/// Returns `0.0` for inputs of length 0 or 1.
///
/// # Example
///
/// ```rust
/// use rune_derivative::integral;
///
/// // constant value 2.0 held for 10 seconds -> area = 20.0
/// let points = vec![(0, 2.0), (10_000, 2.0)];
/// assert!((integral(&points) - 20.0).abs() < 1e-9);
/// ```
#[allow(
    clippy::cast_precision_loss,
    reason = "counts and indices stay far below 2^52, so the f64 conversion is exact"
)]
#[must_use]
pub fn integral(points: &[(i64, f64)]) -> f64 {
    if points.len() < 2 {
        return 0.0;
    }
    points
        .windows(2)
        .map(|pair| {
            let (t1, v1) = pair[0];
            let (t2, v2) = pair[1];
            let dt_secs = (t2 - t1) as f64 / 1000.0;
            f64::midpoint(v1, v2) * dt_secs
        })
        .sum()
}

/// Computes the running trapezoidal integral, one output point per input point.
///
/// The first output point always has cumulative value `0.0`. Returns an empty
/// vector for an empty input; a single-point input returns `[(ts, 0.0)]`.
///
/// # Example
///
/// ```rust
/// use rune_derivative::{cumulative_integral, integral};
///
/// let points = vec![(0, 1.0), (1000, 1.0), (2000, 3.0)];
/// let cum = cumulative_integral(&points);
/// assert_eq!(cum.len(), 3);
/// assert!((cum[0].1).abs() < 1e-9);
/// assert!((cum.last().unwrap().1 - integral(&points)).abs() < 1e-9);
/// ```
#[allow(
    clippy::cast_precision_loss,
    reason = "counts and indices stay far below 2^52, so the f64 conversion is exact"
)]
#[must_use]
pub fn cumulative_integral(points: &[(i64, f64)]) -> Vec<(i64, f64)> {
    if points.is_empty() {
        return Vec::new();
    }
    let mut out = Vec::with_capacity(points.len());
    let mut running = 0.0;
    out.push((points[0].0, 0.0));
    for pair in points.windows(2) {
        let (t1, v1) = pair[0];
        let (t2, v2) = pair[1];
        let dt_secs = (t2 - t1) as f64 / 1000.0;
        running = f64::mul_add(f64::midpoint(v1, v2), dt_secs, running);
        out.push((t2, running));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derivative_of_linear_ramp_is_constant() {
        let points = vec![(0, 0.0), (1000, 1.0), (2000, 2.0), (3000, 3.0)];
        let rates = derivative(&points);
        assert_eq!(rates.len(), 3);
        for (_, rate) in rates {
            assert!((rate - 1.0).abs() < 1e-9);
        }
    }

    #[test]
    fn derivative_of_constant_series_is_zero() {
        let points = vec![(0, 5.0), (1000, 5.0), (2000, 5.0)];
        let rates = derivative(&points);
        for (_, rate) in rates {
            assert!(rate.abs() < 1e-9);
        }
    }

    #[test]
    fn derivative_timestamps_are_second_point() {
        let points = vec![(0, 0.0), (500, 1.0)];
        let rates = derivative(&points);
        assert_eq!(rates[0].0, 500);
    }

    #[test]
    fn derivative_handles_short_input() {
        assert_eq!(derivative(&[]), [] as [(i64, f64); 0]);
        assert_eq!(derivative(&[(0, 1.0)]), [] as [(i64, f64); 0]);
    }

    #[test]
    fn integral_of_constant_value() {
        let points = vec![(0, 2.0), (10_000, 2.0)];
        assert!((integral(&points) - 20.0).abs() < 1e-9);
    }

    #[test]
    fn integral_of_short_input_is_zero() {
        assert_eq!(integral(&[]), 0.0);
        assert_eq!(integral(&[(0, 1.0)]), 0.0);
    }

    #[test]
    fn integral_of_ramp() {
        // v = t/1000 from t=0 to t=2000ms -> triangle area = 0.5 * base(2s) * height(2.0) = 2.0
        let points = vec![(0, 0.0), (1000, 1.0), (2000, 2.0)];
        assert!((integral(&points) - 2.0).abs() < 1e-9);
    }

    #[test]
    fn cumulative_integral_last_matches_integral_total() {
        let points = vec![(0, 1.0), (1000, 1.0), (2000, 3.0), (5000, 0.0)];
        let cum = cumulative_integral(&points);
        assert_eq!(cum.len(), points.len());
        assert!((cum.last().unwrap().1 - integral(&points)).abs() < 1e-9);
    }

    #[test]
    fn cumulative_integral_first_point_is_zero() {
        let points = vec![(0, 42.0), (1000, 1.0)];
        let cum = cumulative_integral(&points);
        assert_eq!(cum[0], (0, 0.0));
    }

    #[test]
    fn cumulative_integral_handles_edge_cases() {
        assert_eq!(cumulative_integral(&[]), [] as [(i64, f64); 0]);
        let single = cumulative_integral(&[(10, 5.0)]);
        assert_eq!(single, vec![(10, 0.0)]);
    }
}
