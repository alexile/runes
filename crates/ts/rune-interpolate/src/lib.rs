//! Linear and natural cubic spline interpolation over irregular `(x, y)` series.
//!
//! Useful for filling gaps in sampled data — sensor readings, sparse time series,
//! or any series where you know pairs of points but need a value at an arbitrary
//! `x` between (or exactly at) them.
//!
//! # Features
//!
//! - [`linear`] — piecewise linear interpolation between the two bracketing points.
//! - [`cubic_spline`] — natural cubic spline (smooth, passes exactly through every
//!   input point, continuous first and second derivatives).
//! - [`fill_gaps_linear`] — batch-evaluate [`linear`] at a set of query points.
//!
//! Both interpolators are extrapolation-free: querying outside the input range
//! returns `None` rather than guessing.
//!
//! # Quick Start
//!
//! ```rust
//! use rune_interpolate::linear;
//!
//! let points = [(0.0, 0.0), (10.0, 100.0)];
//! assert_eq!(linear(&points, 5.0), Some(50.0));
//! assert_eq!(linear(&points, 15.0), None);
//! ```
//!
//! # CLI
//!
//! ```bash
//! rune-interpolate --points "0,0;10,100" --at 5 --method linear
//! ```

/// Piecewise linear interpolation. `points` must be sorted by `x`.
///
/// Returns `None` if `points` is empty, `at` is `NaN`, or `at` falls outside
/// `[points[0].0, points[last].0]`. A `NaN` `y` value propagates to queries in
/// the segments that touch it.
///
/// # Example
///
/// ```rust
/// use rune_interpolate::linear;
///
/// let points = [(0.0, 0.0), (2.0, 4.0), (4.0, 8.0)];
/// assert_eq!(linear(&points, 1.0), Some(2.0));
/// assert_eq!(linear(&points, 3.0), Some(6.0));
/// ```
#[allow(clippy::float_cmp, reason = "exact comparison is intended here")]
#[must_use]
pub fn linear(points: &[(f64, f64)], at: f64) -> Option<f64> {
    if at.is_nan() {
        return None;
    }
    match points.len() {
        0 => None,
        1 => {
            let (x0, y0) = points[0];
            (x0 == at).then_some(y0)
        }
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
                // Knots return their own value exactly: `y0 + 1.0 * (y1 - y0)`
                // does not round-trip to `y1` in floating point.
                if at == x0 || x1 == x0 {
                    Some(y0)
                } else if at == x1 {
                    Some(y1)
                } else {
                    let t = (at - x0) / (x1 - x0);
                    Some(t.mul_add(y1 - y0, y0))
                }
            })
        }
    }
}

struct SplineCoeffs {
    b: Vec<f64>,
    c: Vec<f64>,
    d: Vec<f64>,
}

/// Solves the natural cubic spline tridiagonal system, returning per-segment coefficients.
#[allow(
    clippy::many_single_char_names,
    reason = "short names follow the textbook notation"
)]
fn spline_coeffs(points: &[(f64, f64)]) -> SplineCoeffs {
    let n = points.len();
    let x: Vec<f64> = points.iter().map(|p| p.0).collect();
    let y: Vec<f64> = points.iter().map(|p| p.1).collect();

    let mut h = vec![0.0; n - 1];
    for i in 0..n - 1 {
        h[i] = x[i + 1] - x[i];
    }

    let mut alpha = vec![0.0; n];
    for i in 1..n - 1 {
        alpha[i] = (3.0 / h[i - 1]).mul_add(-(y[i] - y[i - 1]), 3.0 / h[i] * (y[i + 1] - y[i]));
    }

    let mut l = vec![1.0; n];
    let mut mu = vec![0.0; n];
    let mut z = vec![0.0; n];

    for i in 1..n - 1 {
        l[i] = h[i - 1].mul_add(-mu[i - 1], 2.0 * (x[i + 1] - x[i - 1]));
        mu[i] = h[i] / l[i];
        z[i] = h[i - 1].mul_add(-z[i - 1], alpha[i]) / l[i];
    }

    let mut c = vec![0.0; n];
    let mut b = vec![0.0; n - 1];
    let mut d = vec![0.0; n - 1];

    for j in (0..n - 1).rev() {
        c[j] = mu[j].mul_add(-c[j + 1], z[j]);
        b[j] = (y[j + 1] - y[j]) / h[j] - h[j] * 2.0f64.mul_add(c[j], c[j + 1]) / 3.0;
        d[j] = (c[j + 1] - c[j]) / (3.0 * h[j]);
    }

    SplineCoeffs { b, c, d }
}

/// Natural cubic spline interpolation. `points` must be sorted by `x` with at least 2 points.
///
/// Returns `None` if there are fewer than 2 points, the `x` values are not
/// strictly increasing (duplicates or `NaN` would divide by zero in the
/// spline system), or `at` is `NaN` or falls outside the input range.
/// The spline passes exactly through every input point.
///
/// # Example
///
/// ```rust
/// use rune_interpolate::cubic_spline;
///
/// let points = [(0.0, 0.0), (1.0, 1.0), (2.0, 0.0)];
/// // The spline passes exactly through each input point.
/// assert!((cubic_spline(&points, 1.0).unwrap() - 1.0).abs() < 1e-9);
/// ```
#[must_use]
pub fn cubic_spline(points: &[(f64, f64)], at: f64) -> Option<f64> {
    let n = points.len();
    if n < 2 || !points.windows(2).all(|w| w[1].0 > w[0].0) {
        return None;
    }
    if at.is_nan() || at < points[0].0 || at > points[n - 1].0 {
        return None;
    }

    let coeffs = spline_coeffs(points);
    let j = (0..n - 1).find(|&i| at >= points[i].0 && at <= points[i + 1].0)?;
    let dx = at - points[j].0;
    Some((coeffs.d[j] * dx * dx).mul_add(
        dx,
        (coeffs.c[j] * dx).mul_add(dx, coeffs.b[j].mul_add(dx, points[j].1)),
    ))
}

/// Batch-evaluates [`linear`] at each of `xs`, one [`Option<f64>`] per query point.
///
/// # Example
///
/// ```rust
/// use rune_interpolate::fill_gaps_linear;
///
/// let points = [(0.0, 0.0), (10.0, 100.0)];
/// let filled = fill_gaps_linear(&points, &[2.5, 5.0, 20.0]);
/// assert_eq!(filled, vec![Some(25.0), Some(50.0), None]);
/// ```
#[must_use]
pub fn fill_gaps_linear(points: &[(f64, f64)], xs: &[f64]) -> Vec<Option<f64>> {
    xs.iter().map(|&x| linear(points, x)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn linear_midpoint() {
        let points = [(0.0, 0.0), (10.0, 10.0)];
        assert_eq!(linear(&points, 5.0), Some(5.0));
    }

    #[test]
    fn linear_returns_none_outside_range() {
        let points = [(0.0, 0.0), (10.0, 10.0)];
        assert_eq!(linear(&points, -1.0), None);
        assert_eq!(linear(&points, 11.0), None);
    }

    #[test]
    fn linear_empty_is_none() {
        assert_eq!(linear(&[], 0.0), None);
    }

    #[test]
    fn linear_single_point_matches_only_at_its_x() {
        let points = [(5.0, 42.0)];
        assert_eq!(linear(&points, 5.0), Some(42.0));
        assert_eq!(linear(&points, 6.0), None);
    }

    #[test]
    fn linear_multi_segment() {
        let points = [(0.0, 0.0), (1.0, 10.0), (3.0, 30.0)];
        assert_eq!(linear(&points, 0.5), Some(5.0));
        assert_eq!(linear(&points, 2.0), Some(20.0));
    }

    #[test]
    fn cubic_spline_passes_through_input_points() {
        let points = [(0.0, 0.0), (1.0, 2.0), (2.0, 1.0), (3.0, 5.0)];
        for &(x, y) in &points {
            let interpolated = cubic_spline(&points, x).unwrap();
            assert!(
                (interpolated - y).abs() < 1e-9,
                "at x={x}: got {interpolated}, want {y}"
            );
        }
    }

    #[test]
    fn cubic_spline_on_straight_line_matches_linear() {
        let points = [(0.0, 0.0), (1.0, 2.0), (2.0, 4.0), (3.0, 6.0)];
        for at in [0.5, 1.5, 2.5] {
            let spline_val = cubic_spline(&points, at).unwrap();
            let linear_val = linear(&points, at).unwrap();
            assert!(
                (spline_val - linear_val).abs() < 1e-9,
                "at={at}: spline={spline_val}, linear={linear_val}"
            );
        }
    }

    #[test]
    fn cubic_spline_out_of_range_is_none() {
        let points = [(0.0, 0.0), (1.0, 1.0), (2.0, 0.0)];
        assert_eq!(cubic_spline(&points, -1.0), None);
        assert_eq!(cubic_spline(&points, 3.0), None);
    }

    #[test]
    fn cubic_spline_too_few_points_is_none() {
        assert_eq!(cubic_spline(&[(0.0, 0.0)], 0.0), None);
        assert_eq!(cubic_spline(&[], 0.0), None);
    }

    /// Reference: `scipy.interpolate.CubicSpline([0, 1, 2], [0, 1, 0],
    /// bc_type="natural")(0.5)` = 0.6875 (and 1.5 by symmetry).
    #[test]
    fn cubic_spline_matches_scipy_three_points() {
        let points = [(0.0, 0.0), (1.0, 1.0), (2.0, 0.0)];
        assert!((cubic_spline(&points, 0.5).unwrap() - 0.6875).abs() < 1e-12);
        assert!((cubic_spline(&points, 1.5).unwrap() - 0.6875).abs() < 1e-12);
    }

    /// Reference: natural spline through `y = x^3` at x = 0..3, solved exactly
    /// (second-derivative form): S(0.5) = 1/5, S(1.5) = 63/20, S(2.5) = 329/20.
    #[test]
    fn cubic_spline_matches_exact_natural_spline_of_cubic() {
        let points = [(0.0, 0.0), (1.0, 1.0), (2.0, 8.0), (3.0, 27.0)];
        for (at, want) in [(0.5, 0.2), (1.5, 3.15), (2.5, 16.45)] {
            let got = cubic_spline(&points, at).unwrap();
            assert!(
                (got - want).abs() < 1e-12,
                "at={at}: got {got}, want {want}"
            );
        }
    }

    #[test]
    fn cubic_spline_two_points_is_linear() {
        let points = [(1.0, 3.0), (3.0, 7.0)];
        assert!((cubic_spline(&points, 2.0).unwrap() - 5.0).abs() < 1e-12);
    }

    #[test]
    fn cubic_spline_irregular_spacing_hits_knots() {
        let points = [(0.0, 1.0), (0.3, -2.0), (2.0, 4.0), (2.1, 4.5), (7.0, 0.0)];
        for &(x, y) in &points {
            assert!((cubic_spline(&points, x).unwrap() - y).abs() < 1e-9);
        }
    }

    /// Regression: duplicate `x` values used to divide by zero and return `NaN`.
    #[test]
    fn cubic_spline_rejects_non_increasing_x() {
        assert_eq!(
            cubic_spline(&[(0.0, 0.0), (0.0, 1.0), (1.0, 2.0)], 0.5),
            None
        );
        assert_eq!(cubic_spline(&[(1.0, 0.0), (0.0, 1.0)], 0.5), None);
        assert_eq!(cubic_spline(&[(0.0, 0.0), (f64::NAN, 1.0)], 0.5), None);
    }

    /// Regression: `linear(points, NaN)` used to return `Some(NaN)`.
    #[test]
    fn nan_query_is_none() {
        let points = [(0.0, 0.0), (10.0, 10.0)];
        assert_eq!(linear(&points, f64::NAN), None);
        assert_eq!(cubic_spline(&points, f64::NAN), None);
    }

    #[test]
    fn nan_y_propagates_only_to_adjacent_segments() {
        let points = [(0.0, 0.0), (1.0, f64::NAN), (2.0, 2.0), (3.0, 3.0)];
        assert!(linear(&points, 0.5).unwrap().is_nan());
        assert_eq!(linear(&points, 2.5), Some(2.5));
    }

    #[test]
    fn linear_at_knots_and_endpoints_is_exact() {
        let points = [(-2.0, 4.0), (0.5, -1.0), (3.0, 9.0)];
        for &(x, y) in &points {
            assert_eq!(linear(&points, x), Some(y));
        }
    }

    /// Regression: the right-hand knot of a segment was computed as
    /// `y0 + 1.0 * (y1 - y0)`, which is not `y1` in floating point.
    #[test]
    fn linear_right_knot_is_bit_exact() {
        let points = [
            (0.01, -968.334_830_125_686_5),
            (0.02, 477.456_612_695_724_9),
        ];
        assert_eq!(linear(&points, 0.02), Some(477.456_612_695_724_9));
    }

    #[test]
    fn linear_duplicate_x_takes_first_value() {
        let points = [(0.0, 0.0), (1.0, 5.0), (1.0, 9.0), (2.0, 9.0)];
        assert_eq!(linear(&points, 1.0), Some(5.0));
    }

    #[test]
    fn fill_gaps_linear_matches_individual_calls() {
        let points = [(0.0, 0.0), (10.0, 100.0)];
        let xs = [1.0, 2.0, 20.0];
        let batch = fill_gaps_linear(&points, &xs);
        let individual: Vec<Option<f64>> = xs.iter().map(|&x| linear(&points, x)).collect();
        assert_eq!(batch, individual);
    }
}
