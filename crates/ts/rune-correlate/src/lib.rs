//! Cross-correlation and lag detection between two numeric series.
//!
//! Answers "how well do these two series line up, and by how much would I
//! need to shift one to make them line up best?" — useful for finding a
//! delay between two related sensors, or checking whether one series leads
//! or lags another.
//!
//! # Lag convention
//!
//! At lag `L`, [`cross_correlation`] pairs `a[i]` with `b[i + L]` for every `i`
//! where both indices are in bounds, and computes the Pearson correlation
//! coefficient over those pairs. A positive `L` means `b` is compared against
//! itself shifted backward relative to `a` — equivalently, if `b` is a delayed
//! copy of `a` (`b[i] = a[i - L]`), the best correlation is found at lag `+L`.
//!
//! # Features
//!
//! - [`cross_correlation`] — Pearson correlation at every integer lag in
//!   `-max_lag..=max_lag`.
//! - [`best_lag`] — the single lag with the highest correlation.
//!
//! # Quick Start
//!
//! ```rust
//! use rune_correlate::best_lag;
//!
//! let a = vec![1.0, 4.0, 2.0, 8.0, 5.0, 7.0, 3.0];
//! // b is a, delayed by 2 steps
//! let mut b = vec![0.0, 0.0, 1.0, 4.0, 2.0, 8.0, 5.0];
//! b[0] = -1.0;
//! b[1] = -1.0;
//! let (lag, corr) = best_lag(&a, &b, 4);
//! assert_eq!(lag, 2);
//! assert!(corr > 0.99);
//! ```
//!
//! # CLI
//!
//! ```bash
//! rune-correlate --max-lag 5 --a 1,2,3,4,5 --b 0,1,2,3,4
//! ```

#[allow(
    clippy::cast_precision_loss,
    reason = "counts and indices stay far below 2^52, so the f64 conversion is exact"
)]
fn pearson(x: &[f64], y: &[f64]) -> f64 {
    if x.len() < 2 {
        return 0.0;
    }
    let n = x.len() as f64;
    let mean_x = x.iter().sum::<f64>() / n;
    let mean_y = y.iter().sum::<f64>() / n;

    let mut cov = 0.0;
    let mut var_x = 0.0;
    let mut var_y = 0.0;
    for i in 0..x.len() {
        let dx = x[i] - mean_x;
        let dy = y[i] - mean_y;
        cov = dx.mul_add(dy, cov);
        var_x = dx.mul_add(dx, var_x);
        var_y = dy.mul_add(dy, var_y);
    }

    if var_x == 0.0 || var_y == 0.0 {
        return 0.0;
    }
    cov / (var_x.sqrt() * var_y.sqrt())
}

#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    reason = "the value is non-negative and bounded by the input size; float-to-int `as` saturates"
)]
fn correlation_at_lag(a: &[f64], b: &[f64], lag: i64) -> f64 {
    let mut xs = Vec::new();
    let mut ys = Vec::new();
    for (i, &ai) in a.iter().enumerate() {
        let j = i as i64 + lag;
        if j >= 0 && (j as usize) < b.len() {
            xs.push(ai);
            ys.push(b[j as usize]);
        }
    }
    pearson(&xs, &ys)
}

/// Computes the Pearson correlation between `a` and `b` at every integer lag
/// from `-max_lag` to `+max_lag`, inclusive.
///
/// See the module docs for the lag sign convention. Returns `2*max_lag + 1`
/// `(lag, correlation)` pairs, ordered by increasing lag. Lags with fewer than
/// 2 overlapping points, or with zero variance on either side, report a
/// correlation of `0.0`.
///
/// # Example
///
/// ```rust
/// use rune_correlate::cross_correlation;
///
/// let a = vec![1.0, 2.0, 3.0, 4.0];
/// let result = cross_correlation(&a, &a, 2);
/// assert_eq!(result.len(), 5);
/// let (lag_zero, corr) = result.iter().find(|(lag, _)| *lag == 0).unwrap();
/// assert_eq!(*lag_zero, 0);
/// assert!((corr - 1.0).abs() < 1e-9);
/// ```
#[allow(
    clippy::cast_possible_wrap,
    reason = "lengths and lags stay far below 2^52 and i64::MAX"
)]
#[must_use]
pub fn cross_correlation(a: &[f64], b: &[f64], max_lag: usize) -> Vec<(i64, f64)> {
    let max_lag = max_lag as i64;
    (-max_lag..=max_lag)
        .map(|lag| (lag, correlation_at_lag(a, b, lag)))
        .collect()
}

/// Returns the lag (within `-max_lag..=max_lag`) with the highest correlation,
/// and that correlation value.
///
/// Lags whose correlation is undefined (`NaN`, e.g. a constant series) are
/// skipped. If no lag has a defined correlation, returns `(0, 0.0)`.
///
/// # Example
///
/// ```rust
/// use rune_correlate::best_lag;
///
/// let a = vec![5.0, 1.0, 9.0, 2.0, 7.0];
/// let (lag, corr) = best_lag(&a, &a, 3);
/// assert_eq!(lag, 0);
/// assert!((corr - 1.0).abs() < 1e-9);
/// ```
#[must_use]
pub fn best_lag(a: &[f64], b: &[f64], max_lag: usize) -> (i64, f64) {
    cross_correlation(a, b, max_lag)
        .into_iter()
        .filter(|(_, corr)| !corr.is_nan())
        .max_by(|(_, ca), (_, cb)| ca.total_cmp(cb))
        .unwrap_or((0, 0.0))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identical_series_correlate_perfectly_at_zero_lag() {
        let a = vec![1.0, 4.0, 2.0, 8.0, 5.0, 7.0, 3.0];
        let (lag, corr) = best_lag(&a, &a, 3);
        assert_eq!(lag, 0);
        assert!((corr - 1.0).abs() < 1e-9);
    }

    #[test]
    fn shifted_copy_is_found_at_the_correct_lag() {
        let a = vec![1.0, 4.0, 2.0, 8.0, 5.0, 7.0, 3.0, 9.0, 6.0, 10.0];
        let mut b = vec![-1.0, -1.0, -1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0];
        b[3..a.len()].copy_from_slice(&a[..(a.len() - 3)]);
        let (lag, corr) = best_lag(&a, &b, 5);
        assert_eq!(lag, 3);
        assert!(corr > 0.99, "corr={corr}");
    }

    #[test]
    fn anti_correlated_series_have_negative_correlation() {
        let a = vec![1.0, 4.0, 2.0, 8.0, 5.0, 7.0, 3.0];
        let b: Vec<f64> = a.iter().map(|&x| -x).collect();
        let corr = correlation_at_lag(&a, &b, 0);
        assert!(corr < -0.99, "corr={corr}");
    }

    #[test]
    fn constant_series_has_zero_correlation() {
        let varying = vec![1.0, 2.0, 3.0, 4.0, 5.0];
        let constant = vec![7.0; 5];
        for (_, corr) in cross_correlation(&varying, &constant, 2) {
            assert_eq!(corr, 0.0);
        }
    }

    #[test]
    fn cross_correlation_length_matches_max_lag() {
        let a = vec![1.0, 2.0, 3.0];
        let result = cross_correlation(&a, &a, 4);
        assert_eq!(result.len(), 9);
    }

    #[test]
    fn cross_correlation_lags_are_ordered_ascending() {
        let a = vec![1.0, 2.0, 3.0, 4.0];
        let result = cross_correlation(&a, &a, 3);
        let lags: Vec<i64> = result.iter().map(|(lag, _)| *lag).collect();
        assert_eq!(lags, vec![-3, -2, -1, 0, 1, 2, 3]);
    }

    #[test]
    fn short_overlap_does_not_panic() {
        let a = vec![1.0, 2.0];
        let b = vec![3.0, 4.0];
        let result = cross_correlation(&a, &b, 5);
        assert_eq!(result.len(), 11);
    }
}
