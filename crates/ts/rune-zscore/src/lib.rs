//! Z-score and IQR-based outlier/anomaly detection over a batch of numbers.
//!
//! Two independent, standard detectors, each usable on its own:
//!
//! - **Z-score**: flags points far from the mean in units of standard
//!   deviation. Sensitive to the outliers themselves, since they inflate the
//!   mean/stddev used to score them.
//! - **IQR (interquartile range)**: flags points outside `[Q1 - 1.5*IQR, Q3 +
//!   1.5*IQR]`. More robust to extreme outliers than the z-score method,
//!   since quantiles aren't pulled around by a handful of extreme values.
//!
//! # Quick Start
//!
//! ```rust
//! use rune_zscore::{zscore_outliers, iqr_outliers};
//!
//! let data = [2.0, 4.0, 4.0, 4.0, 5.0, 5.0, 7.0, 9.0];
//! assert_eq!(zscore_outliers(&data, 1.6), vec![7]); // the 9.0
//!
//! let data = [1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 9.0, 10.0, 100.0];
//! assert_eq!(iqr_outliers(&data), vec![10]); // the 100.0
//! ```
//!
//! # CLI
//!
//! ```bash
//! rune-zscore 2 4 4 4 5 5 7 9
//! ```

/// Population mean and standard deviation of the non-`NaN` values in `data`,
/// or `None` if there are none.
#[allow(
    clippy::cast_precision_loss,
    reason = "counts and indices stay far below 2^52, so the f64 conversion is exact"
)]
fn mean_and_stddev(data: &[f64]) -> Option<(f64, f64)> {
    let present = || data.iter().copied().filter(|x| !x.is_nan());
    let n = present().count();
    if n == 0 {
        return None;
    }
    let mean = present().sum::<f64>() / n as f64;
    let variance = present().map(|x| (x - mean).powi(2)).sum::<f64>() / n as f64;
    Some((mean, variance.sqrt()))
}

/// Computes the per-point z-score `(x - mean) / stddev` using the population
/// mean and standard deviation of `data`.
///
/// Returns an empty vector if `data` is empty, and all zeros if `data` has
/// zero variance (every z-score is well-defined as `0.0` in that case, not
/// `NaN`).
///
/// `NaN` entries are treated as missing: they are left out of the mean and
/// standard deviation, and their own z-score is `NaN` (so they are never
/// flagged by [`zscore_outliers`]). This matches
/// `scipy.stats.zscore(data, nan_policy="omit")`.
///
/// # Example
///
/// ```rust
/// use rune_zscore::zscores;
///
/// let data = [2.0, 4.0, 4.0, 4.0, 5.0, 5.0, 7.0, 9.0];
/// let z = zscores(&data);
/// assert!((z[7] - 2.0).abs() < 1e-9);
/// ```
#[must_use]
pub fn zscores(data: &[f64]) -> Vec<f64> {
    let Some((m, sd)) = mean_and_stddev(data) else {
        return vec![f64::NAN; data.len()];
    };
    data.iter()
        .map(|&x| {
            if x.is_nan() {
                f64::NAN
            } else if sd == 0.0 {
                0.0
            } else {
                (x - m) / sd
            }
        })
        .collect()
}

/// Returns the indices of points whose absolute z-score exceeds `threshold`.
///
/// # Example
///
/// ```rust
/// use rune_zscore::zscore_outliers;
///
/// let data = [2.0, 4.0, 4.0, 4.0, 5.0, 5.0, 7.0, 9.0];
/// assert_eq!(zscore_outliers(&data, 1.6), vec![7]);
/// ```
#[must_use]
pub fn zscore_outliers(data: &[f64], threshold: f64) -> Vec<usize> {
    zscores(data)
        .iter()
        .enumerate()
        .filter(|(_, z)| z.abs() > threshold)
        .map(|(i, _)| i)
        .collect()
}

#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss,
    reason = "the value is non-negative and bounded by the input size; float-to-int `as` saturates"
)]
fn quantile(sorted: &[f64], p: f64) -> f64 {
    match sorted.len() {
        0 => return f64::NAN,
        1 => return sorted[0],
        _ => {}
    }
    let index = p * (sorted.len() - 1) as f64;
    let lower = index.floor() as usize;
    let upper = index.ceil() as usize;
    if lower == upper {
        return sorted[lower];
    }
    let frac = index - lower as f64;
    frac.mul_add(sorted[upper] - sorted[lower], sorted[lower])
}

/// Computes the `(lower, upper)` Tukey fence bounds `[Q1 - 1.5*IQR, Q3 +
/// 1.5*IQR]` using linear-interpolation quantiles (the same convention as
/// `NumPy`'s default `linear` interpolation method).
///
/// `NaN` entries are ignored. If `data` holds no non-`NaN` value the bounds
/// are `(NaN, NaN)`, which flag nothing.
///
/// # Example
///
/// ```rust
/// use rune_zscore::iqr_bounds;
///
/// let data = [1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 9.0, 10.0];
/// let (lower, upper) = iqr_bounds(&data);
/// assert!((lower - -3.5).abs() < 1e-9);
/// assert!((upper - 14.5).abs() < 1e-9);
/// ```
#[must_use]
pub fn iqr_bounds(data: &[f64]) -> (f64, f64) {
    let mut sorted: Vec<f64> = data.iter().copied().filter(|x| !x.is_nan()).collect();
    sorted.sort_by(f64::total_cmp);
    let q1 = quantile(&sorted, 0.25);
    let q3 = quantile(&sorted, 0.75);
    let iqr = q3 - q1;
    (1.5f64.mul_add(-iqr, q1), 1.5f64.mul_add(iqr, q3))
}

/// Returns the indices of points falling outside the [`iqr_bounds`] fence.
///
/// # Example
///
/// ```rust
/// use rune_zscore::iqr_outliers;
///
/// let data = [1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 9.0, 10.0, 100.0];
/// assert_eq!(iqr_outliers(&data), vec![10]);
/// ```
#[must_use]
pub fn iqr_outliers(data: &[f64]) -> Vec<usize> {
    let (lower, upper) = iqr_bounds(data);
    data.iter()
        .enumerate()
        .filter(|&(_, &x)| x < lower || x > upper)
        .map(|(i, _)| i)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zscores_hand_computed() {
        // Classic example: mean = 5, population stddev = 2.
        let data = [2.0, 4.0, 4.0, 4.0, 5.0, 5.0, 7.0, 9.0];
        let z = zscores(&data);
        let expected = [-1.5, -0.5, -0.5, -0.5, 0.0, 0.0, 1.0, 2.0];
        for (got, want) in z.iter().zip(expected.iter()) {
            assert!((got - want).abs() < 1e-9, "got {got}, want {want}");
        }
    }

    #[test]
    fn zscore_outliers_flags_only_the_clear_outlier() {
        // mean=5, population stddev=2: z-scores are [-1.5, -0.5, -0.5, -0.5, 0, 0, 1.0, 2.0].
        // A threshold of 1.6 sits strictly between the mild deviation at index 0
        // (|z|=1.5) and the clear outlier at index 7 (|z|=2.0).
        let data = [2.0, 4.0, 4.0, 4.0, 5.0, 5.0, 7.0, 9.0];
        assert_eq!(zscore_outliers(&data, 1.6), vec![7]);
    }

    #[test]
    fn zscore_uniform_data_flags_nothing() {
        let data = [5.0; 10];
        assert_eq!(zscore_outliers(&data, 0.001), Vec::<usize>::new());
    }

    #[test]
    fn iqr_bounds_textbook_example() {
        let data = [1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 9.0, 10.0];
        let (lower, upper) = iqr_bounds(&data);
        assert!((lower - -3.5).abs() < 1e-9);
        assert!((upper - 14.5).abs() < 1e-9);
    }

    #[test]
    fn iqr_outliers_flags_the_extreme_point() {
        let data = [1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 9.0, 10.0, 100.0];
        assert_eq!(iqr_outliers(&data), vec![10]);
    }

    #[test]
    fn iqr_no_outlier_dataset_flags_nothing() {
        let data = [1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 9.0, 10.0];
        assert_eq!(iqr_outliers(&data), Vec::<usize>::new());
    }

    #[test]
    fn empty_input_returns_empty() {
        assert_eq!(zscores(&[]), Vec::<f64>::new());
        assert_eq!(zscore_outliers(&[], 1.0), Vec::<usize>::new());
    }

    /// Regression: `iqr_bounds(&[])` / `iqr_outliers(&[])` used to panic on
    /// `len() - 1` underflow.
    #[test]
    fn iqr_on_empty_input_does_not_panic() {
        let (lower, upper) = iqr_bounds(&[]);
        assert!(lower.is_nan() && upper.is_nan());
        assert_eq!(iqr_outliers(&[]), Vec::<usize>::new());
    }

    #[test]
    fn single_point() {
        assert_eq!(zscores(&[3.0]), vec![0.0]);
        assert_eq!(iqr_bounds(&[3.0]), (3.0, 3.0));
        assert_eq!(iqr_outliers(&[3.0]), Vec::<usize>::new());
    }

    /// Reference: `scipy.stats.zscore([1, 2, 3, 4, 5])` (ddof=0) =
    /// `[-sqrt(2), -sqrt(2)/2, 0, sqrt(2)/2, sqrt(2)]`.
    #[test]
    fn matches_scipy_population_zscore() {
        let z = zscores(&[1.0, 2.0, 3.0, 4.0, 5.0]);
        let r = std::f64::consts::SQRT_2;
        let want = [-r, -r / 2.0, 0.0, r / 2.0, r];
        for (got, want) in z.iter().zip(want) {
            assert!((got - want).abs() < 1e-12, "got {got}, want {want}");
        }
    }

    /// Reference: `numpy.percentile([7, 1, 3, 15, 9, 4], [25, 75])` = `[3.25, 8.5]`,
    /// so IQR = 5.25 and the fences are `-4.625` / `16.375`. Input is unsorted on purpose.
    #[test]
    fn iqr_bounds_match_numpy_linear_percentiles() {
        let (lower, upper) = iqr_bounds(&[7.0, 1.0, 3.0, 15.0, 9.0, 4.0]);
        assert!((lower - -4.625).abs() < 1e-12, "lower {lower}");
        assert!((upper - 16.375).abs() < 1e-12, "upper {upper}");
    }

    #[test]
    fn zscores_have_zero_mean_and_unit_variance() {
        let data = [3.1, -2.0, 8.5, 0.25, 4.0, 4.0, 11.0, -6.5];
        let z = zscores(&data);
        let n: f64 = z.iter().map(|_| 1.0).sum();
        let mean = z.iter().sum::<f64>() / n;
        let var = z.iter().map(|v| (v - mean).powi(2)).sum::<f64>() / n;
        assert!(mean.abs() < 1e-12);
        assert!((var - 1.0).abs() < 1e-12);
    }

    /// Regression: one `NaN` used to turn every z-score into `NaN`.
    #[test]
    fn nan_is_omitted_from_zscore_statistics() {
        let data = [2.0, 4.0, f64::NAN, 4.0, 4.0, 5.0, 5.0, 7.0, 9.0];
        let z = zscores(&data);
        assert!(z[2].is_nan());
        assert!((z[8] - 2.0).abs() < 1e-12);
        assert_eq!(zscore_outliers(&data, 1.6), vec![8]);
    }

    #[test]
    fn all_nan_input_yields_nan_scores_and_no_outliers() {
        let data = [f64::NAN, f64::NAN];
        assert!(zscores(&data).iter().all(|z| z.is_nan()));
        assert_eq!(zscore_outliers(&data, 0.0), Vec::<usize>::new());
        assert_eq!(iqr_outliers(&data), Vec::<usize>::new());
    }

    /// Regression: `NaN` used to sort to the end and drag Q3 to `NaN`.
    #[test]
    fn nan_is_ignored_by_iqr() {
        let data = [
            1.0,
            2.0,
            3.0,
            4.0,
            5.0,
            f64::NAN,
            6.0,
            7.0,
            8.0,
            9.0,
            10.0,
            100.0,
        ];
        assert_eq!(iqr_outliers(&data), vec![11]);
    }
}
