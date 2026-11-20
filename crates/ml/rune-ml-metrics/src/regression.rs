//! Regression metrics on real-valued targets and predictions.
//!
//! Every function takes `f32` or `f64` slices, checks they are non-empty,
//! equally long and finite, and accumulates in `f64` with compensated
//! summation.

use rune_ml_core::Float;

use crate::util::{Sum, check_finite, check_pair, to_f64};
use crate::{MetricsError, Result};

fn validate<F: Float>(y_true: &[F], y_pred: &[F]) -> Result<()> {
    check_pair(y_true, y_pred)?;
    check_finite(y_true)?;
    check_finite(y_pred)
}

fn mean_of<F: Float>(y_true: &[F], y_pred: &[F], f: impl Fn(f64, f64) -> f64) -> Result<f64> {
    validate(y_true, y_pred)?;
    let mut s = Sum::default();
    for (&t, &p) in y_true.iter().zip(y_pred) {
        s.add(f(t.to_f64(), p.to_f64()));
    }
    Ok(s.value() / to_f64(y_true.len()))
}

/// Mean absolute error, `mean(|y − ŷ|)`.
///
/// ```
/// use rune_ml_metrics::mean_absolute_error;
/// assert_eq!(mean_absolute_error(&[3.0, -0.5, 2.0, 7.0], &[2.5, 0.0, 2.0, 8.0])?, 0.5);
/// # Ok::<(), rune_ml_metrics::MetricsError>(())
/// ```
///
/// # Errors
///
/// [`MetricsError::Empty`], [`MetricsError::LengthMismatch`] or
/// [`MetricsError::NonFinite`].
pub fn mean_absolute_error<F: Float>(y_true: &[F], y_pred: &[F]) -> Result<f64> {
    mean_of(y_true, y_pred, |t, p| (t - p).abs())
}

/// Mean squared error, `mean((y − ŷ)²)`.
///
/// ```
/// use rune_ml_metrics::mean_squared_error;
/// assert_eq!(mean_squared_error(&[3.0, -0.5, 2.0, 7.0], &[2.5, 0.0, 2.0, 8.0])?, 0.375);
/// # Ok::<(), rune_ml_metrics::MetricsError>(())
/// ```
///
/// # Errors
///
/// As [`mean_absolute_error`].
pub fn mean_squared_error<F: Float>(y_true: &[F], y_pred: &[F]) -> Result<f64> {
    mean_of(y_true, y_pred, |t, p| (t - p) * (t - p))
}

/// Root mean squared error, `sqrt(MSE)`.
///
/// # Errors
///
/// As [`mean_absolute_error`].
pub fn root_mean_squared_error<F: Float>(y_true: &[F], y_pred: &[F]) -> Result<f64> {
    mean_squared_error(y_true, y_pred).map(f64::sqrt)
}

/// Mean absolute percentage error, `mean(|y − ŷ| / max(|y|, ε))` with `ε`
/// the `f64` machine epsilon, as scikit-learn.
///
/// The result is a fraction, not a percentage: `0.1` means 10 %. A target
/// of zero with a non-zero error gives a huge (but finite) value.
///
/// ```
/// use rune_ml_metrics::mean_absolute_percentage_error;
/// let m = mean_absolute_percentage_error(&[3.0, -0.5, 2.0, 7.0], &[2.5, 0.0, 2.0, 8.0])?;
/// assert!((m - 0.327_380_952_380_952_4).abs() < 1e-15);
/// # Ok::<(), rune_ml_metrics::MetricsError>(())
/// ```
///
/// # Errors
///
/// As [`mean_absolute_error`].
pub fn mean_absolute_percentage_error<F: Float>(y_true: &[F], y_pred: &[F]) -> Result<f64> {
    mean_of(y_true, y_pred, |t, p| {
        (t - p).abs() / t.abs().max(f64::EPSILON)
    })
}

/// Median of `|y − ŷ|`; robust to outliers. For an even count it is the mean
/// of the two middle values, as numpy's `median`.
///
/// ```
/// use rune_ml_metrics::median_absolute_error;
/// assert_eq!(median_absolute_error(&[3.0, -0.5, 2.0, 7.0], &[2.5, 0.0, 2.0, 8.0])?, 0.5);
/// # Ok::<(), rune_ml_metrics::MetricsError>(())
/// ```
///
/// # Errors
///
/// As [`mean_absolute_error`].
pub fn median_absolute_error<F: Float>(y_true: &[F], y_pred: &[F]) -> Result<f64> {
    validate(y_true, y_pred)?;
    let mut d: Vec<f64> = y_true
        .iter()
        .zip(y_pred)
        .map(|(&t, &p)| (t.to_f64() - p.to_f64()).abs())
        .collect();
    let n = d.len();
    let mid = n / 2;
    let (lower, m, _) = d.select_nth_unstable_by(mid, f64::total_cmp);
    let m = *m;
    if n % 2 == 1 {
        return Ok(m);
    }
    // The other middle value is the largest of the lower half.
    let below = lower.iter().copied().fold(f64::NEG_INFINITY, f64::max);
    Ok(below.midpoint(m))
}

/// Largest absolute error, `max |y − ŷ|`.
///
/// ```
/// use rune_ml_metrics::max_error;
/// assert_eq!(max_error(&[3.0, 2.0, 7.0, 1.0], &[4.0, 2.0, 7.0, 1.0])?, 1.0);
/// # Ok::<(), rune_ml_metrics::MetricsError>(())
/// ```
///
/// # Errors
///
/// As [`mean_absolute_error`].
pub fn max_error<F: Float>(y_true: &[F], y_pred: &[F]) -> Result<f64> {
    validate(y_true, y_pred)?;
    Ok(y_true
        .iter()
        .zip(y_pred)
        .map(|(&t, &p)| (t.to_f64() - p.to_f64()).abs())
        .fold(0.0, f64::max))
}

/// Mean of `y_true` and `Σ (y − mean)²`, two-pass for accuracy.
fn total_sum_of_squares(y: impl Iterator<Item = f64> + Clone, n: usize) -> (f64, f64) {
    let mean = {
        let mut s = Sum::default();
        y.clone().for_each(|v| s.add(v));
        s.value() / to_f64(n)
    };
    let mut ss = Sum::default();
    y.for_each(|v| ss.add((v - mean) * (v - mean)));
    (mean, ss.value())
}

/// scikit-learn's `force_finite=True`: a constant target gives 1.0 for a
/// perfect fit and 0.0 otherwise instead of `NaN` / `-inf`.
const fn finite_ratio(num: f64, den: f64) -> f64 {
    if den == 0.0 {
        if num == 0.0 { 1.0 } else { 0.0 }
    } else {
        1.0 - num / den
    }
}

const fn need_two<F>(y: &[F]) -> Result<()> {
    if y.len() < 2 {
        return Err(MetricsError::TooFewSamples {
            needed: 2,
            got: y.len(),
        });
    }
    Ok(())
}

/// Coefficient of determination `R² = 1 − Σ(y − ŷ)² / Σ(y − ȳ)²`.
///
/// `1.0` is a perfect fit, `0.0` is no better than predicting the mean, and
/// it can be arbitrarily negative. For a constant `y_true` it returns `1.0`
/// if the predictions are exact and `0.0` otherwise (scikit-learn's
/// `force_finite=True`).
///
/// ```
/// use rune_ml_metrics::r2_score;
/// let r2 = r2_score(&[3.0, -0.5, 2.0, 7.0], &[2.5, 0.0, 2.0, 8.0])?;
/// assert!((r2 - 0.948_608_137_044_967_9).abs() < 1e-15);
/// # Ok::<(), rune_ml_metrics::MetricsError>(())
/// ```
///
/// # Errors
///
/// As [`mean_absolute_error`], plus [`MetricsError::TooFewSamples`] for a
/// single sample (scikit-learn returns `NaN` there).
pub fn r2_score<F: Float>(y_true: &[F], y_pred: &[F]) -> Result<f64> {
    validate(y_true, y_pred)?;
    need_two(y_true)?;
    let mut rss = Sum::default();
    for (&t, &p) in y_true.iter().zip(y_pred) {
        let d = t.to_f64() - p.to_f64();
        rss.add(d * d);
    }
    let (_, tss) = total_sum_of_squares(y_true.iter().map(|v| v.to_f64()), y_true.len());
    Ok(finite_ratio(rss.value(), tss))
}

/// Explained variance `1 − Var(y − ŷ) / Var(y)`. Equals [`r2_score`] when the
/// residuals have zero mean; unlike R² it ignores a constant bias.
///
/// Constant targets are handled like [`r2_score`].
///
/// ```
/// use rune_ml_metrics::explained_variance_score;
/// let ev = explained_variance_score(&[3.0, -0.5, 2.0, 7.0], &[2.5, 0.0, 2.0, 8.0])?;
/// assert!((ev - 0.957_173_447_537_473_2).abs() < 1e-15);
/// # Ok::<(), rune_ml_metrics::MetricsError>(())
/// ```
///
/// # Errors
///
/// As [`r2_score`].
pub fn explained_variance_score<F: Float>(y_true: &[F], y_pred: &[F]) -> Result<f64> {
    validate(y_true, y_pred)?;
    need_two(y_true)?;
    let n = y_true.len();
    let resid = y_true
        .iter()
        .zip(y_pred)
        .map(|(&t, &p)| t.to_f64() - p.to_f64());
    let (_, num) = total_sum_of_squares(resid, n);
    let (_, den) = total_sum_of_squares(y_true.iter().map(|v| v.to_f64()), n);
    Ok(finite_ratio(num, den))
}
