//! Metrics on predicted probabilities: log loss and Brier score.

use rune_ml_core::{Float, MatrixView};

use crate::util::{Sum, check_pair, check_probabilities, to_f64};
use crate::{MetricsError, Result};

/// Cross-entropy (logistic) loss, `−(1/n) Σ ln p(true class)`, natural log.
///
/// `y_prob` has one row per sample and one column per class, in the sorted
/// order of `labels` (or of the distinct labels of `y_true` when `labels` is
/// `None`). A single column with two classes is taken as the probability of
/// the second (larger) class, as in scikit-learn.
///
/// Probabilities are clipped to `[ε, 1 − ε]` with `ε` the machine epsilon of
/// `F`, so a confident wrong answer costs a large but finite loss. Rows are
/// not renormalised: like scikit-learn, the loss only reads the column of the
/// true class.
///
/// ```
/// use rune_ml_core::Matrix;
/// use rune_ml_metrics::log_loss;
///
/// let p = Matrix::from_rows(&[[0.1, 0.9], [0.9, 0.1], [0.8, 0.2], [0.35, 0.65]])?;
/// let l = log_loss(&["spam", "ham", "ham", "spam"], p.view(), None)?;
/// assert!((l - 0.216_161_874_680_579_12).abs() < 1e-12);
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
///
/// # Errors
///
/// - [`MetricsError::Empty`] or [`MetricsError::LengthMismatch`] (rows vs `y_true`);
/// - [`MetricsError::NonFinite`] / [`MetricsError::InvalidProbability`] for
///   values outside `[0, 1]` (flat row-major index);
/// - [`MetricsError::InvalidLabelCount`] for fewer than two classes, or a
///   column count that matches neither the class count nor 1 (binary);
/// - [`MetricsError::UnknownLabel`] if a `y_true` value is not in `labels`.
pub fn log_loss<L: Ord + Clone, F: Float>(
    y_true: &[L],
    y_prob: MatrixView<'_, F>,
    labels: Option<&[L]>,
) -> Result<f64> {
    if y_true.len() != y_prob.nrows() {
        return Err(MetricsError::LengthMismatch {
            expected: y_true.len(),
            found: y_prob.nrows(),
        });
    }
    if y_true.is_empty() {
        return Err(MetricsError::Empty);
    }
    check_probabilities(y_prob.as_slice())?;
    let mut classes: Vec<&L> =
        labels.map_or_else(|| y_true.iter().collect(), |l| l.iter().collect());
    classes.sort_unstable();
    classes.dedup();
    let k = classes.len();
    if k < 2 {
        return Err(MetricsError::label_count(format!(
            "log loss needs at least 2 classes, found {k}; pass the full label list"
        )));
    }
    let cols = y_prob.ncols();
    let binary = cols == 1 && k == 2;
    if cols != k && !binary {
        return Err(MetricsError::label_count(format!(
            "y_prob has {cols} columns for {k} classes"
        )));
    }
    let eps = F::EPSILON;
    let hi = F::ONE - eps;
    let mut sum = Sum::default();
    for (index, (t, row)) in y_true.iter().zip(y_prob.rows()).enumerate() {
        let c = classes
            .binary_search(&t)
            .map_err(|_| MetricsError::UnknownLabel { index })?;
        let p = if binary {
            if c == 1 { row[0] } else { F::ONE - row[0] }
        } else {
            row[c]
        };
        sum.add(p.max(eps).min(hi).to_f64().ln());
    }
    Ok(-sum.value() / to_f64(y_true.len()))
}

/// Brier score of binary probabilistic predictions: the mean squared
/// difference between the predicted probability of the positive class and
/// the outcome (1 for `true`, 0 for `false`). Lower is better.
///
/// ```
/// use rune_ml_metrics::brier_score_loss;
/// let b = brier_score_loss(&[false, true, true, false], &[0.1, 0.9, 0.8, 0.3])?;
/// assert!((b - 0.0375).abs() < 1e-12);
/// # Ok::<(), rune_ml_metrics::MetricsError>(())
/// ```
///
/// # Errors
///
/// [`MetricsError::Empty`], [`MetricsError::LengthMismatch`],
/// [`MetricsError::NonFinite`] or [`MetricsError::InvalidProbability`].
pub fn brier_score_loss<F: Float>(y_true: &[bool], y_prob: &[F]) -> Result<f64> {
    check_pair(y_true, y_prob)?;
    check_probabilities(y_prob)?;
    let mut sum = Sum::default();
    for (&t, &p) in y_true.iter().zip(y_prob) {
        let d = p.to_f64() - f64::from(u8::from(t));
        sum.add(d * d);
    }
    Ok(sum.value() / to_f64(y_true.len()))
}
