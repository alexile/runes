//! Ranking metrics for binary scores: ROC and precision-recall curves.

use rune_ml_core::Float;

use crate::util::{Sum, check_finite, check_pair, to_f64};
use crate::{MetricsError, Result};

/// Cumulative counts at each distinct score, highest score first.
struct Steps<F> {
    fps: Vec<usize>,
    tps: Vec<usize>,
    thresholds: Vec<F>,
}

/// scikit-learn's `_binary_clf_curve`: sort by score (descending) and record
/// the false / true positive counts at the end of every run of equal scores.
/// Tied scores are one step, which is what gives ties half credit in the AUC.
fn binary_clf_curve<F: Float>(y_true: &[bool], y_score: &[F]) -> Result<Steps<F>> {
    check_pair(y_true, y_score)?;
    check_finite(y_score)?;
    let mut order: Vec<(F, bool)> = y_score
        .iter()
        .copied()
        .zip(y_true.iter().copied())
        .collect();
    order.sort_unstable_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(core::cmp::Ordering::Equal));
    let mut s = Steps {
        fps: Vec::new(),
        tps: Vec::new(),
        thresholds: Vec::new(),
    };
    let mut tp = 0usize;
    for (i, &(score, label)) in order.iter().enumerate() {
        tp += usize::from(label);
        if order.get(i + 1).is_none_or(|next| next.0 != score) {
            s.tps.push(tp);
            s.fps.push(i + 1 - tp);
            s.thresholds.push(score);
        }
    }
    Ok(s)
}

const fn missing(what: &'static str) -> MetricsError {
    MetricsError::MissingClass { missing: what }
}

/// Points of a receiver operating characteristic curve.
#[derive(Debug, Clone, PartialEq)]
pub struct RocCurve<F> {
    /// False positive rate at each threshold, increasing from 0 to 1.
    pub fpr: Vec<f64>,
    /// True positive rate at each threshold, increasing from 0 to 1.
    pub tpr: Vec<f64>,
    /// Decreasing score thresholds: a sample is predicted positive when its
    /// score is `>=` the threshold. The first is `+∞` (nothing predicted
    /// positive), as in scikit-learn ≥ 1.3.
    pub thresholds: Vec<F>,
}

/// ROC curve of a binary classifier, as `sklearn.metrics.roc_curve`.
///
/// `y_score` can be probabilities, decision values or any score where higher
/// means "more positive". With `drop_intermediate`, points that lie on a
/// straight segment between their neighbours are dropped; the area does not
/// change.
///
/// Unlike scikit-learn, which warns and fills the curve with `NaN`, a
/// `y_true` without positives or without negatives is an error.
///
/// ```
/// use rune_ml_metrics::roc_curve;
///
/// let roc = roc_curve(&[false, false, true, true], &[0.1, 0.4, 0.35, 0.8], true)?;
/// assert_eq!(roc.fpr, [0.0, 0.0, 0.5, 0.5, 1.0]);
/// assert_eq!(roc.tpr, [0.0, 0.5, 0.5, 1.0, 1.0]);
/// assert_eq!(roc.thresholds, [f64::INFINITY, 0.8, 0.4, 0.35, 0.1]);
/// # Ok::<(), rune_ml_metrics::MetricsError>(())
/// ```
///
/// # Errors
///
/// [`MetricsError::Empty`], [`MetricsError::LengthMismatch`],
/// [`MetricsError::NonFinite`] for a `NaN` or infinite score, or
/// [`MetricsError::MissingClass`].
pub fn roc_curve<F: Float>(
    y_true: &[bool],
    y_score: &[F],
    drop_intermediate: bool,
) -> Result<RocCurve<F>> {
    let mut s = binary_clf_curve(y_true, y_score)?;
    let (p, n) = positives_negatives(&s);
    if p == 0 {
        return Err(missing("positive"));
    }
    if n == 0 {
        return Err(missing("negative"));
    }
    if drop_intermediate && s.fps.len() > 2 {
        let m = s.fps.len();
        // Keep a point unless the second difference of both fps and tps is 0.
        let keep: Vec<bool> = (0..m)
            .map(|i| {
                i == 0
                    || i == m - 1
                    || s.fps[i + 1] + s.fps[i - 1] != 2 * s.fps[i]
                    || s.tps[i + 1] + s.tps[i - 1] != 2 * s.tps[i]
            })
            .collect();
        retain(&mut s, &keep);
    }
    let len = s.fps.len() + 1;
    let mut roc = RocCurve {
        fpr: Vec::with_capacity(len),
        tpr: Vec::with_capacity(len),
        thresholds: Vec::with_capacity(len),
    };
    roc.fpr.push(0.0);
    roc.tpr.push(0.0);
    roc.thresholds.push(F::INFINITY);
    let (pf, nf) = (to_f64(p), to_f64(n));
    for i in 0..s.fps.len() {
        roc.fpr.push(to_f64(s.fps[i]) / nf);
        roc.tpr.push(to_f64(s.tps[i]) / pf);
        roc.thresholds.push(s.thresholds[i]);
    }
    Ok(roc)
}

fn positives_negatives<F>(s: &Steps<F>) -> (usize, usize) {
    (
        s.tps.last().copied().unwrap_or(0),
        s.fps.last().copied().unwrap_or(0),
    )
}

fn retain<F: Copy>(s: &mut Steps<F>, keep: &[bool]) {
    let mut it = keep.iter();
    s.fps.retain(|_| it.next().copied().unwrap_or(true));
    let mut it = keep.iter();
    s.tps.retain(|_| it.next().copied().unwrap_or(true));
    let mut it = keep.iter();
    s.thresholds.retain(|_| it.next().copied().unwrap_or(true));
}

/// Area under the ROC curve: the probability that a random positive scores
/// higher than a random negative, with ties counted as one half (the
/// trapezoidal rule over tied runs, as scikit-learn).
///
/// The area is summed in exact integer arithmetic and divided once, so it is
/// correctly rounded.
///
/// ```
/// use rune_ml_metrics::roc_auc_score;
/// assert_eq!(roc_auc_score(&[false, false, true, true], &[0.1, 0.4, 0.35, 0.8])?, 0.75);
/// // One tie between a positive and a negative: half a point.
/// assert_eq!(roc_auc_score(&[false, true], &[0.5, 0.5])?, 0.5);
/// # Ok::<(), rune_ml_metrics::MetricsError>(())
/// ```
///
/// # Errors
///
/// As [`roc_curve`].
pub fn roc_auc_score<F: Float>(y_true: &[bool], y_score: &[F]) -> Result<f64> {
    let s = binary_clf_curve(y_true, y_score)?;
    let (p, n) = positives_negatives(&s);
    if p == 0 {
        return Err(missing("positive"));
    }
    if n == 0 {
        return Err(missing("negative"));
    }
    // 2·area·P·N = Σ Δfp · (tp_prev + tp), all integers.
    let (mut twice, mut fp0, mut tp0) = (0u128, 0usize, 0usize);
    for (&fp, &tp) in s.fps.iter().zip(&s.tps) {
        twice += (fp - fp0) as u128 * (tp0 + tp) as u128;
        (fp0, tp0) = (fp, tp);
    }
    let den = 2 * p as u128 * n as u128;
    Ok(ratio(twice, den))
}

/// `a / b` for big integers, correctly rounded when both fit in 2^53 and
/// otherwise within a couple of ulps.
#[allow(clippy::cast_precision_loss, reason = "documented rounding")]
fn ratio(a: u128, b: u128) -> f64 {
    if a == b {
        return 1.0;
    }
    let q = a / b;
    let r = a % b;
    q as f64 + r as f64 / b as f64
}

/// Points of a precision-recall curve.
#[derive(Debug, Clone, PartialEq)]
pub struct PrecisionRecallCurve<F> {
    /// Precision at each threshold, then a final `1.0`.
    pub precision: Vec<f64>,
    /// Recall at each threshold (decreasing), then a final `0.0`.
    pub recall: Vec<f64>,
    /// Increasing thresholds; one fewer than `precision` and `recall`.
    pub thresholds: Vec<F>,
}

/// Precision-recall pairs for every distinct threshold.
///
/// As `sklearn.metrics.precision_recall_curve`: ordered by increasing threshold
/// and ending with the point `(precision = 1, recall = 0)`, which has no
/// threshold.
///
/// With `drop_intermediate`, thresholds that do not change the recall
/// (no new true positive) are dropped.
///
/// Unlike scikit-learn, which warns and sets recall to 1, a `y_true` without
/// positives is an error.
///
/// ```
/// use rune_ml_metrics::precision_recall_curve;
///
/// let pr = precision_recall_curve(&[false, false, true, true], &[0.1, 0.4, 0.35, 0.8], false)?;
/// assert_eq!(pr.precision, [0.5, 2.0 / 3.0, 0.5, 1.0, 1.0]);
/// assert_eq!(pr.recall, [1.0, 1.0, 0.5, 0.5, 0.0]);
/// assert_eq!(pr.thresholds, [0.1, 0.35, 0.4, 0.8]);
/// # Ok::<(), rune_ml_metrics::MetricsError>(())
/// ```
///
/// # Errors
///
/// [`MetricsError::Empty`], [`MetricsError::LengthMismatch`],
/// [`MetricsError::NonFinite`] or [`MetricsError::MissingClass`].
pub fn precision_recall_curve<F: Float>(
    y_true: &[bool],
    y_score: &[F],
    drop_intermediate: bool,
) -> Result<PrecisionRecallCurve<F>> {
    let mut s = binary_clf_curve(y_true, y_score)?;
    let (p, _) = positives_negatives(&s);
    if p == 0 {
        return Err(missing("positive"));
    }
    if drop_intermediate && s.fps.len() > 2 {
        let m = s.fps.len();
        let keep: Vec<bool> = (0..m)
            .map(|i| i == 0 || i == m - 1 || s.tps[i] != s.tps[i - 1] || s.tps[i + 1] != s.tps[i])
            .collect();
        retain(&mut s, &keep);
    }
    let m = s.fps.len();
    let mut pr = PrecisionRecallCurve {
        precision: Vec::with_capacity(m + 1),
        recall: Vec::with_capacity(m + 1),
        thresholds: Vec::with_capacity(m),
    };
    let pf = to_f64(p);
    for i in (0..m).rev() {
        let tp = to_f64(s.tps[i]);
        // tps + fps = samples at or above the threshold, always >= 1.
        pr.precision.push(tp / to_f64(s.tps[i] + s.fps[i]));
        pr.recall.push(tp / pf);
        pr.thresholds.push(s.thresholds[i]);
    }
    pr.precision.push(1.0);
    pr.recall.push(0.0);
    Ok(pr)
}

/// Average precision: `Σₙ (Rₙ − Rₙ₋₁) Pₙ` over thresholds, the step-wise
/// (non-interpolated) area under the precision-recall curve, as
/// `sklearn.metrics.average_precision_score`.
///
/// ```
/// use rune_ml_metrics::average_precision_score;
/// let ap = average_precision_score(&[false, false, true, true], &[0.1, 0.4, 0.35, 0.8])?;
/// assert!((ap - 0.833_333_333_333_333_3).abs() < 1e-12);
/// # Ok::<(), rune_ml_metrics::MetricsError>(())
/// ```
///
/// # Errors
///
/// As [`precision_recall_curve`]; scikit-learn returns `0.0` with a warning
/// when there are no positives.
pub fn average_precision_score<F: Float>(y_true: &[bool], y_score: &[F]) -> Result<f64> {
    let s = binary_clf_curve(y_true, y_score)?;
    let (p, _) = positives_negatives(&s);
    if p == 0 {
        return Err(missing("positive"));
    }
    let mut sum = Sum::default();
    let mut tp0 = 0usize;
    for (&fp, &tp) in s.fps.iter().zip(&s.tps) {
        if tp > tp0 {
            sum.add(to_f64(tp - tp0) * to_f64(tp) / to_f64(tp + fp));
        }
        tp0 = tp;
    }
    Ok(sum.value() / to_f64(p))
}
