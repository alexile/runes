//! Classification metrics computed from hard label predictions.

use core::fmt;
use core::ops::Index;

use crate::util::{Encoded, check_pair, encode_sorted, to_f64};
use crate::{MetricsError, Result};

/// What to return when a ratio has a zero denominator, as scikit-learn's
/// `zero_division` parameter.
///
/// Precision is undefined for a class that is never predicted
/// (`tp + fp = 0`), recall for a class that never occurs (`tp + fn = 0`) and
/// the F-score when both are zero. scikit-learn's default, `"warn"`, returns
/// `0.0` and emits a warning; this crate has no warnings, so the default is
/// [`ZeroDivision::Zero`].
///
/// With [`ZeroDivision::Nan`], undefined per-class values are skipped when
/// averaging (scikit-learn's `nanaverage`), and the average is `NaN` only if
/// every class is undefined.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ZeroDivision {
    /// Undefined ratios are `0.0` (scikit-learn's `"warn"` and `0`).
    #[default]
    Zero,
    /// Undefined ratios are `1.0`.
    One,
    /// Undefined ratios are `NaN` and are ignored by the averages.
    Nan,
}

impl ZeroDivision {
    const fn value(self) -> f64 {
        match self {
            Self::Zero => 0.0,
            Self::One => 1.0,
            Self::Nan => f64::NAN,
        }
    }

    fn divide(self, num: f64, den: f64) -> f64 {
        if den == 0.0 { self.value() } else { num / den }
    }
}

/// How per-class precision, recall and F-scores are combined into one number.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Average<L> {
    /// Only report the score of `pos_label`. The data must have at most two
    /// distinct labels, and if it has two, one must be `pos_label`.
    Binary {
        /// The positive class.
        pos_label: L,
    },
    /// Count true positives, false negatives and false positives over all
    /// classes, then compute the ratio once. For single-label multiclass data
    /// micro precision, recall and F1 all equal the accuracy.
    Micro,
    /// Unweighted mean over classes.
    Macro,
    /// Mean over classes weighted by support (number of true samples).
    Weighted,
}

/// Fraction of samples whose prediction equals the target.
///
/// ```
/// use rune_ml_metrics::accuracy_score;
/// assert_eq!(accuracy_score(&[0, 1, 2, 3], &[0, 2, 1, 3])?, 0.5);
/// # Ok::<(), rune_ml_metrics::MetricsError>(())
/// ```
///
/// # Errors
///
/// [`MetricsError::Empty`] or [`MetricsError::LengthMismatch`].
pub fn accuracy_score<L: PartialEq>(y_true: &[L], y_pred: &[L]) -> Result<f64> {
    check_pair(y_true, y_pred)?;
    let hits = y_true.iter().zip(y_pred).filter(|(a, b)| a == b).count();
    Ok(to_f64(hits) / to_f64(y_true.len()))
}

/// Mean recall over the classes present in `y_true`.
///
/// Classes that only appear in `y_pred` are ignored, as in scikit-learn.
/// With `adjusted`, the score is rescaled so random guessing gives `0` and
/// perfect prediction `1`: `(score − 1/k) / (1 − 1/k)`; for a single class
/// this is `0 / 0` and the result is `NaN`, as in numpy.
///
/// # Errors
///
/// [`MetricsError::Empty`] or [`MetricsError::LengthMismatch`].
pub fn balanced_accuracy_score<L: Ord + Clone>(
    y_true: &[L],
    y_pred: &[L],
    adjusted: bool,
) -> Result<f64> {
    check_pair(y_true, y_pred)?;
    let c = Counts::new(&encode_sorted(y_true, y_pred));
    let (mut sum, mut k) = (0.0, 0usize);
    for (&tp, &t) in c.tp.iter().zip(&c.true_sum) {
        if t > 0 {
            sum += to_f64(tp) / to_f64(t);
            k += 1;
        }
    }
    let score = sum / to_f64(k);
    if adjusted {
        let chance = 1.0 / to_f64(k);
        Ok((score - chance) / (1.0 - chance))
    } else {
        Ok(score)
    }
}

/// Per-class true positives and predicted / true totals.
struct Counts {
    tp: Vec<usize>,
    pred_sum: Vec<usize>,
    true_sum: Vec<usize>,
}

impl Counts {
    fn new<L>(e: &Encoded<L>) -> Self {
        let k = e.classes.len();
        let mut c = Self {
            tp: vec![0; k],
            pred_sum: vec![0; k],
            true_sum: vec![0; k],
        };
        for (&t, &p) in e.a.iter().zip(&e.b) {
            c.true_sum[t] += 1;
            c.pred_sum[p] += 1;
            if t == p {
                c.tp[t] += 1;
            }
        }
        c
    }
}

/// Precision, recall, F-score and support for every class.
///
/// Returned by [`precision_recall_fscore_support`]. Each vector is indexed
/// like `labels`, which holds the sorted union of the labels in `y_true` and
/// `y_pred`.
#[derive(Debug, Clone, PartialEq)]
pub struct ClassScores<L> {
    /// Class labels in sorted order.
    pub labels: Vec<L>,
    /// `tp / (tp + fp)` per class.
    pub precision: Vec<f64>,
    /// `tp / (tp + fn)` per class.
    pub recall: Vec<f64>,
    /// F-beta per class.
    pub f_score: Vec<f64>,
    /// Number of true samples of each class.
    pub support: Vec<usize>,
}

fn check_beta(beta: f64) -> Result<()> {
    if beta.is_nan() || beta < 0.0 {
        return Err(MetricsError::parameter(
            "beta",
            format!("must be >= 0, got {beta}"),
        ));
    }
    Ok(())
}

/// `(precision, recall, f)` from raw counts, following scikit-learn: the
/// F-score is `(1 + β²)·tp / ((1 + β²)·tp + β²·fn + fp)` computed from the
/// counts, so it is only undefined when there are no true and no predicted
/// samples. `β = 0` gives precision and `β = ∞` recall.
fn prf(tp: usize, pred: usize, truth: usize, beta: f64, zd: ZeroDivision) -> (f64, f64, f64) {
    let (tp, pred, truth) = (to_f64(tp), to_f64(pred), to_f64(truth));
    let p = zd.divide(tp, pred);
    let r = zd.divide(tp, truth);
    let f = if beta == f64::INFINITY {
        r
    } else if beta == 0.0 {
        p
    } else {
        let b2 = beta * beta;
        zd.divide((1.0 + b2) * tp, b2.mul_add(truth, pred))
    };
    (p, r, f)
}

/// Per-class precision, recall, F-beta and support, as
/// `sklearn.metrics.precision_recall_fscore_support(average=None)`.
///
/// ```
/// use rune_ml_metrics::{precision_recall_fscore_support, ZeroDivision};
///
/// let s = precision_recall_fscore_support(&["cat", "dog", "dog"], &["cat", "cat", "dog"], 1.0, ZeroDivision::Zero)?;
/// assert_eq!(s.labels, ["cat", "dog"]);
/// assert_eq!(s.precision, [0.5, 1.0]);
/// assert_eq!(s.recall, [1.0, 0.5]);
/// assert_eq!(s.support, [1, 2]);
/// # Ok::<(), rune_ml_metrics::MetricsError>(())
/// ```
///
/// # Errors
///
/// [`MetricsError::Empty`], [`MetricsError::LengthMismatch`], or
/// [`MetricsError::InvalidParameter`] for a negative or `NaN` `beta`.
pub fn precision_recall_fscore_support<L: Ord + Clone>(
    y_true: &[L],
    y_pred: &[L],
    beta: f64,
    zero_division: ZeroDivision,
) -> Result<ClassScores<L>> {
    check_pair(y_true, y_pred)?;
    check_beta(beta)?;
    let e = encode_sorted(y_true, y_pred);
    let c = Counts::new(&e);
    let k = e.classes.len();
    let mut out = ClassScores {
        labels: e.classes,
        precision: Vec::with_capacity(k),
        recall: Vec::with_capacity(k),
        f_score: Vec::with_capacity(k),
        support: c.true_sum.clone(),
    };
    for i in 0..k {
        let (p, r, f) = prf(c.tp[i], c.pred_sum[i], c.true_sum[i], beta, zero_division);
        out.precision.push(p);
        out.recall.push(r);
        out.f_score.push(f);
    }
    Ok(out)
}

/// Weighted mean that skips `NaN` entries; `NaN` if all are `NaN`. With
/// all-zero weights it falls back to the plain mean (scikit-learn's
/// `_nanaverage`).
fn nan_average(v: &[f64], w: Option<&[usize]>) -> f64 {
    let (mut num, mut den, mut plain, mut n) = (0.0, 0.0, 0.0, 0usize);
    for (i, &x) in v.iter().enumerate() {
        if x.is_nan() {
            continue;
        }
        let wi = w.map_or(1.0, |w| to_f64(w[i]));
        num += wi * x;
        den += wi;
        plain += x;
        n += 1;
    }
    if n == 0 {
        f64::NAN
    } else if den == 0.0 {
        plain / to_f64(n)
    } else {
        num / den
    }
}

/// Averaged `(precision, recall, f_beta)`.
fn averaged<L: Ord + Clone>(
    y_true: &[L],
    y_pred: &[L],
    beta: f64,
    average: &Average<L>,
    zd: ZeroDivision,
) -> Result<(f64, f64, f64)> {
    check_pair(y_true, y_pred)?;
    check_beta(beta)?;
    let e = encode_sorted(y_true, y_pred);
    let c = Counts::new(&e);
    match average {
        Average::Binary { pos_label } => {
            if e.classes.len() > 2 {
                return Err(MetricsError::NotBinary {
                    found: e.classes.len(),
                });
            }
            match e.classes.binary_search(pos_label) {
                Ok(i) => Ok(prf(c.tp[i], c.pred_sum[i], c.true_sum[i], beta, zd)),
                Err(_) if e.classes.len() == 2 => Err(MetricsError::UnknownPosLabel),
                // A single label that is not the positive one: no positives at all.
                Err(_) => Ok(prf(0, 0, 0, beta, zd)),
            }
        }
        Average::Micro => {
            let tp = c.tp.iter().sum();
            // Every sample is counted once as predicted and once as true.
            let n = y_true.len();
            Ok(prf(tp, n, n, beta, zd))
        }
        Average::Macro | Average::Weighted => {
            let k = e.classes.len();
            let (mut p, mut r, mut f) = (
                Vec::with_capacity(k),
                Vec::with_capacity(k),
                Vec::with_capacity(k),
            );
            for i in 0..k {
                let s = prf(c.tp[i], c.pred_sum[i], c.true_sum[i], beta, zd);
                p.push(s.0);
                r.push(s.1);
                f.push(s.2);
            }
            let w = matches!(average, Average::Weighted).then_some(c.true_sum.as_slice());
            Ok((nan_average(&p, w), nan_average(&r, w), nan_average(&f, w)))
        }
    }
}

/// Precision `tp / (tp + fp)`: of the samples predicted positive, the share
/// that really are.
///
/// See [`Average`] for multiclass averaging and [`ZeroDivision`] for classes
/// that are never predicted.
///
/// ```
/// use rune_ml_metrics::{precision_score, Average, ZeroDivision};
///
/// let y_true = [0, 1, 2, 0, 1, 2];
/// let y_pred = [0, 2, 1, 0, 0, 1];
/// let p = precision_score(&y_true, &y_pred, &Average::Macro, ZeroDivision::Zero)?;
/// assert!((p - 2.0 / 9.0).abs() < 1e-12);
/// # Ok::<(), rune_ml_metrics::MetricsError>(())
/// ```
///
/// # Errors
///
/// [`MetricsError::Empty`], [`MetricsError::LengthMismatch`],
/// [`MetricsError::NotBinary`] or [`MetricsError::UnknownPosLabel`] for
/// [`Average::Binary`] on data it does not fit.
pub fn precision_score<L: Ord + Clone>(
    y_true: &[L],
    y_pred: &[L],
    average: &Average<L>,
    zero_division: ZeroDivision,
) -> Result<f64> {
    averaged(y_true, y_pred, 1.0, average, zero_division).map(|s| s.0)
}

/// Recall `tp / (tp + fn)`: of the truly positive samples, the share found.
///
/// # Errors
///
/// As [`precision_score`].
pub fn recall_score<L: Ord + Clone>(
    y_true: &[L],
    y_pred: &[L],
    average: &Average<L>,
    zero_division: ZeroDivision,
) -> Result<f64> {
    averaged(y_true, y_pred, 1.0, average, zero_division).map(|s| s.1)
}

/// F1 score, the harmonic mean of precision and recall.
///
/// ```
/// use rune_ml_metrics::{f1_score, Average, ZeroDivision};
///
/// let f = f1_score(&[1, 1, 0, 0], &[1, 0, 1, 0], &Average::Binary { pos_label: 1 }, ZeroDivision::Zero)?;
/// assert_eq!(f, 0.5);
/// # Ok::<(), rune_ml_metrics::MetricsError>(())
/// ```
///
/// # Errors
///
/// As [`precision_score`].
pub fn f1_score<L: Ord + Clone>(
    y_true: &[L],
    y_pred: &[L],
    average: &Average<L>,
    zero_division: ZeroDivision,
) -> Result<f64> {
    averaged(y_true, y_pred, 1.0, average, zero_division).map(|s| s.2)
}

/// F-beta score: weighs recall `beta` times as much as precision. `beta = 0`
/// is precision, `beta = f64::INFINITY` is recall.
///
/// # Errors
///
/// As [`precision_score`], plus [`MetricsError::InvalidParameter`] for a
/// negative or `NaN` `beta`.
pub fn fbeta_score<L: Ord + Clone>(
    y_true: &[L],
    y_pred: &[L],
    beta: f64,
    average: &Average<L>,
    zero_division: ZeroDivision,
) -> Result<f64> {
    averaged(y_true, y_pred, beta, average, zero_division).map(|s| s.2)
}

/// A `k × k` confusion matrix: entry `(i, j)` counts samples whose true
/// label is `labels()[i]` and predicted label is `labels()[j]`.
///
/// Uses `k²` counters, so for data with a huge number of distinct labels
/// prefer [`precision_recall_fscore_support`], which needs only `O(k)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfusionMatrix<L> {
    labels: Vec<L>,
    counts: Vec<usize>,
}

impl<L> ConfusionMatrix<L> {
    /// Class labels indexing rows (truth) and columns (prediction).
    #[must_use]
    pub fn labels(&self) -> &[L] {
        &self.labels
    }

    /// Number of classes `k`.
    #[must_use]
    pub const fn n_classes(&self) -> usize {
        self.labels.len()
    }

    /// Row-major `k × k` counts.
    #[must_use]
    pub fn as_slice(&self) -> &[usize] {
        &self.counts
    }

    /// Row `i`: how samples of true class `i` were predicted.
    ///
    /// # Panics
    ///
    /// If `i >= n_classes()`.
    #[must_use]
    pub fn row(&self, i: usize) -> &[usize] {
        let k = self.labels.len();
        &self.counts[i * k..(i + 1) * k]
    }

    /// Entry `(i, j)`, or `None` out of range.
    #[must_use]
    pub fn get(&self, i: usize, j: usize) -> Option<usize> {
        let k = self.labels.len();
        (i < k && j < k).then(|| self.counts[i * k + j])
    }

    /// Rows as nested vectors, for printing or comparison.
    #[must_use]
    pub fn to_rows(&self) -> Vec<Vec<usize>> {
        let k = self.labels.len();
        if k == 0 {
            return Vec::new();
        }
        self.counts.chunks_exact(k).map(<[usize]>::to_vec).collect()
    }
}

impl<L> Index<(usize, usize)> for ConfusionMatrix<L> {
    type Output = usize;

    fn index(&self, (i, j): (usize, usize)) -> &usize {
        let k = self.labels.len();
        assert!(
            i < k && j < k,
            "index ({i}, {j}) out of range for {k} classes"
        );
        &self.counts[i * k + j]
    }
}

/// Confusion matrix over the sorted union of the labels in `y_true` and `y_pred`.
///
/// ```
/// use rune_ml_metrics::confusion_matrix;
///
/// let cm = confusion_matrix(&["cat", "ant", "cat", "cat", "ant", "bird"],
///                           &["ant", "ant", "cat", "cat", "ant", "cat"])?;
/// assert_eq!(cm.labels(), ["ant", "bird", "cat"]);
/// assert_eq!(cm.to_rows(), [[2, 0, 0], [0, 0, 1], [1, 0, 2]]);
/// # Ok::<(), rune_ml_metrics::MetricsError>(())
/// ```
///
/// # Errors
///
/// [`MetricsError::Empty`] or [`MetricsError::LengthMismatch`].
pub fn confusion_matrix<L: Ord + Clone>(y_true: &[L], y_pred: &[L]) -> Result<ConfusionMatrix<L>> {
    check_pair(y_true, y_pred)?;
    let e = encode_sorted(y_true, y_pred);
    let k = e.classes.len();
    // k <= 2n, so k² only overflows for inputs that cannot exist in memory.
    let size = k
        .checked_mul(k)
        .ok_or_else(|| MetricsError::label_count(format!("{k} classes overflow k²")))?;
    let mut counts = vec![0usize; size];
    for (&t, &p) in e.a.iter().zip(&e.b) {
        counts[t * k + p] += 1;
    }
    Ok(ConfusionMatrix {
        labels: e.classes,
        counts,
    })
}

/// Confusion matrix with an explicit label list, kept in the given order.
///
/// Samples whose true or predicted label is not in `labels` are ignored, as
/// in scikit-learn.
///
/// # Errors
///
/// [`MetricsError::Empty`], [`MetricsError::LengthMismatch`],
/// [`MetricsError::InvalidParameter`] if `labels` is empty, has duplicates or
/// shares no label with `y_true`.
pub fn confusion_matrix_with_labels<L: Ord + Clone>(
    y_true: &[L],
    y_pred: &[L],
    labels: &[L],
) -> Result<ConfusionMatrix<L>> {
    check_pair(y_true, y_pred)?;
    if labels.is_empty() {
        return Err(MetricsError::parameter("labels", "must not be empty"));
    }
    let mut lookup: Vec<(&L, usize)> = labels.iter().zip(0..).collect();
    lookup.sort_unstable_by(|a, b| a.0.cmp(b.0));
    if lookup.windows(2).any(|w| w[0].0 == w[1].0) {
        return Err(MetricsError::parameter("labels", "contains duplicates"));
    }
    let find = |l: &L| {
        lookup
            .binary_search_by(|x| x.0.cmp(l))
            .ok()
            .map(|i| lookup[i].1)
    };
    let k = labels.len();
    let size = k
        .checked_mul(k)
        .ok_or_else(|| MetricsError::label_count(format!("{k} classes overflow k²")))?;
    let mut counts = vec![0usize; size];
    let mut any_true = false;
    for (t, p) in y_true.iter().zip(y_pred) {
        let Some(ti) = find(t) else { continue };
        any_true = true;
        if let Some(pi) = find(p) {
            counts[ti * k + pi] += 1;
        }
    }
    if !any_true {
        return Err(MetricsError::parameter(
            "labels",
            "at least one label must be present in y_true",
        ));
    }
    Ok(ConfusionMatrix {
        labels: labels.to_vec(),
        counts,
    })
}

/// Matthews correlation coefficient, in `[-1, 1]`; the multiclass
/// generalisation (Gorodkin's `R_K`) for more than two labels.
///
/// Returns `0.0` when it is undefined (all samples in one true or one
/// predicted class), as scikit-learn does.
///
/// ```
/// use rune_ml_metrics::matthews_corrcoef;
/// let m = matthews_corrcoef(&[1, 1, 1, 0], &[1, 0, 1, 1])?;
/// assert!((m + 1.0 / 3.0).abs() < 1e-12);
/// # Ok::<(), rune_ml_metrics::MetricsError>(())
/// ```
///
/// # Errors
///
/// [`MetricsError::Empty`] or [`MetricsError::LengthMismatch`].
pub fn matthews_corrcoef<L: Ord + Clone>(y_true: &[L], y_pred: &[L]) -> Result<f64> {
    check_pair(y_true, y_pred)?;
    let c = Counts::new(&encode_sorted(y_true, y_pred));
    // Exact integer arithmetic: every term is at most n² < 2^126.
    let wide = |x: usize| i128::try_from(x).unwrap_or(i128::MAX);
    let n = wide(y_true.len());
    let correct: i128 = c.tp.iter().map(|&x| wide(x)).sum();
    let dot = |a: &[usize], b: &[usize]| -> i128 {
        a.iter().zip(b).map(|(&x, &y)| wide(x) * wide(y)).sum()
    };
    let cov_ytyp = i128_f64(correct * n - dot(&c.true_sum, &c.pred_sum));
    let cov_ypyp = i128_f64(n * n - dot(&c.pred_sum, &c.pred_sum));
    let cov_ytyt = i128_f64(n * n - dot(&c.true_sum, &c.true_sum));
    if cov_ypyp == 0.0 || cov_ytyt == 0.0 {
        return Ok(0.0);
    }
    Ok(cov_ytyp / (cov_ytyt.sqrt() * cov_ypyp.sqrt()))
}

#[allow(clippy::cast_precision_loss, reason = "rounds only beyond 2^53")]
pub const fn i128_f64(x: i128) -> f64 {
    x as f64
}

/// Disagreement weights for [`cohen_kappa_score`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum KappaWeights {
    /// Every disagreement costs 1 (plain Cohen's kappa).
    #[default]
    None,
    /// Disagreement costs `|i − j|` between sorted label positions.
    Linear,
    /// Disagreement costs `(i − j)²` (quadratic weighted kappa).
    Quadratic,
}

/// Cohen's kappa: agreement between two annotators, corrected for chance.
///
/// The labels are sorted, and the [`KappaWeights::Linear`] and
/// [`KappaWeights::Quadratic`] weights use positions in that order, so they
/// only make sense for ordinal labels.
///
/// When the chance disagreement is zero (both raters use one and the same
/// label for everything) kappa is undefined and `NaN` is returned, matching
/// scikit-learn's default `replace_undefined_by=np.nan`.
///
/// ```
/// use rune_ml_metrics::{cohen_kappa_score, KappaWeights};
/// let k = cohen_kappa_score(&["a", "a", "b", "b"], &["a", "b", "b", "b"], KappaWeights::None)?;
/// assert!((k - 0.5).abs() < 1e-12);
/// # Ok::<(), rune_ml_metrics::MetricsError>(())
/// ```
///
/// # Errors
///
/// [`MetricsError::Empty`] or [`MetricsError::LengthMismatch`].
pub fn cohen_kappa_score<L: Ord + Clone>(y1: &[L], y2: &[L], weights: KappaWeights) -> Result<f64> {
    check_pair(y1, y2)?;
    let e = encode_sorted(y1, y2);
    let k = e.classes.len();
    let w = |i: usize, j: usize| -> f64 {
        let d = to_f64(i.abs_diff(j));
        match weights {
            KappaWeights::None => f64::from(u8::from(i != j)),
            KappaWeights::Linear => d,
            KappaWeights::Quadratic => d * d,
        }
    };
    // Observed weighted disagreement, straight from the samples.
    let observed: f64 = crate::util::stable_sum(e.a.iter().zip(&e.b).map(|(&i, &j)| w(i, j)));
    // Expected disagreement Σᵢⱼ w(i, j)·rᵢ·cⱼ / n, in O(k) per weighting.
    let (mut r, mut c) = (vec![0.0f64; k], vec![0.0f64; k]);
    for (&i, &j) in e.a.iter().zip(&e.b) {
        r[i] += 1.0;
        c[j] += 1.0;
    }
    let n = to_f64(y1.len());
    let expected = match weights {
        KappaWeights::None => {
            let same: f64 = r.iter().zip(&c).map(|(a, b)| a * b).sum();
            n.mul_add(n, -same)
        }
        KappaWeights::Linear => {
            // Σᵢ rᵢ Σⱼ |i − j| cⱼ with running prefix counts and sums.
            let (total_c, total_jc) = c.iter().enumerate().fold((0.0, 0.0), |(s, sj), (j, &cj)| {
                (s + cj, to_f64(j).mul_add(cj, sj))
            });
            let (mut below_c, mut below_jc, mut acc) = (0.0, 0.0, 0.0);
            for (i, (&ri, &ci)) in r.iter().zip(&c).enumerate() {
                let x = to_f64(i);
                // j < i contribute (i − j) cⱼ, j ≥ i contribute (j − i) cⱼ.
                let left = x.mul_add(below_c, -below_jc);
                let right = (total_jc - below_jc) - x * (total_c - below_c);
                acc += ri * (left + right);
                below_c += ci;
                below_jc = x.mul_add(ci, below_jc);
            }
            acc
        }
        KappaWeights::Quadratic => {
            let moment = |v: &[f64], p: i32| -> f64 {
                v.iter()
                    .enumerate()
                    .map(|(i, &x)| to_f64(i).powi(p) * x)
                    .sum()
            };
            moment(&r, 2) * n + n * moment(&c, 2) - 2.0 * moment(&r, 1) * moment(&c, 1)
        }
    } / n;
    if expected == 0.0 {
        return Ok(f64::NAN);
    }
    Ok(1.0 - observed / expected)
}

/// Scores of one class in a [`ClassificationReport`].
#[derive(Debug, Clone, PartialEq)]
pub struct ClassReport<L> {
    /// Class label.
    pub label: L,
    /// Precision of this class.
    pub precision: f64,
    /// Recall of this class.
    pub recall: f64,
    /// F1 of this class.
    pub f1: f64,
    /// Number of true samples of this class.
    pub support: usize,
}

/// An averaged row (`macro avg`, `weighted avg`) of a [`ClassificationReport`].
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct AverageReport {
    /// Averaged precision.
    pub precision: f64,
    /// Averaged recall.
    pub recall: f64,
    /// Averaged F1.
    pub f1: f64,
    /// Total number of samples.
    pub support: usize,
}

/// Per-class precision, recall and F1 plus accuracy and averages, as
/// `sklearn.metrics.classification_report`.
///
/// `Display` prints the same table as scikit-learn. The format precision
/// sets the number of digits (default 2): `format!("{report:.4}")`.
#[derive(Debug, Clone, PartialEq)]
pub struct ClassificationReport<L> {
    /// One row per class, in sorted label order.
    pub classes: Vec<ClassReport<L>>,
    /// Overall accuracy (equal to micro-averaged F1).
    pub accuracy: f64,
    /// Unweighted mean over classes.
    pub macro_avg: AverageReport,
    /// Support-weighted mean over classes.
    pub weighted_avg: AverageReport,
}

/// Builds a [`ClassificationReport`].
///
/// ```
/// use rune_ml_metrics::{classification_report, ZeroDivision};
///
/// let r = classification_report(&[0, 1, 2, 2, 2], &[0, 0, 2, 2, 1], ZeroDivision::Zero)?;
/// assert_eq!(r.accuracy, 0.6);
/// println!("{r}");
/// # Ok::<(), rune_ml_metrics::MetricsError>(())
/// ```
///
/// # Errors
///
/// [`MetricsError::Empty`] or [`MetricsError::LengthMismatch`].
pub fn classification_report<L: Ord + Clone>(
    y_true: &[L],
    y_pred: &[L],
    zero_division: ZeroDivision,
) -> Result<ClassificationReport<L>> {
    let s = precision_recall_fscore_support(y_true, y_pred, 1.0, zero_division)?;
    let n = y_true.len();
    let avg = |w: Option<&[usize]>| AverageReport {
        precision: nan_average(&s.precision, w),
        recall: nan_average(&s.recall, w),
        f1: nan_average(&s.f_score, w),
        support: n,
    };
    let macro_avg = avg(None);
    let weighted_avg = avg(Some(&s.support));
    let accuracy = accuracy_score(y_true, y_pred)?;
    let classes = s
        .labels
        .iter()
        .enumerate()
        .map(|(i, l)| ClassReport {
            label: l.clone(),
            precision: s.precision[i],
            recall: s.recall[i],
            f1: s.f_score[i],
            support: s.support[i],
        })
        .collect();
    Ok(ClassificationReport {
        classes,
        accuracy,
        macro_avg,
        weighted_avg,
    })
}

impl<L: fmt::Display> fmt::Display for ClassificationReport<L> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let d = f.precision().unwrap_or(2);
        let names: Vec<String> = self.classes.iter().map(|c| c.label.to_string()).collect();
        let width = names
            .iter()
            .map(|s| s.chars().count())
            .chain([12, d])
            .max()
            .unwrap_or(12);
        writeln!(
            f,
            "{:>width$}  {:>9} {:>9} {:>9} {:>9}\n",
            "", "precision", "recall", "f1-score", "support"
        )?;
        let row = |f: &mut fmt::Formatter<'_>, name: &str, p: f64, r: f64, f1: f64, s: usize| {
            writeln!(f, "{name:>width$}  {p:>9.d$} {r:>9.d$} {f1:>9.d$} {s:>9}")
        };
        for (c, name) in self.classes.iter().zip(&names) {
            row(f, name, c.precision, c.recall, c.f1, c.support)?;
        }
        writeln!(f)?;
        writeln!(
            f,
            "{:>width$}  {:>9} {:>9} {:>9.d$} {:>9}",
            "accuracy", "", "", self.accuracy, self.macro_avg.support
        )?;
        for (name, a) in [
            ("macro avg", self.macro_avg),
            ("weighted avg", self.weighted_avg),
        ] {
            row(f, name, a.precision, a.recall, a.f1, a.support)?;
        }
        Ok(())
    }
}
