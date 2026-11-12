//! Distribution-free confidence intervals: the median, and the
//! Hodges–Lehmann location estimators that go with the rank tests.

use crate::Error;
use crate::descriptive::median_sorted;
use crate::dist::{normal_cdf, normal_quantile};
use crate::exact::Distribution;
use crate::rank::walk;
use crate::util::{check, check_confidence, count, sorted_copy};

/// Largest number of pairwise differences or Walsh averages the
/// Hodges–Lehmann estimators materialise (2²⁷, about 1 GiB of `f64`).
pub const MAX_PAIRS: usize = 1 << 27;

/// Samples below this size (each) get exact critical values when there are
/// no ties, as in R's `wilcox.test`.
const EXACT_BELOW: usize = 50;

/// A point estimate with a confidence interval.
#[derive(Debug, Clone, Copy, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub struct ConfidenceInterval {
    /// Point estimate.
    pub estimate: f64,
    /// Lower bound.
    pub lower: f64,
    /// Upper bound.
    pub upper: f64,
    /// Requested confidence level.
    pub confidence: f64,
    /// Coverage actually achieved. Order-statistic intervals move in
    /// discrete steps, so this is at least the requested level whenever the
    /// critical value is exact, and close to it otherwise.
    pub achieved_confidence: f64,
    /// Whether the critical values come from an exact distribution
    /// (binomial or rank-sum) rather than the normal approximation.
    pub exact: bool,
}

/// Distribution-free confidence interval for the median.
///
/// The interval is `[x₍ₖ₎, x₍ₙ₋ₖ₊₁₎]` with the largest `k` for which the
/// Binomial(n, ½) tail `P(B ≤ k − 1)` is at most `(1 − confidence)/2`, so
/// it holds for any continuous distribution.
///
/// # Errors
///
/// [`Error::InvalidParameter`] for a confidence outside `(0, 1)`;
/// [`Error::TooFew`] when the sample is too small to reach the requested
/// confidence at all.
///
/// ```
/// let ci = rune_stats::median_ci(&[3.1, 4.7, 2.2, 5.9, 4.1, 3.8, 6.3, 4.4, 3.0, 5.0], 0.95)?;
/// assert_eq!((ci.lower, ci.upper), (3.0, 5.9));
/// assert!(ci.achieved_confidence >= 0.95);
/// # Ok::<(), rune_stats::Error>(())
/// ```
pub fn median_ci(values: &[f64], confidence: f64) -> Result<ConfidenceInterval, Error> {
    check_confidence(confidence)?;
    let sorted = sorted_copy(values)?;
    let n = sorted.len();
    let half_alpha = (1.0 - confidence) / 2.0;
    // Walk the Binomial(n, 1/2) distribution function in log space so that
    // large n does not underflow 2^-n.
    let mut log_pmf = -count(n) * std::f64::consts::LN_2;
    let mut cdf = 0.0;
    let mut k = 0;
    let mut tail = 0.0;
    for j in 0..n.div_ceil(2) {
        cdf += log_pmf.exp();
        if cdf > half_alpha {
            break;
        }
        k = j + 1;
        tail = cdf;
        log_pmf += (count(n - j) / count(j + 1)).ln();
    }
    if k == 0 {
        let needed = (2.0 / (1.0 - confidence)).log2().ceil();
        #[expect(
            clippy::cast_possible_truncation,
            clippy::cast_sign_loss,
            reason = "log2 of a finite value above 2 is a small positive number"
        )]
        let needed = needed as usize;
        return Err(Error::TooFew { needed, got: n });
    }
    Ok(ConfidenceInterval {
        estimate: median_sorted(&sorted)?,
        lower: sorted[k - 1],
        upper: sorted[n - k],
        confidence,
        achieved_confidence: 2.0f64.mul_add(-tail, 1.0),
        exact: true,
    })
}

/// Picks the order-statistic index `q` (1-based, as in R) for a rank
/// statistic on `0..=total` with null mean `total/2` and standard
/// deviation `sd`, returning `(q, achieved_confidence)`.
fn critical_index(
    exact: Option<&Distribution>,
    total: usize,
    sd: f64,
    confidence: f64,
) -> (usize, f64) {
    let half_alpha = (1.0 - confidence) / 2.0;
    let largest = total.div_ceil(2).max(1);
    if let Some(dist) = exact {
        let q = dist.quantile(half_alpha).clamp(1, largest);
        return (q, 2.0f64.mul_add(-dist.cdf(q - 1), 1.0));
    }
    if sd <= f64::EPSILON {
        return (1, 1.0);
    }
    let mean = count(total) / 2.0;
    let raw = sd.mul_add(normal_quantile(half_alpha), mean) - 0.5;
    #[expect(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        reason = "clamped to [1, largest] right after; negative values saturate to 0"
    )]
    let q = (raw.ceil().max(0.0) as usize).clamp(1, largest);
    let below = normal_cdf((count(q - 1) + 0.5 - mean) / sd);
    (q, 2.0f64.mul_add(-below, 1.0))
}

/// Hodges–Lehmann estimate of the location shift `x − y` with its
/// confidence interval, the estimator that goes with the Mann–Whitney test.
///
/// The estimate is the median of all `m·n` differences `xᵢ − yⱼ`; the
/// interval is a pair of order statistics of those differences chosen from
/// the null distribution of `U`. That distribution is exact when there are
/// no ties and both samples have fewer than 50 observations (matching R's
/// `wilcox.test(conf.int = TRUE)`), and the tie-corrected normal
/// approximation otherwise. Allocates the `m·n` differences.
///
/// # Errors
///
/// [`Error::TooLarge`] when `m·n` exceeds [`MAX_PAIRS`].
///
/// ```
/// let x = [1.83, 0.50, 1.62, 2.48, 1.68, 1.88, 1.55, 3.06, 1.30];
/// let y = [0.878, 0.647, 0.598, 2.05, 1.06, 1.29, 1.06, 3.14, 1.29];
/// let shift = rune_stats::hodges_lehmann_shift(&x, &y, 0.95)?;
/// assert!(shift.lower < shift.estimate && shift.estimate < shift.upper);
/// # Ok::<(), rune_stats::Error>(())
/// ```
#[allow(
    clippy::many_single_char_names,
    reason = "names follow the textbook formulas"
)]
pub fn hodges_lehmann_shift(
    x: &[f64],
    y: &[f64],
    confidence: f64,
) -> Result<ConfidenceInterval, Error> {
    check_confidence(confidence)?;
    let xs = sorted_copy(x)?;
    let ys = sorted_copy(y)?;
    let (m, n) = (xs.len(), ys.len());
    let pairs = m
        .checked_mul(n)
        .filter(|&pairs| pairs <= MAX_PAIRS)
        .ok_or(Error::TooLarge { limit: MAX_PAIRS })?;
    let mut diffs = Vec::with_capacity(pairs);
    for a in &xs {
        diffs.extend(ys.iter().map(|b| a - b));
    }
    diffs.sort_unstable_by(f64::total_cmp);

    let tie_term = walk(&xs, &ys).tie_term;
    let exact = tie_term == 0.0 && m < EXACT_BELOW && n < EXACT_BELOW;
    let dist = if exact {
        Some(Distribution::mann_whitney(m, n)?)
    } else {
        None
    };
    let (n1, n2) = (count(m), count(n));
    let big_n = n1 + n2;
    let variance = if m + n > 1 {
        n1 * n2 / 12.0 * ((big_n + 1.0) - tie_term / (big_n * (big_n - 1.0)))
    } else {
        0.0
    };
    let (q, achieved) = critical_index(dist.as_ref(), pairs, variance.sqrt(), confidence);
    Ok(ConfidenceInterval {
        estimate: median_sorted(&diffs)?,
        lower: diffs[q - 1],
        upper: diffs[pairs - q],
        confidence,
        achieved_confidence: achieved,
        exact,
    })
}

/// Hodges–Lehmann one-sample location estimate (pseudo-median) with its
/// confidence interval, the estimator that goes with the signed-rank test.
///
/// The estimate is the median of the `n(n+1)/2` Walsh averages
/// `(xᵢ + xⱼ)/2, i ≤ j`; the interval is a pair of their order statistics
/// chosen from the null distribution of `W⁺`: exact without ties or zeros
/// and with fewer than 50 observations, otherwise the tie-corrected normal
/// approximation. For paired data pass the differences.
///
/// # Errors
///
/// [`Error::TooLarge`] when the number of Walsh averages exceeds
/// [`MAX_PAIRS`].
///
/// ```
/// let diffs = [1.83, 0.50, 1.62, 2.48, 1.68, 1.88, 1.55, 3.06, 1.30];
/// let ci = rune_stats::hodges_lehmann_one_sample(&diffs, 0.95)?;
/// assert!(ci.exact && ci.lower > 0.0);
/// # Ok::<(), rune_stats::Error>(())
/// ```
pub fn hodges_lehmann_one_sample(
    values: &[f64],
    confidence: f64,
) -> Result<ConfidenceInterval, Error> {
    check_confidence(confidence)?;
    check(values)?;
    let n = values.len();
    let pairs = n
        .checked_add(1)
        .and_then(|next| next.checked_mul(n))
        .map(|product| product / 2)
        .filter(|&pairs| pairs <= MAX_PAIRS)
        .ok_or(Error::TooLarge { limit: MAX_PAIRS })?;
    let mut walsh = Vec::with_capacity(pairs);
    for (i, a) in values.iter().enumerate() {
        walsh.extend(values[i..].iter().map(|b| f64::midpoint(*a, *b)));
    }
    walsh.sort_unstable_by(f64::total_cmp);

    let mut magnitudes: Vec<f64> = values.iter().map(|v| v.abs()).collect();
    magnitudes.sort_unstable_by(f64::total_cmp);
    let has_zero = magnitudes.first().is_some_and(|v| *v == 0.0);
    let mut tie_term = 0.0;
    for group in magnitudes.chunk_by(|a, b| a.total_cmp(b).is_eq()) {
        let tied = count(group.len());
        tie_term += tied.mul_add(tied * tied, -tied);
    }
    let exact = tie_term == 0.0 && !has_zero && n < EXACT_BELOW;
    let dist = if exact {
        Some(Distribution::signed_rank(n)?)
    } else {
        None
    };
    let size = count(n);
    let variance = size * (size + 1.0) * 2.0f64.mul_add(size, 1.0) / 24.0 - tie_term / 48.0;
    let (q, achieved) = critical_index(dist.as_ref(), pairs, variance.max(0.0).sqrt(), confidence);
    Ok(ConfidenceInterval {
        estimate: median_sorted(&walsh)?,
        lower: walsh[q - 1],
        upper: walsh[pairs - q],
        confidence,
        achieved_confidence: achieved,
        exact,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn median_ci_rejects_tiny_samples() {
        // n = 5: P(B ≤ 0) = 1/32 > 0.025, so 95 % is out of reach.
        assert_eq!(
            median_ci(&[1.0, 2.0, 3.0, 4.0, 5.0], 0.95),
            Err(Error::TooFew { needed: 6, got: 5 })
        );
        let ci = median_ci(&[1.0, 2.0, 3.0, 4.0, 5.0, 6.0], 0.95).unwrap();
        assert_eq!((ci.lower, ci.upper), (1.0, 6.0));
        assert!((ci.achieved_confidence - (1.0 - 2.0 / 64.0)).abs() < 1e-15);
        assert!(median_ci(&[1.0], 1.0).is_err());
    }

    #[test]
    fn median_ci_large_sample_does_not_underflow() {
        let data: Vec<f64> = (0..5000).map(f64::from).collect();
        let ci = median_ci(&data, 0.99).unwrap();
        assert!(ci.lower < ci.estimate && ci.estimate < ci.upper);
        assert!(ci.achieved_confidence >= 0.99);
    }

    #[test]
    fn shift_of_shifted_sample() {
        let x: Vec<f64> = (0..30).map(|i| f64::from(i) * 0.37 % 5.0).collect();
        let y: Vec<f64> = x.iter().map(|v| v - 2.0).collect();
        let ci = hodges_lehmann_shift(&x, &y, 0.9).unwrap();
        assert!((ci.estimate - 2.0).abs() < 1e-12);
        assert!(ci.lower <= 2.0 && 2.0 <= ci.upper);
    }
}
