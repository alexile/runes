//! Mann–Whitney U test (Wilcoxon rank-sum test).

use crate::Error;
use crate::exact::Distribution;
use crate::hypothesis::{Alternative, Method, correction_sign, exact_p_value, normal_p_value};
use crate::rank::walk;
use crate::util::{check_sorted, count, sorted_copy};

/// Samples below this size (both of them) get an exact p-value under
/// [`Method::Auto`] when there are no ties, as in R's `wilcox.test`.
const AUTO_EXACT_BELOW: usize = 50;

/// Settings for [`mann_whitney_u`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub struct MannWhitneyOptions {
    /// Alternative hypothesis. Default: [`Alternative::TwoSided`].
    pub alternative: Alternative,
    /// How to compute the p-value. Default: [`Method::Auto`], which is
    /// exact when there are no ties and both samples have fewer than 50
    /// observations, and asymptotic otherwise.
    pub method: Method,
    /// Apply the 0.5 continuity correction to the normal approximation.
    /// Default: `true`.
    pub continuity: bool,
}

impl Default for MannWhitneyOptions {
    fn default() -> Self {
        Self {
            alternative: Alternative::TwoSided,
            method: Method::Auto,
            continuity: true,
        }
    }
}

impl MannWhitneyOptions {
    /// Sets [`MannWhitneyOptions::alternative`].
    #[must_use]
    pub const fn with_alternative(mut self, alternative: Alternative) -> Self {
        self.alternative = alternative;
        self
    }

    /// Sets [`MannWhitneyOptions::method`].
    #[must_use]
    pub const fn with_method(mut self, method: Method) -> Self {
        self.method = method;
        self
    }

    /// Sets [`MannWhitneyOptions::continuity`].
    #[must_use]
    pub const fn with_continuity(mut self, continuity: bool) -> Self {
        self.continuity = continuity;
        self
    }
}

/// Result of a Mann–Whitney U test.
#[derive(Debug, Clone, Copy, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub struct MannWhitney {
    /// `U` statistic of the first sample: the number of pairs `(xᵢ, yⱼ)`
    /// with `xᵢ > yⱼ`, ties counting one half.
    pub u: f64,
    /// Normal-approximation z score of `u` (tie-corrected, and continuity
    /// corrected when enabled). Positive when the first sample tends to be
    /// larger. Reported even when the p-value is exact.
    pub z: f64,
    /// p-value under the chosen alternative.
    pub p_value: f64,
    /// Whether [`MannWhitney::p_value`] comes from the exact distribution.
    pub exact: bool,
    /// Probability of superiority (common-language effect size)
    /// `u / (m·n)`: the chance that a random `x` exceeds a random `y`,
    /// ties counting one half.
    pub probability_of_superiority: f64,
    /// Rank-biserial correlation `2·u/(m·n) − 1` in `[−1, 1]`; equal to
    /// Cliff's delta, `P(x > y) − P(x < y)`.
    pub rank_biserial: f64,
}

/// Mann–Whitney U test of `x` against `y`. Copies and sorts both samples;
/// use [`mann_whitney_u_sorted`] on pre-sorted data to avoid allocating.
///
/// The normal approximation uses the tie-corrected variance
/// `m·n/12 · ((N + 1) − Σ(t³ − t) / (N(N − 1)))`. When that variance is
/// zero (every value tied) the result is `z = 0`, `p = 1`.
///
/// ```
/// use rune_stats::{mann_whitney_u, Alternative, MannWhitneyOptions};
///
/// let fast = [10.1, 11.4, 9.8, 10.6, 10.9, 10.2];
/// let slow = [12.5, 13.1, 12.2, 14.0, 12.9, 13.3];
/// let options = MannWhitneyOptions::default().with_alternative(Alternative::Greater);
/// let result = mann_whitney_u(&slow, &fast, &options)?;
/// assert_eq!(result.u, 36.0);
/// assert!(result.exact && result.p_value < 0.01);
/// # Ok::<(), rune_stats::Error>(())
/// ```
pub fn mann_whitney_u(
    x: &[f64],
    y: &[f64],
    options: &MannWhitneyOptions,
) -> Result<MannWhitney, Error> {
    let x = sorted_copy(x)?;
    let y = sorted_copy(y)?;
    mann_whitney_u_sorted(&x, &y, options)
}

/// [`mann_whitney_u`] on samples already sorted ascending. Does not
/// allocate unless an exact p-value is computed.
///
/// # Errors
///
/// [`Error::NotSorted`] for unsorted input, [`Error::ExactWithTies`] for
/// [`Method::Exact`] with ties, [`Error::TooLarge`] for [`Method::Exact`]
/// with more than 128 observations in total.
#[allow(
    clippy::many_single_char_names,
    reason = "names follow the textbook formulas"
)]
pub fn mann_whitney_u_sorted(
    x: &[f64],
    y: &[f64],
    options: &MannWhitneyOptions,
) -> Result<MannWhitney, Error> {
    check_sorted(x)?;
    check_sorted(y)?;
    let n1 = count(x.len());
    let n2 = count(y.len());
    let walk = walk(x, y);
    let u = n1.mul_add(-(n1 + 1.0) / 2.0, walk.rank_sum_x);
    let n = n1 + n2;
    let expected = n1 * n2 / 2.0;
    let variance = n1 * n2 / 12.0 * ((n + 1.0) - walk.tie_term / (n * (n - 1.0)));
    let ties = walk.tie_term > 0.0;

    let exact = match options.method {
        Method::Exact if ties => return Err(Error::ExactWithTies),
        Method::Exact => true,
        Method::Asymptotic => false,
        Method::Auto => !ties && x.len() < AUTO_EXACT_BELOW && y.len() < AUTO_EXACT_BELOW,
    };

    let (z, asymptotic_p) = if variance <= f64::EPSILON {
        (0.0, 1.0)
    } else {
        let mut numerator = u - expected;
        if options.continuity {
            numerator =
                (-0.5f64).mul_add(correction_sign(numerator, options.alternative), numerator);
        }
        let z = numerator / variance.sqrt();
        (z, normal_p_value(z, options.alternative))
    };

    let p_value = if exact {
        let dist = Distribution::mann_whitney(x.len(), y.len())?;
        #[expect(
            clippy::cast_possible_truncation,
            clippy::cast_sign_loss,
            reason = "without ties u is an integer in [0, m·n]"
        )]
        let k = u.round() as usize;
        exact_p_value(dist.sf(k), dist.cdf(k), options.alternative)
    } else {
        asymptotic_p
    };

    let pairs = n1 * n2;
    let probability_of_superiority = u / pairs;
    Ok(MannWhitney {
        u,
        z,
        p_value,
        exact,
        probability_of_superiority,
        rank_biserial: 2.0f64.mul_add(probability_of_superiority, -1.0),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn asymptotic(alternative: Alternative) -> MannWhitneyOptions {
        MannWhitneyOptions::default()
            .with_method(Method::Asymptotic)
            .with_alternative(alternative)
    }

    #[test]
    fn separated_and_identical() {
        let low = [1.0, 2.0, 3.0, 4.0, 5.0, 6.0];
        let high = [10.0, 11.0, 12.0, 13.0, 14.0, 15.0];
        let result = mann_whitney_u(&high, &low, &asymptotic(Alternative::Greater)).unwrap();
        assert_eq!(result.u, 36.0);
        assert!(result.p_value < 0.01);
        assert_eq!(result.rank_biserial, 1.0);
        let reverse = mann_whitney_u(&low, &high, &asymptotic(Alternative::Greater)).unwrap();
        assert!(reverse.p_value > 0.99);
        let same = mann_whitney_u(&[5.0; 4], &[5.0; 4], &asymptotic(Alternative::Greater)).unwrap();
        assert_eq!((same.z, same.p_value), (0.0, 1.0));
        assert_eq!(
            mann_whitney_u(&[], &low, &MannWhitneyOptions::default()),
            Err(Error::Empty)
        );
    }

    #[test]
    fn exact_rejects_ties() {
        let options = MannWhitneyOptions::default().with_method(Method::Exact);
        assert_eq!(
            mann_whitney_u(&[1.0, 2.0], &[2.0, 3.0], &options),
            Err(Error::ExactWithTies)
        );
        // Auto falls back to the normal approximation instead.
        let auto =
            mann_whitney_u(&[1.0, 2.0], &[2.0, 3.0], &MannWhitneyOptions::default()).unwrap();
        assert!(!auto.exact);
    }

    #[test]
    fn swapping_samples_mirrors_the_result() {
        let x = [1.2, 3.4, 0.5, 7.7, 2.2];
        let y = [4.1, 5.5, 6.0, 0.9];
        for method in [Method::Exact, Method::Asymptotic] {
            let options = MannWhitneyOptions::default().with_method(method);
            let forward = mann_whitney_u(&x, &y, &options).unwrap();
            let backward = mann_whitney_u(&y, &x, &options).unwrap();
            assert_eq!(forward.u + backward.u, 20.0);
            assert!((forward.p_value - backward.p_value).abs() < 1e-15);
            assert_eq!(forward.rank_biserial, -backward.rank_biserial);
        }
    }
}
