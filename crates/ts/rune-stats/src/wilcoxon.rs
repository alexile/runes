//! Wilcoxon signed-rank test for paired samples or one sample.

use crate::Error;
use crate::exact::Distribution;
use crate::hypothesis::{Alternative, Method, correction_sign, exact_p_value, normal_p_value};
use crate::util::{check, count};

/// Samples below this many non-zero differences get an exact p-value under
/// [`Method::Auto`] when there are no ties or zeros, as in R's
/// `wilcox.test`.
const AUTO_EXACT_BELOW: usize = 50;

/// How zero differences are treated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub enum ZeroMethod {
    /// Drop zero differences before ranking (Wilcoxon's original method,
    /// the default in R and `SciPy`).
    #[default]
    Wilcox,
    /// Rank zero differences together with the others, then drop them from
    /// the rank sums (Pratt 1959); the normal approximation is adjusted
    /// (Cureton 1967).
    Pratt,
}

/// Settings for [`wilcoxon_signed_rank`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub struct WilcoxonOptions {
    /// Alternative hypothesis. Default: [`Alternative::TwoSided`].
    pub alternative: Alternative,
    /// How to compute the p-value. Default: [`Method::Auto`], exact when
    /// there are no ties or zeros and fewer than 50 differences, otherwise
    /// asymptotic.
    pub method: Method,
    /// Apply the 0.5 continuity correction to the normal approximation.
    /// Default: `true`.
    pub continuity: bool,
    /// Treatment of zero differences. Default: [`ZeroMethod::Wilcox`].
    pub zero_method: ZeroMethod,
}

impl Default for WilcoxonOptions {
    fn default() -> Self {
        Self {
            alternative: Alternative::TwoSided,
            method: Method::Auto,
            continuity: true,
            zero_method: ZeroMethod::Wilcox,
        }
    }
}

impl WilcoxonOptions {
    /// Sets [`WilcoxonOptions::alternative`].
    #[must_use]
    pub const fn with_alternative(mut self, alternative: Alternative) -> Self {
        self.alternative = alternative;
        self
    }

    /// Sets [`WilcoxonOptions::method`].
    #[must_use]
    pub const fn with_method(mut self, method: Method) -> Self {
        self.method = method;
        self
    }

    /// Sets [`WilcoxonOptions::continuity`].
    #[must_use]
    pub const fn with_continuity(mut self, continuity: bool) -> Self {
        self.continuity = continuity;
        self
    }

    /// Sets [`WilcoxonOptions::zero_method`].
    #[must_use]
    pub const fn with_zero_method(mut self, zero_method: ZeroMethod) -> Self {
        self.zero_method = zero_method;
        self
    }
}

/// Result of a Wilcoxon signed-rank test.
#[derive(Debug, Clone, Copy, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub struct WilcoxonSignedRank {
    /// Sum of the ranks of the positive differences, `W⁺`.
    pub w_plus: f64,
    /// Sum of the ranks of the negative differences, `W⁻`.
    pub w_minus: f64,
    /// Number of non-zero differences.
    pub n_nonzero: usize,
    /// Number of zero differences.
    pub n_zero: usize,
    /// Normal-approximation z score of `W⁺` (tie-corrected, and continuity
    /// corrected when enabled). Positive when differences tend to be
    /// positive. Reported even when the p-value is exact.
    pub z: f64,
    /// p-value under the chosen alternative.
    pub p_value: f64,
    /// Whether [`WilcoxonSignedRank::p_value`] is exact.
    pub exact: bool,
    /// Matched-pairs rank-biserial correlation `(W⁺ − W⁻)/(W⁺ + W⁻)` in
    /// `[−1, 1]`.
    pub rank_biserial: f64,
}

/// Signed-rank test that the differences `diffs` are symmetric about zero.
/// Copies the input once; see [`wilcoxon_signed_rank_in_place`].
///
/// For a one-sample test against a location `μ`, pass `xᵢ − μ`; for paired
/// samples, see [`wilcoxon_paired`].
///
/// ```
/// use rune_stats::{wilcoxon_signed_rank, WilcoxonOptions};
///
/// let diffs = [1.83, 0.50, 1.62, 2.48, 1.68, 1.88, 1.55, 3.06, 1.30];
/// let result = wilcoxon_signed_rank(&diffs, &WilcoxonOptions::default())?;
/// assert_eq!(result.w_plus, 45.0);
/// assert!(result.exact);
/// assert!((result.p_value - 2.0 / 512.0).abs() < 1e-15);
/// # Ok::<(), rune_stats::Error>(())
/// ```
pub fn wilcoxon_signed_rank(
    diffs: &[f64],
    options: &WilcoxonOptions,
) -> Result<WilcoxonSignedRank, Error> {
    check(diffs)?;
    wilcoxon_signed_rank_in_place(&mut diffs.to_vec(), options)
}

/// Signed-rank test on paired samples, using the differences `xᵢ − yᵢ`.
///
/// # Errors
///
/// [`Error::LengthMismatch`] when the samples differ in length.
pub fn wilcoxon_paired(
    x: &[f64],
    y: &[f64],
    options: &WilcoxonOptions,
) -> Result<WilcoxonSignedRank, Error> {
    if x.len() != y.len() {
        return Err(Error::LengthMismatch {
            left: x.len(),
            right: y.len(),
        });
    }
    check(x)?;
    check(y)?;
    let mut diffs: Vec<f64> = x.iter().zip(y).map(|(a, b)| a - b).collect();
    wilcoxon_signed_rank_in_place(&mut diffs, options)
}

/// [`wilcoxon_signed_rank`] without copying: sorts `diffs` by absolute
/// value in place. Allocates only for an exact p-value.
///
/// # Errors
///
/// [`Error::TooFew`] when every difference is zero,
/// [`Error::ExactWithTies`] for [`Method::Exact`] with ties or zeros,
/// [`Error::TooLarge`] for [`Method::Exact`] with more than 120 non-zero
/// differences.
pub fn wilcoxon_signed_rank_in_place(
    diffs: &mut [f64],
    options: &WilcoxonOptions,
) -> Result<WilcoxonSignedRank, Error> {
    check(diffs)?;
    diffs.sort_unstable_by(|a, b| a.abs().total_cmp(&b.abs()));
    let n_zero = diffs.iter().take_while(|d| **d == 0.0).count();
    let n_nonzero = diffs.len() - n_zero;
    if n_nonzero == 0 {
        return Err(Error::TooFew { needed: 1, got: 0 });
    }

    // Ranks of the non-zero differences start after the zeros under Pratt,
    // at 1 under Wilcox.
    let mut position = match options.zero_method {
        ZeroMethod::Wilcox => 0,
        ZeroMethod::Pratt => n_zero,
    };
    let (mut w_plus, mut w_minus, mut tie_term) = (0.0, 0.0, 0.0);
    let mut rest = &diffs[n_zero..];
    while let Some(first) = rest.first() {
        let magnitude = first.abs();
        let group = rest
            .iter()
            .take_while(|d| d.abs().total_cmp(&magnitude).is_eq())
            .count();
        let positive = rest[..group].iter().filter(|d| **d > 0.0).count();
        let average = count(2 * position + group + 1) / 2.0;
        w_plus = count(positive).mul_add(average, w_plus);
        w_minus = count(group - positive).mul_add(average, w_minus);
        let tied = count(group);
        tie_term += tied.mul_add(tied * tied, -tied);
        position += group;
        rest = &rest[group..];
    }
    let ties = tie_term > 0.0;

    let ranked = match options.zero_method {
        ZeroMethod::Wilcox => count(n_nonzero),
        ZeroMethod::Pratt => count(diffs.len()),
    };
    let mut mean = ranked * (ranked + 1.0) * 0.25;
    let mut spread = ranked * (ranked + 1.0) * 2.0f64.mul_add(ranked, 1.0);
    if options.zero_method == ZeroMethod::Pratt {
        let zeros = count(n_zero);
        mean = (zeros * (zeros + 1.0)).mul_add(-0.25, mean);
        spread = (zeros * (zeros + 1.0)).mul_add(-2.0f64.mul_add(zeros, 1.0), spread);
    }
    let se = (tie_term.mul_add(-0.5, spread) / 24.0).sqrt();
    let mut numerator = w_plus - mean;
    if options.continuity {
        numerator = (-0.5f64).mul_add(correction_sign(numerator, options.alternative), numerator);
    }
    let z = numerator / se;

    let exact = match options.method {
        Method::Exact if ties || n_zero > 0 => return Err(Error::ExactWithTies),
        Method::Exact => true,
        Method::Asymptotic => false,
        Method::Auto => !ties && n_zero == 0 && n_nonzero < AUTO_EXACT_BELOW,
    };
    let p_value = if exact {
        let dist = Distribution::signed_rank(n_nonzero)?;
        #[expect(
            clippy::cast_possible_truncation,
            clippy::cast_sign_loss,
            reason = "without ties W⁺ is an integer in [0, n(n+1)/2]"
        )]
        let k = w_plus.round() as usize;
        exact_p_value(dist.sf(k), dist.cdf(k), options.alternative)
    } else {
        normal_p_value(z, options.alternative)
    };

    Ok(WilcoxonSignedRank {
        w_plus,
        w_minus,
        n_nonzero,
        n_zero,
        z,
        p_value,
        exact,
        rank_biserial: (w_plus - w_minus) / (w_plus + w_minus),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ranks_with_zeros_and_ties() {
        let diffs = [0.0, 1.0, -1.0, 2.0, -3.0, 0.0];
        let wilcox = wilcoxon_signed_rank(&diffs, &WilcoxonOptions::default()).unwrap();
        // |d| ranks without zeros: 1.5, 1.5, 3, 4.
        assert_eq!((wilcox.w_plus, wilcox.w_minus), (4.5, 5.5));
        assert_eq!((wilcox.n_zero, wilcox.n_nonzero), (2, 4));
        assert!(!wilcox.exact);
        let pratt = wilcoxon_signed_rank(
            &diffs,
            &WilcoxonOptions::default().with_zero_method(ZeroMethod::Pratt),
        )
        .unwrap();
        // With zeros holding ranks 1 and 2: 3.5, 3.5, 5, 6.
        assert_eq!((pratt.w_plus, pratt.w_minus), (8.5, 9.5));
    }

    #[test]
    fn errors() {
        assert_eq!(
            wilcoxon_signed_rank(&[0.0, 0.0], &WilcoxonOptions::default()),
            Err(Error::TooFew { needed: 1, got: 0 })
        );
        assert_eq!(
            wilcoxon_signed_rank(
                &[1.0, -1.0, 2.0],
                &WilcoxonOptions::default().with_method(Method::Exact)
            ),
            Err(Error::ExactWithTies)
        );
        assert_eq!(
            wilcoxon_paired(&[1.0], &[1.0, 2.0], &WilcoxonOptions::default()),
            Err(Error::LengthMismatch { left: 1, right: 2 })
        );
    }

    #[test]
    fn paired_matches_differences() {
        let x = [
            125.0, 115.0, 130.0, 140.0, 140.0, 115.0, 140.0, 125.0, 140.0, 135.0,
        ];
        let y = [
            110.0, 122.0, 125.0, 120.0, 140.0, 124.0, 123.0, 137.0, 135.0, 145.0,
        ];
        let diffs: Vec<f64> = x.iter().zip(&y).map(|(a, b)| a - b).collect();
        let options = WilcoxonOptions::default();
        assert_eq!(
            wilcoxon_paired(&x, &y, &options).unwrap(),
            wilcoxon_signed_rank(&diffs, &options).unwrap()
        );
    }
}
