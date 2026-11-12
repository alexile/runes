//! Two-sample Kolmogorov–Smirnov test.

use crate::Error;
use crate::dist::kolmogorov_sf;
use crate::hypothesis::{Alternative, Method};
use crate::rank::walk;
use crate::util::{check_sorted, count, int, sorted_copy};

/// Under [`Method::Auto`] the exact p-value is used while `m·n` stays at
/// or below this many lattice points (a few milliseconds of work).
const AUTO_EXACT_MAX_CELLS: usize = 10_000_000;

/// Settings for [`ks_two_sample`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub struct KsOptions {
    /// Alternative hypothesis. Default: [`Alternative::TwoSided`].
    /// [`Alternative::Greater`] tests `D⁺ = max(F_x − F_y)`, i.e. that `x`
    /// tends to be *smaller* somewhere (its ECDF lies above `y`'s), following
    /// `SciPy`'s convention for `ks_2samp`.
    pub alternative: Alternative,
    /// How to compute the p-value. Default: [`Method::Auto`], exact while
    /// `m·n ≤ 10⁷`, otherwise asymptotic.
    pub method: Method,
}

impl KsOptions {
    /// Sets [`KsOptions::alternative`].
    #[must_use]
    pub const fn with_alternative(mut self, alternative: Alternative) -> Self {
        self.alternative = alternative;
        self
    }

    /// Sets [`KsOptions::method`].
    #[must_use]
    pub const fn with_method(mut self, method: Method) -> Self {
        self.method = method;
        self
    }
}

/// Result of a two-sample Kolmogorov–Smirnov test.
#[derive(Debug, Clone, Copy, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub struct KolmogorovSmirnov {
    /// The statistic for the chosen alternative: `D = max(D⁺, D⁻)` for
    /// two-sided, `D⁺` for greater, `D⁻` for less. As the largest gap
    /// between the two ECDFs it doubles as an effect size in `[0, 1]`.
    pub statistic: f64,
    /// `D⁺ = max (F_x − F_y)`.
    pub d_plus: f64,
    /// `D⁻ = max (F_y − F_x)`.
    pub d_minus: f64,
    /// p-value under the chosen alternative.
    pub p_value: f64,
    /// Whether [`KolmogorovSmirnov::p_value`] is exact.
    pub exact: bool,
}

/// Two-sample Kolmogorov–Smirnov test. Copies and sorts both samples; use
/// [`ks_two_sample_sorted`] on pre-sorted data.
///
/// The exact p-value counts monotone lattice paths (each equally likely
/// under the null) that reach the observed statistic, in `O(m·n)` time and
/// `O(n)` memory. It assumes continuous data; with ties it is
/// conservative. The asymptotic two-sided p-value is the Kolmogorov limit
/// `Q(√(mn/(m+n)) · D)`; one-sided uses Hodges' (1958) approximation, as
/// `SciPy` does.
///
/// ```
/// use rune_stats::{ks_two_sample, KsOptions};
///
/// let a = [0.61, 0.29, 0.06, 0.59, -1.73, -0.74, 0.51, -0.56, 0.39, 1.64];
/// let b = [2.21, 1.87, 3.04, 2.55, 1.25, 2.97, 1.93, 2.41, 3.12, 2.08];
/// let result = ks_two_sample(&a, &b, &KsOptions::default())?;
/// assert!(result.statistic > 0.8 && result.p_value < 1e-3);
/// # Ok::<(), rune_stats::Error>(())
/// ```
pub fn ks_two_sample(
    x: &[f64],
    y: &[f64],
    options: &KsOptions,
) -> Result<KolmogorovSmirnov, Error> {
    let x = sorted_copy(x)?;
    let y = sorted_copy(y)?;
    ks_two_sample_sorted(&x, &y, options)
}

/// [`ks_two_sample`] on samples already sorted ascending. The statistic and
/// the asymptotic p-value need no allocation; the exact p-value allocates
/// one row of `min(m, n) + 1` floats.
///
/// # Errors
///
/// [`Error::NotSorted`] for unsorted input.
pub fn ks_two_sample_sorted(
    x: &[f64],
    y: &[f64],
    options: &KsOptions,
) -> Result<KolmogorovSmirnov, Error> {
    check_sorted(x)?;
    check_sorted(y)?;
    let (m, n) = (x.len(), y.len());
    let walk = walk(x, y);
    let cells = int(i128::from(m as u64) * i128::from(n as u64));
    let gap = match options.alternative {
        Alternative::TwoSided => walk.max_gap.max(-walk.min_gap),
        Alternative::Greater => walk.max_gap,
        Alternative::Less => -walk.min_gap,
    };
    let statistic = int(gap) / cells;
    let exact = match options.method {
        Method::Exact => true,
        Method::Asymptotic => false,
        Method::Auto => m
            .checked_mul(n)
            .is_some_and(|product| product <= AUTO_EXACT_MAX_CELLS),
    };
    let p_value = if exact {
        exact_p_value(m, n, gap, options.alternative)
    } else {
        asymptotic_p_value(m, n, statistic, options.alternative)
    };
    Ok(KolmogorovSmirnov {
        statistic,
        d_plus: int(walk.max_gap) / cells,
        d_minus: int(-walk.min_gap) / cells,
        p_value,
        exact,
    })
}

/// `P(statistic ≥ gap / (m·n))` under the null, by dynamic programming
/// over the lattice of `(i, j)` = (values of `x`, values of `y`) seen.
///
/// Each monotone path from `(0, 0)` to `(m, n)` is equally likely, so the
/// step probabilities are those of drawing without replacement. Mass that
/// reaches a point where the gap condition holds is absorbed and summed,
/// which keeps small p-values accurate.
fn exact_p_value(m: usize, n: usize, gap: i128, alternative: Alternative) -> f64 {
    if gap <= 0 {
        return 1.0;
    }
    let (m_i, n_i) = (m as i128, n as i128);
    let hits = |i: usize, j: usize| {
        let diff = (i as i128) * n_i - (j as i128) * m_i;
        match alternative {
            Alternative::TwoSided => diff.abs() >= gap,
            Alternative::Greater => diff >= gap,
            Alternative::Less => -diff >= gap,
        }
    };
    let total = m + n;
    let mut row = vec![0.0f64; n + 1];
    let mut p = 0.0;
    row[0] = 1.0;
    for j in 1..=n {
        row[j] = row[j - 1] * count(n - (j - 1)) / count(total - (j - 1));
        if hits(0, j) {
            p += row[j];
            row[j] = 0.0;
        }
    }
    for i in 1..=m {
        for j in 0..=n {
            let from_below = row[j] * count(m - (i - 1)) / count(total - (i - 1) - j);
            let from_left = if j > 0 {
                row[j - 1] * count(n - (j - 1)) / count(total - i - (j - 1))
            } else {
                0.0
            };
            row[j] = from_below + from_left;
            if hits(i, j) {
                p += row[j];
                row[j] = 0.0;
            }
        }
    }
    p.clamp(0.0, 1.0)
}

fn asymptotic_p_value(m: usize, n: usize, statistic: f64, alternative: Alternative) -> f64 {
    let (large, small) = if m >= n {
        (count(m), count(n))
    } else {
        (count(n), count(m))
    };
    let en = large * small / (large + small);
    let z = en.sqrt() * statistic;
    let p = match alternative {
        Alternative::TwoSided => kolmogorov_sf(z),
        Alternative::Greater | Alternative::Less => {
            let correction = 2.0 * z * 2.0f64.mul_add(small, large)
                / (large * small * (large + small)).sqrt()
                / 3.0;
            (-2.0 * z).mul_add(z, -correction).exp()
        }
    };
    p.clamp(0.0, 1.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identical_samples_have_p_one() {
        let x = [1.0, 2.0, 3.0];
        let result = ks_two_sample(&x, &x, &KsOptions::default()).unwrap();
        assert_eq!(result.statistic, 0.0);
        assert_eq!(result.p_value, 1.0);
    }

    #[test]
    fn fully_separated_exact() {
        // D = 1 is reached only by the two extreme paths: p = 2 / C(m+n, m).
        let x = [1.0, 2.0, 3.0];
        let y = [4.0, 5.0, 6.0, 7.0];
        let result = ks_two_sample(&x, &y, &KsOptions::default()).unwrap();
        assert_eq!(result.statistic, 1.0);
        assert!(result.exact);
        assert!((result.p_value - 2.0 / 35.0).abs() < 1e-15);
        let greater = ks_two_sample(
            &x,
            &y,
            &KsOptions::default().with_alternative(Alternative::Greater),
        )
        .unwrap();
        assert!((greater.p_value - 1.0 / 35.0).abs() < 1e-15);
        assert_eq!(greater.d_minus, 0.0);
    }
}
