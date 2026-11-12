//! Descriptive statistics: location, spread and quantiles.
//!
//! Each order statistic comes in up to three flavours:
//!
//! * a convenience function on `&[f64]` that copies the input once
//!   ([`median`], [`quantile`], [`mad`]),
//! * an `_in_place` variant that reorders a caller-owned buffer and does not
//!   allocate ([`median_in_place`], [`quantile_in_place`], [`mad_in_place`]),
//! * a `_sorted` variant for data that is already sorted ascending
//!   ([`median_sorted`], [`quantile_sorted`]), which is `O(1)`.
//!
//! Ordering always uses [`f64::total_cmp`], and every function rejects `NaN`
//! with [`Error::Nan`] and empty input with [`Error::Empty`].

use crate::Error;
use crate::util::{check, check_sorted, count};

/// Factor that turns a median absolute deviation into a consistent
/// estimate of the standard deviation for normally distributed data
/// (`1 / Φ⁻¹(3/4)`, rounded to four decimals as in most references).
pub const MAD_TO_SIGMA: f64 = 1.4826;

/// Arithmetic mean.
///
/// ```
/// assert_eq!(rune_stats::mean(&[1.0, 2.0, 6.0])?, 3.0);
/// # Ok::<(), rune_stats::Error>(())
/// ```
pub fn mean(values: &[f64]) -> Result<f64, Error> {
    check(values)?;
    Ok(values.iter().sum::<f64>() / count(values.len()))
}

/// Sum of squared deviations from the mean, computed with the corrected
/// two-pass algorithm (Chan, Golub and Le Veque, 1983) for numerical stability.
pub fn sum_of_squares(values: &[f64]) -> Result<f64, Error> {
    let center = mean(values)?;
    let mut squares = 0.0;
    let mut compensation = 0.0;
    for value in values {
        let deviation = value - center;
        squares = deviation.mul_add(deviation, squares);
        compensation += deviation;
    }
    let corrected = (compensation * compensation).mul_add(-1.0 / count(values.len()), squares);
    Ok(corrected.max(0.0))
}

/// Unbiased sample variance (divisor `n − 1`).
///
/// # Errors
///
/// [`Error::TooFew`] for fewer than two observations.
///
/// ```
/// let var = rune_stats::variance(&[2.0, 4.0, 4.0, 4.0, 5.0, 5.0, 7.0, 9.0])?;
/// assert!((var - 32.0 / 7.0).abs() < 1e-12);
/// # Ok::<(), rune_stats::Error>(())
/// ```
pub fn variance(values: &[f64]) -> Result<f64, Error> {
    if values.len() < 2 {
        check(values)?;
        return Err(Error::TooFew {
            needed: 2,
            got: values.len(),
        });
    }
    Ok(sum_of_squares(values)? / count(values.len() - 1))
}

/// Population variance (divisor `n`).
pub fn population_variance(values: &[f64]) -> Result<f64, Error> {
    Ok(sum_of_squares(values)? / count(values.len()))
}

/// Sample standard deviation, the square root of [`variance`].
///
/// # Errors
///
/// [`Error::TooFew`] for fewer than two observations.
pub fn std_dev(values: &[f64]) -> Result<f64, Error> {
    variance(values).map(f64::sqrt)
}

/// Population standard deviation, the square root of
/// [`population_variance`].
pub fn population_std_dev(values: &[f64]) -> Result<f64, Error> {
    population_variance(values).map(f64::sqrt)
}

/// Median. Copies the input once; see [`median_in_place`] to avoid that.
///
/// For an even number of observations this is the midpoint of the two
/// middle values.
///
/// ```
/// assert_eq!(rune_stats::median(&[4.0, 1.0, 2.0, 3.0])?, 2.5);
/// # Ok::<(), rune_stats::Error>(())
/// ```
pub fn median(values: &[f64]) -> Result<f64, Error> {
    check(values)?;
    median_in_place(&mut values.to_vec())
}

/// Median without allocating. Reorders `values` (partial selection, `O(n)`
/// on average); the multiset of values is unchanged.
pub fn median_in_place(values: &mut [f64]) -> Result<f64, Error> {
    check(values)?;
    let len = values.len();
    let mid = len / 2;
    let (lower_half, upper, _) = values.select_nth_unstable_by(mid, f64::total_cmp);
    let upper = *upper;
    if len.is_multiple_of(2) {
        let lower = lower_half
            .iter()
            .copied()
            .max_by(f64::total_cmp)
            .unwrap_or(upper);
        Ok(f64::midpoint(lower, upper))
    } else {
        Ok(upper)
    }
}

/// Median of data already sorted ascending, in `O(n)` validation time and
/// without allocating.
///
/// # Errors
///
/// [`Error::NotSorted`] if `sorted` is not in ascending order.
pub fn median_sorted(sorted: &[f64]) -> Result<f64, Error> {
    check_sorted(sorted)?;
    let mid = sorted.len() / 2;
    if sorted.len().is_multiple_of(2) {
        Ok(f64::midpoint(sorted[mid - 1], sorted[mid]))
    } else {
        Ok(sorted[mid])
    }
}

fn check_probability(p: f64, name: &'static str) -> Result<(), Error> {
    if (0.0..=1.0).contains(&p) {
        Ok(())
    } else {
        Err(Error::InvalidParameter { name, value: p })
    }
}

/// Position `(index, fraction)` of quantile `p` among `len` sorted values
/// (Hyndman & Fan type 7).
#[expect(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    reason = "h lies in [0, len − 1] and is finite"
)]
fn quantile_position(len: usize, p: f64) -> (usize, f64) {
    let h = count(len - 1) * p;
    let floor = h.floor();
    let index = (floor as usize).min(len - 1);
    (index, h - floor)
}

/// Linear interpolation between `a` and `b`, in the form `NumPy` uses so that
/// results agree to the last bit for most inputs.
fn lerp(a: f64, b: f64, t: f64) -> f64 {
    let diff = b - a;
    if t >= 0.5 {
        diff.mul_add(-(1.0 - t), b)
    } else {
        diff.mul_add(t, a)
    }
}

/// Quantile `p ∈ [0, 1]` of data already sorted ascending, using linear
/// interpolation between order statistics (Hyndman & Fan type 7, the
/// default of R's `quantile` and `NumPy`'s `quantile`).
///
/// # Errors
///
/// [`Error::InvalidParameter`] if `p` is outside `[0, 1]`;
/// [`Error::NotSorted`] if `sorted` is not ascending.
pub fn quantile_sorted(sorted: &[f64], p: f64) -> Result<f64, Error> {
    check_probability(p, "p")?;
    check_sorted(sorted)?;
    let (index, fraction) = quantile_position(sorted.len(), p);
    if fraction == 0.0 || index + 1 >= sorted.len() {
        return Ok(sorted[index]);
    }
    Ok(lerp(sorted[index], sorted[index + 1], fraction))
}

/// Quantile `p ∈ [0, 1]` without allocating. Reorders `values`; see
/// [`quantile_sorted`] for the definition.
pub fn quantile_in_place(values: &mut [f64], p: f64) -> Result<f64, Error> {
    check_probability(p, "p")?;
    check(values)?;
    let (index, fraction) = quantile_position(values.len(), p);
    let (_, lower, upper_part) = values.select_nth_unstable_by(index, f64::total_cmp);
    let lower = *lower;
    if fraction == 0.0 {
        return Ok(lower);
    }
    let upper = upper_part
        .iter()
        .copied()
        .min_by(f64::total_cmp)
        .unwrap_or(lower);
    Ok(lerp(lower, upper, fraction))
}

/// Quantile `p ∈ [0, 1]`. Copies the input once; see [`quantile_sorted`]
/// for the definition.
///
/// ```
/// let q = rune_stats::quantile(&[1.0, 2.0, 3.0, 4.0], 0.25)?;
/// assert!((q - 1.75).abs() < 1e-12);
/// # Ok::<(), rune_stats::Error>(())
/// ```
pub fn quantile(values: &[f64], p: f64) -> Result<f64, Error> {
    check_probability(p, "p")?;
    check(values)?;
    quantile_in_place(&mut values.to_vec(), p)
}

/// Percentile `q ∈ [0, 100]`, i.e. [`quantile`] at `q / 100`.
pub fn percentile(values: &[f64], q: f64) -> Result<f64, Error> {
    if !(0.0..=100.0).contains(&q) {
        return Err(Error::InvalidParameter {
            name: "q",
            value: q,
        });
    }
    quantile(values, q / 100.0)
}

/// Median absolute deviation from the median (unscaled). Copies the input
/// once; multiply by [`MAD_TO_SIGMA`] (or use [`robust_sigma`]) for a robust
/// standard deviation.
///
/// ```
/// assert_eq!(rune_stats::mad(&[1.0, 1.0, 2.0, 2.0, 4.0, 6.0, 9.0])?, 1.0);
/// # Ok::<(), rune_stats::Error>(())
/// ```
pub fn mad(values: &[f64]) -> Result<f64, Error> {
    check(values)?;
    mad_in_place(&mut values.to_vec())
}

/// Median absolute deviation without allocating. **Overwrites** `values`
/// with the absolute deviations from the median.
pub fn mad_in_place(values: &mut [f64]) -> Result<f64, Error> {
    let center = median_in_place(values)?;
    for value in values.iter_mut() {
        *value = (*value - center).abs();
    }
    median_in_place(values)
}

/// Robust standard deviation estimate: [`mad`] × [`MAD_TO_SIGMA`].
pub fn robust_sigma(values: &[f64]) -> Result<f64, Error> {
    mad(values).map(|deviation| deviation * MAD_TO_SIGMA)
}

/// Robust location and scale of a sample: median and scaled MAD.
///
/// Used to flag outliers without letting the outliers themselves inflate
/// the spread, as a mean and standard deviation would.
#[derive(Debug, Clone, Copy, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub struct RobustScale {
    /// Median of the sample.
    pub center: f64,
    /// Median absolute deviation from [`RobustScale::center`].
    pub mad: f64,
    /// Robust standard deviation, `mad × MAD_TO_SIGMA`.
    pub sigma: f64,
}

impl RobustScale {
    /// Estimates the robust scale of `values`, copying the input once.
    pub fn estimate(values: &[f64]) -> Result<Self, Error> {
        check(values)?;
        Self::estimate_in_place(&mut values.to_vec())
    }

    /// Estimates the robust scale without allocating. **Overwrites**
    /// `values` with the absolute deviations from the median.
    pub fn estimate_in_place(values: &mut [f64]) -> Result<Self, Error> {
        let center = median_in_place(values)?;
        for value in values.iter_mut() {
            *value = (*value - center).abs();
        }
        let mad = median_in_place(values)?;
        Ok(Self {
            center,
            mad,
            sigma: mad * MAD_TO_SIGMA,
        })
    }

    /// Whether `value` lies within `threshold × sigma` of the center. When
    /// the spread is zero (at most [`f64::EPSILON`]) every value counts as
    /// an inlier, since there is no scale to measure against.
    #[must_use]
    pub fn is_inlier(&self, value: f64, threshold: f64) -> bool {
        if self.sigma <= f64::EPSILON {
            return true;
        }
        (value - self.center).abs() <= threshold * self.sigma
    }

    /// Robust z-score `(value − center) / sigma`, or `None` when the spread
    /// is zero.
    #[must_use]
    pub fn robust_z(&self, value: f64) -> Option<f64> {
        (self.sigma > f64::EPSILON).then(|| (value - self.center) / self.sigma)
    }
}

/// For each value, whether it lies within `threshold` robust standard
/// deviations of the median (see [`RobustScale::is_inlier`]).
///
/// ```
/// let mask = rune_stats::inlier_mask(&[100.0, 110.0, 105.0, 95.0, 102.0, 5000.0], 3.5)?;
/// assert_eq!(mask, [true, true, true, true, true, false]);
/// # Ok::<(), rune_stats::Error>(())
/// ```
pub fn inlier_mask(values: &[f64], threshold: f64) -> Result<Vec<bool>, Error> {
    let scale = RobustScale::estimate(values)?;
    Ok(values
        .iter()
        .map(|&value| scale.is_inlier(value, threshold))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_and_nan_are_rejected() {
        assert_eq!(mean(&[]), Err(Error::Empty));
        assert_eq!(median(&[1.0, f64::NAN]), Err(Error::Nan));
        assert_eq!(variance(&[1.0]), Err(Error::TooFew { needed: 2, got: 1 }));
        assert_eq!(variance(&[]), Err(Error::Empty));
        assert_eq!(median_sorted(&[2.0, 1.0]), Err(Error::NotSorted));
        assert!(matches!(
            quantile(&[1.0], 1.5),
            Err(Error::InvalidParameter { name: "p", .. })
        ));
        assert!(matches!(
            percentile(&[1.0], f64::NAN),
            Err(Error::InvalidParameter { name: "q", .. })
        ));
    }

    #[test]
    fn median_variants_agree() {
        for data in [
            vec![3.0, 1.0, 2.0],
            vec![4.0, 1.0, 2.0, 3.0],
            vec![5.0],
            vec![-1.0, 7.5, 7.5, 2.0, -3.0, 0.0],
        ] {
            let mut sorted = data.clone();
            sorted.sort_by(f64::total_cmp);
            let expected = median(&data).unwrap();
            assert_eq!(median_sorted(&sorted).unwrap(), expected);
            assert_eq!(median_in_place(&mut data.clone()).unwrap(), expected);
        }
        assert_eq!(median(&[3.0, 1.0, 2.0]).unwrap(), 2.0);
        assert_eq!(median(&[4.0, 1.0, 2.0, 3.0]).unwrap(), 2.5);
    }

    #[test]
    fn quantile_endpoints_and_interpolation() {
        let data = [10.0, 20.0, 30.0, 40.0, 50.0];
        assert_eq!(quantile(&data, 0.0).unwrap(), 10.0);
        assert_eq!(quantile(&data, 1.0).unwrap(), 50.0);
        assert_eq!(quantile(&data, 0.5).unwrap(), 30.0);
        assert_eq!(quantile(&data, 0.1).unwrap(), 14.0);
        assert_eq!(percentile(&data, 90.0).unwrap(), 46.0);
        assert_eq!(quantile_sorted(&data, 0.1).unwrap(), 14.0);
    }

    #[test]
    fn spread() {
        let data = [2.0, 4.0, 4.0, 4.0, 5.0, 5.0, 7.0, 9.0];
        assert_eq!(population_variance(&data).unwrap(), 4.0);
        assert_eq!(population_std_dev(&data).unwrap(), 2.0);
        assert!((std_dev(&data).unwrap() - (32.0f64 / 7.0).sqrt()).abs() < 1e-12);
        // Large offset: naive sum-of-squares would lose all precision.
        let shifted: Vec<f64> = data.iter().map(|x| x + 1e9).collect();
        assert!((population_variance(&shifted).unwrap() - 4.0).abs() < 1e-6);
    }

    #[test]
    fn mad_and_inliers() {
        assert_eq!(mad(&[1.0, 1.0, 2.0, 2.0, 4.0, 6.0, 9.0]).unwrap(), 1.0);
        assert_eq!(
            robust_sigma(&[1.0, 1.0, 2.0, 2.0, 4.0, 6.0, 9.0]).unwrap(),
            MAD_TO_SIGMA
        );
        assert_eq!(inlier_mask(&[1.0, 1.0], 3.5).unwrap(), [true, true]);
        let scale = RobustScale::estimate(&[1.0, 2.0, 3.0, 4.0, 100.0]).unwrap();
        assert_eq!(scale.center, 3.0);
        assert_eq!(scale.mad, 1.0);
        assert!((scale.robust_z(2.0f64.mul_add(MAD_TO_SIGMA, 3.0)).unwrap() - 2.0).abs() < 1e-12);
        let flat = RobustScale::estimate(&[2.0; 4]).unwrap();
        assert_eq!(flat.robust_z(5.0), None);
        assert!(flat.is_inlier(1e9, 0.0));
    }
}
