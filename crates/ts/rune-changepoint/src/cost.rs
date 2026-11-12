//! Segment cost functions for offline change-point search.

#![allow(
    clippy::cast_precision_loss,
    reason = "segment lengths stay far below 2^52, so usize -> f64 is exact"
)]
#![allow(
    clippy::suboptimal_flops,
    reason = "mul_add needs std and this module also builds on core"
)]

use alloc::vec::Vec;

use crate::Error;
use crate::math::ln;

/// A segment cost: twice the negative log-likelihood of a segment under some
/// model, up to terms that are the same for every segmentation.
///
/// [`Pelt`](crate::Pelt) and [`BinSeg`](crate::BinSeg) minimise the total
/// cost plus a penalty per change point. Implement this trait to plug in
/// another model; costs must not increase when a segment is split
/// (`cost(a, c) >= cost(a, b) + cost(b, c)`) for PELT's pruning to be exact.
///
/// # Example
///
/// ```rust
/// use rune_changepoint::{Cost, Pelt, Penalty};
///
/// /// Sum of absolute deviations from the segment median.
/// struct L1<'a>(&'a [f64]);
///
/// impl Cost for L1<'_> {
///     fn len(&self) -> usize {
///         self.0.len()
///     }
///     fn cost(&self, start: usize, end: usize) -> f64 {
///         let mut seg = self.0[start..end].to_vec();
///         seg.sort_by(f64::total_cmp);
///         let med = seg[seg.len() / 2];
///         seg.iter().map(|v| (v - med).abs()).sum()
///     }
/// }
///
/// let data = [0.0, 0.1, -0.1, 0.0, 5.0, 5.1, 4.9, 5.0];
/// let cps = Pelt::new().penalty(Penalty::Manual(2.0)).detect(&L1(&data)).unwrap();
/// assert_eq!(cps, vec![4]);
/// ```
pub trait Cost {
    /// Number of observations.
    fn len(&self) -> usize;

    /// `true` when there are no observations.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Cost of the half-open segment `start..end` (`start < end <= len`).
    fn cost(&self, start: usize, end: usize) -> f64;

    /// Parameters estimated per segment, used by [`Penalty::Bic`] and
    /// [`Penalty::Mbic`](crate::Penalty::Mbic).
    ///
    /// [`Penalty::Bic`]: crate::Penalty::Bic
    fn params_per_segment(&self) -> usize {
        1
    }

    /// Smallest segment length the cost is defined for.
    fn min_size(&self) -> usize {
        1
    }
}

fn check_finite(data: &[f64]) -> Result<(), Error> {
    data.iter()
        .position(|v| !v.is_finite())
        .map_or(Ok(()), |index| Err(Error::NonFinite { index }))
}

/// Prefix sums of `x - shift` and `(x - shift)^2`. Shifting by the overall
/// mean keeps the differences of large sums accurate.
#[derive(Debug, Clone)]
struct Prefix {
    s1: Vec<f64>,
    s2: Vec<f64>,
}

impl Prefix {
    fn new(data: &[f64]) -> Self {
        let shift = if data.is_empty() {
            0.0
        } else {
            data.iter().sum::<f64>() / data.len() as f64
        };
        let mut s1 = Vec::with_capacity(data.len() + 1);
        let mut s2 = Vec::with_capacity(data.len() + 1);
        let (mut a, mut b) = (0.0, 0.0);
        s1.push(a);
        s2.push(b);
        for v in data {
            let d = v - shift;
            a += d;
            b += d * d;
            s1.push(a);
            s2.push(b);
        }
        Self { s1, s2 }
    }

    /// Sum of squared deviations from the segment mean.
    fn sse(&self, start: usize, end: usize) -> f64 {
        let n = (end - start) as f64;
        let s = self.s1[end] - self.s1[start];
        let q = self.s2[end] - self.s2[start];
        (q - s * s / n).max(0.0)
    }
}

/// Mean-shift cost: squared deviations from the segment mean, divided by a
/// noise variance.
///
/// This is the Gaussian `-2 log L` for a change in mean
/// with known variance (ruptures' `CostL2` when the variance is 1).
///
/// With [`Penalty::Bic`](crate::Penalty::Bic) the variance matters: either
/// pass it, or let [`L2::with_estimated_variance`] estimate it robustly.
///
/// # Example
///
/// ```rust
/// use rune_changepoint::{Cost, L2};
///
/// let cost = L2::new(&[1.0, 2.0, 3.0]).unwrap();
/// assert!((cost.cost(0, 3) - 2.0).abs() < 1e-12);
/// ```
#[derive(Debug, Clone)]
pub struct L2 {
    prefix: Prefix,
    variance: f64,
    n: usize,
}

impl L2 {
    /// Cost with unit noise variance.
    ///
    /// # Errors
    ///
    /// [`Error::NonFinite`] for a `NaN` or infinite value.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_changepoint::{Error, L2};
    ///
    /// assert!(L2::new(&[1.0, 2.0]).is_ok());
    /// assert_eq!(L2::new(&[1.0, f64::NAN]).unwrap_err(), Error::NonFinite { index: 1 });
    /// ```
    pub fn new(data: &[f64]) -> Result<Self, Error> {
        Self::with_variance(data, 1.0)
    }

    /// Cost with the given noise variance.
    ///
    /// # Errors
    ///
    /// [`Error::NonFinite`] for a bad value, [`Error::InvalidParameter`] if
    /// `variance` is not finite and positive.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_changepoint::{Cost, L2};
    ///
    /// let cost = L2::with_variance(&[1.0, 2.0, 3.0], 2.0).unwrap();
    /// assert!((cost.cost(0, 3) - 1.0).abs() < 1e-12);
    /// ```
    pub fn with_variance(data: &[f64], variance: f64) -> Result<Self, Error> {
        check_finite(data)?;
        if !(variance.is_finite() && variance > 0.0) {
            return Err(Error::InvalidParameter {
                name: "variance",
                value: variance,
            });
        }
        Ok(Self {
            prefix: Prefix::new(data),
            variance,
            n: data.len(),
        })
    }

    /// Cost with the noise variance estimated by [`noise_variance`] (falls
    /// back to 1 when the series is too short or has no noise).
    ///
    /// # Errors
    ///
    /// [`Error::NonFinite`] for a `NaN` or infinite value.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_changepoint::{L2, Pelt, Penalty};
    ///
    /// let data: Vec<f64> = (0..100)
    ///     .map(|t| if t < 60 { 0.0 } else { 30.0 } + [3.0, -2.0, 1.0, -4.0, 2.0][t % 5])
    ///     .collect();
    /// let cost = L2::with_estimated_variance(&data).unwrap();
    /// assert_eq!(Pelt::new().penalty(Penalty::Bic).detect(&cost).unwrap(), vec![60]);
    /// ```
    pub fn with_estimated_variance(data: &[f64]) -> Result<Self, Error> {
        check_finite(data)?;
        let variance = noise_variance(data).filter(|v| *v > 0.0).unwrap_or(1.0);
        Self::with_variance(data, variance)
    }
}

impl Cost for L2 {
    fn len(&self) -> usize {
        self.n
    }

    fn cost(&self, start: usize, end: usize) -> f64 {
        self.prefix.sse(start, end) / self.variance
    }
}

/// Robust noise variance estimate that ignores level shifts.
///
/// It is the median absolute deviation of first differences, scaled to a normal standard
/// deviation (`MAD / 0.6745`) and halved because differencing doubles the
/// variance. `None` for fewer than 3 values.
///
/// # Example
///
/// ```rust
/// use rune_changepoint::noise_variance;
///
/// // Noise with variance 1/3 (uniform on [-1, 1]) plus a big step: the
/// // step barely moves the estimate.
/// let noise = |t: usize| ((t * t * 7919 + 13 * t) % 1009) as f64 / 504.5 - 1.0;
/// let data: Vec<f64> = (0..200).map(|t| if t < 100 { 0.0 } else { 50.0 } + noise(t)).collect();
/// let v = noise_variance(&data).unwrap();
/// assert!(v > 0.15 && v < 0.6, "{v}");
/// ```
#[must_use]
pub fn noise_variance(data: &[f64]) -> Option<f64> {
    if data.len() < 3 || data.iter().any(|v| !v.is_finite()) {
        return None;
    }
    let mut diffs: Vec<f64> = data.windows(2).map(|w| w[1] - w[0]).collect();
    diffs.sort_by(f64::total_cmp);
    let med = median(&diffs);
    let mut dev: Vec<f64> = diffs
        .iter()
        .map(|d| if d > &med { d - med } else { med - d })
        .collect();
    dev.sort_by(f64::total_cmp);
    let sigma = median(&dev) / 0.674_489_750_196_081_7;
    Some(sigma * sigma / 2.0)
}

const fn median(sorted: &[f64]) -> f64 {
    let n = sorted.len();
    if n % 2 == 1 {
        sorted[n / 2]
    } else {
        f64::midpoint(sorted[n / 2 - 1], sorted[n / 2])
    }
}

/// Normal cost for changes in mean and variance.
///
/// The cost is `len * ln(var)` with the segment's maximum-likelihood
/// variance (Gaussian `-2 log L` up to constants). Segments need at least 2 points; the variance is floored at
/// a tiny fraction of the whole series' variance so flat stretches do not
/// produce `-inf`.
///
/// # Example
///
/// ```rust
/// use rune_changepoint::{NormalMeanVar, Pelt, Penalty};
///
/// let data: Vec<f64> = (0..120)
///     .map(|t| if t < 60 { [0.1, -0.1][t % 2] } else { [3.0, -3.0][t % 2] })
///     .collect();
/// let cost = NormalMeanVar::new(&data).unwrap();
/// assert_eq!(Pelt::new().detect(&cost).unwrap(), vec![60]);
/// ```
#[derive(Debug, Clone)]
pub struct NormalMeanVar {
    prefix: Prefix,
    floor: f64,
    n: usize,
}

impl NormalMeanVar {
    /// Builds the cost from a series.
    ///
    /// # Errors
    ///
    /// [`Error::NonFinite`] for a `NaN` or infinite value.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_changepoint::NormalMeanVar;
    ///
    /// assert!(NormalMeanVar::new(&[1.0, 2.0, 3.0]).is_ok());
    /// ```
    pub fn new(data: &[f64]) -> Result<Self, Error> {
        check_finite(data)?;
        let prefix = Prefix::new(data);
        let n = data.len();
        let total = if n > 0 {
            prefix.sse(0, n) / n as f64
        } else {
            0.0
        };
        let floor = if total > 0.0 { total * 1e-10 } else { 1.0 };
        Ok(Self { prefix, floor, n })
    }
}

impl Cost for NormalMeanVar {
    fn len(&self) -> usize {
        self.n
    }

    fn cost(&self, start: usize, end: usize) -> f64 {
        let len = (end - start) as f64;
        let var = (self.prefix.sse(start, end) / len).max(self.floor);
        len * ln(var)
    }

    fn params_per_segment(&self) -> usize {
        2
    }

    fn min_size(&self) -> usize {
        2
    }
}

/// Poisson cost for changes in the rate of count data:
/// `2 * (S - S ln(S / len))` where `S` is the segment sum (Poisson `-2 log L`
/// up to constants).
///
/// # Example
///
/// ```rust
/// use rune_changepoint::{Pelt, Poisson};
///
/// let counts: Vec<f64> = (0..80).map(|t| if t < 40 { [1.0, 2.0, 0.0, 1.0][t % 4] } else { [9.0, 11.0, 10.0, 8.0][t % 4] }).collect();
/// let cost = Poisson::new(&counts).unwrap();
/// assert_eq!(Pelt::new().detect(&cost).unwrap(), vec![40]);
/// ```
#[derive(Debug, Clone)]
pub struct Poisson {
    sums: Vec<f64>,
}

impl Poisson {
    /// Builds the cost from non-negative counts (non-integer rates are
    /// accepted).
    ///
    /// # Errors
    ///
    /// [`Error::NonFinite`] for a `NaN` or infinite value,
    /// [`Error::Negative`] for a value below zero.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_changepoint::{Error, Poisson};
    ///
    /// assert_eq!(Poisson::new(&[1.0, -1.0]).unwrap_err(), Error::Negative { index: 1 });
    /// ```
    pub fn new(data: &[f64]) -> Result<Self, Error> {
        check_finite(data)?;
        if let Some(index) = data.iter().position(|v| *v < 0.0) {
            return Err(Error::Negative { index });
        }
        let mut sums = Vec::with_capacity(data.len() + 1);
        let mut acc = 0.0;
        sums.push(acc);
        for v in data {
            acc += v;
            sums.push(acc);
        }
        Ok(Self { sums })
    }
}

impl Cost for Poisson {
    fn len(&self) -> usize {
        self.sums.len() - 1
    }

    fn cost(&self, start: usize, end: usize) -> f64 {
        let s = self.sums[end] - self.sums[start];
        if s <= 0.0 {
            return 0.0;
        }
        2.0 * (s - s * ln(s / (end - start) as f64))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn l2_matches_direct_sum() {
        let data = [1e9 + 1.0, 1e9 + 2.0, 1e9 + 4.0, 1e9 + 8.0];
        let cost = L2::new(&data).unwrap();
        // mean 1e9 + 3.75: deviations -2.75, -1.75, 0.25, 4.25
        assert!(
            (cost.cost(0, 4) - 28.75).abs() < 1e-6,
            "{}",
            cost.cost(0, 4)
        );
        assert!(cost.cost(1, 2).abs() < 1e-9);
    }

    #[test]
    fn normal_cost_and_floor() {
        let flat = NormalMeanVar::new(&[2.0; 10]).unwrap();
        assert!(flat.cost(0, 10).is_finite());
        let data = [0.0, 2.0, 0.0, 2.0];
        let cost = NormalMeanVar::new(&data).unwrap();
        assert!((cost.cost(0, 4) - 4.0 * 1f64.ln()).abs() < 1e-12);
    }

    #[test]
    fn poisson_cost_values() {
        let cost = Poisson::new(&[0.0, 0.0, 3.0, 3.0]).unwrap();
        assert_eq!(cost.cost(0, 2), 0.0);
        let want = 2.0 * (6.0 - 6.0 * 3f64.ln());
        assert!((cost.cost(2, 4) - want).abs() < 1e-12);
    }

    #[test]
    fn bad_inputs_are_errors() {
        assert_eq!(
            L2::new(&[f64::INFINITY]).unwrap_err(),
            Error::NonFinite { index: 0 }
        );
        assert!(matches!(
            L2::with_variance(&[1.0], 0.0),
            Err(Error::InvalidParameter {
                name: "variance",
                ..
            })
        ));
        assert_eq!(
            NormalMeanVar::new(&[0.0, f64::NAN]).unwrap_err(),
            Error::NonFinite { index: 1 }
        );
        assert_eq!(
            Poisson::new(&[f64::NAN]).unwrap_err(),
            Error::NonFinite { index: 0 }
        );
    }

    #[test]
    fn noise_variance_of_alternating_series() {
        // diffs are +-2; MAD of {-2, 2} around median 0 is 2.
        let v = noise_variance(&[1.0, -1.0, 1.0, -1.0, 1.0]).unwrap();
        let sigma = 2.0 / 0.674_489_750_196_081_7;
        assert!((v - sigma * sigma / 2.0).abs() < 1e-12);
        assert_eq!(noise_variance(&[1.0, 2.0]), None);
    }
}
