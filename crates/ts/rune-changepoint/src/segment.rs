//! Offline segmentation: PELT and binary segmentation.

#![allow(
    clippy::cast_precision_loss,
    reason = "series lengths stay far below 2^52, so usize -> f64 is exact"
)]

use alloc::vec;
use alloc::vec::Vec;

use crate::Error;
use crate::cost::Cost;
use crate::math::ln;

/// Penalty added for each change point.
///
/// With `p` = [`Cost::params_per_segment`] and `n` observations:
///
/// - `Bic`: `p * ln(n)`, the Schwarz/BIC penalty as defined in R's
///   `changepoint` package.
/// - `Mbic`: the modified BIC of Zhang & Siegmund (2007): `(p + 2) * ln(n)`
///   per change, plus `ln(len / n)` added to every segment's cost, which
///   discourages very short segments.
/// - `Manual(beta)`: a fixed penalty `beta >= 0`.
///
/// Both information criteria assume the cost is a proper `-2 log L`; for
/// [`L2`](crate::L2) that means the noise variance must be right.
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub enum Penalty {
    /// `p * ln(n)` per change point.
    #[default]
    Bic,
    /// `(p + 2) * ln(n)` per change point plus a segment-length term.
    Mbic,
    /// A fixed penalty per change point.
    Manual(f64),
}

impl Penalty {
    /// The per-change penalty for a cost over `n` observations.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_changepoint::{L2, Penalty};
    ///
    /// let cost = L2::new(&[0.0; 100]).unwrap();
    /// assert!((Penalty::Bic.value(&cost) - 100f64.ln()).abs() < 1e-12);
    /// assert!((Penalty::Mbic.value(&cost) - 3.0 * 100f64.ln()).abs() < 1e-12);
    /// assert_eq!(Penalty::Manual(5.0).value(&cost), 5.0);
    /// ```
    #[must_use]
    pub fn value<C: Cost + ?Sized>(&self, cost: &C) -> f64 {
        let n = cost.len().max(1) as f64;
        let p = cost.params_per_segment() as f64;
        match *self {
            Self::Bic => p * ln(n),
            Self::Mbic => (p + 2.0) * ln(n),
            Self::Manual(beta) => beta,
        }
    }

    fn validate(self) -> Result<(), Error> {
        match self {
            Self::Manual(value) if !(value.is_finite() && value >= 0.0) => {
                Err(Error::InvalidPenalty { value })
            }
            _ => Ok(()),
        }
    }
}

/// Segment cost including the MBIC length term when that penalty is used.
struct Scored<'a, C: Cost + ?Sized> {
    cost: &'a C,
    mbic: bool,
    n: f64,
}

impl<C: Cost + ?Sized> Scored<'_, C> {
    fn at(&self, start: usize, end: usize) -> f64 {
        let c = self.cost.cost(start, end);
        if self.mbic {
            c + ln((end - start) as f64 / self.n)
        } else {
            c
        }
    }
}

fn effective_min_size<C: Cost + ?Sized>(requested: usize, cost: &C) -> Result<usize, Error> {
    if requested == 0 {
        return Err(Error::InvalidMinSize { min_size: 0 });
    }
    Ok(requested.max(cost.min_size()).max(1))
}

/// Pruned Exact Linear Time search (Killick, Fearnhead & Eckley, 2012):
/// the segmentation that exactly minimises total cost plus penalty, usually
/// in close to linear time.
///
/// Change points are returned as the index of the first observation of each
/// new segment, in increasing order (ruptures-style breakpoints without the
/// final `n`).
///
/// # Example
///
/// ```rust
/// use rune_changepoint::{L2, Pelt, Penalty};
///
/// let mut data = vec![0.0; 50];
/// data.extend([4.0; 30]);
/// data.extend([-2.0; 40]);
/// for (i, v) in data.iter_mut().enumerate() {
///     *v += [0.3, -0.2, 0.1, -0.3, 0.2][i % 5];
/// }
/// let cost = L2::new(&data).unwrap();
/// let cps = Pelt::new().penalty(Penalty::Manual(10.0)).min_size(5).detect(&cost).unwrap();
/// assert_eq!(cps, vec![50, 80]);
/// ```
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Pelt {
    penalty: Penalty,
    min_size: usize,
}

impl Default for Pelt {
    fn default() -> Self {
        Self::new()
    }
}

impl Pelt {
    /// BIC penalty, minimum segment length 2 (or the cost's own minimum if
    /// larger).
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_changepoint::{L2, Pelt};
    ///
    /// let cost = L2::new(&[1.0; 20]).unwrap();
    /// assert_eq!(Pelt::new().detect(&cost).unwrap(), Vec::<usize>::new());
    /// ```
    #[must_use]
    pub const fn new() -> Self {
        Self {
            penalty: Penalty::Bic,
            min_size: 2,
        }
    }

    /// Sets the penalty.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_changepoint::{Pelt, Penalty};
    ///
    /// let pelt = Pelt::new().penalty(Penalty::Mbic);
    /// # let _ = pelt;
    /// ```
    #[must_use]
    pub const fn penalty(mut self, penalty: Penalty) -> Self {
        self.penalty = penalty;
        self
    }

    /// Sets the minimum segment length (at least 1).
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_changepoint::Pelt;
    ///
    /// let pelt = Pelt::new().min_size(10);
    /// # let _ = pelt;
    /// ```
    #[must_use]
    pub const fn min_size(mut self, min_size: usize) -> Self {
        self.min_size = min_size;
        self
    }

    /// Finds the optimal change points for `cost`.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidPenalty`] for a negative or non-finite manual
    /// penalty, [`Error::InvalidMinSize`] for a minimum segment length of 0.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_changepoint::{Error, L2, Pelt, Penalty};
    ///
    /// let cost = L2::new(&[0.0, 0.0, 9.0, 9.0]).unwrap();
    /// assert_eq!(Pelt::new().penalty(Penalty::Manual(1.0)).detect(&cost).unwrap(), vec![2]);
    /// assert!(matches!(
    ///     Pelt::new().penalty(Penalty::Manual(-1.0)).detect(&cost),
    ///     Err(Error::InvalidPenalty { .. })
    /// ));
    /// ```
    pub fn detect<C: Cost + ?Sized>(&self, cost: &C) -> Result<Vec<usize>, Error> {
        self.penalty.validate()?;
        let ms = effective_min_size(self.min_size, cost)?;
        let n = cost.len();
        if n < 2 * ms {
            return Ok(Vec::new());
        }
        let beta = self.penalty.value(cost);
        let scored = Scored {
            cost,
            mbic: self.penalty == Penalty::Mbic,
            n: n as f64,
        };

        let mut best = vec![f64::INFINITY; n + 1];
        let mut last = vec![0usize; n + 1];
        best[0] = -beta;
        // (tau, step from which tau may be dropped). Pruning at step t is only
        // safe once a segment t..T of at least `ms` points can follow, so
        // the removal is deferred by `ms` steps.
        let mut candidates: Vec<(usize, usize)> = Vec::new();
        let mut values: Vec<f64> = Vec::new();

        for t in ms..=n {
            let s = t - ms;
            if s == 0 || (s >= ms && best[s].is_finite()) {
                candidates.push((s, usize::MAX));
            }
            candidates.retain(|&(_, dead_from)| dead_from > t);
            values.clear();
            let mut min_val = f64::INFINITY;
            let mut arg = 0;
            for &(tau, _) in &candidates {
                let v = best[tau] + scored.at(tau, t);
                values.push(v);
                if v + beta < min_val {
                    min_val = v + beta;
                    arg = tau;
                }
            }
            best[t] = min_val;
            last[t] = arg;
            // tau can never be optimal again if it is already worse than the
            // optimum at t without paying for another change.
            for (candidate, v) in candidates.iter_mut().zip(&values) {
                if *v > min_val && candidate.1 == usize::MAX {
                    candidate.1 = t + ms;
                }
            }
        }

        let mut cps = Vec::new();
        let mut t = n;
        while t > 0 {
            let tau = last[t];
            if tau > 0 {
                cps.push(tau);
            }
            t = tau;
        }
        cps.reverse();
        Ok(cps)
    }
}

/// Binary segmentation.
///
/// Repeatedly splits the segment whose best single split reduces the cost most, while that reduction exceeds the penalty
/// (and, optionally, until a maximum number of change points). Faster than
/// PELT for long series but greedy, so not guaranteed optimal.
///
/// # Example
///
/// ```rust
/// use rune_changepoint::{BinSeg, L2, Penalty};
///
/// let mut data = vec![0.0; 40];
/// data.extend([5.0; 40]);
/// data.extend([1.0; 40]);
/// let cost = L2::new(&data).unwrap();
/// let cps = BinSeg::new().penalty(Penalty::Manual(5.0)).detect(&cost).unwrap();
/// assert_eq!(cps, vec![40, 80]);
/// let one = BinSeg::new().max_changes(1).detect(&cost).unwrap();
/// assert_eq!(one, vec![40]);
/// ```
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct BinSeg {
    penalty: Penalty,
    min_size: usize,
    max_changes: Option<usize>,
}

impl Default for BinSeg {
    fn default() -> Self {
        Self::new()
    }
}

impl BinSeg {
    /// BIC penalty, minimum segment length 2, no cap on change points.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_changepoint::{BinSeg, L2};
    ///
    /// let cost = L2::new(&[1.0; 20]).unwrap();
    /// assert_eq!(BinSeg::new().detect(&cost).unwrap(), Vec::<usize>::new());
    /// ```
    #[must_use]
    pub const fn new() -> Self {
        Self {
            penalty: Penalty::Bic,
            min_size: 2,
            max_changes: None,
        }
    }

    /// Sets the penalty.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_changepoint::{BinSeg, Penalty};
    ///
    /// let binseg = BinSeg::new().penalty(Penalty::Manual(3.0));
    /// # let _ = binseg;
    /// ```
    #[must_use]
    pub const fn penalty(mut self, penalty: Penalty) -> Self {
        self.penalty = penalty;
        self
    }

    /// Sets the minimum segment length (at least 1).
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_changepoint::BinSeg;
    ///
    /// let binseg = BinSeg::new().min_size(5);
    /// # let _ = binseg;
    /// ```
    #[must_use]
    pub const fn min_size(mut self, min_size: usize) -> Self {
        self.min_size = min_size;
        self
    }

    /// Stops after this many change points. Combine with
    /// `Penalty::Manual(0.0)` to get exactly `k` (when the series allows).
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_changepoint::{BinSeg, L2, Penalty};
    ///
    /// let data = [0.0, 0.0, 3.0, 3.0, 7.0, 7.0];
    /// let cost = L2::new(&data).unwrap();
    /// let cps = BinSeg::new().penalty(Penalty::Manual(0.0)).max_changes(2).detect(&cost).unwrap();
    /// assert_eq!(cps, vec![2, 4]);
    /// ```
    #[must_use]
    pub const fn max_changes(mut self, k: usize) -> Self {
        self.max_changes = Some(k);
        self
    }

    /// Finds change points for `cost`.
    ///
    /// # Errors
    ///
    /// As for [`Pelt::detect`].
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_changepoint::{BinSeg, Error, L2};
    ///
    /// let cost = L2::new(&[0.0; 10]).unwrap();
    /// assert_eq!(
    ///     BinSeg::new().min_size(0).detect(&cost).unwrap_err(),
    ///     Error::InvalidMinSize { min_size: 0 }
    /// );
    /// ```
    pub fn detect<C: Cost + ?Sized>(&self, cost: &C) -> Result<Vec<usize>, Error> {
        self.penalty.validate()?;
        let ms = effective_min_size(self.min_size, cost)?;
        let n = cost.len();
        let beta = self.penalty.value(cost);
        let scored = Scored {
            cost,
            mbic: self.penalty == Penalty::Mbic,
            n: n.max(1) as f64,
        };
        let best_split = |start: usize, end: usize| -> Option<(usize, f64)> {
            if end - start < 2 * ms {
                return None;
            }
            let whole = scored.at(start, end);
            let mut best: Option<(usize, f64)> = None;
            for tau in start + ms..=end - ms {
                let gain = whole - scored.at(start, tau) - scored.at(tau, end);
                if best.is_none_or(|(_, g)| gain > g) {
                    best = Some((tau, gain));
                }
            }
            best
        };

        let mut cps = Vec::new();
        // (start, end, best split) for every current segment.
        let mut segments = vec![(0, n, best_split(0, n))];
        loop {
            if self.max_changes.is_some_and(|k| cps.len() >= k) {
                break;
            }
            let pick = segments
                .iter()
                .enumerate()
                .filter_map(|(i, s)| s.2.map(|(tau, gain)| (i, tau, gain)))
                .max_by(|a, b| a.2.total_cmp(&b.2));
            let Some((i, tau, gain)) = pick else { break };
            if gain <= beta {
                break;
            }
            let (start, end, _) = segments.swap_remove(i);
            segments.push((start, tau, best_split(start, tau)));
            segments.push((tau, end, best_split(tau, end)));
            cps.push(tau);
        }
        cps.sort_unstable();
        Ok(cps)
    }
}

#[cfg(test)]
#[allow(clippy::suboptimal_flops)]
mod tests {
    use super::*;
    use crate::cost::{L2, NormalMeanVar, Poisson};
    use proptest::prelude::*;

    /// Deterministic pseudo-noise in roughly [-0.5, 0.5].
    fn noise(i: usize, seed: u64) -> f64 {
        let mut z = (i as u64)
            .wrapping_add(seed)
            .wrapping_mul(0x9e37_79b9_7f4a_7c15);
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z ^= z >> 31;
        (z >> 11) as f64 / (1u64 << 53) as f64 - 0.5
    }

    fn steps(levels: &[(usize, f64)], scale: f64, seed: u64) -> Vec<f64> {
        let mut out = Vec::new();
        for &(len, level) in levels {
            for _ in 0..len {
                let i = out.len();
                out.push(level + scale * noise(i, seed));
            }
        }
        out
    }

    fn within_one(got: &[usize], want: &[usize]) -> bool {
        got.len() == want.len() && got.iter().zip(want).all(|(g, w)| g.abs_diff(*w) <= 1)
    }

    /// Brute-force optimal segmentation for small inputs.
    fn brute_force<C: Cost>(cost: &C, beta: f64, ms: usize) -> f64 {
        let n = cost.len();
        let mut best = vec![f64::INFINITY; n + 1];
        best[0] = -beta;
        for t in ms..=n {
            for s in 0..=t - ms {
                if s != 0 && s < ms {
                    continue;
                }
                best[t] = best[t].min(best[s] + cost.cost(s, t) + beta);
            }
        }
        best[n]
    }

    fn total<C: Cost>(cost: &C, cps: &[usize], beta: f64) -> f64 {
        let mut bounds = vec![0];
        bounds.extend_from_slice(cps);
        bounds.push(cost.len());
        bounds
            .windows(2)
            .map(|w| cost.cost(w[0], w[1]))
            .sum::<f64>()
            + beta * cps.len() as f64
    }

    #[test]
    fn pelt_mean_shift_bic() {
        let data = steps(&[(100, 0.0), (80, 3.0), (120, -1.0)], 1.0, 1);
        let cost = L2::with_estimated_variance(&data).unwrap();
        let cps = Pelt::new().detect(&cost).unwrap();
        assert!(within_one(&cps, &[100, 180]), "{cps:?}");
        let cps = Pelt::new().penalty(Penalty::Mbic).detect(&cost).unwrap();
        assert!(within_one(&cps, &[100, 180]), "{cps:?}");
    }

    #[test]
    fn binseg_mean_shift_bic() {
        let data = steps(&[(100, 0.0), (80, 3.0), (120, -1.0)], 1.0, 2);
        let cost = L2::with_estimated_variance(&data).unwrap();
        let cps = BinSeg::new().detect(&cost).unwrap();
        assert!(within_one(&cps, &[100, 180]), "{cps:?}");
    }

    #[test]
    fn normal_detects_variance_change() {
        let mut data = steps(&[(150, 0.0)], 0.4, 3);
        data.extend(steps(&[(150, 0.0)], 4.0, 4));
        let cost = NormalMeanVar::new(&data).unwrap();
        let cps = Pelt::new().penalty(Penalty::Mbic).detect(&cost).unwrap();
        assert_eq!(cps.len(), 1, "{cps:?}");
        assert!(cps[0].abs_diff(150) <= 3, "{cps:?}");
    }

    #[test]
    fn poisson_rate_changes() {
        // Deterministic counts with rates 2, 12, 5.
        let rates = [(60, 2.0), (60, 12.0), (60, 5.0)];
        let data: Vec<f64> = steps(&rates, 0.0, 0)
            .iter()
            .enumerate()
            .map(|(i, r)| (r + 2.0 * r.sqrt() * noise(i, 9)).round().max(0.0))
            .collect();
        let cost = Poisson::new(&data).unwrap();
        for cps in [
            Pelt::new().detect(&cost).unwrap(),
            BinSeg::new().detect(&cost).unwrap(),
        ] {
            assert!(within_one(&cps, &[60, 120]), "{cps:?}");
        }
    }

    #[test]
    fn exact_on_noiseless_steps() {
        let data = steps(&[(7, 1.0), (5, 4.0), (9, 2.0)], 0.0, 0);
        let cost = L2::new(&data).unwrap();
        assert_eq!(Pelt::new().detect(&cost).unwrap(), vec![7, 12]);
        assert_eq!(BinSeg::new().detect(&cost).unwrap(), vec![7, 12]);
    }

    #[test]
    fn min_size_is_respected() {
        let data = [0.0, 0.0, 0.0, 0.0, 9.0, 0.0, 0.0, 0.0, 0.0];
        let cost = L2::new(&data).unwrap();
        let with_spike = Pelt::new()
            .min_size(1)
            .penalty(Penalty::Manual(1.0))
            .detect(&cost)
            .unwrap();
        assert_eq!(with_spike, vec![4, 5]);
        let cps = Pelt::new()
            .min_size(3)
            .penalty(Penalty::Manual(1.0))
            .detect(&cost)
            .unwrap();
        let mut bounds = vec![0];
        bounds.extend(&cps);
        bounds.push(data.len());
        assert!(bounds.windows(2).all(|w| w[1] - w[0] >= 3), "{cps:?}");
        let cps = BinSeg::new()
            .min_size(3)
            .penalty(Penalty::Manual(1.0))
            .detect(&cost)
            .unwrap();
        let mut bounds = vec![0];
        bounds.extend(&cps);
        bounds.push(data.len());
        assert!(bounds.windows(2).all(|w| w[1] - w[0] >= 3), "{cps:?}");
    }

    #[test]
    fn short_and_empty_series() {
        let empty = L2::new(&[]).unwrap();
        assert_eq!(Pelt::new().detect(&empty).unwrap(), Vec::<usize>::new());
        assert_eq!(BinSeg::new().detect(&empty).unwrap(), Vec::<usize>::new());
        let three = NormalMeanVar::new(&[1.0, 5.0, 9.0]).unwrap();
        assert_eq!(Pelt::new().detect(&three).unwrap(), Vec::<usize>::new());
    }

    #[test]
    fn invalid_settings() {
        let cost = L2::new(&[1.0, 2.0, 3.0]).unwrap();
        for bad in [f64::NAN, -0.5, f64::INFINITY] {
            assert!(matches!(
                Pelt::new().penalty(Penalty::Manual(bad)).detect(&cost),
                Err(Error::InvalidPenalty { .. })
            ));
            assert!(matches!(
                BinSeg::new().penalty(Penalty::Manual(bad)).detect(&cost),
                Err(Error::InvalidPenalty { .. })
            ));
        }
        assert_eq!(
            Pelt::new().min_size(0).detect(&cost).unwrap_err(),
            Error::InvalidMinSize { min_size: 0 }
        );
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]

        /// PELT's pruning never loses the optimum: its total matches an
        /// exhaustive dynamic programme.
        #[test]
        fn pelt_is_optimal(
            data in prop::collection::vec(-5.0f64..5.0, 1..40),
            beta in 0.0f64..10.0,
            ms in 1usize..4,
        ) {
            let cost = L2::new(&data).unwrap();
            let cps = Pelt::new().penalty(Penalty::Manual(beta)).min_size(ms).detect(&cost).unwrap();
            if data.len() >= 2 * ms {
                let want = brute_force(&cost, beta, ms);
                let got = total(&cost, &cps, beta);
                prop_assert!((got - want).abs() <= 1e-7 * (1.0 + want.abs()), "{got} vs {want}");
            }
            prop_assert!(cps.windows(2).all(|w| w[0] < w[1]));
        }

        /// Binary segmentation never does better than the optimum and only
        /// returns valid, sorted indices.
        #[test]
        fn binseg_is_valid(
            data in prop::collection::vec(0.0f64..20.0, 1..60),
            beta in 0.0f64..10.0,
        ) {
            let cost = Poisson::new(&data).unwrap();
            let cps = BinSeg::new().penalty(Penalty::Manual(beta)).detect(&cost).unwrap();
            prop_assert!(cps.windows(2).all(|w| w[0] < w[1]));
            prop_assert!(cps.iter().all(|c| *c > 0 && *c < data.len()));
            let opt = Pelt::new().penalty(Penalty::Manual(beta)).detect(&cost).unwrap();
            prop_assert!(total(&cost, &opt, beta) <= total(&cost, &cps, beta) + 1e-7);
        }
    }
}
