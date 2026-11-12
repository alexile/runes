//! Bayesian online change-point detection (Adams and `MacKay`, 2007) for a
//! Gaussian series with unknown mean and variance.

#![allow(
    clippy::cast_precision_loss,
    reason = "run lengths stay far below 2^52, so usize -> f64 is exact"
)]

use std::vec::Vec;

use crate::Error;

/// Run lengths whose posterior probability drops below this are discarded.
const PRUNE: f64 = 1e-12;

/// Normal-gamma prior on the mean and precision of each segment.
///
/// The defaults (`mean = 0`, `kappa = 1`, `alpha = 1`, `beta = 1`) suit
/// standardised data (roughly zero mean, unit variance); for raw data set
/// `mean` near the expected level and `beta` near the expected variance.
///
/// # Example
///
/// ```rust
/// use rune_changepoint::NormalGammaPrior;
///
/// let prior = NormalGammaPrior { mean: 100.0, beta: 25.0, ..NormalGammaPrior::default() };
/// assert_eq!(prior.kappa, 1.0);
/// ```
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct NormalGammaPrior {
    /// Prior mean.
    pub mean: f64,
    /// Pseudo-observations behind the prior mean (`> 0`).
    pub kappa: f64,
    /// Shape of the gamma prior on the precision (`> 0`).
    pub alpha: f64,
    /// Rate of the gamma prior on the precision (`> 0`).
    pub beta: f64,
}

impl Default for NormalGammaPrior {
    fn default() -> Self {
        Self {
            mean: 0.0,
            kappa: 1.0,
            alpha: 1.0,
            beta: 1.0,
        }
    }
}

/// Posterior statistics for one run length.
#[derive(Debug, Clone, Copy)]
struct Stats {
    mean: f64,
    kappa: f64,
    alpha: f64,
    beta: f64,
}

impl Stats {
    /// Log density of the Student-t posterior predictive at `x`.
    fn log_predictive(&self, x: f64) -> f64 {
        let nu = 2.0 * self.alpha;
        let scale2 = self.beta * (self.kappa + 1.0) / (self.alpha * self.kappa);
        let z = (x - self.mean) * (x - self.mean) / (nu * scale2);
        let log_norm = (nu * std::f64::consts::PI * scale2).ln();
        (-(self.alpha + 0.5)).mul_add(
            z.ln_1p(),
            (-0.5f64).mul_add(log_norm, ln_gamma(self.alpha + 0.5) - ln_gamma(self.alpha)),
        )
    }

    fn update(&self, x: f64) -> Self {
        let kappa = self.kappa + 1.0;
        let d = x - self.mean;
        Self {
            mean: self.mean + d / kappa,
            kappa,
            alpha: self.alpha + 0.5,
            beta: self.beta + self.kappa * d * d / (2.0 * kappa),
        }
    }
}

/// `ln Γ(x)` for `x > 0` (Lanczos, g = 7, about 15 significant digits).
fn ln_gamma(x: f64) -> f64 {
    const G: f64 = 7.0;
    const C: [f64; 9] = [
        0.999_999_999_999_809_9,
        676.520_368_121_885_1,
        -1_259.139_216_722_402_8,
        771.323_428_777_653_1,
        -176.615_029_162_140_6,
        12.507_343_278_686_905,
        -0.138_571_095_265_720_12,
        9.984_369_578_019_572e-6,
        1.505_632_735_149_311_6e-7,
    ];
    if x < 0.5 {
        // Recurrence keeps us in the accurate range for small shapes.
        return ln_gamma(x + 1.0) - x.ln();
    }
    let x = x - 1.0;
    let mut acc = C[0];
    for (i, c) in C.iter().enumerate().skip(1) {
        acc += c / (x + i as f64);
    }
    let t = x + G + 0.5;
    0.5f64.mul_add((2.0 * std::f64::consts::PI).ln(), (x + 0.5) * t.ln()) - t + acc.ln()
}

fn log_sum_exp(values: &[f64]) -> f64 {
    let max = values.iter().copied().fold(f64::NEG_INFINITY, f64::max);
    if max == f64::NEG_INFINITY {
        return max;
    }
    max + values.iter().map(|v| (v - max).exp()).sum::<f64>().ln()
}

/// Online Bayesian change-point detector with a constant hazard rate and a
/// normal-gamma prior (unknown mean and variance per segment).
///
/// Each [`Bocpd::update`] returns the most probable current run length (the
/// number of observations since the last change). A drop in that run length
/// signals a change; [`Bocpd::detect`] does this over a whole series. Run
/// lengths with negligible probability are pruned, so memory and time per
/// step stay bounded in practice.
///
/// Requires the `std` feature.
///
/// # Example
///
/// ```rust
/// use rune_changepoint::{Bocpd, NormalGammaPrior};
///
/// let mut data = vec![0.0; 60];
/// data.extend([5.0; 60]);
/// for (i, v) in data.iter_mut().enumerate() {
///     *v += [0.3, -0.4, 0.1, 0.2, -0.2][i % 5];
/// }
/// let cps = Bocpd::new(100.0, NormalGammaPrior::default()).unwrap().detect(&data).unwrap();
/// assert_eq!(cps, vec![60]);
/// ```
#[derive(Debug, Clone)]
pub struct Bocpd {
    log_hazard: f64,
    log_survive: f64,
    prior: NormalGammaPrior,
    log_probs: Vec<f64>,
    stats: Vec<Stats>,
    seen: usize,
}

impl Bocpd {
    /// A detector expecting a change every `expected_run_length`
    /// observations on average (hazard `1 / expected_run_length`).
    ///
    /// # Errors
    ///
    /// [`Error::InvalidParameter`] if `expected_run_length` is not finite and
    /// above 1, or a prior field is out of range.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_changepoint::{Bocpd, NormalGammaPrior};
    ///
    /// assert!(Bocpd::new(250.0, NormalGammaPrior::default()).is_ok());
    /// assert!(Bocpd::new(0.5, NormalGammaPrior::default()).is_err());
    /// ```
    pub fn new(expected_run_length: f64, prior: NormalGammaPrior) -> Result<Self, Error> {
        if !(expected_run_length.is_finite() && expected_run_length > 1.0) {
            return Err(Error::InvalidParameter {
                name: "expected_run_length",
                value: expected_run_length,
            });
        }
        let positive = [
            ("kappa", prior.kappa),
            ("alpha", prior.alpha),
            ("beta", prior.beta),
        ];
        for (name, value) in positive {
            if !(value.is_finite() && value > 0.0) {
                return Err(Error::InvalidParameter { name, value });
            }
        }
        if !prior.mean.is_finite() {
            return Err(Error::InvalidParameter {
                name: "mean",
                value: prior.mean,
            });
        }
        let hazard = 1.0 / expected_run_length;
        Ok(Self {
            log_hazard: hazard.ln(),
            log_survive: (-hazard).ln_1p(),
            prior,
            log_probs: Vec::new(),
            stats: Vec::new(),
            seen: 0,
        })
    }

    const fn prior_stats(&self) -> Stats {
        Stats {
            mean: self.prior.mean,
            kappa: self.prior.kappa,
            alpha: self.prior.alpha,
            beta: self.prior.beta,
        }
    }

    /// Feeds one observation and returns the most probable run length.
    ///
    /// # Errors
    ///
    /// [`Error::NonFinite`] (with the observation's position in the stream)
    /// for a `NaN` or infinite value; the detector state is unchanged.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_changepoint::{Bocpd, NormalGammaPrior};
    ///
    /// let mut det = Bocpd::new(50.0, NormalGammaPrior::default()).unwrap();
    /// assert_eq!(det.update(0.1).unwrap(), 1);
    /// assert_eq!(det.update(-0.1).unwrap(), 2);
    /// assert!(det.update(f64::NAN).is_err());
    /// ```
    pub fn update(&mut self, x: f64) -> Result<usize, Error> {
        if !x.is_finite() {
            return Err(Error::NonFinite { index: self.seen });
        }
        if self.log_probs.is_empty() {
            // Before any data the run length is 0 with certainty.
            self.log_probs.push(0.0);
            self.stats.push(self.prior_stats());
        }
        let pred: Vec<f64> = self
            .log_probs
            .iter()
            .zip(&self.stats)
            .map(|(lp, s)| lp + s.log_predictive(x))
            .collect();
        let change: Vec<f64> = pred.iter().map(|p| p + self.log_hazard).collect();
        let mut next = Vec::with_capacity(pred.len() + 1);
        next.push(log_sum_exp(&change));
        next.extend(pred.iter().map(|p| p + self.log_survive));
        let norm = log_sum_exp(&next);
        if norm.is_finite() {
            for v in &mut next {
                *v -= norm;
            }
        } else {
            // Every hypothesis underflowed (an extreme outlier): restart.
            next = vec![0.0];
        }

        let mut stats = Vec::with_capacity(next.len());
        stats.push(self.prior_stats());
        if next.len() > 1 {
            stats.extend(self.stats.iter().map(|s| s.update(x)));
        }
        let log_prune = PRUNE.ln();
        while next.len() > 1 && next.last().is_some_and(|v| *v < log_prune) {
            next.pop();
            stats.pop();
        }
        self.log_probs = next;
        self.stats = stats;
        self.seen += 1;
        Ok(self.map_run_length())
    }

    /// Most probable run length after the last update.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_changepoint::{Bocpd, NormalGammaPrior};
    ///
    /// let det = Bocpd::new(50.0, NormalGammaPrior::default()).unwrap();
    /// assert_eq!(det.map_run_length(), 0);
    /// ```
    #[must_use]
    pub fn map_run_length(&self) -> usize {
        self.log_probs
            .iter()
            .enumerate()
            .max_by(|a, b| a.1.total_cmp(b.1))
            .map_or(0, |(i, _)| i)
    }

    /// Posterior probability of each run length `0, 1, 2, ...` (pruned
    /// tail omitted).
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_changepoint::{Bocpd, NormalGammaPrior};
    ///
    /// let mut det = Bocpd::new(50.0, NormalGammaPrior::default()).unwrap();
    /// det.update(0.0).unwrap();
    /// let total: f64 = det.run_length_probabilities().iter().sum();
    /// assert!((total - 1.0).abs() < 1e-9);
    /// ```
    #[must_use]
    pub fn run_length_probabilities(&self) -> Vec<f64> {
        self.log_probs.iter().map(|v| v.exp()).collect()
    }

    /// Runs over a whole series and reports change points as the index of
    /// the first observation of each new segment, inferred whenever the most
    /// probable run length drops.
    ///
    /// # Errors
    ///
    /// [`Error::NonFinite`] for a `NaN` or infinite value.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_changepoint::{Bocpd, NormalGammaPrior};
    ///
    /// let flat = [0.1, -0.2, 0.0, 0.1, -0.1, 0.2, 0.0, -0.1];
    /// let mut det = Bocpd::new(100.0, NormalGammaPrior::default()).unwrap();
    /// assert!(det.detect(&flat).unwrap().is_empty());
    /// ```
    pub fn detect(&mut self, data: &[f64]) -> Result<Vec<usize>, Error> {
        if let Some(index) = data.iter().position(|v| !v.is_finite()) {
            return Err(Error::NonFinite { index });
        }
        let mut cps: Vec<usize> = Vec::new();
        let mut prev = self.map_run_length();
        for &x in data {
            let run = self.update(x)?;
            if run < prev {
                let start = self.seen - run;
                if start > 0 && cps.last().is_none_or(|last| start > *last) {
                    cps.push(start);
                } else if let Some(last) = cps.last_mut() {
                    // A revised estimate of the most recent change.
                    if start > 0 && start < *last {
                        *last = start;
                    }
                }
            }
            prev = run;
        }
        Ok(cps)
    }
}

#[cfg(test)]
#[allow(clippy::suboptimal_flops)]
mod tests {
    use super::*;

    #[test]
    fn ln_gamma_known_values() {
        assert!(ln_gamma(1.0).abs() < 1e-13);
        assert!(ln_gamma(2.0).abs() < 1e-13);
        assert!((ln_gamma(0.5) - std::f64::consts::PI.sqrt().ln()).abs() < 1e-13);
        assert!((ln_gamma(10.0) - 362_880f64.ln()).abs() < 1e-12);
        assert!((ln_gamma(0.1) - 2.252_712_651_734_206).abs() < 1e-12);
    }

    #[test]
    fn detects_mean_and_variance_shifts() {
        let mut data = Vec::new();
        for i in 0..300 {
            let noise = [0.5, -0.3, 0.8, -0.6, 0.1, -0.4, 0.2][i % 7];
            let v = match i {
                0..100 => noise,
                100..200 => 4.0 + noise,
                _ => 4.0 + 5.0 * noise,
            };
            data.push(v);
        }
        let mut det = Bocpd::new(100.0, NormalGammaPrior::default()).unwrap();
        let cps = det.detect(&data).unwrap();
        assert_eq!(cps.len(), 2, "{cps:?}");
        assert!(
            cps[0].abs_diff(100) <= 1 && cps[1].abs_diff(200) <= 3,
            "{cps:?}"
        );
    }

    #[test]
    fn rejects_bad_settings() {
        let p = NormalGammaPrior::default();
        assert!(Bocpd::new(f64::NAN, p).is_err());
        assert!(Bocpd::new(10.0, NormalGammaPrior { beta: 0.0, ..p }).is_err());
        assert!(
            Bocpd::new(
                10.0,
                NormalGammaPrior {
                    mean: f64::INFINITY,
                    ..p
                }
            )
            .is_err()
        );
        let mut det = Bocpd::new(10.0, p).unwrap();
        assert_eq!(
            det.detect(&[0.0, f64::NAN]).unwrap_err(),
            Error::NonFinite { index: 1 }
        );
    }

    #[test]
    fn extreme_outlier_does_not_break_state() {
        let mut det = Bocpd::new(10.0, NormalGammaPrior::default()).unwrap();
        for _ in 0..20 {
            det.update(0.0).unwrap();
        }
        det.update(1e300).unwrap();
        let total: f64 = det.run_length_probabilities().iter().sum();
        assert!((total - 1.0).abs() < 1e-9);
    }
}
