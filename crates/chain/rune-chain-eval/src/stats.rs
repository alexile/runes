//! Small, deterministic statistics: a seeded RNG, percentiles and bootstrap
//! confidence intervals.

use serde::{Deserialize, Serialize};

/// Most bootstrap resamples allowed, to bound the work a config can ask for.
pub const MAX_BOOTSTRAP_RESAMPLES: usize = 100_000;

/// A seeded `SplitMix64` generator. Same seed, same sequence, on every
/// platform.
#[derive(Debug, Clone)]
pub struct SeededRng(u64);

impl SeededRng {
    /// A generator seeded with `seed`.
    #[must_use]
    pub const fn new(seed: u64) -> Self {
        Self(seed)
    }

    /// The next 64 random bits.
    pub const fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// A uniform integer in `0..n` (unbiased). `n == 0` returns 0.
    pub fn below(&mut self, n: usize) -> usize {
        if n <= 1 {
            return 0;
        }
        let n = n as u64;
        // Lemire's multiply-shift with rejection of the biased zone.
        let threshold = n.wrapping_neg() % n;
        loop {
            let m = u128::from(self.next_u64()) * u128::from(n);
            #[allow(clippy::cast_possible_truncation)]
            if (m as u64) >= threshold {
                #[allow(clippy::cast_possible_truncation)]
                return (m >> 64) as usize;
            }
        }
    }

    /// Shuffle `items` in place (Fisher-Yates).
    pub fn shuffle<T>(&mut self, items: &mut [T]) {
        for i in (1..items.len()).rev() {
            let j = self.below(i + 1);
            items.swap(i, j);
        }
    }
}

/// The arithmetic mean, or `None` for an empty slice.
#[must_use]
#[allow(clippy::cast_precision_loss)]
pub fn mean(values: &[f64]) -> Option<f64> {
    if values.is_empty() {
        None
    } else {
        Some(values.iter().sum::<f64>() / values.len() as f64)
    }
}

/// The `q` quantile (`0.0..=1.0`) of already **sorted** values, with linear
/// interpolation between closest ranks (`numpy.percentile`'s default).
/// `None` for an empty slice or a `q` outside `0..=1`.
///
/// ```rust
/// use rune_chain_eval::stats::percentile_sorted;
///
/// let v = [3.0, 5.0, 7.0, 9.0, 12.0, 14.0, 18.0, 22.0, 31.0, 45.0];
/// assert_eq!(percentile_sorted(&v, 0.5), Some(13.0));
/// assert!((percentile_sorted(&v, 0.95).unwrap() - 38.7).abs() < 1e-9);
/// ```
#[must_use]
#[allow(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]
pub fn percentile_sorted(sorted: &[f64], q: f64) -> Option<f64> {
    if sorted.is_empty() || !(0.0..=1.0).contains(&q) {
        return None;
    }
    let rank = (sorted.len() - 1) as f64 * q;
    let lo = rank.floor() as usize;
    let hi = (lo + 1).min(sorted.len() - 1);
    let frac = rank - lo as f64;
    Some((sorted[hi] - sorted[lo]).mul_add(frac, sorted[lo]))
}

/// A two-sided confidence interval for a mean.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct ConfidenceInterval {
    /// Lower bound.
    pub low: f64,
    /// Upper bound.
    pub high: f64,
    /// Confidence level, e.g. `0.95`.
    pub level: f64,
}

impl ConfidenceInterval {
    /// Whether the two intervals share any point.
    #[must_use]
    pub fn overlaps(&self, other: &Self) -> bool {
        self.low <= other.high && other.low <= self.high
    }
}

/// How bootstrap confidence intervals are computed.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct BootstrapConfig {
    /// Number of resamples (default 1000; capped at
    /// [`MAX_BOOTSTRAP_RESAMPLES`]; `0` turns intervals off).
    pub resamples: usize,
    /// Confidence level in `(0, 1)` (default `0.95`).
    pub level: f64,
    /// RNG seed (default `0`). The same seed gives the same interval.
    pub seed: u64,
}

impl Default for BootstrapConfig {
    fn default() -> Self {
        Self {
            resamples: 1000,
            level: 0.95,
            seed: 0,
        }
    }
}

/// A percentile-bootstrap confidence interval for the mean of `values`.
///
/// Returns `None` for an empty slice, zero resamples or a level outside
/// `(0, 1)`. Deterministic for a given [`BootstrapConfig::seed`].
///
/// ```rust
/// use rune_chain_eval::stats::{BootstrapConfig, bootstrap_mean_ci};
///
/// let scores = [1.0, 0.0, 1.0, 1.0, 0.0, 1.0, 1.0, 1.0];
/// let cfg = BootstrapConfig { resamples: 2000, level: 0.95, seed: 7 };
/// let a = bootstrap_mean_ci(&scores, &cfg).unwrap();
/// let b = bootstrap_mean_ci(&scores, &cfg).unwrap();
/// assert_eq!(a, b);
/// assert!(a.low <= 0.75 && 0.75 <= a.high);
/// ```
#[must_use]
#[allow(clippy::cast_precision_loss)]
pub fn bootstrap_mean_ci(values: &[f64], config: &BootstrapConfig) -> Option<ConfidenceInterval> {
    let resamples = config.resamples.min(MAX_BOOTSTRAP_RESAMPLES);
    if values.is_empty() || resamples == 0 || !(config.level > 0.0 && config.level < 1.0) {
        return None;
    }
    let n = values.len();
    let mut rng = SeededRng::new(config.seed);
    let mut means = Vec::with_capacity(resamples);
    for _ in 0..resamples {
        let mut sum = 0.0;
        for _ in 0..n {
            sum += values[rng.below(n)];
        }
        means.push(sum / n as f64);
    }
    means.sort_by(f64::total_cmp);
    let alpha = (1.0 - config.level) / 2.0;
    Some(ConfidenceInterval {
        low: percentile_sorted(&means, alpha)?,
        high: percentile_sorted(&means, 1.0 - alpha)?,
        level: config.level,
    })
}
