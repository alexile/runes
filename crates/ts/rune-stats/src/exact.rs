//! Exact null distributions of the rank statistics, counted in `i128`.

use crate::Error;
use crate::util::int;

/// Largest total sample size `m + n` for the exact Mann–Whitney
/// distribution. `C(128, 64) ≈ 2.4e37` still fits in `i128`.
pub const MAX_EXACT_MANN_WHITNEY: usize = 128;

/// Largest sample size for the exact signed-rank distribution (`2^120`
/// arrangements).
pub const MAX_EXACT_SIGNED_RANK: usize = 120;

/// A discrete null distribution on `0..=max`, stored as counts.
#[derive(Debug, Clone)]
pub struct Distribution {
    counts: Vec<i128>,
    total: i128,
}

impl Distribution {
    fn from_counts(counts: Vec<i128>) -> Result<Self, Error> {
        let mut total: i128 = 0;
        for &value in &counts {
            total = total.checked_add(value).ok_or(Error::TooLarge {
                limit: MAX_EXACT_MANN_WHITNEY,
            })?;
        }
        Ok(Self { counts, total })
    }

    /// Null distribution of the Mann–Whitney `U` for sample sizes `m` and
    /// `n` (no ties): the coefficients of the Gaussian binomial
    /// `[m+n choose m]_q = Π_{i=1}^{m} (1 − q^{n+i}) / (1 − q^i)`.
    pub fn mann_whitney(m: usize, n: usize) -> Result<Self, Error> {
        if m + n > MAX_EXACT_MANN_WHITNEY {
            return Err(Error::TooLarge {
                limit: MAX_EXACT_MANN_WHITNEY,
            });
        }
        let (m, n) = if m <= n { (m, n) } else { (n, m) };
        let max = m * n;
        let mut counts = vec![0i128; max + 1];
        counts[0] = 1;
        for i in 1..=m {
            // Multiply by (1 − q^{n+i}), truncated at degree m·n: terms
            // above it cancel in the exact quotient and never feed lower
            // ones.
            let shift = n + i;
            for k in (shift..=max).rev() {
                counts[k] -= counts[k - shift];
            }
            // Divide by (1 − q^i): a running sum with stride i.
            for k in i..=max {
                counts[k] += counts[k - i];
            }
        }
        Self::from_counts(counts)
    }

    /// Null distribution of the Wilcoxon signed-rank `W⁺` for `n` non-zero
    /// differences without ties: the coefficients of `Π_{i=1}^{n} (1 + q^i)`.
    pub fn signed_rank(n: usize) -> Result<Self, Error> {
        if n > MAX_EXACT_SIGNED_RANK {
            return Err(Error::TooLarge {
                limit: MAX_EXACT_SIGNED_RANK,
            });
        }
        let max = n * (n + 1) / 2;
        let mut counts = vec![0i128; max + 1];
        counts[0] = 1;
        let mut degree = 0;
        for i in 1..=n {
            degree += i;
            for k in (i..=degree).rev() {
                counts[k] += counts[k - i];
            }
        }
        Self::from_counts(counts)
    }

    /// `P(X ≤ k)`.
    pub fn cdf(&self, k: usize) -> f64 {
        let end = k.saturating_add(1).min(self.counts.len());
        let below: i128 = self.counts[..end].iter().sum();
        int(below) / int(self.total)
    }

    /// `P(X ≥ k)`.
    pub fn sf(&self, k: usize) -> f64 {
        let start = k.min(self.counts.len());
        let above: i128 = self.counts[start..].iter().sum();
        int(above) / int(self.total)
    }

    /// Smallest `k` with `P(X ≤ k) ≥ p` (R's `qwilcox` / `qsignrank`).
    pub fn quantile(&self, p: f64) -> usize {
        let target = p * int(self.total);
        let mut cumulative: i128 = 0;
        for (k, &value) in self.counts.iter().enumerate() {
            cumulative += value;
            if int(cumulative) >= target {
                return k;
            }
        }
        self.counts.len() - 1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mann_whitney_counts_small() {
        // m = 2, n = 2: U ∈ {0, 1, 2, 2, 3, 4} → counts 1,1,2,1,1.
        let dist = Distribution::mann_whitney(2, 2).unwrap();
        assert_eq!(dist.counts, [1, 1, 2, 1, 1]);
        assert_eq!(dist.total, 6);
        assert!((dist.cdf(1) - 2.0 / 6.0).abs() < 1e-15);
        assert!((dist.sf(3) - 2.0 / 6.0).abs() < 1e-15);
        assert_eq!(dist.quantile(0.3), 1);
    }

    #[test]
    fn mann_whitney_total_is_binomial() {
        let dist = Distribution::mann_whitney(64, 64).unwrap();
        // C(128, 64)
        assert_eq!(
            dist.total,
            23_951_146_041_928_082_866_135_587_776_380_551_750
        );
        assert!(dist.counts.iter().all(|&c| c >= 0));
        assert!(Distribution::mann_whitney(65, 64).is_err());
    }

    #[test]
    fn signed_rank_counts_small() {
        // n = 3: subsets of {1,2,3} by sum → 0,1,2,3,3,4,5,6.
        let dist = Distribution::signed_rank(3).unwrap();
        assert_eq!(dist.counts, [1, 1, 1, 2, 1, 1, 1]);
        assert_eq!(dist.total, 8);
        let big = Distribution::signed_rank(120).unwrap();
        assert_eq!(big.total, 1i128 << 120);
        assert!(Distribution::signed_rank(121).is_err());
    }
}
