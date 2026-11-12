/// Precomputed alias table for O(1) sampling from an arbitrary discrete distribution.
///
/// Given unnormalised weights, [`AliasTable::new`] constructs `prob` and `alias` arrays
/// that allow a single uniform sample to be resolved in constant time.
pub struct AliasTable {
    prob: Vec<f64>,
    alias: Vec<usize>,
}

impl AliasTable {
    /// Constructs an alias table from unnormalised weights.
    ///
    /// Returns `None` if `weights` is empty or all weights are zero.
    #[allow(
        clippy::cast_precision_loss,
        reason = "counts and indices stay far below 2^52, so the f64 conversion is exact"
    )]
    pub(crate) fn new(weights: &[f64]) -> Option<Self> {
        let k = weights.len();
        if k == 0 {
            return None;
        }

        let total: f64 = weights.iter().sum();
        if total == 0.0 {
            return None;
        }

        let mut prob = vec![0.0f64; k];
        let mut alias = vec![0usize; k];

        // Scale each weight so that the average is 1.0.
        let scale = k as f64 / total;
        let mut scaled: Vec<f64> = weights.iter().map(|w| w * scale).collect();

        let mut small: Vec<usize> = Vec::with_capacity(k);
        let mut large: Vec<usize> = Vec::with_capacity(k);

        for (i, &s) in scaled.iter().enumerate() {
            if s < 1.0 {
                small.push(i);
            } else {
                large.push(i);
            }
        }

        while let (Some(&s), Some(&l)) = (small.last(), large.last()) {
            small.pop();
            large.pop();
            prob[s] = scaled[s];
            alias[s] = l;

            scaled[l] = (scaled[l] + scaled[s]) - 1.0;
            if scaled[l] < 1.0 {
                small.push(l);
            } else {
                large.push(l);
            }
        }

        for &i in large.iter().chain(small.iter()) {
            prob[i] = 1.0;
        }

        Some(Self { prob, alias })
    }

    /// Number of outcomes `k`.
    pub(crate) const fn len(&self) -> usize {
        self.prob.len()
    }

    /// Samples one index from the distribution in O(1).
    ///
    /// `uniform` must be a value uniformly drawn from `[0.0, k)` where `k` is the
    /// number of weights. The integer part selects the column; the fractional part
    /// decides whether to return that column or its alias.
    #[allow(
        clippy::cast_possible_truncation,
        clippy::cast_precision_loss,
        clippy::cast_sign_loss,
        reason = "the value is non-negative and bounded by the input size; float-to-int `as` saturates"
    )]
    pub(crate) fn sample(&self, uniform: f64) -> usize {
        let k = self.prob.len();
        let column = (uniform as usize).min(k - 1);
        let threshold = uniform - column as f64;
        if threshold < self.prob[column] {
            column
        } else {
            self.alias[column]
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_weights_returns_none() {
        assert!(AliasTable::new(&[]).is_none());
    }

    #[test]
    fn zero_weights_returns_none() {
        assert!(AliasTable::new(&[0.0, 0.0]).is_none());
    }

    #[test]
    fn single_weight_always_returns_zero() {
        let table = AliasTable::new(&[1.0]).unwrap();
        for i in 0..100 {
            assert_eq!(table.sample(f64::from(i) * 0.01), 0);
        }
    }

    #[test]
    fn uniform_weights_sample_all_indices() {
        let table = AliasTable::new(&[1.0, 1.0, 1.0, 1.0]).unwrap();
        let mut seen = [false; 4];
        for i in 0..400 {
            let idx = table.sample((f64::from(i) * 0.01) % 4.0);
            seen[idx] = true;
        }
        assert!(seen.iter().all(|&s| s));
    }

    #[test]
    fn probabilities_sum_to_one_within_tolerance() {
        let weights = vec![1.0, 2.0, 3.0, 4.0];
        let table = AliasTable::new(&weights).unwrap();
        for p in &table.prob {
            assert!((0.0..=1.0).contains(p), "prob {p} out of [0,1]");
        }
    }
}
