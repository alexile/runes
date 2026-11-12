//! A simplified, t-digest-style streaming quantile estimator.
//!
//! Feeding millions of values into a `Vec<f64>` just to compute a median is wasteful.
//! `TDigest` accepts values one at a time and periodically compresses its internal
//! centroids so memory stays bounded — roughly proportional to `compression`, not to
//! the number of values seen — while still answering quantile queries.
//!
//! # Features
//!
//! - [`TDigest::add`] / [`TDigest::add_weighted`] — feed values in, one at a time.
//! - [`TDigest::quantile`] — estimate any quantile in `0.0..=1.0`; `0.0` and `1.0`
//!   are tracked exactly rather than through the compressed centroids.
//! - [`TDigest::centroid_count`] — the compressed centroid count, to observe that
//!   compression is actually bounding memory as more values are added.
//!
//! Compression here uses equal-weight bucketing (roughly `compression` buckets of
//! near-equal total weight, merged by weighted mean) rather than the original
//! t-digest paper's density-aware scale function — simpler to implement correctly,
//! with the same bounded-memory streaming-merge property.
//!
//! # Quick Start
//!
//! ```rust
//! use rune_tdigest::TDigest;
//!
//! let mut digest = TDigest::new(100.0);
//! for i in 0..=1000 {
//!     digest.add(i as f64);
//! }
//! let median = digest.quantile(0.5);
//! assert!((median - 500.0).abs() < 20.0);
//! ```
//!
//! # CLI
//!
//! ```bash
//! rune-tdigest --values "1,2,3,4,5,6,7,8,9,10" --quantile 0.5
//! ```

#[derive(Clone, Copy, Debug)]
struct Centroid {
    mean: f64,
    weight: f64,
}

/// A streaming quantile estimator with bounded memory.
pub struct TDigest {
    compression: f64,
    centroids: Vec<Centroid>,
    count: usize,
    unmerged: usize,
    min: f64,
    max: f64,
}

impl TDigest {
    /// Creates a new digest. `compression` controls the target centroid count after
    /// each compression pass — higher values mean more accuracy at the cost of more
    /// memory. `100.0` is a reasonable default.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_tdigest::TDigest;
    ///
    /// let digest = TDigest::new(100.0);
    /// assert_eq!(digest.count(), 0);
    /// ```
    #[must_use]
    pub const fn new(compression: f64) -> Self {
        Self {
            compression: compression.max(1.0),
            centroids: Vec::new(),
            count: 0,
            unmerged: 0,
            min: f64::INFINITY,
            max: f64::NEG_INFINITY,
        }
    }

    /// Adds a single value with unit weight.
    pub fn add(&mut self, x: f64) {
        self.add_weighted(x, 1.0);
    }

    /// Adds a value with an explicit weight (e.g. a pre-aggregated count).
    ///
    /// Non-finite values (`NaN`, `±inf`) and weights that are not finite and
    /// strictly positive are ignored: they would otherwise corrupt every
    /// centroid they are merged into. Ignored calls do not change [`count`](TDigest::count).
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_tdigest::TDigest;
    ///
    /// let mut digest = TDigest::new(50.0);
    /// digest.add_weighted(10.0, 3.0);
    /// assert_eq!(digest.count(), 1);
    /// ```
    #[allow(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        reason = "the value is non-negative and bounded by the input size; float-to-int `as` saturates"
    )]
    pub fn add_weighted(&mut self, x: f64, weight: f64) {
        if !x.is_finite() || !weight.is_finite() || weight <= 0.0 {
            return;
        }
        self.centroids.push(Centroid { mean: x, weight });
        self.count += 1;
        self.unmerged += 1;
        self.min = self.min.min(x);
        self.max = self.max.max(x);

        let threshold = ((self.compression * 4.0).ceil() as usize).max(40);
        if self.unmerged >= threshold {
            self.compress();
        }
    }

    /// Total number of values added (counts, not weight — a weighted add still counts as one).
    #[must_use]
    pub const fn count(&self) -> usize {
        self.count
    }

    /// Current number of internal centroids, i.e. the compressed representation size.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_tdigest::TDigest;
    ///
    /// let mut digest = TDigest::new(50.0);
    /// for i in 0..10_000 {
    ///     digest.add(i as f64);
    /// }
    /// assert!(digest.centroid_count() < 1000, "compression should bound centroid growth");
    /// ```
    #[must_use]
    pub const fn centroid_count(&self) -> usize {
        self.centroids.len()
    }

    fn compress(&mut self) {
        if self.centroids.is_empty() {
            self.unmerged = 0;
            return;
        }
        self.centroids.sort_by(|a, b| a.mean.total_cmp(&b.mean));

        let total_weight: f64 = self.centroids.iter().map(|c| c.weight).sum();
        let target_bucket_weight = (total_weight / self.compression).max(f64::MIN_POSITIVE);

        let mut merged = Vec::new();
        let mut acc_mean = 0.0;
        let mut acc_weight = 0.0;

        for c in self.centroids.drain(..) {
            if acc_weight > 0.0 && acc_weight + c.weight > target_bucket_weight {
                merged.push(Centroid {
                    mean: acc_mean / acc_weight,
                    weight: acc_weight,
                });
                acc_mean = 0.0;
                acc_weight = 0.0;
            }
            acc_mean = f64::mul_add(c.mean, c.weight, acc_mean);
            acc_weight += c.weight;
        }
        if acc_weight > 0.0 {
            merged.push(Centroid {
                mean: acc_mean / acc_weight,
                weight: acc_weight,
            });
        }

        self.centroids = merged;
        self.unmerged = 0;
    }

    /// Estimates the value at quantile `q` (clamped to `0.0..=1.0`).
    ///
    /// Returns `f64::NAN` if no values have been added or `q` is `NaN`.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_tdigest::TDigest;
    ///
    /// let mut digest = TDigest::new(100.0);
    /// for i in 1..=1000 {
    ///     digest.add(i as f64);
    /// }
    /// assert!((digest.quantile(0.5) - 500.5).abs() < 20.0);
    /// assert_eq!(digest.quantile(0.0), 1.0);
    /// assert_eq!(digest.quantile(1.0), 1000.0);
    /// ```
    #[allow(clippy::float_cmp, reason = "exact comparison is intended here")]
    #[must_use]
    pub fn quantile(&self, q: f64) -> f64 {
        if self.centroids.is_empty() || q.is_nan() {
            return f64::NAN;
        }
        let q = q.clamp(0.0, 1.0);

        // The exact min/max are tracked separately (as most t-digest implementations
        // do) so the extreme quantiles stay exact even though interior centroids are
        // compressed and their means can drift away from any single observed value.
        if q == 0.0 {
            return self.min;
        }
        if q == 1.0 {
            return self.max;
        }

        let mut sorted = self.centroids.clone();
        sorted.sort_by(|a, b| a.mean.total_cmp(&b.mean));

        let total_weight: f64 = sorted.iter().map(|c| c.weight).sum();
        let target = q * total_weight;

        let mut cumulative = 0.0;
        for i in 0..sorted.len() {
            let c = sorted[i];
            let next_cumulative = cumulative + c.weight;
            if target <= next_cumulative {
                if i == 0 || i == sorted.len() - 1 {
                    return c.mean;
                }
                let prev = sorted[i - 1];
                let frac = if c.weight > 0.0 {
                    (target - cumulative) / c.weight
                } else {
                    0.0
                };
                return f64::mul_add(frac, c.mean - prev.mean, prev.mean);
            }
            cumulative = next_cumulative;
        }
        sorted.last().map_or(self.max, |c| c.mean)
    }
}

#[cfg(test)]
#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss,
    reason = "test helpers convert small, non-negative counts and ranks"
)]
mod tests {
    use super::*;

    #[test]
    fn empty_digest_quantile_is_nan() {
        let digest = TDigest::new(100.0);
        assert!(digest.quantile(0.5).is_nan());
    }

    #[test]
    fn median_of_uniform_range() {
        let mut digest = TDigest::new(100.0);
        for i in 0..=1000 {
            digest.add(f64::from(i));
        }
        let median = digest.quantile(0.5);
        assert!((median - 500.0).abs() < 20.0, "median was {median}");
    }

    #[test]
    fn min_and_max_quantiles() {
        let mut digest = TDigest::new(100.0);
        for i in 1..=1000 {
            digest.add(f64::from(i));
        }
        assert_eq!(digest.quantile(0.0), 1.0);
        assert_eq!(digest.quantile(1.0), 1000.0);
    }

    #[test]
    fn centroid_count_stays_bounded_for_large_n() {
        let mut digest = TDigest::new(100.0);
        for i in 0..10_000 {
            digest.add(f64::from(i));
        }
        assert!(
            digest.centroid_count() < 2_000,
            "centroid_count={} should be well below n=10000",
            digest.centroid_count()
        );
        assert_eq!(digest.count(), 10_000);
    }

    #[test]
    fn accuracy_on_sorted_1_to_1000() {
        let mut digest = TDigest::new(200.0);
        for i in 1..=1000 {
            digest.add(f64::from(i));
        }
        let median = digest.quantile(0.5);
        assert!((median - 500.5).abs() < 15.0, "median was {median}");
    }

    #[test]
    fn weighted_add_counts_as_one_value() {
        let mut digest = TDigest::new(50.0);
        digest.add_weighted(10.0, 5.0);
        digest.add_weighted(20.0, 5.0);
        assert_eq!(digest.count(), 2);
    }

    #[test]
    fn quantile_clamps_out_of_range_input() {
        let mut digest = TDigest::new(50.0);
        for i in 0..100 {
            digest.add(f64::from(i));
        }
        assert_eq!(digest.quantile(-1.0), digest.quantile(0.0));
        assert_eq!(digest.quantile(2.0), digest.quantile(1.0));
    }

    /// Exact nearest-rank-style quantile of a sorted slice, used as the reference.
    fn exact_quantile(sorted: &[f64], q: f64) -> f64 {
        let idx = (q * (sorted.len() - 1) as f64).round() as usize;
        sorted[idx]
    }

    /// Deterministic xorshift64* stream in `[0, 1)`, so the test needs no RNG crate.
    fn uniform_stream(mut state: u64, n: usize) -> Vec<f64> {
        (0..n)
            .map(|_| {
                state ^= state >> 12;
                state ^= state << 25;
                state ^= state >> 27;
                (state.wrapping_mul(0x2545_F491_4F6C_DD1D) >> 11) as f64 / (1u64 << 53) as f64
            })
            .collect()
    }

    #[test]
    fn uncompressed_small_input_is_exact_at_ranks() {
        // Below the compression threshold every value is its own centroid, so
        // q = k/n lands exactly on the k-th smallest value.
        let mut digest = TDigest::new(100.0);
        for x in [5.0, 1.0, 4.0, 2.0, 3.0] {
            digest.add(x);
        }
        assert_eq!(digest.quantile(0.2), 1.0);
        assert_eq!(digest.quantile(0.4), 2.0);
        assert_eq!(digest.quantile(0.6), 3.0);
        assert_eq!(digest.quantile(0.8), 4.0);
    }

    #[test]
    fn accuracy_against_exact_quantiles_on_shuffled_uniform() {
        let data = uniform_stream(0x9E37_79B9_7F4A_7C15, 50_000);
        let mut digest = TDigest::new(100.0);
        for &x in &data {
            digest.add(x);
        }
        let mut sorted = data;
        sorted.sort_by(f64::total_cmp);
        for q in [0.01, 0.1, 0.25, 0.5, 0.75, 0.9, 0.99] {
            let got = digest.quantile(q);
            let want = exact_quantile(&sorted, q);
            assert!((got - want).abs() < 0.02, "q={q}: got {got}, exact {want}");
        }
    }

    #[test]
    fn quantile_is_monotone_and_bounded() {
        let data = uniform_stream(42, 5_000);
        let mut digest = TDigest::new(50.0);
        for &x in &data {
            digest.add(x.mul_add(100.0, -50.0));
        }
        let mut prev = f64::NEG_INFINITY;
        for i in 0..=1000 {
            let v = digest.quantile(f64::from(i) / 1000.0);
            assert!(
                v >= prev,
                "quantile decreased at q={}",
                f64::from(i) / 1000.0
            );
            assert!((digest.quantile(0.0)..=digest.quantile(1.0)).contains(&v));
            prev = v;
        }
    }

    #[test]
    fn constant_input_is_exact_everywhere() {
        let mut digest = TDigest::new(20.0);
        for _ in 0..10_000 {
            digest.add(3.5);
        }
        for q in [0.0, 0.1, 0.5, 0.9, 1.0] {
            assert_eq!(digest.quantile(q), 3.5);
        }
    }

    #[test]
    fn weights_shift_the_median() {
        let mut digest = TDigest::new(100.0);
        digest.add_weighted(1.0, 1.0);
        digest.add_weighted(10.0, 9.0);
        assert_eq!(digest.quantile(0.5), 10.0);
    }

    /// Regression: `NaN` used to sort to the end and poison the last centroid,
    /// and non-positive weights corrupted the cumulative weight walk.
    #[test]
    fn invalid_values_and_weights_are_ignored() {
        let mut digest = TDigest::new(10.0);
        for i in 0..1000 {
            digest.add(f64::from(i));
            digest.add(f64::NAN);
            digest.add(f64::INFINITY);
            digest.add_weighted(f64::from(i), -1.0);
            digest.add_weighted(f64::from(i), 0.0);
            digest.add_weighted(f64::from(i), f64::NAN);
        }
        assert_eq!(digest.count(), 1000);
        assert_eq!(digest.quantile(1.0), 999.0);
        let median = digest.quantile(0.5);
        assert!((median - 499.5).abs() < 60.0, "median was {median}");
        let p99 = digest.quantile(0.99);
        assert!(p99.is_finite() && p99 <= 999.0, "p99 was {p99}");
    }

    /// Regression: `quantile(NaN)` used to return the largest centroid mean.
    #[test]
    fn nan_quantile_is_nan() {
        let mut digest = TDigest::new(10.0);
        digest.add(1.0);
        digest.add(2.0);
        assert!(digest.quantile(f64::NAN).is_nan());
    }

    #[test]
    fn single_value_digest() {
        let mut digest = TDigest::new(100.0);
        digest.add(42.0);
        assert_eq!(digest.quantile(0.5), 42.0);
        assert_eq!(digest.quantile(0.0), 42.0);
        assert_eq!(digest.quantile(1.0), 42.0);
    }
}
