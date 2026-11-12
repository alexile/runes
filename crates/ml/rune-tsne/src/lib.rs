//! t-SNE dimensionality reduction — map high-dimensional data into 2D or 3D for visualisation.
//!
//! t-SNE (t-distributed Stochastic Neighbour Embedding, van der Maaten & Hinton 2008)
//! converts similarities between data points in the original high-dimensional space into
//! conditional probabilities, then finds a low-dimensional embedding that preserves those
//! similarities. The Student-t distribution in the low-dimensional space alleviates the
//! "crowding problem" that afflicts Gaussian-based embeddings.
//!
//! The algorithm runs in three stages:
//!
//! 1. **High-dimensional affinities** — for each point a binary search finds the Gaussian
//!    bandwidth `σ_i` that yields the target perplexity, producing a symmetrised joint
//!    probability matrix P.
//!
//! 2. **Random initialisation** — each embedded coordinate is drawn from N(0, 1e-4)
//!    via a Box-Muller transform seeded by Xorshift64.
//!
//! 3. **Momentum SGD** — the KL-divergence between P and the low-dimensional
//!    Student-t distribution Q is minimised with early exaggeration (first 250 iterations
//!    multiply P by 12), a momentum schedule (0.5 → 0.8 at iteration 250) and
//!    per-coordinate adaptive gains, as in the reference implementation.
//!
//! The bandwidth search starts at each point's root-mean-square distance to the rest
//! of the data, so the result does not depend on the units the data is measured in.
//!
//! # Features
//!
//! - Exact O(n²) t-SNE following the original paper
//! - 2D or nD output via `n_components`
//! - Configurable perplexity, learning rate (automatic by default), iteration count,
//!   and random seed
//! - Parallelised gradient computation via rayon
//! - Deterministic output for a given seed
//! - Pure Rust, no unsafe code
//!
//! # Quick Start
//!
//! ```rust
//! use rune_tsne::Tsne;
//!
//! // Two tight clusters, six points each
//! let points: Vec<Vec<f64>> = (0..6)
//!     .map(|i| vec![i as f64 * 0.1, i as f64 * 0.1])
//!     .chain((0..6).map(|i| vec![10.0 + i as f64 * 0.1, 10.0 + i as f64 * 0.1]))
//!     .collect();
//!
//! let result = Tsne::new().perplexity(3.0).n_iter(300).fit(&points)?;
//! assert_eq!(result.embedding.len(), 12);
//! assert_eq!(result.embedding[0].len(), 2);
//! # Ok::<(), rune_tsne::TsneError>(())
//! ```
//!
//! Invalid input — too few points, a perplexity too large for the data set, rows of
//! different lengths, or NaN/infinite coordinates — is reported as a [`TsneError`];
//! `fit` never panics.
//!
//! # CLI
//!
//! ```bash
//! rune-tsne data.csv --perplexity 30 --n-iter 1000
//! cat data.csv | rune-tsne - --perplexity 10
//! ```

mod affinities;
mod layout;
mod rng;

/// Factor applied to P during the early-exaggeration phase.
const EXAGGERATION: f64 = 12.0;
/// Number of initial iterations run with exaggerated P (and momentum 0.5).
const EXAGGERATION_ITERS: usize = 250;

/// Errors returned by [`Tsne::fit`] for input it cannot embed.
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
#[non_exhaustive]
pub enum TsneError {
    /// Fewer than three points were supplied.
    #[error("t-SNE requires at least 3 points, got {n}")]
    TooFewPoints {
        /// Number of points supplied.
        n: usize,
    },
    /// The perplexity is not below `n_points / 3`.
    #[error("perplexity ({perplexity:.1}) must be less than n_points / 3 ({limit:.1})")]
    PerplexityTooLarge {
        /// The configured perplexity.
        perplexity: f64,
        /// The exclusive upper bound, `n_points / 3`.
        limit: f64,
    },
    /// A point has a different number of coordinates from the first point.
    #[error("point {index} has {found} coordinates, expected {expected}")]
    DimensionMismatch {
        /// Index of the offending point.
        index: usize,
        /// Dimensionality of the first point.
        expected: usize,
        /// Dimensionality of the offending point.
        found: usize,
    },
    /// A point has a NaN or infinite coordinate.
    #[error("point {index} has a non-finite coordinate")]
    NonFiniteInput {
        /// Index of the offending point.
        index: usize,
    },
    /// The learning rate is not finite.
    #[error("learning rate must be finite, got {0}")]
    InvalidLearningRate(f64),
}

/// Builder for configuring and running a t-SNE dimensionality reduction.
///
/// Construct with [`Tsne::new`], chain optional parameters, then call [`Tsne::fit`].
///
/// # Example
///
/// ```rust
/// use rune_tsne::Tsne;
///
/// let tsne = Tsne::new()
///     .n_components(2)
///     .perplexity(30.0)
///     .n_iter(1000)
///     .learning_rate(200.0)
///     .random_seed(42);
/// ```
#[derive(Debug, Clone)]
pub struct Tsne {
    n_components: usize,
    perplexity: f64,
    n_iter: usize,
    /// `None` selects the automatic rate, see [`Tsne::learning_rate`].
    learning_rate: Option<f64>,
    random_seed: u64,
}

impl Default for Tsne {
    fn default() -> Self {
        Self::new()
    }
}

impl Tsne {
    /// Creates a new `Tsne` instance with sensible defaults.
    ///
    /// | Parameter | Default |
    /// |---|---|
    /// | `n_components` | 2 |
    /// | `perplexity` | 30.0 |
    /// | `n_iter` | 1000 |
    /// | `learning_rate` | automatic: `max(n_points / 48, 50)` |
    /// | `random_seed` | 42 |
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_tsne::Tsne;
    ///
    /// let tsne = Tsne::new();
    /// ```
    #[must_use]
    pub const fn new() -> Self {
        Self {
            n_components: 2,
            perplexity: 30.0,
            n_iter: 1000,
            learning_rate: None,
            random_seed: 42,
        }
    }

    /// Dimensionality of the output embedding. Clamped to at least 1. Defaults to `2`.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_tsne::Tsne;
    ///
    /// let tsne = Tsne::new().n_components(3);
    /// ```
    #[must_use]
    pub fn n_components(mut self, d: usize) -> Self {
        self.n_components = d.max(1);
        self
    }

    /// Target perplexity for the high-dimensional affinity matrix.
    ///
    /// Perplexity loosely controls how many neighbours each point considers; typical
    /// values are 5–50. Values at or below `1.0` (and NaN) are raised to just above
    /// `1.0`; [`Tsne::fit`] rejects values at or above `n_points / 3` with
    /// [`TsneError::PerplexityTooLarge`]. Defaults to `30.0`.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_tsne::Tsne;
    ///
    /// let tsne = Tsne::new().perplexity(15.0);
    /// ```
    #[must_use]
    pub fn perplexity(mut self, p: f64) -> Self {
        self.perplexity = p.max(1.0 + f64::EPSILON);
        self
    }

    /// Number of gradient-descent iterations. Clamped to at least 1. Defaults to `1000`.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_tsne::Tsne;
    ///
    /// let tsne = Tsne::new().n_iter(500);
    /// ```
    #[must_use]
    pub fn n_iter(mut self, n: usize) -> Self {
        self.n_iter = n.max(1);
        self
    }

    /// Learning rate for the momentum SGD update. Clamped to at least `1.0` (NaN becomes
    /// `1.0`); an infinite rate is rejected by [`Tsne::fit`].
    ///
    /// When not set, the rate is chosen from the data size as
    /// `max(n_points / (early_exaggeration · 4), 50) = max(n_points / 48, 50)`
    /// (Belkina et al. 2019, as in scikit-learn's `learning_rate="auto"`). The once
    /// common fixed default of `200` is too aggressive for small data sets and can
    /// leave clusters torn apart.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_tsne::Tsne;
    ///
    /// let tsne = Tsne::new().learning_rate(100.0);
    /// ```
    #[must_use]
    pub const fn learning_rate(mut self, lr: f64) -> Self {
        self.learning_rate = Some(lr.max(1.0));
        self
    }

    /// Seed for the internal Xorshift64 PRNG. Identical seeds produce identical embeddings.
    /// Defaults to `42`.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_tsne::Tsne;
    ///
    /// let tsne = Tsne::new().random_seed(123);
    /// ```
    #[must_use]
    pub const fn random_seed(mut self, s: u64) -> Self {
        self.random_seed = s;
        self
    }

    /// Computes the t-SNE embedding of `points`.
    ///
    /// All points must have the same dimensionality. Runtime is O(n²) in both time and
    /// memory. The output is a deterministic function of the input and the configuration
    /// (including the seed), independent of the number of rayon worker threads.
    ///
    /// # Errors
    ///
    /// - [`TsneError::TooFewPoints`] if `points.len() < 3`;
    /// - [`TsneError::PerplexityTooLarge`] if `perplexity ≥ n_points / 3`;
    /// - [`TsneError::DimensionMismatch`] if the points do not all have the same length;
    /// - [`TsneError::NonFiniteInput`] if any coordinate is NaN or infinite;
    /// - [`TsneError::InvalidLearningRate`] if the learning rate is infinite.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_tsne::Tsne;
    ///
    /// let points: Vec<Vec<f64>> = (0..12)
    ///     .map(|i| vec![i as f64, (i as f64).sin()])
    ///     .collect();
    ///
    /// let result = Tsne::new().perplexity(3.0).n_iter(50).fit(&points)?;
    /// assert_eq!(result.embedding.len(), 12);
    /// assert_eq!(result.embedding[0].len(), 2);
    /// assert!(result.kl_divergence.is_finite());
    /// # Ok::<(), rune_tsne::TsneError>(())
    /// ```
    #[allow(
        clippy::cast_precision_loss,
        reason = "counts and indices stay far below 2^52, so the f64 conversion is exact"
    )]
    pub fn fit(&self, points: &[Vec<f64>]) -> Result<TsneResult, TsneError> {
        let n = points.len();
        if n < 3 {
            return Err(TsneError::TooFewPoints { n });
        }

        let perplexity_limit = n as f64 / 3.0;
        // The setter maps NaN to just above 1, so the perplexity is never NaN here.
        if self.perplexity >= perplexity_limit {
            return Err(TsneError::PerplexityTooLarge {
                perplexity: self.perplexity,
                limit: perplexity_limit,
            });
        }
        let learning_rate = self
            .learning_rate
            .unwrap_or_else(|| (n as f64 / (EXAGGERATION * 4.0)).max(50.0));
        if !learning_rate.is_finite() {
            return Err(TsneError::InvalidLearningRate(learning_rate));
        }
        let dim = points[0].len();
        for (index, point) in points.iter().enumerate() {
            if point.len() != dim {
                return Err(TsneError::DimensionMismatch {
                    index,
                    expected: dim,
                    found: point.len(),
                });
            }
            if !point.iter().all(|x| x.is_finite()) {
                return Err(TsneError::NonFiniteInput { index });
            }
        }

        let p = affinities::compute_p(points, self.perplexity);

        let mut rng = rng::Rng::new(self.random_seed);
        let mut embedding: Vec<Vec<f64>> = (0..n)
            .map(|_| {
                (0..self.n_components)
                    .map(|_| rng.next_gaussian() * 1e-4)
                    .collect()
            })
            .collect();

        layout::optimize(
            &mut embedding,
            &p,
            &layout::OptimizeParams {
                n,
                nc: self.n_components,
                learning_rate,
                n_iter: self.n_iter,
                early_exag_iter: EXAGGERATION_ITERS,
                exag_factor: EXAGGERATION,
            },
        );

        let kl_divergence = layout::kl_divergence(&embedding, &p, n, self.n_components);
        Ok(TsneResult {
            embedding,
            kl_divergence,
        })
    }
}

/// The result of a completed t-SNE run.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct TsneResult {
    /// The low-dimensional embedding: one inner `Vec<f64>` per input point,
    /// with length equal to `n_components`. The embedding is centred on the origin.
    pub embedding: Vec<Vec<f64>>,
    /// Final Kullback–Leibler divergence `KL(P ‖ Q)` between the high-dimensional
    /// affinities and the embedding's Student-t affinities (without exaggeration).
    /// Lower is better; useful for comparing runs on the same data.
    pub kl_divergence: f64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[allow(
        clippy::cast_precision_loss,
        reason = "counts and indices stay far below 2^52, so the f64 conversion is exact"
    )]
    fn two_blobs(n_each: usize) -> Vec<Vec<f64>> {
        let mut pts = Vec::new();
        for i in 0..n_each {
            pts.push(vec![i as f64 * 0.1, i as f64 * 0.1]);
        }
        for i in 0..n_each {
            pts.push(vec![
                (i as f64).mul_add(0.1, 10.0),
                (i as f64).mul_add(0.1, 10.0),
            ]);
        }
        pts
    }

    #[test]
    fn output_shape() {
        let pts = two_blobs(10);
        let result = Tsne::new().perplexity(5.0).n_iter(50).fit(&pts).unwrap();
        assert_eq!(result.embedding.len(), 20);
        assert!(result.embedding.iter().all(|row| row.len() == 2));
    }

    #[test]
    fn three_components_shape() {
        let pts = two_blobs(10);
        let result = Tsne::new()
            .n_components(3)
            .perplexity(5.0)
            .n_iter(50)
            .fit(&pts)
            .unwrap();
        assert_eq!(result.embedding.len(), 20);
        assert!(result.embedding.iter().all(|row| row.len() == 3));
    }

    #[test]
    fn deterministic_with_same_seed() {
        let pts = two_blobs(10);
        let r1 = Tsne::new()
            .perplexity(5.0)
            .n_iter(50)
            .random_seed(7)
            .fit(&pts)
            .unwrap();
        let r2 = Tsne::new()
            .perplexity(5.0)
            .n_iter(50)
            .random_seed(7)
            .fit(&pts)
            .unwrap();
        for (a, b) in r1.embedding.iter().zip(&r2.embedding) {
            for (x, y) in a.iter().zip(b) {
                assert!((x - y).abs() < 1e-12, "embeddings differ with same seed");
            }
        }
    }

    #[test]
    fn blobs_are_separated() {
        let pts = two_blobs(15);
        let result = Tsne::new()
            .perplexity(5.0)
            .n_iter(500)
            .random_seed(42)
            .fit(&pts)
            .unwrap();

        let centroid_a: Vec<f64> = (0..2)
            .map(|d| result.embedding[0..15].iter().map(|r| r[d]).sum::<f64>() / 15.0)
            .collect();
        let centroid_b: Vec<f64> = (0..2)
            .map(|d| result.embedding[15..30].iter().map(|r| r[d]).sum::<f64>() / 15.0)
            .collect();

        let separation = centroid_a
            .iter()
            .zip(&centroid_b)
            .map(|(a, b)| (a - b).powi(2))
            .sum::<f64>()
            .sqrt();

        assert!(
            separation > 2.0,
            "cluster centroids should be well separated, got {separation:.3}"
        );
    }
}
