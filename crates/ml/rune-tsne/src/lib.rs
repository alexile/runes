//! t-SNE dimensionality reduction — map high-dimensional data into 2D or 3D for visualisation.
//!
//! t-SNE (t-distributed Stochastic Neighbour Embedding, van der Maaten & Hinton 2008)
//! converts distances between points into neighbour probabilities P, then finds a
//! low-dimensional embedding whose Student-t neighbour probabilities Q match them,
//! by gradient descent on `KL(P ‖ Q)`.
//!
//! Two gradient methods are available, selected with [`Method`]:
//!
//! - [`Method::Exact`]: the original O(n²) algorithm. P uses every pair of points.
//! - [`Method::BarnesHut`]: van der Maaten, *Accelerating t-SNE using tree-based
//!   algorithms* (JMLR 15, 2014). P is restricted to each point's `⌊3·perplexity⌋`
//!   nearest neighbours and the repulsive forces are approximated with a
//!   quadtree/octree in O(n log n) per iteration; `theta` trades accuracy for speed.
//!   Supports up to 3 output dimensions.
//!
//! [`Method::Auto`] (the default) uses the exact method for small inputs
//! (at most 1000 points) or more than 3 output dimensions, and Barnes-Hut otherwise.
//!
//! The pipeline:
//!
//! 1. **Affinities** — for each point a bounded bisection on the Gaussian precision finds
//!    the bandwidth whose conditional distribution has the target perplexity. The search
//!    starts at the point's own distance scale (so results do not depend on the units of
//!    the data), works on minimum-shifted distances (so it never divides 0 by 0) and stops
//!    after 200 steps.
//! 2. **Initialisation** — [`Init::Pca`] (default) projects onto the leading principal
//!    components, scaled to a standard deviation of `1e-4`; [`Init::Random`] draws from
//!    `N(0, 1e-4²)`. Both are seeded.
//! 3. **Optimisation** — as in van der Maaten (2014): P is multiplied by
//!    `early_exaggeration` (12) for the first `exaggeration_iters` (250) iterations with
//!    momentum 0.5, then momentum 0.8; per-coordinate adaptive gains; learning rate
//!    `n / (4·early_exaggeration)` unless set.
//!
//! Output is a deterministic function of the input and configuration (including the
//! seed) and does not depend on the number of rayon threads.
//!
//! # Quick start
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
//! let result = Tsne::new().perplexity(3.0).n_iter(300).try_fit(&points)?;
//! assert_eq!(result.embedding.len(), 12);
//! assert_eq!(result.embedding[0].len(), 2);
//!
//! // How well are neighbourhoods preserved? (1.0 = perfectly)
//! let t = rune_tsne::trustworthiness(&points, &result.embedding, 3, rune_tsne::Metric::Euclidean)?;
//! assert!(t > 0.9);
//! # Ok::<(), rune_tsne::TsneError>(())
//! ```
//!
//! Progress, including the KL divergence after every iteration, is available through
//! [`Tsne::try_fit_with`], whose callback can also stop the run early.
//!
//! Invalid input — too few points for the perplexity, rows of different lengths,
//! NaN/infinite values, or out-of-range parameters — is reported as a [`TsneError`];
//! nothing panics.

mod affinities;
mod bhtree;
mod layout;

use std::ops::ControlFlow;

use rune_ml_core::{Matrix, MlError};

pub use rune_ml_core::Metric;

/// A per-iteration progress callback.
pub(crate) type Callback<'a> = dyn FnMut(&Iteration) -> ControlFlow<()> + 'a;

/// Largest input for which [`Method::Auto`] picks the exact method.
const AUTO_EXACT_MAX_POINTS: usize = 1000;

/// Errors returned by [`Tsne::try_fit`] and [`trustworthiness`].
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
#[non_exhaustive]
pub enum TsneError {
    /// Fewer than four points were supplied.
    #[error("t-SNE requires at least 4 points, got {n}")]
    TooFewPoints {
        /// Number of points supplied.
        n: usize,
    },
    /// The points have no coordinates.
    #[error("points have no features")]
    NoFeatures,
    /// There are not enough points for the perplexity: it must be below `n_points / 3`.
    #[error("perplexity ({perplexity}) must be less than n_points / 3 ({limit:.3})")]
    PerplexityTooLarge {
        /// The configured perplexity.
        perplexity: f64,
        /// The exclusive upper bound, `n_points / 3`.
        limit: f64,
    },
    /// A point has a different number of coordinates from the first point.
    #[error("row {index} has {found} values, expected {expected}")]
    DimensionMismatch {
        /// Index of the offending point.
        index: usize,
        /// Number of values in that point.
        found: usize,
        /// Dimensionality of the first point.
        expected: usize,
    },
    /// A coordinate is NaN or infinite.
    #[error("row {row}, column {col} is not finite ({value})")]
    NonFinite {
        /// Row of the offending value.
        row: usize,
        /// Column of the offending value.
        col: usize,
        /// The offending value.
        value: f64,
    },
    /// A parameter is out of range.
    #[error("invalid parameter {name} = {value}: {reason}")]
    InvalidParameter {
        /// Parameter name.
        name: &'static str,
        /// Offending value.
        value: f64,
        /// Why the value is rejected.
        reason: &'static str,
    },
    /// An error from the shared ML core (raised by [`trustworthiness`]).
    #[error(transparent)]
    Core(#[from] MlError),
}

/// How the gradient is computed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum Method {
    /// [`Method::Exact`] for at most 1000 points, `theta == 0` or more than 3 output
    /// dimensions; [`Method::BarnesHut`] otherwise.
    #[default]
    Auto,
    /// Exact t-SNE: dense P and O(n²) time and memory per iteration.
    Exact,
    /// Barnes-Hut t-SNE: sparse P over `⌊3·perplexity⌋` neighbours and tree-approximated
    /// repulsion, O(n log n) per iteration. At most 3 output dimensions. The
    /// nearest-neighbour search is a parallel brute-force scan (O(n²·d) once, O(n·k)
    /// memory).
    BarnesHut,
}

/// How the embedding is initialised.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum Init {
    /// Projection onto the leading principal components (computed with `rune-pca`),
    /// rescaled so the first coordinate has standard deviation `1e-4`. Keeps the global
    /// layout more stable than random initialisation (Kobak & Linderman 2021). Output
    /// dimensions beyond the rank of the data are filled randomly.
    #[default]
    Pca,
    /// Independent `N(0, 1e-4²)` coordinates from the seeded generator.
    Random,
}

/// Progress report passed to the [`Tsne::try_fit_with`] callback after every iteration.
#[derive(Debug, Clone, Copy, PartialEq)]
#[non_exhaustive]
pub struct Iteration {
    /// Zero-based iteration index.
    pub iteration: usize,
    /// `KL(P ‖ Q)` with the true (unexaggerated) P, at the embedding this iteration
    /// started from. With Barnes-Hut, Q's normaliser is the tree estimate.
    pub kl_divergence: f64,
    /// Euclidean norm of the gradient used for this step (with exaggeration applied).
    pub gradient_norm: f64,
    /// Whether this iteration was part of the early-exaggeration phase.
    pub exaggerated: bool,
}

/// Builder for configuring and running a t-SNE dimensionality reduction.
///
/// Construct with [`Tsne::new`], chain optional parameters, then call
/// [`Tsne::try_fit`]. Setters store values as given; [`Tsne::try_fit`] validates them.
///
/// # Example
///
/// ```rust
/// use rune_tsne::{Init, Method, Tsne};
///
/// let tsne = Tsne::new()
///     .n_components(2)
///     .perplexity(30.0)
///     .method(Method::BarnesHut)
///     .theta(0.5)
///     .init(Init::Pca)
///     .n_iter(1000)
///     .random_seed(42);
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct Tsne {
    n_components: usize,
    perplexity: f64,
    n_iter: usize,
    /// `None` selects the automatic rate, see [`Tsne::learning_rate`].
    learning_rate: Option<f64>,
    early_exaggeration: f64,
    exaggeration_iters: usize,
    theta: f64,
    method: Method,
    init: Init,
    random_seed: u64,
}

impl Default for Tsne {
    fn default() -> Self {
        Self::new()
    }
}

impl Tsne {
    /// Creates a new `Tsne` instance with the usual defaults.
    ///
    /// | Parameter | Default |
    /// |---|---|
    /// | `n_components` | 2 |
    /// | `perplexity` | 30.0 |
    /// | `n_iter` | 1000 |
    /// | `learning_rate` | automatic: `n_points / (4 · early_exaggeration)` |
    /// | `early_exaggeration` | 12.0 |
    /// | `exaggeration_iters` | 250 |
    /// | `method` | [`Method::Auto`] |
    /// | `theta` | 0.5 |
    /// | `init` | [`Init::Pca`] |
    /// | `random_seed` | 42 |
    ///
    /// # Example
    ///
    /// ```rust
    /// let tsne = rune_tsne::Tsne::new();
    /// assert_eq!(tsne, rune_tsne::Tsne::default());
    /// ```
    #[must_use]
    pub const fn new() -> Self {
        Self {
            n_components: 2,
            perplexity: 30.0,
            n_iter: 1000,
            learning_rate: None,
            early_exaggeration: 12.0,
            exaggeration_iters: 250,
            theta: 0.5,
            method: Method::Auto,
            init: Init::Pca,
            random_seed: 42,
        }
    }

    /// Dimensionality of the output embedding, at least 1. Defaults to `2`.
    ///
    /// # Example
    ///
    /// ```rust
    /// let tsne = rune_tsne::Tsne::new().n_components(3);
    /// ```
    #[must_use]
    pub const fn n_components(mut self, d: usize) -> Self {
        self.n_components = d;
        self
    }

    /// Target perplexity, loosely the number of effective neighbours of each point;
    /// typical values are 5–50. Must be at least 1 and below `n_points / 3`.
    /// Defaults to `30.0`.
    ///
    /// # Example
    ///
    /// ```rust
    /// let tsne = rune_tsne::Tsne::new().perplexity(15.0);
    /// ```
    #[must_use]
    pub const fn perplexity(mut self, p: f64) -> Self {
        self.perplexity = p;
        self
    }

    /// Number of gradient-descent iterations, at least 1. Defaults to `1000`.
    ///
    /// # Example
    ///
    /// ```rust
    /// let tsne = rune_tsne::Tsne::new().n_iter(500);
    /// ```
    #[must_use]
    pub const fn n_iter(mut self, n: usize) -> Self {
        self.n_iter = n;
        self
    }

    /// Learning rate of the gradient descent; must be finite and positive.
    ///
    /// When not set, the rate is `n_points / (4 · early_exaggeration)` (Belkina et al.
    /// 2019; the 4 accounts for the factor in the gradient). This keeps the
    /// early-exaggeration phase stable: a step larger than about
    /// `n_points / (2 · early_exaggeration)` overshoots the attractive forces and the
    /// embedding oscillates instead of contracting. scikit-learn additionally floors the
    /// rate at 50, which is unstable below ~2400 points and visibly scrambles small 1D
    /// embeddings, so no floor is applied here; the adaptive gains make up for a small
    /// rate within a few iterations.
    ///
    /// # Example
    ///
    /// ```rust
    /// let tsne = rune_tsne::Tsne::new().learning_rate(100.0);
    /// ```
    #[must_use]
    pub const fn learning_rate(mut self, lr: f64) -> Self {
        self.learning_rate = Some(lr);
        self
    }

    /// Factor applied to P during the early-exaggeration phase; must be finite and at
    /// least 1. Defaults to `12.0`.
    ///
    /// # Example
    ///
    /// ```rust
    /// let tsne = rune_tsne::Tsne::new().early_exaggeration(4.0);
    /// ```
    #[must_use]
    pub const fn early_exaggeration(mut self, factor: f64) -> Self {
        self.early_exaggeration = factor;
        self
    }

    /// Length of the early-exaggeration phase (which also uses momentum 0.5 instead of
    /// 0.8). Defaults to `250`.
    ///
    /// # Example
    ///
    /// ```rust
    /// let tsne = rune_tsne::Tsne::new().exaggeration_iters(100);
    /// ```
    #[must_use]
    pub const fn exaggeration_iters(mut self, n: usize) -> Self {
        self.exaggeration_iters = n;
        self
    }

    /// The gradient method. Defaults to [`Method::Auto`].
    ///
    /// # Example
    ///
    /// ```rust
    /// let tsne = rune_tsne::Tsne::new().method(rune_tsne::Method::Exact);
    /// ```
    #[must_use]
    pub const fn method(mut self, method: Method) -> Self {
        self.method = method;
        self
    }

    /// Barnes-Hut accuracy: a tree cell is summarised by its centre of mass when
    /// `cell side / distance < theta`. `0` is exact (and slow); larger is faster and
    /// coarser. Must be in `[0, 1]`. Defaults to `0.5`. Ignored by [`Method::Exact`].
    ///
    /// # Example
    ///
    /// ```rust
    /// let tsne = rune_tsne::Tsne::new().theta(0.3);
    /// ```
    #[must_use]
    pub const fn theta(mut self, theta: f64) -> Self {
        self.theta = theta;
        self
    }

    /// The initialisation. Defaults to [`Init::Pca`].
    ///
    /// # Example
    ///
    /// ```rust
    /// let tsne = rune_tsne::Tsne::new().init(rune_tsne::Init::Random);
    /// ```
    #[must_use]
    pub const fn init(mut self, init: Init) -> Self {
        self.init = init;
        self
    }

    /// Seed for the random initialisation (and the randomized PCA used by
    /// [`Init::Pca`] on large inputs). Identical seeds give identical embeddings.
    /// Defaults to `42`.
    ///
    /// # Example
    ///
    /// ```rust
    /// let tsne = rune_tsne::Tsne::new().random_seed(123);
    /// ```
    #[must_use]
    pub const fn random_seed(mut self, s: u64) -> Self {
        self.random_seed = s;
        self
    }

    /// Computes the t-SNE embedding of `points`.
    ///
    /// # Errors
    ///
    /// - [`TsneError::TooFewPoints`] for fewer than 4 points;
    /// - [`TsneError::NoFeatures`] if the points have no coordinates;
    /// - [`TsneError::DimensionMismatch`] if the points do not all have the same length;
    /// - [`TsneError::NonFinite`] for a NaN or infinite coordinate;
    /// - [`TsneError::PerplexityTooLarge`] unless `n_points > 3 · perplexity`;
    /// - [`TsneError::InvalidParameter`] for a parameter out of range (including
    ///   [`Method::BarnesHut`] with more than 3 output dimensions).
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_tsne::{Tsne, TsneError};
    ///
    /// let points: Vec<Vec<f64>> = (0..12).map(|i| vec![i as f64, (i as f64).sin()]).collect();
    /// let result = Tsne::new().perplexity(3.0).n_iter(50).try_fit(&points)?;
    /// assert_eq!(result.embedding.len(), 12);
    /// assert!(result.kl_divergence.is_finite());
    ///
    /// // 12 points support a perplexity below 4 only.
    /// assert!(matches!(
    ///     Tsne::new().perplexity(4.0).try_fit(&points),
    ///     Err(TsneError::PerplexityTooLarge { .. })
    /// ));
    /// # Ok::<(), TsneError>(())
    /// ```
    pub fn try_fit(&self, points: &[Vec<f64>]) -> Result<TsneResult, TsneError> {
        self.run(points, None)
    }

    /// Like [`Tsne::try_fit`], calling `callback` after every iteration with an
    /// [`Iteration`] report (iteration index, KL divergence, gradient norm).
    /// Returning [`ControlFlow::Break`] stops the optimisation early; the result then
    /// holds the embedding reached so far.
    ///
    /// Reporting costs one extra pass over P per iteration.
    ///
    /// # Errors
    ///
    /// As [`Tsne::try_fit`].
    ///
    /// # Example
    ///
    /// ```rust
    /// use std::ops::ControlFlow;
    /// use rune_tsne::Tsne;
    ///
    /// let points: Vec<Vec<f64>> = (0..30).map(|i| vec![i as f64, (i % 3) as f64]).collect();
    /// let mut kl = Vec::new();
    /// let result = Tsne::new().perplexity(5.0).try_fit_with(&points, |it| {
    ///     kl.push(it.kl_divergence);
    ///     if it.iteration + 1 == 300 { ControlFlow::Break(()) } else { ControlFlow::Continue(()) }
    /// })?;
    /// assert_eq!((kl.len(), result.n_iter), (300, 300));
    /// // Optimisation lowers the divergence from the near-random start.
    /// assert!(kl[299] < kl[0]);
    /// # Ok::<(), rune_tsne::TsneError>(())
    /// ```
    pub fn try_fit_with<F>(
        &self,
        points: &[Vec<f64>],
        mut callback: F,
    ) -> Result<TsneResult, TsneError>
    where
        F: FnMut(&Iteration) -> ControlFlow<()>,
    {
        self.run(points, Some(&mut callback))
    }

    /// Same as [`Tsne::try_fit`]; kept so code written against 0.2 still compiles.
    ///
    /// # Errors
    ///
    /// As [`Tsne::try_fit`].
    pub fn fit(&self, points: &[Vec<f64>]) -> Result<TsneResult, TsneError> {
        self.try_fit(points)
    }

    /// The method that would be used for `n` points.
    const fn resolve_method(&self, n: usize) -> Method {
        match self.method {
            Method::Auto
                if n <= AUTO_EXACT_MAX_POINTS
                    || self.n_components > bhtree::MAX_DIM
                    || self.theta == 0.0 =>
            {
                Method::Exact
            }
            Method::Auto => Method::BarnesHut,
            m => m,
        }
    }

    #[allow(
        clippy::cast_precision_loss,
        reason = "counts and indices stay far below 2^52, so the f64 conversion is exact"
    )]
    fn validate(&self, points: &[Vec<f64>]) -> Result<f64, TsneError> {
        let n = points.len();
        if n < 4 {
            return Err(TsneError::TooFewPoints { n });
        }
        let dim = points[0].len();
        if dim == 0 {
            return Err(TsneError::NoFeatures);
        }
        for (row, p) in points.iter().enumerate() {
            if p.len() != dim {
                return Err(TsneError::DimensionMismatch {
                    index: row,
                    found: p.len(),
                    expected: dim,
                });
            }
            if let Some((col, &value)) = p.iter().enumerate().find(|(_, v)| !v.is_finite()) {
                return Err(TsneError::NonFinite { row, col, value });
            }
        }
        let invalid = |name, value, reason| TsneError::InvalidParameter {
            name,
            value,
            reason,
        };
        if self.n_components == 0 {
            return Err(invalid("n_components", 0.0, "must be at least 1"));
        }
        if self.n_iter == 0 {
            return Err(invalid("n_iter", 0.0, "must be at least 1"));
        }
        if !(self.perplexity.is_finite() && self.perplexity >= 1.0) {
            return Err(invalid(
                "perplexity",
                self.perplexity,
                "must be finite and at least 1",
            ));
        }
        let limit = n as f64 / 3.0;
        if self.perplexity >= limit {
            return Err(TsneError::PerplexityTooLarge {
                perplexity: self.perplexity,
                limit,
            });
        }
        if !(self.early_exaggeration.is_finite() && self.early_exaggeration >= 1.0) {
            return Err(invalid(
                "early_exaggeration",
                self.early_exaggeration,
                "must be finite and at least 1",
            ));
        }
        if !(0.0..=1.0).contains(&self.theta) {
            return Err(invalid("theta", self.theta, "must be in [0, 1]"));
        }
        let learning_rate = self
            .learning_rate
            .unwrap_or_else(|| n as f64 / (4.0 * self.early_exaggeration));
        if !(learning_rate.is_finite() && learning_rate > 0.0) {
            return Err(invalid(
                "learning_rate",
                learning_rate,
                "must be finite and positive",
            ));
        }
        if self.resolve_method(n) == Method::BarnesHut && self.n_components > bhtree::MAX_DIM {
            return Err(invalid(
                "n_components",
                self.n_components as f64,
                "Barnes-Hut supports at most 3 output dimensions",
            ));
        }
        Ok(learning_rate)
    }

    fn run(
        &self,
        points: &[Vec<f64>],
        report: Option<&mut Callback<'_>>,
    ) -> Result<TsneResult, TsneError> {
        let learning_rate = self.validate(points)?;
        let n = points.len();
        let dim = self.n_components;
        let method = self.resolve_method(n);

        let p = match method {
            Method::BarnesHut => layout::Affinities::Sparse(
                affinities::sparse_p(points, self.perplexity),
                self.theta,
            ),
            _ => layout::Affinities::Dense(affinities::dense_p(points, self.perplexity)),
        };
        let mut y = self.initial_embedding(points);
        let n_iter = layout::optimize(
            &mut y,
            dim,
            &p,
            &layout::Schedule {
                learning_rate,
                n_iter: self.n_iter,
                exaggeration: self.early_exaggeration,
                exaggeration_iters: self.exaggeration_iters,
            },
            report,
        );
        let kl_divergence = layout::kl_divergence(&p, &y, dim);
        Ok(TsneResult {
            embedding: y.chunks_exact(dim).map(<[f64]>::to_vec).collect(),
            kl_divergence,
            n_iter,
            method,
        })
    }

    /// Flat `n × n_components` starting embedding.
    #[allow(
        clippy::cast_precision_loss,
        reason = "counts and indices stay far below 2^52, so the f64 conversion is exact"
    )]
    fn initial_embedding(&self, points: &[Vec<f64>]) -> Vec<f64> {
        const SCALE: f64 = 1e-4;
        let n = points.len();
        let dim = self.n_components;
        let mut rng = rune_ml_core::Rng::new(self.random_seed);
        let mut y: Vec<f64> = (0..n * dim).map(|_| rng.normal() * SCALE).collect();
        if self.init == Init::Random {
            return y;
        }
        let k = dim.min(points[0].len()).min(n);
        let Ok((_, proj)) = rune_pca::Pca::new(k)
            .with_seed(self.random_seed)
            .fit_transform(points)
        else {
            return y;
        };
        let std = (proj.iter().map(|r| r[0] * r[0]).sum::<f64>() / (n as f64 - 1.0)).sqrt();
        if !(std > 0.0 && std.is_finite()) {
            // No variance at all: random it is.
            return y;
        }
        for (row, out) in proj.iter().zip(y.chunks_exact_mut(dim)) {
            for (o, v) in out.iter_mut().zip(row) {
                *o = v / std * SCALE;
            }
        }
        y
    }
}

/// The result of a completed t-SNE run.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct TsneResult {
    /// The low-dimensional embedding: one inner `Vec<f64>` per input point,
    /// with length equal to `n_components`. The embedding is centred on the origin.
    pub embedding: Vec<Vec<f64>>,
    /// Final `KL(P ‖ Q)` between the high-dimensional affinities and the embedding's
    /// Student-t affinities (without exaggeration; with Barnes-Hut, Q's normaliser is
    /// the tree estimate). Lower is better; useful for comparing runs on the same data.
    pub kl_divergence: f64,
    /// Number of iterations performed (fewer than configured if a
    /// [`Tsne::try_fit_with`] callback stopped the run).
    pub n_iter: usize,
    /// The method used ([`Method::Auto`] resolved).
    pub method: Method,
}

/// Trustworthiness of an embedding (Venna & Kaski 2001), in `[0, 1]`.
///
/// Measures how many of each point's `k` nearest neighbours in `low` were also near
/// it in `high`, penalising intruders by their original rank. `1.0` means every
/// embedded neighbourhood is faithful. Matches `sklearn.manifold.trustworthiness`, and the
/// function of the same name in `rune-umap`.
///
/// `metric` is used in the original space, the embedding is measured with the
/// Euclidean distance. O(n² log n), meant for evaluation and tests.
///
/// # Errors
///
/// [`TsneError::DimensionMismatch`] for ragged rows, otherwise [`TsneError::Core`]
/// when the inputs have different lengths, contain non-finite values, have fewer than
/// 3 rows, or `k` is not in `1..n / 2`.
///
/// # Example
///
/// ```rust
/// use rune_tsne::{trustworthiness, Metric};
///
/// let high = vec![vec![0.0, 0.0], vec![1.0, 0.1], vec![2.0, 0.0], vec![3.0, 0.1], vec![4.0, 0.0]];
/// let low: Vec<Vec<f64>> = high.iter().map(|p| vec![p[0]]).collect();
/// assert!((trustworthiness(&high, &low, 2, Metric::Euclidean)? - 1.0).abs() < 1e-12);
/// # Ok::<(), rune_tsne::TsneError>(())
/// ```
pub fn trustworthiness(
    high: &[Vec<f64>],
    low: &[Vec<f64>],
    k: usize,
    metric: Metric,
) -> Result<f64, TsneError> {
    let to_matrix = |rows: &[Vec<f64>]| {
        Matrix::from_rows(rows).map_err(|e| match e {
            MlError::RaggedRows {
                row,
                expected,
                found,
            } => TsneError::DimensionMismatch {
                index: row,
                found,
                expected,
            },
            other => TsneError::Core(other),
        })
    };
    let (h, l) = (to_matrix(high)?, to_matrix(low)?);
    Ok(rune_ml_core::trustworthiness(
        h.view(),
        l.view(),
        k,
        metric,
    )?)
}

/// Compiles and runs the README examples.
#[cfg(doctest)]
#[doc = include_str!("../README.md")]
struct ReadmeDoctests;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auto_method_resolution() {
        let t = Tsne::new();
        assert_eq!(t.resolve_method(100), Method::Exact);
        assert_eq!(t.resolve_method(5000), Method::BarnesHut);
        assert_eq!(
            t.clone().n_components(4).resolve_method(5000),
            Method::Exact
        );
        assert_eq!(t.clone().theta(0.0).resolve_method(5000), Method::Exact);
        assert_eq!(
            t.method(Method::BarnesHut).resolve_method(10),
            Method::BarnesHut
        );
    }

    #[test]
    fn pca_init_is_scaled_and_seeded() {
        let pts: Vec<Vec<f64>> = (0..20)
            .map(|i| vec![f64::from(i), f64::from(i % 4), 1.0])
            .collect();
        let y = Tsne::new().initial_embedding(&pts);
        let std = (y.iter().step_by(2).map(|v| v * v).sum::<f64>() / 19.0).sqrt();
        assert!((std - 1e-4).abs() < 1e-12, "{std}");
        // More output dimensions than features: the extra one is random noise.
        let y3 = Tsne::new().n_components(4).initial_embedding(&pts[..10]);
        assert_eq!(y3.len(), 40);
        assert!(y3.iter().all(|v| v.is_finite() && v.abs() < 1e-2));
        // Constant data has no principal axis: falls back to random.
        let flat = vec![vec![1.0, 1.0]; 8];
        let a = Tsne::new().initial_embedding(&flat);
        let b = Tsne::new().init(Init::Random).initial_embedding(&flat);
        assert_eq!(a, b);
    }
}
