//! UMAP dimensionality reduction — project high-dimensional data into 2D or nD embeddings.
//!
//! UMAP (Uniform Manifold Approximation and Projection) is a general-purpose dimensionality
//! reduction algorithm that preserves both local structure (neighbouring points stay
//! neighbours) and global structure (distant clusters remain separated). It is faster
//! than t-SNE and tends to produce cleaner cluster boundaries.
//!
//! The algorithm proceeds in two phases:
//!
//! 1. **Graph construction** — find `k` nearest neighbours for each point, compute a
//!    per-point bandwidth `σ` via binary search, and build a symmetrised fuzzy k-NN graph
//!    where edge weights encode neighbourhood membership strength.
//!
//! 2. **Layout optimisation** — initialise the embedding (spectrally or randomly), then
//!    run stochastic gradient descent with attractive forces along graph edges and repulsive
//!    forces toward randomly sampled negative pairs, using the low-dimensional membership
//!    function `1 / (1 + a·d^(2b))`.
//!
//! # Features
//!
//! - 2D or nD output via `n_components`
//! - Four distance metrics: Euclidean, Manhattan, Cosine, Correlation
//! - Exact k-NN for small inputs, NN-Descent approximate k-NN for large ones
//!   ([`KnnMethod`]), parallelised with rayon; also usable on its own through
//!   the [`knn`] module (`knn::knn_graph(data, k, metric, seed)`)
//! - Spectral initialisation (default) or random
//! - Supervised (`fit_supervised`) and semi-supervised (`fit_semi_supervised`)
//!   modes — label graph merged with the structure graph
//! - `FittedUmap::transform` — embed new points into an existing embedding
//! - Deterministic via `random_seed` (independent of the rayon thread count)
//! - Fallible `try_*` entry points that validate input (empty, ragged, `NaN`/`inf`,
//!   `n_neighbors ≥ n_samples`, …) and return [`UmapError`] instead of panicking
//! - [`trustworthiness`] quality metric for evaluating embeddings (shared with
//!   the other runes through `rune-ml-core`)
//! - Pure Rust, no unsafe
//!
//! # Error handling
//!
//! ```rust
//! use rune_umap::{Umap, UmapError};
//!
//! let ragged = vec![vec![1.0, 2.0], vec![3.0]];
//! assert!(matches!(
//!     Umap::new().try_fit(&ragged),
//!     Err(UmapError::DimensionMismatch { index: 1, .. })
//! ));
//!
//! let too_few = vec![vec![1.0], vec![2.0], vec![3.0]];
//! assert!(matches!(
//!     Umap::new().n_neighbors(5).try_fit(&too_few),
//!     Err(UmapError::TooFewSamples { .. })
//! ));
//! ```
//!
//! # Quick Start
//!
//! ```rust
//! use rune_umap::Umap;
//!
//! // Six points in two tight clusters
//! let points = vec![
//!     vec![1.0, 2.0], vec![1.5, 1.8], vec![1.2, 1.9],
//!     vec![8.0, 8.0], vec![8.5, 8.2], vec![8.1, 8.3],
//! ];
//!
//! let fitted = Umap::new().n_neighbors(3).n_epochs(200).fit(&points);
//! assert_eq!(fitted.embedding.len(), 6);
//! assert_eq!(fitted.embedding[0].len(), 2);
//! ```
//!
//! # Transform new points
//!
//! ```rust
//! use rune_umap::Umap;
//!
//! let train = vec![
//!     vec![1.0, 2.0], vec![1.5, 1.8], vec![1.2, 1.9],
//!     vec![8.0, 8.0], vec![8.5, 8.2], vec![8.1, 8.3],
//! ];
//! let fitted = Umap::new().n_neighbors(3).n_epochs(100).fit(&train);
//!
//! let new_points = vec![vec![1.1, 2.0], vec![8.2, 8.1]];
//! let coords = fitted.transform(&new_points);
//! assert_eq!(coords.len(), 2);
//! ```
//!
//! # Supervised mode
//!
//! ```rust
//! use rune_umap::Umap;
//!
//! let points = vec![
//!     vec![1.0, 2.0], vec![1.5, 1.8], vec![1.2, 1.9],
//!     vec![8.0, 8.0], vec![8.5, 8.2], vec![8.1, 8.3],
//! ];
//! let labels = vec![0i64, 0, 0, 1, 1, 1];
//!
//! let fitted = Umap::new().n_neighbors(3).n_epochs(100).fit_supervised(&points, &labels);
//! assert_eq!(fitted.embedding.len(), 6);
//! ```
//!
//! # CLI
//!
//! ```bash
//! rune-umap data.csv --n-neighbors 15
//! rune-umap data.csv --n-neighbors 15 --n-components 3 --metric cosine
//! cat data.csv | rune-umap - --n-neighbors 10 --min-dist 0.05
//! ```

mod distance;
mod error;
mod graph;
pub mod knn;
mod layout;
mod nnd;
mod params;
mod quality;
mod rng;
mod supervised;

pub use distance::{Metric, ParseMetricError};
pub use error::UmapError;
pub use quality::trustworthiness;

/// How the k-nearest-neighbour graph is computed.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum KnnMethod {
    /// Exact search for inputs of at most 4096 points, NN-Descent above.
    #[default]
    Auto,
    /// Brute-force exact search: O(n²·d), parallel over points.
    Exact,
    /// Approximate NN-Descent (Dong et al., 2011): roughly O(n·k²·iters).
    NnDescent,
}

/// Builder for configuring and running UMAP dimensionality reduction.
///
/// Construct with [`Umap::new`], chain optional parameters, then call [`Umap::fit`]
/// or [`Umap::fit_supervised`].
///
/// # Example
///
/// ```rust
/// use rune_umap::{Umap, Metric};
///
/// let umap = Umap::new()
///     .n_neighbors(15)
///     .n_components(2)
///     .min_dist(0.1)
///     .metric(Metric::Euclidean)
///     .random_seed(42);
/// ```
#[derive(Clone, Debug)]
pub struct Umap {
    n_neighbors: usize,
    n_components: usize,
    min_dist: f64,
    spread: f64,
    n_epochs: Option<usize>,
    n_transform_epochs: Option<usize>,
    n_nnd_iters: usize,
    learning_rate: f64,
    negative_sample_rate: usize,
    metric: Metric,
    random_seed: u64,
    use_spectral_init: bool,
    target_weight: f64,
    knn_method: KnnMethod,
}

impl Default for Umap {
    fn default() -> Self {
        Self::new()
    }
}

impl Umap {
    /// Creates a new UMAP instance with sensible defaults.
    ///
    /// | Parameter | Default |
    /// |---|---|
    /// | `n_neighbors` | 15 |
    /// | `n_components` | 2 |
    /// | `min_dist` | 0.1 |
    /// | `spread` | 1.0 |
    /// | `learning_rate` | 1.0 |
    /// | `negative_sample_rate` | 5 |
    /// | `metric` | Euclidean |
    /// | `random_seed` | 42 |
    /// | `spectral_init` | true |
    /// | `target_weight` | 0.5 |
    /// | `n_nnd_iters` | 10 |
    /// | `knn_method` | `Auto` |
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_umap::Umap;
    ///
    /// let umap = Umap::new();
    /// ```
    #[must_use]
    pub const fn new() -> Self {
        Self {
            n_neighbors: 15,
            n_components: 2,
            min_dist: 0.1,
            spread: 1.0,
            n_epochs: None,
            n_transform_epochs: None,
            n_nnd_iters: 10,
            learning_rate: 1.0,
            negative_sample_rate: 5,
            metric: Metric::Euclidean,
            random_seed: 42,
            use_spectral_init: true,
            target_weight: 0.5,
            knn_method: KnnMethod::Auto,
        }
    }

    /// Number of nearest neighbours used to build the fuzzy k-NN graph.
    ///
    /// Larger values consider more of the global structure; smaller values focus
    /// on fine local detail. Typical range: 5–50.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_umap::Umap;
    ///
    /// let umap = Umap::new().n_neighbors(10);
    /// ```
    #[must_use]
    pub fn n_neighbors(mut self, k: usize) -> Self {
        self.n_neighbors = k.max(2);
        self
    }

    /// Dimensionality of the output embedding. Defaults to `2`.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_umap::Umap;
    ///
    /// let umap = Umap::new().n_components(3);
    /// ```
    #[must_use]
    pub fn n_components(mut self, d: usize) -> Self {
        self.n_components = d.max(1);
        self
    }

    /// Effective minimum distance between embedded points.
    ///
    /// Smaller values allow points to cluster more tightly; larger values spread them
    /// out. Works together with `spread`. Defaults to `0.1`.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_umap::Umap;
    ///
    /// let umap = Umap::new().min_dist(0.05);
    /// ```
    #[must_use]
    pub const fn min_dist(mut self, d: f64) -> Self {
        self.min_dist = d.clamp(0.0, 1.0);
        self
    }

    /// Scale of the embedded space. Controls cluster separation. Defaults to `1.0`.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_umap::Umap;
    ///
    /// let umap = Umap::new().spread(1.5);
    /// ```
    #[must_use]
    pub const fn spread(mut self, s: f64) -> Self {
        self.spread = s.max(0.01);
        self
    }

    /// Number of SGD optimisation epochs. Defaults to `500` for ≤10 000 points,
    /// `200` otherwise.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_umap::Umap;
    ///
    /// let umap = Umap::new().n_epochs(300);
    /// ```
    #[must_use]
    pub fn n_epochs(mut self, n: usize) -> Self {
        self.n_epochs = Some(n.max(1));
        self
    }

    /// Number of SGD epochs used when calling [`FittedUmap::transform`].
    ///
    /// Defaults to `100` (fewer epochs are needed since we only tune new points).
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_umap::Umap;
    ///
    /// let umap = Umap::new().n_transform_epochs(50);
    /// ```
    #[must_use]
    pub fn n_transform_epochs(mut self, n: usize) -> Self {
        self.n_transform_epochs = Some(n.max(1));
        self
    }

    /// Number of NN-Descent refinement iterations for approximate k-NN. Defaults to `10`.
    ///
    /// More iterations produce a more accurate neighbour graph at the cost of extra
    /// compute. Values between 5 and 20 cover most use cases.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_umap::Umap;
    ///
    /// let umap = Umap::new().n_nnd_iters(20);
    /// ```
    #[must_use]
    pub fn n_nnd_iters(mut self, n: usize) -> Self {
        self.n_nnd_iters = n.max(1);
        self
    }

    /// Initial SGD learning rate. Defaults to `1.0`.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_umap::Umap;
    ///
    /// let umap = Umap::new().learning_rate(0.5);
    /// ```
    #[must_use]
    pub const fn learning_rate(mut self, lr: f64) -> Self {
        self.learning_rate = lr.max(1e-8);
        self
    }

    /// Number of repulsive (negative) samples per attractive (positive) step.
    /// Defaults to `5`.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_umap::Umap;
    ///
    /// let umap = Umap::new().negative_sample_rate(10);
    /// ```
    #[must_use]
    pub fn negative_sample_rate(mut self, rate: usize) -> Self {
        self.negative_sample_rate = rate.max(1);
        self
    }

    /// Distance metric used in the high-dimensional space. Defaults to `Euclidean`.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_umap::{Umap, Metric};
    ///
    /// let umap = Umap::new().metric(Metric::Cosine);
    /// ```
    #[must_use]
    pub const fn metric(mut self, m: Metric) -> Self {
        self.metric = m;
        self
    }

    /// Seed for the internal PRNG. Identical seeds produce identical embeddings.
    /// Defaults to `42`.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_umap::Umap;
    ///
    /// let umap = Umap::new().random_seed(123);
    /// ```
    #[must_use]
    pub const fn random_seed(mut self, seed: u64) -> Self {
        self.random_seed = seed;
        self
    }

    /// Whether to use spectral initialisation (default: `true`).
    ///
    /// Spectral init places points using the leading eigenvectors of the normalised
    /// graph Laplacian, which often produces better convergence. Falls back to random
    /// init when the graph is disconnected.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_umap::Umap;
    ///
    /// let umap = Umap::new().spectral_init(false);
    /// ```
    #[must_use]
    pub const fn spectral_init(mut self, yes: bool) -> Self {
        self.use_spectral_init = yes;
        self
    }

    /// How to compute the k-nearest-neighbour graph. Defaults to [`KnnMethod::Auto`].
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_umap::{KnnMethod, Umap};
    ///
    /// let umap = Umap::new().knn_method(KnnMethod::NnDescent);
    /// ```
    #[must_use]
    pub const fn knn_method(mut self, method: KnnMethod) -> Self {
        self.knn_method = method;
        self
    }

    /// Relative weight of the label graph vs. the structure graph in supervised mode.
    ///
    /// `0.0` ignores labels (equivalent to unsupervised); `1.0` makes the label graph
    /// dominate. Defaults to `0.5`.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_umap::Umap;
    ///
    /// let umap = Umap::new().target_weight(0.8);
    /// ```
    #[must_use]
    pub const fn target_weight(mut self, w: f64) -> Self {
        self.target_weight = w.clamp(0.0, 1.0);
        self
    }

    /// Embeds `points` into a lower-dimensional space and returns a [`FittedUmap`]
    /// that can be used to transform new points.
    ///
    /// All points must have the same dimensionality. Prefer [`Umap::try_fit`],
    /// which reports invalid input as an error instead of panicking.
    ///
    /// # Panics
    ///
    /// Panics on any input [`Umap::try_fit`] rejects: empty, ragged or
    /// non-finite data, or `n_neighbors ≥ n_points`.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_umap::Umap;
    ///
    /// let points: Vec<Vec<f64>> = (0..20)
    ///     .map(|i| vec![i as f64, (i as f64).sin()])
    ///     .collect();
    ///
    /// let fitted = Umap::new().n_neighbors(5).n_epochs(100).fit(&points);
    /// assert_eq!(fitted.embedding.len(), 20);
    /// assert_eq!(fitted.embedding[0].len(), 2);
    /// ```
    #[must_use]
    pub fn fit(&self, points: &[Vec<f64>]) -> FittedUmap {
        or_panic(self.try_fit(points))
    }

    /// Fallible version of [`Umap::fit`]: validates the input and parameters
    /// and returns an error instead of panicking.
    ///
    /// # Errors
    ///
    /// [`UmapError::Empty`], [`UmapError::NoFeatures`],
    /// [`UmapError::DimensionMismatch`] (ragged rows), [`UmapError::NonFinite`],
    /// [`UmapError::TooFewSamples`] (`n_neighbors ≥ n_points`) or
    /// [`UmapError::InvalidParameter`] (a `NaN` parameter).
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_umap::{Umap, UmapError};
    ///
    /// let points = vec![vec![0.0, 1.0], vec![f64::NAN, 2.0], vec![3.0, 4.0]];
    /// let err = Umap::new().n_neighbors(2).try_fit(&points).unwrap_err();
    /// assert!(matches!(err, UmapError::NonFinite { row: 1, col: 0, .. }));
    /// ```
    pub fn try_fit(&self, points: &[Vec<f64>]) -> Result<FittedUmap, UmapError> {
        self.fit_inner(points, None)
    }

    /// Embeds `points` using label information to sharpen cluster boundaries.
    ///
    /// Builds a second graph connecting same-class neighbours, then merges it with
    /// the structure graph via fuzzy union. The relative influence is controlled by
    /// [`Umap::target_weight`].
    ///
    /// # Panics
    ///
    /// Panics on any input [`Umap::try_fit_supervised`] rejects, including
    /// `labels.len() != points.len()`.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_umap::Umap;
    ///
    /// let points = vec![
    ///     vec![0.0, 0.0], vec![0.1, 0.1], vec![0.0, 0.1],
    ///     vec![5.0, 5.0], vec![5.1, 5.0], vec![5.0, 5.1],
    /// ];
    /// let labels = vec![0i64, 0, 0, 1, 1, 1];
    ///
    /// let fitted = Umap::new().n_neighbors(2).n_epochs(50).fit_supervised(&points, &labels);
    /// assert_eq!(fitted.embedding.len(), 6);
    /// ```
    #[must_use]
    pub fn fit_supervised(&self, points: &[Vec<f64>], labels: &[i64]) -> FittedUmap {
        or_panic(self.try_fit_supervised(points, labels))
    }

    /// Fallible version of [`Umap::fit_supervised`].
    ///
    /// # Errors
    ///
    /// Everything [`Umap::try_fit`] reports, plus
    /// [`UmapError::LabelLengthMismatch`].
    pub fn try_fit_supervised(
        &self,
        points: &[Vec<f64>],
        labels: &[i64],
    ) -> Result<FittedUmap, UmapError> {
        let labels: Vec<Option<i64>> = labels.iter().copied().map(Some).collect();
        self.fit_inner(points, Some(&labels))
    }

    /// Semi-supervised embedding: like [`Umap::fit_supervised`], but points
    /// whose label is `None` are unlabelled and positioned by the data
    /// structure alone.
    ///
    /// # Errors
    ///
    /// Everything [`Umap::try_fit`] reports, plus
    /// [`UmapError::LabelLengthMismatch`].
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_umap::Umap;
    ///
    /// let points = vec![
    ///     vec![0.0, 0.0], vec![0.1, 0.1], vec![0.0, 0.1],
    ///     vec![5.0, 5.0], vec![5.1, 5.0], vec![5.0, 5.1],
    /// ];
    /// let labels = [Some(0), None, Some(0), Some(1), None, None];
    ///
    /// let fitted = Umap::new()
    ///     .n_neighbors(2)
    ///     .n_epochs(50)
    ///     .fit_semi_supervised(&points, &labels)?;
    /// assert_eq!(fitted.embedding.len(), 6);
    /// # Ok::<(), rune_umap::UmapError>(())
    /// ```
    pub fn fit_semi_supervised(
        &self,
        points: &[Vec<f64>],
        labels: &[Option<i64>],
    ) -> Result<FittedUmap, UmapError> {
        self.fit_inner(points, Some(labels))
    }

    fn validate_params(&self) -> Result<(), UmapError> {
        let checks = [
            ("min_dist", self.min_dist),
            ("spread", self.spread),
            ("learning_rate", self.learning_rate),
            ("target_weight", self.target_weight),
        ];
        for (name, value) in checks {
            if !value.is_finite() {
                return Err(UmapError::InvalidParameter {
                    name,
                    value,
                    reason: "must be finite",
                });
            }
        }
        Ok(())
    }

    fn fit_inner(
        &self,
        points: &[Vec<f64>],
        labels: Option<&[Option<i64>]>,
    ) -> Result<FittedUmap, UmapError> {
        self.validate_params()?;
        let n_features = quality::validate_matrix(points)?;
        let n = points.len();
        if self.n_neighbors >= n {
            return Err(UmapError::TooFewSamples {
                n_neighbors: self.n_neighbors,
                n_samples: n,
            });
        }
        if let Some(labs) = labels
            && labs.len() != n
        {
            return Err(UmapError::LabelLengthMismatch {
                labels: labs.len(),
                points: n,
            });
        }

        let n_epochs = self.n_epochs.unwrap_or(if n <= 10_000 { 500 } else { 200 });
        let n_transform_epochs = self.n_transform_epochs.unwrap_or(100);
        let (a, b) = params::fit_ab(self.min_dist, self.spread);

        let mut rng = rng::Rng::new(self.random_seed);
        let exact = match self.knn_method {
            KnnMethod::Exact => true,
            KnnMethod::NnDescent => false,
            KnnMethod::Auto => n <= knn::EXACT_MAX_POINTS,
        };
        let knn = if exact {
            nnd::exact(points, self.metric, self.n_neighbors)
        } else {
            nnd::build(
                points,
                self.metric,
                self.n_neighbors,
                self.n_nnd_iters,
                &mut rng,
            )
        };
        let mut edges = graph::build(&knn, self.n_neighbors, n);

        if let Some(labs) = labels {
            let label_edges = supervised::label_edges(
                points,
                self.metric,
                labs,
                self.n_neighbors,
                self.target_weight,
            );
            edges = supervised::merge_fuzzy(&edges, &label_edges);
        }

        edges.sort_unstable_by(|x, y| x.0.cmp(&y.0).then(x.1.cmp(&y.1)));

        let mut flat = if self.use_spectral_init {
            layout::spectral_init(&edges, n, self.n_components, &mut rng)
        } else {
            layout::init_random(n, self.n_components, &mut rng)
        };

        layout::optimize(
            &mut flat,
            &edges,
            &layout::OptimizeParams {
                n,
                nc: self.n_components,
                a,
                b,
                initial_lr: self.learning_rate,
                n_epochs,
                negative_sample_rate: self.negative_sample_rate,
            },
            &mut rng,
        );

        let embedding = flat
            .chunks_exact(self.n_components)
            .map(<[f64]>::to_vec)
            .collect();

        Ok(FittedUmap {
            embedding,
            train_flat: flat,
            train_points: points.to_vec(),
            n_features,
            n_neighbors: self.n_neighbors,
            nc: self.n_components,
            a,
            b,
            learning_rate: self.learning_rate,
            negative_sample_rate: self.negative_sample_rate,
            n_transform_epochs,
            metric: self.metric,
            random_seed: self.random_seed,
        })
    }
}

/// Unwraps the result of a fallible entry point for the legacy panicking API.
#[allow(
    clippy::panic,
    reason = "documented panicking wrappers kept for 0.1 API compatibility; try_* variants are fallible"
)]
fn or_panic<T>(r: Result<T, UmapError>) -> T {
    match r {
        Ok(v) => v,
        Err(e) => panic!("rune-umap: {e}"),
    }
}

/// The result of a completed UMAP embedding run, with the ability to embed new points.
#[derive(Clone, Debug)]
pub struct FittedUmap {
    /// The low-dimensional embedding: one inner `Vec<f64>` per input point,
    /// with length equal to `n_components`.
    pub embedding: Vec<Vec<f64>>,

    train_flat: Vec<f64>,
    train_points: Vec<Vec<f64>>,
    n_features: usize,
    n_neighbors: usize,
    nc: usize,
    a: f64,
    b: f64,
    learning_rate: f64,
    negative_sample_rate: usize,
    n_transform_epochs: usize,
    metric: Metric,
    random_seed: u64,
}

impl FittedUmap {
    /// Dimensionality of the embedding (`n_components`).
    #[must_use]
    pub const fn n_components(&self) -> usize {
        self.nc
    }

    /// Dimensionality of the input space the model was fitted on.
    #[must_use]
    pub const fn n_features(&self) -> usize {
        self.n_features
    }

    /// Number of training points.
    #[must_use]
    pub const fn n_samples(&self) -> usize {
        self.train_points.len()
    }

    /// The metric used in the input space.
    #[must_use]
    pub const fn metric(&self) -> Metric {
        self.metric
    }

    /// The fitted curve parameters `(a, b)` of the low-dimensional membership
    /// function `1 / (1 + a·d^(2b))`.
    #[must_use]
    pub const fn ab(&self) -> (f64, f64) {
        (self.a, self.b)
    }

    /// Projects `new_points` into the existing embedding space.
    ///
    /// Each new point is initialised at the weighted centroid of its nearest training
    /// neighbours, then refined with a short SGD pass (training points are held fixed).
    /// Prefer [`FittedUmap::try_transform`], which reports invalid input as an error.
    ///
    /// # Panics
    ///
    /// Panics on any input [`FittedUmap::try_transform`] rejects (wrong
    /// dimensionality or non-finite values).
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_umap::Umap;
    ///
    /// let train = vec![
    ///     vec![0.0, 0.0], vec![0.1, 0.1], vec![0.0, 0.1],
    ///     vec![5.0, 5.0], vec![5.1, 5.0], vec![5.0, 5.1],
    /// ];
    /// let fitted = Umap::new().n_neighbors(2).n_epochs(50).fit(&train);
    ///
    /// let new_pts = vec![vec![0.05, 0.05], vec![5.05, 5.05]];
    /// let coords = fitted.transform(&new_pts);
    /// assert_eq!(coords.len(), 2);
    /// assert_eq!(coords[0].len(), 2);
    /// ```
    #[must_use]
    pub fn transform(&self, new_points: &[Vec<f64>]) -> Vec<Vec<f64>> {
        or_panic(self.try_transform(new_points))
    }

    /// Fallible version of [`FittedUmap::transform`]. An empty input yields an
    /// empty output.
    ///
    /// # Errors
    ///
    /// [`UmapError::DimensionMismatch`] when a row's length differs from the
    /// training dimensionality, [`UmapError::NonFinite`] for `NaN`/`inf` values.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_umap::{Umap, UmapError};
    ///
    /// let train: Vec<Vec<f64>> = (0..10).map(|i| vec![f64::from(i), 0.0]).collect();
    /// let fitted = Umap::new().n_neighbors(3).n_epochs(30).try_fit(&train)?;
    /// assert!(matches!(
    ///     fitted.try_transform(&[vec![1.0, 2.0, 3.0]]),
    ///     Err(UmapError::DimensionMismatch { expected: 2, found: 3, .. })
    /// ));
    /// # Ok::<(), UmapError>(())
    /// ```
    pub fn try_transform(&self, new_points: &[Vec<f64>]) -> Result<Vec<Vec<f64>>, UmapError> {
        quality::validate_rows(new_points, self.n_features)?;
        let n_new = new_points.len();
        if n_new == 0 {
            return Ok(Vec::new());
        }

        let n_train = self.train_points.len();
        let k = self.n_neighbors.min(n_train);

        let knn = graph::knn_to_train(new_points, &self.train_points, k, self.metric);
        let nn_edges = graph::transform_edges(&knn, k);

        // Initialise each new point at the weighted centroid of its training neighbours
        let mut new_flat = vec![0.0f64; n_new * self.nc];
        for (i, neighbors) in knn.iter().enumerate() {
            let total_w: f64 = neighbors.iter().map(|(_, d)| 1.0 / (d + 1e-10)).sum();
            for &(j, d) in neighbors {
                let w = (1.0 / (d + 1e-10)) / total_w;
                for dim in 0..self.nc {
                    new_flat[i * self.nc + dim] = w.mul_add(
                        self.train_flat[j * self.nc + dim],
                        new_flat[i * self.nc + dim],
                    );
                }
            }
        }

        let mut rng = rng::Rng::new(self.random_seed.wrapping_add(0xdead_beef));

        layout::optimize_transform(
            &mut new_flat,
            &self.train_flat,
            &nn_edges,
            &layout::TransformParams {
                n_train,
                nc: self.nc,
                a: self.a,
                b: self.b,
                initial_lr: self.learning_rate,
                n_epochs: self.n_transform_epochs,
                negative_sample_rate: self.negative_sample_rate,
            },
            &mut rng,
        );

        Ok(new_flat
            .chunks_exact(self.nc)
            .map(<[f64]>::to_vec)
            .collect())
    }
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
        let fitted = Umap::new().n_neighbors(5).n_epochs(50).fit(&pts);
        assert_eq!(fitted.embedding.len(), 20);
        assert!(fitted.embedding.iter().all(|row| row.len() == 2));
    }

    #[test]
    fn three_components() {
        let pts = two_blobs(10);
        let fitted = Umap::new()
            .n_neighbors(5)
            .n_epochs(50)
            .n_components(3)
            .fit(&pts);
        assert!(fitted.embedding.iter().all(|row| row.len() == 3));
    }

    #[test]
    fn deterministic_with_same_seed() {
        let pts = two_blobs(10);
        let r1 = Umap::new()
            .n_neighbors(5)
            .n_epochs(50)
            .random_seed(7)
            .fit(&pts);
        let r2 = Umap::new()
            .n_neighbors(5)
            .n_epochs(50)
            .random_seed(7)
            .fit(&pts);
        for (a, b) in r1.embedding.iter().zip(&r2.embedding) {
            for (x, y) in a.iter().zip(b) {
                assert!((x - y).abs() < 1e-12, "embeddings differ with same seed");
            }
        }
    }

    #[test]
    fn different_seeds_differ() {
        let pts = two_blobs(10);
        let r1 = Umap::new()
            .n_neighbors(5)
            .n_epochs(50)
            .random_seed(1)
            .fit(&pts);
        let r2 = Umap::new()
            .n_neighbors(5)
            .n_epochs(50)
            .random_seed(2)
            .fit(&pts);
        let any_diff = r1
            .embedding
            .iter()
            .zip(&r2.embedding)
            .any(|(a, b)| a.iter().zip(b).any(|(x, y)| (x - y).abs() > 1e-12));
        assert!(
            any_diff,
            "different seeds should produce different embeddings"
        );
    }

    #[test]
    fn separation_preserved() {
        let pts = two_blobs(15);
        let fitted = Umap::new()
            .n_neighbors(5)
            .n_epochs(300)
            .random_seed(42)
            .fit(&pts);

        let centroid_a: Vec<f64> = (0..2)
            .map(|d| fitted.embedding[0..15].iter().map(|r| r[d]).sum::<f64>() / 15.0)
            .collect();
        let centroid_b: Vec<f64> = (0..2)
            .map(|d| fitted.embedding[15..30].iter().map(|r| r[d]).sum::<f64>() / 15.0)
            .collect();

        let sep = centroid_a
            .iter()
            .zip(&centroid_b)
            .map(|(a, b)| (a - b).powi(2))
            .sum::<f64>()
            .sqrt();

        assert!(
            sep > 3.0,
            "cluster centroids should be well separated, got {sep:.3}"
        );
    }

    #[test]
    fn cosine_metric() {
        let pts = two_blobs(10);
        let fitted = Umap::new()
            .n_neighbors(5)
            .n_epochs(50)
            .metric(Metric::Cosine)
            .fit(&pts);
        assert_eq!(fitted.embedding.len(), 20);
    }

    #[test]
    fn random_init() {
        let pts = two_blobs(10);
        let fitted = Umap::new()
            .n_neighbors(5)
            .n_epochs(50)
            .spectral_init(false)
            .fit(&pts);
        assert_eq!(fitted.embedding.len(), 20);
    }

    #[test]
    fn transform_output_shape() {
        let pts = two_blobs(10);
        let fitted = Umap::new().n_neighbors(5).n_epochs(50).fit(&pts);
        let new_pts = vec![vec![0.5, 0.5], vec![10.5, 10.5]];
        let coords = fitted.transform(&new_pts);
        assert_eq!(coords.len(), 2);
        assert!(coords.iter().all(|r| r.len() == 2));
    }

    #[test]
    fn supervised_output_shape() {
        let pts = two_blobs(10);
        let labels: Vec<i64> = (0..10).map(|_| 0).chain((0..10).map(|_| 1)).collect();
        let fitted = Umap::new()
            .n_neighbors(5)
            .n_epochs(50)
            .fit_supervised(&pts, &labels);
        assert_eq!(fitted.embedding.len(), 20);
    }

    #[test]
    fn fit_ab_default_params() {
        let (a, b) = params::fit_ab(0.1, 1.0);
        assert!((a - 1.577).abs() < 0.05, "a={a:.4} expected ~1.577");
        assert!((b - 0.895).abs() < 0.05, "b={b:.4} expected ~0.895");
    }
}
