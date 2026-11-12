//! K-Means++ clustering — partition points into k clusters with smart initialisation.
//!
//! This crate implements the classic K-Means algorithm with K-Means++ centroid
//! initialisation, which spreads the initial centroids across the data rather than
//! placing them randomly. Better initialisation leads to faster convergence and
//! consistently lower final inertia compared to random initialisation.
//!
//! Multiple restarts (`n_init`) guard against unfortunate seeds: all runs execute
//! independently with different seeds derived from `random_seed + restart_index`,
//! and the run with the lowest inertia is returned.
//!
//! # Features
//!
//! - K-Means++ initialisation: first centroid uniform-at-random, subsequent centroids
//!   sampled with probability proportional to D²(x) (squared distance to nearest
//!   already-chosen centroid)
//! - Two distance metrics: Euclidean and Manhattan
//! - Configurable convergence tolerance and iteration cap
//! - Multiple restarts with the best result kept
//! - Deterministic via `random_seed`
//! - Pure Rust, no unsafe, no external library dependencies
//!
//! # Quick Start
//!
//! ```rust
//! use rune_kmeans::{KMeans, Metric};
//!
//! // Two well-separated blobs
//! let points = vec![
//!     vec![1.0, 1.0], vec![1.2, 0.9], vec![0.9, 1.1],
//!     vec![9.0, 9.0], vec![9.1, 8.9], vec![8.8, 9.2],
//! ];
//!
//! let result = KMeans::new(2).random_seed(42).fit(&points);
//! assert_eq!(result.labels.len(), 6);
//! assert_eq!(result.centroids.len(), 2);
//!
//! // All points in blob A share one label; all points in blob B share the other
//! assert_eq!(result.labels[0], result.labels[1]);
//! assert_eq!(result.labels[1], result.labels[2]);
//! assert_eq!(result.labels[3], result.labels[4]);
//! assert_ne!(result.labels[0], result.labels[3]);
//! ```
//!
//! # CLI
//!
//! ```bash
//! rune-kmeans data.csv --k 3
//! cat data.csv | rune-kmeans - --k 5 --metric manhattan --seed 7
//! ```

mod distance;
mod rng;

pub use distance::Metric;

/// Builder for configuring and running K-Means++ clustering.
///
/// Construct with [`KMeans::new`], chain optional parameters, then call [`KMeans::fit`].
///
/// # Example
///
/// ```rust
/// use rune_kmeans::{KMeans, Metric};
///
/// let km = KMeans::new(3)
///     .max_iter(200)
///     .tol(1e-5)
///     .n_init(5)
///     .metric(Metric::Manhattan)
///     .random_seed(99);
/// ```
#[derive(Clone)]
pub struct KMeans {
    k: usize,
    max_iter: usize,
    tol: f64,
    n_init: usize,
    metric: Metric,
    random_seed: u64,
}

/// The result of a completed K-Means clustering run.
pub struct KMeansResult {
    /// Cluster index (0..k) assigned to each input point.
    pub labels: Vec<usize>,
    /// Final centroid positions, one `Vec<f64>` per cluster.
    pub centroids: Vec<Vec<f64>>,
    /// Sum of squared distances from each point to its assigned centroid.
    pub inertia: f64,
    /// Number of iterations taken in the winning restart.
    pub iterations: usize,
}

impl KMeans {
    /// Creates a new `KMeans` instance that will partition data into `k` clusters.
    ///
    /// | Parameter | Default |
    /// |---|---|
    /// | `max_iter` | 300 |
    /// | `tol` | 1e-4 |
    /// | `n_init` | 10 |
    /// | `metric` | Euclidean |
    /// | `random_seed` | 42 |
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_kmeans::KMeans;
    ///
    /// let km = KMeans::new(4);
    /// ```
    ///
    /// `k == 0` is treated as `k == 1` (a single cluster), since zero clusters
    /// cannot hold any point.
    #[must_use]
    pub const fn new(k: usize) -> Self {
        Self {
            k: if k == 0 { 1 } else { k },
            max_iter: 300,
            tol: 1e-4,
            n_init: 10,
            metric: Metric::Euclidean,
            random_seed: 42,
        }
    }

    /// Maximum number of assign/update iterations per restart. Defaults to `300`.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_kmeans::KMeans;
    ///
    /// let km = KMeans::new(3).max_iter(100);
    /// ```
    #[must_use]
    pub const fn max_iter(mut self, n: usize) -> Self {
        self.max_iter = n;
        self
    }

    /// Convergence tolerance: stops when the maximum centroid movement drops below
    /// this value. Defaults to `1e-4`.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_kmeans::KMeans;
    ///
    /// let km = KMeans::new(3).tol(1e-6);
    /// ```
    #[must_use]
    pub const fn tol(mut self, t: f64) -> Self {
        self.tol = t;
        self
    }

    /// Number of independent restarts. The result with the lowest inertia is kept.
    /// Defaults to `10`.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_kmeans::KMeans;
    ///
    /// let km = KMeans::new(3).n_init(5);
    /// ```
    #[must_use]
    pub fn n_init(mut self, n: usize) -> Self {
        self.n_init = n.max(1);
        self
    }

    /// Distance metric used for assignment and inertia. Defaults to `Euclidean`.
    ///
    /// > [!NOTE]
    /// > Cosine distance is not supported because the centroid update (arithmetic mean)
    /// > is not meaningful in angular space.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_kmeans::{KMeans, Metric};
    ///
    /// let km = KMeans::new(3).metric(Metric::Manhattan);
    /// ```
    #[must_use]
    pub const fn metric(mut self, m: Metric) -> Self {
        self.metric = m;
        self
    }

    /// Seed for the internal Xorshift64 PRNG. Identical seeds reproduce identical
    /// results. Defaults to `42`.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_kmeans::KMeans;
    ///
    /// let km = KMeans::new(3).random_seed(123);
    /// ```
    #[must_use]
    pub const fn random_seed(mut self, s: u64) -> Self {
        self.random_seed = s;
        self
    }

    /// Clusters `points` into `k` groups and returns the best result over all restarts.
    ///
    /// Each restart uses a seed derived from `random_seed + restart_index`, so results
    /// are fully deterministic. The restart with the lowest inertia is returned.
    ///
    /// # Panics
    ///
    /// Panics if `points` is empty or if `k > points.len()`.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_kmeans::KMeans;
    ///
    /// let points = vec![
    ///     vec![0.0, 0.0], vec![0.1, 0.0], vec![0.0, 0.1],
    ///     vec![5.0, 5.0], vec![5.1, 5.0], vec![5.0, 5.1],
    /// ];
    ///
    /// let result = KMeans::new(2).random_seed(1).fit(&points);
    /// assert_eq!(result.labels.len(), 6);
    /// assert_eq!(result.centroids.len(), 2);
    /// assert!(result.inertia >= 0.0);
    /// assert!(result.iterations > 0);
    /// ```
    #[must_use]
    pub fn fit(&self, points: &[Vec<f64>]) -> KMeansResult {
        assert!(!points.is_empty(), "points must not be empty");
        assert!(
            self.k <= points.len(),
            "k ({}) must not exceed the number of points ({})",
            self.k,
            points.len()
        );

        let run = |restart: usize| {
            let seed = self.random_seed.wrapping_add(restart as u64);
            let mut rng = rng::Rng::new(seed);
            self.run_once(points, &mut rng)
        };

        let mut best = run(0);
        for restart in 1..self.n_init {
            let candidate = run(restart);
            if candidate.inertia < best.inertia {
                best = candidate;
            }
        }
        best
    }

    fn run_once(&self, points: &[Vec<f64>], rng: &mut rng::Rng) -> KMeansResult {
        let mut centroids = kmeans_plus_plus_init(points, self.k, &self.metric, rng);
        let mut labels = vec![0usize; points.len()];
        let mut iterations = 0;

        for _ in 0..self.max_iter {
            iterations += 1;

            assign_labels(points, &centroids, &self.metric, &mut labels);

            let new_centroids = update_centroids(points, &labels, self.k, rng);

            let max_movement = centroids
                .iter()
                .zip(new_centroids.iter())
                .map(|(old, new)| distance::squared_euclidean(old, new).sqrt())
                .fold(0.0f64, f64::max);

            centroids = new_centroids;

            if max_movement < self.tol {
                break;
            }
        }

        let inertia = compute_inertia(points, &labels, &centroids, &self.metric);

        KMeansResult {
            labels,
            centroids,
            inertia,
            iterations,
        }
    }
}

/// K-Means++ centroid initialisation.
///
/// Picks the first centroid uniformly at random, then each subsequent centroid
/// with probability proportional to its squared distance to the nearest already-chosen
/// centroid. This spreads the initial centroids and reduces the chance of a poor start.
fn kmeans_plus_plus_init(
    points: &[Vec<f64>],
    k: usize,
    metric: &Metric,
    rng: &mut rng::Rng,
) -> Vec<Vec<f64>> {
    let mut centroids: Vec<Vec<f64>> = Vec::with_capacity(k);
    centroids.push(points[rng.next_usize(points.len())].clone());

    for _ in 1..k {
        let squared_distances: Vec<f64> = points
            .iter()
            .map(|point| min_squared_distance_to_centroids(point, &centroids, metric))
            .collect();

        let total_weight: f64 = squared_distances.iter().sum();
        let threshold = rng.next_f64() * total_weight;

        let next_index = weighted_sample(&squared_distances, threshold);
        centroids.push(points[next_index].clone());
    }

    centroids
}

/// Minimum squared distance from `point` to any centroid in `centroids`.
fn min_squared_distance_to_centroids(
    point: &[f64],
    centroids: &[Vec<f64>],
    metric: &Metric,
) -> f64 {
    centroids
        .iter()
        .map(|centroid| distance::squared_distance(metric, point, centroid))
        .fold(f64::INFINITY, f64::min)
}

/// Selects the index whose cumulative weight first exceeds `threshold`.
fn weighted_sample(weights: &[f64], threshold: f64) -> usize {
    let mut cumulative = 0.0;
    for (index, &weight) in weights.iter().enumerate() {
        cumulative += weight;
        if cumulative >= threshold {
            return index;
        }
    }
    weights.len() - 1
}

/// Assigns each point to the index of its nearest centroid.
fn assign_labels(
    points: &[Vec<f64>],
    centroids: &[Vec<f64>],
    metric: &Metric,
    labels: &mut [usize],
) {
    for (label, point) in labels.iter_mut().zip(points.iter()) {
        *label = nearest_centroid_index(point, centroids, metric);
    }
}

/// Index of the centroid closest to `point`.
fn nearest_centroid_index(point: &[f64], centroids: &[Vec<f64>], metric: &Metric) -> usize {
    centroids
        .iter()
        .enumerate()
        .map(|(index, centroid)| (index, distance::point_distance(metric, point, centroid)))
        .min_by(|(_, dist_a), (_, dist_b)| dist_a.total_cmp(dist_b))
        .map_or(0, |(index, _)| index)
}

/// Recomputes each centroid as the mean of its assigned points.
///
/// Empty clusters are reinitialised to a randomly chosen data point so that
/// the number of active clusters never drops below `k`.
#[allow(
    clippy::cast_precision_loss,
    reason = "counts and indices stay far below 2^52, so the f64 conversion is exact"
)]
fn update_centroids(
    points: &[Vec<f64>],
    labels: &[usize],
    k: usize,
    rng: &mut rng::Rng,
) -> Vec<Vec<f64>> {
    let dimensionality = points[0].len();
    let mut sums = vec![vec![0.0f64; dimensionality]; k];
    let mut counts = vec![0usize; k];

    for (point, &label) in points.iter().zip(labels.iter()) {
        for (sum_dim, &coord) in sums[label].iter_mut().zip(point.iter()) {
            *sum_dim += coord;
        }
        counts[label] += 1;
    }

    sums.into_iter()
        .zip(counts)
        .map(|(sum, count)| {
            if count == 0 {
                points[rng.next_usize(points.len())].clone()
            } else {
                sum.into_iter().map(|total| total / count as f64).collect()
            }
        })
        .collect()
}

/// Sum of squared distances from each point to its assigned centroid.
fn compute_inertia(
    points: &[Vec<f64>],
    labels: &[usize],
    centroids: &[Vec<f64>],
    metric: &Metric,
) -> f64 {
    points
        .iter()
        .zip(labels.iter())
        .map(|(point, &label)| distance::squared_distance(metric, point, &centroids[label]))
        .sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn blob_a() -> Vec<Vec<f64>> {
        vec![
            vec![0.0, 0.0],
            vec![0.1, 0.0],
            vec![0.0, 0.1],
            vec![0.1, 0.1],
            vec![0.05, 0.05],
        ]
    }

    fn blob_b() -> Vec<Vec<f64>> {
        vec![
            vec![10.0, 10.0],
            vec![10.1, 10.0],
            vec![10.0, 10.1],
            vec![10.1, 10.1],
            vec![10.05, 10.05],
        ]
    }

    fn two_blobs() -> Vec<Vec<f64>> {
        let mut pts = blob_a();
        pts.extend(blob_b());
        pts
    }

    #[allow(clippy::similar_names, reason = "parallel names for parallel fixtures")]
    #[test]
    fn two_blobs_separate_correctly() {
        let points = two_blobs();
        let result = KMeans::new(2).random_seed(42).fit(&points);

        assert_eq!(result.labels.len(), 10);
        assert_eq!(result.centroids.len(), 2);

        let blob_a_label = result.labels[0];
        for &label in &result.labels[0..5] {
            assert_eq!(
                label, blob_a_label,
                "all blob-A points must share one label"
            );
        }
        let blob_b_label = result.labels[5];
        for &label in &result.labels[5..10] {
            assert_eq!(
                label, blob_b_label,
                "all blob-B points must share one label"
            );
        }
        assert_ne!(
            blob_a_label, blob_b_label,
            "the two blobs must get different labels"
        );
    }

    #[allow(
        clippy::cast_precision_loss,
        reason = "counts and indices stay far below 2^52, so the f64 conversion is exact"
    )]
    #[test]
    fn k1_all_same_label_and_inertia_matches_global_mean() {
        let points = two_blobs();
        let result = KMeans::new(1).random_seed(1).fit(&points);

        assert!(
            result.labels.iter().all(|&l| l == 0),
            "k=1 must assign label 0 to every point"
        );

        let dim = points[0].len();
        let n = points.len() as f64;
        let global_mean: Vec<f64> = (0..dim)
            .map(|d| points.iter().map(|p| p[d]).sum::<f64>() / n)
            .collect();

        let expected_inertia: f64 = points
            .iter()
            .map(|p| distance::squared_euclidean(p, &global_mean))
            .sum();

        assert!(
            (result.inertia - expected_inertia).abs() < 1e-9,
            "inertia={:.6} expected={:.6}",
            result.inertia,
            expected_inertia
        );
    }

    #[test]
    fn deterministic_with_same_seed() {
        let points = two_blobs();
        let result_a = KMeans::new(2).random_seed(7).fit(&points);
        let result_b = KMeans::new(2).random_seed(7).fit(&points);

        assert_eq!(result_a.labels, result_b.labels);
        assert_eq!(result_a.iterations, result_b.iterations);
        assert!((result_a.inertia - result_b.inertia).abs() < 1e-12);
        for (ca, cb) in result_a.centroids.iter().zip(result_b.centroids.iter()) {
            for (x, y) in ca.iter().zip(cb.iter()) {
                assert!((x - y).abs() < 1e-12, "centroids differ with same seed");
            }
        }
    }

    #[allow(clippy::similar_names, reason = "parallel names for parallel fixtures")]
    #[test]
    fn different_seeds_same_cluster_structure() {
        let points = two_blobs();
        let result_a = KMeans::new(2).random_seed(1).fit(&points);
        let result_b = KMeans::new(2).random_seed(2).fit(&points);

        let group_a_label_in_a = result_a.labels[0];
        let group_b_label_in_a = result_a.labels[5];
        let group_a_label_in_b = result_b.labels[0];
        let group_b_label_in_b = result_b.labels[5];

        for i in 0..5 {
            assert_eq!(result_a.labels[i], group_a_label_in_a);
            assert_eq!(result_b.labels[i], group_a_label_in_b);
        }
        for i in 5..10 {
            assert_eq!(result_a.labels[i], group_b_label_in_a);
            assert_eq!(result_b.labels[i], group_b_label_in_b);
        }
        assert_ne!(group_a_label_in_a, group_b_label_in_a);
        assert_ne!(group_a_label_in_b, group_b_label_in_b);
    }

    #[allow(clippy::similar_names, reason = "parallel names for parallel fixtures")]
    #[test]
    fn manhattan_metric_clusters_correctly() {
        let points = two_blobs();
        let result = KMeans::new(2)
            .metric(Metric::Manhattan)
            .random_seed(42)
            .fit(&points);

        let blob_a_label = result.labels[0];
        let blob_b_label = result.labels[5];
        assert_ne!(blob_a_label, blob_b_label);
        for &label in &result.labels[0..5] {
            assert_eq!(label, blob_a_label);
        }
        for &label in &result.labels[5..10] {
            assert_eq!(label, blob_b_label);
        }
    }

    #[test]
    fn result_fields_are_valid() {
        let points = two_blobs();
        let result = KMeans::new(2).random_seed(42).fit(&points);

        assert!(result.inertia >= 0.0, "inertia must be non-negative");
        assert!(result.iterations >= 1, "must take at least one iteration");
        assert!(result.iterations <= 300, "must not exceed max_iter");
        assert!(
            result.labels.iter().all(|&l| l < 2),
            "labels must be in 0..k"
        );
        assert!(
            result.centroids.iter().all(|c| c.len() == 2),
            "centroids must match input dimensionality"
        );
    }

    #[test]
    fn n_init_one_is_valid() {
        let points = two_blobs();
        let result = KMeans::new(2).n_init(1).random_seed(42).fit(&points);
        assert_eq!(result.labels.len(), 10);
    }

    #[test]
    fn k_equals_n_points() {
        let points = vec![vec![1.0], vec![2.0], vec![3.0]];
        let result = KMeans::new(3).n_init(1).fit(&points);
        assert_eq!(result.labels.len(), 3);
        let label_set: std::collections::HashSet<usize> = result.labels.iter().copied().collect();
        assert_eq!(label_set.len(), 3, "each point must be its own cluster");
    }
}
