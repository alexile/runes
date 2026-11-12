//! HDBSCAN clustering — hierarchical density-based clustering with automatic noise detection.
//!
//! HDBSCAN (Hierarchical Density-Based Spatial Clustering of Applications with Noise)
//! improves on DBSCAN by converting it into a hierarchical algorithm and extracting flat
//! clusters via a stability criterion. Unlike DBSCAN, it requires no global density
//! threshold `ε`, making it robust to datasets where clusters vary in density.
//!
//! The algorithm:
//! 1. Computes *core distances* (distance to each point's `k`-th nearest neighbour).
//! 2. Builds a minimum spanning tree on the *mutual reachability graph*.
//! 3. Converts the MST into a cluster hierarchy (dendrogram).
//! 4. Condenses the hierarchy, discarding components below `min_cluster_size`.
//! 5. Selects flat clusters by maximising cluster stability bottom-up.
//!
//! # Features
//!
//! - Automatic noise labelling (label `-1`)
//! - Handles variable-density clusters
//! - Soft membership probabilities (`0.0`–`1.0`)
//! - Three distance metrics: Euclidean, Manhattan, Cosine
//! - Pure Rust, no unsafe, no external dependencies in the library
//!
//! # Quick Start
//!
//! ```rust
//! use rune_hdbscan::{Hdbscan, Metric};
//!
//! let points = vec![
//!     vec![1.0, 2.0], vec![1.5, 1.8], vec![1.2, 1.9], vec![1.3, 2.1], vec![1.1, 1.7],
//!     vec![8.0, 8.0], vec![8.5, 8.2], vec![8.1, 8.3], vec![8.3, 7.9], vec![8.2, 8.1],
//! ];
//!
//! let result = Hdbscan::new(3).fit(&points);
//! assert_eq!(result.num_clusters, 2);
//! for (label, prob) in result.labels.iter().zip(&result.probabilities) {
//!     println!("cluster {label:>2}  prob {prob:.3}");
//! }
//! ```
//!
//! # CLI
//!
//! ```bash
//! rune-hdbscan data.csv --min-cluster-size 5
//! rune-hdbscan data.csv --min-cluster-size 5 --metric cosine --probs
//! cat data.csv | rune-hdbscan -
//! ```

mod cluster;
mod distance;
mod mst;
mod tree;

pub use distance::Metric;

/// Builder for configuring and running HDBSCAN clustering.
///
/// Construct with [`Hdbscan::new`], chain optional parameters, then call [`Hdbscan::fit`].
///
/// # Example
///
/// ```rust
/// use rune_hdbscan::{Hdbscan, Metric};
///
/// let hdb = Hdbscan::new(5)
///     .min_samples(3)
///     .metric(Metric::Manhattan);
/// ```
pub struct Hdbscan {
    min_cluster_size: usize,
    min_samples: usize,
    metric: Metric,
}

impl Hdbscan {
    /// Creates a new HDBSCAN instance.
    ///
    /// `min_cluster_size` is the minimum number of points needed for a group to
    /// qualify as a cluster. Smaller values produce more, smaller clusters. A
    /// value of `5` is a good starting point for most datasets.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_hdbscan::Hdbscan;
    ///
    /// let hdb = Hdbscan::new(5);
    /// ```
    #[must_use]
    pub fn new(min_cluster_size: usize) -> Self {
        let min_cluster_size = min_cluster_size.max(2);
        Self {
            min_samples: min_cluster_size,
            min_cluster_size,
            metric: Metric::Euclidean,
        }
    }

    /// Sets `min_samples` — the neighbourhood size used to compute core distances.
    ///
    /// Defaults to `min_cluster_size`. Higher values make the algorithm more
    /// conservative about which points are "core" members, increasing the noise
    /// fraction and tightening clusters.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_hdbscan::Hdbscan;
    ///
    /// let hdb = Hdbscan::new(5).min_samples(3);
    /// ```
    #[must_use]
    pub fn min_samples(mut self, n: usize) -> Self {
        self.min_samples = n.max(1);
        self
    }

    /// Sets the distance metric.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_hdbscan::{Hdbscan, Metric};
    ///
    /// let hdb = Hdbscan::new(5).metric(Metric::Cosine);
    /// ```
    #[must_use]
    pub const fn metric(mut self, m: Metric) -> Self {
        self.metric = m;
        self
    }

    /// Clusters `points` and returns labels and membership probabilities.
    ///
    /// All points must have the same dimensionality. Points not assigned to any
    /// cluster receive label `-1` and probability `0.0`.
    ///
    /// Runtime is `O(n²)` — suitable for datasets up to ~10 000 points.
    /// An empty `points` slice yields an empty result with no clusters.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_hdbscan::Hdbscan;
    ///
    /// let points = vec![
    ///     vec![0.0, 0.0], vec![0.1, 0.1], vec![0.2, 0.0], vec![0.0, 0.2], vec![0.1, 0.15],
    ///     vec![9.0, 9.0], vec![9.1, 9.2], vec![9.0, 8.9], vec![8.9, 9.1], vec![9.2, 9.0],
    /// ];
    /// let result = Hdbscan::new(3).fit(&points);
    /// assert_eq!(result.num_clusters, 2);
    /// assert!(result.labels[0] == result.labels[1]);
    /// assert!(result.labels[0] != result.labels[5]);
    /// ```
    #[allow(
        clippy::cast_sign_loss,
        reason = "the value is non-negative and bounded by the input size; float-to-int `as` saturates"
    )]
    #[must_use]
    pub fn fit(&self, points: &[Vec<f64>]) -> ClusterResult {
        let n = points.len();

        if n < self.min_cluster_size {
            return ClusterResult {
                labels: vec![-1; n],
                probabilities: vec![0.0; n],
                num_clusters: 0,
            };
        }

        let core_dists = distance::core_distances(points, &self.metric, self.min_samples);
        let mst_edges = mst::build(points, &self.metric, &core_dists);
        let merges = tree::build_dendrogram(n, &mst_edges);
        let condensed = tree::condense(&merges, n, self.min_cluster_size);
        let (labels, probabilities) = cluster::extract(&condensed, n);
        let num_clusters = labels
            .iter()
            .filter(|&&l| l >= 0)
            .max()
            .map_or(0, |&m| m as usize + 1);

        ClusterResult {
            labels,
            probabilities,
            num_clusters,
        }
    }
}

/// Result of a completed HDBSCAN clustering run.
pub struct ClusterResult {
    /// Cluster label for each input point. `-1` means the point is noise.
    ///
    /// Labels are contiguous integers starting at `0`.
    pub labels: Vec<i32>,
    /// Soft membership probability for each point, in `[0.0, 1.0]`.
    ///
    /// Noise points have probability `0.0`. Points near a cluster core have
    /// probabilities close to `1.0`; fringe points have lower values.
    pub probabilities: Vec<f64>,
    /// Number of clusters found (not counting noise).
    pub num_clusters: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn two_blobs() -> Vec<Vec<f64>> {
        let mut points = Vec::new();
        for i in 0..10 {
            let offset = f64::from(i) * 0.1;
            points.push(vec![offset, offset]);
        }
        for i in 0..10 {
            let offset = f64::from(i) * 0.1;
            points.push(vec![10.0 + offset, 10.0 + offset]);
        }
        points
    }

    #[test]
    fn finds_two_clusters() {
        let points = two_blobs();
        let result = Hdbscan::new(3).fit(&points);
        assert_eq!(result.num_clusters, 2);
        assert_eq!(result.labels.len(), 20);
        // All points from each blob should share the same label
        let first_blob_label = result.labels[0];
        let second_blob_label = result.labels[10];
        assert_ne!(first_blob_label, second_blob_label);
        for i in 0..10 {
            assert_eq!(
                result.labels[i], first_blob_label,
                "blob 1 point {i} mislabelled"
            );
            assert_eq!(
                result.labels[i + 10],
                second_blob_label,
                "blob 2 point {i} mislabelled"
            );
        }
    }

    #[test]
    fn too_few_points_returns_noise() {
        let points = vec![vec![0.0], vec![1.0]];
        let result = Hdbscan::new(5).fit(&points);
        assert_eq!(result.num_clusters, 0);
        assert!(result.labels.iter().all(|&l| l == -1));
    }

    #[test]
    fn probabilities_in_range() {
        let points = two_blobs();
        let result = Hdbscan::new(3).fit(&points);
        for &p in &result.probabilities {
            assert!((0.0..=1.0).contains(&p), "probability {p} out of range");
        }
    }

    #[test]
    fn manhattan_metric_clusters() {
        let points = two_blobs();
        let result = Hdbscan::new(3).metric(Metric::Manhattan).fit(&points);
        assert_eq!(result.num_clusters, 2);
    }

    #[test]
    fn cosine_metric_clusters() {
        // Two groups of direction vectors
        let mut points: Vec<Vec<f64>> = (0..5)
            .map(|i| vec![f64::mul_add(f64::from(i), 0.01, 1.0), 0.0])
            .collect();
        points.extend((0..5).map(|i| vec![0.0, f64::mul_add(f64::from(i), 0.01, 1.0)]));
        let result = Hdbscan::new(2).metric(Metric::Cosine).fit(&points);
        assert_eq!(result.num_clusters, 2);
    }
}
