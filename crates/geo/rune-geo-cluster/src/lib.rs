//! Spatial clustering of latitude/longitude point sets.
//!
//! A thin geo-domain wrapper around the general-purpose [`rune-kmeans`](rune_kmeans) and
//! [`rune-hdbscan`](rune_hdbscan) crates: it accepts `&[(f64, f64)]` lat/lon pairs directly
//! instead of the raw `Vec<Vec<f64>>` shape those crates expect, and returns a
//! plain label-per-point vector. The clustering math itself is entirely
//! delegated — this crate's value is the ergonomic geo-flavored API surface,
//! not a reimplementation.
//!
//! # Features
//!
//! - [`cluster_kmeans`] — partition points into exactly `k` clusters via
//!   K-Means++ (delegates to `rune_kmeans::KMeans`).
//! - [`cluster_hdbscan`] — density-based clustering that also detects noise
//!   points, with no need to choose `k` up front (delegates to
//!   `rune_hdbscan::Hdbscan`).
//! - Coordinates are treated as a plain 2D Euclidean plane (lat, lon) — fine
//!   for clustering points that are close together, but it does not correct
//!   for the distortion of lat/lon coordinates over long distances the way a
//!   great-circle distance metric would.
//!
//! # Quick Start
//!
//! ```rust
//! use rune_geo_cluster::{cluster_kmeans, cluster_hdbscan};
//!
//! let points = [
//!     (60.170, 24.938), (60.171, 24.939), (60.169, 24.937),
//!     (60.451, 22.267), (60.452, 22.266), (60.450, 22.268),
//! ];
//!
//! let labels = cluster_kmeans(&points, 2);
//! assert_eq!(labels.len(), 6);
//! assert_eq!(labels[0], labels[1]);
//! assert_ne!(labels[0], labels[3]);
//!
//! let hdb_labels = cluster_hdbscan(&points, 3);
//! assert_eq!(hdb_labels.len(), 6);
//! ```
//!
//! # CLI
//!
//! ```bash
//! rune-geo-cluster points.csv --method kmeans --k 3
//! rune-geo-cluster points.csv --method hdbscan --min-cluster-size 5
//! ```

use rune_hdbscan::Hdbscan;
use rune_kmeans::KMeans;

fn to_rows(points: &[(f64, f64)]) -> Vec<Vec<f64>> {
    points.iter().map(|&(lat, lon)| vec![lat, lon]).collect()
}

/// Partitions `points` into exactly `k` clusters using K-Means++.
///
/// Returns one cluster index (`0..k`) per input point, in the same order as
/// `points`. Internally converts each `(lat, lon)` pair into the `Vec<f64>`
/// row shape `rune_kmeans::KMeans` expects.
///
/// # Panics
///
/// Panics if `points` is empty or if `k > points.len()`, per
/// `rune_kmeans::KMeans::fit`.
///
/// # Example
///
/// ```rust
/// use rune_geo_cluster::cluster_kmeans;
///
/// let points = [
///     (0.0, 0.0), (0.01, 0.01), (0.02, 0.0),
///     (10.0, 10.0), (10.01, 10.01), (10.02, 10.0),
/// ];
///
/// let labels = cluster_kmeans(&points, 2);
/// assert_eq!(labels[0], labels[1]);
/// assert_eq!(labels[1], labels[2]);
/// assert_ne!(labels[0], labels[3]);
/// ```
#[must_use]
pub fn cluster_kmeans(points: &[(f64, f64)], k: usize) -> Vec<usize> {
    let rows = to_rows(points);
    KMeans::new(k).fit(&rows).labels
}

/// Clusters `points` by density using HDBSCAN, with no need to choose the
/// number of clusters up front.
///
/// Returns one label per input point, in the same order as `points`: a
/// non-negative cluster index, or `-1` for points classified as noise.
/// Internally converts each `(lat, lon)` pair into the `Vec<f64>` row shape
/// `rune_hdbscan::Hdbscan` expects.
///
/// # Panics
///
/// Panics if `points` is empty, per `rune_hdbscan::Hdbscan::fit`.
///
/// # Example
///
/// ```rust
/// use rune_geo_cluster::cluster_hdbscan;
///
/// let points = [
///     (0.0, 0.0), (0.01, 0.01), (0.02, 0.0), (0.0, 0.02), (0.01, 0.015),
///     (9.0, 9.0), (9.01, 9.02), (9.0, 8.99), (8.99, 9.01), (9.02, 9.0),
/// ];
///
/// let labels = cluster_hdbscan(&points, 3);
/// assert_eq!(labels.len(), 10);
/// assert_eq!(labels[0], labels[1]);
/// assert_ne!(labels[0], labels[5]);
/// ```
#[must_use]
pub fn cluster_hdbscan(points: &[(f64, f64)], min_cluster_size: usize) -> Vec<i32> {
    let rows = to_rows(points);
    Hdbscan::new(min_cluster_size).fit(&rows).labels
}

#[cfg(test)]
mod tests {
    use super::*;

    fn two_blobs() -> Vec<(f64, f64)> {
        vec![
            (0.0, 0.0),
            (0.01, 0.0),
            (0.0, 0.01),
            (0.01, 0.01),
            (0.005, 0.005),
            (10.0, 10.0),
            (10.01, 10.0),
            (10.0, 10.01),
            (10.01, 10.01),
            (10.005, 10.005),
        ]
    }

    #[allow(clippy::similar_names, reason = "parallel names for parallel fixtures")]
    #[test]
    fn kmeans_separates_two_blobs() {
        let points = two_blobs();
        let labels = cluster_kmeans(&points, 2);
        assert_eq!(labels.len(), 10);

        let blob_a_label = labels[0];
        for &label in &labels[0..5] {
            assert_eq!(label, blob_a_label);
        }
        let blob_b_label = labels[5];
        for &label in &labels[5..10] {
            assert_eq!(label, blob_b_label);
        }
        assert_ne!(blob_a_label, blob_b_label);
    }

    #[test]
    fn kmeans_k1_all_same_label() {
        let points = two_blobs();
        let labels = cluster_kmeans(&points, 1);
        assert!(labels.iter().all(|&l| l == 0));
    }

    #[test]
    #[should_panic(expected = "points must not be empty")]
    fn kmeans_panics_on_empty_points() {
        let points: [(f64, f64); 0] = [];
        let _ = cluster_kmeans(&points, 1);
    }

    #[allow(clippy::similar_names, reason = "parallel names for parallel fixtures")]
    #[test]
    fn hdbscan_separates_two_blobs_and_labels_are_contiguous() {
        let points = two_blobs();
        let labels = cluster_hdbscan(&points, 3);
        assert_eq!(labels.len(), 10);

        let blob_a_label = labels[0];
        let blob_b_label = labels[5];
        assert_ne!(blob_a_label, blob_b_label);
        for &label in &labels[0..5] {
            assert_eq!(label, blob_a_label);
        }
        for &label in &labels[5..10] {
            assert_eq!(label, blob_b_label);
        }
    }

    #[test]
    fn hdbscan_marks_sparse_input_as_noise() {
        let points = vec![(0.0, 0.0), (50.0, 50.0)];
        let labels = cluster_hdbscan(&points, 5);
        assert!(labels.iter().all(|&l| l == -1));
    }

    #[test]
    fn to_rows_preserves_order_and_shape() {
        let points = [(1.0, 2.0), (3.0, 4.0)];
        let rows = to_rows(&points);
        assert_eq!(rows, vec![vec![1.0, 2.0], vec![3.0, 4.0]]);
    }
}
