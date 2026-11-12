use rayon::prelude::*;

use crate::distance::{Metric, point_distance};
use crate::error::UmapError;
use crate::nnd::{by_dist, knn_of};

/// Checks that `points` is a non-empty, rectangular, finite matrix and returns
/// its number of columns.
pub fn validate_matrix(points: &[Vec<f64>]) -> Result<usize, UmapError> {
    let first = points.first().ok_or(UmapError::Empty)?;
    let dim = first.len();
    if dim == 0 {
        return Err(UmapError::NoFeatures);
    }
    validate_rows(points, dim)?;
    Ok(dim)
}

/// Checks that every row has exactly `dim` finite values.
pub fn validate_rows(points: &[Vec<f64>], dim: usize) -> Result<(), UmapError> {
    for (row, p) in points.iter().enumerate() {
        if p.len() != dim {
            return Err(UmapError::DimensionMismatch {
                index: row,
                found: p.len(),
                expected: dim,
            });
        }
        if let Some((col, &value)) = p.iter().enumerate().find(|(_, v)| !v.is_finite()) {
            return Err(UmapError::NonFinite { row, col, value });
        }
    }
    Ok(())
}

/// Trustworthiness of an embedding (Venna & Kaski, 2001), in `[0, 1]`.
///
/// Measures how many of each point's `k` nearest neighbours in the embedding
/// were also near it in the original space, penalising intruders by how far
/// down the original ranking they sit. `1.0` means every embedded
/// neighbourhood is faithful. Matches `sklearn.manifold.trustworthiness`.
///
/// `metric` is used in the original space; the embedding is measured with the
/// Euclidean distance. Runtime is O(n² log n), so this is meant for tests and
/// evaluation rather than very large datasets.
///
/// # Errors
///
/// Returns an error when either matrix is empty, ragged or non-finite, when
/// they have different numbers of rows, or when `k` is `0` or `k ≥ n / 2`.
///
/// # Example
///
/// ```rust
/// use rune_umap::{trustworthiness, Metric};
///
/// let high = vec![vec![0.0, 0.0, 0.0], vec![1.0, 0.0, 0.0], vec![2.0, 0.0, 0.0],
///                 vec![3.0, 0.0, 0.0], vec![4.0, 0.0, 0.0], vec![5.0, 0.0, 0.0]];
/// let low: Vec<Vec<f64>> = high.iter().map(|p| vec![p[0]]).collect();
/// let t = trustworthiness(&high, &low, 2, Metric::Euclidean).unwrap();
/// assert!((t - 1.0).abs() < 1e-12);
/// ```
#[allow(
    clippy::cast_precision_loss,
    reason = "counts and ranks stay far below 2^52, so the f64 conversion is exact"
)]
pub fn trustworthiness(
    high: &[Vec<f64>],
    low: &[Vec<f64>],
    k: usize,
    metric: Metric,
) -> Result<f64, UmapError> {
    validate_matrix(high)?;
    validate_matrix(low)?;
    let n = high.len();
    if low.len() != n {
        return Err(UmapError::DimensionMismatch {
            index: low.len().min(n),
            found: low.len(),
            expected: n,
        });
    }
    if k == 0 || 2 * k >= n {
        return Err(UmapError::InvalidParameter {
            name: "k",
            value: k as f64,
            reason: "must satisfy 1 <= k < n_samples / 2",
        });
    }

    let penalty: usize = (0..n)
        .into_par_iter()
        .map(|i| {
            // rank[j] = position of j in i's original-space ordering (1-based).
            let mut order: Vec<(usize, f64)> = (0..n)
                .filter(|&j| j != i)
                .map(|j| (j, point_distance(metric, &high[i], &high[j])))
                .collect();
            order.sort_unstable_by(by_dist);
            let mut rank = vec![0usize; n];
            for (r, &(j, _)) in order.iter().enumerate() {
                rank[j] = r + 1;
            }
            knn_of(&low[i], low, Some(i), Metric::Euclidean, k)
                .iter()
                .map(|&(j, _)| rank[j].saturating_sub(k))
                .sum::<usize>()
        })
        .sum();

    let (n_f, k_f) = (n as f64, k as f64);
    // 2 / (n·k·(2n − 3k − 1))
    let norm = 2.0 / (n_f * k_f * (3.0f64.mul_add(-k_f, 2.0 * n_f) - 1.0));
    Ok(norm.mul_add(-(penalty as f64), 1.0))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_embedding_is_perfect() {
        let pts: Vec<Vec<f64>> = (0..20)
            .map(|i| vec![f64::from(i), f64::from(i * i % 7)])
            .collect();
        let t = trustworthiness(&pts, &pts, 5, Metric::Euclidean).unwrap();
        assert!((t - 1.0).abs() < 1e-12);
    }

    #[test]
    fn reversed_line_is_still_perfect_but_shuffle_is_not() {
        let high: Vec<Vec<f64>> = (0..30).map(|i| vec![f64::from(i)]).collect();
        let rev: Vec<Vec<f64>> = (0..30).map(|i| vec![-f64::from(i)]).collect();
        assert!((trustworthiness(&high, &rev, 3, Metric::Euclidean).unwrap() - 1.0).abs() < 1e-12);
        let shuffled: Vec<Vec<f64>> = (0..30).map(|i| vec![f64::from((i * 11) % 30)]).collect();
        assert!(trustworthiness(&high, &shuffled, 3, Metric::Euclidean).unwrap() < 0.9);
    }

    #[test]
    fn rejects_bad_k() {
        let pts: Vec<Vec<f64>> = (0..6).map(|i| vec![f64::from(i)]).collect();
        assert!(trustworthiness(&pts, &pts, 0, Metric::Euclidean).is_err());
        assert!(trustworthiness(&pts, &pts, 3, Metric::Euclidean).is_err());
        assert!(trustworthiness(&pts, &pts[..5], 2, Metric::Euclidean).is_err());
    }
}
