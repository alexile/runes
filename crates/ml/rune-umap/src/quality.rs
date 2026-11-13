use rune_ml_core::{Matrix, Metric as CoreMetric};

use crate::distance::Metric;
use crate::error::UmapError;

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
/// This is a thin wrapper over [`rune_ml_core::trustworthiness`], so scores
/// agree with the other dimensionality-reduction runes. It takes nested
/// vectors and this crate's [`Metric`]; [`Metric::Correlation`] is computed as
/// the cosine distance between mean-centred rows, which is the same thing.
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
    reason = "k is small, so the f64 conversion in the error is exact"
)]
pub fn trustworthiness(
    high: &[Vec<f64>],
    low: &[Vec<f64>],
    k: usize,
    metric: Metric,
) -> Result<f64, UmapError> {
    // Validate here first so callers keep getting this crate's error variants.
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

    let (core_metric, high) = match metric {
        Metric::Euclidean => (CoreMetric::Euclidean, Matrix::from_rows(high)?),
        Metric::Manhattan => (CoreMetric::Manhattan, Matrix::from_rows(high)?),
        Metric::Cosine => (CoreMetric::Cosine, Matrix::from_rows(high)?),
        Metric::Correlation => (CoreMetric::Cosine, centred_rows(high)?),
    };
    let low = Matrix::from_rows(low)?;
    Ok(rune_ml_core::trustworthiness(
        high.view(),
        low.view(),
        k,
        core_metric,
    )?)
}

/// Copies `rows` into a matrix with each row shifted to zero mean.
#[allow(
    clippy::cast_precision_loss,
    reason = "dimensionality stays far below 2^52, so the f64 conversion is exact"
)]
fn centred_rows(rows: &[Vec<f64>]) -> Result<Matrix<f64>, UmapError> {
    let mut m = Matrix::from_rows(rows)?;
    for row in m.rows_mut() {
        let mean = row.iter().sum::<f64>() / row.len() as f64;
        for v in row.iter_mut() {
            *v -= mean;
        }
    }
    Ok(m)
}

#[cfg(test)]
#[allow(clippy::suboptimal_flops, reason = "readable test formulas")]
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

    /// Hand-computed, tie-free case shared with `rune-ml-core`: rows 1 and 2
    /// swapped in a 1-D embedding of `[0, 1, 3, 7, 12]` gives `T(1) = 2/3`.
    #[test]
    fn known_value() {
        let x: Vec<Vec<f64>> = [0.0, 1.0, 3.0, 7.0, 12.0].map(|v| vec![v]).to_vec();
        let y: Vec<Vec<f64>> = [0.0, 3.0, 1.0, 7.0, 12.0].map(|v| vec![v]).to_vec();
        let t = trustworthiness(&x, &y, 1, Metric::Euclidean).unwrap();
        assert!((t - 2.0 / 3.0).abs() < 1e-12, "t = {t}");
    }

    /// The core-backed score must agree with a direct O(n²) reference using
    /// this crate's own distances, for every metric including correlation.
    #[test]
    fn matches_reference_for_every_metric() {
        let high: Vec<Vec<f64>> = (0..24)
            .map(|i| {
                let f = f64::from(i);
                vec![
                    f.sin() * 3.0,
                    (f * 0.7).cos() + f * 0.1,
                    (f * 1.3).sin() - 0.5,
                ]
            })
            .collect();
        let low: Vec<Vec<f64>> = high.iter().map(|p| vec![p[0] + 0.3 * p[2], p[1]]).collect();
        for metric in Metric::ALL {
            for k in [1, 3, 5] {
                let got = trustworthiness(&high, &low, k, metric).unwrap();
                let want = reference(&high, &low, k, metric);
                assert!(
                    (got - want).abs() < 1e-12,
                    "{metric} k={k}: {got} vs {want}"
                );
            }
        }
    }

    #[allow(clippy::cast_precision_loss, reason = "tiny test sizes")]
    fn reference(high: &[Vec<f64>], low: &[Vec<f64>], k: usize, metric: Metric) -> f64 {
        use crate::nnd::{by_dist, knn_of};
        let n = high.len();
        let mut penalty = 0usize;
        for i in 0..n {
            let mut order = knn_of(&high[i], high, Some(i), metric, n - 1);
            order.sort_unstable_by(by_dist);
            let mut rank = vec![0usize; n];
            for (r, &(j, _)) in order.iter().enumerate() {
                rank[j] = r + 1;
            }
            penalty += knn_of(&low[i], low, Some(i), Metric::Euclidean, k)
                .iter()
                .map(|&(j, _)| rank[j].saturating_sub(k))
                .sum::<usize>();
        }
        let (n, k) = (n as f64, k as f64);
        1.0 - 2.0 / (n * k * (2.0 * n - 3.0 * k - 1.0)) * penalty as f64
    }
}
