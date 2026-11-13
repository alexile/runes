//! Embedding quality measures shared by the dimensionality-reduction crates.

use crate::{Float, MatrixView, Metric, MlError};

/// Trustworthiness of an embedding (Venna & Kaski, 2001), in `[0, 1]`.
///
/// For every point, looks at its `k` nearest neighbours in the embedding
/// `low` and penalises each one that was not among its `k` nearest
/// neighbours in the original space `high`, by how far down the original
/// ranking it sits. `1.0` means every embedded neighbourhood is faithful;
/// a random embedding scores around `0.5`. Matches
/// `sklearn.manifold.trustworthiness`:
///
/// ```text
/// T(k) = 1 − 2 / (n·k·(2n − 3k − 1)) · Σᵢ Σ_{j ∈ Nₖ(i)} max(0, r(i, j) − k)
/// ```
///
/// where `r(i, j)` is the rank of `j` among `i`'s neighbours in `high`.
///
/// `metric` is used in the original space; the embedding is always measured
/// with the Euclidean distance. Ties are broken by the lower row index. The
/// runtime is `O(n² log n)` with `O(n)` memory per row, so this is meant for
/// evaluation and tests rather than very large data sets. With the `rayon`
/// feature the rows are processed in parallel; the result does not depend on
/// the thread count.
///
/// # Errors
///
/// - [`MlError::TooFewSamples`] for fewer than 3 rows;
/// - [`MlError::DimensionMismatch`] if `high` and `low` have different row
///   counts;
/// - [`MlError::NonFinite`] for a NaN or infinite value in either matrix;
/// - [`MlError::InvalidParameter`] unless `1 ≤ k < n / 2`.
///
/// # Example
///
/// ```
/// use rune_ml_core::{trustworthiness, Matrix, Metric};
///
/// let high = Matrix::from_rows(&[[0.0, 0.0], [1.0, 0.1], [2.0, 0.0], [3.0, 0.1], [4.0, 0.0], [5.0, 0.1]])?;
/// // Dropping the tiny second coordinate keeps every neighbourhood.
/// let low = Matrix::from_rows(&[[0.0], [1.0], [2.0], [3.0], [4.0], [5.0]])?;
/// let t = trustworthiness(high.view(), low.view(), 2, Metric::Euclidean)?;
/// assert!((t - 1.0).abs() < 1e-12);
/// # Ok::<(), rune_ml_core::MlError>(())
/// ```
#[allow(
    clippy::cast_precision_loss,
    reason = "counts and ranks stay far below 2^52, so the f64 conversion is exact"
)]
pub fn trustworthiness<F: Float>(
    high: MatrixView<'_, F>,
    low: MatrixView<'_, F>,
    k: usize,
    metric: Metric,
) -> Result<f64, MlError> {
    let n = high.nrows();
    if n < 3 {
        return Err(MlError::TooFewSamples { needed: 3, got: n });
    }
    if low.nrows() != n {
        return Err(MlError::DimensionMismatch {
            expected: n,
            found: low.nrows(),
        });
    }
    high.check_finite()?;
    low.check_finite()?;
    if k == 0 || 2 * k >= n {
        return Err(MlError::invalid_parameter(
            "k",
            format!("must satisfy 1 <= k < n_samples / 2, got {k} for {n} samples"),
        ));
    }

    let row_penalty = |i: usize| -> usize {
        // rank[j] = 1-based position of j in i's original-space ordering.
        let a = high.row(i);
        let mut order: Vec<(usize, f64)> = (0..n)
            .filter(|&j| j != i)
            .map(|j| (j, metric.distance(a, high.row(j)).to_f64()))
            .collect();
        order.sort_unstable_by(|x, y| x.1.total_cmp(&y.1).then(x.0.cmp(&y.0)));
        let mut rank = vec![0usize; n];
        for (r, &(j, _)) in order.iter().enumerate() {
            rank[j] = r + 1;
        }
        let b = low.row(i);
        let mut near: Vec<(usize, f64)> = (0..n)
            .filter(|&j| j != i)
            .map(|j| (j, Metric::SqEuclidean.distance(b, low.row(j)).to_f64()))
            .collect();
        let by = |x: &(usize, f64), y: &(usize, f64)| x.1.total_cmp(&y.1).then(x.0.cmp(&y.0));
        near.select_nth_unstable_by(k - 1, by);
        near[..k]
            .iter()
            .map(|&(j, _)| rank[j].saturating_sub(k))
            .sum()
    };

    #[cfg(feature = "rayon")]
    let penalty: usize = {
        use rayon::prelude::*;
        (0..n).into_par_iter().map(row_penalty).sum()
    };
    #[cfg(not(feature = "rayon"))]
    let penalty: usize = (0..n).map(row_penalty).sum();

    let (n_f, k_f) = (n as f64, k as f64);
    let norm = 2.0 / (n_f * k_f * (3.0f64.mul_add(-k_f, 2.0 * n_f) - 1.0));
    Ok(norm.mul_add(-(penalty as f64), 1.0))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Matrix;

    fn line(f: impl Fn(f64) -> f64) -> Matrix<f64> {
        let rows: Vec<[f64; 1]> = (0..30).map(|i| [f(f64::from(i))]).collect();
        Matrix::from_rows(&rows).unwrap()
    }

    #[test]
    fn identity_and_reversal_are_perfect() {
        let high = line(|x| x);
        let rev = line(|x| -x);
        for low in [&high, &rev] {
            let t = trustworthiness(high.view(), low.view(), 3, Metric::Euclidean).unwrap();
            assert!((t - 1.0).abs() < 1e-12);
        }
    }

    #[test]
    fn shuffled_embedding_scores_low() {
        let high = line(|x| x);
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let shuffled = line(|x| ((x as u32 * 11) % 30).into());
        let t = trustworthiness(high.view(), shuffled.view(), 3, Metric::Euclidean).unwrap();
        assert!(t < 0.9, "t = {t}");
    }

    /// Tie-free hand computation, k = 1: X = [0, 1, 3, 7, 12] and
    /// Y = [0, 3, 1, 7, 12] (rows 1 and 2 swapped). Embedded nearest
    /// neighbours and their original ranks: 0→2 (rank 2), 1→2 (rank 2),
    /// 2→0 (rank 2), 3→1 (rank 3), 4→3 (rank 1). Penalty 1+1+1+2+0 = 5,
    /// normaliser 2 / (5·1·(10 − 3 − 1)) = 1/15, so T = 1 − 5/15 = 2/3.
    #[test]
    fn known_value() {
        let x = Matrix::from_rows(&[[0.0], [1.0], [3.0], [7.0], [12.0]]).unwrap();
        let y = Matrix::from_rows(&[[0.0], [3.0], [1.0], [7.0], [12.0]]).unwrap();
        let t = trustworthiness(x.view(), y.view(), 1, Metric::Euclidean).unwrap();
        assert!((t - 2.0 / 3.0).abs() < 1e-12, "t = {t}");
    }

    #[test]
    fn rejects_bad_input() {
        let a = line(|x| x);
        assert!(trustworthiness(a.view(), a.view(), 0, Metric::Euclidean).is_err());
        assert!(trustworthiness(a.view(), a.view(), 15, Metric::Euclidean).is_err());
        let short = Matrix::from_rows(&[[0.0], [1.0], [2.0], [3.0]]).unwrap();
        assert!(trustworthiness(a.view(), short.view(), 1, Metric::Euclidean).is_err());
        let nan = Matrix::from_rows(&[[0.0], [f64::NAN], [2.0], [3.0], [4.0]]).unwrap();
        let ok = Matrix::from_rows(&[[0.0], [1.0], [2.0], [3.0], [4.0]]).unwrap();
        assert!(trustworthiness(nan.view(), ok.view(), 1, Metric::Euclidean).is_err());
    }
}
