//! The shared distance [`Metric`] and pairwise distance helpers.

use core::fmt;
use core::str::FromStr;

use crate::{Float, Matrix, MatrixView, MlError, kernels};

/// A distance between two feature vectors.
///
/// Parses from and displays as the lower-case names `euclidean`,
/// `sqeuclidean`, `manhattan`, `cosine` and `chebyshev` (also accepted:
/// `l2`, `l1`, `cityblock`, `linf`, `sq_euclidean`).
///
/// ```
/// use rune_ml_core::Metric;
///
/// let m: Metric = "manhattan".parse()?;
/// assert_eq!(m.distance(&[0.0, 0.0], &[3.0, 4.0]), 7.0);
/// assert_eq!(Metric::Euclidean.distance(&[0.0_f32, 0.0], &[3.0, 4.0]), 5.0);
/// # Ok::<(), rune_ml_core::MlError>(())
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "lowercase"))]
#[non_exhaustive]
pub enum Metric {
    /// `√Σ (aᵢ − bᵢ)²`.
    #[default]
    Euclidean,
    /// `Σ (aᵢ − bᵢ)²` — not a true metric (no triangle inequality), but
    /// order-equivalent to Euclidean and cheaper.
    SqEuclidean,
    /// `Σ |aᵢ − bᵢ|`.
    Manhattan,
    /// `1 − a·b / (‖a‖·‖b‖)`, in `[0, 2]`. Not a true metric. See
    /// [`kernels::cosine`] for the zero-vector convention.
    Cosine,
    /// `max |aᵢ − bᵢ|`.
    Chebyshev,
}

impl Metric {
    /// Every metric, in declaration order.
    pub const ALL: [Self; 5] = [
        Self::Euclidean,
        Self::SqEuclidean,
        Self::Manhattan,
        Self::Cosine,
        Self::Chebyshev,
    ];

    /// Distance between `a` and `b`, over the first `min(len)` coordinates.
    #[inline]
    #[must_use]
    pub fn distance<F: Float>(self, a: &[F], b: &[F]) -> F {
        match self {
            Self::Euclidean => kernels::euclidean(a, b),
            Self::SqEuclidean => kernels::sq_euclidean(a, b),
            Self::Manhattan => kernels::manhattan(a, b),
            Self::Cosine => kernels::cosine(a, b),
            Self::Chebyshev => kernels::chebyshev(a, b),
        }
    }

    /// Like [`distance`](Self::distance) but rejects inputs of different length.
    pub fn try_distance<F: Float>(self, a: &[F], b: &[F]) -> Result<F, MlError> {
        if a.len() == b.len() {
            Ok(self.distance(a, b))
        } else {
            Err(MlError::DimensionMismatch {
                expected: a.len(),
                found: b.len(),
            })
        }
    }

    /// `true` if the triangle inequality holds (Euclidean, Manhattan,
    /// Chebyshev), which tree-based indexes and pruning rely on.
    #[must_use]
    pub const fn is_true_metric(self) -> bool {
        matches!(self, Self::Euclidean | Self::Manhattan | Self::Chebyshev)
    }

    /// The canonical lower-case name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Euclidean => "euclidean",
            Self::SqEuclidean => "sqeuclidean",
            Self::Manhattan => "manhattan",
            Self::Cosine => "cosine",
            Self::Chebyshev => "chebyshev",
        }
    }

    /// Index and distance of the row of `data` nearest to `query`; `None`
    /// if `data` has no rows. Ties go to the lowest index.
    pub fn nearest<F: Float>(
        self,
        query: &[F],
        data: MatrixView<'_, F>,
    ) -> Result<Option<(usize, F)>, MlError> {
        check_dim(data.ncols(), query.len())?;
        let mut best: Option<(usize, F)> = None;
        for (i, r) in data.rows().enumerate() {
            let d = self.distance(query, r);
            if best.is_none_or(|(_, b)| d < b) {
                best = Some((i, d));
            }
        }
        Ok(best)
    }

    /// Symmetric `n x n` matrix of distances between all rows of `data`.
    ///
    /// Computes the upper triangle once and mirrors it. With the `rayon`
    /// feature the rows are processed in parallel.
    pub fn pairwise<F: Float>(self, data: MatrixView<'_, F>) -> Result<Matrix<F>, MlError> {
        let n = data.nrows();
        let mut out = Matrix::zeros(n, n)?;
        if n == 0 {
            return Ok(out);
        }
        let fill = |i: usize, row: &mut [F]| {
            let a = data.row(i);
            for (j, slot) in row.iter_mut().enumerate().skip(i + 1) {
                *slot = self.distance(a, data.row(j));
            }
        };
        #[cfg(feature = "rayon")]
        {
            use rayon::prelude::*;
            out.as_mut_slice()
                .par_chunks_mut(n)
                .enumerate()
                .for_each(|(i, row)| fill(i, row));
        }
        #[cfg(not(feature = "rayon"))]
        for (i, row) in out.rows_mut().enumerate() {
            fill(i, row);
        }
        let buf = out.as_mut_slice();
        for i in 0..n {
            for j in 0..i {
                buf[i * n + j] = buf[j * n + i];
            }
        }
        Ok(out)
    }

    /// `a.nrows() x b.nrows()` matrix of distances from every row of `a` to
    /// every row of `b`. Parallel over rows of `a` with the `rayon` feature.
    pub fn cdist<F: Float>(
        self,
        a: MatrixView<'_, F>,
        b: MatrixView<'_, F>,
    ) -> Result<Matrix<F>, MlError> {
        check_dim(a.ncols(), b.ncols())?;
        let m = b.nrows();
        let mut out = Matrix::zeros(a.nrows(), m)?;
        if m == 0 {
            return Ok(out);
        }
        let fill = |i: usize, row: &mut [F]| {
            let x = a.row(i);
            for (slot, y) in row.iter_mut().zip(b.rows()) {
                *slot = self.distance(x, y);
            }
        };
        #[cfg(feature = "rayon")]
        {
            use rayon::prelude::*;
            out.as_mut_slice()
                .par_chunks_mut(m)
                .enumerate()
                .for_each(|(i, row)| fill(i, row));
        }
        #[cfg(not(feature = "rayon"))]
        for (i, row) in out.rows_mut().enumerate() {
            fill(i, row);
        }
        Ok(out)
    }
}

const fn check_dim(expected: usize, found: usize) -> Result<(), MlError> {
    if expected == found {
        Ok(())
    } else {
        Err(MlError::DimensionMismatch { expected, found })
    }
}

impl fmt::Display for Metric {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

impl FromStr for Metric {
    type Err = MlError;

    fn from_str(s: &str) -> Result<Self, MlError> {
        match s.trim().to_ascii_lowercase().as_str() {
            "euclidean" | "l2" => Ok(Self::Euclidean),
            "sqeuclidean" | "sq_euclidean" | "sq-euclidean" => Ok(Self::SqEuclidean),
            "manhattan" | "l1" | "cityblock" => Ok(Self::Manhattan),
            "cosine" => Ok(Self::Cosine),
            "chebyshev" | "linf" => Ok(Self::Chebyshev),
            other => Err(MlError::invalid_parameter(
                "metric",
                format!(
                    "unknown metric `{other}` (expected euclidean, sqeuclidean, manhattan, cosine or chebyshev)"
                ),
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_round_trip() {
        for m in Metric::ALL {
            assert_eq!(m.to_string().parse::<Metric>(), Ok(m));
        }
        assert_eq!("L1".parse::<Metric>(), Ok(Metric::Manhattan));
        assert!("hamming".parse::<Metric>().is_err());
    }

    #[test]
    fn try_distance_checks_length() {
        assert!(
            Metric::Euclidean
                .try_distance(&[1.0_f64], &[1.0, 2.0])
                .is_err()
        );
        assert_eq!(
            Metric::Chebyshev.try_distance(&[1.0_f64, 5.0], &[2.0, 2.0]),
            Ok(3.0)
        );
    }

    #[test]
    fn pairwise_and_cdist() {
        let m = Matrix::from_rows(&[[0.0_f64, 0.0], [3.0, 4.0], [6.0, 8.0]]).unwrap();
        let d = Metric::Euclidean.pairwise(m.view()).unwrap();
        assert_eq!(
            d.to_rows(),
            vec![
                vec![0.0, 5.0, 10.0],
                vec![5.0, 0.0, 5.0],
                vec![10.0, 5.0, 0.0]
            ]
        );
        let c = Metric::Euclidean.cdist(m.view(), m.view()).unwrap();
        assert_eq!(c, d);
        let q = Matrix::from_rows(&[[1.0_f64]]).unwrap();
        assert!(Metric::Euclidean.cdist(m.view(), q.view()).is_err());
    }

    #[test]
    fn nearest_row() {
        let m = Matrix::from_rows(&[[0.0_f64, 0.0], [3.0, 4.0], [6.0, 8.0]]).unwrap();
        assert_eq!(
            Metric::Manhattan.nearest(&[5.0, 7.0], m.view()),
            Ok(Some((2, 2.0)))
        );
        let empty = Matrix::<f64>::zeros(0, 2).unwrap();
        assert_eq!(
            Metric::Manhattan.nearest(&[5.0, 7.0], empty.view()),
            Ok(None)
        );
        assert!(Metric::Manhattan.nearest(&[5.0], m.view()).is_err());
    }
}
