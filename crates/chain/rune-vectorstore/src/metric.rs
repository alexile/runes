//! Similarity metrics.

use crate::StoreError;

/// How two vectors are compared.
///
/// Every metric produces a *score* where **higher means more similar**, so
/// results from any metric sort the same way.
///
/// | Metric                  | Score                     | Range        |
/// | ----------------------- | ------------------------- | ------------ |
/// | [`Metric::Cosine`]      | cosine of the angle       | `[-1, 1]`    |
/// | [`Metric::DotProduct`]  | inner product             | unbounded    |
/// | [`Metric::Euclidean`]   | negated L2 distance       | `(-inf, 0]`  |
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Metric {
    /// Cosine similarity. Zero vectors are rejected because their angle is
    /// undefined. This is the right default for most text embeddings.
    #[default]
    Cosine,
    /// Raw dot product. Equal to cosine for unit-length vectors, and cheaper.
    DotProduct,
    /// Negated Euclidean (L2) distance.
    Euclidean,
}

impl Metric {
    /// Score `a` against `b` with this metric.
    ///
    /// Both slices must have the same length; extra trailing elements of the
    /// longer one are ignored. Use [`Metric::score`] on validated input (every
    /// index in this crate validates before scoring).
    ///
    /// # Example
    ///
    /// ```
    /// use rune_vectorstore::Metric;
    ///
    /// assert!((Metric::Cosine.score(&[1.0, 0.0], &[2.0, 0.0]) - 1.0).abs() < 1e-6);
    /// assert_eq!(Metric::DotProduct.score(&[1.0, 2.0], &[3.0, 4.0]), 11.0);
    /// assert_eq!(Metric::Euclidean.score(&[0.0, 0.0], &[3.0, 4.0]), -5.0);
    /// ```
    #[must_use]
    pub fn score(self, a: &[f32], b: &[f32]) -> f32 {
        match self {
            Self::Cosine => cosine(a, b),
            Self::DotProduct => dot(a, b),
            Self::Euclidean => -euclidean(a, b),
        }
    }

    /// Score with precomputed norms (`‖a‖`, `‖b‖`); only cosine uses them.
    pub(crate) fn score_with_norms(self, a: &[f32], na: f32, b: &[f32], nb: f32) -> f32 {
        match self {
            Self::Cosine => {
                if na == 0.0 || nb == 0.0 {
                    0.0
                } else {
                    dot(a, b) / (na * nb)
                }
            }
            Self::DotProduct => dot(a, b),
            Self::Euclidean => -euclidean(a, b),
        }
    }

    /// Check that `v` can be used with this metric.
    pub(crate) fn validate(self, v: &[f32]) -> Result<f32, StoreError> {
        if v.is_empty() {
            return Err(StoreError::InvalidVector("vector is empty"));
        }
        if v.iter().any(|x| !x.is_finite()) {
            return Err(StoreError::InvalidVector("vector contains NaN or infinity"));
        }
        let n = norm(v);
        if !n.is_finite() {
            return Err(StoreError::InvalidVector("vector norm overflows f32"));
        }
        if self == Self::Cosine && n == 0.0 {
            return Err(StoreError::InvalidVector(
                "zero vector has no direction under the cosine metric",
            ));
        }
        Ok(n)
    }
}

/// Dot product of two vectors.
///
/// # Example
///
/// ```
/// assert_eq!(rune_vectorstore::dot(&[1.0, 2.0, 3.0], &[4.0, 5.0, 6.0]), 32.0);
/// ```
#[must_use]
pub fn dot(a: &[f32], b: &[f32]) -> f32 {
    a.iter().zip(b).map(|(x, y)| x * y).sum()
}

/// Euclidean (L2) norm of a vector.
///
/// # Example
///
/// ```
/// assert_eq!(rune_vectorstore::norm(&[3.0, 4.0]), 5.0);
/// ```
#[must_use]
pub fn norm(v: &[f32]) -> f32 {
    dot(v, v).sqrt()
}

/// Cosine similarity of two vectors; `0.0` if either has zero length.
///
/// # Example
///
/// ```
/// let s = rune_vectorstore::cosine(&[1.0, 0.0], &[0.0, 1.0]);
/// assert!(s.abs() < 1e-6);
/// ```
#[must_use]
pub fn cosine(a: &[f32], b: &[f32]) -> f32 {
    Metric::Cosine.score_with_norms(a, norm(a), b, norm(b))
}

/// Euclidean (L2) distance between two vectors.
///
/// # Example
///
/// ```
/// assert_eq!(rune_vectorstore::euclidean(&[0.0, 0.0], &[3.0, 4.0]), 5.0);
/// ```
#[must_use]
pub fn euclidean(a: &[f32], b: &[f32]) -> f32 {
    a.iter()
        .zip(b)
        .map(|(x, y)| (x - y) * (x - y))
        .sum::<f32>()
        .sqrt()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cosine_of_parallel_and_orthogonal() {
        assert!((cosine(&[1.0, 1.0], &[2.0, 2.0]) - 1.0).abs() < 1e-6);
        assert!((cosine(&[1.0, 0.0], &[-1.0, 0.0]) + 1.0).abs() < 1e-6);
        assert!(cosine(&[1.0, 0.0], &[0.0, 3.0]).abs() < 1e-6);
        assert!(cosine(&[0.0, 0.0], &[1.0, 0.0]).abs() < f32::EPSILON);
    }

    #[test]
    fn euclidean_score_is_negated_distance() {
        assert!((Metric::Euclidean.score(&[1.0, 1.0], &[4.0, 5.0]) + 5.0).abs() < 1e-6);
    }

    #[test]
    fn validation() {
        assert!(Metric::Cosine.validate(&[]).is_err());
        assert!(Metric::Cosine.validate(&[0.0, 0.0]).is_err());
        assert!(Metric::DotProduct.validate(&[0.0, 0.0]).is_ok());
        assert!(Metric::Euclidean.validate(&[f32::NAN]).is_err());
        assert!(Metric::Euclidean.validate(&[f32::INFINITY]).is_err());
        assert!(Metric::Euclidean.validate(&[f32::MAX, f32::MAX]).is_err());
        assert!((Metric::Cosine.validate(&[3.0, 4.0]).unwrap() - 5.0).abs() < 1e-6);
    }
}
