//! Vector helpers: cosine similarity, dot product, L2 norm and normalization.
//!
//! The `try_*` functions return [`EmbedError::DimensionMismatch`] when the
//! operands differ in length; the infallible ones compare the common prefix
//! (kept for compatibility with 0.1).

use crate::EmbedError;

/// Computes the cosine similarity between two embedding vectors.
///
/// Returns a value in `[-1.0, 1.0]` where `1.0` means the vectors are
/// identical in direction and `-1.0` means they point in opposite directions.
/// Returns `0.0` if either vector has zero magnitude.
///
/// Vectors of different lengths are compared over their common prefix (the
/// magnitudes still use every element); use [`try_cosine_similarity`] to get
/// an error instead.
///
/// # Examples
///
/// ```rust
/// use rune_chain_embed::cosine_similarity;
///
/// let a = vec![1.0, 0.0, 0.0];
/// let b = vec![1.0, 0.0, 0.0];
/// assert!((cosine_similarity(&a, &b) - 1.0).abs() < 1e-6);
///
/// let c = vec![-1.0, 0.0, 0.0];
/// assert!((cosine_similarity(&a, &c) + 1.0).abs() < 1e-6);
/// ```
#[must_use]
pub fn cosine_similarity(a: &[f32], b: &[f32]) -> f32 {
    let dot: f32 = a.iter().zip(b).map(|(x, y)| x * y).sum();
    let mag_a = l2_norm(a);
    let mag_b = l2_norm(b);
    if mag_a == 0.0 || mag_b == 0.0 {
        return 0.0;
    }
    dot / (mag_a * mag_b)
}

/// [`cosine_similarity`] that rejects operands of different lengths.
///
/// # Errors
///
/// [`EmbedError::DimensionMismatch`] when `a.len() != b.len()`.
///
/// ```rust
/// use rune_chain_embed::{EmbedError, try_cosine_similarity};
///
/// assert!(try_cosine_similarity(&[1.0, 0.0], &[2.0, 0.0]).unwrap() > 0.999);
/// assert!(matches!(
///     try_cosine_similarity(&[1.0, 0.0], &[1.0]),
///     Err(EmbedError::DimensionMismatch { expected: 2, actual: 1 })
/// ));
/// ```
pub fn try_cosine_similarity(a: &[f32], b: &[f32]) -> Result<f32, EmbedError> {
    check_dims(a, b)?;
    Ok(cosine_similarity(a, b))
}

/// The dot product of two vectors. For unit vectors (see [`normalize`]) it
/// equals the cosine similarity and is cheaper to compute.
///
/// # Errors
///
/// [`EmbedError::DimensionMismatch`] when `a.len() != b.len()`.
///
/// ```rust
/// use rune_chain_embed::dot;
///
/// assert_eq!(dot(&[1.0, 2.0], &[3.0, 4.0]).unwrap(), 11.0);
/// ```
pub fn dot(a: &[f32], b: &[f32]) -> Result<f32, EmbedError> {
    check_dims(a, b)?;
    Ok(a.iter().zip(b).map(|(x, y)| x * y).sum())
}

/// The Euclidean (L2) norm of a vector.
///
/// ```rust
/// use rune_chain_embed::l2_norm;
///
/// assert_eq!(l2_norm(&[3.0, 4.0]), 5.0);
/// ```
#[must_use]
pub fn l2_norm(v: &[f32]) -> f32 {
    v.iter().map(|x| x * x).sum::<f32>().sqrt()
}

/// Scale `v` in place to unit length. A zero (or non-finite-norm) vector is
/// left unchanged. Returns the original norm.
///
/// ```rust
/// use rune_chain_embed::{l2_norm, normalize};
///
/// let mut v = vec![3.0, 4.0];
/// assert_eq!(normalize(&mut v), 5.0);
/// assert_eq!(v, vec![0.6, 0.8]);
/// assert!((l2_norm(&v) - 1.0).abs() < 1e-6);
/// ```
pub fn normalize(v: &mut [f32]) -> f32 {
    let norm = l2_norm(v);
    if norm > 0.0 && norm.is_finite() {
        for x in v.iter_mut() {
            *x /= norm;
        }
    }
    norm
}

/// Check that every vector has `expected` dimensions (or, with `None`, the
/// same length as the first one).
///
/// # Errors
///
/// [`EmbedError::DimensionMismatch`] for the first vector that differs.
///
/// ```rust
/// use rune_chain_embed::check_dimensions;
///
/// assert!(check_dimensions(&[vec![0.0; 3], vec![1.0; 3]], Some(3)).is_ok());
/// assert!(check_dimensions(&[vec![0.0; 3], vec![1.0; 2]], None).is_err());
/// ```
pub fn check_dimensions(vectors: &[Vec<f32>], expected: Option<usize>) -> Result<(), EmbedError> {
    let Some(expected) = expected.or_else(|| vectors.first().map(Vec::len)) else {
        return Ok(());
    };
    vectors
        .iter()
        .find(|v| v.len() != expected)
        .map_or(Ok(()), |v| {
            Err(EmbedError::DimensionMismatch {
                expected,
                actual: v.len(),
            })
        })
}

const fn check_dims(a: &[f32], b: &[f32]) -> Result<(), EmbedError> {
    if a.len() == b.len() {
        Ok(())
    } else {
        Err(EmbedError::DimensionMismatch {
            expected: a.len(),
            actual: b.len(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cosine_similarity_known_values() {
        assert!((cosine_similarity(&[1.0, 0.0], &[0.0, 1.0])).abs() < 1e-6);
        assert!((cosine_similarity(&[1.0, 1.0], &[2.0, 2.0]) - 1.0).abs() < 1e-6);
        assert!(
            (cosine_similarity(&[1.0, 0.0], &[1.0, 1.0]) - std::f32::consts::FRAC_1_SQRT_2).abs()
                < 1e-6
        );
        assert!((cosine_similarity(&[3.0, -4.0], &[-3.0, 4.0]) + 1.0).abs() < 1e-6);
    }

    #[test]
    fn cosine_similarity_zero_vector_is_zero() {
        assert!(cosine_similarity(&[0.0, 0.0], &[1.0, 2.0]).abs() < f32::EPSILON);
        assert!(cosine_similarity(&[], &[]).abs() < f32::EPSILON);
    }

    #[test]
    fn mismatched_lengths_error_instead_of_panicking() {
        assert!(matches!(
            dot(&[1.0], &[1.0, 2.0]),
            Err(EmbedError::DimensionMismatch {
                expected: 1,
                actual: 2
            })
        ));
        assert!(try_cosine_similarity(&[1.0], &[]).is_err());
        assert!(check_dimensions(&[vec![1.0, 2.0]], Some(3)).is_err());
        assert!(check_dimensions(&[], Some(3)).is_ok());
        assert!(check_dimensions(&[], None).is_ok());
    }

    #[test]
    fn normalize_unit_and_zero() {
        let mut v = vec![0.0, 0.0];
        assert_eq!(normalize(&mut v), 0.0);
        assert_eq!(v, vec![0.0, 0.0]);
        let mut w = vec![1.0, 1.0, 1.0, 1.0];
        normalize(&mut w);
        assert_eq!(w, vec![0.5; 4]);
        let u = w.clone();
        assert!((dot(&w, &u).unwrap() - try_cosine_similarity(&w, &u).unwrap()).abs() < 1e-6);
    }
}
