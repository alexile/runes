//! Unrolled distance and reduction kernels over `&[F]` slices.
//!
//! Each kernel keeps [`LANES`] independent accumulators so the compiler can
//! auto-vectorise the loop (no `unsafe`, no target-specific intrinsics), and
//! handles the tail scalar-wise. Because the summation order differs from a
//! plain left fold, results can differ from a naive loop in the last few
//! ulps; they are never less accurate on long inputs (pairwise-like
//! partial sums).
//!
//! All kernels compare only the first `min(a.len(), b.len())` coordinates.
//! Use [`Metric::try_distance`](crate::Metric::try_distance) for a checked
//! variant.

use crate::Float;

/// Number of independent accumulators per kernel.
pub const LANES: usize = 8;

#[inline]
fn trim<'a, F>(a: &'a [F], b: &'a [F]) -> (&'a [F], &'a [F]) {
    let n = a.len().min(b.len());
    (&a[..n], &b[..n])
}

#[inline]
fn reduce_sum<F: Float>(acc: [F; LANES]) -> F {
    // Pairwise reduction keeps the error low and is order-independent of n.
    let s0 = (acc[0] + acc[4]) + (acc[2] + acc[6]);
    let s1 = (acc[1] + acc[5]) + (acc[3] + acc[7]);
    s0 + s1
}

/// Sums `step(x, y)` over paired coordinates with [`LANES`] accumulators.
#[inline]
fn lane_sum<F: Float>(a: &[F], b: &[F], step: impl Fn(F, F) -> F) -> F {
    let (a, b) = trim(a, b);
    let mut acc = [F::ZERO; LANES];
    let (ca, ra) = a.as_chunks::<LANES>();
    let (cb, rb) = b.as_chunks::<LANES>();
    for (x, y) in ca.iter().zip(cb) {
        for l in 0..LANES {
            acc[l] += step(x[l], y[l]);
        }
    }
    let mut tail = F::ZERO;
    for (&x, &y) in ra.iter().zip(rb) {
        tail += step(x, y);
    }
    reduce_sum(acc) + tail
}

/// Dot product `Σ aᵢ·bᵢ`.
#[inline]
pub fn dot<F: Float>(a: &[F], b: &[F]) -> F {
    lane_sum(a, b, |x, y| x * y)
}

/// Squared Euclidean distance `Σ (aᵢ − bᵢ)²`.
#[inline]
pub fn sq_euclidean<F: Float>(a: &[F], b: &[F]) -> F {
    lane_sum(a, b, |x, y| {
        let d = x - y;
        d * d
    })
}

/// Euclidean (L2) distance `√Σ (aᵢ − bᵢ)²`.
#[inline]
pub fn euclidean<F: Float>(a: &[F], b: &[F]) -> F {
    sq_euclidean(a, b).sqrt()
}

/// Manhattan (L1, city-block) distance `Σ |aᵢ − bᵢ|`.
#[inline]
pub fn manhattan<F: Float>(a: &[F], b: &[F]) -> F {
    lane_sum(a, b, |x, y| (x - y).abs())
}

/// Chebyshev (L∞) distance `max |aᵢ − bᵢ|`; `0` for empty input.
#[inline]
pub fn chebyshev<F: Float>(a: &[F], b: &[F]) -> F {
    let (a, b) = trim(a, b);
    let mut acc = [F::ZERO; LANES];
    let (ca, ra) = a.as_chunks::<LANES>();
    let (cb, rb) = b.as_chunks::<LANES>();
    for (x, y) in ca.iter().zip(cb) {
        for l in 0..LANES {
            acc[l] = acc[l].max((x[l] - y[l]).abs());
        }
    }
    let mut m = F::ZERO;
    for (&x, &y) in ra.iter().zip(rb) {
        m = m.max((x - y).abs());
    }
    acc.iter().fold(m, |m, &v| m.max(v))
}

/// Squared L2 norm `Σ aᵢ²`.
#[inline]
pub fn norm_sq<F: Float>(a: &[F]) -> F {
    dot(a, a)
}

/// L2 norm `√Σ aᵢ²`.
#[inline]
pub fn norm<F: Float>(a: &[F]) -> F {
    norm_sq(a).sqrt()
}

/// `(a·b, a·a, b·b)` in a single pass.
#[inline]
pub fn dot_and_norms<F: Float>(a: &[F], b: &[F]) -> (F, F, F) {
    let (a, b) = trim(a, b);
    let mut ab = [F::ZERO; LANES];
    let mut aa = [F::ZERO; LANES];
    let mut bb = [F::ZERO; LANES];
    let (ca, ra) = a.as_chunks::<LANES>();
    let (cb, rb) = b.as_chunks::<LANES>();
    for (x, y) in ca.iter().zip(cb) {
        for l in 0..LANES {
            ab[l] += x[l] * y[l];
            aa[l] += x[l] * x[l];
            bb[l] += y[l] * y[l];
        }
    }
    let (mut tab, mut taa, mut tbb) = (F::ZERO, F::ZERO, F::ZERO);
    for (&x, &y) in ra.iter().zip(rb) {
        tab += x * y;
        taa += x * x;
        tbb += y * y;
    }
    (
        reduce_sum(ab) + tab,
        reduce_sum(aa) + taa,
        reduce_sum(bb) + tbb,
    )
}

/// Cosine distance `1 − a·b / (‖a‖·‖b‖)`, clamped to `[0, 2]`.
///
/// Conventions for zero vectors: two zero vectors are at distance `0`; a
/// zero vector and a non-zero vector are at distance `1` (orthogonal).
#[inline]
pub fn cosine<F: Float>(a: &[F], b: &[F]) -> F {
    let (ab, aa, bb) = dot_and_norms(a, b);
    let zero_a = aa <= F::ZERO;
    let zero_b = bb <= F::ZERO;
    if zero_a && zero_b {
        return F::ZERO;
    }
    if zero_a || zero_b {
        return F::ONE;
    }
    let sim = ab / (aa.sqrt() * bb.sqrt());
    (F::ONE - sim).max(F::ZERO).min(F::ONE + F::ONE)
}

/// `y ← y + alpha·x` over the first `min(len)` coordinates.
#[inline]
pub fn axpy<F: Float>(alpha: F, x: &[F], y: &mut [F]) {
    for (yi, &xi) in y.iter_mut().zip(x) {
        *yi += alpha * xi;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn small_known_values() {
        let a = [0.0_f64, 0.0];
        let b = [3.0_f64, 4.0];
        assert_eq!(euclidean(&a, &b), 5.0);
        assert_eq!(sq_euclidean(&a, &b), 25.0);
        assert_eq!(manhattan(&a, &b), 7.0);
        assert_eq!(chebyshev(&a, &b), 4.0);
        assert_eq!(dot(&b, &b), 25.0);
        assert_eq!(norm(&b), 5.0);
    }

    #[test]
    fn long_input_crosses_lanes() {
        let a: Vec<f32> = (0..19_u8).map(f32::from).collect();
        let b: Vec<f32> = (0..19_u8).map(|i| f32::from(2 * i)).collect();
        assert_eq!(manhattan(&a, &b), 171.0);
        assert_eq!(chebyshev(&a, &b), 18.0);
    }

    #[test]
    fn cosine_conventions() {
        let z = [0.0_f64; 3];
        let x = [1.0_f64, 0.0, 0.0];
        let y = [0.0_f64, 2.0, 0.0];
        assert_eq!(cosine(&z, &z), 0.0);
        assert_eq!(cosine(&z, &x), 1.0);
        assert!((cosine(&x, &y) - 1.0).abs() < 1e-15);
        assert!(cosine(&x, &x).abs() < 1e-15);
        assert!((cosine(&x, &[-1.0, 0.0, 0.0]) - 2.0).abs() < 1e-15);
    }

    #[test]
    fn mismatched_lengths_use_prefix() {
        assert_eq!(sq_euclidean(&[1.0_f64, 2.0, 3.0], &[1.0, 2.0]), 0.0);
        assert_eq!(chebyshev::<f64>(&[], &[]), 0.0);
    }

    #[test]
    fn axpy_updates() {
        let mut y = [1.0_f64, 1.0];
        axpy(2.0, &[1.0, 2.0], &mut y);
        assert_eq!(y, [3.0, 5.0]);
    }
}
