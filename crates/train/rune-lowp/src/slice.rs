//! Bulk conversions between `f32` slices and element slices.
//!
//! `bf16` and `f16` use branch-free kernels that the compiler vectorizes;
//! the 8-bit and smaller types decode through 256-entry tables. With the
//! `rayon` feature, inputs of at least [`PARALLEL_THRESHOLD`] elements are
//! split into chunks and converted in parallel. Results never depend on the
//! thread count.

use crate::error::{LowpError, Result};
use crate::format::{Overflow, Rounding};
use crate::types::Element;

/// Inputs at least this long are converted in parallel when the `rayon`
/// feature is enabled.
pub const PARALLEL_THRESHOLD: usize = 1 << 16;

/// Chunk length for parallel work.
#[cfg(feature = "rayon")]
pub(crate) const CHUNK: usize = 1 << 14;

pub(crate) const fn check_len(expected: usize, found: usize) -> Result<()> {
    if expected == found {
        Ok(())
    } else {
        Err(LowpError::LengthMismatch { expected, found })
    }
}

/// Applies `f` to matching chunks of `src` and `dst` (same length),
/// in parallel for long inputs when the `rayon` feature is on.
pub(crate) fn zip_chunks<A, B, F>(src: &[A], dst: &mut [B], f: F)
where
    A: Sync,
    B: Send,
    F: Fn(&[A], &mut [B]) + Sync,
{
    #[cfg(feature = "rayon")]
    {
        if src.len() >= PARALLEL_THRESHOLD {
            use rayon::prelude::*;
            src.par_chunks(CHUNK)
                .zip(dst.par_chunks_mut(CHUNK))
                .for_each(|(s, d)| f(s, d));
            return;
        }
    }
    f(src, dst);
}

/// Converts `src` into `dst` with round-to-nearest-even.
///
/// # Errors
///
/// [`LowpError::LengthMismatch`] if the slices differ in length.
///
/// ```
/// use rune_lowp::{from_f32_slice, Bf16, Overflow};
///
/// let src = [1.0f32, 1.003_906_25, -3.4e38];
/// let mut dst = [Bf16::ZERO; 3];
/// from_f32_slice(&src, &mut dst, Overflow::NonSaturating)?;
/// assert_eq!(dst[0].to_f32(), 1.0);
/// assert_eq!(dst[1].to_f32(), 1.0); // tie, rounds to even
/// assert_eq!(dst[2].to_f32(), f32::NEG_INFINITY);
/// # Ok::<(), rune_lowp::LowpError>(())
/// ```
pub fn from_f32_slice<T: Element>(src: &[f32], dst: &mut [T], overflow: Overflow) -> Result<()> {
    check_len(src.len(), dst.len())?;
    zip_chunks(src, dst, |s, d| T::encode_slice(s, d, overflow));
    Ok(())
}

/// Converts `src` into `dst` with stochastic rounding, one random number
/// per element (`random[i]` rounds `src[i]`).
///
/// # Errors
///
/// [`LowpError::LengthMismatch`] if the three slices differ in length.
pub fn from_f32_slice_stochastic<T: Element>(
    src: &[f32],
    random: &[u32],
    dst: &mut [T],
    overflow: Overflow,
) -> Result<()> {
    check_len(src.len(), dst.len())?;
    check_len(src.len(), random.len())?;
    #[cfg(feature = "rayon")]
    {
        if src.len() >= PARALLEL_THRESHOLD {
            use rayon::prelude::*;
            src.par_chunks(CHUNK)
                .zip(random.par_chunks(CHUNK))
                .zip(dst.par_chunks_mut(CHUNK))
                .for_each(|((s, r), d)| stochastic_chunk(s, r, d, overflow));
            return Ok(());
        }
    }
    stochastic_chunk(src, random, dst, overflow);
    Ok(())
}

fn stochastic_chunk<T: Element>(src: &[f32], random: &[u32], dst: &mut [T], overflow: Overflow) {
    for ((d, &s), &r) in dst.iter_mut().zip(src).zip(random) {
        *d = T::from_f32_with(s, Rounding::Stochastic(r), overflow);
    }
}

/// Converts `src` into `dst` exactly.
///
/// # Errors
///
/// [`LowpError::LengthMismatch`] if the slices differ in length.
pub fn to_f32_slice<T: Element>(src: &[T], dst: &mut [f32]) -> Result<()> {
    check_len(src.len(), dst.len())?;
    zip_chunks(src, dst, |s, d| T::decode_slice(s, d));
    Ok(())
}

/// Round-to-nearest-even, non-saturating conversion into a new vector.
///
/// ```
/// use rune_lowp::{from_f32_vec, to_f32_vec, F8E4M3};
///
/// let q: Vec<F8E4M3> = from_f32_vec(&[0.3, 500.0, -1e-3]);
/// assert_eq!(to_f32_vec(&q)[0], 0.3125);
/// assert!(q[1].is_nan()); // E4M3 has no infinity: overflow is NaN
/// assert_eq!(to_f32_vec(&q)[2], -0.001953125); // 2^-9, the smallest subnormal
/// ```
#[must_use]
pub fn from_f32_vec<T: Element>(src: &[f32]) -> Vec<T> {
    from_f32_vec_with(src, Overflow::NonSaturating)
}

/// Round-to-nearest-even conversion into a new vector with the given
/// overflow behaviour.
#[must_use]
pub fn from_f32_vec_with<T: Element>(src: &[f32], overflow: Overflow) -> Vec<T> {
    let mut out = vec![T::default(); src.len()];
    zip_chunks(src, &mut out, |s, d| T::encode_slice(s, d, overflow));
    out
}

/// Exact widening into a new vector.
#[must_use]
pub fn to_f32_vec<T: Element>(src: &[T]) -> Vec<f32> {
    let mut out = vec![0.0f32; src.len()];
    zip_chunks(src, &mut out, |s, d| T::decode_slice(s, d));
    out
}
