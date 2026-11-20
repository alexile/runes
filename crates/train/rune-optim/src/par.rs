//! Chunked parallel loops and deterministic reductions.
//!
//! Element-wise updates are split into fixed-size chunks and run on the
//! current rayon pool once a tensor has [`PARALLEL_MIN_LEN`] elements. Each
//! element is computed by the same expression whichever thread runs it, so
//! results are bitwise identical for any thread count.
//!
//! Reductions (sums of squares, means) are done in `f64` over fixed chunks of
//! [`REDUCE_CHUNK`] elements; the per-chunk partials are then added in chunk
//! order. The summation tree depends only on the length, never on the
//! number of threads.

use rayon::prelude::*;

/// Tensors with at least this many elements are updated in parallel.
pub const PARALLEL_MIN_LEN: usize = 1 << 15;

/// Chunk length for parallel element-wise loops.
pub(crate) const CHUNK: usize = 1 << 13;

/// Chunk length of the fixed reduction tree.
pub const REDUCE_CHUNK: usize = 1 << 12;

/// `f(p, a)` over matching chunks.
pub(crate) fn apply2<F>(p: &mut [f32], a: &[f32], f: F)
where
    F: Fn(&mut [f32], &[f32]) + Sync,
{
    if p.len() >= PARALLEL_MIN_LEN {
        p.par_chunks_mut(CHUNK)
            .zip(a.par_chunks(CHUNK))
            .for_each(|(p, a)| f(p, a));
    } else {
        f(p, a);
    }
}

/// `f(p, g, a)` over matching chunks.
pub(crate) fn apply3<F>(p: &mut [f32], g: &[f32], a: &mut [f32], f: F)
where
    F: Fn(&mut [f32], &[f32], &mut [f32]) + Sync,
{
    if p.len() >= PARALLEL_MIN_LEN {
        p.par_chunks_mut(CHUNK)
            .zip(g.par_chunks(CHUNK))
            .zip(a.par_chunks_mut(CHUNK))
            .for_each(|((p, g), a)| f(p, g, a));
    } else {
        f(p, g, a);
    }
}

/// `f(p, g, a, b)` over matching chunks.
pub(crate) fn apply4<F>(p: &mut [f32], g: &[f32], a: &mut [f32], b: &mut [f32], f: F)
where
    F: Fn(&mut [f32], &[f32], &mut [f32], &mut [f32]) + Sync,
{
    if p.len() >= PARALLEL_MIN_LEN {
        p.par_chunks_mut(CHUNK)
            .zip(g.par_chunks(CHUNK))
            .zip(a.par_chunks_mut(CHUNK))
            .zip(b.par_chunks_mut(CHUNK))
            .for_each(|(((p, g), a), b)| f(p, g, a, b));
    } else {
        f(p, g, a, b);
    }
}

/// `f(p, g, a, b, c)` over matching chunks.
pub(crate) fn apply5<F>(p: &mut [f32], g: &[f32], a: &mut [f32], b: &mut [f32], c: &mut [f32], f: F)
where
    F: Fn(&mut [f32], &[f32], &mut [f32], &mut [f32], &mut [f32]) + Sync,
{
    if p.len() >= PARALLEL_MIN_LEN {
        p.par_chunks_mut(CHUNK)
            .zip(g.par_chunks(CHUNK))
            .zip(a.par_chunks_mut(CHUNK))
            .zip(b.par_chunks_mut(CHUNK))
            .zip(c.par_chunks_mut(CHUNK))
            .for_each(|((((p, g), a), b), c)| f(p, g, a, b, c));
    } else {
        f(p, g, a, b, c);
    }
}

/// `f` over chunks of one mutable slice.
pub(crate) fn apply1<F>(p: &mut [f32], f: F)
where
    F: Fn(&mut [f32]) + Sync,
{
    if p.len() >= PARALLEL_MIN_LEN {
        p.par_chunks_mut(CHUNK).for_each(&f);
    } else {
        f(p);
    }
}

/// Sum of `f(x)` in `f64` over a fixed reduction tree.
pub(crate) fn det_sum<F>(x: &[f32], f: F) -> f64
where
    F: Fn(f32) -> f64 + Sync,
{
    let chunk_sum = |c: &[f32]| c.iter().fold(0.0f64, |acc, &v| acc + f(v));
    if x.len() >= PARALLEL_MIN_LEN {
        let partials: Vec<f64> = x.par_chunks(REDUCE_CHUNK).map(chunk_sum).collect();
        partials.iter().sum()
    } else {
        x.chunks(REDUCE_CHUNK).map(chunk_sum).sum()
    }
}

/// Sum of squares in `f64`, deterministic.
pub(crate) fn sum_sq(x: &[f32]) -> f64 {
    det_sum(x, |v| {
        let v = f64::from(v);
        v * v
    })
}

/// Root mean square in `f64` (0 for an empty slice).
#[allow(clippy::cast_precision_loss, reason = "element counts fit f64")]
pub(crate) fn rms(x: &[f32]) -> f64 {
    if x.is_empty() {
        0.0
    } else {
        (sum_sq(x) / x.len() as f64).sqrt()
    }
}
