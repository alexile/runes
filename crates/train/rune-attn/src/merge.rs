//! Combining partial attention results over disjoint key sets.

use rayon::prelude::*;

use crate::{AttnError, AttnOutput};

/// One accumulator row and its LSE.
type Acc<'a> = (&'a mut [f32], &'a mut f32);
/// One incoming row and its LSE.
type Part<'a> = (&'a [f32], &'a f32);

/// Rows below this many elements are merged on one thread.
const PARALLEL_MIN: usize = 1 << 16;

/// Combine two partial results for the same queries computed over disjoint
/// key sets, as in ring (context-parallel) attention and split-KV decoding.
///
/// `out_*` hold `n` rows of `dim` values and `lse_*` the `n` matching
/// log-sum-exps, in any row order as long as both sides agree (for this
/// crate's tensors: `out [tokens, heads, dim_v]`, `lse [tokens, heads]`).
/// The row dimension is `out_a.len() / lse_a.len()`. With
/// `m = max(lse_a, lse_b)`, `w_x = exp(lse_x - m)`:
///
/// ```text
/// lse = m + ln(w_a + w_b)
/// out = (w_a out_a + w_b out_b) / (w_a + w_b)
/// ```
///
/// which never overflows. A row whose sides both have LSE `-inf` (no
/// visible key on either side) stays `0` with LSE `-inf`; a side with LSE
/// `-inf` contributes nothing, whatever its `out` holds.
///
/// ```
/// use rune_attn::merge_partials;
///
/// // One row of dim 2. Side b saw nothing.
/// let m = merge_partials(&[1.0, 2.0], &[0.5], &[9.0, 9.0], &[f32::NEG_INFINITY])?;
/// assert_eq!(m.out, [1.0, 2.0]);
/// assert_eq!(m.lse, [0.5]);
/// # Ok::<(), rune_attn::AttnError>(())
/// ```
pub fn merge_partials(
    out_a: &[f32],
    lse_a: &[f32],
    out_b: &[f32],
    lse_b: &[f32],
) -> Result<AttnOutput, AttnError> {
    let mut out = out_a.to_vec();
    let mut lse = lse_a.to_vec();
    merge_partials_into(&mut out, &mut lse, out_b, lse_b)?;
    Ok(AttnOutput { out, lse })
}

/// [`merge_partials`] that accumulates `(out_b, lse_b)` into
/// `(out, lse)` in place.
pub fn merge_partials_into(
    out: &mut [f32],
    lse: &mut [f32],
    out_b: &[f32],
    lse_b: &[f32],
) -> Result<(), AttnError> {
    if lse_b.len() != lse.len() {
        return Err(AttnError::ShapeMismatch {
            what: "lse_b",
            expected: lse.len(),
            found: lse_b.len(),
        });
    }
    if out_b.len() != out.len() {
        return Err(AttnError::ShapeMismatch {
            what: "out_b",
            expected: out.len(),
            found: out_b.len(),
        });
    }
    if lse.is_empty() {
        return if out.is_empty() {
            Ok(())
        } else {
            Err(AttnError::ShapeMismatch {
                what: "lse",
                expected: 1,
                found: 0,
            })
        };
    }
    if !out.len().is_multiple_of(lse.len()) || out.is_empty() {
        return Err(AttnError::ShapeMismatch {
            what: "out (a multiple of the lse length)",
            expected: lse.len(),
            found: out.len(),
        });
    }
    let dim = out.len() / lse.len();
    let row = |((o, l), (ob, &lb)): (Acc<'_>, Part<'_>)| {
        let la = *l;
        let m = la.max(lb);
        if m == f32::NEG_INFINITY {
            o.fill(0.0);
            *l = f32::NEG_INFINITY;
            return;
        }
        let wa = (la - m).exp();
        let wb = (lb - m).exp();
        let sum = wa + wb;
        let (fa, fb) = (wa / sum, wb / sum);
        *l = m + sum.ln();
        for (x, &y) in o.iter_mut().zip(ob) {
            let a = if wa > 0.0 { fa * *x } else { 0.0 };
            *x = if wb > 0.0 { fb.mul_add(y, a) } else { a };
        }
    };
    if out.len() >= PARALLEL_MIN {
        out.par_chunks_exact_mut(dim)
            .zip(lse.par_iter_mut())
            .zip(out_b.par_chunks_exact(dim).zip(lse_b.par_iter()))
            .for_each(row);
    } else {
        out.chunks_exact_mut(dim)
            .zip(lse.iter_mut())
            .zip(out_b.chunks_exact(dim).zip(lse_b.iter()))
            .for_each(row);
    }
    Ok(())
}
