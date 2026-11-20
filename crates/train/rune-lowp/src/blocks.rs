//! Shared plumbing for the block-scaled tensor formats: shape checks and a
//! driver that walks row-local blocks, in parallel for large inputs.

use crate::error::{LowpError, Result};
use crate::pack::{pack_into, packed_len, unpack_into};

/// Validates `rows × cols == len` and returns the element count.
pub(crate) fn check_shape(len: usize, rows: usize, cols: usize) -> Result<usize> {
    if rows == 0 || cols == 0 {
        if len == 0 && rows == 0 && cols == 0 {
            return Ok(0);
        }
        return Err(LowpError::InvalidShape(
            "rows and cols must both be zero or both non-zero",
        ));
    }
    let n = rows
        .checked_mul(cols)
        .ok_or(LowpError::InvalidShape("rows * cols overflows usize"))?;
    if n != len {
        return Err(LowpError::LengthMismatch {
            expected: n,
            found: len,
        });
    }
    Ok(n)
}

/// Shape of a row-blocked tensor.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Layout {
    pub rows: usize,
    pub cols: usize,
    pub block: usize,
    pub bits: u32,
}

impl Layout {
    pub(crate) const fn blocks_per_row(&self) -> usize {
        self.cols.div_ceil(self.block)
    }

    pub(crate) const fn row_bytes(&self) -> usize {
        packed_len(self.bits, self.cols)
    }

    pub(crate) const fn scale_count(&self) -> usize {
        self.rows * self.blocks_per_row()
    }

    pub(crate) const fn data_len(&self) -> usize {
        self.rows * self.row_bytes()
    }
}

/// Elements per parallel work item inside a row (a multiple of every block
/// size used here).
#[cfg(feature = "rayon")]
const GROUP: usize = 32 * 256;

/// Runs `f(offset, values, codes, scales)` over runs of whole blocks; every
/// run lies in one row, `offset` is the index of its first element in the
/// flat tensor, and `scales` holds one entry per block of the run.
pub(crate) fn for_each_run<S, F>(
    lay: Layout,
    values: &[f32],
    codes: &mut [u8],
    scales: &mut [S],
    f: F,
) where
    S: Send,
    F: Fn(usize, &[f32], &mut [u8], &mut [S]) + Sync,
{
    let cols = lay.cols;
    let bpr = lay.blocks_per_row();
    if cols == 0 {
        return;
    }
    #[cfg(feature = "rayon")]
    {
        if values.len() >= crate::slice::PARALLEL_THRESHOLD {
            use rayon::prelude::*;
            let group_blocks = GROUP / lay.block;
            values
                .par_chunks(cols)
                .zip(codes.par_chunks_mut(cols))
                .zip(scales.par_chunks_mut(bpr))
                .enumerate()
                .for_each(|(r, ((v, c), s))| {
                    v.par_chunks(GROUP)
                        .zip(c.par_chunks_mut(GROUP))
                        .zip(s.par_chunks_mut(group_blocks))
                        .enumerate()
                        .for_each(|(g, ((v, c), s))| f(r * cols + g * GROUP, v, c, s));
                });
            return;
        }
    }
    for (r, ((v, c), s)) in values
        .chunks(cols)
        .zip(codes.chunks_mut(cols))
        .zip(scales.chunks_mut(bpr))
        .enumerate()
    {
        f(r * cols, v, c, s);
    }
}

/// Packs per-row codes into row-strided storage.
pub(crate) fn pack_rows(lay: Layout, codes: &[u8]) -> Vec<u8> {
    let mut data = vec![0u8; lay.data_len()];
    if lay.cols == 0 {
        return data;
    }
    for (row, out) in codes.chunks(lay.cols).zip(data.chunks_mut(lay.row_bytes())) {
        pack_into(lay.bits, row, out);
    }
    data
}

/// Inverse of [`pack_rows`].
pub(crate) fn unpack_rows(lay: Layout, data: &[u8]) -> Vec<u8> {
    let mut codes = vec![0u8; lay.rows * lay.cols];
    if lay.cols == 0 {
        return codes;
    }
    for (row, packed) in codes.chunks_mut(lay.cols).zip(data.chunks(lay.row_bytes())) {
        unpack_into(lay.bits, packed, row);
    }
    codes
}

/// Splits `out` into rows and calls `f(row_codes, row_scales, row_out)`, in
/// parallel over rows for large tensors.
pub(crate) fn for_each_row_out<S, F>(lay: Layout, codes: &[u8], scales: &[S], out: &mut [f32], f: F)
where
    S: Sync,
    F: Fn(&[u8], &[S], &mut [f32]) + Sync,
{
    let cols = lay.cols;
    let bpr = lay.blocks_per_row();
    if cols == 0 {
        return;
    }
    #[cfg(feature = "rayon")]
    {
        if out.len() >= crate::slice::PARALLEL_THRESHOLD {
            use rayon::prelude::*;
            codes
                .par_chunks(cols)
                .zip(scales.par_chunks(bpr))
                .zip(out.par_chunks_mut(cols))
                .for_each(|((c, s), o)| f(c, s, o));
            return;
        }
    }
    for ((c, s), o) in codes
        .chunks(cols)
        .zip(scales.chunks(bpr))
        .zip(out.chunks_mut(cols))
    {
        f(c, s, o);
    }
}
