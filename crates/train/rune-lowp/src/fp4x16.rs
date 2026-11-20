//! FP4 (E2M1) with 16-element blocks, an FP8 E4M3 scale per block and an
//! `f32` scale per tensor.
//!
//! The two-level scale lets the block scales use the full E4M3 range: the
//! per-tensor scale maps the tensor amax onto `448 · 6` (the product of the
//! largest E4M3 and E2M1 values), then each block scale maps its block amax
//! onto 6. With `amax` the largest finite magnitude in the tensor:
//!
//! ```text
//! s_enc        = 448 · 6 / amax                (1 if amax == 0; capped at f32::MAX)
//! tensor_scale = 1 / s_enc                     (stored, f32)
//! per block:
//!   scale_b    = e4m3_sat((amax_b / 6) · s_enc)   (stored, E4M3, nearest even)
//!   enc_b      = s_enc / f32(scale_b)            (capped at f32::MAX)
//!   q_i        = e2m1_sat(x_i · enc_b)           (nearest even or stochastic)
//! decode:  x_i ≈ f32(q_i) · f32(scale_b) · tensor_scale
//! ```
//!
//! All arithmetic is single-precision in the order written, so results are
//! reproducible bit for bit. A block whose scale rounds to zero stores zero
//! codes. A block containing NaN or infinity gets the E4M3 NaN scale and
//! decodes to NaN; non-finite values are left out of the tensor amax.

use crate::blocks::{Layout, check_shape, for_each_row_out, for_each_run, pack_rows, unpack_rows};
use crate::error::{LowpError, Result};
use crate::format::{Format, Overflow, Rounding};
use crate::types::F8E4M3;

/// Elements per block.
pub const FP4X16_BLOCK_SIZE: usize = 16;

const FP4_MAX: f32 = 6.0;
const FP8_MAX: f32 = 448.0;

/// A tensor of E2M1 codes with E4M3 scales per 16 elements and one `f32`
/// scale per tensor.
///
/// ```
/// use rune_lowp::Fp4x16Tensor;
///
/// let x = [0.5f32, -1.0, 3.0, 6.0, 0.0, 2.0, -4.0, 1.5, 0.25, 0.75, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0];
/// let q = Fp4x16Tensor::quantize(&x)?;
/// assert_eq!(q.data().len(), 8); // two codes per byte
/// let y = q.dequantize();
/// assert!((y[3] - 6.0).abs() < 1e-5);
/// assert!((y[1] + 1.0).abs() < 1e-5);
/// # Ok::<(), rune_lowp::LowpError>(())
/// ```
#[derive(Clone, Debug, PartialEq)]
pub struct Fp4x16Tensor {
    rows: usize,
    cols: usize,
    tensor_scale: f32,
    scales: Vec<F8E4M3>,
    data: Vec<u8>,
}

/// Largest finite magnitude, ignoring NaN and infinities.
fn finite_amax(values: &[f32]) -> f32 {
    values
        .iter()
        .filter(|v| v.is_finite())
        .fold(0.0f32, |m, v| m.max(v.abs()))
}

impl Fp4x16Tensor {
    const fn layout_of(rows: usize, cols: usize) -> Layout {
        Layout {
            rows,
            cols,
            block: FP4X16_BLOCK_SIZE,
            bits: 4,
        }
    }

    const fn layout(&self) -> Layout {
        Self::layout_of(self.rows, self.cols)
    }

    /// Quantizes a flat vector (one row), nearest-even rounding.
    pub fn quantize(values: &[f32]) -> Result<Self> {
        let cols = values.len();
        Self::quantize_rows(values, usize::from(cols != 0), cols)
    }

    /// Quantizes a row-major `rows × cols` matrix; blocks run along rows.
    pub fn quantize_rows(values: &[f32], rows: usize, cols: usize) -> Result<Self> {
        Self::quantize_impl(values, rows, cols, finite_amax(values), None)
    }

    /// Like [`Fp4x16Tensor::quantize_rows`] with a caller-supplied tensor
    /// amax (for example one reduced across data-parallel ranks, or a
    /// delayed amax). Values above it saturate.
    ///
    /// # Errors
    ///
    /// [`LowpError::InvalidParameter`] if `amax` is negative or not finite.
    pub fn quantize_rows_with_amax(
        values: &[f32],
        rows: usize,
        cols: usize,
        amax: f32,
    ) -> Result<Self> {
        if !(amax.is_finite() && amax >= 0.0) {
            return Err(LowpError::InvalidParameter(
                "amax must be finite and non-negative",
            ));
        }
        Self::quantize_impl(values, rows, cols, amax, None)
    }

    /// Like [`Fp4x16Tensor::quantize_rows`] with stochastic rounding of the
    /// elements (`random[i]` rounds `values[i]`); scales are unchanged.
    pub fn quantize_rows_stochastic(
        values: &[f32],
        rows: usize,
        cols: usize,
        random: &[u32],
    ) -> Result<Self> {
        if random.len() != values.len() {
            return Err(LowpError::LengthMismatch {
                expected: values.len(),
                found: random.len(),
            });
        }
        Self::quantize_impl(values, rows, cols, finite_amax(values), Some(random))
    }

    fn quantize_impl(
        values: &[f32],
        rows: usize,
        cols: usize,
        amax: f32,
        random: Option<&[u32]>,
    ) -> Result<Self> {
        let n = check_shape(values.len(), rows, cols)?;
        let lay = Self::layout_of(rows, cols);
        let s_enc = if amax > 0.0 {
            (FP8_MAX * FP4_MAX / amax).min(f32::MAX)
        } else {
            1.0
        };
        let tensor_scale = 1.0 / s_enc;
        let fp4 = Format::F4_E2M1;
        let mut codes = vec![0u8; n];
        let mut scales = vec![F8E4M3::ZERO; lay.scale_count()];
        for_each_run(lay, values, &mut codes, &mut scales, |offset, v, c, s| {
            for (b, ((blk, cb), sc)) in v
                .chunks(FP4X16_BLOCK_SIZE)
                .zip(c.chunks_mut(FP4X16_BLOCK_SIZE))
                .zip(s.iter_mut())
                .enumerate()
            {
                if blk.iter().any(|x| !x.is_finite()) {
                    *sc = F8E4M3::NAN;
                    cb.fill(0);
                    continue;
                }
                let bamax = blk.iter().fold(0.0f32, |m, x| m.max(x.abs()));
                let scale = F8E4M3::from_f32_sat((bamax / FP4_MAX) * s_enc);
                *sc = scale;
                let sf = scale.to_f32();
                if sf == 0.0 {
                    cb.fill(0);
                    continue;
                }
                let enc = (s_enc / sf).min(f32::MAX);
                let base = offset + b * FP4X16_BLOCK_SIZE;
                for (i, (code, &x)) in cb.iter_mut().zip(blk).enumerate() {
                    let rounding = random
                        .and_then(|r| r.get(base + i))
                        .map_or(Rounding::NearestEven, |&r| Rounding::Stochastic(r));
                    *code = fp4.encode(x * enc, rounding, Overflow::Saturating) as u8;
                }
            }
        });
        let data = pack_rows(lay, &codes);
        Ok(Self {
            rows,
            cols,
            tensor_scale,
            scales,
            data,
        })
    }

    /// Reassembles a tensor from stored parts. `scales` must hold
    /// `rows · ceil(cols / 16)` entries and `data` `rows · ceil(cols / 2)`
    /// bytes; `tensor_scale` must be finite and positive.
    pub fn from_parts(
        rows: usize,
        cols: usize,
        tensor_scale: f32,
        scales: Vec<F8E4M3>,
        data: Vec<u8>,
    ) -> Result<Self> {
        if (rows == 0) != (cols == 0) {
            return Err(LowpError::InvalidShape(
                "rows and cols must both be zero or both non-zero",
            ));
        }
        rows.checked_mul(cols)
            .ok_or(LowpError::InvalidShape("rows * cols overflows usize"))?;
        if !(tensor_scale.is_finite() && tensor_scale > 0.0) {
            return Err(LowpError::InvalidParameter(
                "tensor_scale must be finite and positive",
            ));
        }
        let lay = Self::layout_of(rows, cols);
        if scales.len() != lay.scale_count() {
            return Err(LowpError::LengthMismatch {
                expected: lay.scale_count(),
                found: scales.len(),
            });
        }
        if data.len() != lay.data_len() {
            return Err(LowpError::LengthMismatch {
                expected: lay.data_len(),
                found: data.len(),
            });
        }
        Ok(Self {
            rows,
            cols,
            tensor_scale,
            scales,
            data,
        })
    }

    /// Decodes every element to `f32`.
    #[must_use]
    pub fn dequantize(&self) -> Vec<f32> {
        let mut out = vec![0.0f32; self.len()];
        self.dequantize_impl(&mut out);
        out
    }

    /// Decodes into `out`, which must hold [`Fp4x16Tensor::len`] values.
    pub fn dequantize_into(&self, out: &mut [f32]) -> Result<()> {
        if out.len() != self.len() {
            return Err(LowpError::LengthMismatch {
                expected: self.len(),
                found: out.len(),
            });
        }
        self.dequantize_impl(out);
        Ok(())
    }

    fn dequantize_impl(&self, out: &mut [f32]) {
        let lay = self.layout();
        let codes = unpack_rows(lay, &self.data);
        let ts = self.tensor_scale;
        let fp4 = Format::F4_E2M1;
        for_each_row_out(lay, &codes, &self.scales, out, |c, s, o| {
            for ((cb, ob), sc) in c
                .chunks(FP4X16_BLOCK_SIZE)
                .zip(o.chunks_mut(FP4X16_BLOCK_SIZE))
                .zip(s)
            {
                let sf = sc.to_f32();
                for (dst, &code) in ob.iter_mut().zip(cb) {
                    *dst = fp4.decode(u16::from(code)) * sf * ts;
                }
            }
        });
    }

    /// Element codes, unpacked to one byte each (row-major).
    #[must_use]
    pub fn codes(&self) -> Vec<u8> {
        unpack_rows(self.layout(), &self.data)
    }

    /// Per-tensor decode scale (`1 / s_enc`).
    #[must_use]
    pub const fn tensor_scale(&self) -> f32 {
        self.tensor_scale
    }

    /// Block scales, row-major (`rows × ceil(cols / 16)`).
    #[must_use]
    pub fn scales(&self) -> &[F8E4M3] {
        &self.scales
    }

    /// Packed codes, `rows × ceil(cols / 2)` bytes.
    #[must_use]
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// Number of rows.
    #[must_use]
    pub const fn rows(&self) -> usize {
        self.rows
    }

    /// Number of columns.
    #[must_use]
    pub const fn cols(&self) -> usize {
        self.cols
    }

    /// Total number of elements.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.rows * self.cols
    }

    /// `true` if the tensor has no elements.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Blocks per row, `ceil(cols / 16)`.
    #[must_use]
    pub const fn blocks_per_row(&self) -> usize {
        self.layout().blocks_per_row()
    }
}
