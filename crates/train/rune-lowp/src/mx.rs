//! OCP Microscaling (MX) block formats: 32 elements share one
//! [`E8M0`] power-of-two scale.
//!
//! Quantization follows the OCP Microscaling Formats (MX) Specification
//! v1.0, section 6.3: for each block,
//!
//! ```text
//! shared_exp = floor(log2(max_i |V_i|)) - emax_elem      (clamped to -127..=127)
//! X          = 2^shared_exp                              (stored as E8M0)
//! P_i        = round_to_element(V_i / X)                 (nearest even, saturating)
//! ```
//!
//! where `emax_elem` is the exponent of the largest normal element value
//! (8 for E4M3, 15 for E5M2, 2 for E2M3, 4 for E3M2, 2 for E2M1). `V_i / X`
//! is computed exactly (no intermediate `f32` rounding), so the only
//! rounding is the one into the element format. Decoding is `P_i · X`.
//!
//! Special cases, as the spec allows:
//!
//! * An all-zero block gets the smallest scale, `2^-127`.
//! * A block containing NaN or infinity gets the NaN scale (`0xFF`); its
//!   element codes are zero and every value decodes to NaN.
//!
//! Blocks run along rows: a `rows × cols` tensor has `ceil(cols / 32)`
//! blocks per row, and a short final block holds only the remaining
//! elements (its amax ignores the padding). Element codes are packed per
//! row (see [`crate::pack`]); each row starts on a byte boundary.

use crate::blocks::{Layout, check_shape, for_each_row_out, for_each_run, pack_rows, unpack_rows};
use crate::e8m0::E8M0;
use crate::error::{LowpError, Result};
use crate::format::{Format, Overflow, Rounding, floor_log2, pow2};
use crate::pack::packed_len;

/// Elements per MX block.
pub const MX_BLOCK_SIZE: usize = 32;

/// MX element type.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum MxElement {
    /// MXFP8 with E4M3 elements.
    Fp8E4M3,
    /// MXFP8 with E5M2 elements.
    Fp8E5M2,
    /// MXFP6 with E2M3 elements.
    Fp6E2M3,
    /// MXFP6 with E3M2 elements.
    Fp6E3M2,
    /// MXFP4 with E2M1 elements.
    Fp4E2M1,
}

impl MxElement {
    /// All element types.
    pub const ALL: [Self; 5] = [
        Self::Fp8E4M3,
        Self::Fp8E5M2,
        Self::Fp6E2M3,
        Self::Fp6E3M2,
        Self::Fp4E2M1,
    ];

    /// The element format.
    #[must_use]
    pub const fn format(self) -> Format {
        match self {
            Self::Fp8E4M3 => Format::F8_E4M3,
            Self::Fp8E5M2 => Format::F8_E5M2,
            Self::Fp6E2M3 => Format::F6_E2M3,
            Self::Fp6E3M2 => Format::F6_E3M2,
            Self::Fp4E2M1 => Format::F4_E2M1,
        }
    }

    /// Bits per element.
    #[must_use]
    pub const fn bits(self) -> u32 {
        self.format().bits()
    }

    /// `emax_elem` of the spec: exponent of the largest normal value.
    #[must_use]
    pub const fn emax(self) -> i32 {
        self.format().emax()
    }

    /// Bytes of packed element storage for `n` elements.
    #[must_use]
    pub const fn packed_len(self, n: usize) -> usize {
        packed_len(self.bits(), n)
    }
}

/// The shared exponent of one block, `None` for the NaN scale.
fn shared_exponent(block: &[f32], emax: i32) -> Option<i32> {
    let mut amax = 0.0f32;
    for &v in block {
        if !v.is_finite() {
            return None;
        }
        amax = amax.max(v.abs());
    }
    if amax == 0.0 {
        return Some(-127);
    }
    Some((floor_log2(amax) - emax).clamp(-127, 127))
}

/// The MX scale for a block of values, as chosen by the spec (exposed for
/// callers that keep their own element storage).
///
/// ```
/// use rune_lowp::{mx_block_scale, E8M0, MxElement};
///
/// // amax = 5.0 → floor(log2 5) = 2; FP4 emax = 2 → X = 2^0.
/// assert_eq!(mx_block_scale(&[1.0, -5.0, 0.25], MxElement::Fp4E2M1), E8M0::ONE);
/// ```
#[must_use]
pub fn mx_block_scale(block: &[f32], element: MxElement) -> E8M0 {
    shared_exponent(block, element.emax()).map_or(E8M0::NAN, E8M0::from_exponent_saturating)
}

/// A tensor in an MX format: packed element codes plus one [`E8M0`] scale
/// per 32-element block.
///
/// ```
/// use rune_lowp::{MxElement, MxTensor};
///
/// let x: Vec<f32> = (0..64).map(|i| (i as f32 - 32.0) * 0.1).collect();
/// let q = MxTensor::quantize(MxElement::Fp8E4M3, &x)?;
/// assert_eq!(q.scales().len(), 2);
/// assert_eq!(q.data().len(), 64); // one byte per FP8 element
/// let y = q.dequantize();
/// for (a, b) in x.iter().zip(&y) {
///     assert!((a - b).abs() <= a.abs() / 16.0 + 1e-6);
/// }
/// # Ok::<(), rune_lowp::LowpError>(())
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MxTensor {
    element: MxElement,
    rows: usize,
    cols: usize,
    scales: Vec<E8M0>,
    data: Vec<u8>,
}

impl MxTensor {
    const fn layout_of(element: MxElement, rows: usize, cols: usize) -> Layout {
        Layout {
            rows,
            cols,
            block: MX_BLOCK_SIZE,
            bits: element.bits(),
        }
    }

    const fn layout(&self) -> Layout {
        Self::layout_of(self.element, self.rows, self.cols)
    }

    /// Quantizes a flat vector (one row) with round-to-nearest-even.
    pub fn quantize(element: MxElement, values: &[f32]) -> Result<Self> {
        let cols = values.len();
        Self::quantize_impl(element, values, usize::from(cols != 0), cols, None)
    }

    /// Quantizes a row-major `rows × cols` matrix; blocks run along rows.
    pub fn quantize_rows(
        element: MxElement,
        values: &[f32],
        rows: usize,
        cols: usize,
    ) -> Result<Self> {
        Self::quantize_impl(element, values, rows, cols, None)
    }

    /// Like [`MxTensor::quantize_rows`] but with stochastic rounding of the
    /// elements; `random[i]` rounds `values[i]`. The scale choice is the
    /// same as for nearest rounding.
    pub fn quantize_rows_stochastic(
        element: MxElement,
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
        Self::quantize_impl(element, values, rows, cols, Some(random))
    }

    fn quantize_impl(
        element: MxElement,
        values: &[f32],
        rows: usize,
        cols: usize,
        random: Option<&[u32]>,
    ) -> Result<Self> {
        let n = check_shape(values.len(), rows, cols)?;
        let lay = Self::layout_of(element, rows, cols);
        let fmt = element.format();
        let emax = element.emax();
        let mut codes = vec![0u8; n];
        let mut scales = vec![E8M0::ONE; lay.scale_count()];
        for_each_run(lay, values, &mut codes, &mut scales, |offset, v, c, s| {
            for (b, ((blk, cb), sc)) in v
                .chunks(MX_BLOCK_SIZE)
                .zip(c.chunks_mut(MX_BLOCK_SIZE))
                .zip(s.iter_mut())
                .enumerate()
            {
                let Some(shared) = shared_exponent(blk, emax) else {
                    *sc = E8M0::NAN;
                    cb.fill(0);
                    continue;
                };
                *sc = E8M0::from_exponent_saturating(shared);
                let base = offset + b * MX_BLOCK_SIZE;
                for (i, (code, &x)) in cb.iter_mut().zip(blk).enumerate() {
                    let rounding = random
                        .and_then(|r| r.get(base + i))
                        .map_or(Rounding::NearestEven, |&r| Rounding::Stochastic(r));
                    *code = fmt.encode_scaled(x, shared, rounding, Overflow::Saturating) as u8;
                }
            }
        });
        let data = pack_rows(lay, &codes);
        Ok(Self {
            element,
            rows,
            cols,
            scales,
            data,
        })
    }

    /// Reassembles a tensor from stored parts (for example after loading a
    /// checkpoint). `scales` must hold `rows · ceil(cols / 32)` entries and
    /// `data` exactly `rows · packed_len(cols)` bytes.
    pub fn from_parts(
        element: MxElement,
        rows: usize,
        cols: usize,
        scales: Vec<E8M0>,
        data: Vec<u8>,
    ) -> Result<Self> {
        if (rows == 0) != (cols == 0) {
            return Err(LowpError::InvalidShape(
                "rows and cols must both be zero or both non-zero",
            ));
        }
        rows.checked_mul(cols)
            .ok_or(LowpError::InvalidShape("rows * cols overflows usize"))?;
        let lay = Self::layout_of(element, rows, cols);
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
            element,
            rows,
            cols,
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

    /// Decodes into `out`, which must hold [`MxTensor::len`] values.
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
        let fmt = self.element.format();
        for_each_row_out(lay, &codes, &self.scales, out, |c, s, o| {
            for ((cb, ob), sc) in c
                .chunks(MX_BLOCK_SIZE)
                .zip(o.chunks_mut(MX_BLOCK_SIZE))
                .zip(s)
            {
                match sc.exponent() {
                    None => ob.fill(f32::NAN),
                    Some(e) => {
                        let x = pow2(e);
                        for (dst, &code) in ob.iter_mut().zip(cb) {
                            *dst = fmt.decode(u16::from(code)) * x;
                        }
                    }
                }
            }
        });
    }

    /// Element codes, unpacked to one byte each (row-major).
    #[must_use]
    pub fn codes(&self) -> Vec<u8> {
        unpack_rows(self.layout(), &self.data)
    }

    /// The element type.
    #[must_use]
    pub const fn element(&self) -> MxElement {
        self.element
    }

    /// Number of rows.
    #[must_use]
    pub const fn rows(&self) -> usize {
        self.rows
    }

    /// Number of columns (elements per row).
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

    /// Blocks per row, `ceil(cols / 32)`.
    #[must_use]
    pub const fn blocks_per_row(&self) -> usize {
        self.layout().blocks_per_row()
    }

    /// Bytes of packed storage per row.
    #[must_use]
    pub const fn row_bytes(&self) -> usize {
        self.layout().row_bytes()
    }

    /// Block scales, row-major (`rows × blocks_per_row`).
    #[must_use]
    pub fn scales(&self) -> &[E8M0] {
        &self.scales
    }

    /// Packed element storage, `rows × row_bytes` bytes.
    #[must_use]
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// Splits into `(scales, data)`.
    #[must_use]
    pub fn into_parts(self) -> (Vec<E8M0>, Vec<u8>) {
        (self.scales, self.data)
    }
}
