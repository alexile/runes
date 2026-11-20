//! Scaling recipes for FP8 (and other low-precision) training.
//!
//! A tensor is quantized as `q = T(x · scale)` and restored as
//! `x ≈ f32(q) · scale_inv`. The recipes here choose `scale` so that the
//! tensor amax lands at the top of the target format:
//!
//! ```text
//! scale = (target_max / amax) / 2^margin       (optionally rounded down to a power of two)
//! ```
//!
//! * **Current scaling** ([`ScalingRecipe::current`]): `amax` of the tensor
//!   being quantized.
//! * **Delayed scaling** ([`DelayedScaling`]): `amax` reduced over a window
//!   of amaxes recorded at previous steps (maximum or most recent).
//! * **Fine-grained block scaling** ([`BlockScaledMatrix`]): one scale per
//!   `block_rows × block_cols` tile of a matrix (for example 1×128 for
//!   activations and 128×128 for weights).
//!
//! When `amax` is zero, NaN or infinite the previous scale is kept (the
//! identity for current and block scaling). A scale that would overflow is
//! capped at `f32::MAX` (`2^127` in power-of-two mode).

use crate::error::{LowpError, Result};
use crate::format::{Overflow, floor_log2, pow2};
use crate::slice::{check_len, zip_chunks};
use crate::types::Element;

/// A scale and its reciprocal.
#[derive(Clone, Copy, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ScalePair {
    /// Multiplier applied before the narrowing cast.
    pub scale: f32,
    /// Multiplier applied after widening, `1 / scale`.
    pub scale_inv: f32,
}

impl ScalePair {
    /// `scale = scale_inv = 1`.
    pub const IDENTITY: Self = Self {
        scale: 1.0,
        scale_inv: 1.0,
    };

    /// A pair from a scale.
    ///
    /// # Errors
    ///
    /// [`LowpError::InvalidParameter`] unless `scale` is finite and positive.
    pub fn from_scale(scale: f32) -> Result<Self> {
        if !(scale.is_finite() && scale > 0.0) {
            return Err(LowpError::InvalidParameter(
                "scale must be finite and positive",
            ));
        }
        Ok(Self {
            scale,
            scale_inv: 1.0 / scale,
        })
    }
}

impl Default for ScalePair {
    fn default() -> Self {
        Self::IDENTITY
    }
}

/// Largest magnitude in `values`: NaN if any value is NaN, `0` for an empty
/// slice. Parallel for long inputs with the `rayon` feature.
///
/// ```
/// assert_eq!(rune_lowp::amax(&[1.0, -3.0, 2.0]), 3.0);
/// assert!(rune_lowp::amax(&[1.0, f32::NAN]).is_nan());
/// ```
#[must_use]
pub fn amax(values: &[f32]) -> f32 {
    fn seq(v: &[f32]) -> f32 {
        let mut m = 0.0f32;
        let mut nan = false;
        for &x in v {
            nan |= x.is_nan();
            m = m.max(x.abs());
        }
        if nan { f32::NAN } else { m }
    }
    #[cfg(feature = "rayon")]
    {
        if values.len() >= crate::slice::PARALLEL_THRESHOLD {
            use rayon::prelude::*;
            return values.par_chunks(crate::slice::CHUNK).map(seq).reduce(
                || 0.0,
                |a, b| {
                    if a.is_nan() || b.is_nan() {
                        f32::NAN
                    } else {
                        a.max(b)
                    }
                },
            );
        }
    }
    seq(values)
}

/// How a scale is derived from an amax.
#[derive(Clone, Copy, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ScalingRecipe {
    target_max: f32,
    margin: i32,
    power_of_two: bool,
}

impl ScalingRecipe {
    /// A recipe that maps amax onto `target_max`, margin 0, any scale.
    ///
    /// # Errors
    ///
    /// [`LowpError::InvalidParameter`] unless `target_max` is finite and
    /// positive.
    pub fn new(target_max: f32) -> Result<Self> {
        if !(target_max.is_finite() && target_max > 0.0) {
            return Err(LowpError::InvalidParameter(
                "target_max must be finite and positive",
            ));
        }
        Ok(Self {
            target_max,
            margin: 0,
            power_of_two: false,
        })
    }

    /// A recipe targeting the largest finite value of `T` (448 for E4M3,
    /// 57344 for E5M2, ...).
    #[must_use]
    pub const fn for_element<T: Element>() -> Self {
        Self {
            target_max: T::FORMAT.max_finite(),
            margin: 0,
            power_of_two: false,
        }
    }

    /// Sets the margin: the scale is divided by `2^margin` (positive values
    /// leave headroom).
    ///
    /// # Errors
    ///
    /// [`LowpError::InvalidParameter`] if `|margin| > 64`.
    pub const fn with_margin(mut self, margin: i32) -> Result<Self> {
        if margin < -64 || margin > 64 {
            return Err(LowpError::InvalidParameter("margin must be in -64..=64"));
        }
        self.margin = margin;
        Ok(self)
    }

    /// Rounds scales down to powers of two, so that scaling is exact and
    /// `scale_inv` is exactly `1 / scale`.
    #[must_use]
    pub const fn with_power_of_two(mut self, on: bool) -> Self {
        self.power_of_two = on;
        self
    }

    /// The value amax is mapped to.
    #[must_use]
    pub const fn target_max(&self) -> f32 {
        self.target_max
    }

    /// The margin exponent.
    #[must_use]
    pub const fn margin(&self) -> i32 {
        self.margin
    }

    /// Whether scales are powers of two.
    #[must_use]
    pub const fn power_of_two(&self) -> bool {
        self.power_of_two
    }

    /// The scale for a given amax; `fallback` is returned when `amax` is
    /// zero, negative, NaN or infinite.
    ///
    /// ```
    /// use rune_lowp::{F8E4M3, ScalePair, ScalingRecipe};
    ///
    /// let r = ScalingRecipe::for_element::<F8E4M3>();
    /// let s = r.scale_from_amax(2.0, ScalePair::IDENTITY);
    /// assert_eq!(s.scale, 224.0);
    /// let p = r.with_power_of_two(true).scale_from_amax(2.0, ScalePair::IDENTITY);
    /// assert_eq!((p.scale, p.scale_inv), (128.0, 1.0 / 128.0));
    /// ```
    #[must_use]
    pub fn scale_from_amax(&self, amax: f32, fallback: ScalePair) -> ScalePair {
        if !(amax.is_finite() && amax > 0.0) {
            return fallback;
        }
        let mut sf = (self.target_max / amax) * pow2(-self.margin);
        if !sf.is_finite() {
            sf = f32::MAX;
        }
        if sf < f32::MIN_POSITIVE {
            sf = f32::MIN_POSITIVE;
        }
        if self.power_of_two {
            sf = pow2(floor_log2(sf));
        }
        ScalePair {
            scale: sf,
            scale_inv: 1.0 / sf,
        }
    }

    /// Current scaling: the scale from this tensor's own amax (identity if
    /// the amax is zero or not finite).
    #[must_use]
    pub fn current(&self, values: &[f32]) -> ScalePair {
        self.scale_from_amax(amax(values), ScalePair::IDENTITY)
    }
}

/// How the amax history is reduced to one value.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum AmaxReduction {
    /// Maximum over the window.
    #[default]
    Max,
    /// The most recently recorded amax.
    MostRecent,
}

/// Delayed scaling: the scale used at step `t` comes from the amaxes
/// recorded at steps before `t`.
///
/// Call [`DelayedScaling::scale`] to quantize, then
/// [`DelayedScaling::record`] with the amax observed in that step (or
/// [`DelayedScaling::record_tensor`]) to update the scale for the next one.
///
/// ```
/// use rune_lowp::{AmaxReduction, DelayedScaling, F8E4M3, ScalePair, ScalingRecipe};
///
/// let recipe = ScalingRecipe::for_element::<F8E4M3>();
/// let mut ds = DelayedScaling::new(recipe, 3, AmaxReduction::Max)?;
/// assert_eq!(ds.scale(), ScalePair::IDENTITY);
/// ds.record(4.0);
/// ds.record(1.0);
/// assert_eq!(ds.scale().scale, 448.0 / 4.0); // max over [4, 1]
/// ds.record(2.0);
/// ds.record(1.0); // the 4.0 falls out of the 3-step window
/// assert_eq!(ds.scale().scale, 448.0 / 2.0);
/// # Ok::<(), rune_lowp::LowpError>(())
/// ```
#[derive(Clone, Debug, PartialEq)]
pub struct DelayedScaling {
    recipe: ScalingRecipe,
    reduction: AmaxReduction,
    history: Vec<f32>,
    next: usize,
    filled: usize,
    scale: ScalePair,
}

/// Largest accepted history window.
pub const MAX_AMAX_HISTORY: usize = 1 << 20;

impl DelayedScaling {
    /// Starts with an empty history and the identity scale.
    ///
    /// # Errors
    ///
    /// [`LowpError::InvalidParameter`] unless
    /// `1 <= history_len <= MAX_AMAX_HISTORY`.
    pub fn new(
        recipe: ScalingRecipe,
        history_len: usize,
        reduction: AmaxReduction,
    ) -> Result<Self> {
        if history_len == 0 || history_len > MAX_AMAX_HISTORY {
            return Err(LowpError::InvalidParameter(
                "history_len must be in 1..=2^20",
            ));
        }
        Ok(Self {
            recipe,
            reduction,
            history: vec![0.0; history_len],
            next: 0,
            filled: 0,
            scale: ScalePair::IDENTITY,
        })
    }

    /// The scale to use now.
    #[must_use]
    pub const fn scale(&self) -> ScalePair {
        self.scale
    }

    /// The recipe.
    #[must_use]
    pub const fn recipe(&self) -> ScalingRecipe {
        self.recipe
    }

    /// The reduction.
    #[must_use]
    pub const fn reduction(&self) -> AmaxReduction {
        self.reduction
    }

    /// Window length.
    #[must_use]
    pub const fn history_len(&self) -> usize {
        self.history.len()
    }

    /// Recorded amaxes, oldest first (at most `history_len`).
    #[must_use]
    pub fn history(&self) -> Vec<f32> {
        let len = self.history.len();
        let start = (self.next + len - self.filled) % len;
        (0..self.filled)
            .map(|i| self.history[(start + i) % len])
            .collect()
    }

    /// The reduced amax the current scale was computed from (`0` before
    /// anything is recorded).
    #[must_use]
    pub fn reduced_amax(&self) -> f32 {
        if self.filled == 0 {
            return 0.0;
        }
        match self.reduction {
            AmaxReduction::Max => self.history().into_iter().fold(0.0, f32::max),
            AmaxReduction::MostRecent => {
                let len = self.history.len();
                self.history[(self.next + len - 1) % len]
            }
        }
    }

    /// Records one step's amax and recomputes the scale, which is returned.
    ///
    /// A NaN, infinite or negative amax (for example from a step that
    /// overflowed) is not recorded and leaves the scale unchanged, so one
    /// bad step cannot poison the window.
    pub fn record(&mut self, amax: f32) -> ScalePair {
        if amax.is_finite() && amax >= 0.0 {
            self.history[self.next] = amax;
            self.next = (self.next + 1) % self.history.len();
            self.filled = (self.filled + 1).min(self.history.len());
            self.scale = self.recipe.scale_from_amax(self.reduced_amax(), self.scale);
        }
        self.scale
    }

    /// Records the amax of `values`.
    pub fn record_tensor(&mut self, values: &[f32]) -> ScalePair {
        self.record(amax(values))
    }

    /// Clears the history and returns to the identity scale.
    pub fn reset(&mut self) {
        self.history.fill(0.0);
        self.next = 0;
        self.filled = 0;
        self.scale = ScalePair::IDENTITY;
    }
}

/// Quantizes `src` as `T(x · scale.scale)` (nearest even).
///
/// # Errors
///
/// [`LowpError::LengthMismatch`] if the slices differ in length.
pub fn quantize_scaled<T: Element>(
    src: &[f32],
    scale: ScalePair,
    overflow: Overflow,
    dst: &mut [T],
) -> Result<()> {
    check_len(src.len(), dst.len())?;
    let s = scale.scale;
    zip_chunks(src, dst, |a, b| {
        for (d, &x) in b.iter_mut().zip(a) {
            *d = T::from_f32_with(x * s, crate::Rounding::NearestEven, overflow);
        }
    });
    Ok(())
}

/// Restores `f32(q) · scale.scale_inv`.
///
/// # Errors
///
/// [`LowpError::LengthMismatch`] if the slices differ in length.
pub fn dequantize_scaled<T: Element>(src: &[T], scale: ScalePair, dst: &mut [f32]) -> Result<()> {
    check_len(src.len(), dst.len())?;
    let s = scale.scale_inv;
    zip_chunks(src, dst, |a, b| {
        for (d, &q) in b.iter_mut().zip(a) {
            *d = q.to_f32() * s;
        }
    });
    Ok(())
}

/// A row-major matrix quantized to `T` with one scale per
/// `block_rows × block_cols` tile (edge tiles may be smaller).
///
/// Each tile gets `recipe.scale_from_amax(tile_amax, IDENTITY)`, and its
/// values are stored as `T(x · scale)` with nearest-even rounding and
/// saturation.
///
/// ```
/// use rune_lowp::{BlockScaledMatrix, F8E4M3, ScalingRecipe};
///
/// let (rows, cols) = (2, 256);
/// let x: Vec<f32> = (0..rows * cols).map(|i| (i % 7) as f32 - 3.0).collect();
/// let recipe = ScalingRecipe::for_element::<F8E4M3>();
/// let m = BlockScaledMatrix::<F8E4M3>::quantize(&x, rows, cols, 1, 128, recipe)?;
/// assert_eq!(m.scales().len(), 4); // 2 rows × 2 column tiles
/// assert_eq!(m.scales()[0].scale, 448.0 / 3.0);
/// let y = m.dequantize();
/// assert!(x.iter().zip(&y).all(|(a, b)| (a - b).abs() <= 3.0 / 16.0));
/// # Ok::<(), rune_lowp::LowpError>(())
/// ```
#[derive(Clone, Debug, PartialEq)]
pub struct BlockScaledMatrix<T> {
    rows: usize,
    cols: usize,
    block_rows: usize,
    block_cols: usize,
    data: Vec<T>,
    scales: Vec<ScalePair>,
}

impl<T: Element> BlockScaledMatrix<T> {
    /// Quantizes a row-major `rows × cols` matrix.
    ///
    /// # Errors
    ///
    /// [`LowpError::InvalidShape`] for zero block sizes or overflowing
    /// shapes; [`LowpError::LengthMismatch`] if `values.len() != rows · cols`.
    pub fn quantize(
        values: &[f32],
        rows: usize,
        cols: usize,
        block_rows: usize,
        block_cols: usize,
        recipe: ScalingRecipe,
    ) -> Result<Self> {
        if block_rows == 0 || block_cols == 0 {
            return Err(LowpError::InvalidShape("block sizes must be non-zero"));
        }
        crate::blocks::check_shape(values.len(), rows, cols)?;
        let gr = rows.div_ceil(block_rows);
        let gc = cols.div_ceil(block_cols);
        // Tile amaxes, accumulated row by row (NaN-propagating).
        let mut amaxes = vec![0.0f32; gr * gc];
        for (r, row) in values.chunks(cols.max(1)).enumerate() {
            let g = &mut amaxes[(r / block_rows) * gc..(r / block_rows + 1) * gc];
            for (a, chunk) in g.iter_mut().zip(row.chunks(block_cols)) {
                let m = amax(chunk);
                *a = if a.is_nan() || m.is_nan() {
                    f32::NAN
                } else {
                    a.max(m)
                };
            }
        }
        let scales: Vec<ScalePair> = amaxes
            .iter()
            .map(|&a| recipe.scale_from_amax(a, ScalePair::IDENTITY))
            .collect();
        let mut data = vec![T::default(); values.len()];
        let quantize_row = |r: usize, src: &[f32], dst: &mut [T]| {
            let g = &scales[(r / block_rows) * gc..(r / block_rows + 1) * gc];
            for ((s, d), sp) in src
                .chunks(block_cols)
                .zip(dst.chunks_mut(block_cols))
                .zip(g)
            {
                for (q, &x) in d.iter_mut().zip(s) {
                    *q = T::from_f32_sat(x * sp.scale);
                }
            }
        };
        if cols > 0 {
            #[cfg(feature = "rayon")]
            {
                use rayon::prelude::*;
                if values.len() >= crate::slice::PARALLEL_THRESHOLD {
                    values
                        .par_chunks(cols)
                        .zip(data.par_chunks_mut(cols))
                        .enumerate()
                        .for_each(|(r, (s, d))| quantize_row(r, s, d));
                } else {
                    for (r, (s, d)) in values.chunks(cols).zip(data.chunks_mut(cols)).enumerate() {
                        quantize_row(r, s, d);
                    }
                }
            }
            #[cfg(not(feature = "rayon"))]
            for (r, (s, d)) in values.chunks(cols).zip(data.chunks_mut(cols)).enumerate() {
                quantize_row(r, s, d);
            }
        }
        Ok(Self {
            rows,
            cols,
            block_rows,
            block_cols,
            data,
            scales,
        })
    }

    /// Restores the matrix: `f32(q) · scale_inv` of its tile.
    #[must_use]
    pub fn dequantize(&self) -> Vec<f32> {
        let mut out = vec![0.0f32; self.data.len()];
        if self.cols == 0 {
            return out;
        }
        let gc = self.grid_cols();
        for (r, (src, dst)) in self
            .data
            .chunks(self.cols)
            .zip(out.chunks_mut(self.cols))
            .enumerate()
        {
            let g = &self.scales[(r / self.block_rows) * gc..(r / self.block_rows + 1) * gc];
            for ((s, d), sp) in src
                .chunks(self.block_cols)
                .zip(dst.chunks_mut(self.block_cols))
                .zip(g)
            {
                for (o, &q) in d.iter_mut().zip(s) {
                    *o = q.to_f32() * sp.scale_inv;
                }
            }
        }
        out
    }

    /// Quantized values, row-major.
    #[must_use]
    pub fn data(&self) -> &[T] {
        &self.data
    }

    /// Tile scales, row-major over the `grid_rows × grid_cols` grid.
    #[must_use]
    pub fn scales(&self) -> &[ScalePair] {
        &self.scales
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

    /// Tile height.
    #[must_use]
    pub const fn block_rows(&self) -> usize {
        self.block_rows
    }

    /// Tile width.
    #[must_use]
    pub const fn block_cols(&self) -> usize {
        self.block_cols
    }

    /// Tiles per column, `ceil(rows / block_rows)`.
    #[must_use]
    pub const fn grid_rows(&self) -> usize {
        self.rows.div_ceil(self.block_rows)
    }

    /// Tiles per row, `ceil(cols / block_cols)`.
    #[must_use]
    pub const fn grid_cols(&self) -> usize {
        self.cols.div_ceil(self.block_cols)
    }
}
