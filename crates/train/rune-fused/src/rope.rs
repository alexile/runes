//! Rotary position embeddings (Su et al., "RoFormer: Enhanced Transformer
//! with Rotary Position Embedding") with long-context frequency scaling.

use crate::error::{FusedError, check_len, invalid, mul};
use crate::reduce::{rows_per_task, run_tasks, worth_parallel};

/// Which pairs of a head vector rotate together.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum RopeLayout {
    /// Pair `i` is `(x[i], x[i + r/2])` (the GPT-NeoX / Llama layout).
    #[default]
    HalfSplit,
    /// Pair `i` is `(x[2i], x[2i + 1])` (the GPT-J layout).
    Interleaved,
}

/// YaRN settings (Peng et al., "YaRN: Efficient Context Window Extension of
/// Large Language Models").
///
/// Dimensions whose wavelength fits many times into the original context
/// (`> beta_fast` rotations) keep their frequency, those that rotate fewer
/// than `beta_slow` times are interpolated by `factor`, and a linear ramp
/// blends the two in between. Cos and sin are multiplied by the attention
/// temperature [`attention_factor`](Self::attention_factor).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct YarnScaling {
    /// Context extension factor `s`.
    pub factor: f64,
    /// Context length the model was trained with.
    pub original_max_positions: usize,
    /// Rotation count above which a dimension is not interpolated (32).
    pub beta_fast: f64,
    /// Rotation count below which a dimension is fully interpolated (1).
    pub beta_slow: f64,
    /// `mscale` coefficient. Used only together with `mscale_all_dim`.
    pub mscale: Option<f64>,
    /// `mscale_all_dim` coefficient. When both it and `mscale` are set and
    /// non-zero, the temperature is `m(s, mscale) / m(s, mscale_all_dim)`.
    pub mscale_all_dim: Option<f64>,
    /// Explicit attention temperature, overriding the formulas.
    pub attention_factor: Option<f64>,
    /// Round the ramp ends to whole dimensions (floor/ceil), as in the
    /// reference implementation.
    pub truncate: bool,
}

impl YarnScaling {
    /// Defaults from the paper: `beta_fast = 32`, `beta_slow = 1`,
    /// truncated ramp, temperature `0.1 ln s + 1`.
    #[must_use]
    pub const fn new(factor: f64, original_max_positions: usize) -> Self {
        Self {
            factor,
            original_max_positions,
            beta_fast: 32.0,
            beta_slow: 1.0,
            mscale: None,
            mscale_all_dim: None,
            attention_factor: None,
            truncate: true,
        }
    }

    /// The attention temperature applied to cos and sin. With
    /// `m(s, c) = 0.1 · c · ln s + 1` for `s > 1` (else 1): the explicit
    /// value if given, else `m(s, mscale) / m(s, mscale_all_dim)` when both
    /// are non-zero, else `m(s, 1)`.
    #[must_use]
    pub fn attention_factor(&self) -> f64 {
        fn m(s: f64, c: f64) -> f64 {
            if s <= 1.0 {
                1.0
            } else {
                0.1 * c * s.ln() + 1.0
            }
        }
        if let Some(a) = self.attention_factor {
            return a;
        }
        match (self.mscale, self.mscale_all_dim) {
            (Some(a), Some(b)) if a != 0.0 && b != 0.0 => m(self.factor, a) / m(self.factor, b),
            _ => m(self.factor, 1.0),
        }
    }
}

/// How the inverse frequencies `θ_i = base^(-2i/r)` are adapted for
/// contexts longer than the training length.
#[derive(Debug, Clone, Copy, PartialEq)]
#[non_exhaustive]
pub enum RopeScaling {
    /// Plain rotary embeddings.
    None,
    /// Position interpolation (Chen et al., "Extending Context Window of
    /// Large Language Models via Positional Interpolation"):
    /// `θ_i / factor`.
    Linear {
        /// Interpolation factor.
        factor: f64,
    },
    /// NTK-aware base change: `base' = base · factor^(r / (r - 2))`.
    Ntk {
        /// Context extension factor.
        factor: f64,
    },
    /// Dynamic NTK: for a sequence of length `L > original_max_positions`,
    /// `base' = base · (factor · L / original - (factor - 1))^(r / (r - 2))`;
    /// unchanged otherwise. The table is built for `L = max_positions`.
    DynamicNtk {
        /// Context extension factor (`>= 1`).
        factor: f64,
        /// Context length the model was trained with.
        original_max_positions: usize,
    },
    /// YaRN ramp and attention temperature.
    Yarn(YarnScaling),
    /// Wavelength-banded scaling as used by Llama 3.1: with
    /// `λ_i = 2π / θ_i`, `λ_lo = original / low_freq_factor` and
    /// `λ_hi = original / high_freq_factor`, frequencies with `λ_i < λ_hi`
    /// are kept, those with `λ_i > λ_lo` are divided by `factor`, and in
    /// between `θ_i' = (1 - t) θ_i / factor + t θ_i` with
    /// `t = (original / λ_i - low_freq_factor) / (high_freq_factor - low_freq_factor)`.
    WavelengthBands {
        /// Divisor for the low-frequency band (8 in Llama 3.1).
        factor: f64,
        /// Lower wavelength-band factor (1 in Llama 3.1).
        low_freq_factor: f64,
        /// Upper wavelength-band factor (4 in Llama 3.1).
        high_freq_factor: f64,
        /// Context length the model was trained with (8192 in Llama 3.1).
        original_max_positions: usize,
    },
}

/// Rotary settings: rotary dimension `r` (even, at most the head size; only
/// the first `r` values of each head rotate), frequency base, scaling.
///
/// ```
/// use rune_fused::{RopeConfig, RopeScaling};
///
/// let cfg = RopeConfig::new(4, 10_000.0)?;
/// assert_eq!(cfg.inv_freq(0), vec![1.0, 0.01]);
/// let pi = cfg.with_scaling(RopeScaling::Linear { factor: 2.0 })?;
/// assert_eq!(pi.inv_freq(0), vec![0.5, 0.005]);
/// # Ok::<(), rune_fused::FusedError>(())
/// ```
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct RopeConfig {
    rotary_dim: usize,
    base: f64,
    scaling: RopeScaling,
}

fn pos_finite(name: &'static str, v: f64) -> Result<(), FusedError> {
    if v.is_finite() && v > 0.0 {
        Ok(())
    } else {
        Err(invalid(name, "must be finite and positive"))
    }
}

const fn nonzero(name: &'static str, v: usize) -> Result<(), FusedError> {
    if v == 0 {
        Err(invalid(name, "must be positive"))
    } else {
        Ok(())
    }
}

#[allow(clippy::cast_precision_loss)]
const fn f(v: usize) -> f64 {
    v as f64
}

impl RopeConfig {
    /// Unscaled rotary embeddings over `rotary_dim` (even, positive)
    /// dimensions with frequency base `base` (finite, `> 1`).
    pub fn new(rotary_dim: usize, base: f64) -> Result<Self, FusedError> {
        if rotary_dim == 0 || !rotary_dim.is_multiple_of(2) {
            return Err(invalid("rotary_dim", "must be even and positive"));
        }
        if !(base.is_finite() && base > 1.0) {
            return Err(invalid("base", "must be finite and greater than 1"));
        }
        Ok(Self {
            rotary_dim,
            base,
            scaling: RopeScaling::None,
        })
    }

    /// The same settings with a long-context scaling rule.
    pub fn with_scaling(mut self, scaling: RopeScaling) -> Result<Self, FusedError> {
        match scaling {
            RopeScaling::None => {}
            RopeScaling::Linear { factor } => pos_finite("factor", factor)?,
            RopeScaling::Ntk { factor } => {
                pos_finite("factor", factor)?;
                self.check_ntk_dim()?;
            }
            RopeScaling::DynamicNtk {
                factor,
                original_max_positions,
            } => {
                pos_finite("factor", factor)?;
                if factor < 1.0 {
                    return Err(invalid("factor", "must be at least 1"));
                }
                nonzero("original_max_positions", original_max_positions)?;
                self.check_ntk_dim()?;
            }
            RopeScaling::Yarn(y) => {
                pos_finite("factor", y.factor)?;
                pos_finite("beta_fast", y.beta_fast)?;
                pos_finite("beta_slow", y.beta_slow)?;
                nonzero("original_max_positions", y.original_max_positions)?;
                for (name, v) in [("mscale", y.mscale), ("mscale_all_dim", y.mscale_all_dim)] {
                    if v.is_some_and(|v| !v.is_finite()) {
                        return Err(invalid(name, "must be finite"));
                    }
                }
                if let Some(a) = y.attention_factor {
                    pos_finite("attention_factor", a)?;
                }
                pos_finite("attention_factor", y.attention_factor())?;
            }
            RopeScaling::WavelengthBands {
                factor,
                low_freq_factor,
                high_freq_factor,
                original_max_positions,
            } => {
                pos_finite("factor", factor)?;
                pos_finite("low_freq_factor", low_freq_factor)?;
                pos_finite("high_freq_factor", high_freq_factor)?;
                if high_freq_factor <= low_freq_factor {
                    return Err(invalid(
                        "high_freq_factor",
                        "must be greater than low_freq_factor",
                    ));
                }
                nonzero("original_max_positions", original_max_positions)?;
            }
        }
        self.scaling = scaling;
        Ok(self)
    }

    const fn check_ntk_dim(&self) -> Result<(), FusedError> {
        if self.rotary_dim <= 2 {
            Err(invalid(
                "rotary_dim",
                "NTK scaling needs more than 2 dimensions",
            ))
        } else {
            Ok(())
        }
    }

    /// Number of rotated dimensions `r`.
    #[must_use]
    pub const fn rotary_dim(&self) -> usize {
        self.rotary_dim
    }

    /// Frequency base.
    #[must_use]
    pub const fn base(&self) -> f64 {
        self.base
    }

    /// Scaling rule.
    #[must_use]
    pub const fn scaling(&self) -> RopeScaling {
        self.scaling
    }

    /// The factor cos and sin are multiplied by: the YaRN temperature, or 1.
    #[must_use]
    pub fn attention_factor(&self) -> f64 {
        match self.scaling {
            RopeScaling::Yarn(y) => y.attention_factor(),
            _ => 1.0,
        }
    }

    fn plain_inv_freq(&self, base: f64) -> Vec<f64> {
        let r = f(self.rotary_dim);
        (0..self.rotary_dim / 2)
            .map(|i| 1.0 / base.powf(f(2 * i) / r))
            .collect()
    }

    /// The `r / 2` inverse frequencies, in `f64`. `seq_len` matters only
    /// for [`RopeScaling::DynamicNtk`].
    #[must_use]
    pub fn inv_freq(&self, seq_len: usize) -> Vec<f64> {
        let r = f(self.rotary_dim);
        let ntk_exp = r / (r - 2.0);
        match self.scaling {
            RopeScaling::None => self.plain_inv_freq(self.base),
            RopeScaling::Linear { factor } => self
                .plain_inv_freq(self.base)
                .into_iter()
                .map(|v| v / factor)
                .collect(),
            RopeScaling::Ntk { factor } => self.plain_inv_freq(self.base * factor.powf(ntk_exp)),
            RopeScaling::DynamicNtk {
                factor,
                original_max_positions,
            } => {
                let base = if seq_len > original_max_positions {
                    let ratio = f(seq_len) / f(original_max_positions);
                    self.base * (factor * ratio - (factor - 1.0)).powf(ntk_exp)
                } else {
                    self.base
                };
                self.plain_inv_freq(base)
            }
            RopeScaling::Yarn(y) => self.yarn_inv_freq(&y),
            RopeScaling::WavelengthBands {
                factor,
                low_freq_factor,
                high_freq_factor,
                original_max_positions,
            } => {
                let old = f(original_max_positions);
                let low_wl = old / low_freq_factor;
                let high_wl = old / high_freq_factor;
                self.plain_inv_freq(self.base)
                    .into_iter()
                    .map(|v| {
                        let wl = std::f64::consts::TAU / v;
                        if wl < high_wl {
                            v
                        } else if wl > low_wl {
                            v / factor
                        } else {
                            let t =
                                (old / wl - low_freq_factor) / (high_freq_factor - low_freq_factor);
                            (1.0 - t) * v / factor + t * v
                        }
                    })
                    .collect()
            }
        }
    }

    fn yarn_inv_freq(&self, y: &YarnScaling) -> Vec<f64> {
        let r = f(self.rotary_dim);
        let orig = f(y.original_max_positions);
        // Dimension index at which a frequency completes `n` rotations over
        // the original context.
        let corr =
            |n: f64| (r * (orig / (n * std::f64::consts::TAU)).ln()) / (2.0 * self.base.ln());
        let (mut lo, mut hi) = (corr(y.beta_fast), corr(y.beta_slow));
        if y.truncate {
            lo = lo.floor();
            hi = hi.ceil();
        }
        lo = lo.max(0.0);
        hi = hi.min(r - 1.0);
        if (hi - lo).abs() == 0.0 {
            hi += 0.001;
        }
        self.plain_inv_freq(self.base)
            .into_iter()
            .enumerate()
            .map(|(i, extra)| {
                let ramp = ((f(i) - lo) / (hi - lo)).clamp(0.0, 1.0);
                let keep = 1.0 - ramp;
                let inter = extra / y.factor;
                inter * (1.0 - keep) + extra * keep
            })
            .collect()
    }
}

/// Precomputed `cos(p θ_i) · a` and `sin(p θ_i) · a` for positions
/// `0..len` (`a` is the attention factor), computed in `f64` and stored
/// as `f32`, laid out `[len, r / 2]`.
///
/// Inputs are `[tokens, heads, head_dim]`, row-major, with one position id
/// per token, so packed sequences (several documents in one row, each
/// restarting at 0, see [`packed_positions`]) work directly.
///
/// ```
/// use rune_fused::{RopeConfig, RopeLayout, RopeTable};
///
/// let table = RopeTable::new(&RopeConfig::new(2, 10_000.0)?, 4)?;
/// let mut q = [1.0f32, 0.0];        // one token, one head of size 2
/// table.apply(&mut q, 1, 2, &[1], RopeLayout::HalfSplit)?;
/// assert!((q[0] - 1f32.cos()).abs() < 1e-7 && (q[1] - 1f32.sin()).abs() < 1e-7);
/// table.apply_backward(&mut q, 1, 2, &[1], RopeLayout::HalfSplit)?; // rotate back
/// assert!((q[0] - 1.0).abs() < 1e-6 && q[1].abs() < 1e-6);
/// # Ok::<(), rune_fused::FusedError>(())
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct RopeTable {
    rotary_dim: usize,
    len: usize,
    cos: Vec<f32>,
    sin: Vec<f32>,
}

impl RopeTable {
    /// The table for `max_positions` positions under `config`.
    pub fn new(config: &RopeConfig, max_positions: usize) -> Result<Self, FusedError> {
        Self::from_inv_freq(
            &config.inv_freq(max_positions),
            config.attention_factor(),
            max_positions,
        )
    }

    /// A table from explicit inverse frequencies (one per rotated pair) and
    /// an attention factor.
    #[allow(clippy::cast_possible_truncation)]
    pub fn from_inv_freq(
        inv_freq: &[f64],
        attention_factor: f64,
        max_positions: usize,
    ) -> Result<Self, FusedError> {
        nonzero("inv_freq length", inv_freq.len())?;
        if inv_freq.iter().any(|v| !v.is_finite()) {
            return Err(invalid("inv_freq", "must be finite"));
        }
        if !attention_factor.is_finite() {
            return Err(invalid("attention_factor", "must be finite"));
        }
        let half = inv_freq.len();
        let total = mul(max_positions, half)?;
        let mut cos = vec![0.0f32; total];
        let mut sin = vec![0.0f32; total];
        let rpt = rows_per_task(half);
        let tasks: Vec<_> = cos
            .chunks_mut(rpt * half)
            .zip(sin.chunks_mut(rpt * half))
            .enumerate()
            .collect();
        run_tasks(worth_parallel(total), tasks, |(b, (c, s))| {
            let rows = c.chunks_exact_mut(half).zip(s.chunks_exact_mut(half));
            for (k, (c, s)) in rows.enumerate() {
                let p = f(b * rpt + k);
                for ((c, s), &w) in c.iter_mut().zip(s.iter_mut()).zip(inv_freq) {
                    let (sn, cs) = (p * w).sin_cos();
                    *c = (cs * attention_factor) as f32;
                    *s = (sn * attention_factor) as f32;
                }
            }
        });
        Ok(Self {
            rotary_dim: 2 * half,
            len: max_positions,
            cos,
            sin,
        })
    }

    /// Number of rotated dimensions `r`.
    #[must_use]
    pub const fn rotary_dim(&self) -> usize {
        self.rotary_dim
    }

    /// Number of positions covered.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Whether the table covers no positions.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// The `r / 2` cosines at `position`.
    #[must_use]
    pub fn cos(&self, position: usize) -> Option<&[f32]> {
        let h = self.rotary_dim / 2;
        self.cos.get(position * h..(position + 1) * h)
    }

    /// The `r / 2` sines at `position`.
    #[must_use]
    pub fn sin(&self, position: usize) -> Option<&[f32]> {
        let h = self.rotary_dim / 2;
        self.sin.get(position * h..(position + 1) * h)
    }

    /// Rotates the first `r` values of every head in place by `p θ_i`.
    /// `x: [tokens, heads, head_dim]` with `tokens = positions.len()`.
    pub fn apply(
        &self,
        x: &mut [f32],
        heads: usize,
        head_dim: usize,
        positions: &[usize],
        layout: RopeLayout,
    ) -> Result<(), FusedError> {
        self.rotate(x, heads, head_dim, positions, layout, false)
    }

    /// Backward of [`apply`](Self::apply), in place on the gradient:
    /// rotation by `-p θ_i` (the transpose). It is the exact inverse of
    /// `apply` when the attention factor is 1.
    pub fn apply_backward(
        &self,
        grad: &mut [f32],
        heads: usize,
        head_dim: usize,
        positions: &[usize],
        layout: RopeLayout,
    ) -> Result<(), FusedError> {
        self.rotate(grad, heads, head_dim, positions, layout, true)
    }

    fn rotate(
        &self,
        x: &mut [f32],
        heads: usize,
        head_dim: usize,
        positions: &[usize],
        layout: RopeLayout,
        inverse: bool,
    ) -> Result<(), FusedError> {
        nonzero("heads", heads)?;
        nonzero("head_dim", head_dim)?;
        if self.rotary_dim > head_dim {
            return Err(invalid("head_dim", "must be at least the rotary dimension"));
        }
        let row = mul(heads, head_dim)?;
        check_len("x", mul(positions.len(), row)?, x.len())?;
        if let Some((index, &position)) =
            positions.iter().enumerate().find(|&(_, &p)| p >= self.len)
        {
            return Err(FusedError::PositionOutOfRange {
                index,
                position,
                len: self.len,
            });
        }
        let half = self.rotary_dim / 2;
        let rpt = rows_per_task(row);
        let parallel = worth_parallel(x.len());
        let tasks: Vec<_> = x.chunks_mut(rpt * row).zip(positions.chunks(rpt)).collect();
        run_tasks(parallel, tasks, |(x, pos)| {
            for (tok, &p) in x.chunks_exact_mut(row).zip(pos) {
                let c = &self.cos[p * half..(p + 1) * half];
                let s = &self.sin[p * half..(p + 1) * half];
                for head in tok.chunks_exact_mut(head_dim) {
                    rotate_head(&mut head[..2 * half], c, s, layout, inverse);
                }
            }
        });
        Ok(())
    }
}

#[inline]
fn rotate_head(v: &mut [f32], c: &[f32], s: &[f32], layout: RopeLayout, inverse: bool) {
    let sign = if inverse { -1.0f32 } else { 1.0 };
    match layout {
        RopeLayout::HalfSplit => {
            let (a, b) = v.split_at_mut(c.len());
            for (((a, b), &c), &s) in a.iter_mut().zip(b.iter_mut()).zip(c).zip(s) {
                let s = sign * s;
                let (x0, x1) = (*a, *b);
                *a = x0 * c - x1 * s;
                *b = x1 * c + x0 * s;
            }
        }
        RopeLayout::Interleaved => {
            for ((pair, &c), &s) in v.as_chunks_mut::<2>().0.iter_mut().zip(c).zip(s) {
                let s = sign * s;
                let [x0, x1] = *pair;
                pair[0] = x0 * c - x1 * s;
                pair[1] = x1 * c + x0 * s;
            }
        }
    }
}

/// Position ids for packed sequences: `[0..l0, 0..l1, ...]`.
///
/// ```
/// assert_eq!(rune_fused::packed_positions(&[3, 2]), vec![0, 1, 2, 0, 1]);
/// ```
#[must_use]
pub fn packed_positions(seq_lens: &[usize]) -> Vec<usize> {
    seq_lens.iter().flat_map(|&l| 0..l).collect()
}
