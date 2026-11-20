//! Adafactor: factored second moments with relative step sizes.

use rayon::prelude::*;

use crate::error::{OptimError, finite, non_negative, positive, unit};
use crate::par::{self, PARALLEL_MIN_LEN};
use crate::params::{GroupOptions, ParamSet};
use crate::{Optimizer, check_scale, check_state_count};

/// Adafactor hyperparameters. The defaults are the usual ones: relative
/// step size, parameter scaling, update clipping at 1, `beta2_t = 1 - t^-0.8`,
/// no first moment and no weight decay.
#[derive(Debug, Clone, Copy, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct AdafactorConfig {
    /// Fixed learning rate. `None` (and no group override) uses the relative
    /// step size `min(1e-2, 1 / sqrt(t))`.
    pub lr: Option<f32>,
    /// `(eps1, eps2)`: `eps1` is added to the squared gradient, `eps2` is
    /// the floor of the parameter RMS used by `scale_parameter`.
    pub eps: (f32, f32),
    /// Updates are scaled down so their RMS is at most this.
    pub clip_threshold: f32,
    /// Exponent of the second-moment decay `beta2_t = 1 - t^decay_rate`,
    /// in `[-1, 0]`.
    pub decay_rate: f32,
    /// First-moment coefficient; `None` keeps no first moment.
    pub beta1: Option<f32>,
    /// Weight decay, scaled by the step size (`p -= wd * lr * p`).
    pub weight_decay: f32,
    /// Multiply the step size by `max(eps2, RMS(p))`.
    pub scale_parameter: bool,
    /// Relative step only: ramp the step as `min(1e-6 * t, 1 / sqrt(t))`.
    pub warmup_init: bool,
}

impl Default for AdafactorConfig {
    fn default() -> Self {
        Self {
            lr: None,
            eps: (1e-30, 1e-3),
            clip_threshold: 1.0,
            decay_rate: -0.8,
            beta1: None,
            weight_decay: 0.0,
            scale_parameter: true,
            warmup_init: false,
        }
    }
}

impl AdafactorConfig {
    fn validate(&self) -> Result<(), OptimError> {
        if let Some(lr) = self.lr {
            non_negative("lr", f64::from(lr))?;
        }
        positive("eps1", f64::from(self.eps.0))?;
        non_negative("eps2", f64::from(self.eps.1))?;
        positive("clip_threshold", f64::from(self.clip_threshold))?;
        let d = f64::from(self.decay_rate);
        finite("decay_rate", d)?;
        if !(-1.0..=0.0).contains(&d) {
            return Err(OptimError::InvalidHyperparameter {
                name: "decay_rate",
                value: d,
                reason: "must be in [-1, 0]",
            });
        }
        if let Some(b1) = self.beta1 {
            unit("beta1", f64::from(b1))?;
        }
        non_negative("weight_decay", f64::from(self.weight_decay))
    }
}

/// Second-moment estimate of one tensor.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
enum SecondMoment {
    /// Row and column statistics of a `rows × cols` matrix.
    Factored { row: Vec<f32>, col: Vec<f32> },
    /// One value per element.
    Full(Vec<f32>),
}

#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
struct FactorState {
    second: SecondMoment,
    /// First moment; empty when `beta1` is `None`.
    m: Vec<f32>,
}

/// Adafactor (Shazeer & Stern, "Adafactor: Adaptive Learning Rates with
/// Sublinear Memory Cost").
///
/// For a matrix the second moment is kept as one value per row and per
/// column (`rows + cols` numbers instead of `rows * cols`):
///
/// ```text
/// beta2_t = 1 - t^decay_rate
/// R = beta2_t * R + (1 - beta2_t) * mean_cols(g^2 + eps1)
/// C = beta2_t * C + (1 - beta2_t) * mean_rows(g^2 + eps1)
/// u = g * rsqrt(R / mean(R)) ⊗ rsqrt(C)
/// u = u / max(1, RMS(u) / clip_threshold)
/// lr_t = (lr or min(1e-2, 1/sqrt(t))) * max(eps2, RMS(p))
/// m = beta1 * m + (1 - beta1) * lr_t * u                 (optional)
/// p = p - wd * lr_t * p - lr_t * u   (or - m)
/// ```
///
/// Other tensors keep a full second moment. Means and RMS values are
/// accumulated in `f64` over a fixed order, so results do not depend on the
/// thread count. The learning-rate scale ([`Optimizer::set_lr_scale`])
/// multiplies `lr_t`.
///
/// ```
/// use rune_optim::{Adafactor, AdafactorConfig, Optimizer, ParamSet, ParamSpec};
///
/// let set = ParamSet::single_group(vec![ParamSpec::matrix(2, 3)])?;
/// let mut opt = Adafactor::new(set, AdafactorConfig::default())?;
/// let mut w = vec![0.5f32; 6];
/// opt.step(&mut [&mut w], &[&[1.0, -1.0, 1.0, -1.0, 1.0, -1.0]])?;
/// // First step: relative step 1e-2 times RMS(p) = 0.5, clipped unit update.
/// assert!((w[0] - 0.495).abs() < 1e-6 && (w[1] - 0.505).abs() < 1e-6);
/// # Ok::<(), rune_optim::OptimError>(())
/// ```
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Adafactor {
    set: ParamSet,
    config: AdafactorConfig,
    step: u64,
    lr_scale: f64,
    state: Vec<FactorState>,
}

impl Adafactor {
    /// A fresh optimizer.
    pub fn new(set: ParamSet, config: AdafactorConfig) -> Result<Self, OptimError> {
        set.validate()?;
        config.validate()?;
        let state = set
            .specs()
            .iter()
            .map(|s| FactorState {
                second: match s.matrix {
                    Some((r, c)) => SecondMoment::Factored {
                        row: vec![0.0; r],
                        col: vec![0.0; c],
                    },
                    None => SecondMoment::Full(vec![0.0; s.len]),
                },
                m: if config.beta1.is_some() {
                    vec![0.0; s.len]
                } else {
                    Vec::new()
                },
            })
            .collect();
        Ok(Self {
            set,
            config,
            step: 0,
            lr_scale: 1.0,
            state,
        })
    }

    /// The configuration.
    #[must_use]
    pub const fn config(&self) -> &AdafactorConfig {
        &self.config
    }

    /// Number of `f32` values of optimizer state (the memory saving of
    /// factoring shows here).
    #[must_use]
    pub fn state_len(&self) -> usize {
        self.state
            .iter()
            .map(|s| {
                s.m.len()
                    + match &s.second {
                        SecondMoment::Factored { row, col } => row.len() + col.len(),
                        SecondMoment::Full(v) => v.len(),
                    }
            })
            .sum()
    }

    fn check_state(&self) -> Result<(), OptimError> {
        check_state_count(self.state.len(), self.set.len())?;
        for (index, (st, s)) in self.state.iter().zip(self.set.specs()).enumerate() {
            let ok = match (&st.second, s.matrix) {
                (SecondMoment::Factored { row, col }, Some((r, c))) => {
                    row.len() == r && col.len() == c
                }
                (SecondMoment::Full(v), None) => v.len() == s.len,
                _ => false,
            };
            let m_len = if self.config.beta1.is_some() {
                s.len
            } else {
                0
            };
            if !ok || st.m.len() != m_len {
                return Err(OptimError::CorruptState {
                    index,
                    reason: "state shape differs from the tensor",
                });
            }
        }
        Ok(())
    }

    #[allow(clippy::cast_precision_loss, reason = "step counts are far below 2^53")]
    fn step_size(&self, group: &GroupOptions, t: u64, p: &[f32]) -> f64 {
        let t = t as f64;
        let relative = || {
            let min_step = if self.config.warmup_init {
                1e-6 * t
            } else {
                1e-2
            };
            min_step.min(1.0 / t.sqrt())
        };
        let base = group.lr.or(self.config.lr).map_or_else(relative, f64::from);
        let scale = if self.config.scale_parameter {
            f64::from(self.config.eps.1).max(par::rms(p))
        } else {
            1.0
        };
        base * scale * self.lr_scale
    }
}

/// Row means of `rows × cols` row-major `x`, in `f64`.
#[allow(clippy::cast_precision_loss, reason = "dimensions fit f64")]
fn row_means(x: &[f32], cols: usize) -> Vec<f64> {
    let mean = |r: &[f32]| r.iter().map(|&v| f64::from(v)).sum::<f64>() / cols as f64;
    if x.len() >= PARALLEL_MIN_LEN {
        x.par_chunks(cols).map(mean).collect()
    } else {
        x.chunks(cols).map(mean).collect()
    }
}

/// Column means of `rows × cols` row-major `x`, in `f64`, summed in row
/// order.
#[allow(clippy::cast_precision_loss, reason = "dimensions fit f64")]
fn col_means(x: &[f32], rows: usize, cols: usize) -> Vec<f64> {
    let mut acc = vec![0.0f64; cols];
    for r in x.chunks(cols) {
        for (a, &v) in acc.iter_mut().zip(r) {
            *a += f64::from(v);
        }
    }
    for a in &mut acc {
        *a /= rows as f64;
    }
    acc
}

/// Update the row/column statistics from `g` and write the preconditioned
/// direction `g * rsqrt(R / mean(R)) ⊗ rsqrt(C)` into `u`.
#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    reason = "f64 means rounded to f32 once; dimensions fit f64"
)]
fn factored_direction(
    row: &mut [f32],
    col: &mut [f32],
    g: &[f32],
    u: &mut [f32],
    (b2, one_minus_b2): (f32, f32),
    eps1: f32,
) {
    let (rows, cols) = (row.len(), col.len());
    par::apply2(u, g, |u, g| {
        for (u, &g) in u.iter_mut().zip(g) {
            *u = g * g + eps1;
        }
    });
    let rm = row_means(u, cols);
    let cm = col_means(u, rows, cols);
    for (r, m) in row.iter_mut().zip(&rm) {
        *r = *r * b2 + (*m as f32) * one_minus_b2;
    }
    for (c, m) in col.iter_mut().zip(&cm) {
        *c = *c * b2 + (*m as f32) * one_minus_b2;
    }
    let row_mean = (row.iter().map(|&v| f64::from(v)).sum::<f64>() / rows as f64) as f32;
    let rf: Vec<f32> = row.iter().map(|&r| 1.0 / (r / row_mean).sqrt()).collect();
    let cf: Vec<f32> = col.iter().map(|&c| 1.0 / c.sqrt()).collect();
    let fill = |(r, (u, g)): (usize, (&mut [f32], &[f32]))| {
        let ri = rf[r];
        for ((u, &g), &cj) in u.iter_mut().zip(g).zip(&cf) {
            *u = ri * cj * g;
        }
    };
    if u.len() >= PARALLEL_MIN_LEN {
        u.par_chunks_mut(cols)
            .zip(g.par_chunks(cols))
            .enumerate()
            .for_each(fill);
    } else {
        u.chunks_mut(cols)
            .zip(g.chunks(cols))
            .enumerate()
            .for_each(fill);
    }
}

impl Optimizer for Adafactor {
    fn param_set(&self) -> &ParamSet {
        &self.set
    }

    fn groups_mut(&mut self) -> &mut [GroupOptions] {
        self.set.groups_mut()
    }

    fn steps(&self) -> u64 {
        self.step
    }

    fn lr_scale(&self) -> f64 {
        self.lr_scale
    }

    fn set_lr_scale(&mut self, scale: f64) {
        self.lr_scale = scale;
    }

    #[allow(
        clippy::cast_possible_truncation,
        clippy::cast_precision_loss,
        reason = "f64 scalars rounded to f32 once; step counts fit f64"
    )]
    fn step(&mut self, params: &mut [&mut [f32]], grads: &[&[f32]]) -> Result<(), OptimError> {
        self.set.check_slices(params, grads)?;
        self.config.validate()?;
        check_scale(self.lr_scale)?;
        self.check_state()?;
        let t = self.step + 1;
        let beta2 = 1.0 - (t as f64).powf(f64::from(self.config.decay_rate));
        let b2 = beta2 as f32;
        let one_minus_b2 = (1.0 - beta2) as f32;
        let eps1 = self.config.eps.0;
        let clip = f64::from(self.config.clip_threshold);
        let max_len = self.set.specs().iter().map(|s| s.len).max().unwrap_or(0);
        let mut scratch = vec![0.0f32; max_len];
        for i in 0..self.set.len() {
            let group = self.set.group_of(i);
            let lr = self.step_size(&group, t, params[i]);
            let wd = if group.no_decay {
                0.0
            } else {
                f64::from(group.weight_decay.unwrap_or(self.config.weight_decay))
            };
            let g = grads[i];
            let u = &mut scratch[..g.len()];
            let st = &mut self.state[i];
            match &mut st.second {
                SecondMoment::Factored { row, col } => {
                    factored_direction(row, col, g, u, (b2, one_minus_b2), eps1);
                }
                SecondMoment::Full(v) => {
                    par::apply3(u, g, v, |u, g, v| {
                        for ((u, &g), v) in u.iter_mut().zip(g).zip(v) {
                            *v = *v * b2 + (g * g + eps1) * one_minus_b2;
                            *u = g / v.sqrt();
                        }
                    });
                }
            }
            let denom = (par::rms(u) / clip).max(1.0) as f32;
            let lr32 = lr as f32;
            par::apply1(u, |u| {
                for u in u {
                    *u = (*u / denom) * lr32;
                }
            });
            if let Some(b1) = self.config.beta1 {
                let one_minus_b1 = 1.0 - b1;
                par::apply2(&mut st.m, u, |m, u| {
                    for (m, &u) in m.iter_mut().zip(u) {
                        *m = *m * b1 + u * one_minus_b1;
                    }
                });
                u.copy_from_slice(&st.m);
            }
            let decay = (-wd * lr) as f32;
            par::apply2(params[i], u, |p, u| {
                for (p, &u) in p.iter_mut().zip(u) {
                    *p += *p * decay;
                    *p -= u;
                }
            });
        }
        self.step = t;
        Ok(())
    }
}
