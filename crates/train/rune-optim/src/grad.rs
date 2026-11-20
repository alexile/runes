//! Gradient utilities: global norm, clipping, accumulation and dynamic loss
//! scaling.

use crate::error::{OptimError, positive};
use crate::par;

/// The global L2 norm of a set of gradients.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct GradNorm {
    /// `sqrt(sum of squares)` over every element, accumulated in `f64`.
    /// `inf` if any element is infinite (or the sum overflows), `NaN` if any
    /// element is `NaN`.
    pub norm: f64,
    /// Whether every element (and the norm) is finite.
    pub finite: bool,
}

/// Global L2 norm of many slices.
///
/// Each element is squared in `f64` and summed over a fixed tree (fixed
/// chunks within a slice, slices in order), so the result is the same on any
/// number of threads. Infinite or `NaN` gradients are reported through
/// [`GradNorm::finite`]; an `f32` gradient cannot overflow the `f64` sum.
///
/// ```
/// use rune_optim::global_norm;
///
/// let n = global_norm(&[&[3.0], &[0.0, 4.0]]);
/// assert_eq!(n.norm, 5.0);
/// assert!(n.finite);
/// assert!(!global_norm(&[&[1.0, f32::NAN]]).finite);
/// ```
#[must_use]
pub fn global_norm(grads: &[&[f32]]) -> GradNorm {
    let mut sum = 0.0f64;
    let mut finite = true;
    for g in grads {
        finite &= g.iter().all(|v| v.is_finite());
        sum += par::sum_sq(g);
    }
    let norm = sum.sqrt();
    GradNorm {
        norm,
        finite: finite && norm.is_finite(),
    }
}

/// Clip gradients to a global L2 norm of at most `max_norm` and return the
/// norm before clipping.
///
/// When the norm exceeds `max_norm`, every element is multiplied by
/// `max_norm / norm` (computed in `f64`, applied as one `f32` factor), so
/// the clipped norm equals `max_norm` up to `f32` rounding. Gradients at or
/// below the limit are not touched (bit for bit), nor are non-finite
/// gradients: check [`GradNorm::finite`] and skip the step.
///
/// ```
/// use rune_optim::clip_grad_norm;
///
/// let mut g = vec![3.0f32, 4.0];
/// let before = clip_grad_norm(&mut [&mut g], 1.0)?;
/// assert_eq!(before.norm, 5.0);
/// assert_eq!(g, [0.6, 0.8]);
/// # Ok::<(), rune_optim::OptimError>(())
/// ```
pub fn clip_grad_norm(grads: &mut [&mut [f32]], max_norm: f64) -> Result<GradNorm, OptimError> {
    positive("max_norm", max_norm)?;
    let view: Vec<&[f32]> = grads.iter().map(|g| &**g).collect();
    let n = global_norm(&view);
    if n.finite && n.norm > max_norm {
        #[allow(clippy::cast_possible_truncation, reason = "one f32 factor")]
        let s = (max_norm / n.norm) as f32;
        scale_grads(grads, s);
    }
    Ok(n)
}

/// Multiply every gradient element by `factor`.
pub fn scale_grads(grads: &mut [&mut [f32]], factor: f32) {
    for g in grads {
        par::apply1(g, |g| {
            for v in g {
                *v *= factor;
            }
        });
    }
}

/// `acc += grad`, element-wise.
pub fn accumulate(acc: &mut [f32], grad: &[f32]) -> Result<(), OptimError> {
    if acc.len() != grad.len() {
        return Err(OptimError::LengthMismatch {
            what: "grad",
            index: 0,
            expected: acc.len(),
            found: grad.len(),
        });
    }
    par::apply2(acc, grad, |a, g| {
        for (a, &g) in a.iter_mut().zip(g) {
            *a += g;
        }
    });
    Ok(())
}

/// The factor that turns a sum of per-micro-batch mean gradients into the
/// mean over all micro-batches: `1 / micro_batches`.
///
/// When micro-batches hold different token counts, weight each one by
/// `tokens_i / total_tokens` instead ([`token_weight`]).
#[allow(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    reason = "counts"
)]
pub fn accumulation_factor(micro_batches: usize) -> Result<f32, OptimError> {
    if micro_batches == 0 {
        return Err(OptimError::InvalidHyperparameter {
            name: "micro_batches",
            value: 0.0,
            reason: "must be at least 1",
        });
    }
    Ok((1.0 / micro_batches as f64) as f32)
}

/// `tokens / total_tokens` in `f64`, rounded once: the weight of a
/// micro-batch's mean gradient when micro-batches differ in size.
#[allow(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    reason = "counts"
)]
pub fn token_weight(tokens: u64, total_tokens: u64) -> Result<f32, OptimError> {
    if total_tokens == 0 || tokens > total_tokens {
        return Err(OptimError::InvalidHyperparameter {
            name: "tokens",
            value: tokens as f64,
            reason: "must be at most total_tokens, which must be positive",
        });
    }
    Ok((tokens as f64 / total_tokens as f64) as f32)
}

/// Settings of [`LossScaler`]. Defaults: initial scale `2^16`, growth ×2
/// after 2000 clean steps, backoff ×0.5 on the first overflow, scale kept in
/// `[1, 2^24]`.
#[derive(Debug, Clone, Copy, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct LossScalerConfig {
    /// Initial scale.
    pub init_scale: f32,
    /// Multiplier applied after `growth_interval` consecutive clean steps.
    pub growth_factor: f32,
    /// Multiplier applied on overflow (in `(0, 1)`).
    pub backoff_factor: f32,
    /// Clean steps needed before growing.
    pub growth_interval: u32,
    /// Overflowing steps tolerated before backing off (1 backs off on every
    /// overflow). The count resets when the scale grows.
    pub hysteresis: u32,
    /// Lower bound of the scale.
    pub min_scale: f32,
    /// Upper bound of the scale.
    pub max_scale: f32,
}

impl Default for LossScalerConfig {
    fn default() -> Self {
        Self {
            init_scale: 65536.0,
            growth_factor: 2.0,
            backoff_factor: 0.5,
            growth_interval: 2000,
            hysteresis: 1,
            min_scale: 1.0,
            max_scale: 16_777_216.0,
        }
    }
}

/// Dynamic loss scaling for low-precision training.
///
/// Multiply the loss by [`Self::scale`] before the backward pass,
/// [`Self::unscale`] the gradients, then call [`Self::update`] with whether
/// they overflowed; skip the optimizer step when it returns `false`.
///
/// ```
/// use rune_optim::{LossScaler, LossScalerConfig};
///
/// let cfg = LossScalerConfig { init_scale: 8.0, growth_interval: 2, ..Default::default() };
/// let mut s = LossScaler::new(cfg)?;
/// let mut g = vec![16.0f32, -8.0];
/// let overflow = s.unscale(&mut [&mut g]);
/// assert_eq!(g, [2.0, -1.0]);
/// assert!(s.update(overflow));             // clean: step
/// assert!(s.update(false));                // second clean step: scale doubles
/// assert_eq!(s.scale(), 16.0);
/// assert!(!s.update(true));                // overflow: skip, halve
/// assert_eq!(s.scale(), 8.0);
/// # Ok::<(), rune_optim::OptimError>(())
/// ```
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct LossScaler {
    config: LossScalerConfig,
    scale: f32,
    clean_steps: u32,
    hysteresis_left: u32,
    skipped: u64,
}

impl LossScaler {
    /// A scaler at `config.init_scale`.
    pub fn new(config: LossScalerConfig) -> Result<Self, OptimError> {
        positive("init_scale", f64::from(config.init_scale))?;
        positive("min_scale", f64::from(config.min_scale))?;
        positive("max_scale", f64::from(config.max_scale))?;
        positive("growth_factor", f64::from(config.growth_factor))?;
        positive("backoff_factor", f64::from(config.backoff_factor))?;
        if config.growth_factor < 1.0 || config.backoff_factor >= 1.0 {
            return Err(OptimError::InvalidHyperparameter {
                name: "growth_factor / backoff_factor",
                value: f64::from(config.backoff_factor),
                reason: "need growth_factor >= 1 and backoff_factor < 1",
            });
        }
        if config.min_scale > config.max_scale {
            return Err(OptimError::InvalidHyperparameter {
                name: "min_scale",
                value: f64::from(config.min_scale),
                reason: "must not exceed max_scale",
            });
        }
        if config.growth_interval == 0 || config.hysteresis == 0 {
            return Err(OptimError::InvalidHyperparameter {
                name: "growth_interval / hysteresis",
                value: 0.0,
                reason: "must be at least 1",
            });
        }
        Ok(Self {
            config,
            scale: config.init_scale.clamp(config.min_scale, config.max_scale),
            clean_steps: 0,
            hysteresis_left: config.hysteresis,
            skipped: 0,
        })
    }

    /// The current scale.
    #[must_use]
    pub const fn scale(&self) -> f32 {
        self.scale
    }

    /// `loss * scale`.
    #[must_use]
    pub fn scale_loss(&self, loss: f32) -> f32 {
        loss * self.scale
    }

    /// Steps skipped because of overflow so far.
    #[must_use]
    pub const fn skipped_steps(&self) -> u64 {
        self.skipped
    }

    /// Divide the gradients by the scale and report whether any element is
    /// infinite or `NaN` (in which case the step should be skipped).
    pub fn unscale(&self, grads: &mut [&mut [f32]]) -> bool {
        let inv = 1.0 / self.scale;
        let mut bad = false;
        for g in grads.iter_mut() {
            bad |= !g.iter().all(|v| v.is_finite());
        }
        scale_grads(grads, inv);
        bad
    }

    /// Record the outcome of a step. Returns whether the optimizer should
    /// step (`false` after an overflow).
    pub fn update(&mut self, found_non_finite: bool) -> bool {
        let c = self.config;
        if found_non_finite {
            self.clean_steps = 0;
            self.skipped += 1;
            self.hysteresis_left = self.hysteresis_left.saturating_sub(1);
            if self.hysteresis_left == 0 {
                self.scale = (self.scale * c.backoff_factor).max(c.min_scale);
            }
            false
        } else {
            self.clean_steps += 1;
            if self.clean_steps >= c.growth_interval {
                self.clean_steps = 0;
                self.hysteresis_left = c.hysteresis;
                self.scale = (self.scale * c.growth_factor).min(c.max_scale);
            }
            true
        }
    }
}
