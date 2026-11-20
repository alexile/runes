//! AdamW: Adam with decoupled weight decay.

use crate::error::{OptimError, non_negative, positive, unit};
use crate::par;
use crate::params::{GroupOptions, ParamSet, Resolved};
use crate::{Optimizer, check_scale, check_state_count};

/// AdamW hyperparameters (defaults: `lr = 1e-3`, `betas = (0.9, 0.999)`,
/// `eps = 1e-8`, `weight_decay = 0.01`).
#[derive(Debug, Clone, Copy, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct AdamWConfig {
    /// Learning rate.
    pub lr: f32,
    /// `(beta1, beta2)`: decay rates of the first and second moments.
    pub betas: (f32, f32),
    /// Added to the denominator for numerical stability.
    pub eps: f32,
    /// Decoupled weight decay coefficient (`p *= 1 - lr * weight_decay`).
    pub weight_decay: f32,
    /// Use the running maximum of the second moment (AMSGrad).
    pub amsgrad: bool,
    /// Put `eps` inside the square root: `sqrt(v_hat + eps)` instead of
    /// `sqrt(v_hat) + eps`.
    pub eps_inside_sqrt: bool,
}

impl Default for AdamWConfig {
    fn default() -> Self {
        Self {
            lr: 1e-3,
            betas: (0.9, 0.999),
            eps: 1e-8,
            weight_decay: 0.01,
            amsgrad: false,
            eps_inside_sqrt: false,
        }
    }
}

impl AdamWConfig {
    pub(crate) fn validate(&self) -> Result<(), OptimError> {
        non_negative("lr", f64::from(self.lr))?;
        unit("beta1", f64::from(self.betas.0))?;
        unit("beta2", f64::from(self.betas.1))?;
        positive("eps", f64::from(self.eps))?;
        non_negative("weight_decay", f64::from(self.weight_decay))
    }
}

/// Moments of one tensor.
#[derive(Debug, Clone, PartialEq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub(crate) struct AdamState {
    pub m: Vec<f32>,
    pub v: Vec<f32>,
    /// Running max of `v`; empty unless AMSGrad is on.
    pub v_max: Vec<f32>,
}

impl AdamState {
    pub(crate) fn new(len: usize, amsgrad: bool) -> Self {
        Self {
            m: vec![0.0; len],
            v: vec![0.0; len],
            v_max: if amsgrad { vec![0.0; len] } else { Vec::new() },
        }
    }

    pub(crate) const fn check(
        &self,
        index: usize,
        len: usize,
        amsgrad: bool,
    ) -> Result<(), OptimError> {
        let want_max = if amsgrad { len } else { 0 };
        if self.m.len() != len || self.v.len() != len {
            return Err(OptimError::CorruptState {
                index,
                reason: "moment length differs from the tensor",
            });
        }
        if self.v_max.len() != want_max {
            return Err(OptimError::CorruptState {
                index,
                reason: "AMSGrad buffer does not match the amsgrad setting",
            });
        }
        Ok(())
    }
}

/// `a + w * (b - a)`, evaluated the way the reference framework's `lerp`
/// does so the moments match it bit for bit.
#[inline]
pub(crate) fn lerp(a: f32, b: f32, w: f32) -> f32 {
    if w < 0.5 {
        a + w * (b - a)
    } else {
        b - (b - a) * (1.0 - w)
    }
}

/// Per-step scalars of an AdamW update, rounded to `f32` once.
#[derive(Debug, Clone, Copy)]
pub(crate) struct AdamScalars {
    decay: f32,
    one_minus_b1: f32,
    b2: f32,
    one_minus_b2: f32,
    step_size: f32,
    bc2_sqrt: f32,
    bc2: f32,
    eps: f32,
    eps_inside_sqrt: bool,
    amsgrad: bool,
}

impl AdamScalars {
    #[allow(
        clippy::cast_possible_truncation,
        reason = "f64 scalars rounded to f32 once"
    )]
    #[allow(clippy::cast_precision_loss, reason = "step counts are far below 2^53")]
    pub(crate) fn new(h: &Resolved, cfg: &AdamWConfig, t: u64) -> Self {
        let t = t as f64;
        let bc1 = 1.0 - h.beta1.powf(t);
        let bc2 = 1.0 - h.beta2.powf(t);
        Self {
            decay: (1.0 - h.lr * h.wd) as f32,
            one_minus_b1: (1.0 - h.beta1) as f32,
            b2: h.beta2 as f32,
            one_minus_b2: (1.0 - h.beta2) as f32,
            step_size: (h.lr / bc1) as f32,
            bc2_sqrt: bc2.sqrt() as f32,
            bc2: bc2 as f32,
            eps: cfg.eps,
            eps_inside_sqrt: cfg.eps_inside_sqrt,
            amsgrad: cfg.amsgrad,
        }
    }

    #[inline]
    fn denom(&self, v: f32) -> f32 {
        if self.eps_inside_sqrt {
            (v / self.bc2 + self.eps).sqrt()
        } else {
            v.sqrt() / self.bc2_sqrt + self.eps
        }
    }

    #[inline]
    fn moments(&self, p: &mut f32, g: f32, m: &mut f32, v: &mut f32) {
        *p *= self.decay;
        *m = lerp(*m, g, self.one_minus_b1);
        *v = *v * self.b2 + g * g * self.one_minus_b2;
    }

    /// One tensor, in place.
    pub(crate) fn apply(&self, p: &mut [f32], g: &[f32], st: &mut AdamState) {
        let s = *self;
        if s.amsgrad {
            par::apply5(
                p,
                g,
                &mut st.m,
                &mut st.v,
                &mut st.v_max,
                |p, g, m, v, vm| {
                    for ((((p, &g), m), v), vm) in p.iter_mut().zip(g).zip(m).zip(v).zip(vm) {
                        s.moments(p, g, m, v);
                        *vm = vm.max(*v);
                        *p -= s.step_size * (*m / s.denom(*vm));
                    }
                },
            );
        } else {
            par::apply4(p, g, &mut st.m, &mut st.v, |p, g, m, v| {
                for (((p, &g), m), v) in p.iter_mut().zip(g).zip(m).zip(v) {
                    s.moments(p, g, m, v);
                    *p -= s.step_size * (*m / s.denom(*v));
                }
            });
        }
    }
}

/// AdamW (Loshchilov & Hutter, "Decoupled Weight Decay Regularization").
///
/// Per element, at step `t` (starting at 1):
///
/// ```text
/// p  = p * (1 - lr * wd)
/// m  = lerp(m, g, 1 - beta1)
/// v  = beta2 * v + (1 - beta2) * g^2
/// v' = max(v', v)                          (AMSGrad only; used in place of v)
/// p  = p - lr / (1 - beta1^t) * m / (sqrt(v) / sqrt(1 - beta2^t) + eps)
/// ```
///
/// With `eps_inside_sqrt` the denominator is `sqrt(v / (1 - beta2^t) + eps)`.
/// Bias corrections and step size are computed in `f64` and rounded to
/// `f32` once per step; the element-wise work is plain `f32` (no fused
/// multiply-add), so results are bitwise reproducible across machines and
/// thread counts.
///
/// ```
/// use rune_optim::{AdamW, AdamWConfig, Optimizer, ParamSet, ParamSpec};
///
/// let set = ParamSet::single_group(vec![ParamSpec::vector(2)])?;
/// let mut opt = AdamW::new(set, AdamWConfig { lr: 0.1, weight_decay: 0.0, ..Default::default() })?;
/// let mut w = vec![1.0f32, -1.0];
/// opt.step(&mut [&mut w], &[&[0.5, -2.0]])?;
/// // The first Adam step moves each weight by about lr against its gradient sign.
/// assert!((w[0] - 0.9).abs() < 1e-6 && (w[1] + 0.9).abs() < 1e-6);
/// # Ok::<(), rune_optim::OptimError>(())
/// ```
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct AdamW {
    set: ParamSet,
    config: AdamWConfig,
    step: u64,
    lr_scale: f64,
    state: Vec<AdamState>,
}

impl AdamW {
    /// A fresh optimizer with zero moments.
    pub fn new(set: ParamSet, config: AdamWConfig) -> Result<Self, OptimError> {
        set.validate()?;
        config.validate()?;
        let state = set
            .specs()
            .iter()
            .map(|s| AdamState::new(s.len, config.amsgrad))
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
    pub const fn config(&self) -> &AdamWConfig {
        &self.config
    }

    /// First moment of tensor `index`.
    #[must_use]
    pub fn first_moment(&self, index: usize) -> Option<&[f32]> {
        self.state.get(index).map(|s| s.m.as_slice())
    }

    /// Second moment of tensor `index`.
    #[must_use]
    pub fn second_moment(&self, index: usize) -> Option<&[f32]> {
        self.state.get(index).map(|s| s.v.as_slice())
    }
}

impl Optimizer for AdamW {
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

    fn step(&mut self, params: &mut [&mut [f32]], grads: &[&[f32]]) -> Result<(), OptimError> {
        self.set.check_slices(params, grads)?;
        self.config.validate()?;
        check_scale(self.lr_scale)?;
        check_state_count(self.state.len(), self.set.len())?;
        for (i, (st, s)) in self.state.iter().zip(self.set.specs()).enumerate() {
            st.check(i, s.len, self.config.amsgrad)?;
        }
        let t = self.step + 1;
        for (i, ((p, g), st)) in params
            .iter_mut()
            .zip(grads)
            .zip(&mut self.state)
            .enumerate()
        {
            let h = Resolved::new(
                &self.set.group_of(i),
                self.config.lr,
                self.config.weight_decay,
                self.config.betas,
                self.lr_scale,
            );
            AdamScalars::new(&h, &self.config, t).apply(p, g, st);
        }
        self.step = t;
        Ok(())
    }
}
