//! Lion: sign-of-momentum updates.

use crate::adamw::lerp;
use crate::error::{OptimError, non_negative, unit};
use crate::par;
use crate::params::{GroupOptions, ParamSet, Resolved};
use crate::{Optimizer, check_scale, check_state_count};

/// Lion hyperparameters (defaults: `lr = 1e-4`, `betas = (0.9, 0.99)`,
/// `weight_decay = 0.0`). Lion wants a learning rate 3–10× smaller and a
/// weight decay 3–10× larger than AdamW.
#[derive(Debug, Clone, Copy, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct LionConfig {
    /// Learning rate.
    pub lr: f32,
    /// `(beta1, beta2)`: interpolation for the update direction and the
    /// momentum decay.
    pub betas: (f32, f32),
    /// Decoupled weight decay coefficient.
    pub weight_decay: f32,
}

impl Default for LionConfig {
    fn default() -> Self {
        Self {
            lr: 1e-4,
            betas: (0.9, 0.99),
            weight_decay: 0.0,
        }
    }
}

impl LionConfig {
    fn validate(&self) -> Result<(), OptimError> {
        non_negative("lr", f64::from(self.lr))?;
        unit("beta1", f64::from(self.betas.0))?;
        unit("beta2", f64::from(self.betas.1))?;
        non_negative("weight_decay", f64::from(self.weight_decay))
    }
}

/// `sign(x)` with `sign(0) = 0` (and `NaN` kept).
#[inline]
fn sign(x: f32) -> f32 {
    if x > 0.0 {
        1.0
    } else if x < 0.0 {
        -1.0
    } else {
        x * 0.0
    }
}

/// Lion (Chen et al., "Symbolic Discovery of Optimization Algorithms").
///
/// ```text
/// p = p * (1 - lr * wd)
/// p = p - lr * sign(lerp(m, g, 1 - beta1))
/// m = lerp(m, g, 1 - beta2)
/// ```
///
/// `sign(0) = 0`, so a coordinate whose interpolated momentum is exactly
/// zero is not moved.
///
/// ```
/// use rune_optim::{Lion, LionConfig, Optimizer, ParamSet, ParamSpec};
///
/// let set = ParamSet::single_group(vec![ParamSpec::vector(3)])?;
/// let mut opt = Lion::new(set, LionConfig { lr: 0.5, ..Default::default() })?;
/// let mut w = vec![1.0f32, 1.0, 1.0];
/// opt.step(&mut [&mut w], &[&[3.0, -0.1, 0.0]])?;
/// assert_eq!(w, [0.5, 1.5, 1.0]);
/// # Ok::<(), rune_optim::OptimError>(())
/// ```
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Lion {
    set: ParamSet,
    config: LionConfig,
    step: u64,
    lr_scale: f64,
    momentum: Vec<Vec<f32>>,
}

impl Lion {
    /// A fresh optimizer with zero momentum.
    pub fn new(set: ParamSet, config: LionConfig) -> Result<Self, OptimError> {
        set.validate()?;
        config.validate()?;
        let momentum = set.specs().iter().map(|s| vec![0.0; s.len]).collect();
        Ok(Self {
            set,
            config,
            step: 0,
            lr_scale: 1.0,
            momentum,
        })
    }

    /// The configuration.
    #[must_use]
    pub const fn config(&self) -> &LionConfig {
        &self.config
    }

    /// Momentum of tensor `index`.
    #[must_use]
    pub fn momentum(&self, index: usize) -> Option<&[f32]> {
        self.momentum.get(index).map(Vec::as_slice)
    }
}

impl Optimizer for Lion {
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
        reason = "f64 scalars rounded to f32 once"
    )]
    fn step(&mut self, params: &mut [&mut [f32]], grads: &[&[f32]]) -> Result<(), OptimError> {
        self.set.check_slices(params, grads)?;
        self.config.validate()?;
        check_scale(self.lr_scale)?;
        check_state_count(self.momentum.len(), self.set.len())?;
        for (index, (m, s)) in self.momentum.iter().zip(self.set.specs()).enumerate() {
            if m.len() != s.len {
                return Err(OptimError::CorruptState {
                    index,
                    reason: "momentum length differs from the tensor",
                });
            }
        }
        for (i, ((p, g), m)) in params
            .iter_mut()
            .zip(grads)
            .zip(&mut self.momentum)
            .enumerate()
        {
            let h = Resolved::new(
                &self.set.group_of(i),
                self.config.lr,
                self.config.weight_decay,
                self.config.betas,
                self.lr_scale,
            );
            let decay = (1.0 - h.lr * h.wd) as f32;
            let lr = h.lr as f32;
            let w1 = (1.0 - h.beta1) as f32;
            let w2 = (1.0 - h.beta2) as f32;
            par::apply3(p, g, m, |p, g, m| {
                for ((p, &g), m) in p.iter_mut().zip(g).zip(m) {
                    *p *= decay;
                    *p -= lr * sign(lerp(*m, g, w1));
                    *m = lerp(*m, g, w2);
                }
            });
        }
        self.step += 1;
        Ok(())
    }
}
