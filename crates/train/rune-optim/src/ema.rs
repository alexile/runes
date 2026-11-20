//! Exponential moving average of parameters.

use crate::adamw::lerp;
use crate::error::{OptimError, finite, positive, unit};
use crate::par;

/// How the EMA decay ramps up from the first update.
#[derive(Debug, Clone, Copy, PartialEq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum EmaWarmup {
    /// The configured decay from the first update.
    None,
    /// `min(decay, (1 + t) / (10 + t))`.
    #[default]
    Ratio,
    /// `min(decay, 1 - (1 + t / gamma)^-power)`. `gamma = 1, power = 2/3`
    /// suits runs of ~1M steps, `power = 3/4` shorter ones.
    Power {
        /// Time scale.
        gamma: f32,
        /// Exponent.
        power: f32,
    },
}

/// A shadow copy of the parameters updated as
/// `shadow = decay_t * shadow + (1 - decay_t) * param` after each step.
///
/// `t` counts the updates made so far (0 for the first one). The decay is
/// computed in `f64` and rounded once per update.
///
/// ```
/// use rune_optim::{EmaWarmup, ParamEma};
///
/// let mut ema = ParamEma::new(&[&[0.0]], 0.9, EmaWarmup::None)?;
/// ema.update(&[&[1.0]])?;
/// assert!((ema.shadow(0).unwrap()[0] - 0.1).abs() < 1e-7);
/// # Ok::<(), rune_optim::OptimError>(())
/// ```
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ParamEma {
    decay: f32,
    warmup: EmaWarmup,
    updates: u64,
    shadow: Vec<Vec<f32>>,
}

impl ParamEma {
    /// Start from a copy of `params`.
    pub fn new(params: &[&[f32]], decay: f32, warmup: EmaWarmup) -> Result<Self, OptimError> {
        unit("decay", f64::from(decay))?;
        if let EmaWarmup::Power { gamma, power } = warmup {
            positive("gamma", f64::from(gamma))?;
            positive("power", f64::from(power))?;
        }
        Ok(Self {
            decay,
            warmup,
            updates: 0,
            shadow: params.iter().map(|p| p.to_vec()).collect(),
        })
    }

    /// The decay used by update number `t` (0-based).
    #[must_use]
    #[allow(
        clippy::cast_precision_loss,
        reason = "update counts are far below 2^53"
    )]
    pub fn decay_at(&self, t: u64) -> f64 {
        let d = f64::from(self.decay);
        let t = t as f64;
        match self.warmup {
            EmaWarmup::None => d,
            EmaWarmup::Ratio => d.min((1.0 + t) / (10.0 + t)),
            EmaWarmup::Power { gamma, power } => {
                d.min(1.0 - (1.0 + t / f64::from(gamma)).powf(-f64::from(power)))
            }
        }
        .max(0.0)
    }

    /// Updates made so far.
    #[must_use]
    pub const fn updates(&self) -> u64 {
        self.updates
    }

    /// Shadow of tensor `index`.
    #[must_use]
    pub fn shadow(&self, index: usize) -> Option<&[f32]> {
        self.shadow.get(index).map(Vec::as_slice)
    }

    fn check<T: AsRef<[f32]>>(&self, params: &[T]) -> Result<(), OptimError> {
        if params.len() != self.shadow.len() {
            return Err(OptimError::TensorCount {
                what: "params",
                expected: self.shadow.len(),
                found: params.len(),
            });
        }
        for (index, (s, p)) in self.shadow.iter().zip(params).enumerate() {
            if s.len() != p.as_ref().len() {
                return Err(OptimError::LengthMismatch {
                    what: "param",
                    index,
                    expected: s.len(),
                    found: p.as_ref().len(),
                });
            }
        }
        Ok(())
    }

    /// Fold the current parameters into the average.
    #[allow(clippy::cast_possible_truncation, reason = "decay rounded to f32 once")]
    pub fn update(&mut self, params: &[&[f32]]) -> Result<(), OptimError> {
        self.check(params)?;
        let d = self.decay_at(self.updates);
        finite("ema decay", d)?;
        let w = (1.0 - d) as f32;
        for (s, p) in self.shadow.iter_mut().zip(params) {
            par::apply2(s, p, |s, p| {
                for (s, &p) in s.iter_mut().zip(p) {
                    *s = lerp(*s, p, w);
                }
            });
        }
        self.updates += 1;
        Ok(())
    }

    /// Copy the averaged weights into `params` (for evaluation or export).
    pub fn copy_to(&self, params: &mut [&mut [f32]]) -> Result<(), OptimError> {
        self.check(params)?;
        for (s, p) in self.shadow.iter().zip(params.iter_mut()) {
            p.copy_from_slice(s);
        }
        Ok(())
    }
}
