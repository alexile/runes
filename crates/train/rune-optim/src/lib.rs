//! Optimizers and schedules for large-model training on plain `f32` slices.
//!
//! | Item | What it does |
//! |------|--------------|
//! | [`AdamW`] | Adam with decoupled weight decay; AMSGrad and eps-inside-sqrt variants |
//! | [`Lion`] | sign-of-momentum update |
//! | [`Adafactor`] | factored second moments, relative step size, update clipping |
//! | [`Muon`] | Newton–Schulz orthogonalized momentum for matrices, AdamW for the rest |
//! | [`NewtonSchulz`] | the orthogonalization on its own |
//! | [`qk_clip`] | per-head query/key rescaling to cap attention logits |
//! | [`Schedule`] | constant, warmup, warmup-cosine, warmup-stable-decay, inverse sqrt, piecewise linear, concatenation |
//! | [`global_norm`], [`clip_grad_norm`] | deterministic `f64` global norm with inf/NaN detection, clipping |
//! | [`LossScaler`] | dynamic loss scaling with growth interval and hysteresis |
//! | [`ParamEma`] | parameter EMA with warmup |
//!
//! # Parameters and groups
//!
//! An optimizer manages a [`ParamSet`]: one [`ParamSpec`] per tensor (its
//! length, an optional `rows × cols` matrix shape and a group index) and a
//! list of [`GroupOptions`] overriding the learning rate, weight decay and
//! betas, or turning weight decay off for norms, biases and embeddings.
//!
//! [`Optimizer::step`] takes one parameter slice and one gradient slice per
//! tensor; [`Optimizer::step_flat`] takes one flat buffer of each, with a
//! [`FlatLayout`] giving every tensor's offset (the layout sharded data
//! parallelism uses). Optimizer state lives in the optimizer; with the
//! `serde` feature, the whole optimizer serializes and a restored copy
//! continues bit for bit.
//!
//! # Determinism
//!
//! Updates are element-wise `f32` arithmetic in a fixed expression order (no
//! fused multiply-add), with per-step scalars computed in `f64` and rounded
//! once. Tensors of at least [`PARALLEL_MIN_LEN`] elements are split into
//! chunks on the current rayon pool; reductions use a fixed tree of
//! [`REDUCE_CHUNK`]-element partials. Results are therefore bitwise identical
//! for any thread count. Muon's matrix products use `rune-gemm`, which is
//! also thread-count invariant.
//!
//! # Example
//!
//! ```
//! use rune_optim::{
//!     clip_grad_norm, AdamW, AdamWConfig, GroupOptions, Optimizer, ParamSet, ParamSpec, Schedule,
//! };
//!
//! // A weight matrix (decayed) and a bias (not decayed).
//! let set = ParamSet::new(
//!     vec![ParamSpec::matrix(2, 2), ParamSpec::vector(2).in_group(1)],
//!     vec![GroupOptions::new(), GroupOptions::no_decay()],
//! )?;
//! let mut opt = AdamW::new(set, AdamWConfig { lr: 1e-2, weight_decay: 0.1, ..Default::default() })?;
//! let schedule = Schedule::warmup_cosine(1.0, 10, 100, 0.1)?;
//!
//! let (mut w, mut b) = (vec![1.0f32; 4], vec![0.0f32; 2]);
//! for step in 0..100 {
//!     // Gradient of 0.5 * |w - 0.5|^2 + 0.5 * |b - 1|^2.
//!     let mut gw: Vec<f32> = w.iter().map(|x| x - 0.5).collect();
//!     let mut gb: Vec<f32> = b.iter().map(|x| x - 1.0).collect();
//!     clip_grad_norm(&mut [&mut gw, &mut gb], 1.0)?;
//!     opt.set_lr_scale(schedule.value(step + 1));
//!     opt.step(&mut [&mut w, &mut b], &[&gw, &gb])?;
//! }
//! assert!(w.iter().all(|x| (x - 0.5).abs() < 0.2));
//! # Ok::<(), rune_optim::OptimError>(())
//! ```
//!
//! # Features
//!
//! * `serde` — `Serialize` / `Deserialize` for optimizers (including their
//!   state), configs, parameter sets, layouts, schedules, the loss scaler
//!   and the EMA.

#![warn(missing_docs)]
#![allow(
    clippy::many_single_char_names,
    clippy::similar_names,
    clippy::redundant_pub_crate,
    clippy::doc_markdown,
    clippy::suboptimal_flops,
    reason = "math notation; algorithm names (AdamW, AMSGrad) are prose; mul_add changes rounding and is slow without hardware FMA, so updates use plain f32 ops on purpose"
)]

/// The README examples, compiled and run as doc tests.
#[cfg(doctest)]
#[doc = include_str!("../README.md")]
struct ReadmeDoctests;

mod adafactor;
mod adamw;
mod ema;
mod error;
mod grad;
mod lion;
mod muon;
mod par;
mod params;
mod qkclip;
mod schedule;

pub use adafactor::{Adafactor, AdafactorConfig};
pub use adamw::{AdamW, AdamWConfig};
pub use ema::{EmaWarmup, ParamEma};
pub use error::OptimError;
pub use grad::{
    GradNorm, LossScaler, LossScalerConfig, accumulate, accumulation_factor, clip_grad_norm,
    global_norm, scale_grads, token_weight,
};
pub use lion::{Lion, LionConfig};
pub use muon::{Muon, MuonConfig, MuonScale, NewtonSchulz};
pub use par::{PARALLEL_MIN_LEN, REDUCE_CHUNK};
pub use params::{FlatLayout, GroupOptions, ParamSet, ParamSpec};
pub use qkclip::{QkLayout, qk_clip};
pub use schedule::{DecayShape, Schedule};

/// The interface shared by every optimizer.
///
/// A step validates all inputs and the optimizer state before touching
/// anything; on error, parameters and state are unchanged.
pub trait Optimizer {
    /// The tensors and groups.
    fn param_set(&self) -> &ParamSet;

    /// Mutable group options (learning rates and the like can change between
    /// steps; the tensor list cannot).
    fn groups_mut(&mut self) -> &mut [GroupOptions];

    /// Steps taken so far.
    fn steps(&self) -> u64;

    /// The multiplier applied to every group's learning rate.
    fn lr_scale(&self) -> f64;

    /// Set the learning-rate multiplier, typically from a [`Schedule`]. It
    /// must be finite and non-negative; this is checked by the next step.
    fn set_lr_scale(&mut self, scale: f64);

    /// One step over per-tensor parameter and gradient slices, in
    /// [`ParamSet`] order.
    fn step(&mut self, params: &mut [&mut [f32]], grads: &[&[f32]]) -> Result<(), OptimError>;

    /// One step over flat parameter and gradient buffers laid out by
    /// `layout`. Identical, bit for bit, to [`Self::step`] on the same
    /// tensors.
    fn step_flat(
        &mut self,
        layout: &FlatLayout,
        params: &mut [f32],
        grads: &[f32],
    ) -> Result<(), OptimError> {
        let g = layout.split(self.param_set(), grads)?;
        let mut p = layout.split_mut(self.param_set(), params)?;
        self.step(&mut p, &g)
    }
}

pub(crate) fn check_scale(scale: f64) -> Result<(), OptimError> {
    error::non_negative("lr_scale", scale)
}

pub(crate) const fn check_state_count(state: usize, tensors: usize) -> Result<(), OptimError> {
    if state == tensors {
        Ok(())
    } else {
        Err(OptimError::CorruptState {
            index: if state < tensors { state } else { tensors },
            reason: "number of state entries differs from the tensors",
        })
    }
}
