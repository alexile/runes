//! Fused transformer training ops, forward and backward, on plain `f32`
//! slices.
//!
//! Activations are row-major `[rows, hidden]` buffers with explicit sizes,
//! so the ops plug into any tensor type. Every op validates its shapes and
//! returns a [`FusedError`] instead of panicking; on error no output is
//! written.
//!
//! | Op | Forward | Backward |
//! |----|---------|----------|
//! | [`RmsNorm`] | `x · rstd · w` (optional weight, `(1 + w)` offset, residual-add fusion) | `dx`, `dw`, residual gradient |
//! | [`LayerNorm`] | `(x - mean) · rstd · w + b` (weight, bias optional) | `dx`, `dw`, `db` |
//! | [`glu_forward`], [`glu_forward_fused`] | `f(gate) · up` for SwiGLU, GeGLU (tanh / erf), squared ReLU | `dgate`, `dup` |
//! | [`activation_forward`] | `f(x)` | `dx` |
//! | [`RopeTable`] | rotary embeddings, half-split or interleaved, partial, per-token positions | rotation by `-θ` |
//! | [`CrossEntropy`] | loss on given logits | `dlogits` |
//! | [`LinearCrossEntropy`] | `hidden · Wᵀ` + loss, chunked, no full logits | `dhidden`, `dweight` in the same pass |
//!
//! # Numerics
//!
//! - Row reductions (mean square, mean, variance, the dot products of the
//!   norm backward passes, the log-sum-exp) use pairwise summation with
//!   8-lane, 128-element leaves, so the error grows like `log n`.
//! - LayerNorm computes the variance from centred values in a second pass
//!   over the row (still in cache), avoiding `E[x²] - E[x]²` cancellation.
//! - The cross-entropy log-sum-exp is single-pass and online over 512-wide
//!   blocks; the running block sum is Kahan-compensated, the one place a
//!   long sequential `f32` sum remains. The loss uses `(max - z_y) + ln Σ`
//!   rather than `lse - z_y`, which keeps full precision for large logits.
//! - Norm weight and bias gradients reduce over rows in fixed 64-row
//!   blocks whose partial sums are combined by a pairwise tree in block
//!   order.
//! - Rotary cos/sin tables are computed in `f64` (including `p · θ`) and
//!   stored as `f32`; exact GELU evaluates `erf` in `f64`.
//!
//! # Threads and determinism
//!
//! Ops with at least [`PARALLEL_MIN_ELEMS`] elements run on the current
//! rayon pool, split over blocks of rows. Block boundaries and every
//! summation order depend only on the shapes, never on the thread count,
//! so results are bitwise identical on 1 or 64 threads.
//!
//! # Example
//!
//! ```
//! use rune_fused::{Activation, RmsNorm, glu_forward_fused};
//!
//! // Pre-norm with the residual add fused in, then a SwiGLU unit.
//! let norm = RmsNorm::new(2, 1e-6)?;
//! let x = [3.0f32, 4.0];
//! let mut residual = [0.0f32, 0.0];
//! let (mut y, mut rstd) = ([0.0f32; 2], [0.0f32]);
//! norm.forward_residual(&x, &mut residual, Some(&[1.0, 1.0]), &mut y, &mut rstd)?;
//! assert_eq!(residual, x);
//! assert!((y[0] - 3.0 / 12.5f32.sqrt()).abs() < 1e-6);
//!
//! let gate_up = [y[0], y[1], 1.0, 1.0]; // [gate | up]
//! let mut h = [0.0f32; 2];
//! glu_forward_fused(Activation::Silu, &gate_up, 2, &mut h)?;
//! assert!(h[1] > h[0]);
//! # Ok::<(), rune_fused::FusedError>(())
//! ```

#![warn(missing_docs)]
#![allow(
    clippy::too_many_arguments,
    clippy::suboptimal_flops,
    clippy::similar_names,
    clippy::many_single_char_names,
    clippy::doc_markdown
)]

mod act;
mod ce;
mod error;
mod norm;
mod reduce;
mod rope;

pub use act::{
    Activation, activation_backward, activation_forward, erf, erfc, glu_backward,
    glu_backward_fused, glu_forward, glu_forward_fused,
};
pub use ce::{CeLoss, CrossEntropy, LinearCrossEntropy, Reduction};
pub use error::FusedError;
pub use norm::{LayerNorm, RmsNorm};
pub use reduce::PARALLEL_MIN_ELEMS;
pub use rope::{RopeConfig, RopeLayout, RopeScaling, RopeTable, YarnScaling, packed_positions};

#[cfg(doctest)]
#[doc = include_str!("../README.md")]
struct ReadmeDoctests;
