//! Low-precision numerics for mixed-precision training, bit-exact with the
//! hardware formats.
//!
//! | Type | Bits | Layout | Max | Specials |
//! |------|------|--------|-----|----------|
//! | [`Bf16`] | 16 | E8M7, bias 127 | 3.39e38 | inf, NaN |
//! | [`F16`] | 16 | E5M10, bias 15 (IEEE binary16) | 65504 | inf, NaN |
//! | [`F8E4M3`] | 8 | E4M3, bias 7 (OCP FP8) | 448 | NaN only (`S.1111.111`) |
//! | [`F8E5M2`] | 8 | E5M2, bias 15 (OCP FP8) | 57344 | inf, NaN |
//! | [`F6E2M3`] | 6 | E2M3, bias 1 (OCP MX) | 7.5 | none |
//! | [`F6E3M2`] | 6 | E3M2, bias 3 (OCP MX) | 28 | none |
//! | [`F4E2M1`] | 4 | E2M1, bias 1 (OCP MX) | 6 | none |
//! | [`E8M0`] | 8 | unsigned exponent, bias 127 (OCP MX scale) | 2^127 | NaN (`0xFF`) |
//!
//! Conversions to `f32` are exact. Conversions from `f32` round exactly once
//! — to nearest even by default, toward zero, or stochastically from a
//! caller-supplied `u32` — and handle subnormals exactly. Overflow is
//! [`Overflow::NonSaturating`] (IEEE: infinity, or NaN for E4M3) or
//! [`Overflow::Saturating`] (clamp to the largest finite value). The MX
//! FP6/FP4 types always saturate, as the OCP spec defines.
//!
//! On top of the scalars:
//!
//! * slice conversions ([`from_f32_slice`], [`to_f32_slice`], ...) with
//!   vectorizable bf16/f16 kernels, table-driven FP8/6/4 decoding and, with
//!   the `rayon` feature, parallel chunks for large inputs;
//! * OCP MX block formats ([`MxTensor`]: 32-element blocks with an
//!   [`E8M0`] scale and FP8/FP6/FP4 elements, packed);
//! * FP4 with 16-element blocks, E4M3 block scales and an `f32` tensor
//!   scale ([`Fp4x16Tensor`]);
//! * FP8 training recipes: current and delayed per-tensor scaling
//!   ([`ScalingRecipe`], [`DelayedScaling`]) and fine-grained per-tile
//!   scaling of matrices ([`BlockScaledMatrix`]).
//!
//! # Example
//!
//! ```
//! use rune_lowp::{Bf16, F8E4M3, F8E5M2, F4E2M1, Overflow, Rounding};
//!
//! assert_eq!(Bf16::from_f32(1.0 + 1.0 / 256.0).to_f32(), 1.0); // tie → even
//! assert_eq!(F8E4M3::from_f32(464.0).to_f32(), 448.0);          // tie → even (448)
//! assert!(F8E4M3::from_f32(465.0).is_nan());                    // overflow → NaN
//! assert_eq!(F8E4M3::from_f32_sat(1e9).to_f32(), 448.0);        // saturating
//! assert_eq!(F8E5M2::from_f32(1e9).to_f32(), f32::INFINITY);
//! assert_eq!(F4E2M1::from_f32(2.5).to_f32(), 2.0);              // tie → even
//! assert_eq!(F4E2M1::from_f32(100.0).to_f32(), 6.0);            // FP4 always saturates
//!
//! // Stochastic rounding: 2.5 → 2 or 3, each half the time.
//! let lo = F4E2M1::from_f32_stochastic(2.5, 0xFFFF_FFFF).to_f32();
//! let hi = F4E2M1::from_f32_stochastic(2.5, 0).to_f32();
//! assert_eq!((lo, hi), (2.0, 3.0));
//! # let _ = (Overflow::Saturating, Rounding::NearestEven);
//! ```
//!
//! # Features
//!
//! * `serde` — the scalar types serialize as their raw bits (deserializing
//!   rejects out-of-range bits for the sub-byte types); the small config
//!   types ([`Rounding`], [`Overflow`], [`ScalePair`], [`ScalingRecipe`],
//!   [`MxElement`], ...) derive `Serialize` / `Deserialize`.
//! * `rayon` — parallel slice conversion, amax and block quantization above
//!   [`PARALLEL_THRESHOLD`] elements. Results are identical to the
//!   sequential path.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::cast_precision_loss,
    clippy::cast_lossless,
    clippy::many_single_char_names,
    clippy::similar_names,
    clippy::float_cmp,
    clippy::redundant_pub_crate,
    reason = "bit-level numerics: casts between code widths are the point, and are range-checked by construction"
)]

mod blocks;
mod e8m0;
mod error;
mod format;
mod fp4x16;
mod mx;
pub mod pack;
mod scaling;
mod slice;
mod types;

pub use e8m0::E8M0;
pub use error::{LowpError, Result};
pub use format::{Format, Overflow, Rounding, Specials};
pub use fp4x16::{FP4X16_BLOCK_SIZE, Fp4x16Tensor};
pub use mx::{MX_BLOCK_SIZE, MxElement, MxTensor, mx_block_scale};
pub use scaling::{
    AmaxReduction, BlockScaledMatrix, DelayedScaling, MAX_AMAX_HISTORY, ScalePair, ScalingRecipe,
    amax, dequantize_scaled, quantize_scaled,
};
pub use slice::{
    PARALLEL_THRESHOLD, from_f32_slice, from_f32_slice_stochastic, from_f32_vec, from_f32_vec_with,
    to_f32_slice, to_f32_vec,
};
pub use types::{Bf16, Element, F4E2M1, F6E2M3, F6E3M2, F8E4M3, F8E5M2, F16};
