# rune-lowp

> Low-precision numerics for mixed-precision training: bf16, f16, fp8, MX block formats, stochastic rounding and FP8 scaling recipes

[![crates.io](https://img.shields.io/crates/v/rune-lowp)](https://crates.io/crates/rune-lowp)
[![docs.rs](https://img.shields.io/docsrs/rune-lowp)](https://docs.rs/rune-lowp)
[![license](https://img.shields.io/crates/l/rune-lowp)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

## What it does

The number formats used to train large models, bit for bit as the
hardware defines them, plus the scaling recipes that make them usable.

- **Scalars:** `Bf16`, `F16` (IEEE binary16), `F8E4M3` and `F8E5M2` (OCP
  FP8), `F6E2M3`, `F6E3M2` and `F4E2M1` (OCP MX element types), and the
  `E8M0` power-of-two scale. Every code decodes exactly to `f32`; encoding
  rounds once, with exact subnormals.
- **Rounding:** nearest-even (default), toward zero, or stochastic from a
  caller-supplied `u32` per value.
- **Overflow:** non-saturating (IEEE: infinity, or NaN for E4M3, which has
  no infinity) or saturating (clamp to the largest finite value). The MX
  FP6/FP4 types always saturate, as the spec defines.
- **Bulk conversion:** slice and `Vec` conversions with vectorizable
  bf16/f16 kernels and table-driven FP8/FP6/FP4 decoding; parallel above
  64Ki elements with the `rayon` feature.
- **Microscaling (OCP MX v1.0):** `MxTensor` with 32-element blocks, an
  E8M0 scale chosen from the block amax as in section 6.3, and FP8/FP6/FP4
  elements packed (FP4: two per byte, FP6: four per three bytes).
- **FP4 with 16-element blocks:** `Fp4x16Tensor` with an E4M3 scale per
  block and an `f32` scale per tensor.
- **FP8 training recipes:** current scaling, delayed scaling (amax history
  window, max or most-recent reduction, margin, optional power-of-two
  scales) and per-tile scaling of matrices (`1×128`, `128×128`, ...).

## Installation

```toml
[dependencies]
rune-lowp = "0.1"
```

Optional features:

- `serde`: the scalar types serialize as their raw bits (out-of-range
  bits are rejected when deserializing), and the config types
  (`Rounding`, `Overflow`, `ScalePair`, `ScalingRecipe`, `MxElement`, ...)
  derive `Serialize` / `Deserialize`.
- `rayon`: parallel slice conversion, amax and block quantization for
  large inputs. Results are identical to the sequential path.

## Quickstart

```rust
use rune_lowp::{Bf16, F8E4M3, F8E5M2, F4E2M1, Overflow, Rounding};

assert_eq!(Bf16::from_f32(1.0 + 1.0 / 256.0).to_f32(), 1.0); // tie → even
assert_eq!(F8E4M3::from_f32(464.0).to_f32(), 448.0);          // tie → even
assert!(F8E4M3::from_f32(465.0).is_nan());                    // overflow → NaN
assert_eq!(F8E4M3::from_f32_sat(1e9).to_f32(), 448.0);        // saturating
assert_eq!(F8E5M2::from_f32(1e9).to_f32(), f32::INFINITY);
assert_eq!(F4E2M1::from_f32(100.0).to_f32(), 6.0);            // FP4 always saturates

// Stochastic rounding: 2.25 → 3 for a quarter of the random numbers.
assert_eq!(F4E2M1::from_f32_stochastic(2.25, (1 << 30) - 1).to_f32(), 3.0);
assert_eq!(F4E2M1::from_f32_stochastic(2.25, 1 << 30).to_f32(), 2.0);
let _ = F8E4M3::from_f32_with(3.3, Rounding::TowardZero, Overflow::Saturating);
```

Microscaling and FP8 recipes:

```rust
use rune_lowp::{
    AmaxReduction, BlockScaledMatrix, DelayedScaling, F8E4M3, MxElement, MxTensor, ScalingRecipe,
};

let x: Vec<f32> = (0..256).map(|i| ((i * 37) % 101) as f32 / 50.0 - 1.0).collect();

// MXFP4: 8 blocks of 32, one E8M0 scale each, 128 bytes of packed codes.
let mx = MxTensor::quantize(MxElement::Fp4E2M1, &x)?;
assert_eq!((mx.scales().len(), mx.data().len()), (8, 128));
let _approx = mx.dequantize();

// Delayed per-tensor scaling for FP8 E4M3.
let recipe = ScalingRecipe::for_element::<F8E4M3>().with_margin(0)?;
let mut ds = DelayedScaling::new(recipe, 16, AmaxReduction::Max)?;
let scale = ds.scale();      // quantize this step with the current scale...
ds.record_tensor(&x);        // ...then record this step's amax for the next
assert_eq!(scale.scale, 1.0);
assert_eq!(ds.scale().scale, 448.0);

// 1×128 tiles, one scale per tile.
let m = BlockScaledMatrix::<F8E4M3>::quantize(&x, 2, 128, 1, 128, recipe)?;
assert_eq!(m.scales().len(), 2);
# Ok::<(), rune_lowp::LowpError>(())
```

## Conventions

- **NaN.** IEEE-style formats keep the sign and the top payload bits and
  quiet the NaN, as hardware conversions do. E4M3 NaN is `S.1111.111`. The
  FP6/FP4 types have no NaN: NaN converts to the largest positive value.
  Widening always produces a quiet NaN.
- **MX special blocks.** A block containing NaN or infinity gets the NaN
  scale (`0xFF`) and decodes to NaN; an all-zero block gets `2^-127`.
  Blocks run along rows and never span two rows; a short last block uses
  the amax of the elements it has.
- **MX scaling** divides by the power-of-two scale exactly, so the only
  rounding is the one into the element format.
- **Stochastic rounding** is exact when at most 32 bits are discarded
  (every case except results far below the smallest subnormal, where the
  probability is truncated to 32 bits).
- **Scaling recipes.** `scale = (target_max / amax) / 2^margin`. A zero,
  NaN or infinite amax keeps the previous scale (the identity for current
  and tile scaling), and in delayed scaling a non-finite amax is not
  recorded. An overflowing scale is capped at `f32::MAX`.
- **Errors.** Length and shape mismatches, zero block sizes and invalid
  parameters are `LowpError`s; nothing panics.
- **Custom formats.** `Format::new(exp_bits, man_bits, bias, specials)`
  describes any format up to 16 bits that fits in `f32`, and
  `Format::encode` / `Format::decode` work on it directly.

## Testing

- Every code of every type decodes to the value computed from its bit
  fields in `f64`, and every non-NaN code round-trips under every rounding
  mode.
- Encoding is checked against an independent search-based reference on
  every rounding boundary (each value, each midpoint, and the adjacent
  `f32`s), in all rounding and overflow modes, plus random bit patterns.
- The bf16 and f16 fast paths agree with the generic encoder on all 2^32
  `f32` inputs (an ignored test, about a minute in release).
- Stochastic rounding: exact threshold checks, statistical unbiasedness
  for each type, and accumulation that does not stagnate.
- MX quantization matches hand-computed examples and a naive reference
  implementation of the spec algorithm for every element type.

## License

MIT
