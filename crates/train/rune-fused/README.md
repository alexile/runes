# rune-fused

> Fused transformer training ops with backward on f32 slices: RMSNorm, LayerNorm, gated MLP activations, rotary embeddings with long-context scaling, chunked linear + cross-entropy

[![crates.io](https://img.shields.io/crates/v/rune-fused)](https://crates.io/crates/rune-fused)
[![docs.rs](https://img.shields.io/docsrs/rune-fused)](https://docs.rs/rune-fused)
[![license](https://img.shields.io/crates/l/rune-fused)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

## What it does

The memory-bound ops of a transformer training step, each done in one pass
over its rows, with a hand-written backward pass. Inputs are plain
row-major `&[f32]` buffers with explicit sizes.

- **RMSNorm:** `x · rstd · w` with an optional weight, optional `(1 + w)`
  weighting, and residual-add fusion (`out = norm(x + residual)`, the sum
  written back as the new residual stream). Backward gives `dx`, `dw` and
  the residual gradient from the saved `rstd`.
- **LayerNorm:** weight and bias optional; backward gives `dx`, `dw`, `db`
  from the saved `mean` and `rstd`.
- **Gated MLP units:** SwiGLU, GeGLU (tanh and exact erf GELU) and gated
  squared ReLU, on separate `gate`/`up` buffers or the fused
  `[rows, 2·inter]` layout, plus the bare activations.
- **Rotary embeddings:** half-split (NeoX) and interleaved (GPT-J) pair
  layouts, partial rotary, per-token position ids for packed sequences,
  in-place apply and backward. Frequency scaling: linear position
  interpolation, NTK-aware, dynamic NTK, YaRN (ramp plus attention
  temperature, including the `mscale` / `mscale_all_dim` ratio) and
  wavelength-banded scaling. Tables are computed in `f64`, stored as `f32`.
- **Cross-entropy:** `ignore_index`, label smoothing, z-loss
  (`λ · lse²`), logit soft-capping, mean or sum reduction with the
  non-ignored token count as the normalizer. An all-ignored batch has loss
  0 and zero gradients.
- **Linear + cross-entropy, fused:** `hidden [T, H] · weight [V, H]ᵀ`
  chunked over tokens, so the `[T, V]` logits never exist. Each chunk
  becomes the loss and, in place, the logit gradient, which then feeds
  `dhidden` and `dweight` in the same pass. Peak extra memory is
  `chunk · V` floats. Matrix products use
  [`rune-gemm`](../rune-gemm).
- **Determinism:** work is split over fixed blocks of rows, every sum has a
  fixed order, and the norm weight/bias gradients combine per-block
  partial sums by a fixed pairwise tree, so results are bitwise identical
  for any thread count.
- **Safety:** every shape is validated and every failure is a
  `FusedError`. No `unsafe`, and no input makes it panic.

## Installation

```toml
[dependencies]
rune-fused = "0.1"
```

## Quickstart

RMSNorm forward and backward:

```rust
use rune_fused::RmsNorm;

let (rows, hidden) = (2, 4);
let norm = RmsNorm::new(hidden, 1e-6)?;
let x = [1.0f32, 2.0, 3.0, 4.0, -1.0, 0.5, 0.0, 2.0];
let w = [1.0f32; 4];
let (mut y, mut rstd) = (vec![0.0f32; rows * hidden], vec![0.0f32; rows]);
norm.forward(&x, Some(&w), &mut y, &mut rstd)?;

let dy = [1.0f32; 8];
let (mut dx, mut dw) = (vec![0.0f32; rows * hidden], vec![0.0f32; hidden]);
norm.backward(&dy, &x, Some(&w), &rstd, &mut dx, Some(&mut dw))?;
# Ok::<(), rune_fused::FusedError>(())
```

Rotary embeddings with YaRN scaling on packed sequences:

```rust
use rune_fused::{packed_positions, RopeConfig, RopeLayout, RopeScaling, RopeTable, YarnScaling};

let (heads, head_dim) = (2, 8);
let cfg = RopeConfig::new(head_dim, 10_000.0)?
    .with_scaling(RopeScaling::Yarn(YarnScaling::new(4.0, 4096)))?;
let table = RopeTable::new(&cfg, 16_384)?;
let pos = packed_positions(&[3, 2]); // two documents in one row
let mut q = vec![0.5f32; pos.len() * heads * head_dim];
table.apply(&mut q, heads, head_dim, &pos, RopeLayout::HalfSplit)?;
# Ok::<(), rune_fused::FusedError>(())
```

The output layer and loss without materializing the logits:

```rust
use rune_fused::{CrossEntropy, LinearCrossEntropy};

let (tokens, hidden, vocab) = (4, 3, 10);
let h = vec![0.1f32; tokens * hidden];
let w = vec![0.2f32; vocab * hidden];
let targets = [1i64, 4, -100, 9]; // -100 is ignored
let loss = CrossEntropy::new().with_z_loss(1e-4)?.with_label_smoothing(0.1)?;
let fused = LinearCrossEntropy::new(loss).with_chunk_tokens(2)?;
let (mut dh, mut dw) = (vec![0.0f32; h.len()], vec![0.0f32; w.len()]);
let out = fused.forward_backward(&h, &w, hidden, &targets, &mut dh, Some(&mut dw))?;
assert_eq!(out.valid_tokens, 3);
# Ok::<(), rune_fused::FusedError>(())
```

## Conventions

- **Shapes.** Rows are inferred from the buffer length and the row size;
  a buffer that is not a whole number of rows, or any output of the wrong
  length, is an error and nothing is written.
- **Gradients overwrite.** `dx`, `dw`, `db`, `dhidden` and `dweight` are
  overwritten, not accumulated.
- **Fused gated layout.** Each row of `gate_up` is `[gate | up]`.
- **Rotary input.** `[tokens, heads, head_dim]`, one position per token;
  only the first `rotary_dim` values of each head rotate. The backward is
  the transpose of the forward rotation, which is its exact inverse unless
  an attention temperature is applied.
- **Cross-entropy.** Label smoothing is uniform over the whole vocabulary;
  z-loss is reported both inside `loss` and separately. The fused op
  assumes an upstream gradient of 1 unless `with_grad_scale` says
  otherwise.
- **Numerics.** Pairwise summation for row reductions, two-pass variance
  for LayerNorm, online block log-sum-exp with a Kahan-compensated running
  sum, `(max - z_y) + ln Σ` for the loss so huge logits keep precision,
  `f64` rotary tables and `f64` exact GELU.
- **Not covered (yet).** Low-precision (bf16/fp16) inputs, a bias on the
  fused output projection, strided (non-contiguous) rotary inputs such as a
  packed QKV buffer, and SIMD-specialized element-wise kernels.

## License

MIT
