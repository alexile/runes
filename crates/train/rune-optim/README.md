# rune-optim

> Optimizers and schedules for large-model training: AdamW, Lion, Adafactor, Muon, warmup-cosine and WSD schedules, global-norm clipping, loss scaling, EMA

[![crates.io](https://img.shields.io/crates/v/rune-optim)](https://crates.io/crates/rune-optim)
[![docs.rs](https://img.shields.io/docsrs/rune-optim)](https://docs.rs/rune-optim)
[![license](https://img.shields.io/crates/l/rune-optim)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

## What it does

Optimizer steps on plain `&mut [f32]` parameter and `&[f32]` gradient
slices, either one slice per tensor or one flat buffer with offsets (the
layout sharded data parallelism uses).

- **AdamW:** decoupled weight decay, bias correction, `sqrt(v̂) + eps`
  denominator as in the reference formulation, AMSGrad, optional
  `sqrt(v̂ + eps)` variant.
- **Lion:** `sign(lerp(m, g, 1 − β₁))` update, betas `(0.9, 0.99)`.
- **Adafactor:** row/column factored second moments for matrices, relative
  step size with parameter-RMS scaling, update clipping, `1 − t^−0.8`
  second-moment decay, optional first moment.
- **Muon:** momentum (Nesterov optional) orthogonalized by the quintic
  Newton–Schulz iteration (coefficients `3.4445, −4.7750, 2.0315`, 5 steps,
  Frobenius pre-normalization, transposed when `rows > cols`), matrix
  products on `rune-gemm`. Shape scaling `sqrt(max(1, rows/cols))` or the
  AdamW-RMS-matching `0.2 · sqrt(max(rows, cols))`, decoupled weight decay,
  AdamW fallback for vectors and for groups marked element-wise only.
- **QK-clip:** per-head rescaling of query/key projections when the max
  attention logit exceeds a threshold, exact per head, GQA aware.
- **Parameter groups:** per-group learning rate, weight decay and betas, a
  no-decay flag for norms, biases and embeddings, and a global learning-rate
  scale for schedules.
- **Schedules:** constant, linear warmup, warmup-cosine with min-lr ratio,
  warmup-stable-decay with linear / cosine / `1 − sqrt` tails, inverse sqrt,
  piecewise linear, concatenation. Endpoints are exact.
- **Gradients:** global L2 norm in `f64` with a fixed summation order and
  inf/NaN detection, clipping by global norm (returns the pre-clip norm),
  accumulation helpers, dynamic loss scaler with growth interval and
  hysteresis.
- **EMA:** parameter averaging with `(1 + t)/(10 + t)` or power warmup.
- **Resume:** with the `serde` feature every optimizer (with its state),
  schedule, scaler and EMA serializes; a restored optimizer continues bit for
  bit.

## Installation

```toml
[dependencies]
rune-optim = "0.1"
# rune-optim = { version = "0.1", features = ["serde"] }
```

## Quickstart

```rust
use rune_optim::{
    clip_grad_norm, AdamW, AdamWConfig, GroupOptions, Optimizer, ParamSet, ParamSpec, Schedule,
};

// A weight matrix (decayed) and a bias (not decayed).
let set = ParamSet::new(
    vec![ParamSpec::matrix(2, 2), ParamSpec::vector(2).in_group(1)],
    vec![GroupOptions::new(), GroupOptions::no_decay()],
)?;
let mut opt = AdamW::new(set, AdamWConfig { lr: 1e-2, weight_decay: 0.1, ..Default::default() })?;
let schedule = Schedule::warmup_cosine(1.0, 10, 100, 0.1)?;

let (mut w, mut b) = (vec![1.0f32; 4], vec![0.0f32; 2]);
for step in 0..100 {
    let mut gw: Vec<f32> = w.iter().map(|x| x - 0.5).collect();
    let mut gb: Vec<f32> = b.iter().map(|x| x - 1.0).collect();
    let norm = clip_grad_norm(&mut [&mut gw, &mut gb], 1.0)?;
    if !norm.finite {
        continue; // skip the step on inf/NaN gradients
    }
    opt.set_lr_scale(schedule.value(step + 1));
    opt.step(&mut [&mut w, &mut b], &[&gw, &gb])?;
}
assert!(w.iter().all(|x| (x - 0.5).abs() < 0.2));
# Ok::<(), rune_optim::OptimError>(())
```

Muon for the hidden matrices, AdamW for everything else:

```rust
use rune_optim::{GroupOptions, Muon, MuonConfig, MuonScale, Optimizer, ParamSet, ParamSpec};

let set = ParamSet::new(
    vec![
        ParamSpec::matrix(64, 16),              // hidden weight: Muon
        ParamSpec::matrix(100, 16).in_group(1), // embedding: AdamW
        ParamSpec::vector(16).in_group(2),      // norm gain: AdamW, no decay
    ],
    vec![
        GroupOptions::new(),
        GroupOptions::new().elementwise(),
        GroupOptions::no_decay(),
    ],
)?;
let cfg = MuonConfig {
    weight_decay: 0.1,
    scale: MuonScale::MatchAdamW { coefficient: 0.2 },
    ..Default::default()
};
let opt = Muon::new(set, cfg)?;
assert!(opt.is_matrix(0) && !opt.is_matrix(1) && !opt.is_matrix(2));
# Ok::<(), rune_optim::OptimError>(())
```

A flat buffer with aligned offsets:

```rust
use rune_optim::{FlatLayout, Lion, LionConfig, Optimizer, ParamSet, ParamSpec};

let set = ParamSet::single_group(vec![ParamSpec::vector(3), ParamSpec::matrix(2, 2)])?;
let layout = FlatLayout::aligned(&set, 4); // offsets 0 and 4, total 8
let mut opt = Lion::new(set, LionConfig { lr: 0.5, ..Default::default() })?;
let mut params = vec![1.0f32; layout.total()];
let grads = vec![1.0f32; layout.total()];
opt.step_flat(&layout, &mut params, &grads)?;
assert_eq!(params, [0.5, 0.5, 0.5, 1.0, 0.5, 0.5, 0.5, 0.5]); // padding untouched
# Ok::<(), rune_optim::OptimError>(())
```

## Conventions

- **Steps** count from 1; bias corrections use the step being taken.
- **Atomic errors.** A step validates every slice length, hyperparameter
  and the stored state first; on error nothing is modified and the step
  count does not advance. Every failure is an `OptimError`; no input panics.
- **Determinism.** Element-wise `f32` math in a fixed expression order (no
  fused multiply-add), per-step scalars computed in `f64` and rounded once,
  reductions over a fixed chunk tree. Same inputs, same bits, on any number
  of threads. Tensors of 2¹⁵+ elements are updated in parallel with rayon.
- **Matrices** are row-major `rows × cols` with rows = output features
  (`[out, in]`), which is what Muon's shape scaling and Adafactor's
  factoring assume.
- **Newton–Schulz band.** Singular values of `G` at least `1.5e-3 · ‖G‖_F`
  map into `[0.68, 1.21]`; smaller ones stay small (near-null directions are
  not amplified).

## Limitations

- `f32` parameters and state only; low-precision storage (bf16 moments,
  8-bit states) is out of scope here.
- Muon handles 2-D tensors; reshape convolution or stacked weights into
  matrices before registering them.
- With sharded data parallelism, Muon needs each matrix whole on one rank
  (element-wise optimizers work on any shard).
- Muon's Newton–Schulz runs in `f32` (the reference runs it in bf16); the
  SIMD and portable `rune-gemm` kernels agree to rounding, not bit for bit,
  so Muon results are bitwise reproducible per machine.

## License

MIT
