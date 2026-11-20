# rune-gemm

> Packed, cache-blocked, SIMD, multithreaded CPU matrix multiply: strided/transposed f32/f64 GEMM, batched and grouped (ragged MoE)

[![crates.io](https://img.shields.io/crates/v/rune-gemm)](https://crates.io/crates/rune-gemm)
[![docs.rs](https://img.shields.io/docsrs/rune-gemm)](https://docs.rs/rune-gemm)
[![license](https://img.shields.io/crates/l/rune-gemm)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

## What it does

`C = alpha * op(A) * op(B) + beta * C` on plain `&[f32]` / `&[f64]` slices,
built the way the fast BLAS libraries are built:

- **Algorithm:** the five-loop blocked scheme of the Goto and BLIS papers.
  `B` is packed into `KC × NR` micro-panels, `A` into `MC × KC` blocks of
  `MR`-row panels, and a register-blocked micro-kernel computes each
  `MR × NR` tile of `C`. Edge tiles are zero-padded in the packed buffers.
- **Kernels:** 6 × 16 (`f32`) and 6 × 8 (`f64`) tiles for AVX2 + FMA and
  NEON, chosen at run time by CPU feature detection, plus a portable kernel
  that always works.
- **Operands:** any strides. Row-major, column-major, padded leading
  dimensions, free transposes (`MatRef::t` swaps strides), stride-0
  broadcast.
- **Threads:** rayon over row blocks (and column blocks when there are few
  rows). The `k` loop is never split, so results are **bitwise identical
  for any thread count**.
- **Batched GEMM:** strided batches, including interleaved layouts such as
  `[seq, heads, dim]` and a shared (stride-0) weight matrix.
- **Grouped GEMM:** ragged row groups of `A`/`C`, each with its own `B[g]`.
  This is the mixture-of-experts expert layer with tokens sorted by expert,
  run as one parallel job.
- **Safety:** views are validated (bounds, overflow, self-overlap of
  outputs), every failure is a `GemmError`, and no input makes it panic.
  `unsafe` is limited to the SIMD loads and stores, behind run-time CPU
  detection.

## Installation

```toml
[dependencies]
rune-gemm = "0.1"
```

## Quickstart

```rust
use rune_gemm::{gemm, MatMut, MatRef};

let a = [1.0f32, 2.0, 3.0, 4.0, 5.0, 6.0]; // 2 × 3, row-major
let b = [1.0f32, 0.0, 0.0, 1.0, 1.0, 1.0]; // 3 × 2
let mut c = [0.0f32; 4];
gemm(
    1.0,
    MatRef::row_major(&a, 2, 3)?,
    MatRef::row_major(&b, 3, 2)?,
    0.0,
    MatMut::row_major(&mut c, 2, 2)?,
)?;
assert_eq!(c, [4.0, 5.0, 10.0, 11.0]);
# Ok::<(), rune_gemm::GemmError>(())
```

A BLAS-style call (row-major, transpose flags, leading dimensions):

```rust
use rune_gemm::{sgemm, Transpose};

let a = [1.0, 4.0, 2.0, 5.0, 3.0, 6.0]; // stored 3 × 2, used as Aᵀ
let b = [1.0, 0.0, 0.0, 1.0, 1.0, 1.0];
let mut c = [0.0f32; 4];
sgemm(Transpose::Yes, Transpose::No, 2, 2, 3, 1.0, &a, 2, &b, 2, 0.0, &mut c, 2)?;
assert_eq!(c, [4.0, 5.0, 10.0, 11.0]);
# Ok::<(), rune_gemm::GemmError>(())
```

A mixture-of-experts layer: 3 experts with 2, 0 and 1 tokens.

```rust
use rune_gemm::{gemm_grouped, BatchRef, MatMut, MatRef};

let (k, n) = (2, 2);
let tokens = [1.0f32, 0.0, 0.0, 1.0, 1.0, 1.0]; // 3 × k, sorted by expert
let experts = [
    1.0, 2.0, 3.0, 4.0, // expert 0 (k × n)
    0.0, 0.0, 0.0, 0.0, // expert 1
    1.0, 0.0, 0.0, 1.0, // expert 2
];
let mut out = [0.0f32; 6];
gemm_grouped(
    1.0,
    MatRef::row_major(&tokens, 3, k)?,
    &[2, 0, 1],
    BatchRef::row_major(&experts, 3, k, n)?,
    0.0,
    MatMut::row_major(&mut out, 3, n)?,
)?;
assert_eq!(out, [1.0, 2.0, 3.0, 4.0, 1.0, 1.0]);
# Ok::<(), rune_gemm::GemmError>(())
```

Threading and kernel choice go through `Gemm`:

```rust
use rune_gemm::{Gemm, Isa};

let serial = Gemm::new().parallel(false);
let portable = Gemm::new().isa(Isa::Scalar);
println!("using {}", Gemm::new().kernel().name());
```

## Conventions

- **BLAS semantics.** `alpha == 0` or `k == 0`: `A` and `B` are not read
  and `C = beta * C`. `beta == 0`: `C` is overwritten without being read,
  so `NaN` in `C` does not survive.
- **Shapes.** `op(A)` is `m × k`, `op(B)` is `k × n`, `C` is `m × n`;
  anything else is `GemmError::DimensionMismatch`. Empty dimensions are
  fine.
- **Outputs.** A mutable view may not address an element twice
  (`GemmError::Overlapping`). Outputs with neither stride equal to 1 work
  through a dense scratch copy.
- **Determinism.** Same inputs, same bits, on any number of threads. The
  SIMD kernels use fused multiply-add and the portable kernel does not, so
  the two agree to rounding error, not bit for bit.
- **Not covered (yet).** AVX-512 kernels, complex types, mixed precision
  (low-precision inputs with `f32` accumulation), triangular and symmetric
  BLAS-3 routines.

## Performance

Measured once with `cargo run --release -p rune-gemm --example gflops`
(512 × 512 × 512, row-major, 16-thread x86-64 with AVX2):

| Configuration | GFLOP/s |
|---------------|--------:|
| `f32`, AVX2 + FMA, 1 thread | ~98 |
| `f32`, AVX2 + FMA, 16 threads | ~365 |
| `f32`, portable kernel, 1 thread | ~42 |
| `f64`, AVX2 + FMA, 1 thread | ~57 |
| `f64`, AVX2 + FMA, 16 threads | ~315 |

Rough numbers, from one run. At 512³ the multithreaded runs are limited by
per-call overhead; larger problems scale further. Problems under
`PARALLEL_MIN_MACS` (2¹⁸) multiply-adds run on one thread.

## License

MIT
