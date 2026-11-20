# rune-attn

> Tiled online-softmax attention forward and backward in O(N) memory: causal, sliding window, GQA/MQA, softcap, ALiBi/bias, varlen packing, LSE merging

[![crates.io](https://img.shields.io/crates/v/rune-attn)](https://crates.io/crates/rune-attn)
[![docs.rs](https://img.shields.io/docsrs/rune-attn)](https://docs.rs/rune-attn)
[![license](https://img.shields.io/crates/l/rune-attn)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

## What it does

Exact scaled-dot-product attention for training, on plain `&[f32]` slices,
without ever storing the `seq_q × seq_k` attention matrix:

- **Forward:** query blocks × key blocks with the online max/sum rescale
  ("Online normalizer calculation for softmax"; the tiled IO-aware
  attention papers). Returns the output and the per-row log-sum-exp.
- **Backward:** recomputes the probabilities tile by tile from the LSE,
  with the `D = rowsum(dO ∘ O)` preprocessing, and returns `dq`, `dk`,
  `dv` (and the dense-bias gradient). GQA `dk`/`dv` are summed over the
  query heads of each group.
- **Masks:** causal (bottom-right aligned when `seq_q != seq_k`, for
  decoding and chunked prefill), sliding window with independent left and
  right extents, packed variable-length sequences via cumulative offsets.
  Fully masked tiles are skipped.
- **Scores:** custom scale (default `1/sqrt(dim_qk)`), tanh softcap,
  ALiBi slopes or a dense additive bias.
- **Heads:** MHA, GQA, MQA; the query/key head dimension may differ from
  the value head dimension.
- **Partials:** `merge_partials` combines results over disjoint key sets
  (ring/context-parallel attention, split-KV decoding);
  `forward_key_range` computes one such partial with masks at the true
  positions, and `forward_kv_chunked` runs the whole thing chunk by chunk.
- **Threads:** rayon over (sequence, head, block). No cross-thread
  accumulation anywhere, so results are **bitwise identical for any
  thread count**.
- **Safety:** every shape and parameter is validated into an `AttnError`;
  no input makes it panic. No `unsafe` in this crate; the tile matrix
  products run on [`rune-gemm`](../rune-gemm)'s SIMD kernels.

## Installation

```toml
[dependencies]
rune-attn = "0.1"
```

## Quickstart

```rust
use rune_attn::{Attention, AttnInputs, AttnLayout, HeadDims};

// 2 sequences of 6 tokens, 4 query heads over 2 kv heads, dim 8.
let layout = AttnLayout::dense(2, 6, 6, HeadDims::new(4, 2, 8, 8))?;
let q = vec![0.1f32; layout.q_len()];
let k = vec![0.2f32; layout.k_len()];
let v = vec![0.3f32; layout.v_len()];
let inputs = AttnInputs::new(&q, &k, &v);

let attn = Attention::new().causal(true).softcap(50.0);
let fwd = attn.forward(&layout, &inputs)?;
let d_out = vec![1.0f32; layout.out_len()];
let grads = attn.backward(&layout, &inputs, &fwd.out, &fwd.lse, &d_out)?;
assert_eq!(grads.dq.len(), layout.q_len());
# Ok::<(), rune_attn::AttnError>(())
```

Packed documents and a sliding window:

```rust
use rune_attn::{Attention, AttnInputs, AttnLayout, HeadDims};

// Three documents of 5, 2 and 9 tokens in one row.
let cu = [0, 5, 7, 16];
let layout = AttnLayout::varlen(&cu, &cu, HeadDims::mha(2, 4))?;
let x = vec![0.5f32; layout.q_len()];
let attn = Attention::new().causal(true).window(Some(3), None);
let fwd = attn.forward(&layout, &AttnInputs::new(&x, &x, &x))?;
assert_eq!(fwd.lse.len(), 16 * 2);
# Ok::<(), rune_attn::AttnError>(())
```

Ring-style partial results:

```rust
use rune_attn::{merge_partials, Attention, AttnInputs, AttnLayout, HeadDims};

let layout = AttnLayout::dense(1, 4, 8, HeadDims::mha(1, 2))?;
let q = [0.3f32, -0.1, 0.2, 0.4, -0.5, 0.1, 0.0, 0.2];
let k: Vec<f32> = (0..16).map(|i| (i as f32 * 0.3).sin()).collect();
let v: Vec<f32> = (0..16).map(|i| (i as f32 * 0.7).cos()).collect();
let inputs = AttnInputs::new(&q, &k, &v);
let attn = Attention::new().causal(true);

let a = attn.forward_key_range(&layout, &inputs, 0..4)?;
let b = attn.forward_key_range(&layout, &inputs, 4..8)?;
let merged = merge_partials(&a.out, &a.lse, &b.out, &b.lse)?;
let full = attn.forward(&layout, &inputs)?;
for (x, y) in merged.out.iter().zip(&full.out) {
    assert!((x - y).abs() < 1e-6);
}
# Ok::<(), rune_attn::AttnError>(())
```

## Conventions

- **Layout.** Tokens first, contiguous: `q [tokens_q, heads_q, dim_qk]`,
  `k [tokens_k, heads_kv, dim_qk]`, `v [tokens_k, heads_kv, dim_v]`,
  `out [tokens_q, heads_q, dim_v]`, `lse [tokens_q, heads_q]`. A dense
  batch is `[batch, seq, heads, dim]`. A dense bias is
  `[heads_q, seq_q, seq_k]` per sequence, back to back.
- **Score order.** `scale · q·k`, then softcap, then bias, then mask.
- **Alignment.** Query `i` sits at key position `i + seq_k - seq_q`. Causal
  means `j <= that position`; a window `(left, right)` means
  `position - left <= j <= position + right`.
- **Empty rows.** A query that sees no key returns `0` with LSE `-inf`
  and gets zero gradient; nothing becomes `NaN`. The merge treats an LSE
  of `-inf` as "no contribution".
- **Backward cost.** To stay deterministic without atomics the backward
  runs two passes over the tiles (key-major for `dk`/`dv`, query-major for
  `dq` and the bias gradient), recomputing the scores in each.
- **Not covered (yet).** Dropout, strided (non-contiguous) inputs,
  low-precision inputs, a gradient for the LSE output, a bias broadcast
  over heads or batch, learned ALiBi slopes.

## Tests

Against a naive softmax reference in `f64` for every combination of
mask, softcap, bias and head grouping over odd shapes, `seq = 1` and
`seq_q != seq_k`; finite-difference gradients for `q`, `k`, `v` and the
bias; varlen equal (bit for bit) to running each sequence alone; chunked
and merged equal to full attention; bitwise determinism on 1, 2, 3 and 8
threads; huge logits staying finite; property tests over random shapes.

## Performance

Measured once with `cargo run --release -p rune-attn --example throughput`
(one sequence, 16 query / 4 kv heads, head dim 128, causal, 128 × 128
tiles, 16-thread x86-64 with AVX2):

| Configuration | Forward | Backward | Forward + backward |
|---------------|--------:|---------:|-------------------:|
| 2048 tokens, 16 threads | ~48k tok/s (~400 GFLOP/s) | ~19k tok/s | ~13.6k tok/s |
| 1024 tokens, 1 thread | ~12k tok/s (~51 GFLOP/s) | ~4.5k tok/s | ~3.3k tok/s |

Rough numbers from one run.

## License

MIT
