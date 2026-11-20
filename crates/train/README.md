# Train

Building blocks for training large language models, from number formats up to a
full training loop. Each crate does one job and can be used on its own; the
higher layers compose the lower ones.

Kernel crates work on plain `&[f32]` slices with explicit shapes, so they plug into
any tensor type. Everything is pure Rust, deterministic, and checked against
naive reference implementations and finite-difference gradients.

## Layers

| Layer | Crate | What it does | Status |
| --- | --- | --- | --- |
| Numerics | [`rune-lowp`](rune-lowp) | bf16, f16, fp8 (E4M3/E5M2), microscaling block formats (MX fp8/fp6/fp4, 16-element fp4 with fp8 scales), stochastic rounding, per-tensor delayed and current scaling | 0.1.0 |
| Kernels | [`rune-gemm`](rune-gemm) | Packed, cache-blocked, SIMD, multithreaded matrix multiply; batched and grouped (ragged MoE) GEMM; strided/transposed operands | 0.1.0 |
| Kernels | [`rune-attn`](rune-attn) | Tiled online-softmax attention forward and backward in O(N) memory: causal, GQA/MQA, sliding window, logit softcap, varlen packed sequences, log-sum-exp output and partial-result merging for ring attention | 0.1.0 |
| Kernels | [`rune-fused`](rune-fused) | Fused training ops with backward: RMSNorm, LayerNorm, SwiGLU/GeGLU, rotary embeddings (with long-context scaling), chunked linear + cross-entropy with z-loss and label smoothing | 0.1.0 |
| Framework | [`rune-tensor`](rune-tensor) | Strided n-d tensor: views, broadcasting, reductions, elementwise ops | planned |
| Framework | [`rune-autodiff`](rune-autodiff) | Reverse-mode autodiff tape over `rune-tensor`, wired to the fast kernels, with gradient checking | planned |
| Parallelism | [`rune-collective`](rune-collective) | Communicator trait plus in-process and TCP backends: ring/tree all-reduce, reduce-scatter, all-gather, all-to-all(v), broadcast, barrier, gradient bucketing | planned |
| Parallelism | [`rune-shard`](rune-shard) | Device mesh (data, fully-sharded, tensor, pipeline, context, expert axes), shard/replicate/partial placements, redistribution plans, ZeRO 1–3 partitioning | planned |
| Parallelism | [`rune-pipesched`](rune-pipesched) | Pipeline schedules (fill-drain, one-forward-one-backward, interleaved virtual stages, zero-bubble split backward, bidirectional), a validator and a bubble/memory simulator | planned |
| Parallelism | [`rune-moe`](rune-moe) | Mixture-of-experts routing: softmax/sigmoid top-k, group-limited routing, bias-based (aux-loss-free) balancing, auxiliary losses, capacity and dropping, token permute/unpermute, expert-parallel dispatch layout | planned |
| Optimization | [`rune-optim`](rune-optim) | AdamW, Lion, Adafactor, Muon (Newton–Schulz orthogonalization), schedules (warmup-cosine, warmup-stable-decay), global-norm clipping, EMA, flat sharded state | planned |
| Data | [`rune-bpe`](rune-bpe) | Byte-level BPE: fast trainer, encoder with a hand-written pre-tokenizer, special tokens, rank-file import/export | planned |
| Data | [`rune-neardup`](rune-neardup) | Exact and near-duplicate detection: shingling, MinHash, LSH banding, union-find clustering | planned |
| Data | [`rune-text-quality`](rune-text-quality) | Heuristic quality filters for web text: repetition, symbol ratios, line rules, stop-word presence, length bounds | planned |
| Data | [`rune-tokpack`](rune-tokpack) | Packed token shards on disk, sequence packing with document boundaries, deterministic resumable shuffled loading, weighted data mixtures | planned |
| Systems | [`rune-ckpt`](rune-ckpt) | Sharded checkpoints with a manifest, atomic commit, resharding to a different world size, safetensors-format tensors | planned |
| Systems | [`rune-trainguard`](rune-trainguard) | Run health: NaN/Inf and loss-spike detection, batch skipping, straggler detection, heartbeats and restart policy | planned |
| Post-training | [`rune-policy-grad`](rune-policy-grad) | RL and preference losses: PPO, group-relative advantages, decoupled clipping, GAE, KL estimators, token/sequence aggregation, DPO-family losses | planned |
| Model | [`rune-lm`](rune-lm) | Decoder-only transformer (GQA, RoPE, SwiGLU, RMSNorm, optional MoE) and a training loop that composes everything above | planned |

[All groups](../../README.md)
