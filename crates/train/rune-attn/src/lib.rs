//! Tiled online-softmax attention, forward and backward, in `O(N)` extra
//! memory on plain `f32` slices.
//!
//! The attention matrix is never stored. The forward pass walks key
//! blocks for each query block and keeps a running maximum and sum per row
//! (the online softmax of "Online normalizer calculation for softmax"),
//! rescaling the output accumulator as the maximum grows, as in
//! "`FlashAttention`: Fast and Memory-Efficient Exact Attention with
//! IO-Awareness" and its follow-up on work partitioning. It returns the
//! output and the per-row log-sum-exp (LSE). The backward pass recomputes
//! the probabilities tile by tile from the LSE and the preprocessed
//! `D = rowsum(dO ∘ O)`.
//!
//! | Entry point | What it does |
//! |-------------|--------------|
//! | [`Attention::forward`] | output and LSE |
//! | [`Attention::backward`] | `dq`, `dk`, `dv` (and the dense-bias gradient) |
//! | [`Attention::forward_key_range`] | partial result over a range of key positions |
//! | [`Attention::forward_kv_chunked`] | the same result as `forward`, computed chunk by chunk over keys and merged |
//! | [`merge_partials`], [`merge_partials_into`] | the stable combine of two partial results (ring attention, split-KV decoding) |
//!
//! # Layout
//!
//! Tokens first, row-major, contiguous; see [`AttnLayout`]:
//! `q [tokens_q, heads_q, dim_qk]`, `k [tokens_k, heads_kv, dim_qk]`,
//! `v [tokens_k, heads_kv, dim_v]`, `out [tokens_q, heads_q, dim_v]`,
//! `lse [tokens_q, heads_q]`. A dense batch is `[batch, seq, heads, dim]`;
//! packed variable-length sequences are described by cumulative offsets
//! and never attend across their boundaries.
//!
//! # Scores and masks
//!
//! For query `i` and key `j` of one sequence (`seq_q` queries, `seq_k`
//! keys) and query head `h`:
//!
//! ```text
//! s = scale · q_i · k_j                 scale defaults to 1/sqrt(dim_qk)
//! s = cap · tanh(s / cap)               with a softcap
//! s = s + bias                          ALiBi slope or dense bias
//! s = -inf                              where masked
//! ```
//!
//! Masks use **bottom-right alignment**: query `i` sits at key position
//! `p = i + seq_k - seq_q`, so the last query lines up with the last key.
//! This is what decoding (one new query against a cache) and chunked
//! prefill (a block of new queries against all keys so far) need. Key `j`
//! is visible when
//!
//! - causal: `j <= p`;
//! - window `(left, right)`: `p - left <= j <= p + right` (either side may
//!   be unbounded; combined with causal, `right` is 0).
//!
//! With causal masking and `seq_q > seq_k` the first `seq_q - seq_k`
//! queries see nothing. A query that sees no key gets output `0`, LSE
//! `-inf` and zero gradients, never `NaN`.
//!
//! `ALiBi` adds `-slope[h] · |p - j|`.
//!
//! # Threads and determinism
//!
//! Work is split with rayon over (sequence, head, query block) in the
//! forward pass. The backward pass runs twice over the tiles: once over
//! (sequence, kv head, key block), summing `dk`/`dv` over the query heads
//! of the group and the query blocks in a fixed order, and once over
//! (sequence, head, query block) for `dq`. Nothing is accumulated across
//! threads, so results are **bitwise identical for any thread count**. The
//! price is recomputing the scores once more than a single fused pass with
//! atomic `dq` updates would.
//!
//! # Example
//!
//! ```
//! use rune_attn::{Attention, AttnInputs, AttnLayout, HeadDims};
//!
//! // 2 sequences of 5 tokens, 4 query heads sharing 2 kv heads, dim 8.
//! let layout = AttnLayout::dense(2, 5, 5, HeadDims::new(4, 2, 8, 8))?;
//! let q: Vec<f32> = (0..layout.q_len()).map(|i| (i as f32 * 0.37).sin()).collect();
//! let k: Vec<f32> = (0..layout.k_len()).map(|i| (i as f32 * 0.11).cos()).collect();
//! let v: Vec<f32> = (0..layout.v_len()).map(|i| (i as f32 * 0.07).sin()).collect();
//! let inputs = AttnInputs::new(&q, &k, &v);
//!
//! let attn = Attention::new().causal(true);
//! let fwd = attn.forward(&layout, &inputs)?;
//! assert_eq!(fwd.out.len(), layout.out_len());
//!
//! let d_out = vec![1.0f32; layout.out_len()];
//! let grads = attn.backward(&layout, &inputs, &fwd.out, &fwd.lse, &d_out)?;
//! assert_eq!(grads.dk.len(), layout.k_len());
//!
//! // Ring-style: two halves of the keys, merged, equal the full result.
//! let merged = attn.forward_kv_chunked(&layout, &inputs, 3)?;
//! for (a, b) in merged.out.iter().zip(&fwd.out) {
//!     assert!((a - b).abs() < 1e-5);
//! }
//! # Ok::<(), rune_attn::AttnError>(())
//! ```

#![warn(missing_docs)]
#![allow(
    clippy::many_single_char_names,
    clippy::similar_names,
    clippy::too_many_arguments
)]

mod error;
mod kernel;
mod layout;
mod mask;
mod merge;

use std::ops::Range;

pub use error::AttnError;
pub use layout::{AttnLayout, HeadDims};
pub use merge::{merge_partials, merge_partials_into};
pub use rune_gemm::{Gemm, Isa};

use kernel::Ctx;

/// The README examples, compiled and run as doc tests.
#[cfg(doctest)]
#[doc = include_str!("../README.md")]
struct ReadmeDoctests;

/// Default query block (tile rows).
pub const DEFAULT_BLOCK_Q: usize = 128;
/// Default key block (tile columns).
pub const DEFAULT_BLOCK_K: usize = 128;

/// An additive term on the logits, applied after the softcap.
#[derive(Debug, Clone, Copy, Default)]
pub enum Bias<'a> {
    /// No bias.
    #[default]
    None,
    /// `ALiBi`: one slope per query head (`heads_q` values); adds
    /// `-slope[h] · |p - j|` with `p` the aligned query position.
    Alibi(&'a [f32]),
    /// A dense bias, per sequence `[heads_q, seq_q, seq_k]`, sequences back
    /// to back ([`AttnLayout::bias_len`] values; `[batch, heads_q, seq_q,
    /// seq_k]` for a dense batch). Its gradient is returned by
    /// [`Attention::backward`]. `-inf` entries act as a mask.
    Dense(&'a [f32]),
}

/// The tensors of one call. See [`AttnLayout`] for their shapes.
#[derive(Debug, Clone, Copy)]
pub struct AttnInputs<'a> {
    /// Queries, `[tokens_q, heads_q, dim_qk]`.
    pub q: &'a [f32],
    /// Keys, `[tokens_k, heads_kv, dim_qk]`.
    pub k: &'a [f32],
    /// Values, `[tokens_k, heads_kv, dim_v]`.
    pub v: &'a [f32],
    /// Additive logit bias.
    pub bias: Bias<'a>,
}

impl<'a> AttnInputs<'a> {
    /// Queries, keys and values, no bias.
    #[must_use]
    pub const fn new(q: &'a [f32], k: &'a [f32], v: &'a [f32]) -> Self {
        Self {
            q,
            k,
            v,
            bias: Bias::None,
        }
    }

    /// Add a logit bias.
    #[must_use]
    pub const fn with_bias(mut self, bias: Bias<'a>) -> Self {
        self.bias = bias;
        self
    }
}

/// Forward result.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct AttnOutput {
    /// Output, `[tokens_q, heads_q, dim_v]`.
    pub out: Vec<f32>,
    /// Natural-log log-sum-exp of each row's final logits,
    /// `[tokens_q, heads_q]`; `-inf` for a row that sees no key.
    pub lse: Vec<f32>,
}

/// Backward result.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct AttnGrads {
    /// Gradient of `q`.
    pub dq: Vec<f32>,
    /// Gradient of `k`, summed over the query heads sharing each kv head.
    pub dk: Vec<f32>,
    /// Gradient of `v`, summed likewise.
    pub dv: Vec<f32>,
    /// Gradient of a [`Bias::Dense`] bias (same layout); `None` otherwise.
    pub dbias: Option<Vec<f32>>,
}

/// Attention settings. [`Attention::new`] is plain softmax attention with
/// scale `1/sqrt(dim_qk)`, no mask, multithreaded, with 128 × 128 tiles.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Attention {
    scale: Option<f32>,
    causal: bool,
    window_left: Option<usize>,
    window_right: Option<usize>,
    softcap: Option<f32>,
    block_q: usize,
    block_k: usize,
    parallel: bool,
    gemm: Gemm,
}

impl Default for Attention {
    fn default() -> Self {
        Self::new()
    }
}

impl Attention {
    /// Default settings.
    #[must_use]
    pub fn new() -> Self {
        Self {
            scale: None,
            causal: false,
            window_left: None,
            window_right: None,
            softcap: None,
            block_q: DEFAULT_BLOCK_Q,
            block_k: DEFAULT_BLOCK_K,
            parallel: true,
            gemm: Gemm::new().parallel(false),
        }
    }

    /// Logit scale (default `1/sqrt(dim_qk)`). Must be finite.
    #[must_use]
    pub const fn scale(mut self, scale: f32) -> Self {
        self.scale = Some(scale);
        self
    }

    /// Causal masking, bottom-right aligned (see the crate docs).
    #[must_use]
    pub const fn causal(mut self, causal: bool) -> Self {
        self.causal = causal;
        self
    }

    /// Sliding window: query position `p` sees keys `p - left ..= p +
    /// right`; `None` leaves a side unbounded. `(Some(w - 1), Some(0))` is
    /// a causal window of `w` keys.
    #[must_use]
    pub const fn window(mut self, left: Option<usize>, right: Option<usize>) -> Self {
        self.window_left = left;
        self.window_right = right;
        self
    }

    /// Tanh logit softcap `cap · tanh(s / cap)`; must be positive and
    /// finite. `0` turns it off.
    #[must_use]
    pub fn softcap(mut self, cap: f32) -> Self {
        self.softcap = if cap == 0.0 { None } else { Some(cap) };
        self
    }

    /// Tile sizes: `block_q` query rows by `block_k` keys. Both must be
    /// positive. Results depend on them only through rounding.
    #[must_use]
    pub const fn blocks(mut self, block_q: usize, block_k: usize) -> Self {
        self.block_q = block_q;
        self.block_k = block_k;
        self
    }

    /// Allow or forbid using more than one thread. Results do not change.
    #[must_use]
    pub const fn parallel(mut self, parallel: bool) -> Self {
        self.parallel = parallel;
        self
    }

    /// Kernel for the tile matrix products (always run single-threaded
    /// inside a tile).
    #[must_use]
    pub const fn gemm(mut self, gemm: Gemm) -> Self {
        self.gemm = gemm.parallel(false);
        self
    }

    fn ctx<'a>(
        &self,
        layout: &'a AttnLayout,
        inputs: &AttnInputs<'a>,
        keys: Option<(usize, usize)>,
    ) -> Result<Ctx<'a>, AttnError> {
        let check = |what, expected: usize, found: usize| {
            if expected == found {
                Ok(())
            } else {
                Err(AttnError::ShapeMismatch {
                    what,
                    expected,
                    found,
                })
            }
        };
        check("q", layout.q_len(), inputs.q.len())?;
        check("k", layout.k_len(), inputs.k.len())?;
        check("v", layout.v_len(), inputs.v.len())?;
        match inputs.bias {
            Bias::None => {}
            Bias::Alibi(s) => check("ALiBi slopes", layout.heads.heads_q, s.len())?,
            Bias::Dense(b) => check("bias", layout.bias_len(), b.len())?,
        }
        if self.block_q == 0 {
            return Err(AttnError::Zero { what: "block_q" });
        }
        if self.block_k == 0 {
            return Err(AttnError::Zero { what: "block_k" });
        }
        #[allow(clippy::cast_precision_loss)]
        let scale = self
            .scale
            .unwrap_or_else(|| 1.0 / (layout.heads.dim_qk as f32).sqrt());
        if !scale.is_finite() {
            return Err(AttnError::Parameter {
                what: "scale must be finite",
            });
        }
        if let Some(c) = self.softcap
            && !(c.is_finite() && c > 0.0)
        {
            return Err(AttnError::Parameter {
                what: "softcap must be positive and finite",
            });
        }
        Ok(Ctx {
            layout,
            q: inputs.q,
            k: inputs.k,
            v: inputs.v,
            bias: inputs.bias,
            scale,
            softcap: self.softcap,
            left: self.window_left,
            right: if self.causal {
                Some(0)
            } else {
                self.window_right
            },
            br: self.block_q,
            bc: self.block_k,
            gemm: self.gemm,
            parallel: self.parallel,
            keys,
        })
    }

    /// Attention output and per-row LSE.
    pub fn forward(
        &self,
        layout: &AttnLayout,
        inputs: &AttnInputs<'_>,
    ) -> Result<AttnOutput, AttnError> {
        self.ctx(layout, inputs, None)?.forward()
    }

    /// The partial result over key positions `keys` of every sequence
    /// (positions within the sequence, clipped to its length), with all
    /// masks evaluated at the true positions. Results over disjoint ranges
    /// combine with [`merge_partials`] into the full result; this is the
    /// per-step computation of ring attention and split-KV decoding.
    pub fn forward_key_range(
        &self,
        layout: &AttnLayout,
        inputs: &AttnInputs<'_>,
        keys: Range<usize>,
    ) -> Result<AttnOutput, AttnError> {
        if keys.start > keys.end {
            return Err(AttnError::Parameter {
                what: "key range start exceeds its end",
            });
        }
        self.ctx(layout, inputs, Some((keys.start, keys.end)))?
            .forward()
    }

    /// [`Attention::forward`] computed over key chunks of `chunk` positions,
    /// one [`Attention::forward_key_range`] each, combined with
    /// [`merge_partials_into`]. Equal to the full result up to rounding.
    pub fn forward_kv_chunked(
        &self,
        layout: &AttnLayout,
        inputs: &AttnInputs<'_>,
        chunk: usize,
    ) -> Result<AttnOutput, AttnError> {
        if chunk == 0 {
            return Err(AttnError::Zero { what: "chunk" });
        }
        let max_k = (0..layout.num_seqs())
            .map(|b| layout.seq_k(b))
            .max()
            .unwrap_or(0);
        let mut acc = self.forward_key_range(layout, inputs, 0..chunk.min(max_k))?;
        let mut start = chunk;
        while start < max_k {
            let part =
                self.forward_key_range(layout, inputs, start..start.saturating_add(chunk))?;
            merge_partials_into(&mut acc.out, &mut acc.lse, &part.out, &part.lse)?;
            start = start.saturating_add(chunk);
        }
        Ok(acc)
    }

    /// Gradients of `q`, `k`, `v` (and a dense bias) given the forward
    /// `out` and `lse` and the output gradient `d_out`.
    ///
    /// `out` and `lse` must come from [`Attention::forward`] with the same
    /// settings and inputs. Nothing of size `seq_q × seq_k` is allocated
    /// except the bias gradient itself.
    pub fn backward(
        &self,
        layout: &AttnLayout,
        inputs: &AttnInputs<'_>,
        out: &[f32],
        lse: &[f32],
        d_out: &[f32],
    ) -> Result<AttnGrads, AttnError> {
        let ctx = self.ctx(layout, inputs, None)?;
        for (what, expected, found) in [
            ("out", layout.out_len(), out.len()),
            ("lse", layout.lse_len(), lse.len()),
            ("d_out", layout.out_len(), d_out.len()),
        ] {
            if expected != found {
                return Err(AttnError::ShapeMismatch {
                    what,
                    expected,
                    found,
                });
            }
        }
        ctx.backward(out, lse, d_out)
    }
}
