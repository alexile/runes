//! Tensor layout: head counts, head dimensions and sequence boundaries.

use crate::AttnError;

/// Head counts and head dimensions.
///
/// `heads_q` must be a positive multiple of `heads_kv`: query head `h` reads
/// key/value head `h / (heads_q / heads_kv)` (grouped-query attention;
/// `heads_kv == 1` is multi-query attention). `dim_qk` is the query/key head
/// dimension and `dim_v` the value (and output) head dimension; they may
/// differ.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct HeadDims {
    /// Query (and output) heads.
    pub heads_q: usize,
    /// Key/value heads.
    pub heads_kv: usize,
    /// Query/key head dimension.
    pub dim_qk: usize,
    /// Value/output head dimension.
    pub dim_v: usize,
}

impl HeadDims {
    /// Explicit head counts and dimensions.
    #[must_use]
    pub const fn new(heads_q: usize, heads_kv: usize, dim_qk: usize, dim_v: usize) -> Self {
        Self {
            heads_q,
            heads_kv,
            dim_qk,
            dim_v,
        }
    }

    /// Multi-head attention: as many key/value heads as query heads, one
    /// head dimension.
    #[must_use]
    pub const fn mha(heads: usize, dim: usize) -> Self {
        Self::new(heads, heads, dim, dim)
    }

    const fn validate(self) -> Result<Self, AttnError> {
        if self.heads_kv == 0 || self.heads_q == 0 || !self.heads_q.is_multiple_of(self.heads_kv) {
            return Err(AttnError::Heads {
                heads_q: self.heads_q,
                heads_kv: self.heads_kv,
            });
        }
        if self.dim_qk == 0 {
            return Err(AttnError::Zero { what: "dim_qk" });
        }
        if self.dim_v == 0 {
            return Err(AttnError::Zero { what: "dim_v" });
        }
        Ok(self)
    }
}

/// Where the sequences are in the packed token arrays.
///
/// All tensors are dense and row-major, tokens first:
///
/// | Tensor | Shape |
/// |--------|-------|
/// | `q` | `[total_q, heads_q, dim_qk]` |
/// | `k` | `[total_k, heads_kv, dim_qk]` |
/// | `v` | `[total_k, heads_kv, dim_v]` |
/// | `out`, `d_out` | `[total_q, heads_q, dim_v]` |
/// | `lse` | `[total_q, heads_q]` |
/// | dense bias | per sequence `[heads_q, seq_q, seq_k]`, sequences back to back |
///
/// Sequence `b` owns query tokens `cu_q[b]..cu_q[b + 1]` and key tokens
/// `cu_k[b]..cu_k[b + 1]`; it never sees another sequence's tokens. A
/// batch of equal-length sequences ([`AttnLayout::dense`]) is the special
/// case `cu_q = [0, s_q, 2 s_q, ...]`, so `q` is `[batch, seq_q, heads_q,
/// dim_qk]` and the dense bias is `[batch, heads_q, seq_q, seq_k]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttnLayout {
    pub(crate) cu_q: Vec<usize>,
    pub(crate) cu_k: Vec<usize>,
    pub(crate) bias_off: Vec<usize>,
    pub(crate) heads: HeadDims,
}

fn mul(a: usize, b: usize) -> Result<usize, AttnError> {
    a.checked_mul(b).ok_or(AttnError::Overflow)
}

impl AttnLayout {
    /// `batch` sequences of `seq_q` queries and `seq_k` keys each.
    pub fn dense(
        batch: usize,
        seq_q: usize,
        seq_k: usize,
        heads: HeadDims,
    ) -> Result<Self, AttnError> {
        // Reject sizes that cannot be addressed before allocating offsets.
        mul(batch, seq_q.max(seq_k).max(1))?;
        let n = batch.checked_add(1).ok_or(AttnError::Overflow)?;
        let offsets = |seq: usize| -> Result<Vec<usize>, AttnError> {
            let mut v = Vec::new();
            v.try_reserve_exact(n).map_err(|_| AttnError::Overflow)?;
            v.extend((0..n).map(|b| b * seq));
            Ok(v)
        };
        let cu_q = offsets(seq_q)?;
        let cu_k = offsets(seq_k)?;
        Self::build(cu_q, cu_k, heads)
    }

    /// Variable-length sequences packed back to back, described by
    /// cumulative offsets: both slices start at 0, never decrease and have
    /// one more entry than there are sequences.
    pub fn varlen(
        cu_seqlens_q: &[usize],
        cu_seqlens_k: &[usize],
        heads: HeadDims,
    ) -> Result<Self, AttnError> {
        Self::build(cu_seqlens_q.to_vec(), cu_seqlens_k.to_vec(), heads)
    }

    fn build(cu_q: Vec<usize>, cu_k: Vec<usize>, heads: HeadDims) -> Result<Self, AttnError> {
        let heads = heads.validate()?;
        if cu_q.is_empty() || cu_k.is_empty() {
            return Err(AttnError::Seqlens {
                reason: "offsets must have at least one entry",
            });
        }
        if cu_q.len() != cu_k.len() {
            return Err(AttnError::Seqlens {
                reason: "query and key offsets differ in length",
            });
        }
        if cu_q[0] != 0 || cu_k[0] != 0 {
            return Err(AttnError::Seqlens {
                reason: "offsets must start at 0",
            });
        }
        if cu_q.windows(2).any(|w| w[1] < w[0]) || cu_k.windows(2).any(|w| w[1] < w[0]) {
            return Err(AttnError::Seqlens {
                reason: "offsets must not decrease",
            });
        }
        let mut bias_off = Vec::with_capacity(cu_q.len());
        let mut acc = 0usize;
        bias_off.push(0);
        for b in 0..cu_q.len() - 1 {
            let block = mul(
                mul(heads.heads_q, cu_q[b + 1] - cu_q[b])?,
                cu_k[b + 1] - cu_k[b],
            )?;
            acc = acc.checked_add(block).ok_or(AttnError::Overflow)?;
            bias_off.push(acc);
        }
        let layout = Self {
            cu_q,
            cu_k,
            bias_off,
            heads,
        };
        // Make every tensor size representable up front.
        layout.q_len_checked()?;
        layout.k_len_checked()?;
        layout.v_len_checked()?;
        layout.out_len_checked()?;
        Ok(layout)
    }

    /// Head counts and dimensions.
    #[must_use]
    pub const fn heads(&self) -> HeadDims {
        self.heads
    }

    /// Number of sequences.
    #[must_use]
    pub const fn num_seqs(&self) -> usize {
        self.cu_q.len() - 1
    }

    /// Query tokens of sequence `b` (0 when out of range).
    #[must_use]
    pub fn seq_q(&self, b: usize) -> usize {
        match (self.cu_q.get(b), self.cu_q.get(b + 1)) {
            (Some(lo), Some(hi)) => hi - lo,
            _ => 0,
        }
    }

    /// Key tokens of sequence `b` (0 when out of range).
    #[must_use]
    pub fn seq_k(&self, b: usize) -> usize {
        match (self.cu_k.get(b), self.cu_k.get(b + 1)) {
            (Some(lo), Some(hi)) => hi - lo,
            _ => 0,
        }
    }

    /// Cumulative query offsets.
    #[must_use]
    pub fn cu_seqlens_q(&self) -> &[usize] {
        &self.cu_q
    }

    /// Cumulative key offsets.
    #[must_use]
    pub fn cu_seqlens_k(&self) -> &[usize] {
        &self.cu_k
    }

    /// Total query tokens.
    #[must_use]
    pub fn total_q(&self) -> usize {
        self.cu_q.last().copied().unwrap_or(0)
    }

    /// Total key tokens.
    #[must_use]
    pub fn total_k(&self) -> usize {
        self.cu_k.last().copied().unwrap_or(0)
    }

    fn q_len_checked(&self) -> Result<usize, AttnError> {
        mul(
            mul(self.total_q(), self.heads.heads_q)?,
            self.heads.dim_qk.max(self.heads.dim_v),
        )
    }

    fn k_len_checked(&self) -> Result<usize, AttnError> {
        mul(mul(self.total_k(), self.heads.heads_kv)?, self.heads.dim_qk)
    }

    fn v_len_checked(&self) -> Result<usize, AttnError> {
        mul(mul(self.total_k(), self.heads.heads_kv)?, self.heads.dim_v)
    }

    fn out_len_checked(&self) -> Result<usize, AttnError> {
        mul(mul(self.total_q(), self.heads.heads_q)?, self.heads.dim_v)
    }

    /// Length of `q` and `dq`.
    #[must_use]
    pub fn q_len(&self) -> usize {
        self.total_q() * self.heads.heads_q * self.heads.dim_qk
    }

    /// Length of `k` and `dk`.
    #[must_use]
    pub fn k_len(&self) -> usize {
        self.total_k() * self.heads.heads_kv * self.heads.dim_qk
    }

    /// Length of `v` and `dv`.
    #[must_use]
    pub fn v_len(&self) -> usize {
        self.total_k() * self.heads.heads_kv * self.heads.dim_v
    }

    /// Length of `out` and `d_out`.
    #[must_use]
    pub fn out_len(&self) -> usize {
        self.total_q() * self.heads.heads_q * self.heads.dim_v
    }

    /// Length of `lse`.
    #[must_use]
    pub fn lse_len(&self) -> usize {
        self.total_q() * self.heads.heads_q
    }

    /// Length of a dense bias and its gradient.
    #[must_use]
    pub fn bias_len(&self) -> usize {
        self.bias_off.last().copied().unwrap_or(0)
    }
}
