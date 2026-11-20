//! The tiled forward and backward passes.
//!
//! # Why the tile products go through `rune-gemm`
//!
//! Every tile does two (forward) or three to four (backward) small matrix
//! products, e.g. `S = Q_i K_jᵀ` with `Q_i: Br × d` and `K_j: Bc × d`,
//! `Br, Bc = 64..128`, `d = 64..256`. A one-threaded `rune-gemm` call at
//! those shapes measured 60–82 GFLOP/s on AVX2 + FMA, against 24–27
//! GFLOP/s for a portable dot-product/axpy loop that LLVM auto-vectorizes
//! (the default target has no FMA and only 128-bit vectors). `rune-gemm`
//! also reads the strided `[token, head, dim]` rows directly, so no tile is
//! copied, and its summation order is fixed, which the determinism
//! guarantee relies on. 128 × 128 tiles beat 64 × 64 by up to 15 % end to
//! end at 2–4k tokens and tie at 512.
//! The per-call packing cost is amortized over `Br · Bc · d` multiply-adds.

use rayon::prelude::*;
use rune_gemm::{Gemm, MatMut, MatRef};

use crate::layout::AttnLayout;
use crate::mask::{RowMask, TileKind, to_i64};
use crate::{AttnError, AttnGrads, AttnOutput, Bias};

/// Validated inputs and settings of one call.
pub struct Ctx<'a> {
    pub layout: &'a AttnLayout,
    pub q: &'a [f32],
    pub k: &'a [f32],
    pub v: &'a [f32],
    pub bias: Bias<'a>,
    pub scale: f32,
    pub softcap: Option<f32>,
    pub left: Option<usize>,
    pub right: Option<usize>,
    pub br: usize,
    pub bc: usize,
    pub gemm: Gemm,
    pub parallel: bool,
    pub keys: Option<(usize, usize)>,
}

/// `(sequence, head, first row or key)` of one block.
type Task = (usize, usize, usize);

/// One sequence: token offsets, lengths and mask.
struct Seq {
    q0: usize,
    k0: usize,
    sq: usize,
    sk: usize,
    bias_off: usize,
    mask: RowMask,
}

/// Map `f` over `items`, in parallel or not; output order is input order.
fn run<T, R, F>(parallel: bool, items: Vec<T>, f: F) -> Result<Vec<R>, AttnError>
where
    T: Send,
    R: Send,
    F: Fn(T) -> Result<R, AttnError> + Sync + Send,
{
    if parallel {
        items.into_par_iter().map(f).collect()
    } else {
        items.into_iter().map(f).collect()
    }
}

/// Rows `tok0..tok0 + rows` of head `h` of a `[token, heads, dim]` tensor.
fn rows_view(
    data: &[f32],
    tok0: usize,
    rows: usize,
    heads: usize,
    h: usize,
    dim: usize,
) -> Result<MatRef<'_, f32>, AttnError> {
    let rs = heads * dim;
    let tail = data.get(tok0 * rs + h * dim..).ok_or(AttnError::Overflow)?;
    Ok(MatRef::new(tail, rows, dim, rs, 1)?)
}

fn mat_mut(data: &mut [f32], rows: usize, cols: usize) -> Result<MatMut<'_, f32>, AttnError> {
    let len = data.len();
    let data = data
        .get_mut(..rows * cols)
        .ok_or(AttnError::ShapeMismatch {
            what: "tile buffer",
            expected: rows * cols,
            found: len,
        })?;
    Ok(MatMut::row_major(data, rows, cols)?)
}

fn mat_ref(data: &[f32], rows: usize, cols: usize) -> Result<MatRef<'_, f32>, AttnError> {
    let len = data.len();
    let data = data.get(..rows * cols).ok_or(AttnError::ShapeMismatch {
        what: "tile buffer",
        expected: rows * cols,
        found: len,
    })?;
    Ok(MatRef::row_major(data, rows, cols)?)
}

impl Ctx<'_> {
    const fn group(&self) -> usize {
        self.layout.heads.heads_q / self.layout.heads.heads_kv
    }

    fn seq(&self, b: usize) -> Seq {
        let l = self.layout;
        let (sq, sk) = (l.seq_q(b), l.seq_k(b));
        Seq {
            q0: l.cu_q[b],
            k0: l.cu_k[b],
            sq,
            sk,
            bias_off: l.bias_off[b],
            mask: RowMask::new(sq, sk, self.left, self.right, self.keys.unwrap_or((0, sk))),
        }
    }

    /// `(sequence, query head, first row)` of every query block, ordered as
    /// a per-sequence `[head, row]` array.
    fn q_tasks(&self) -> Vec<(usize, usize, usize)> {
        let mut t = Vec::new();
        for b in 0..self.layout.num_seqs() {
            let sq = self.layout.seq_q(b);
            for h in 0..self.layout.heads.heads_q {
                t.extend((0..sq).step_by(self.br).map(|i0| (b, h, i0)));
            }
        }
        t
    }

    /// `(sequence, kv head, first key)` of every key block.
    fn kv_tasks(&self) -> Vec<(usize, usize, usize)> {
        let mut t = Vec::new();
        for b in 0..self.layout.num_seqs() {
            let sk = self.layout.seq_k(b);
            for g in 0..self.layout.heads.heads_kv {
                t.extend((0..sk).step_by(self.bc).map(|j0| (b, g, j0)));
            }
        }
        t
    }

    /// Final logits of a tile into `s` (`rows × cols`): scaled `q·k`,
    /// softcapped, biased, masked to `-inf`. With softcap on, `dcap` gets
    /// the derivative of the cap, `1 - tanh²`.
    #[allow(clippy::cast_precision_loss)]
    fn logits(
        &self,
        seq: &Seq,
        h: usize,
        (i0, rows): (usize, usize),
        (j0, cols): (usize, usize),
        kind: TileKind,
        s: &mut [f32],
        dcap: Option<&mut [f32]>,
    ) -> Result<(), AttnError> {
        let hd = self.layout.heads;
        let kvh = h / self.group();
        let qv = rows_view(self.q, seq.q0 + i0, rows, hd.heads_q, h, hd.dim_qk)?;
        let kv = rows_view(self.k, seq.k0 + j0, cols, hd.heads_kv, kvh, hd.dim_qk)?.t();
        self.gemm
            .gemm(self.scale, qv, kv, 0.0, mat_mut(s, rows, cols)?)?;
        let s = &mut s[..rows * cols];
        if let Some(cap) = self.softcap {
            let inv = 1.0 / cap;
            match dcap {
                Some(d) => {
                    for (x, d) in s.iter_mut().zip(d.iter_mut()) {
                        let t = (*x * inv).tanh();
                        *x = cap * t;
                        *d = t.mul_add(-t, 1.0);
                    }
                }
                None => {
                    for x in s.iter_mut() {
                        *x = cap * (*x * inv).tanh();
                    }
                }
            }
        }
        match self.bias {
            Bias::None => {}
            Bias::Alibi(slopes) => {
                let slope = slopes[h];
                for (r, row) in s.chunks_exact_mut(cols).enumerate() {
                    let center = to_i64(i0 + r) + seq.mask.shift;
                    for (c, x) in row.iter_mut().enumerate() {
                        let dist = (center - to_i64(j0 + c)).unsigned_abs() as f32;
                        *x = slope.mul_add(-dist, *x);
                    }
                }
            }
            Bias::Dense(bias) => {
                let base = seq.bias_off + h * seq.sq * seq.sk + i0 * seq.sk + j0;
                for (r, row) in s.chunks_exact_mut(cols).enumerate() {
                    let b = &bias[base + r * seq.sk..][..cols];
                    for (x, &b) in row.iter_mut().zip(b) {
                        *x += b;
                    }
                }
            }
        }
        if kind == TileKind::Partial {
            let (j0, j1) = (to_i64(j0), to_i64(j0 + cols));
            for (r, row) in s.chunks_exact_mut(cols).enumerate() {
                let (lo, hi) = seq.mask.row(i0 + r);
                let a = crate::mask::clamp_usize(lo - j0, cols);
                let b = crate::mask::clamp_usize(hi.min(j1) - j0, cols).max(a);
                row[..a].fill(f32::NEG_INFINITY);
                row[b..].fill(f32::NEG_INFINITY);
            }
        }
        Ok(())
    }

    // ----------------------------------------------------------------- forward

    /// One query block of one head: online softmax over its key blocks.
    /// Returns the normalized output rows (`rows × dim_v`) and their LSE.
    fn forward_block(
        &self,
        b: usize,
        h: usize,
        i0: usize,
    ) -> Result<(Vec<f32>, Vec<f32>), AttnError> {
        let hd = self.layout.heads;
        let seq = self.seq(b);
        let rows = self.br.min(seq.sq - i0);
        let dv = hd.dim_v;
        let kvh = h / self.group();
        let mut acc = vec![0.0f32; rows * dv];
        let mut m = vec![f32::NEG_INFINITY; rows];
        let mut l = vec![0.0f32; rows];
        let mut s = vec![0.0f32; rows * self.bc];
        let mut j0 = 0;
        while j0 < seq.sk {
            let cols = self.bc.min(seq.sk - j0);
            let kind = seq.mask.tile(i0, i0 + rows, j0, j0 + cols);
            if kind != TileKind::Empty {
                let s = &mut s[..rows * cols];
                self.logits(&seq, h, (i0, rows), (j0, cols), kind, s, None)?;
                for (r, row) in s.chunks_exact_mut(cols).enumerate() {
                    let mx = row.iter().fold(f32::NEG_INFINITY, |a, &x| a.max(x));
                    let m_new = m[r].max(mx);
                    if m_new == f32::NEG_INFINITY {
                        row.fill(0.0);
                        continue;
                    }
                    let alpha = (m[r] - m_new).exp();
                    let mut sum = 0.0f32;
                    for x in row.iter_mut() {
                        *x = (*x - m_new).exp();
                        sum += *x;
                    }
                    l[r] = l[r].mul_add(alpha, sum);
                    m[r] = m_new;
                    if alpha < 1.0 {
                        for o in &mut acc[r * dv..(r + 1) * dv] {
                            *o *= alpha;
                        }
                    }
                }
                let vv = rows_view(self.v, seq.k0 + j0, cols, hd.heads_kv, kvh, dv)?;
                self.gemm.gemm(
                    1.0,
                    mat_ref(s, rows, cols)?,
                    vv,
                    1.0,
                    mat_mut(&mut acc, rows, dv)?,
                )?;
            }
            j0 += cols;
        }
        let mut lse = vec![f32::NEG_INFINITY; rows];
        for (r, o) in acc.chunks_exact_mut(dv).enumerate() {
            if l[r] > 0.0 {
                let inv = 1.0 / l[r];
                for x in o.iter_mut() {
                    *x *= inv;
                }
                lse[r] = m[r] + l[r].ln();
            } else {
                o.fill(0.0);
            }
        }
        Ok((acc, lse))
    }

    pub fn forward(&self) -> Result<AttnOutput, AttnError> {
        let hd = self.layout.heads;
        let tasks = self.q_tasks();
        let blocks = run(self.parallel, tasks.clone(), |(b, h, i0)| {
            self.forward_block(b, h, i0)
        })?;
        let mut out = vec![0.0f32; self.layout.out_len()];
        let mut lse = vec![f32::NEG_INFINITY; self.layout.lse_len()];
        let dv = hd.dim_v;
        for (&(b, h, i0), (acc, l)) in tasks.iter().zip(&blocks) {
            let t0 = self.layout.cu_q[b] + i0;
            for (r, (o, &l)) in acc.chunks_exact(dv).zip(l).enumerate() {
                let row = (t0 + r) * hd.heads_q + h;
                out[row * dv..(row + 1) * dv].copy_from_slice(o);
                lse[row] = l;
            }
        }
        Ok(AttnOutput { out, lse })
    }

    // ---------------------------------------------------------------- backward

    /// Turn logits into probabilities with the saved LSE of each row.
    fn probs(&self, seq: &Seq, h: usize, i0: usize, cols: usize, s: &mut [f32], lse: &[f32]) {
        let hq = self.layout.heads.heads_q;
        for (r, row) in s.chunks_exact_mut(cols).enumerate() {
            let l = lse[(seq.q0 + i0 + r) * hq + h];
            // A fully masked row has LSE -inf and every probability 0.
            let l = if l == f32::NEG_INFINITY {
                f32::INFINITY
            } else {
                l
            };
            for x in row.iter_mut() {
                *x = (*x - l).exp();
            }
        }
    }

    /// `ds = P ∘ (dP - D)` in place of `dp`, the gradient of the final
    /// logits.
    fn dscores(
        &self,
        seq: &Seq,
        h: usize,
        i0: usize,
        cols: usize,
        p: &[f32],
        dp: &mut [f32],
        dvec: &[f32],
    ) {
        let hq = self.layout.heads.heads_q;
        for (r, (dp, p)) in dp
            .chunks_exact_mut(cols)
            .zip(p.chunks_exact(cols))
            .enumerate()
        {
            let d = dvec[(seq.q0 + i0 + r) * hq + h];
            for (x, &p) in dp.iter_mut().zip(p) {
                *x = p * (*x - d);
            }
        }
    }

    /// Gradient of the softcap: multiply by `1 - tanh²`.
    fn uncap(&self, ds: &mut [f32], dcap: &[f32]) {
        if self.softcap.is_some() {
            for (x, &d) in ds.iter_mut().zip(dcap) {
                *x *= d;
            }
        }
    }

    /// `dk` and `dv` of one key block of one kv head, summed over the query
    /// heads of its group and all query blocks, in a fixed order.
    #[allow(clippy::too_many_lines)]
    fn backward_kv_block(
        &self,
        (b, g, j0): (usize, usize, usize),
        d_out: &[f32],
        lse: &[f32],
        dvec: &[f32],
    ) -> Result<(Vec<f32>, Vec<f32>), AttnError> {
        let hd = self.layout.heads;
        let seq = self.seq(b);
        let cols = self.bc.min(seq.sk - j0);
        let (dqk, dv) = (hd.dim_qk, hd.dim_v);
        let mut dk = vec![0.0f32; cols * dqk];
        let mut dvb = vec![0.0f32; cols * dv];
        let tile = self.br * cols;
        let mut p = vec![0.0f32; tile];
        let mut dp = vec![0.0f32; tile];
        let mut dcap = vec![0.0f32; if self.softcap.is_some() { tile } else { 0 }];
        let vv = rows_view(self.v, seq.k0 + j0, cols, hd.heads_kv, g, dv)?;
        let group = self.group();
        for h in g * group..(g + 1) * group {
            let mut i0 = 0;
            while i0 < seq.sq {
                let rows = self.br.min(seq.sq - i0);
                let kind = seq.mask.tile(i0, i0 + rows, j0, j0 + cols);
                if kind != TileKind::Empty {
                    let n = rows * cols;
                    let dc = if self.softcap.is_some() {
                        Some(&mut dcap[..n])
                    } else {
                        None
                    };
                    self.logits(&seq, h, (i0, rows), (j0, cols), kind, &mut p[..n], dc)?;
                    self.probs(&seq, h, i0, cols, &mut p[..n], lse);
                    let dov = rows_view(d_out, seq.q0 + i0, rows, hd.heads_q, h, dv)?;
                    let pm = mat_ref(&p, rows, cols)?;
                    self.gemm
                        .gemm(1.0, pm.t(), dov, 1.0, mat_mut(&mut dvb, cols, dv)?)?;
                    self.gemm
                        .gemm(1.0, dov, vv.t(), 0.0, mat_mut(&mut dp, rows, cols)?)?;
                    self.dscores(&seq, h, i0, cols, &p[..n], &mut dp[..n], dvec);
                    self.uncap(&mut dp[..n], &dcap);
                    let qv = rows_view(self.q, seq.q0 + i0, rows, hd.heads_q, h, dqk)?;
                    let dsm = mat_ref(&dp, rows, cols)?;
                    self.gemm
                        .gemm(self.scale, dsm.t(), qv, 1.0, mat_mut(&mut dk, cols, dqk)?)?;
                }
                i0 += rows;
            }
        }
        Ok((dk, dvb))
    }

    /// `dq` of one query block of one head (and its rows of the bias
    /// gradient), over all its key blocks in order.
    fn backward_q_block(
        &self,
        (b, h, i0): (usize, usize, usize),
        d_out: &[f32],
        lse: &[f32],
        dvec: &[f32],
        mut dbias: Option<&mut [f32]>,
    ) -> Result<Vec<f32>, AttnError> {
        let hd = self.layout.heads;
        let seq = self.seq(b);
        let rows = self.br.min(seq.sq - i0);
        let (dqk, dv) = (hd.dim_qk, hd.dim_v);
        let kvh = h / self.group();
        let mut dq = vec![0.0f32; rows * dqk];
        let tile = rows * self.bc;
        let mut p = vec![0.0f32; tile];
        let mut dp = vec![0.0f32; tile];
        let mut dcap = vec![0.0f32; if self.softcap.is_some() { tile } else { 0 }];
        let dov = rows_view(d_out, seq.q0 + i0, rows, hd.heads_q, h, dv)?;
        let mut j0 = 0;
        while j0 < seq.sk {
            let cols = self.bc.min(seq.sk - j0);
            let kind = seq.mask.tile(i0, i0 + rows, j0, j0 + cols);
            if kind != TileKind::Empty {
                let n = rows * cols;
                let dc = if self.softcap.is_some() {
                    Some(&mut dcap[..n])
                } else {
                    None
                };
                self.logits(&seq, h, (i0, rows), (j0, cols), kind, &mut p[..n], dc)?;
                self.probs(&seq, h, i0, cols, &mut p[..n], lse);
                let vv = rows_view(self.v, seq.k0 + j0, cols, hd.heads_kv, kvh, dv)?;
                self.gemm
                    .gemm(1.0, dov, vv.t(), 0.0, mat_mut(&mut dp, rows, cols)?)?;
                self.dscores(&seq, h, i0, cols, &p[..n], &mut dp[..n], dvec);
                if let Some(db) = dbias.as_deref_mut() {
                    for (r, ds) in dp[..n].chunks_exact(cols).enumerate() {
                        db[r * seq.sk + j0..][..cols].copy_from_slice(ds);
                    }
                }
                self.uncap(&mut dp[..n], &dcap);
                let kv = rows_view(self.k, seq.k0 + j0, cols, hd.heads_kv, kvh, dqk)?;
                self.gemm.gemm(
                    self.scale,
                    mat_ref(&dp, rows, cols)?,
                    kv,
                    1.0,
                    mat_mut(&mut dq, rows, dqk)?,
                )?;
            }
            j0 += cols;
        }
        Ok(dq)
    }

    /// Two passes, both free of write races: one over key blocks
    /// accumulates `dk`/`dv`, one over query blocks accumulates `dq` (and the
    /// bias gradient). Each recomputes the probabilities from the LSE.
    pub fn backward(
        &self,
        out: &[f32],
        lse: &[f32],
        d_out: &[f32],
    ) -> Result<AttnGrads, AttnError> {
        let hd = self.layout.heads;
        let (hq, hkv, dqk, dv) = (hd.heads_q, hd.heads_kv, hd.dim_qk, hd.dim_v);
        // D = rowsum(dO ∘ O), one value per (token, query head).
        let dvec: Vec<f32> = if self.parallel {
            d_out
                .par_chunks_exact(dv)
                .zip(out.par_chunks_exact(dv))
                .map(|(a, b)| a.iter().zip(b).map(|(x, y)| x * y).sum())
                .collect()
        } else {
            d_out
                .chunks_exact(dv)
                .zip(out.chunks_exact(dv))
                .map(|(a, b)| a.iter().zip(b).map(|(x, y)| x * y).sum())
                .collect()
        };

        let kv_tasks = self.kv_tasks();
        let kv_blocks = run(self.parallel, kv_tasks.clone(), |t| {
            self.backward_kv_block(t, d_out, lse, &dvec)
        })?;
        let mut dk = vec![0.0f32; self.layout.k_len()];
        let mut dvv = vec![0.0f32; self.layout.v_len()];
        for (&(b, g, j0), (dkb, dvb)) in kv_tasks.iter().zip(&kv_blocks) {
            let t0 = self.layout.cu_k[b] + j0;
            for (c, (a, v)) in dkb.chunks_exact(dqk).zip(dvb.chunks_exact(dv)).enumerate() {
                let row = (t0 + c) * hkv + g;
                dk[row * dqk..(row + 1) * dqk].copy_from_slice(a);
                dvv[row * dv..(row + 1) * dv].copy_from_slice(v);
            }
        }
        drop(kv_blocks);

        let q_tasks = self.q_tasks();
        let want_dbias = matches!(self.bias, Bias::Dense(_));
        let mut dbias = vec![
            0.0f32;
            if want_dbias {
                self.layout.bias_len()
            } else {
                0
            }
        ];
        let mut items: Vec<(Task, Option<&mut [f32]>)> = Vec::with_capacity(q_tasks.len());
        let mut rest: &mut [f32] = &mut dbias;
        for &(b, h, i0) in &q_tasks {
            let chunk = if want_dbias {
                let len = self.br.min(self.layout.seq_q(b) - i0) * self.layout.seq_k(b);
                let (a, r) = std::mem::take(&mut rest)
                    .split_at_mut_checked(len)
                    .ok_or(AttnError::Overflow)?;
                rest = r;
                Some(a)
            } else {
                None
            };
            items.push(((b, h, i0), chunk));
        }
        let q_blocks = run(self.parallel, items, |(t, db)| {
            self.backward_q_block(t, d_out, lse, &dvec, db)
        })?;
        let mut dq = vec![0.0f32; self.layout.q_len()];
        for (&(b, h, i0), dqb) in q_tasks.iter().zip(&q_blocks) {
            let t0 = self.layout.cu_q[b] + i0;
            for (r, a) in dqb.chunks_exact(dqk).enumerate() {
                let row = (t0 + r) * hq + h;
                dq[row * dqk..(row + 1) * dqk].copy_from_slice(a);
            }
        }
        Ok(AttnGrads {
            dq,
            dk,
            dv: dvv,
            dbias: want_dbias.then_some(dbias),
        })
    }
}
