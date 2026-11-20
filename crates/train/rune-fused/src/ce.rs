//! Cross-entropy on given logits, and linear + cross-entropy fused and
//! chunked over tokens.

use rune_gemm::{Gemm, MatMut, MatRef};

use crate::error::{FusedError, check_len, invalid, mul, rows_of};
use crate::reduce::{rows_per_task, run_tasks, sum_by, worth_parallel};

/// How per-token losses are combined.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum Reduction {
    /// Sum divided by the number of non-ignored tokens (0 when there are
    /// none).
    #[default]
    Mean,
    /// Plain sum.
    Sum,
}

/// Cross-entropy settings.
///
/// For a row of logits `x` (length `V`) with target `y`, optionally capped
/// as `z = c · tanh(x / c)`, `lse = log Σ_j exp(z_j)`:
///
/// `loss = (1 - ε)(lse - z_y) + ε (lse - mean_j z_j) + λ lse²`
///
/// with label smoothing `ε` (uniform over the vocabulary, as in most
/// frameworks) and z-loss weight `λ` (Chowdhery et al., "PaLM: Scaling
/// Language Modeling with Pathways"). Rows whose target equals
/// `ignore_index` contribute nothing and are not counted by
/// [`Reduction::Mean`]; an all-ignored batch has loss 0 and zero gradients.
///
/// ```
/// use rune_fused::CrossEntropy;
///
/// let ce = CrossEntropy::default();
/// let logits = [0.0f32, 0.0, 0.0, 1.0, 2.0, 3.0];
/// let mut lse = [0.0f32; 2];
/// let out = ce.forward(&logits, 3, &[0, -100], &mut lse)?; // second row ignored
/// assert_eq!(out.valid_tokens, 1);
/// assert!((out.loss - 3f32.ln()).abs() < 1e-6);
/// # Ok::<(), rune_fused::FusedError>(())
/// ```
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct CrossEntropy {
    ignore_index: i64,
    label_smoothing: f32,
    z_loss: f32,
    softcap: Option<f32>,
    reduction: Reduction,
}

impl Default for CrossEntropy {
    fn default() -> Self {
        Self::new()
    }
}

/// Result of a cross-entropy call.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct CeLoss {
    /// The reduced loss, z-loss included.
    pub loss: f32,
    /// The z-loss part of `loss` (same reduction), for logging.
    pub z_loss: f32,
    /// Number of tokens whose target is not `ignore_index`.
    pub valid_tokens: usize,
}

#[derive(Clone, Copy)]
struct RowStat {
    m: f32,
    ln_s: f32,
    sum_z: f32,
}

impl RowStat {
    fn lse(self) -> f32 {
        self.m + self.ln_s
    }
}

const LSE_BLOCK: usize = 512;

/// Single-pass online log-sum-exp over blocks: each block's max and
/// pairwise sum of `exp(z - block max)` is merged into a running
/// `(max, sum)`. The running sum is Kahan-compensated, since a large
/// vocabulary merges hundreds of blocks.
fn row_stats(z: &[f32], need_sum: bool) -> RowStat {
    let mut m = f32::NEG_INFINITY;
    let (mut s, mut comp) = (0.0f32, 0.0f32);
    let mut sum_z = 0.0f32;
    let mut sum_c = 0.0f32;
    for blk in z.chunks(LSE_BLOCK) {
        let bm = blk.iter().fold(f32::NEG_INFINITY, |a, &v| a.max(v));
        if need_sum {
            let y = sum_by(blk, |v| v) - sum_c;
            let t = sum_z + y;
            sum_c = (t - sum_z) - y;
            sum_z = t;
        }
        if bm == f32::NEG_INFINITY {
            // NaN logits do not reach here: `max` skips them, but they
            // poison the block sum below.
            if blk.iter().any(|v| v.is_nan()) {
                s = f32::NAN;
            }
            continue;
        }
        let bs = sum_by(blk, |v| (v - bm).exp());
        if bm > m {
            let r = (m - bm).exp();
            s *= r;
            comp *= r;
            m = bm;
        }
        let y = bs * (bm - m).exp() - comp;
        let t = s + y;
        comp = (t - s) - y;
        s = t;
    }
    RowStat {
        m,
        ln_s: s.ln(),
        sum_z,
    }
}

impl CrossEntropy {
    /// Plain cross-entropy: `ignore_index = -100`, no smoothing, no z-loss,
    /// no softcap, mean reduction.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            ignore_index: -100,
            label_smoothing: 0.0,
            z_loss: 0.0,
            softcap: None,
            reduction: Reduction::Mean,
        }
    }

    /// Target value that marks a token as ignored.
    #[must_use]
    pub const fn with_ignore_index(mut self, ignore_index: i64) -> Self {
        self.ignore_index = ignore_index;
        self
    }

    /// Label smoothing `ε` in `[0, 1]`.
    pub fn with_label_smoothing(mut self, eps: f32) -> Result<Self, FusedError> {
        if !(0.0..=1.0).contains(&eps) {
            return Err(invalid("label_smoothing", "must be in [0, 1]"));
        }
        self.label_smoothing = eps;
        Ok(self)
    }

    /// z-loss weight `λ` (finite, `>= 0`); `1e-4` is a common choice.
    pub fn with_z_loss(mut self, lambda: f32) -> Result<Self, FusedError> {
        if !(lambda.is_finite() && lambda >= 0.0) {
            return Err(invalid("z_loss", "must be finite and non-negative"));
        }
        self.z_loss = lambda;
        Ok(self)
    }

    /// Logit soft-capping `z = c · tanh(x / c)` with `c` finite and
    /// positive, or `None` to disable.
    pub fn with_softcap(mut self, cap: Option<f32>) -> Result<Self, FusedError> {
        if cap.is_some_and(|c| !(c.is_finite() && c > 0.0)) {
            return Err(invalid("softcap", "must be finite and positive"));
        }
        self.softcap = cap;
        Ok(self)
    }

    /// Mean or sum.
    #[must_use]
    pub const fn with_reduction(mut self, reduction: Reduction) -> Self {
        self.reduction = reduction;
        self
    }

    /// The ignore index.
    #[must_use]
    pub const fn ignore_index(&self) -> i64 {
        self.ignore_index
    }

    /// The label smoothing `ε`.
    #[must_use]
    pub const fn label_smoothing(&self) -> f32 {
        self.label_smoothing
    }

    /// The z-loss weight `λ`.
    #[must_use]
    pub const fn z_loss(&self) -> f32 {
        self.z_loss
    }

    /// The softcap `c`.
    #[must_use]
    pub const fn softcap(&self) -> Option<f32> {
        self.softcap
    }

    /// The reduction.
    #[must_use]
    pub const fn reduction(&self) -> Reduction {
        self.reduction
    }

    /// Checks every target and counts the non-ignored ones.
    fn count_valid(&self, targets: &[i64], vocab: usize) -> Result<usize, FusedError> {
        let mut n = 0;
        for (index, &t) in targets.iter().enumerate() {
            if t == self.ignore_index {
                continue;
            }
            if usize::try_from(t).map_or(true, |t| t >= vocab) {
                return Err(FusedError::TargetOutOfRange {
                    index,
                    target: t,
                    vocab,
                });
            }
            n += 1;
        }
        Ok(n)
    }

    /// Multiplier from summed to reduced loss.
    #[allow(clippy::cast_precision_loss)]
    fn norm(&self, valid: usize) -> f32 {
        match self.reduction {
            Reduction::Sum => 1.0,
            Reduction::Mean if valid == 0 => 0.0,
            Reduction::Mean => 1.0 / valid as f32,
        }
    }

    fn target(&self, t: i64) -> Option<usize> {
        if t == self.ignore_index {
            None
        } else {
            usize::try_from(t).ok()
        }
    }

    fn cap_in_place(&self, row: &mut [f32]) {
        if let Some(c) = self.softcap {
            let ic = 1.0 / c;
            for v in row {
                *v = c * (*v * ic).tanh();
            }
        }
    }

    /// Per-token `(loss, z-loss)` from the row statistics.
    #[allow(clippy::cast_precision_loss)]
    fn row_loss(&self, st: RowStat, z_y: f32, vocab: usize) -> (f32, f32) {
        let nll = (st.m - z_y) + st.ln_s;
        let eps = self.label_smoothing;
        let mut l = if eps > 0.0 {
            let smooth = (st.m - st.sum_z / vocab as f32) + st.ln_s;
            (1.0 - eps) * nll + eps * smooth
        } else {
            nll
        };
        let lse = st.lse();
        let zl = self.z_loss * lse * lse;
        l += zl;
        (l, zl)
    }

    /// Overwrites the (capped) logits row with `scale · ∂loss/∂x`.
    #[allow(clippy::cast_precision_loss)]
    fn grad_in_place(&self, row: &mut [f32], y: usize, st: RowStat, scale: f32) {
        let eps = self.label_smoothing;
        let k = scale * (1.0 + 2.0 * self.z_loss * st.lse());
        let u = scale * eps / row.len() as f32;
        let t = scale * (1.0 - eps);
        let (m, ln_s) = (st.m, st.ln_s);
        let z_y = row[y];
        if let Some(c) = self.softcap {
            let ic = 1.0 / c;
            for v in row.iter_mut() {
                let z = *v;
                let q = z * ic;
                *v = (k * ((z - m) - ln_s).exp() - u) * (1.0 - q * q);
            }
            let q = z_y * ic;
            row[y] -= t * (1.0 - q * q);
        } else {
            for v in row.iter_mut() {
                *v = k * ((*v - m) - ln_s).exp() - u;
            }
            row[y] -= t;
        }
    }

    /// Processes rows that the caller owns: caps in place, computes the
    /// loss (and the gradient in place when `grad_scale` is set). Ignored
    /// rows get loss 0 and, with gradients, a zero row.
    fn process_rows(&self, mut b: RowBlock<'_>, vocab: usize, grad_scale: Option<f32>) {
        let need_sum = self.label_smoothing > 0.0;
        let rows = b
            .rows
            .chunks_exact_mut(vocab)
            .zip(b.targets)
            .zip(b.losses.iter_mut().zip(b.zls.iter_mut()));
        for (i, ((row, &t), (l, zl))) in rows.enumerate() {
            let Some(y) = self.target(t) else {
                (*l, *zl) = (0.0, 0.0);
                if grad_scale.is_some() {
                    row.fill(0.0);
                }
                continue;
            };
            self.cap_in_place(row);
            let st = row_stats(row, need_sum);
            (*l, *zl) = self.row_loss(st, row[y], vocab);
            if let Some(lse) = b.lse.as_deref_mut().and_then(|s| s.get_mut(i)) {
                *lse = st.lse();
            }
            if let Some(g) = grad_scale {
                self.grad_in_place(row, y, st, g);
            }
        }
    }

    fn reduce(&self, losses: &[f32], zls: &[f32], valid: usize) -> CeLoss {
        let n = self.norm(valid);
        CeLoss {
            loss: sum_by(losses, |v| v) * n,
            z_loss: sum_by(zls, |v| v) * n,
            valid_tokens: valid,
        }
    }

    /// Loss on `logits: [tokens, vocab]` with one target per token. Writes
    /// the per-token `lse` (of the capped logits; 0 for ignored tokens) for
    /// [`backward`](Self::backward).
    pub fn forward(
        &self,
        logits: &[f32],
        vocab: usize,
        targets: &[i64],
        lse: &mut [f32],
    ) -> Result<CeLoss, FusedError> {
        let tokens = rows_of("logits", logits.len(), vocab)?;
        check_len("targets", tokens, targets.len())?;
        check_len("lse", tokens, lse.len())?;
        let valid = self.count_valid(targets, vocab)?;
        let mut losses = vec![0.0f32; tokens];
        let mut zls = vec![0.0f32; tokens];
        let rpt = rows_per_task(vocab);
        let tasks: Vec<_> = logits
            .chunks(rpt * vocab)
            .zip(targets.chunks(rpt))
            .zip(losses.chunks_mut(rpt).zip(zls.chunks_mut(rpt)))
            .zip(lse.chunks_mut(rpt))
            .collect();
        run_tasks(
            worth_parallel(logits.len()),
            tasks,
            |(((x, targets), (losses, zls)), lse)| {
                let mut scratch = Vec::new();
                for (i, (row, &t)) in x.chunks_exact(vocab).zip(targets).enumerate() {
                    if self.target(t).is_none() {
                        (lse[i], losses[i], zls[i]) = (0.0, 0.0, 0.0);
                        continue;
                    }
                    scratch.clear();
                    scratch.extend_from_slice(row);
                    let b = RowBlock {
                        rows: &mut scratch,
                        targets: std::slice::from_ref(&t),
                        losses: &mut losses[i..=i],
                        zls: &mut zls[i..=i],
                        lse: Some(&mut lse[i..=i]),
                    };
                    self.process_rows(b, vocab, None);
                }
            },
        );
        Ok(self.reduce(&losses, &zls, valid))
    }

    /// Gradient of the reduced loss times `dloss` with respect to the raw
    /// logits, from the `lse` saved by [`forward`](Self::forward).
    pub fn backward(
        &self,
        dloss: f32,
        logits: &[f32],
        vocab: usize,
        targets: &[i64],
        lse: &[f32],
        dlogits: &mut [f32],
    ) -> Result<(), FusedError> {
        let tokens = rows_of("logits", logits.len(), vocab)?;
        check_len("targets", tokens, targets.len())?;
        check_len("lse", tokens, lse.len())?;
        check_len("dlogits", logits.len(), dlogits.len())?;
        let valid = self.count_valid(targets, vocab)?;
        let scale = dloss * self.norm(valid);
        let rpt = rows_per_task(vocab);
        let tasks: Vec<_> = logits
            .chunks(rpt * vocab)
            .zip(dlogits.chunks_mut(rpt * vocab))
            .zip(targets.chunks(rpt).zip(lse.chunks(rpt)))
            .collect();
        run_tasks(
            worth_parallel(logits.len()),
            tasks,
            |((x, dx), (ts, ls))| {
                let rows = x.chunks_exact(vocab).zip(dx.chunks_exact_mut(vocab));
                for ((x, dx), (&t, &l)) in rows.zip(ts.iter().zip(ls)) {
                    let Some(y) = self.target(t) else {
                        dx.fill(0.0);
                        continue;
                    };
                    dx.copy_from_slice(x);
                    self.cap_in_place(dx);
                    let st = RowStat {
                        m: l,
                        ln_s: 0.0,
                        sum_z: 0.0,
                    };
                    self.grad_in_place(dx, y, st, scale);
                }
            },
        );
        Ok(())
    }

    /// Loss and gradient (for upstream gradient 1) in one pass. More
    /// accurate than [`forward`](Self::forward) + [`backward`](Self::backward)
    /// for very large logits, since the softmax is formed from the row max
    /// and the log-sum directly rather than from a rounded `lse`.
    pub fn forward_backward(
        &self,
        logits: &[f32],
        vocab: usize,
        targets: &[i64],
        dlogits: &mut [f32],
    ) -> Result<CeLoss, FusedError> {
        let tokens = rows_of("logits", logits.len(), vocab)?;
        check_len("targets", tokens, targets.len())?;
        check_len("dlogits", logits.len(), dlogits.len())?;
        let valid = self.count_valid(targets, vocab)?;
        dlogits.copy_from_slice(logits);
        let mut losses = vec![0.0f32; tokens];
        let mut zls = vec![0.0f32; tokens];
        self.process_all(
            dlogits,
            vocab,
            targets,
            &mut losses,
            &mut zls,
            Some(self.norm(valid)),
        );
        Ok(self.reduce(&losses, &zls, valid))
    }

    fn process_all(
        &self,
        rows: &mut [f32],
        vocab: usize,
        targets: &[i64],
        losses: &mut [f32],
        zls: &mut [f32],
        grad_scale: Option<f32>,
    ) {
        let rpt = rows_per_task(vocab);
        let parallel = worth_parallel(rows.len());
        let tasks: Vec<_> = rows
            .chunks_mut(rpt * vocab)
            .zip(targets.chunks(rpt))
            .zip(losses.chunks_mut(rpt).zip(zls.chunks_mut(rpt)))
            .map(|((rows, targets), (losses, zls))| RowBlock {
                rows,
                targets,
                losses,
                zls,
                lse: None,
            })
            .collect();
        run_tasks(parallel, tasks, |b| self.process_rows(b, vocab, grad_scale));
    }
}

struct RowBlock<'a> {
    rows: &'a mut [f32],
    targets: &'a [i64],
    losses: &'a mut [f32],
    zls: &'a mut [f32],
    lse: Option<&'a mut [f32]>,
}

/// Linear projection to the vocabulary fused with cross-entropy, chunked
/// over tokens so the `[tokens, vocab]` logits are never materialized.
///
/// For `hidden: [T, H]` and `weight: [V, H]` (the output embedding,
/// row-major), each chunk of `C` tokens computes `logits = hidden_c · Wᵀ`
/// into one reused `C × V` buffer, turns it into the loss and, in place,
/// into `∂loss/∂logits`, then accumulates `dhidden_c = G · W` and
/// `dweight += Gᵀ · hidden_c`. Peak extra memory is `C · V` floats plus
/// two floats per token. Matrix products go through `rune-gemm`; results
/// are bitwise identical for any thread count.
///
/// The loss settings are those of [`CrossEntropy`].
///
/// ```
/// use rune_fused::{CrossEntropy, LinearCrossEntropy};
///
/// let (t, h, v) = (3, 2, 4);
/// let hidden = [1.0f32, 0.0, 0.0, 1.0, 1.0, 1.0];
/// let weight = [1.0f32, 0.0, 0.0, 1.0, -1.0, 0.0, 0.0, -1.0];
/// let targets = [0i64, 1, -100];
/// let fused = LinearCrossEntropy::new(CrossEntropy::default()).with_chunk_tokens(2)?;
/// let (mut dh, mut dw) = (vec![0.0f32; t * h], vec![0.0f32; v * h]);
/// let out = fused.forward_backward(&hidden, &weight, h, &targets, &mut dh, Some(&mut dw))?;
/// assert_eq!(out.valid_tokens, 2);
/// assert_eq!(&dh[4..], &[0.0, 0.0]); // ignored token
/// # Ok::<(), rune_fused::FusedError>(())
/// ```
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct LinearCrossEntropy {
    ce: CrossEntropy,
    chunk_tokens: Option<usize>,
    grad_scale: f32,
}

/// Default budget for the logits buffer, in floats (32 MiB).
const DEFAULT_CHUNK_FLOATS: usize = 1 << 23;

impl LinearCrossEntropy {
    /// Fused op with the given loss settings and an automatic chunk size.
    #[must_use]
    pub const fn new(ce: CrossEntropy) -> Self {
        Self {
            ce,
            chunk_tokens: None,
            grad_scale: 1.0,
        }
    }

    /// Tokens per chunk (positive). Bounds the logits buffer at
    /// `chunk_tokens · vocab` floats.
    pub const fn with_chunk_tokens(mut self, chunk_tokens: usize) -> Result<Self, FusedError> {
        if chunk_tokens == 0 {
            return Err(invalid("chunk_tokens", "must be positive"));
        }
        self.chunk_tokens = Some(chunk_tokens);
        Ok(self)
    }

    /// Upstream gradient of the loss (default 1), folded into `dhidden` and
    /// `dweight`. Use it for loss scaling or gradient accumulation weights.
    pub const fn with_grad_scale(mut self, scale: f32) -> Result<Self, FusedError> {
        if !scale.is_finite() {
            return Err(invalid("grad_scale", "must be finite"));
        }
        self.grad_scale = scale;
        Ok(self)
    }

    /// The loss settings.
    #[must_use]
    pub const fn loss(&self) -> &CrossEntropy {
        &self.ce
    }

    /// Tokens per chunk for `tokens` tokens and a vocabulary of `vocab`:
    /// the explicit setting, or as many as fit 2²³ floats (at least 1), and
    /// never more than `tokens`.
    #[must_use]
    pub fn chunk_tokens(&self, tokens: usize, vocab: usize) -> usize {
        let c = self
            .chunk_tokens
            .unwrap_or_else(|| (DEFAULT_CHUNK_FLOATS / vocab.max(1)).max(1));
        c.min(tokens).max(1)
    }

    /// Loss only (no gradients).
    pub fn forward(
        &self,
        hidden: &[f32],
        weight: &[f32],
        hidden_dim: usize,
        targets: &[i64],
    ) -> Result<CeLoss, FusedError> {
        self.run(hidden, weight, hidden_dim, targets, None)
    }

    /// Loss, `dhidden` (overwritten) and, if given, `dweight` (overwritten)
    /// in one pass.
    pub fn forward_backward(
        &self,
        hidden: &[f32],
        weight: &[f32],
        hidden_dim: usize,
        targets: &[i64],
        dhidden: &mut [f32],
        dweight: Option<&mut [f32]>,
    ) -> Result<CeLoss, FusedError> {
        self.run(
            hidden,
            weight,
            hidden_dim,
            targets,
            Some((dhidden, dweight)),
        )
    }

    #[allow(clippy::type_complexity)]
    fn run(
        &self,
        hidden: &[f32],
        weight: &[f32],
        hd: usize,
        targets: &[i64],
        mut grads: Option<(&mut [f32], Option<&mut [f32]>)>,
    ) -> Result<CeLoss, FusedError> {
        let tokens = rows_of("hidden", hidden.len(), hd)?;
        let vocab = rows_of("weight", weight.len(), hd)?;
        if vocab == 0 {
            return Err(invalid("vocab", "weight must have at least one row"));
        }
        check_len("targets", tokens, targets.len())?;
        if let Some((dh, dw)) = grads.as_ref() {
            check_len("dhidden", hidden.len(), dh.len())?;
            if let Some(dw) = dw {
                check_len("dweight", weight.len(), dw.len())?;
            }
        }
        let ce = &self.ce;
        let valid = ce.count_valid(targets, vocab)?;
        let scale = self.grad_scale * ce.norm(valid);
        let chunk = self.chunk_tokens(tokens, vocab);
        let mut buf = vec![0.0f32; mul(chunk, vocab)?];
        let mut losses = vec![0.0f32; tokens];
        let mut zls = vec![0.0f32; tokens];
        let gemm = Gemm::new();
        let w = MatRef::row_major(weight, vocab, hd)?;
        let mut dw_started = false;
        for (c, ts) in targets.chunks(chunk).enumerate() {
            let r0 = c * chunk;
            let n = ts.len();
            let h_c = &hidden[r0 * hd..(r0 + n) * hd];
            let any_valid = ts.iter().any(|&t| t != ce.ignore_index);
            if !any_valid {
                losses[r0..r0 + n].fill(0.0);
                zls[r0..r0 + n].fill(0.0);
                if let Some((dh, _)) = grads.as_mut() {
                    dh[r0 * hd..(r0 + n) * hd].fill(0.0);
                }
                continue;
            }
            let g = &mut buf[..n * vocab];
            let hm = MatRef::row_major(h_c, n, hd)?;
            gemm.gemm(1.0, hm, w.t(), 0.0, MatMut::row_major(g, n, vocab)?)?;
            ce.process_all(
                g,
                vocab,
                ts,
                &mut losses[r0..r0 + n],
                &mut zls[r0..r0 + n],
                grads.is_some().then_some(scale),
            );
            if let Some((dh, dw)) = grads.as_mut() {
                let gm = MatRef::row_major(g, n, vocab)?;
                let dh_c = &mut dh[r0 * hd..(r0 + n) * hd];
                gemm.gemm(1.0, gm, w, 0.0, MatMut::row_major(dh_c, n, hd)?)?;
                if let Some(dw) = dw.as_deref_mut() {
                    let beta = if dw_started { 1.0 } else { 0.0 };
                    gemm.gemm(1.0, gm.t(), hm, beta, MatMut::row_major(dw, vocab, hd)?)?;
                    dw_started = true;
                }
            }
        }
        if let Some((_, Some(dw))) = grads.as_mut()
            && !dw_started
        {
            dw.fill(0.0);
        }
        Ok(ce.reduce(&losses, &zls, valid))
    }
}
