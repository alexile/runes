//! RMSNorm and LayerNorm, forward and backward.

use crate::error::{FusedError, check_len, invalid, rows_of};
use crate::reduce::{
    GRAD_BLOCK_ROWS, combine_partials, map_tasks, rows_per_task, run_tasks, sum_by, sum2_by,
    worth_parallel,
};

#[allow(clippy::cast_possible_truncation)]
fn inv_sqrt(v: f32, eps: f32) -> f32 {
    (1.0 / (f64::from(v) + f64::from(eps)).sqrt()) as f32
}

fn check_eps(eps: f32) -> Result<(), FusedError> {
    if eps.is_finite() && eps >= 0.0 {
        Ok(())
    } else {
        Err(invalid("eps", "must be finite and non-negative"))
    }
}

fn check_param(what: &'static str, p: Option<&[f32]>, hidden: usize) -> Result<(), FusedError> {
    p.map_or(Ok(()), |p| check_len(what, hidden, p.len()))
}

fn check_param_mut(
    what: &'static str,
    p: Option<&&mut [f32]>,
    hidden: usize,
) -> Result<(), FusedError> {
    p.map_or(Ok(()), |p| check_len(what, hidden, p.len()))
}

/// Root-mean-square layer normalization (Zhang and Sennrich, "Root Mean
/// Square Layer Normalization"):
///
/// `rstd = 1 / sqrt(mean(x²) + eps)`, `y = x · rstd · w`
///
/// over rows of length `hidden`. The weight is optional; with
/// [`with_unit_offset`](Self::with_unit_offset) it is applied as `(1 + w)`
/// (weights stored as an offset from one). With a residual
/// ([`forward_residual`](Self::forward_residual)) the op first forms
/// `h = x + residual`, normalizes `h`, and writes `h` back as the new
/// residual stream.
///
/// The forward pass saves `rstd` per row for the backward pass.
///
/// ```
/// use rune_fused::RmsNorm;
///
/// let norm = RmsNorm::new(4, 0.0)?;
/// let x = [1.0f32, -1.0, 1.0, -1.0, 2.0, 2.0, 2.0, 2.0];
/// let (mut y, mut rstd) = ([0.0f32; 8], [0.0f32; 2]);
/// norm.forward(&x, None, &mut y, &mut rstd)?;
/// assert_eq!(rstd, [1.0, 0.5]);
/// assert_eq!(y, [1.0, -1.0, 1.0, -1.0, 1.0, 1.0, 1.0, 1.0]);
/// # Ok::<(), rune_fused::FusedError>(())
/// ```
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct RmsNorm {
    hidden: usize,
    eps: f32,
    unit_offset: bool,
}

struct RmsFwdTask<'a> {
    x: &'a [f32],
    res: Option<&'a mut [f32]>,
    out: &'a mut [f32],
    rstd: &'a mut [f32],
}

struct RmsBwdTask<'a> {
    dy: &'a [f32],
    dres: Option<&'a [f32]>,
    x: &'a [f32],
    rstd: &'a [f32],
    dx: &'a mut [f32],
}

impl RmsNorm {
    /// Rows of length `hidden` (positive) with `eps` (finite, `>= 0`) added
    /// to the mean square.
    pub fn new(hidden: usize, eps: f32) -> Result<Self, FusedError> {
        if hidden == 0 {
            return Err(invalid("hidden", "must be positive"));
        }
        check_eps(eps)?;
        Ok(Self {
            hidden,
            eps,
            unit_offset: false,
        })
    }

    /// Apply the weight as `(1 + w)` instead of `w`.
    #[must_use]
    pub const fn with_unit_offset(mut self, on: bool) -> Self {
        self.unit_offset = on;
        self
    }

    /// Row length.
    #[must_use]
    pub const fn hidden(&self) -> usize {
        self.hidden
    }

    /// The epsilon added to the mean square.
    #[must_use]
    pub const fn eps(&self) -> f32 {
        self.eps
    }

    /// Whether the weight is applied as `(1 + w)`.
    #[must_use]
    pub const fn unit_offset(&self) -> bool {
        self.unit_offset
    }

    const fn offset(&self) -> f32 {
        if self.unit_offset { 1.0 } else { 0.0 }
    }

    /// `out = norm(x) · w` for `x: [rows, hidden]`; writes `rstd: [rows]`.
    pub fn forward(
        &self,
        x: &[f32],
        weight: Option<&[f32]>,
        out: &mut [f32],
        rstd: &mut [f32],
    ) -> Result<(), FusedError> {
        self.forward_impl(x, None, weight, out, rstd)
    }

    /// Residual-add fusion: `h = x + residual`, `out = norm(h) · w`, and
    /// `residual` is overwritten with `h` (the summed residual stream that
    /// the next block adds to). Writes `rstd: [rows]`.
    pub fn forward_residual(
        &self,
        x: &[f32],
        residual: &mut [f32],
        weight: Option<&[f32]>,
        out: &mut [f32],
        rstd: &mut [f32],
    ) -> Result<(), FusedError> {
        self.forward_impl(x, Some(residual), weight, out, rstd)
    }

    fn forward_impl(
        &self,
        x: &[f32],
        residual: Option<&mut [f32]>,
        weight: Option<&[f32]>,
        out: &mut [f32],
        rstd: &mut [f32],
    ) -> Result<(), FusedError> {
        let h = self.hidden;
        let rows = rows_of("x", x.len(), h)?;
        check_len("out", x.len(), out.len())?;
        check_len("rstd", rows, rstd.len())?;
        check_param("weight", weight, h)?;
        if let Some(r) = residual.as_deref() {
            check_len("residual", x.len(), r.len())?;
        }
        let rpt = rows_per_task(h);
        let mut res_chunks: Vec<Option<&mut [f32]>> = residual
            .map(|r| r.chunks_mut(rpt * h).map(Some).collect())
            .unwrap_or_default();
        res_chunks.resize_with(rows.div_ceil(rpt), || None);
        let tasks: Vec<RmsFwdTask<'_>> = x
            .chunks(rpt * h)
            .zip(out.chunks_mut(rpt * h))
            .zip(rstd.chunks_mut(rpt))
            .zip(res_chunks)
            .map(|(((x, out), rstd), res)| RmsFwdTask { x, res, out, rstd })
            .collect();
        let (eps, off) = (self.eps, self.offset());
        run_tasks(worth_parallel(x.len()), tasks, |t| {
            let RmsFwdTask { x, res, out, rstd } = t;
            if let Some(res) = res {
                for (r, &v) in res.iter_mut().zip(x) {
                    *r += v;
                }
                rms_rows(res, weight, off, eps, h, out, rstd);
            } else {
                rms_rows(x, weight, off, eps, h, out, rstd);
            }
        });
        Ok(())
    }

    /// Backward of [`forward`](Self::forward): from `dy`, the forward input
    /// `x` and the saved `rstd`, writes `dx` and, if given, `dw` (the weight
    /// gradient, overwritten, not accumulated).
    pub fn backward(
        &self,
        dy: &[f32],
        x: &[f32],
        weight: Option<&[f32]>,
        rstd: &[f32],
        dx: &mut [f32],
        dw: Option<&mut [f32]>,
    ) -> Result<(), FusedError> {
        self.backward_impl(dy, None, x, weight, rstd, dx, dw)
    }

    /// Backward of [`forward_residual`](Self::forward_residual). `x` is the
    /// summed residual `h` the forward pass wrote back, and `d_residual` is
    /// the gradient arriving at that residual output. Since
    /// `h = x + residual`, the one buffer `dx` is the gradient of both `x`
    /// and the input residual.
    pub fn backward_residual(
        &self,
        dy: &[f32],
        d_residual: &[f32],
        x: &[f32],
        weight: Option<&[f32]>,
        rstd: &[f32],
        dx: &mut [f32],
        dw: Option<&mut [f32]>,
    ) -> Result<(), FusedError> {
        self.backward_impl(dy, Some(d_residual), x, weight, rstd, dx, dw)
    }

    fn backward_impl(
        &self,
        dy: &[f32],
        d_residual: Option<&[f32]>,
        x: &[f32],
        weight: Option<&[f32]>,
        rstd: &[f32],
        dx: &mut [f32],
        dw: Option<&mut [f32]>,
    ) -> Result<(), FusedError> {
        let h = self.hidden;
        let rows = rows_of("x", x.len(), h)?;
        check_len("dy", x.len(), dy.len())?;
        check_len("dx", x.len(), dx.len())?;
        check_len("rstd", rows, rstd.len())?;
        check_param("weight", weight, h)?;
        if let Some(d) = d_residual {
            check_len("d_residual", x.len(), d.len())?;
        }
        check_param_mut("dw", dw.as_ref(), h)?;
        let b = GRAD_BLOCK_ROWS;
        let mut dres: Vec<Option<&[f32]>> = d_residual
            .map(|d| d.chunks(b * h).map(Some).collect())
            .unwrap_or_default();
        dres.resize(rows.div_ceil(b), None);
        let tasks: Vec<RmsBwdTask<'_>> = dy
            .chunks(b * h)
            .zip(x.chunks(b * h))
            .zip(rstd.chunks(b))
            .zip(dx.chunks_mut(b * h))
            .zip(dres)
            .map(|((((dy, x), rstd), dx), dres)| RmsBwdTask {
                dy,
                dres,
                x,
                rstd,
                dx,
            })
            .collect();
        let want_dw = dw.is_some();
        let off = self.offset();
        let partials = map_tasks(worth_parallel(x.len()), tasks, |t| {
            let mut part = if want_dw { vec![0.0f32; h] } else { Vec::new() };
            rms_backward_rows(t, weight, off, h, want_dw.then_some(&mut part[..]));
            part
        });
        if let Some(dw) = dw {
            combine_partials(partials, dw);
        }
        Ok(())
    }
}

fn rms_rows(
    x: &[f32],
    weight: Option<&[f32]>,
    off: f32,
    eps: f32,
    h: usize,
    out: &mut [f32],
    rstd: &mut [f32],
) {
    #[allow(clippy::cast_precision_loss)]
    let inv_h = 1.0 / h as f32;
    for ((x, out), r) in x.chunks_exact(h).zip(out.chunks_exact_mut(h)).zip(rstd) {
        let ms = sum_by(x, |v| v * v) * inv_h;
        let rs = inv_sqrt(ms, eps);
        *r = rs;
        match weight {
            Some(w) => {
                for ((o, &v), &w) in out.iter_mut().zip(x).zip(w) {
                    *o = (v * rs) * (w + off);
                }
            }
            None => {
                for (o, &v) in out.iter_mut().zip(x) {
                    *o = v * rs;
                }
            }
        }
    }
}

fn rms_backward_rows(
    t: RmsBwdTask<'_>,
    weight: Option<&[f32]>,
    off: f32,
    h: usize,
    mut dw: Option<&mut [f32]>,
) {
    let RmsBwdTask {
        dy,
        dres,
        x,
        rstd,
        dx,
    } = t;
    #[allow(clippy::cast_precision_loss)]
    let inv_h = 1.0 / h as f32;
    for (i, ((dy, x), dx)) in dy
        .chunks_exact(h)
        .zip(x.chunks_exact(h))
        .zip(dx.chunks_exact_mut(h))
        .enumerate()
    {
        let r = rstd[i];
        // g = dy · w_eff, staged in dx.
        match weight {
            Some(w) => {
                for ((g, &d), &w) in dx.iter_mut().zip(dy).zip(w) {
                    *g = d * (w + off);
                }
            }
            None => dx.copy_from_slice(dy),
        }
        // c = mean(g · n) with n = x · r.
        let c = sum2_by(dx, x, |g, v| g * v) * r * inv_h;
        let rc = r * c;
        for (g, &v) in dx.iter_mut().zip(x) {
            *g = r * (*g - v * rc);
        }
        if let Some(dres) = dres {
            for (g, &d) in dx.iter_mut().zip(&dres[i * h..(i + 1) * h]) {
                *g += d;
            }
        }
        if let Some(dw) = dw.as_deref_mut() {
            for ((acc, &d), &v) in dw.iter_mut().zip(dy).zip(x) {
                *acc += d * (v * r);
            }
        }
    }
}

/// Layer normalization (Ba, Kiros and Hinton, "Layer Normalization"):
///
/// `mean = mean(x)`, `rstd = 1 / sqrt(mean((x - mean)²) + eps)`,
/// `y = (x - mean) · rstd · w + b`
///
/// over rows of length `hidden`; weight and bias are each optional. The
/// variance is computed in a second pass over the (cached) row from the
/// centred values, which avoids the cancellation of `E[x²] - E[x]²`. The
/// forward pass saves `mean` and `rstd` per row for the backward pass.
///
/// ```
/// use rune_fused::LayerNorm;
///
/// let ln = LayerNorm::new(2, 0.0)?;
/// let x = [1.0f32, 3.0];
/// let (mut y, mut mean, mut rstd) = ([0.0f32; 2], [0.0f32], [0.0f32]);
/// ln.forward(&x, None, Some(&[10.0, 20.0]), &mut y, &mut mean, &mut rstd)?;
/// assert_eq!((mean[0], rstd[0]), (2.0, 1.0));
/// assert_eq!(y, [9.0, 21.0]);
/// # Ok::<(), rune_fused::FusedError>(())
/// ```
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct LayerNorm {
    hidden: usize,
    eps: f32,
}

struct LnFwdTask<'a> {
    x: &'a [f32],
    out: &'a mut [f32],
    mean: &'a mut [f32],
    rstd: &'a mut [f32],
}

struct LnBwdTask<'a> {
    dy: &'a [f32],
    x: &'a [f32],
    mean: &'a [f32],
    rstd: &'a [f32],
    dx: &'a mut [f32],
}

impl LayerNorm {
    /// Rows of length `hidden` (positive) with `eps` (finite, `>= 0`) added
    /// to the variance.
    pub fn new(hidden: usize, eps: f32) -> Result<Self, FusedError> {
        if hidden == 0 {
            return Err(invalid("hidden", "must be positive"));
        }
        check_eps(eps)?;
        Ok(Self { hidden, eps })
    }

    /// Row length.
    #[must_use]
    pub const fn hidden(&self) -> usize {
        self.hidden
    }

    /// The epsilon added to the variance.
    #[must_use]
    pub const fn eps(&self) -> f32 {
        self.eps
    }

    /// `out = (x - mean) · rstd · w + b` for `x: [rows, hidden]`; writes
    /// `mean: [rows]` and `rstd: [rows]`.
    pub fn forward(
        &self,
        x: &[f32],
        weight: Option<&[f32]>,
        bias: Option<&[f32]>,
        out: &mut [f32],
        mean: &mut [f32],
        rstd: &mut [f32],
    ) -> Result<(), FusedError> {
        let h = self.hidden;
        let rows = rows_of("x", x.len(), h)?;
        check_len("out", x.len(), out.len())?;
        check_len("mean", rows, mean.len())?;
        check_len("rstd", rows, rstd.len())?;
        check_param("weight", weight, h)?;
        check_param("bias", bias, h)?;
        let rpt = rows_per_task(h);
        let tasks: Vec<LnFwdTask<'_>> = x
            .chunks(rpt * h)
            .zip(out.chunks_mut(rpt * h))
            .zip(mean.chunks_mut(rpt))
            .zip(rstd.chunks_mut(rpt))
            .map(|(((x, out), mean), rstd)| LnFwdTask { x, out, mean, rstd })
            .collect();
        let eps = self.eps;
        #[allow(clippy::cast_precision_loss)]
        let inv_h = 1.0 / h as f32;
        run_tasks(worth_parallel(x.len()), tasks, |t| {
            let rows =
                t.x.chunks_exact(h)
                    .zip(t.out.chunks_exact_mut(h))
                    .zip(t.mean.iter_mut().zip(t.rstd.iter_mut()));
            for ((x, out), (m, r)) in rows {
                let mu = sum_by(x, |v| v) * inv_h;
                let var = sum_by(x, |v| (v - mu) * (v - mu)) * inv_h;
                let rs = inv_sqrt(var, eps);
                *m = mu;
                *r = rs;
                for (j, (o, &v)) in out.iter_mut().zip(x).enumerate() {
                    let mut y = (v - mu) * rs;
                    if let Some(w) = weight {
                        y *= w[j];
                    }
                    if let Some(b) = bias {
                        y += b[j];
                    }
                    *o = y;
                }
            }
        });
        Ok(())
    }

    /// Backward: from `dy`, the forward input `x` and the saved `mean` and
    /// `rstd`, writes `dx` and, if given, `dw` and `db` (overwritten, not
    /// accumulated).
    pub fn backward(
        &self,
        dy: &[f32],
        x: &[f32],
        weight: Option<&[f32]>,
        mean: &[f32],
        rstd: &[f32],
        dx: &mut [f32],
        dw: Option<&mut [f32]>,
        db: Option<&mut [f32]>,
    ) -> Result<(), FusedError> {
        let h = self.hidden;
        let rows = rows_of("x", x.len(), h)?;
        check_len("dy", x.len(), dy.len())?;
        check_len("dx", x.len(), dx.len())?;
        check_len("mean", rows, mean.len())?;
        check_len("rstd", rows, rstd.len())?;
        check_param("weight", weight, h)?;
        check_param_mut("dw", dw.as_ref(), h)?;
        check_param_mut("db", db.as_ref(), h)?;
        let b = GRAD_BLOCK_ROWS;
        let tasks: Vec<LnBwdTask<'_>> = dy
            .chunks(b * h)
            .zip(x.chunks(b * h))
            .zip(mean.chunks(b))
            .zip(rstd.chunks(b))
            .zip(dx.chunks_mut(b * h))
            .map(|((((dy, x), mean), rstd), dx)| LnBwdTask {
                dy,
                x,
                mean,
                rstd,
                dx,
            })
            .collect();
        let (want_dw, want_db) = (dw.is_some(), db.is_some());
        #[allow(clippy::cast_precision_loss)]
        let inv_h = 1.0 / h as f32;
        let partials = map_tasks(worth_parallel(x.len()), tasks, |t| {
            let mut pw = if want_dw { vec![0.0f32; h] } else { Vec::new() };
            let mut pb = if want_db { vec![0.0f32; h] } else { Vec::new() };
            let rows =
                t.dy.chunks_exact(h)
                    .zip(t.x.chunks_exact(h))
                    .zip(t.dx.chunks_exact_mut(h))
                    .enumerate();
            for (i, ((dy, x), dx)) in rows {
                let (mu, r) = (t.mean[i], t.rstd[i]);
                match weight {
                    Some(w) => {
                        for ((g, &d), &w) in dx.iter_mut().zip(dy).zip(w) {
                            *g = d * w;
                        }
                    }
                    None => dx.copy_from_slice(dy),
                }
                let a = sum_by(dx, |g| g) * inv_h;
                let c = sum2_by(dx, x, |g, v| g * ((v - mu) * r)) * inv_h;
                for (g, &v) in dx.iter_mut().zip(x) {
                    *g = r * (*g - a - ((v - mu) * r) * c);
                }
                if want_dw {
                    for ((acc, &d), &v) in pw.iter_mut().zip(dy).zip(x) {
                        *acc += d * ((v - mu) * r);
                    }
                }
                if want_db {
                    for (acc, &d) in pb.iter_mut().zip(dy) {
                        *acc += d;
                    }
                }
            }
            (pw, pb)
        });
        let (pw, pb): (Vec<_>, Vec<_>) = partials.into_iter().unzip();
        if let Some(dw) = dw {
            combine_partials(pw, dw);
        }
        if let Some(db) = db {
            combine_partials(pb, db);
        }
        Ok(())
    }
}
