//! Gradient descent on `KL(P ‖ Q)`: exact O(n²) gradients or the Barnes-Hut
//! approximation, with the early-exaggeration / momentum / gains schedule of
//! van der Maaten (2014).

use rayon::prelude::*;

use crate::affinities::Sparse;
use crate::bhtree::{MAX_DIM, Tree};
use crate::{Callback, Iteration};

/// Lower bound on the per-coordinate adaptive gain.
const MIN_GAIN: f64 = 0.01;
/// Momentum during, and after, the early-exaggeration phase.
const MOMENTUM_EARLY: f64 = 0.5;
const MOMENTUM_LATE: f64 = 0.8;

/// The joint probabilities, in the form the chosen method uses.
pub enum Affinities {
    Dense(Vec<f64>),
    Sparse(Sparse, f64),
}

pub struct Schedule {
    pub learning_rate: f64,
    pub n_iter: usize,
    pub exaggeration: f64,
    pub exaggeration_iters: usize,
}

/// Gradient (flat `n × dim`) and, when requested, `KL(P ‖ Q)`.
struct Eval {
    grad: Vec<f64>,
    kl: Option<f64>,
}

/// `Σ p·ln p` over the non-zero entries.
fn neg_entropy(p: &[f64]) -> f64 {
    p.iter().filter(|&&x| x > 0.0).map(|&x| x * x.ln()).sum()
}

impl Affinities {
    /// Evaluates the gradient at `y` with P multiplied by `exaggeration`.
    fn eval(&self, y: &[f64], dim: usize, exaggeration: f64, want_kl: bool) -> Eval {
        match self {
            Self::Dense(p) => dense_eval(p, y, dim, exaggeration, want_kl),
            Self::Sparse(p, theta) => sparse_eval(p, *theta, y, dim, exaggeration, want_kl),
        }
    }
}

#[allow(
    clippy::many_single_char_names,
    reason = "names follow the t-SNE papers (p, q, w, y, z)"
)]
/// Exact gradient: `∂C/∂y_i = 4 Σ_j (α·p_ij − q_ij)·w_ij·(y_i − y_j)` with
/// `w_ij = (1 + ‖y_i − y_j‖²)⁻¹` and `q_ij = w_ij / Z`.
fn dense_eval(p: &[f64], y: &[f64], dim: usize, alpha: f64, want_kl: bool) -> Eval {
    let n = y.len() / dim;
    let row = |i: usize| -> (Vec<f64>, f64) {
        let yi = &y[i * dim..(i + 1) * dim];
        let w: Vec<f64> = (0..n)
            .map(|j| {
                if j == i {
                    0.0
                } else {
                    let yj = &y[j * dim..(j + 1) * dim];
                    let d: f64 = yi.iter().zip(yj).map(|(a, b)| (a - b) * (a - b)).sum();
                    1.0 / (1.0 + d)
                }
            })
            .collect();
        let z = w.iter().sum();
        (w, z)
    };
    let rows: Vec<(Vec<f64>, f64)> = (0..n).into_par_iter().map(row).collect();
    let z: f64 = rows.iter().map(|r| r.1).sum::<f64>().max(f64::MIN_POSITIVE);

    let per_point: Vec<(Vec<f64>, f64)> = rows
        .par_iter()
        .enumerate()
        .map(|(i, (w, _))| {
            let yi = &y[i * dim..(i + 1) * dim];
            let mut g = vec![0.0; dim];
            let mut kl = 0.0;
            for j in (0..n).filter(|&j| j != i) {
                let pij = p[i * n + j];
                let f = 4.0 * alpha.mul_add(pij, -w[j] / z) * w[j];
                for d in 0..dim {
                    g[d] = f.mul_add(yi[d] - y[j * dim + d], g[d]);
                }
                if want_kl && pij > 0.0 {
                    kl = pij.mul_add(-w[j].ln(), kl);
                }
            }
            (g, kl)
        })
        .collect();
    let kl = want_kl.then(|| {
        let cross: f64 = per_point.iter().map(|r| r.1).sum();
        p.iter()
            .sum::<f64>()
            .mul_add(z.ln(), neg_entropy(p) + cross)
    });
    Eval {
        grad: per_point.into_iter().flat_map(|r| r.0).collect(),
        kl,
    }
}

#[allow(
    clippy::many_single_char_names,
    reason = "names follow the t-SNE papers (p, q, w, y, z)"
)]
/// Barnes-Hut gradient: exact attraction over the sparse P, repulsion and
/// `Z` estimated with the space-partitioning tree.
fn sparse_eval(p: &Sparse, theta: f64, y: &[f64], dim: usize, alpha: f64, want_kl: bool) -> Eval {
    let n = y.len() / dim;
    let tree = Tree::build(y, dim);
    let per_point: Vec<PointForces> = (0..n)
        .into_par_iter()
        .map(|i| {
            let yi = &y[i * dim..(i + 1) * dim];
            let mut attr = [0.0; MAX_DIM];
            let mut cross = 0.0;
            for e in p.row_start[i]..p.row_start[i + 1] {
                let j = p.cols[e];
                let yj = &y[j * dim..(j + 1) * dim];
                let d: f64 = yi.iter().zip(yj).map(|(a, b)| (a - b) * (a - b)).sum();
                let w = 1.0 / (1.0 + d);
                let f = p.vals[e] * w;
                for k in 0..dim {
                    attr[k] = f.mul_add(yi[k] - yj[k], attr[k]);
                }
                if want_kl && p.vals[e] > 0.0 {
                    cross = p.vals[e].mul_add(-w.ln(), cross);
                }
            }
            let rep = tree.repulsion(i, theta);
            (attr, rep.force, rep.z, cross)
        })
        .collect();
    let z: f64 = per_point
        .iter()
        .map(|r| r.2)
        .sum::<f64>()
        .max(f64::MIN_POSITIVE);
    let mut grad = vec![0.0; n * dim];
    for (i, (attr, rep, _, _)) in per_point.iter().enumerate() {
        for k in 0..dim {
            grad[i * dim + k] = 4.0 * alpha.mul_add(attr[k], -rep[k] / z);
        }
    }
    let kl = want_kl.then(|| {
        let cross: f64 = per_point.iter().map(|r| r.3).sum();
        p.vals
            .iter()
            .sum::<f64>()
            .mul_add(z.ln(), neg_entropy(&p.vals) + cross)
    });
    Eval { grad, kl }
}

/// Per-point Barnes-Hut terms: attraction, repulsion, share of `Z`, and
/// `−Σ_j p_ij·ln w_ij` for the KL divergence.
type PointForces = ([f64; MAX_DIM], [f64; MAX_DIM], f64, f64);

/// `KL(P ‖ Q)` at `y` (no exaggeration).
pub fn kl_divergence(p: &Affinities, y: &[f64], dim: usize) -> f64 {
    p.eval(y, dim, 1.0, true).kl.unwrap_or(f64::NAN)
}

/// Runs the optimisation in place on the flat embedding `y` and returns the
/// number of iterations performed. `report` (if any) is called after every
/// iteration and can stop the run early.
pub fn optimize(
    y: &mut [f64],
    dim: usize,
    p: &Affinities,
    schedule: &Schedule,
    mut report: Option<&mut Callback<'_>>,
) -> usize {
    let mut velocity = vec![0.0f64; y.len()];
    // Per-coordinate adaptive gains (Jacobs 1988 "delta-bar-delta"), as in
    // the reference implementation.
    let mut gains = vec![1.0f64; y.len()];

    for iteration in 0..schedule.n_iter {
        let early = iteration < schedule.exaggeration_iters;
        let alpha = if early { schedule.exaggeration } else { 1.0 };
        let momentum = if early { MOMENTUM_EARLY } else { MOMENTUM_LATE };

        // The reported KL always uses the true (unexaggerated) P, measured at
        // the embedding the step starts from.
        let eval = p.eval(y, dim, alpha, report.is_some());
        let mut grad_sq = 0.0;
        for ((yv, (v, g)), &grad) in y
            .iter_mut()
            .zip(velocity.iter_mut().zip(gains.iter_mut()))
            .zip(&eval.grad)
        {
            // Grow the gain while the gradient keeps opposing the velocity
            // (steady descent); shrink it when they agree (overshoot).
            *g = if (grad > 0.0) == (*v > 0.0) {
                (*g * 0.8).max(MIN_GAIN)
            } else {
                *g + 0.2
            };
            *v = (schedule.learning_rate * *g).mul_add(-grad, momentum * *v);
            *yv += *v;
            grad_sq = grad.mul_add(grad, grad_sq);
        }
        center(y, dim);

        if let Some(cb) = report.as_mut() {
            let info = Iteration {
                iteration,
                kl_divergence: eval.kl.unwrap_or(f64::NAN),
                gradient_norm: grad_sq.sqrt(),
                exaggerated: early,
            };
            if cb(&info).is_break() {
                return iteration + 1;
            }
        }
    }
    schedule.n_iter
}

#[allow(
    clippy::cast_precision_loss,
    reason = "counts and indices stay far below 2^52, so the f64 conversion is exact"
)]
fn center(y: &mut [f64], dim: usize) {
    let n = y.len() / dim;
    for d in 0..dim {
        let mean = y.iter().skip(d).step_by(dim).sum::<f64>() / n as f64;
        for v in y.iter_mut().skip(d).step_by(dim) {
            *v -= mean;
        }
    }
}
