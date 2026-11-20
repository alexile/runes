//! Smooth (L-BFGS) and composite (FISTA) minimisers over flat parameter
//! vectors. All buffers are allocated once per solve.

use rune_ml_core::Float;
use rune_ml_core::kernels::dot;

/// A differentiable objective: writes the gradient and returns the value.
pub trait Objective<F> {
    fn eval(&mut self, theta: &[F], grad: &mut [F]) -> F;
}

/// Result of a minimisation.
#[derive(Debug, Clone, Copy)]
pub struct Report {
    pub n_iter: usize,
    pub converged: bool,
}

/// `v <= tol`, also true for `NaN` (treated as "stop").
fn not_above<F: Float>(v: F, tol: F) -> bool {
    v.is_nan() || v <= tol
}

fn max_abs<F: Float>(v: &[F]) -> F {
    v.iter().fold(F::ZERO, |m, x| m.max(x.abs()))
}

/// Limited-memory BFGS with a backtracking Armijo line search.
///
/// Stops when `max |g| <= tol` (scipy's `gtol`), or when the relative
/// decrease of the objective falls below `64·eps` (scipy's `ftol`).
pub fn lbfgs<F: Float, O: Objective<F>>(
    obj: &mut O,
    theta: &mut [F],
    max_iter: usize,
    tol: F,
    memory: usize,
) -> Report {
    let dim = theta.len();
    let m = memory.max(1);
    let mut s_hist = vec![F::ZERO; m * dim];
    let mut y_hist = vec![F::ZERO; m * dim];
    let mut rho = vec![F::ZERO; m];
    let mut alpha = vec![F::ZERO; m];
    let (mut len, mut head) = (0_usize, 0_usize);
    let mut g = vec![F::ZERO; dim];
    let mut g_new = vec![F::ZERO; dim];
    let mut d = vec![F::ZERO; dim];
    let mut next = vec![F::ZERO; dim];
    let mut f = obj.eval(theta, &mut g);
    let ftol = F::from_f64(64.0) * F::EPSILON;
    for it in 0..max_iter {
        if not_above(max_abs(&g), tol) {
            return Report {
                n_iter: it,
                converged: f.is_finite(),
            };
        }
        // Two-loop recursion: d = −H·g.
        d.copy_from_slice(&g);
        for back in 0..len {
            let slot = (head + m - 1 - back) % m;
            let s = &s_hist[slot * dim..(slot + 1) * dim];
            let y = &y_hist[slot * dim..(slot + 1) * dim];
            alpha[slot] = rho[slot] * dot(s, &d);
            for (di, &yi) in d.iter_mut().zip(y) {
                *di -= alpha[slot] * yi;
            }
        }
        let gamma = if len > 0 {
            let slot = (head + m - 1) % m;
            let y = &y_hist[slot * dim..(slot + 1) * dim];
            F::ONE / (rho[slot] * dot(y, y))
        } else {
            F::ONE / F::ONE.max(dot(&g, &g).sqrt())
        };
        for di in &mut d {
            *di *= gamma;
        }
        for fwd in 0..len {
            let slot = (head + m - len + fwd) % m;
            let s = &s_hist[slot * dim..(slot + 1) * dim];
            let y = &y_hist[slot * dim..(slot + 1) * dim];
            let beta = rho[slot] * dot(y, &d);
            for (di, &si) in d.iter_mut().zip(s) {
                *di += (alpha[slot] - beta) * si;
            }
        }
        for di in &mut d {
            *di = -*di;
        }
        let mut gd = dot(&g, &d);
        if gd.is_nan() || gd >= F::ZERO {
            // Not a descent direction: drop the history, use −g.
            len = 0;
            for (di, &gi) in d.iter_mut().zip(&g) {
                *di = -gi;
            }
            gd = -dot(&g, &g);
        }
        let Some(f_new) = backtrack(obj, theta, &d, f, gd, &mut next, &mut g_new) else {
            return Report {
                n_iter: it + 1,
                converged: false,
            };
        };
        // Keep the pair (s, y) = (next − θ, g_new − g) only if it has
        // positive curvature.
        let (mut sy, mut yy) = (F::ZERO, F::ZERO);
        for i in 0..dim {
            let y = g_new[i] - g[i];
            sy += (next[i] - theta[i]) * y;
            yy += y * y;
        }
        if sy > F::EPSILON * yy {
            let slot = head;
            for i in 0..dim {
                s_hist[slot * dim + i] = next[i] - theta[i];
                y_hist[slot * dim + i] = g_new[i] - g[i];
            }
            rho[slot] = F::ONE / sy;
            head = (head + 1) % m;
            len = (len + 1).min(m);
        }
        theta.copy_from_slice(&next);
        core::mem::swap(&mut g, &mut g_new);
        let rel = (f - f_new) / f.abs().max(f_new.abs()).max(F::ONE);
        f = f_new;
        if rel <= ftol {
            return Report {
                n_iter: it + 1,
                converged: true,
            };
        }
    }
    Report {
        n_iter: max_iter,
        converged: not_above(max_abs(&g), tol),
    }
}

/// Armijo backtracking from a unit step. Writes the accepted point to
/// `next` and its gradient to `g_new`; `None` if no decrease was found.
fn backtrack<F: Float, O: Objective<F>>(
    obj: &mut O,
    theta: &[F],
    d: &[F],
    f: F,
    gd: F,
    next: &mut [F],
    g_new: &mut [F],
) -> Option<F> {
    let c1 = F::from_f64(1e-4);
    let half = F::from_f64(0.5);
    let mut t = F::ONE;
    for _ in 0..60 {
        for ((n, &x), &di) in next.iter_mut().zip(theta).zip(d) {
            *n = x + t * di;
        }
        let f_new = obj.eval(next, g_new);
        if f_new <= f + c1 * t * gd {
            return Some(f_new);
        }
        t *= half;
    }
    None
}

/// FISTA with backtracking and gradient-based restart for
/// `f(θ) + λ Σ_{j ∈ penalised} |θ_j|`.
///
/// Stops when the gradient mapping `L·‖θ⁺ − y‖∞` is at most `tol`.
pub fn fista<F: Float, O: Objective<F>>(
    obj: &mut O,
    theta: &mut [F],
    penalised: impl Fn(usize) -> bool,
    lambda: F,
    max_iter: usize,
    tol: F,
) -> Report {
    let dim = theta.len();
    let mut y = theta.to_vec();
    let mut gy = vec![F::ZERO; dim];
    let mut next = vec![F::ZERO; dim];
    let mut scratch = vec![F::ZERO; dim];
    let mut t = F::ONE;
    let mut lip = F::ONE;
    let half = F::from_f64(0.5);
    for it in 0..max_iter {
        let fy = obj.eval(&y, &mut gy);
        lip *= F::from_f64(0.9);
        let mut accepted = false;
        for _ in 0..80 {
            let step = F::ONE / lip;
            for i in 0..dim {
                let v = y[i] - step * gy[i];
                next[i] = if penalised(i) {
                    shrink(v, lambda * step)
                } else {
                    v
                };
            }
            let fx = obj.eval(&next, &mut scratch);
            let mut lin = F::ZERO;
            let mut sq = F::ZERO;
            for i in 0..dim {
                let diff = next[i] - y[i];
                lin += gy[i] * diff;
                sq += diff * diff;
            }
            if fx <= fy + lin + half * lip * sq {
                accepted = true;
                break;
            }
            lip *= F::from_f64(2.0);
        }
        if !accepted {
            return Report {
                n_iter: it + 1,
                converged: false,
            };
        }
        let mapping = (0..dim).fold(F::ZERO, |m, i| m.max((next[i] - y[i]).abs())) * lip;
        // Restart momentum when it points uphill.
        let mut uphill = F::ZERO;
        for i in 0..dim {
            uphill += (y[i] - next[i]) * (next[i] - theta[i]);
        }
        let t_new = (F::ONE + (F::ONE + F::from_f64(4.0) * t * t).sqrt()) * half;
        let momentum = if uphill > F::ZERO {
            t = F::ONE;
            F::ZERO
        } else {
            let mo = (t - F::ONE) / t_new;
            t = t_new;
            mo
        };
        for i in 0..dim {
            y[i] = next[i] + momentum * (next[i] - theta[i]);
        }
        theta.copy_from_slice(&next);
        if not_above(mapping, tol) {
            return Report {
                n_iter: it + 1,
                converged: true,
            };
        }
    }
    Report {
        n_iter: max_iter,
        converged: false,
    }
}

#[inline]
fn shrink<F: Float>(v: F, t: F) -> F {
    if v > t {
        v - t
    } else if v < -t {
        v + t
    } else {
        F::ZERO
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `f(x) = Σ (i+1)·(x_i − 1)²`, a badly scaled quadratic.
    struct Quad;
    impl Objective<f64> for Quad {
        fn eval(&mut self, x: &[f64], g: &mut [f64]) -> f64 {
            let mut f = 0.0;
            for (i, (&xi, gi)) in x.iter().zip(g.iter_mut()).enumerate() {
                let c = (i + 1) as f64;
                f += c * (xi - 1.0) * (xi - 1.0);
                *gi = 2.0 * c * (xi - 1.0);
            }
            f
        }
    }

    #[test]
    fn lbfgs_minimises_quadratic() {
        let mut x = vec![0.0; 6];
        let r = lbfgs(&mut Quad, &mut x, 100, 1e-10, 10);
        assert!(r.converged);
        assert!(x.iter().all(|v| (v - 1.0).abs() < 1e-8), "{x:?}");
    }

    #[test]
    fn fista_soft_thresholds() {
        // min Σ c_i (x_i − 1)² + 3|x_i|: x_i = max(0, 1 − 1.5 / c_i).
        let mut x = vec![0.0; 4];
        let r = fista(&mut Quad, &mut x, |_| true, 3.0, 5000, 1e-10);
        assert!(r.converged);
        for (i, v) in x.iter().enumerate() {
            let c = (i + 1) as f64;
            assert!((v - (1.0 - 1.5 / c).max(0.0)).abs() < 1e-8, "{x:?}");
        }
    }
}
