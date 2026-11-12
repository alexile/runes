//! Small numerical helpers: a box-bounded Nelder-Mead minimiser and a
//! Householder least-squares solver.

#![allow(
    clippy::many_single_char_names,
    reason = "matrix code reads better with the usual single-letter names"
)]

/// Clamps every coordinate of `x` into `[lower[i], upper[i]]`.
fn clamp_into(x: &mut [f64], lower: &[f64], upper: &[f64]) {
    for ((v, &lo), &hi) in x.iter_mut().zip(lower).zip(upper) {
        *v = v.clamp(lo, hi);
    }
}

/// Evaluates `f`, mapping `NaN` to `+inf` so it always loses comparisons.
fn eval<F: FnMut(&[f64]) -> f64>(f: &mut F, x: &[f64]) -> f64 {
    let v = f(x);
    if v.is_nan() { f64::INFINITY } else { v }
}

/// One Nelder-Mead run. Points that leave the box are projected back onto it.
#[allow(
    clippy::cast_precision_loss,
    reason = "dimensions are tiny, the f64 conversion is exact"
)]
fn nelder_mead_once<F: FnMut(&[f64]) -> f64>(
    f: &mut F,
    x0: &[f64],
    step: &[f64],
    lower: &[f64],
    upper: &[f64],
    max_evals: usize,
) -> (Vec<f64>, f64) {
    let dim = x0.len();
    let mut start = x0.to_vec();
    clamp_into(&mut start, lower, upper);
    let f0 = eval(f, &start);
    if dim == 0 {
        return (start, f0);
    }

    let mut simplex: Vec<(Vec<f64>, f64)> = Vec::with_capacity(dim + 1);
    simplex.push((start.clone(), f0));
    for i in 0..dim {
        let mut v = start.clone();
        v[i] += step[i];
        if v[i] > upper[i] {
            v[i] = start[i] - step[i];
        }
        clamp_into(&mut v, lower, upper);
        let fv = eval(f, &v);
        simplex.push((v, fv));
    }
    let mut evals = dim + 1;

    while evals < max_evals {
        simplex.sort_by(|a, b| a.1.total_cmp(&b.1));
        let best = simplex[0].1;
        let worst = simplex[dim].1;
        let spread = (0..dim)
            .map(|i| {
                let (lo, hi) = simplex
                    .iter()
                    .fold((f64::INFINITY, f64::NEG_INFINITY), |acc, p| {
                        (acc.0.min(p.0[i]), acc.1.max(p.0[i]))
                    });
                hi - lo
            })
            .fold(0.0_f64, f64::max);
        if (worst - best).abs() <= 1e-12 * (best.abs() + 1e-30) && spread <= 1e-10 {
            break;
        }
        if spread <= 1e-12 {
            break;
        }

        let mut centroid = vec![0.0; dim];
        for (p, _) in &simplex[..dim] {
            for (c, v) in centroid.iter_mut().zip(p) {
                *c += v / dim as f64;
            }
        }
        let towards = |coef: f64, from: &[f64]| -> Vec<f64> {
            let mut v: Vec<f64> = centroid
                .iter()
                .zip(from)
                .map(|(c, w)| coef.mul_add(c - w, *c))
                .collect();
            clamp_into(&mut v, lower, upper);
            v
        };

        let worst_point = simplex[dim].0.clone();
        let reflected = towards(1.0, &worst_point);
        let fr = eval(f, &reflected);
        evals += 1;

        if fr < best {
            let expanded = towards(2.0, &worst_point);
            let fe = eval(f, &expanded);
            evals += 1;
            simplex[dim] = if fe < fr {
                (expanded, fe)
            } else {
                (reflected, fr)
            };
            continue;
        }
        if fr < simplex[dim - 1].1 {
            simplex[dim] = (reflected, fr);
            continue;
        }
        let (contracted, fc) = if fr < worst {
            let c = towards(0.5, &worst_point);
            let fc = eval(f, &c);
            (c, fc)
        } else {
            let c = towards(-0.5, &worst_point);
            let fc = eval(f, &c);
            (c, fc)
        };
        evals += 1;
        if fc < fr.min(worst) {
            simplex[dim] = (contracted, fc);
            continue;
        }
        // Shrink everything towards the best vertex.
        let anchor = simplex[0].0.clone();
        for (p, fp) in simplex.iter_mut().skip(1) {
            for (v, a) in p.iter_mut().zip(&anchor) {
                *v = 0.5f64.mul_add(*v - a, *a);
            }
            *fp = eval(f, p);
            evals += 1;
        }
    }
    simplex.sort_by(|a, b| a.1.total_cmp(&b.1));
    let (x, fx) = simplex.swap_remove(0);
    (x, fx)
}

/// Minimises `f` inside the box `[lower, upper]` with Nelder-Mead, restarting
/// from the best point until a restart no longer improves the objective.
pub fn minimize<F: FnMut(&[f64]) -> f64>(
    mut f: F,
    x0: &[f64],
    step: &[f64],
    lower: &[f64],
    upper: &[f64],
    max_evals: usize,
) -> (Vec<f64>, f64) {
    let (mut x, mut fx) = nelder_mead_once(&mut f, x0, step, lower, upper, max_evals);
    for _ in 0..6 {
        let (nx, nfx) = nelder_mead_once(&mut f, &x, step, lower, upper, max_evals);
        let improved = fx - nfx;
        if nfx < fx {
            x = nx;
            fx = nfx;
        }
        if improved.is_nan() || improved <= 1e-10 * (fx.abs() + 1e-30) {
            break;
        }
    }
    (x, fx)
}

/// Solves `min ||A x - b||` where `A` is given column by column, using
/// Householder QR. Columns that are numerically dependent get a zero
/// coefficient instead of blowing up.
pub fn least_squares(columns: &[Vec<f64>], b: &[f64]) -> Vec<f64> {
    let k = columns.len();
    let n = b.len();
    let mut a: Vec<Vec<f64>> = columns.to_vec();
    let mut rhs = b.to_vec();
    let mut diag = vec![0.0; k];

    for j in 0..k.min(n) {
        let (head, tail) = a.split_at_mut(j + 1);
        let col = &mut head[j];
        let norm = col[j..].iter().map(|v| v * v).sum::<f64>().sqrt();
        if norm == 0.0 {
            continue;
        }
        let alpha = if col[j] > 0.0 { -norm } else { norm };
        col[j] -= alpha;
        let vnorm2: f64 = col[j..].iter().map(|v| v * v).sum();
        diag[j] = alpha;
        if vnorm2 == 0.0 {
            continue;
        }
        let reflect = |target: &mut [f64]| {
            let dot: f64 = col[j..].iter().zip(&target[j..]).map(|(v, t)| v * t).sum();
            let factor = 2.0 * dot / vnorm2;
            for (t, v) in target[j..].iter_mut().zip(&col[j..]) {
                *t -= factor * v;
            }
        };
        for other in tail.iter_mut() {
            reflect(other);
        }
        reflect(&mut rhs);
    }

    let max_diag = diag.iter().fold(0.0_f64, |m, d| m.max(d.abs()));
    let mut x = vec![0.0; k];
    for j in (0..k.min(n)).rev() {
        if diag[j].abs() <= 1e-12 * max_diag {
            continue;
        }
        let acc: f64 = (j + 1..k).map(|c| a[c][j] * x[c]).sum();
        x[j] = (rhs[j] - acc) / diag[j];
    }
    x
}

#[cfg(test)]
#[allow(clippy::suboptimal_flops)]
mod tests {
    use super::*;

    #[test]
    fn minimises_a_shifted_quadratic() {
        let (x, fx) = minimize(
            |v| (v[0] - 0.3).powi(2) + 10.0 * (v[1] + 2.0).powi(2),
            &[0.0, 0.0],
            &[0.5, 0.5],
            &[-5.0, -5.0],
            &[5.0, 5.0],
            2000,
        );
        assert!(
            (x[0] - 0.3).abs() < 1e-5 && (x[1] + 2.0).abs() < 1e-5,
            "{x:?}"
        );
        assert!(fx < 1e-9);
    }

    #[test]
    fn respects_bounds() {
        let (x, _) = minimize(
            |v| (v[0] - 3.0).powi(2),
            &[0.5],
            &[0.1],
            &[0.0],
            &[1.0],
            500,
        );
        assert!((x[0] - 1.0).abs() < 1e-9);
    }

    #[test]
    fn least_squares_recovers_line() {
        let xs: Vec<f64> = (0..10).map(f64::from).collect();
        let ys: Vec<f64> = xs.iter().map(|x| 2.0f64.mul_add(*x, 1.0)).collect();
        let coef = least_squares(&[vec![1.0; 10], xs], &ys);
        assert!((coef[0] - 1.0).abs() < 1e-10 && (coef[1] - 2.0).abs() < 1e-10);
    }

    #[test]
    fn least_squares_handles_dependent_columns() {
        let coef = least_squares(&[vec![1.0; 4], vec![2.0; 4]], &[3.0; 4]);
        let fit = coef[0] + 2.0 * coef[1];
        assert!((fit - 3.0).abs() < 1e-10, "{coef:?}");
    }
}
