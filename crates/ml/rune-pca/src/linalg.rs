//! Dense linear-algebra kernels: symmetric eigendecomposition (Householder
//! tridiagonalisation + implicit QL), one-sided Jacobi SVD, Gram-Schmidt and the
//! matrix products the randomized solver needs.
//!
//! Every routine is deterministic: summation orders are fixed and parallel loops
//! only split independent outputs, so results do not depend on the thread count.

use rayon::prelude::*;

/// A non-convergence report from an iterative kernel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NoConvergence;

/// Maximum QL iterations per eigenvalue.
const QL_MAX_ITER: usize = 64;
/// Maximum one-sided Jacobi sweeps.
const JACOBI_MAX_SWEEPS: usize = 80;

pub fn dot(a: &[f64], b: &[f64]) -> f64 {
    a.iter().zip(b).fold(0.0, |acc, (x, y)| x.mul_add(*y, acc))
}

pub fn norm(a: &[f64]) -> f64 {
    dot(a, a).sqrt()
}

/// Eigendecomposition of the symmetric matrix `a` (`n × n`, rows).
///
/// Returns `(eigenvalues, eigenvectors)` with eigenvectors as rows, sorted by
/// decreasing eigenvalue. Port of the EISPACK `tred2`/`tql2` routines (via JAMA).
#[allow(
    clippy::many_single_char_names,
    clippy::similar_names,
    clippy::too_many_lines,
    clippy::needless_range_loop,
    clippy::suboptimal_flops,
    reason = "direct transcription of the EISPACK algorithm keeps its well-known names"
)]
pub fn symmetric_eigen(a: Vec<Vec<f64>>) -> Result<(Vec<f64>, Vec<Vec<f64>>), NoConvergence> {
    let n = a.len();
    if n == 0 {
        return Ok((Vec::new(), Vec::new()));
    }
    let mut v = a;
    let mut d = vec![0.0f64; n];
    let mut e = vec![0.0f64; n];

    // ---- tred2: Householder reduction to tridiagonal form.
    d.copy_from_slice(&v[n - 1]);
    for i in (1..n).rev() {
        let mut scale = 0.0;
        let mut h = 0.0;
        for k in 0..i {
            scale += d[k].abs();
        }
        if scale == 0.0 {
            e[i] = d[i - 1];
            for j in 0..i {
                d[j] = v[i - 1][j];
                v[i][j] = 0.0;
                v[j][i] = 0.0;
            }
        } else {
            for k in 0..i {
                d[k] /= scale;
                h += d[k] * d[k];
            }
            let mut f = d[i - 1];
            let mut g = h.sqrt();
            if f > 0.0 {
                g = -g;
            }
            e[i] = scale * g;
            h -= f * g;
            d[i - 1] = f - g;
            for j in 0..i {
                e[j] = 0.0;
            }
            for j in 0..i {
                f = d[j];
                v[j][i] = f;
                g = v[j][j].mul_add(f, e[j]);
                for k in (j + 1)..i {
                    g = v[k][j].mul_add(d[k], g);
                    e[k] = v[k][j].mul_add(f, e[k]);
                }
                e[j] = g;
            }
            f = 0.0;
            for j in 0..i {
                e[j] /= h;
                f = e[j].mul_add(d[j], f);
            }
            let hh = f / (h + h);
            for j in 0..i {
                e[j] = (-hh).mul_add(d[j], e[j]);
            }
            for j in 0..i {
                f = d[j];
                g = e[j];
                for k in j..i {
                    v[k][j] -= f.mul_add(e[k], g * d[k]);
                }
                d[j] = v[i - 1][j];
                v[i][j] = 0.0;
            }
        }
        d[i] = h;
    }
    for i in 0..n - 1 {
        v[n - 1][i] = v[i][i];
        v[i][i] = 1.0;
        let h = d[i + 1];
        if h != 0.0 {
            for k in 0..=i {
                d[k] = v[k][i + 1] / h;
            }
            for j in 0..=i {
                let mut g = 0.0;
                for k in 0..=i {
                    g = v[k][i + 1].mul_add(v[k][j], g);
                }
                for k in 0..=i {
                    v[k][j] = (-g).mul_add(d[k], v[k][j]);
                }
            }
        }
        for k in 0..=i {
            v[k][i + 1] = 0.0;
        }
    }
    for j in 0..n {
        d[j] = v[n - 1][j];
        v[n - 1][j] = 0.0;
    }
    v[n - 1][n - 1] = 1.0;
    e[0] = 0.0;

    // ---- tql2: implicit QL on the tridiagonal matrix.
    for i in 1..n {
        e[i - 1] = e[i];
    }
    e[n - 1] = 0.0;
    let mut f = 0.0f64;
    let mut tst1 = 0.0f64;
    let eps = f64::EPSILON;
    for l in 0..n {
        tst1 = tst1.max(d[l].abs() + e[l].abs());
        let mut m = l;
        while m < n - 1 && e[m].abs() > eps * tst1 {
            m += 1;
        }
        if m > l {
            let mut iter = 0;
            loop {
                iter += 1;
                if iter > QL_MAX_ITER {
                    return Err(NoConvergence);
                }
                let mut g = d[l];
                let mut p = (d[l + 1] - g) / (2.0 * e[l]);
                let mut r = p.hypot(1.0);
                if p < 0.0 {
                    r = -r;
                }
                d[l] = e[l] / (p + r);
                d[l + 1] = e[l] * (p + r);
                let dl1 = d[l + 1];
                let mut h = g - d[l];
                for di in d.iter_mut().skip(l + 2) {
                    *di -= h;
                }
                f += h;

                p = d[m];
                let mut c = 1.0f64;
                let mut c2 = c;
                let mut c3 = c;
                let el1 = e[l + 1];
                let mut s = 0.0f64;
                let mut s2 = 0.0f64;
                for i in (l..m).rev() {
                    c3 = c2;
                    c2 = c;
                    s2 = s;
                    g = c * e[i];
                    h = c * p;
                    r = p.hypot(e[i]);
                    e[i + 1] = s * r;
                    s = e[i] / r;
                    c = p / r;
                    p = c.mul_add(d[i], -(s * g));
                    d[i + 1] = s.mul_add(c.mul_add(g, s * d[i]), h);
                    for row in &mut v {
                        let h = row[i + 1];
                        row[i + 1] = s.mul_add(row[i], c * h);
                        row[i] = c.mul_add(row[i], -(s * h));
                    }
                }
                p = -s * s2 * c3 * el1 * e[l] / dl1;
                e[l] = s * p;
                d[l] = c * p;
                if e[l].abs() <= eps * tst1 {
                    break;
                }
            }
        }
        d[l] += f;
        e[l] = 0.0;
    }
    if d.iter().any(|x| !x.is_finite()) {
        return Err(NoConvergence);
    }

    // Columns of `v` are the eigenvectors; return them as rows, sorted.
    let mut order: Vec<usize> = (0..n).collect();
    order.sort_by(|&x, &y| d[y].total_cmp(&d[x]).then(x.cmp(&y)));
    let values = order.iter().map(|&i| d[i]).collect();
    let vectors = order
        .iter()
        .map(|&i| v.iter().map(|row| row[i]).collect())
        .collect();
    Ok((values, vectors))
}

/// One-sided (Hestenes) Jacobi orthogonalisation of `cols`, a matrix stored as
/// its columns. On return the columns are mutually orthogonal: `cols = M·W`
/// where `M` is the input and `W` the accumulated rotation, returned when
/// `want_rotation` is set (as columns, `W[j]` = column `j`).
///
/// The column norms are the singular values of `M`; normalised columns are its
/// left singular vectors and the columns of `W` its right singular vectors.
pub fn one_sided_jacobi(
    cols: &mut [Vec<f64>],
    want_rotation: bool,
) -> Result<Option<Vec<Vec<f64>>>, NoConvergence> {
    let c = cols.len();
    let mut w: Option<Vec<Vec<f64>>> = want_rotation.then(|| {
        (0..c)
            .map(|j| {
                let mut col = vec![0.0; c];
                col[j] = 1.0;
                col
            })
            .collect()
    });
    if c < 2 {
        return Ok(w);
    }
    let m = cols[0].len();
    #[allow(
        clippy::cast_precision_loss,
        reason = "matrix sizes stay far below 2^52"
    )]
    let tol = f64::EPSILON * (m.max(1) as f64).sqrt();
    // Columns whose squared norm is below this are numerically zero; rotating
    // them only shuffles rounding noise and would never converge.
    let frob2: f64 = cols.iter().map(|col| dot(col, col)).sum();
    let null = frob2 * tol * tol;

    for _ in 0..JACOBI_MAX_SWEEPS {
        let mut rotated = false;
        for p in 0..c - 1 {
            for q in p + 1..c {
                let alpha = dot(&cols[p], &cols[p]);
                let beta = dot(&cols[q], &cols[q]);
                let gamma = dot(&cols[p], &cols[q]);
                if gamma == 0.0
                    || alpha <= null
                    || beta <= null
                    || gamma.abs() <= tol * (alpha.sqrt() * beta.sqrt())
                {
                    continue;
                }
                rotated = true;
                let zeta = (beta - alpha) / (2.0 * gamma);
                let t = zeta.signum() / (zeta.abs() + zeta.hypot(1.0));
                let cs = 1.0 / t.hypot(1.0);
                let sn = cs * t;
                rotate(cols, p, q, cs, sn);
                if let Some(w) = w.as_mut() {
                    rotate(w, p, q, cs, sn);
                }
            }
        }
        if !rotated {
            return Ok(w);
        }
    }
    Err(NoConvergence)
}

/// Applies the plane rotation `(cs, sn)` to columns `p` and `q`.
fn rotate(cols: &mut [Vec<f64>], p: usize, q: usize, cs: f64, sn: f64) {
    let (head, tail) = cols.split_at_mut(q);
    let (a, b) = (&mut head[p], &mut tail[0]);
    for (x, y) in a.iter_mut().zip(b.iter_mut()) {
        let (xv, yv) = (*x, *y);
        *x = cs.mul_add(xv, -(sn * yv));
        *y = sn.mul_add(xv, cs * yv);
    }
}

/// Orthonormalises `cols` in place with twice-iterated modified Gram-Schmidt.
/// Columns that are (numerically) dependent on earlier ones become zero.
pub fn orthonormalize(cols: &mut [Vec<f64>]) {
    for j in 0..cols.len() {
        let (done, rest) = cols.split_at_mut(j);
        let col = &mut rest[0];
        let original = norm(col);
        for _ in 0..2 {
            for q in done.iter() {
                let proj = dot(q, col);
                for (x, qv) in col.iter_mut().zip(q) {
                    *x = (-proj).mul_add(*qv, *x);
                }
            }
        }
        let n = norm(col);
        if n > 1e-10 * original && n > 0.0 && n.is_finite() {
            for x in col.iter_mut() {
                *x /= n;
            }
        } else {
            for x in col.iter_mut() {
                *x = 0.0;
            }
        }
    }
}

/// Replaces `basis[start..]` by unit vectors orthogonal to every earlier row,
/// starting from their current direction and falling back to coordinate axes.
pub fn complete_orthonormal(basis: &mut [Vec<f64>], start: usize) {
    for j in start..basis.len() {
        let dim = basis[j].len();
        let candidates = std::iter::once(basis[j].clone()).chain((0..dim).map(|axis| {
            let mut e = vec![0.0; dim];
            e[axis] = 1.0;
            e
        }));
        for mut cand in candidates {
            let original = norm(&cand);
            if original == 0.0 || !original.is_finite() {
                continue;
            }
            for _ in 0..2 {
                for q in &basis[..j] {
                    let proj = dot(q, &cand);
                    for (x, qv) in cand.iter_mut().zip(q) {
                        *x = (-proj).mul_add(*qv, *x);
                    }
                }
            }
            let n = norm(&cand);
            if n > 1e-6 * original {
                for x in &mut cand {
                    *x /= n;
                }
                basis[j] = cand;
                break;
            }
        }
    }
}

/// `A · x` for each `x` in `vecs`, where `a` holds the rows of `A`.
pub fn mul_cols(a: &[Vec<f64>], vecs: &[Vec<f64>]) -> Vec<Vec<f64>> {
    vecs.par_iter()
        .map(|x| a.iter().map(|row| dot(row, x)).collect())
        .collect()
}

/// `Aᵀ · y` for each `y` in `vecs`, where `a` holds the rows of `A`.
pub fn mul_t_cols(a: &[Vec<f64>], vecs: &[Vec<f64>], n_cols: usize) -> Vec<Vec<f64>> {
    vecs.par_iter()
        .map(|y| {
            let mut out = vec![0.0; n_cols];
            for (row, &yr) in a.iter().zip(y) {
                for (o, &v) in out.iter_mut().zip(row) {
                    *o = v.mul_add(yr, *o);
                }
            }
            out
        })
        .collect()
}

/// `Aᵀ·A` for `A` given by its columns.
pub fn gram(cols: &[Vec<f64>]) -> Vec<Vec<f64>> {
    let d = cols.len();
    let upper: Vec<Vec<f64>> = (0..d)
        .into_par_iter()
        .map(|i| (i..d).map(|j| dot(&cols[i], &cols[j])).collect())
        .collect();
    let mut g = vec![vec![0.0; d]; d];
    for (i, row) in upper.iter().enumerate() {
        for (off, &val) in row.iter().enumerate() {
            g[i][i + off] = val;
            g[i + off][i] = val;
        }
    }
    g
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn eigen_of_diagonal_matrix() {
        let a = vec![
            vec![1.0, 0.0, 0.0],
            vec![0.0, 3.0, 0.0],
            vec![0.0, 0.0, 2.0],
        ];
        let (vals, vecs) = symmetric_eigen(a).unwrap();
        assert_eq!(vals, vec![3.0, 2.0, 1.0]);
        assert!((vecs[0][1].abs() - 1.0).abs() < 1e-15);
        assert!((vecs[1][2].abs() - 1.0).abs() < 1e-15);
    }

    #[test]
    #[allow(clippy::needless_range_loop, reason = "index-heavy matrix check")]
    fn eigen_reconstructs_random_symmetric_matrix() {
        let n = 7;
        let mut a = vec![vec![0.0; n]; n];
        for i in 0..n {
            for j in 0..=i {
                #[allow(clippy::cast_precision_loss, reason = "tiny indices")]
                let v = ((i * 7 + j * 13) % 11) as f64 - 5.0;
                a[i][j] = v;
                a[j][i] = v;
            }
        }
        let (vals, vecs) = symmetric_eigen(a.clone()).unwrap();
        for i in 0..n {
            for j in 0..n {
                let r: f64 = (0..n).map(|k| vals[k] * vecs[k][i] * vecs[k][j]).sum();
                assert!((r - a[i][j]).abs() < 1e-10, "{r} vs {}", a[i][j]);
            }
            for j in 0..n {
                let dp = dot(&vecs[i], &vecs[j]);
                let want = if i == j { 1.0 } else { 0.0 };
                assert!((dp - want).abs() < 1e-12);
            }
        }
        assert!(vals.windows(2).all(|w| w[0] >= w[1]));
    }

    #[test]
    fn jacobi_gives_singular_values() {
        // Columns of [[3, 0], [4, 5]] → singular values √45 and √5.
        let mut cols = vec![vec![3.0, 4.0], vec![0.0, 5.0]];
        let w = one_sided_jacobi(&mut cols, true).unwrap().unwrap();
        let mut s: Vec<f64> = cols.iter().map(|c| norm(c)).collect();
        s.sort_by(|a, b| b.total_cmp(a));
        assert!((s[0] - 45f64.sqrt()).abs() < 1e-12);
        assert!((s[1] - 5f64.sqrt()).abs() < 1e-12);
        assert!(dot(&w[0], &w[1]).abs() < 1e-14);
        assert!(dot(&cols[0], &cols[1]).abs() < 1e-12);
    }

    #[test]
    fn gram_schmidt_zeroes_dependent_columns() {
        let mut cols = vec![
            vec![1.0, 1.0, 0.0],
            vec![2.0, 2.0, 0.0],
            vec![0.0, 1.0, 1.0],
        ];
        orthonormalize(&mut cols);
        assert!((norm(&cols[0]) - 1.0).abs() < 1e-15);
        assert_eq!(norm(&cols[1]), 0.0);
        assert!(dot(&cols[0], &cols[2]).abs() < 1e-15);
    }

    #[test]
    fn completion_yields_orthonormal_basis() {
        let mut b = vec![
            vec![1.0, 0.0, 0.0],
            vec![0.0, 0.0, 0.0],
            vec![1.0, 0.0, 0.0],
        ];
        complete_orthonormal(&mut b, 1);
        for i in 0..3 {
            for j in 0..3 {
                let want = if i == j { 1.0 } else { 0.0 };
                assert!((dot(&b[i], &b[j]) - want).abs() < 1e-12);
            }
        }
    }
}
