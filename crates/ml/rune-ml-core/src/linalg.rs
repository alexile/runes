//! Small dense solvers over row-major [`Matrix`] buffers.
//!
//! * [`cholesky`] / [`cholesky_solve`] — symmetric positive definite
//!   systems (normal equations, ridge, Newton steps).
//! * [`lstsq`] — full-rank least squares by Householder QR.
//!
//! All loops walk rows, so they stay cache friendly on the row-major
//! layout. The routines work in place and allocate at most one vector.
//! A system that is singular to working precision is reported as
//! [`MlError::Singular`], never as `NaN` output.
//!
//! ```
//! use rune_ml_core::{Matrix, linalg};
//!
//! // Solve [[4, 2], [2, 3]] x = [2, 1].
//! let mut a = Matrix::from_rows(&[[4.0, 2.0], [2.0, 3.0]])?;
//! linalg::cholesky(&mut a)?;
//! let mut b = [2.0_f64, 1.0];
//! linalg::cholesky_solve(&a, &mut b)?;
//! assert!((b[0] - 0.5_f64).abs() < 1e-12 && b[1].abs() < 1e-12);
//!
//! // Least squares fit of y = 1 + 2x.
//! let mut a = Matrix::from_rows(&[[1.0, 0.0], [1.0, 1.0], [1.0, 2.0]])?;
//! let mut y = [1.0_f64, 3.0, 5.0];
//! let x = linalg::lstsq(&mut a, &mut y)?;
//! assert!((x[0] - 1.0).abs() < 1e-12 && (x[1] - 2.0).abs() < 1e-12);
//! # Ok::<(), rune_ml_core::MlError>(())
//! ```

#![allow(
    clippy::many_single_char_names,
    clippy::needless_range_loop,
    reason = "textbook names (a, b, m, n, x) and index loops read best here"
)]

use crate::kernels::dot;
use crate::{Float, Matrix, MlError};

/// Relative pivot tolerance: `max(rows, cols) * eps * scale`.
fn pivot_tol<F: Float>(dim: usize, scale: F) -> F {
    F::from_usize(dim.max(1)) * F::EPSILON * scale
}

const fn check_square<F: Float>(a: &Matrix<F>) -> Result<usize, MlError> {
    let (r, c) = a.shape();
    if r == c {
        Ok(r)
    } else {
        Err(MlError::DimensionMismatch {
            expected: r,
            found: c,
        })
    }
}

/// Cholesky factorisation `A = L·Lᵀ` in place.
///
/// `a` must be square and symmetric; only its lower triangle is read. On
/// success the lower triangle holds `L` and the strict upper triangle is
/// zeroed. Fails with [`MlError::Singular`] when a pivot is not clearly
/// positive (relative to the largest diagonal entry), i.e. the matrix is
/// not positive definite to working precision.
pub fn cholesky<F: Float>(a: &mut Matrix<F>) -> Result<(), MlError> {
    let n = check_square(a)?;
    let max_diag = (0..n).fold(F::ZERO, |m, i| m.max(a[(i, i)].abs()));
    let tol = pivot_tol(n, max_diag);
    let data = a.as_mut_slice();
    for i in 0..n {
        let (head, tail) = data.split_at_mut(i * n);
        let ri = &mut tail[..n];
        for j in 0..i {
            let rj = &head[j * n..=j * n + j];
            let s = ri[j] - dot(&ri[..j], &rj[..j]);
            ri[j] = s / rj[j];
        }
        let s = ri[i] - dot(&ri[..i], &ri[..i]);
        if s.is_nan() || s <= tol {
            return Err(MlError::Singular { pivot: i });
        }
        ri[i] = s.sqrt();
        for v in &mut ri[i + 1..] {
            *v = F::ZERO;
        }
    }
    Ok(())
}

/// Solves `L·Lᵀ x = b` in place, given the factor from [`cholesky`].
pub fn cholesky_solve<F: Float>(l: &Matrix<F>, b: &mut [F]) -> Result<(), MlError> {
    let n = check_square(l)?;
    if b.len() != n {
        return Err(MlError::DimensionMismatch {
            expected: n,
            found: b.len(),
        });
    }
    // Forward: L y = b.
    for i in 0..n {
        let row = l.row(i);
        let s = b[i] - dot(&row[..i], &b[..i]);
        b[i] = s / row[i];
    }
    // Backward: Lᵀ x = y, column-oriented so each step reads one row of L.
    for i in (0..n).rev() {
        let row = l.row(i);
        let xi = b[i] / row[i];
        b[i] = xi;
        for (bk, &lik) in b[..i].iter_mut().zip(&row[..i]) {
            *bk -= lik * xi;
        }
    }
    Ok(())
}

/// Least-squares solution of `min ‖A·x − b‖₂` by Householder QR.
///
/// `a` is `m × n` with `m >= n` and full column rank; it is overwritten
/// with the factorisation and `b` (length `m`) with `Qᵀb`. Fails with
/// [`MlError::Singular`] if `m < n` or a column is (numerically) a linear
/// combination of the previous ones.
pub fn lstsq<F: Float>(a: &mut Matrix<F>, b: &mut [F]) -> Result<Vec<F>, MlError> {
    let (m, n) = a.shape();
    if b.len() != m {
        return Err(MlError::DimensionMismatch {
            expected: m,
            found: b.len(),
        });
    }
    if m < n {
        return Err(MlError::Singular { pivot: m });
    }
    // Largest column norm, for a scale-aware rank test.
    let mut col_sq = vec![F::ZERO; n];
    for row in a.rows() {
        for (c, &v) in col_sq.iter_mut().zip(row) {
            *c += v * v;
        }
    }
    let scale = col_sq.iter().fold(F::ZERO, |s, &v| s.max(v)).sqrt();
    let tol = pivot_tol(m, scale);
    // `col_sq` is reused as the workspace w = Vᵀ·A[k.., k+1..].
    let w = &mut col_sq;
    let mut rdiag = vec![F::ZERO; n];
    for k in 0..n {
        let norm = (k..m).map(|i| a[(i, k)] * a[(i, k)]).sum::<F>().sqrt();
        if norm.is_nan() || norm <= tol {
            return Err(MlError::Singular { pivot: k });
        }
        let x1 = a[(k, k)];
        let beta = if x1 >= F::ZERO { -norm } else { norm };
        a[(k, k)] = x1 - beta;
        // vᵀv = 2β(β − x1); H = I − c·v·vᵀ with c = 2 / vᵀv.
        let c = F::ONE / (beta * (beta - x1));
        rdiag[k] = beta;

        let wk = &mut w[k + 1..];
        wk.fill(F::ZERO);
        let mut wb = F::ZERO;
        for i in k..m {
            let row = a.row(i);
            let vi = row[k];
            for (wj, &aij) in wk.iter_mut().zip(&row[k + 1..]) {
                *wj += vi * aij;
            }
            wb += vi * b[i];
        }
        for i in k..m {
            let row = a.row_mut(i);
            let f = c * row[k];
            for (aij, &wj) in row[k + 1..].iter_mut().zip(wk.iter()) {
                *aij -= f * wj;
            }
            b[i] -= f * wb;
        }
    }
    // Back substitution with R (strict upper part in `a`, diagonal in rdiag).
    let mut x = vec![F::ZERO; n];
    for i in (0..n).rev() {
        let row = a.row(i);
        let s = b[i] - dot(&row[i + 1..], &x[i + 1..]);
        x[i] = s / rdiag[i];
    }
    Ok(x)
}

#[cfg(test)]
#[allow(
    clippy::suboptimal_flops,
    clippy::suspicious_operation_groupings,
    reason = "plain formulas in tests"
)]
mod tests {
    use super::*;

    #[test]
    fn cholesky_known_factor() {
        let mut a = Matrix::from_rows(&[
            [4.0, 12.0, -16.0],
            [12.0, 37.0, -43.0],
            [-16.0, -43.0, 98.0],
        ])
        .unwrap();
        cholesky(&mut a).unwrap();
        let expect = [[2.0, 0.0, 0.0], [6.0, 1.0, 0.0], [-8.0, 5.0, 3.0]];
        for (i, row) in expect.iter().enumerate() {
            for (j, &v) in row.iter().enumerate() {
                assert!((a[(i, j)] - v).abs() < 1e-12);
            }
        }
        let mut b = [1.0, 2.0, 3.0];
        cholesky_solve(&a, &mut b).unwrap();
        // A·x = [1, 2, 3]
        let a0 = [
            [4.0, 12.0, -16.0],
            [12.0, 37.0, -43.0],
            [-16.0, -43.0, 98.0],
        ];
        for (row, t) in a0.iter().zip([1.0, 2.0, 3.0]) {
            assert!((dot(row, &b) - t).abs() < 1e-9);
        }
    }

    #[test]
    fn cholesky_rejects_singular_and_indefinite() {
        let mut a = Matrix::from_rows(&[[1.0, 2.0], [2.0, 4.0]]).unwrap();
        assert_eq!(cholesky(&mut a), Err(MlError::Singular { pivot: 1 }));
        let mut a = Matrix::from_rows(&[[1.0, 0.0], [0.0, -1.0]]).unwrap();
        assert_eq!(cholesky(&mut a), Err(MlError::Singular { pivot: 1 }));
        let mut a = Matrix::<f64>::zeros(2, 2).unwrap();
        assert_eq!(cholesky(&mut a), Err(MlError::Singular { pivot: 0 }));
        let mut a = Matrix::from_rows(&[[f64::NAN]]).unwrap();
        assert!(cholesky(&mut a).is_err());
        let mut a = Matrix::<f64>::zeros(2, 3).unwrap();
        assert!(cholesky(&mut a).is_err());
    }

    #[test]
    fn lstsq_overdetermined_matches_normal_equations() {
        // y ≈ 0.5 + 1.5 x with noise; closed form via the normal equations.
        let xs = [0.0, 1.0, 2.0, 3.0, 4.0];
        let ys = [0.6, 1.9, 3.6, 5.0, 6.4];
        let rows: Vec<[f64; 2]> = xs.iter().map(|&x| [1.0, x]).collect();
        let mut a = Matrix::from_rows(&rows).unwrap();
        let mut b = ys;
        let sol = lstsq(&mut a, &mut b).unwrap();
        let n = 5.0;
        let (sx, sy): (f64, f64) = (xs.iter().sum(), ys.iter().sum());
        let sxx: f64 = xs.iter().map(|x| x * x).sum();
        let sxy: f64 = xs.iter().zip(&ys).map(|(x, y)| x * y).sum();
        let slope = (n * sxy - sx * sy) / (n * sxx - sx * sx);
        let icpt = (sy - slope * sx) / n;
        assert!((sol[0] - icpt).abs() < 1e-12);
        assert!((sol[1] - slope).abs() < 1e-12);
    }

    #[test]
    fn lstsq_rank_deficient_and_shapes() {
        let mut a = Matrix::from_rows(&[[1.0, 2.0], [2.0, 4.0], [3.0, 6.0]]).unwrap();
        let mut b = [1.0, 2.0, 3.0];
        assert_eq!(lstsq(&mut a, &mut b), Err(MlError::Singular { pivot: 1 }));
        let mut a = Matrix::from_rows(&[[1.0, 2.0]]).unwrap();
        assert!(lstsq(&mut a, &mut [1.0]).is_err());
        let mut a = Matrix::from_rows(&[[1.0_f32], [1.0]]).unwrap();
        assert!(lstsq(&mut a, &mut [1.0]).is_err());
        let x = lstsq(&mut a, &mut [1.0, 3.0]).unwrap();
        assert!((x[0] - 2.0).abs() < 1e-6);
    }
}
