//! Input validation, centring and label encoding shared by the estimators.

use rune_ml_core::{Float, Matrix, MatrixView, MlError};

use crate::error::{LinearError, Result};

/// Checks `x` is non-empty, has at least one feature and is finite.
pub fn check_x<F: Float>(x: MatrixView<'_, F>) -> Result<()> {
    if x.nrows() == 0 {
        return Err(MlError::TooFewSamples { needed: 1, got: 0 }.into());
    }
    if x.ncols() == 0 {
        return Err(LinearError::param("x", "must have at least one feature"));
    }
    x.check_finite()?;
    if !sum_sq(x.as_slice()).is_finite() {
        return Err(LinearError::Overflow("x"));
    }
    Ok(())
}

fn sum_sq<F: Float>(v: &[F]) -> F {
    rune_ml_core::kernels::norm_sq(v)
}

/// Checks `x` for prediction: finite and with `n_features` columns.
pub fn check_predict<F: Float>(x: MatrixView<'_, F>, n_features: usize) -> Result<()> {
    if x.ncols() != n_features {
        return Err(LinearError::FeatureMismatch {
            expected: n_features,
            found: x.ncols(),
        });
    }
    x.check_finite()?;
    Ok(())
}

pub const fn check_len(n: usize, found: usize) -> Result<()> {
    if n == found {
        Ok(())
    } else {
        Err(LinearError::LengthMismatch { expected: n, found })
    }
}

/// Checks a regression target.
pub fn check_y<F: Float>(y: &[F], n: usize) -> Result<()> {
    check_len(n, y.len())?;
    y.iter()
        .position(|v| !v.is_finite())
        .map_or(Ok(()), |index| Err(LinearError::NonFiniteTarget { index }))?;
    if sum_sq(y).is_finite() {
        Ok(())
    } else {
        Err(LinearError::Overflow("y"))
    }
}

/// Checks sample weights (finite, non-negative, positive sum).
pub fn check_weights<F: Float>(sw: Option<&[F]>, n: usize) -> Result<()> {
    let Some(sw) = sw else { return Ok(()) };
    check_len(n, sw.len())?;
    if let Some(index) = sw.iter().position(|&w| !w.is_finite() || w < F::ZERO) {
        return Err(LinearError::InvalidSampleWeight { index });
    }
    let total: F = sw.iter().sum();
    if total > F::ZERO && total.is_finite() {
        Ok(())
    } else {
        Err(LinearError::ZeroWeightSum)
    }
}

pub fn check_alpha(name: &'static str, v: f64) -> Result<()> {
    if v.is_finite() && v >= 0.0 {
        Ok(())
    } else {
        Err(LinearError::param(name, "must be finite and >= 0"))
    }
}

pub fn check_unit(name: &'static str, v: f64) -> Result<()> {
    if (0.0..=1.0).contains(&v) {
        Ok(())
    } else {
        Err(LinearError::param(name, "must be in [0, 1]"))
    }
}

/// Weighted column means of `x` and mean of `y`; zeros without an intercept.
pub fn means<F: Float>(
    x: MatrixView<'_, F>,
    y: &[F],
    sw: Option<&[F]>,
    fit_intercept: bool,
) -> (Vec<F>, F) {
    let mut xm = vec![F::ZERO; x.ncols()];
    if !fit_intercept {
        return (xm, F::ZERO);
    }
    let mut ym = F::ZERO;
    let mut total = F::ZERO;
    for (i, row) in x.rows().enumerate() {
        let w = sw.map_or(F::ONE, |s| s[i]);
        for (m, &v) in xm.iter_mut().zip(row) {
            *m += w * v;
        }
        ym += w * y[i];
        total += w;
    }
    for m in &mut xm {
        *m /= total;
    }
    (xm, ym / total)
}

/// `sqrt(w_i)` per sample, optionally rescaled so the weights sum to `n`.
pub fn sqrt_weights<F: Float>(sw: Option<&[F]>, n: usize, rescale: bool) -> Option<Vec<F>> {
    let sw = sw?;
    let f = if rescale {
        F::from_usize(n) / sw.iter().copied().sum::<F>()
    } else {
        F::ONE
    };
    Some(sw.iter().map(|&w| (w * f).sqrt()).collect())
}

/// Row-major copy of `sqrt(w) * (x - xm)`.
pub fn centered_rows<F: Float>(x: MatrixView<'_, F>, xm: &[F], sq: Option<&[F]>) -> Matrix<F> {
    let mut data = Vec::with_capacity(x.nrows() * x.ncols());
    for (i, row) in x.rows().enumerate() {
        let s = sq.map_or(F::ONE, |s| s[i]);
        data.extend(row.iter().zip(xm).map(|(&v, &m)| (v - m) * s));
    }
    Matrix::from_vec(data, x.nrows(), x.ncols()).unwrap_or_default()
}

/// Column-major copy of `sqrt(w) * (x - xm)`: feature `j` at `j*n..(j+1)*n`.
pub fn centered_cols<F: Float>(x: MatrixView<'_, F>, xm: &[F], sq: Option<&[F]>) -> Vec<F> {
    let (n, p) = x.shape();
    let mut data = vec![F::ZERO; n * p];
    for (i, row) in x.rows().enumerate() {
        let s = sq.map_or(F::ONE, |s| s[i]);
        for (j, (&v, &m)) in row.iter().zip(xm).enumerate() {
            data[j * n + i] = (v - m) * s;
        }
    }
    data
}

/// `sqrt(w) * (y - ym)`.
pub fn centered_target<F: Float>(y: &[F], ym: F, sq: Option<&[F]>) -> Vec<F> {
    y.iter()
        .enumerate()
        .map(|(i, &v)| (v - ym) * sq.map_or(F::ONE, |s| s[i]))
        .collect()
}

/// Sorted distinct classes and the class index of every sample.
pub fn encode_labels<L: Ord + Clone>(y: &[L]) -> (Vec<L>, Vec<usize>) {
    let mut classes = y.to_vec();
    classes.sort_unstable();
    classes.dedup();
    let codes = y
        .iter()
        .map(|l| classes.binary_search(l).unwrap_or(0))
        .collect();
    (classes, codes)
}

/// Class index of every sample against known classes.
pub fn encode_known<L: Ord>(classes: &[L], y: &[L]) -> Result<Vec<usize>> {
    y.iter()
        .enumerate()
        .map(|(index, l)| {
            classes
                .binary_search(l)
                .map_err(|_| LinearError::UnknownLabel { index })
        })
        .collect()
}

/// `"balanced"` class weights: `sum(w) / (k * sum(w of class c))`.
pub fn balanced_weights<F: Float>(codes: &[usize], k: usize, sw: Option<&[F]>) -> Vec<F> {
    let mut per_class = vec![F::ZERO; k];
    for (i, &c) in codes.iter().enumerate() {
        per_class[c] += sw.map_or(F::ONE, |s| s[i]);
    }
    let total: F = per_class.iter().copied().sum();
    let kf = F::from_usize(k);
    per_class
        .iter()
        .map(|&c| {
            if c > F::ZERO {
                total / (kf * c)
            } else {
                F::ONE
            }
        })
        .collect()
}

/// `x · w + b` for every row.
pub fn linear_predict<F: Float>(x: MatrixView<'_, F>, coef: &[F], intercept: F) -> Vec<F> {
    x.rows()
        .map(|r| rune_ml_core::kernels::dot(r, coef) + intercept)
        .collect()
}

#[inline]
pub fn sigmoid<F: Float>(z: F) -> F {
    if z >= F::ZERO {
        F::ONE / (F::ONE + (-z).exp())
    } else {
        let e = z.exp();
        e / (F::ONE + e)
    }
}

/// `log(1 + exp(x))` without overflow, with scikit-learn's cut-offs.
#[inline]
pub fn softplus<F: Float>(x: F) -> F {
    let v = x.to_f64();
    let r = if v <= -37.0 {
        v.exp()
    } else if v <= 18.0 {
        v.exp().ln_1p()
    } else if v <= 33.3 {
        v + (-v).exp()
    } else {
        v
    };
    F::from_f64(r)
}

/// `sigmoid(z) − y`, the binomial log-loss gradient, without the
/// cancellation of the naive form when `y = 1` and `z` is large.
#[inline]
pub fn binomial_grad<F: Float>(y: F, z: F) -> F {
    if z > F::from_f64(-37.0) {
        let e = (-z).exp();
        ((F::ONE - y) - y * e) / (F::ONE + e)
    } else {
        z.exp() - y
    }
}
