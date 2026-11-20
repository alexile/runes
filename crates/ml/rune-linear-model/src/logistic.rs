//! Logistic regression: binary and multinomial, L2 / L1 / elastic net.

use rune_ml_core::kernels::{axpy, dot};
use rune_ml_core::{Fit, Float, Matrix, MatrixView, Predict};

use crate::data::{
    balanced_weights, binomial_grad, check_len, check_predict, check_unit, check_weights, check_x,
    encode_labels, sigmoid, softplus,
};
use crate::error::{LinearError, Result};
use crate::optim::{Objective, Report, fista, lbfgs};

/// Per-class sample weighting for classifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum ClassWeight {
    /// Every class weighs the same (sklearn `class_weight=None`).
    #[default]
    Uniform,
    /// `n_samples / (n_classes · count(c))` (sklearn `"balanced"`); with
    /// sample weights for logistic regression, the weighted equivalent.
    Balanced,
}

/// Logistic regression (sklearn `LogisticRegression`).
///
/// Uses sklearn ≥ 1.8's parameterisation: `C` and `l1_ratio`. It
/// minimises
///
/// ```text
/// C · Σ wᵢ ℓᵢ + (1 − ρ)/2 ‖W‖² + ρ ‖W‖₁
/// ```
///
/// where `ℓ` is the binary log loss (two classes, one coefficient row) or
/// the multinomial softmax loss (three or more classes, one row per
/// class), `ρ = l1_ratio`, and the intercept is not penalised.
/// `C = f64::INFINITY` disables the penalty.
///
/// With `l1_ratio = 0` (the default) the problem is smooth and solved by
/// L-BFGS, like sklearn's `lbfgs` solver. Any L1 part switches to an
/// accelerated proximal gradient method (FISTA), giving exact zeros like
/// sklearn's `saga`.
///
/// Labels can be any `Ord + Clone` type; classes are sorted, so the
/// positive class of a binary problem is the larger label.
///
/// ```
/// use rune_linear_model::LogisticRegression;
/// use rune_ml_core::Matrix;
///
/// let x = Matrix::from_rows(&[[0.0_f64], [1.0], [2.0], [3.0]])?;
/// let model = LogisticRegression::new().fit(x.view(), &["no", "no", "yes", "yes"])?;
/// assert_eq!(model.predict(x.view())?, ["no", "no", "yes", "yes"]);
/// // sklearn: coef_ = [[0.95826546]], intercept_ = [-1.43738173]
/// assert!((model.coef()[(0, 0)] - 0.958_265_46).abs() < 1e-3);
/// assert!((model.intercept()[0] + 1.437_381_73).abs() < 1e-3);
/// # Ok::<(), rune_linear_model::LinearError>(())
/// ```
#[derive(Debug, Clone, Copy, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct LogisticRegression {
    /// Inverse regularisation strength, `> 0`; `INFINITY` for none.
    /// Default `1.0`.
    pub c: f64,
    /// Share of L1 in the penalty, in `[0, 1]`. Default `0.0` (pure L2).
    pub l1_ratio: f64,
    /// Fit an intercept. Default `true`.
    pub fit_intercept: bool,
    /// Maximum solver iterations. Default `100`.
    pub max_iter: usize,
    /// Gradient tolerance on the `1/Σw`-scaled objective. Default `1e-4`.
    pub tol: f64,
    /// Class weighting. Default [`ClassWeight::Uniform`].
    pub class_weight: ClassWeight,
    /// L-BFGS history length. Default `10`.
    pub memory: usize,
}

impl Default for LogisticRegression {
    fn default() -> Self {
        Self::new()
    }
}

impl LogisticRegression {
    /// sklearn defaults: `C = 1`, L2, intercept, `max_iter = 100`, `tol = 1e-4`.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            c: 1.0,
            l1_ratio: 0.0,
            fit_intercept: true,
            max_iter: 100,
            tol: 1e-4,
            class_weight: ClassWeight::Uniform,
            memory: 10,
        }
    }

    /// Sets `C`.
    #[must_use]
    pub const fn with_c(mut self, c: f64) -> Self {
        self.c = c;
        self
    }

    /// Sets `l1_ratio` (`1.0` for a pure L1 penalty).
    #[must_use]
    pub const fn with_l1_ratio(mut self, l1_ratio: f64) -> Self {
        self.l1_ratio = l1_ratio;
        self
    }

    /// Sets `fit_intercept`.
    #[must_use]
    pub const fn with_fit_intercept(mut self, fit_intercept: bool) -> Self {
        self.fit_intercept = fit_intercept;
        self
    }

    /// Sets `max_iter`.
    #[must_use]
    pub const fn with_max_iter(mut self, max_iter: usize) -> Self {
        self.max_iter = max_iter;
        self
    }

    /// Sets `tol`.
    #[must_use]
    pub const fn with_tol(mut self, tol: f64) -> Self {
        self.tol = tol;
        self
    }

    /// Sets the class weighting.
    #[must_use]
    pub const fn with_class_weight(mut self, class_weight: ClassWeight) -> Self {
        self.class_weight = class_weight;
        self
    }

    fn validate(&self) -> Result<()> {
        if self.c.is_nan() || self.c <= 0.0 {
            return Err(LinearError::param(
                "c",
                "must be > 0 (INFINITY for no penalty)",
            ));
        }
        check_unit("l1_ratio", self.l1_ratio)?;
        if !(self.tol.is_finite() && self.tol >= 0.0) {
            return Err(LinearError::param("tol", "must be finite and >= 0"));
        }
        if self.max_iter == 0 {
            return Err(LinearError::param("max_iter", "must be at least 1"));
        }
        Ok(())
    }

    /// Fits on `x` and labels `y`.
    pub fn fit<F: Float, L: Ord + Clone>(
        &self,
        x: MatrixView<'_, F>,
        y: &[L],
    ) -> Result<LogisticModel<F, L>> {
        self.fit_weighted(x, y, None)
    }

    /// Fits with optional per-sample weights.
    pub fn fit_weighted<F: Float, L: Ord + Clone>(
        &self,
        x: MatrixView<'_, F>,
        y: &[L],
        sample_weight: Option<&[F]>,
    ) -> Result<LogisticModel<F, L>> {
        self.validate()?;
        check_x(x)?;
        check_len(x.nrows(), y.len())?;
        check_weights(sample_weight, x.nrows())?;
        let (classes, codes) = encode_labels(y);
        if classes.len() < 2 {
            return Err(LinearError::TooFewClasses {
                found: classes.len(),
            });
        }
        let n_classes = classes.len();
        let mut sw: Vec<F> = sample_weight.map_or_else(|| vec![F::ONE; codes.len()], <[F]>::to_vec);
        if self.class_weight == ClassWeight::Balanced {
            let cw = balanced_weights(&codes, n_classes, sample_weight);
            for (w, &c) in sw.iter_mut().zip(&codes) {
                *w *= cw[c];
            }
        }
        let total: F = sw.iter().copied().sum();
        if total <= F::ZERO {
            return Err(LinearError::ZeroWeightSum);
        }
        for w in &mut sw {
            *w /= total;
        }
        let rows = if n_classes == 2 { 1 } else { n_classes };
        let p = x.ncols();
        // Penalties on the 1/Σw-scaled objective.
        let inv_c = if self.c.is_infinite() {
            0.0
        } else {
            1.0 / self.c
        };
        let lambda1 = F::from_f64(inv_c * self.l1_ratio) / total;
        let lambda2 = F::from_f64(inv_c * (1.0 - self.l1_ratio)) / total;
        let mut obj = LogLoss {
            x,
            codes: &codes,
            sw: &sw,
            rows,
            fit_intercept: self.fit_intercept,
            l2: lambda2,
            z: vec![F::ZERO; rows],
        };
        let stride = p + 1;
        let mut theta = vec![F::ZERO; rows * stride];
        let tol = F::from_f64(self.tol);
        let report: Report = if lambda1 > F::ZERO {
            fista(
                &mut obj,
                &mut theta,
                |i| i % stride != p,
                lambda1,
                self.max_iter,
                tol,
            )
        } else {
            lbfgs(&mut obj, &mut theta, self.max_iter, tol, self.memory)
        };
        if theta.iter().any(|v| !v.is_finite()) {
            return Err(LinearError::InvalidModel(
                "solver produced non-finite coefficients",
            ));
        }
        let mut coef = Matrix::zeros(rows, p)?;
        let mut intercept = vec![F::ZERO; rows];
        for k in 0..rows {
            coef.row_mut(k)
                .copy_from_slice(&theta[k * stride..k * stride + p]);
            intercept[k] = theta[k * stride + p];
        }
        Ok(LogisticModel {
            classes,
            coef,
            intercept,
            n_iter: report.n_iter,
            converged: report.converged,
        })
    }
}

impl<'a, F: Float, L: Ord + Clone> Fit<(MatrixView<'a, F>, &'a [L])> for LogisticRegression {
    type Model = LogisticModel<F, L>;
    type Error = LinearError;
    fn fit(&self, data: &(MatrixView<'a, F>, &'a [L])) -> Result<LogisticModel<F, L>> {
        Self::fit(self, data.0, data.1)
    }
}

/// Weighted mean log loss plus `l2/2 ‖W‖²`.
struct LogLoss<'a, F> {
    x: MatrixView<'a, F>,
    codes: &'a [usize],
    sw: &'a [F],
    rows: usize,
    fit_intercept: bool,
    l2: F,
    z: Vec<F>,
}

impl<F: Float> Objective<F> for LogLoss<'_, F> {
    fn eval(&mut self, theta: &[F], grad: &mut [F]) -> F {
        let p = self.x.ncols();
        let stride = p + 1;
        grad.fill(F::ZERO);
        let mut f = F::ZERO;
        for ((xi, &c), &w) in self.x.rows().zip(self.codes).zip(self.sw) {
            if w == F::ZERO {
                continue;
            }
            for (k, z) in self.z.iter_mut().enumerate() {
                let t = &theta[k * stride..(k + 1) * stride];
                *z = dot(xi, &t[..p]) + t[p];
            }
            if self.rows == 1 {
                let z = self.z[0];
                let yv = if c == 1 { F::ONE } else { F::ZERO };
                f += w * (softplus(z) - yv * z);
                self.z[0] = w * binomial_grad(yv, z);
            } else {
                let zmax = self.z.iter().fold(F::NEG_INFINITY, |m, &v| m.max(v));
                let mut sum = F::ZERO;
                for z in &mut self.z {
                    *z = (*z - zmax).exp();
                    sum += *z;
                }
                // −log softmax_c = log Σ e^{z−zmax} − (z_c − zmax)
                f += w * (sum.ln() - self.z[c].ln());
                for (k, z) in self.z.iter_mut().enumerate() {
                    let target = if k == c { F::ONE } else { F::ZERO };
                    *z = w * (*z / sum - target);
                }
            }
            for (k, &r) in self.z.iter().enumerate() {
                let g = &mut grad[k * stride..(k + 1) * stride];
                axpy(r, xi, &mut g[..p]);
                g[p] += r;
            }
        }
        let half = F::from_f64(0.5);
        for k in 0..self.rows {
            let t = &theta[k * stride..k * stride + p];
            let g = &mut grad[k * stride..(k + 1) * stride];
            if self.l2 > F::ZERO {
                f += half * self.l2 * dot(t, t);
                axpy(self.l2, t, &mut g[..p]);
            }
            if !self.fit_intercept {
                g[p] = F::ZERO;
            }
        }
        f
    }
}

/// A fitted [`LogisticRegression`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct LogisticModel<F, L> {
    classes: Vec<L>,
    coef: Matrix<F>,
    intercept: Vec<F>,
    n_iter: usize,
    converged: bool,
}

impl<F: Float, L: Ord + Clone> LogisticModel<F, L> {
    /// Sorted class labels (sklearn `classes_`).
    #[must_use]
    pub fn classes(&self) -> &[L] {
        &self.classes
    }

    /// Coefficients: one row for a binary problem (for `classes()[1]`),
    /// otherwise one row per class (sklearn `coef_`).
    #[must_use]
    pub const fn coef(&self) -> &Matrix<F> {
        &self.coef
    }

    /// Intercepts, one per row of [`coef`](Self::coef).
    #[must_use]
    pub fn intercept(&self) -> &[F] {
        &self.intercept
    }

    /// Solver iterations (sklearn `n_iter_`).
    #[must_use]
    pub const fn n_iter(&self) -> usize {
        self.n_iter
    }

    /// `false` when `max_iter` ran out first (sklearn's `ConvergenceWarning`).
    #[must_use]
    pub const fn converged(&self) -> bool {
        self.converged
    }

    /// Number of features the model expects.
    #[must_use]
    pub const fn n_features(&self) -> usize {
        self.coef.ncols()
    }

    /// Raw scores `x · Wᵀ + b`: `n × 1` for binary, `n × n_classes` otherwise.
    pub fn decision_function(&self, x: MatrixView<'_, F>) -> Result<Matrix<F>> {
        check_shape(&self.classes, &self.coef, &self.intercept)?;
        decision(&self.coef, &self.intercept, x)
    }

    /// Class probabilities, `n × n_classes`, columns in `classes()` order.
    pub fn predict_proba(&self, x: MatrixView<'_, F>) -> Result<Matrix<F>> {
        let mut scores = self.decision_function(x)?;
        if self.coef.nrows() == 1 {
            let mut out = Matrix::zeros(scores.nrows(), 2)?;
            for (o, s) in out.rows_mut().zip(scores.rows()) {
                let p = sigmoid(s[0]);
                o[0] = F::ONE - p;
                o[1] = p;
            }
            return Ok(out);
        }
        for row in scores.rows_mut() {
            softmax(row);
        }
        Ok(scores)
    }

    /// Most likely class for every row.
    pub fn predict(&self, x: MatrixView<'_, F>) -> Result<Vec<L>> {
        let scores = self.decision_function(x)?;
        Ok(labels_from_scores(&scores, &self.classes))
    }

    /// Mean accuracy on `(x, y)` (sklearn `score`).
    pub fn score(&self, x: MatrixView<'_, F>, y: &[L]) -> Result<f64> {
        let pred = self.predict(x)?;
        Ok(rune_ml_metrics::accuracy_score(y, &pred)?)
    }
}

impl<'a, F: Float, L: Ord + Clone> Predict<MatrixView<'a, F>> for LogisticModel<F, L> {
    type Output = Vec<L>;
    type Error = LinearError;
    fn predict(&self, x: &MatrixView<'a, F>) -> Result<Vec<L>> {
        Self::predict(self, *x)
    }
}

/// In-place numerically stable softmax.
pub fn softmax<F: Float>(row: &mut [F]) {
    let m = row.iter().fold(F::NEG_INFINITY, |m, &v| m.max(v));
    let mut sum = F::ZERO;
    for v in row.iter_mut() {
        *v = (*v - m).exp();
        sum += *v;
    }
    for v in row.iter_mut() {
        *v /= sum;
    }
}

/// Checks a (possibly deserialized) linear classifier is consistent.
pub const fn check_shape<F: Float, L>(
    classes: &[L],
    coef: &Matrix<F>,
    intercept: &[F],
) -> Result<()> {
    let rows = coef.nrows();
    let ok = classes.len() >= 2
        && intercept.len() == rows
        && (rows == classes.len() || (rows == 1 && classes.len() == 2));
    if ok {
        Ok(())
    } else {
        Err(LinearError::InvalidModel(
            "classes, coefficient rows and intercepts disagree",
        ))
    }
}

/// `x · Wᵀ + b`, row by row.
pub fn decision<F: Float>(
    coef: &Matrix<F>,
    intercept: &[F],
    x: MatrixView<'_, F>,
) -> Result<Matrix<F>> {
    check_predict(x, coef.ncols())?;
    let k = coef.nrows();
    let mut out = Matrix::zeros(x.nrows(), k)?;
    for (o, xi) in out.rows_mut().zip(x.rows()) {
        for ((v, w), &b) in o.iter_mut().zip(coef.rows()).zip(intercept) {
            *v = dot(xi, w) + b;
        }
    }
    Ok(out)
}

/// Binary: `score > 0` → `classes[1]`; multiclass: arg-max (first on ties).
pub fn labels_from_scores<F: Float, L: Clone>(scores: &Matrix<F>, classes: &[L]) -> Vec<L> {
    scores
        .rows()
        .map(|s| {
            let k = if s.len() == 1 {
                usize::from(s[0] > F::ZERO)
            } else {
                let mut best = 0;
                for (j, &v) in s.iter().enumerate() {
                    if v > s[best] {
                        best = j;
                    }
                }
                best
            };
            classes[k].clone()
        })
        .collect()
}
