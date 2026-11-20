//! Lasso and elastic net by cyclic coordinate descent.

use rune_ml_core::kernels::{axpy, dot};
use rune_ml_core::{Fit, Float, MatrixView, Predict, Rng};

use crate::data::{
    centered_cols, centered_target, check_alpha, check_len, check_unit, means, sqrt_weights,
};
use crate::error::{LinearError, Result};
use crate::linear::{LinearModel, check_regression};

/// Order in which coordinate descent visits the features.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum Selection {
    /// Features in order `0..p` every sweep (sklearn default).
    #[default]
    Cyclic,
    /// A uniformly random feature per step, from the estimator's seed.
    /// Often converges faster when `tol` is loose.
    Random,
}

/// Elastic net (sklearn `ElasticNet`), and lasso via [`ElasticNet::lasso`].
///
/// Minimises, exactly as scikit-learn does,
///
/// ```text
/// 1/(2·n) ‖y − Xβ − b‖² + α·ρ‖β‖₁ + α·(1 − ρ)/2 ‖β‖²
/// ```
///
/// with `ρ = l1_ratio`. With sample weights the squared loss becomes
/// `1/(2·Σw) Σ wᵢ rᵢ²`. Solved by coordinate descent on the centred data
/// with an incrementally updated residual; it stops when the duality gap
/// falls below `tol · ‖y − ȳ‖²` (sklearn's criterion).
///
/// Not reaching the gap within `max_iter` sweeps is not an error: the
/// model reports it through [`ElasticNetModel::converged`].
///
/// ```
/// use rune_linear_model::ElasticNet;
/// use rune_ml_core::Matrix;
///
/// let x = Matrix::from_rows(&[[0.0_f64, 0.0], [1.0, 1.0], [2.0, 2.0]])?;
/// let model = ElasticNet::lasso(0.1).fit(x.view(), &[0.0, 1.0, 2.0])?;
/// // sklearn: coef_ = [0.85, 0.0], intercept_ = 0.15
/// assert!((model.coef()[0] - 0.85).abs() < 1e-6 && model.coef()[1] == 0.0);
/// assert!(model.converged());
/// # Ok::<(), rune_linear_model::LinearError>(())
/// ```
#[derive(Debug, Clone, Copy, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ElasticNet {
    /// Overall penalty strength `α >= 0`. Default `1.0`.
    pub alpha: f64,
    /// Mix between L1 (`1.0`) and L2 (`0.0`). Default `0.5`.
    pub l1_ratio: f64,
    /// Fit an intercept. Default `true`.
    pub fit_intercept: bool,
    /// Maximum number of sweeps over the features. Default `1000`.
    pub max_iter: usize,
    /// Tolerance on the duality gap (relative to `‖y − ȳ‖²`) and on the
    /// largest coefficient update. Default `1e-4`.
    pub tol: f64,
    /// Feature visiting order. Default [`Selection::Cyclic`].
    pub selection: Selection,
    /// Seed for [`Selection::Random`]. Default `0`.
    pub seed: u64,
}

impl Default for ElasticNet {
    fn default() -> Self {
        Self::new(1.0, 0.5)
    }
}

impl ElasticNet {
    /// Elastic net with the given `alpha` and `l1_ratio`.
    #[must_use]
    pub const fn new(alpha: f64, l1_ratio: f64) -> Self {
        Self {
            alpha,
            l1_ratio,
            fit_intercept: true,
            max_iter: 1000,
            tol: 1e-4,
            selection: Selection::Cyclic,
            seed: 0,
        }
    }

    /// Lasso (sklearn `Lasso(alpha)`): elastic net with `l1_ratio = 1`.
    #[must_use]
    pub const fn lasso(alpha: f64) -> Self {
        Self::new(alpha, 1.0)
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

    /// Sets the feature selection order.
    #[must_use]
    pub const fn with_selection(mut self, selection: Selection) -> Self {
        self.selection = selection;
        self
    }

    /// Sets the seed used by [`Selection::Random`].
    #[must_use]
    pub const fn with_seed(mut self, seed: u64) -> Self {
        self.seed = seed;
        self
    }

    fn validate(&self) -> Result<()> {
        check_alpha("alpha", self.alpha)?;
        check_unit("l1_ratio", self.l1_ratio)?;
        check_alpha("tol", self.tol)?;
        if self.max_iter == 0 {
            return Err(LinearError::param("max_iter", "must be at least 1"));
        }
        Ok(())
    }

    /// Fits on `x` and `y`, starting from zero coefficients.
    pub fn fit<F: Float>(&self, x: MatrixView<'_, F>, y: &[F]) -> Result<ElasticNetModel<F>> {
        self.fit_with(x, y, None, None)
    }

    /// Fits with optional per-sample weights.
    pub fn fit_weighted<F: Float>(
        &self,
        x: MatrixView<'_, F>,
        y: &[F],
        sample_weight: Option<&[F]>,
    ) -> Result<ElasticNetModel<F>> {
        self.fit_with(x, y, sample_weight, None)
    }

    /// Warm start (sklearn `warm_start=True`): begins from `previous`'s
    /// coefficients, e.g. when walking down a grid of `alpha` values.
    pub fn fit_warm<F: Float>(
        &self,
        x: MatrixView<'_, F>,
        y: &[F],
        sample_weight: Option<&[F]>,
        previous: &ElasticNetModel<F>,
    ) -> Result<ElasticNetModel<F>> {
        self.fit_with(x, y, sample_weight, Some(previous.coef()))
    }

    fn fit_with<F: Float>(
        &self,
        x: MatrixView<'_, F>,
        y: &[F],
        sw: Option<&[F]>,
        init: Option<&[F]>,
    ) -> Result<ElasticNetModel<F>> {
        self.validate()?;
        check_regression(x, y, sw)?;
        let (n, p) = x.shape();
        let mut w = match init {
            Some(c) => {
                check_len(p, c.len()).map_err(|_| LinearError::FeatureMismatch {
                    expected: p,
                    found: c.len(),
                })?;
                if c.iter().any(|v| !v.is_finite()) {
                    return Err(LinearError::InvalidModel("non-finite warm start"));
                }
                c.to_vec()
            }
            None => vec![F::ZERO; p],
        };
        let (xm, ym) = means(x, y, sw, self.fit_intercept);
        let sq = sqrt_weights(sw, n, true);
        let cols = centered_cols(x, &xm, sq.as_deref());
        let yc = centered_target(y, ym, sq.as_deref());
        let nf = F::from_usize(n);
        let problem = Problem {
            cols: &cols,
            y: &yc,
            n,
            l1: F::from_f64(self.alpha * self.l1_ratio) * nf,
            l2: F::from_f64(self.alpha * (1.0 - self.l1_ratio)) * nf,
        };
        let mut rng = (self.selection == Selection::Random).then(|| Rng::new(self.seed));
        let out = problem.solve(&mut w, self.max_iter, F::from_f64(self.tol), rng.as_mut());
        let intercept = ym - dot(&xm, &w);
        Ok(ElasticNetModel {
            linear: LinearModel::new(w, intercept),
            n_iter: out.n_iter,
            dual_gap: out.gap / nf,
            converged: out.converged,
        })
    }
}

impl<'a, F: Float> Fit<(MatrixView<'a, F>, &'a [F])> for ElasticNet {
    type Model = ElasticNetModel<F>;
    type Error = LinearError;
    fn fit(&self, data: &(MatrixView<'a, F>, &'a [F])) -> Result<ElasticNetModel<F>> {
        Self::fit(self, data.0, data.1)
    }
}

/// A fitted [`ElasticNet`] / lasso model with its convergence report.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ElasticNetModel<F> {
    linear: LinearModel<F>,
    n_iter: usize,
    dual_gap: F,
    converged: bool,
}

impl<F: Float> ElasticNetModel<F> {
    /// Coefficients (sklearn `coef_`); exact zeros for dropped features.
    #[must_use]
    pub fn coef(&self) -> &[F] {
        self.linear.coef()
    }

    /// Intercept (sklearn `intercept_`).
    #[must_use]
    pub const fn intercept(&self) -> F {
        self.linear.intercept()
    }

    /// Sweeps performed (sklearn `n_iter_`).
    #[must_use]
    pub const fn n_iter(&self) -> usize {
        self.n_iter
    }

    /// Final duality gap, on sklearn's `1/n`-scaled objective (`dual_gap_`).
    #[must_use]
    pub const fn dual_gap(&self) -> F {
        self.dual_gap
    }

    /// `false` when `max_iter` ran out before the gap reached `tol`
    /// (where sklearn emits a `ConvergenceWarning`).
    #[must_use]
    pub const fn converged(&self) -> bool {
        self.converged
    }

    /// Indices of the non-zero coefficients.
    #[must_use]
    pub fn support(&self) -> Vec<usize> {
        self.coef()
            .iter()
            .enumerate()
            .filter_map(|(j, &c)| (c != F::ZERO).then_some(j))
            .collect()
    }

    /// The plain linear model (coefficients and intercept).
    #[must_use]
    pub const fn linear(&self) -> &LinearModel<F> {
        &self.linear
    }

    /// Predicted target for every row of `x`.
    pub fn predict(&self, x: MatrixView<'_, F>) -> Result<Vec<F>> {
        self.linear.predict(x)
    }

    /// R² of the predictions.
    pub fn score(&self, x: MatrixView<'_, F>, y: &[F]) -> Result<f64> {
        self.linear.score(x, y)
    }
}

impl<'a, F: Float> Predict<MatrixView<'a, F>> for ElasticNetModel<F> {
    type Output = Vec<F>;
    type Error = LinearError;
    fn predict(&self, x: &MatrixView<'a, F>) -> Result<Vec<F>> {
        self.linear.predict(*x)
    }
}

/// Centred, weighted problem in column-major layout, with penalties
/// already multiplied by `n` (sklearn's `cd_fast` scaling).
struct Problem<'a, F> {
    cols: &'a [F],
    y: &'a [F],
    n: usize,
    l1: F,
    l2: F,
}

struct Outcome<F> {
    n_iter: usize,
    gap: F,
    converged: bool,
}

impl<F: Float> Problem<'_, F> {
    fn col(&self, j: usize) -> &[F] {
        &self.cols[j * self.n..(j + 1) * self.n]
    }

    fn solve(&self, w: &mut [F], max_iter: usize, tol: F, mut rng: Option<&mut Rng>) -> Outcome<F> {
        let p = w.len();
        let norms: Vec<F> = (0..p).map(|j| dot(self.col(j), self.col(j))).collect();
        // Residual r = y − Xw, kept up to date after every coordinate step.
        let mut r = self.y.to_vec();
        for (j, &wj) in w.iter().enumerate() {
            if wj != F::ZERO {
                axpy(-wj, self.col(j), &mut r);
            }
        }
        let mut xta = vec![F::ZERO; p];
        let gap_tol = tol * dot(self.y, self.y);
        let mut gap = self.gap(w, &r, &mut xta);
        if gap <= gap_tol {
            return Outcome {
                n_iter: 0,
                gap,
                converged: true,
            };
        }
        for it in 0..max_iter {
            let (mut w_max, mut d_w_max) = (F::ZERO, F::ZERO);
            for step in 0..p {
                let j = rng.as_mut().map_or(step, |g| g.index(p));
                if norms[j] == F::ZERO {
                    continue;
                }
                let col = self.col(j);
                let old = w[j];
                let tmp = dot(col, &r) + old * norms[j];
                let new = soft_threshold(tmp, self.l1) / (norms[j] + self.l2);
                if new != old {
                    axpy(old - new, col, &mut r);
                }
                w[j] = new;
                d_w_max = d_w_max.max((new - old).abs());
                w_max = w_max.max(new.abs());
            }
            if w_max == F::ZERO || d_w_max / w_max <= tol || it + 1 == max_iter {
                gap = self.gap(w, &r, &mut xta);
                if gap <= gap_tol {
                    return Outcome {
                        n_iter: it + 1,
                        gap,
                        converged: true,
                    };
                }
            }
        }
        Outcome {
            n_iter: max_iter,
            gap,
            converged: false,
        }
    }

    /// Duality gap of the `n`-scaled problem (sklearn `gap_enet`).
    fn gap(&self, w: &[F], r: &[F], xta: &mut [F]) -> F {
        let half = F::from_f64(0.5);
        let r_norm2 = dot(r, r);
        let w_norm2 = if self.l2 > F::ZERO {
            dot(w, w)
        } else {
            F::ZERO
        };
        let ry = dot(r, self.y);
        for (j, v) in xta.iter_mut().enumerate() {
            *v = dot(self.col(j), r) - self.l2 * w[j];
        }
        if self.l1 == F::ZERO {
            let xtr2: F = xta
                .iter()
                .zip(w)
                .map(|(&v, &wj)| {
                    let g = v + self.l2 * wj;
                    g * g
                })
                .sum();
            if self.l2 == F::ZERO {
                return xtr2;
            }
            return r_norm2 + half * self.l2 * w_norm2 - ry + xtr2 / (F::from_f64(2.0) * self.l2);
        }
        let dual_norm = xta.iter().fold(F::ZERO, |m, v| m.max(v.abs()));
        let w_l1: F = w.iter().map(|v| v.abs()).sum();
        let primal = half * (r_norm2 + self.l2 * w_norm2) + self.l1 * w_l1;
        let scale = if dual_norm > self.l1 {
            self.l1 / dual_norm
        } else {
            F::ONE
        };
        let dual = -half * scale * scale * (r_norm2 + self.l2 * w_norm2) + scale * ry;
        primal - dual
    }
}

#[inline]
fn soft_threshold<F: Float>(v: F, t: F) -> F {
    if v > t {
        v - t
    } else if v < -t {
        v + t
    } else {
        F::ZERO
    }
}
