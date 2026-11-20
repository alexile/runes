//! Ordinary least squares and ridge regression (closed form).

use rune_ml_core::kernels::{axpy, dot};
use rune_ml_core::{Fit, Float, Matrix, MatrixView, Predict, linalg};

use crate::data::{
    centered_rows, centered_target, check_alpha, check_predict, check_weights, check_x, check_y,
    linear_predict, means, sqrt_weights,
};
use crate::error::{LinearError, Result, map_singular};

/// A fitted linear regressor: `y = x · coef + intercept`.
///
/// Returned by [`LinearRegression`], [`Ridge`] and (inside
/// [`ElasticNetModel`](crate::ElasticNetModel)) the coordinate descent
/// models.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct LinearModel<F> {
    pub(crate) coef: Vec<F>,
    pub(crate) intercept: F,
}

impl<F: Float> LinearModel<F> {
    /// Builds a model from known coefficients.
    #[must_use]
    pub const fn new(coef: Vec<F>, intercept: F) -> Self {
        Self { coef, intercept }
    }

    /// Coefficients, one per feature (sklearn `coef_`).
    #[must_use]
    pub fn coef(&self) -> &[F] {
        &self.coef
    }

    /// Intercept (sklearn `intercept_`); `0` when not fitted.
    #[must_use]
    pub const fn intercept(&self) -> F {
        self.intercept
    }

    /// Number of features the model expects.
    #[must_use]
    pub const fn n_features(&self) -> usize {
        self.coef.len()
    }

    /// Predicted target for every row of `x`.
    pub fn predict(&self, x: MatrixView<'_, F>) -> Result<Vec<F>> {
        check_predict(x, self.coef.len())?;
        Ok(linear_predict(x, &self.coef, self.intercept))
    }

    /// Coefficient of determination R² of the predictions (sklearn `score`).
    pub fn score(&self, x: MatrixView<'_, F>, y: &[F]) -> Result<f64> {
        let pred = self.predict(x)?;
        Ok(rune_ml_metrics::r2_score(y, &pred)?)
    }
}

impl<'a, F: Float> Predict<MatrixView<'a, F>> for LinearModel<F> {
    type Output = Vec<F>;
    type Error = LinearError;
    fn predict(&self, x: &MatrixView<'a, F>) -> Result<Vec<F>> {
        Self::predict(self, *x)
    }
}

/// Validates `(x, y, sample_weight)` for a regressor.
pub fn check_regression<F: Float>(x: MatrixView<'_, F>, y: &[F], sw: Option<&[F]>) -> Result<()> {
    check_x(x)?;
    check_y(y, x.nrows())?;
    check_weights(sw, x.nrows())
}

fn finish<F: Float>(coef: Vec<F>, xm: &[F], ym: F) -> LinearModel<F> {
    let intercept = ym - dot(xm, &coef);
    LinearModel { coef, intercept }
}

/// Ordinary least squares (sklearn `LinearRegression`).
///
/// Solves `min Σ wᵢ (yᵢ − xᵢ·β − b)²` with a Householder QR of the centred
/// data, which is more accurate than the normal equations. Collinear or
/// constant features, or fewer samples than features, give
/// [`LinearError::Singular`] rather than an arbitrary solution; use
/// [`Ridge`] for those.
///
/// ```
/// use rune_linear_model::LinearRegression;
/// use rune_ml_core::Matrix;
///
/// let x = Matrix::from_rows(&[[1.0_f64, 1.0], [1.0, 2.0], [2.0, 2.0], [2.0, 3.0]])?;
/// let y = [6.0, 8.0, 9.0, 11.0]; // 1·x0 + 2·x1 + 3
/// let model = LinearRegression::new().fit(x.view(), &y)?;
/// assert!((model.coef()[0] - 1.0).abs() < 1e-12);
/// assert!((model.coef()[1] - 2.0).abs() < 1e-12);
/// assert!((model.intercept() - 3.0).abs() < 1e-12);
/// # Ok::<(), rune_linear_model::LinearError>(())
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct LinearRegression {
    /// Fit an intercept (centre the data first). Default `true`.
    pub fit_intercept: bool,
}

impl Default for LinearRegression {
    fn default() -> Self {
        Self::new()
    }
}

impl LinearRegression {
    /// Defaults: `fit_intercept = true`.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            fit_intercept: true,
        }
    }

    /// Sets `fit_intercept`.
    #[must_use]
    pub const fn with_fit_intercept(mut self, fit_intercept: bool) -> Self {
        self.fit_intercept = fit_intercept;
        self
    }

    /// Fits on `x` (`n × p`) and `y` (`n`).
    pub fn fit<F: Float>(&self, x: MatrixView<'_, F>, y: &[F]) -> Result<LinearModel<F>> {
        self.fit_weighted(x, y, None)
    }

    /// Fits with optional per-sample weights.
    pub fn fit_weighted<F: Float>(
        &self,
        x: MatrixView<'_, F>,
        y: &[F],
        sample_weight: Option<&[F]>,
    ) -> Result<LinearModel<F>> {
        check_regression(x, y, sample_weight)?;
        let (xm, ym) = means(x, y, sample_weight, self.fit_intercept);
        let sq = sqrt_weights(sample_weight, x.nrows(), false);
        let mut a = centered_rows(x, &xm, sq.as_deref());
        let mut b = centered_target(y, ym, sq.as_deref());
        let coef = linalg::lstsq(&mut a, &mut b).map_err(map_singular)?;
        Ok(finish(coef, &xm, ym))
    }
}

impl<'a, F: Float> Fit<(MatrixView<'a, F>, &'a [F])> for LinearRegression {
    type Model = LinearModel<F>;
    type Error = LinearError;
    fn fit(&self, data: &(MatrixView<'a, F>, &'a [F])) -> Result<LinearModel<F>> {
        Self::fit(self, data.0, data.1)
    }
}

/// How [`Ridge`] solves its normal equations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub enum RidgeSolver {
    /// Primal when `n_features <= n_samples`, dual otherwise.
    #[default]
    Auto,
    /// Cholesky of `XᵀX + αI` (`p × p`).
    Primal,
    /// Cholesky of the kernel `XXᵀ + αI` (`n × n`); cheaper when
    /// `n_features > n_samples` (sklearn's kernel ridge path).
    Dual,
}

/// L2-penalised least squares (sklearn `Ridge`).
///
/// Minimises `Σ wᵢ (yᵢ − xᵢ·β − b)² + α‖β‖²`. The intercept is not
/// penalised. Solved in closed form with a Cholesky factorisation of
/// either the `p × p` Gram matrix or, when there are more features than
/// samples, the `n × n` kernel matrix, so memory stays at
/// `min(n, p)²`.
///
/// ```
/// use rune_linear_model::Ridge;
/// use rune_ml_core::Matrix;
///
/// let x = Matrix::from_rows(&[[0.0_f64, 0.0], [0.0, 0.0], [1.0, 1.0]])?;
/// let model = Ridge::new(1.0).fit(x.view(), &[0.0, 0.1, 1.0])?;
/// // sklearn: coef_ = [0.27142857, 0.27142857], intercept_ = 0.18571429
/// assert!((model.coef()[0] - 0.271_428_571).abs() < 1e-8);
/// assert!((model.intercept() - 0.185_714_286).abs() < 1e-8);
/// # Ok::<(), rune_linear_model::LinearError>(())
/// ```
#[derive(Debug, Clone, Copy, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Ridge {
    /// Regularisation strength `α >= 0`. Default `1.0`.
    pub alpha: f64,
    /// Fit an intercept. Default `true`.
    pub fit_intercept: bool,
    /// Solver choice. Default [`RidgeSolver::Auto`].
    pub solver: RidgeSolver,
}

impl Default for Ridge {
    fn default() -> Self {
        Self::new(1.0)
    }
}

impl Ridge {
    /// Ridge with the given `alpha`.
    #[must_use]
    pub const fn new(alpha: f64) -> Self {
        Self {
            alpha,
            fit_intercept: true,
            solver: RidgeSolver::Auto,
        }
    }

    /// Sets `fit_intercept`.
    #[must_use]
    pub const fn with_fit_intercept(mut self, fit_intercept: bool) -> Self {
        self.fit_intercept = fit_intercept;
        self
    }

    /// Sets the solver.
    #[must_use]
    pub const fn with_solver(mut self, solver: RidgeSolver) -> Self {
        self.solver = solver;
        self
    }

    /// Fits on `x` and `y`.
    pub fn fit<F: Float>(&self, x: MatrixView<'_, F>, y: &[F]) -> Result<LinearModel<F>> {
        self.fit_weighted(x, y, None)
    }

    /// Fits with optional per-sample weights.
    pub fn fit_weighted<F: Float>(
        &self,
        x: MatrixView<'_, F>,
        y: &[F],
        sample_weight: Option<&[F]>,
    ) -> Result<LinearModel<F>> {
        check_alpha("alpha", self.alpha)?;
        check_regression(x, y, sample_weight)?;
        let (n, p) = x.shape();
        let (xm, ym) = means(x, y, sample_weight, self.fit_intercept);
        let sq = sqrt_weights(sample_weight, n, false);
        let a = centered_rows(x, &xm, sq.as_deref());
        let b = centered_target(y, ym, sq.as_deref());
        let alpha = F::from_f64(self.alpha);
        let dual = match self.solver {
            RidgeSolver::Auto => p > n,
            RidgeSolver::Primal => false,
            RidgeSolver::Dual => true,
        };
        let coef = if dual {
            solve_dual(&a, &b, alpha)?
        } else {
            solve_primal(&a, &b, alpha)?
        };
        Ok(finish(coef, &xm, ym))
    }
}

impl<'a, F: Float> Fit<(MatrixView<'a, F>, &'a [F])> for Ridge {
    type Model = LinearModel<F>;
    type Error = LinearError;
    fn fit(&self, data: &(MatrixView<'a, F>, &'a [F])) -> Result<LinearModel<F>> {
        Self::fit(self, data.0, data.1)
    }
}

/// `(AᵀA + αI) β = Aᵀb`, accumulating the lower triangle row by row.
fn solve_primal<F: Float>(a: &Matrix<F>, b: &[F], alpha: F) -> Result<Vec<F>> {
    let p = a.ncols();
    let mut g = Matrix::zeros(p, p)?;
    let mut rhs = vec![F::ZERO; p];
    for (row, &bi) in a.rows().zip(b) {
        for (j, &rj) in row.iter().enumerate() {
            if rj != F::ZERO {
                axpy(rj, &row[..=j], &mut g.row_mut(j)[..=j]);
            }
        }
        axpy(bi, row, &mut rhs);
    }
    for j in 0..p {
        g[(j, j)] += alpha;
    }
    linalg::cholesky(&mut g).map_err(map_singular)?;
    linalg::cholesky_solve(&g, &mut rhs)?;
    Ok(rhs)
}

/// `β = Aᵀ (AAᵀ + αI)⁻¹ b`.
fn solve_dual<F: Float>(a: &Matrix<F>, b: &[F], alpha: F) -> Result<Vec<F>> {
    let n = a.nrows();
    let mut k = Matrix::zeros(n, n)?;
    for i in 0..n {
        let ri = a.row(i);
        for j in 0..=i {
            k[(i, j)] = dot(ri, a.row(j));
        }
        k[(i, i)] += alpha;
    }
    linalg::cholesky(&mut k).map_err(map_singular)?;
    let mut dual = b.to_vec();
    linalg::cholesky_solve(&k, &mut dual)?;
    let mut coef = vec![F::ZERO; a.ncols()];
    for (row, &d) in a.rows().zip(&dual) {
        axpy(d, row, &mut coef);
    }
    Ok(coef)
}
