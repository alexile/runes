//! Stochastic gradient descent regressors and classifiers, with
//! `partial_fit` for streaming data.
//!
//! The update rule is scikit-learn's `_plain_sgd`: the same losses,
//! learning-rate schedules, lazily scaled weight vector, truncated-gradient
//! L1 penalty and stopping rule. With `shuffle = false` the coefficients
//! match scikit-learn to rounding error; with shuffling the order comes from
//! the deterministic [`Rng`] seeded by `seed`, so runs are reproducible but
//! not sample-for-sample identical to `NumPy`'s.

use rune_ml_core::kernels::dot;
use rune_ml_core::{Fit, Float, Matrix, MatrixView, Predict, Rng};

use crate::data::{
    balanced_weights, binomial_grad, check_len, check_unit, check_weights, check_x, check_y,
    encode_known, encode_labels, sigmoid,
};
use crate::error::{LinearError, Result};
use crate::linear::LinearModel;
use crate::logistic::{ClassWeight, check_shape, decision, labels_from_scores};

/// Step size schedule (sklearn `learning_rate`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum LearningRate {
    /// `eta = eta0`.
    Constant,
    /// `eta = 1 / (alpha · (t0 + t))`, Bottou's heuristic `t0`
    /// (classifier default).
    Optimal,
    /// `eta = eta0 / t^power_t` (regressor default).
    InvScaling,
    /// `eta0`, divided by 5 each time the loss stops improving.
    Adaptive,
}

/// Regularisation term (sklearn `penalty`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum SgdPenalty {
    /// No penalty.
    None,
    /// `alpha/2 ‖w‖²` (default).
    L2,
    /// `alpha ‖w‖₁` (truncated gradient).
    L1,
    /// `alpha (ρ‖w‖₁ + (1−ρ)/2 ‖w‖²)` with `ρ = l1_ratio`.
    ElasticNet,
}

/// Loss of [`SgdRegressor`] (sklearn names in brackets).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum RegressorLoss {
    /// `½(p − y)²` (`squared_error`, default).
    #[default]
    SquaredError,
    /// Quadratic within `epsilon`, linear outside (`huber`).
    Huber,
    /// `max(0, |y − p| − ε)` (`epsilon_insensitive`, linear SVR).
    EpsilonInsensitive,
    /// `max(0, |y − p| − ε)²` (`squared_epsilon_insensitive`).
    SquaredEpsilonInsensitive,
}

/// Loss of [`SgdClassifier`] (sklearn names in brackets).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum ClassifierLoss {
    /// Linear SVM, `max(0, 1 − y·p)` (`hinge`, default).
    #[default]
    Hinge,
    /// Logistic regression (`log_loss`); enables `predict_proba`.
    LogLoss,
    /// Smoothed hinge (`modified_huber`); enables `predict_proba`.
    ModifiedHuber,
    /// `max(0, 1 − y·p)²` (`squared_hinge`).
    SquaredHinge,
    /// `max(0, −y·p)` (`perceptron`).
    Perceptron,
    /// Least squares on ±1 targets (`squared_error`).
    SquaredError,
    /// Huber on ±1 targets (`huber`).
    Huber,
    /// `epsilon_insensitive` on ±1 targets.
    EpsilonInsensitive,
    /// `squared_epsilon_insensitive` on ±1 targets.
    SquaredEpsilonInsensitive,
}

#[derive(Debug, Clone, Copy)]
enum LossFn<F> {
    Hinge(F),
    Log,
    ModifiedHuber,
    SquaredHinge,
    Squared,
    Huber(F),
    EpsIns(F),
    SqEpsIns(F),
}

impl<F: Float> LossFn<F> {
    fn loss(self, y: F, p: F) -> F {
        let two = F::from_f64(2.0);
        match self {
            Self::Hinge(th) => (th - p * y).max(F::ZERO),
            Self::Log => crate::data::softplus(p) - y * p,
            Self::ModifiedHuber => {
                let z = p * y;
                if z >= F::ONE {
                    F::ZERO
                } else if z >= -F::ONE {
                    (F::ONE - z) * (F::ONE - z)
                } else {
                    -two * two * z
                }
            }
            Self::SquaredHinge => {
                let z = F::ONE - p * y;
                if z > F::ZERO { z * z } else { F::ZERO }
            }
            Self::Squared => F::from_f64(0.5) * (p - y) * (p - y),
            Self::Huber(d) => {
                let r = (y - p).abs();
                if r <= d {
                    F::from_f64(0.5) * r * r
                } else {
                    d * (r - F::from_f64(0.5) * d)
                }
            }
            Self::EpsIns(e) => ((y - p).abs() - e).max(F::ZERO),
            Self::SqEpsIns(e) => {
                let r = (y - p).abs() - e;
                if r > F::ZERO { r * r } else { F::ZERO }
            }
        }
    }

    fn dloss(self, y: F, p: F) -> F {
        let two = F::from_f64(2.0);
        match self {
            Self::Hinge(th) => {
                if p * y <= th {
                    -y
                } else {
                    F::ZERO
                }
            }
            Self::Log => binomial_grad(y, p),
            Self::ModifiedHuber => {
                let z = p * y;
                if z >= F::ONE {
                    F::ZERO
                } else if z >= -F::ONE {
                    two * (F::ONE - z) * -y
                } else {
                    -two * two * y
                }
            }
            Self::SquaredHinge => {
                let z = F::ONE - p * y;
                if z > F::ZERO { -two * y * z } else { F::ZERO }
            }
            Self::Squared => p - y,
            Self::Huber(d) => {
                let r = p - y;
                if r.abs() <= d {
                    r
                } else if r >= F::ZERO {
                    d
                } else {
                    -d
                }
            }
            Self::EpsIns(e) => {
                if y - p > e {
                    -F::ONE
                } else if p - y > e {
                    F::ONE
                } else {
                    F::ZERO
                }
            }
            Self::SqEpsIns(e) => {
                let z = y - p;
                if z > e {
                    -two * (z - e)
                } else if z < -e {
                    two * (-z - e)
                } else {
                    F::ZERO
                }
            }
        }
    }
}

/// Hyper-parameters shared by [`SgdRegressor`] and [`SgdClassifier`].
#[derive(Debug, Clone, Copy, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SgdParams {
    /// Regularisation. Default [`SgdPenalty::L2`].
    pub penalty: SgdPenalty,
    /// Penalty strength (also scales the `Optimal` schedule). Default `1e-4`.
    pub alpha: f64,
    /// L1 share for [`SgdPenalty::ElasticNet`]. Default `0.15`.
    pub l1_ratio: f64,
    /// Fit an intercept. Default `true`.
    pub fit_intercept: bool,
    /// Maximum epochs for `fit`. Default `1000`.
    pub max_iter: usize,
    /// Stop when the epoch objective has not improved by `tol` for
    /// `n_iter_no_change` epochs; `None` always runs `max_iter`.
    /// Default `Some(1e-3)`.
    pub tol: Option<f64>,
    /// Epochs without improvement before stopping. Default `5`.
    pub n_iter_no_change: usize,
    /// Shuffle samples every epoch. Default `true`.
    pub shuffle: bool,
    /// Seed of the shuffling RNG. Default `0`.
    pub seed: u64,
    /// Step size schedule.
    pub learning_rate: LearningRate,
    /// Initial step size. Default `0.01`.
    pub eta0: f64,
    /// Exponent of [`LearningRate::InvScaling`].
    pub power_t: f64,
    /// Width of the Huber / epsilon-insensitive zone. Default `0.1`.
    pub epsilon: f64,
}

impl SgdParams {
    const fn defaults(learning_rate: LearningRate, power_t: f64) -> Self {
        Self {
            penalty: SgdPenalty::L2,
            alpha: 1e-4,
            l1_ratio: 0.15,
            fit_intercept: true,
            max_iter: 1000,
            tol: Some(1e-3),
            n_iter_no_change: 5,
            shuffle: true,
            seed: 0,
            learning_rate,
            eta0: 0.01,
            power_t,
            epsilon: 0.1,
        }
    }

    fn validate(&self) -> Result<()> {
        let bad = |name, why: &str| Err(LinearError::param(name, why));
        if !(self.alpha.is_finite() && self.alpha >= 0.0) {
            return bad("alpha", "must be finite and >= 0");
        }
        if self.learning_rate == LearningRate::Optimal && self.alpha <= 0.0 {
            return bad("alpha", "must be > 0 with the optimal learning rate");
        }
        if self.learning_rate != LearningRate::Optimal
            && !(self.eta0.is_finite() && self.eta0 > 0.0)
        {
            return bad("eta0", "must be finite and > 0");
        }
        check_unit("l1_ratio", self.l1_ratio)?;
        if !self.power_t.is_finite() {
            return bad("power_t", "must be finite");
        }
        if !(self.epsilon.is_finite() && self.epsilon >= 0.0) {
            return bad("epsilon", "must be finite and >= 0");
        }
        if self.max_iter == 0 {
            return bad("max_iter", "must be at least 1");
        }
        if self.n_iter_no_change == 0 {
            return bad("n_iter_no_change", "must be at least 1");
        }
        if let Some(t) = self.tol
            && t.is_nan()
        {
            return bad("tol", "must not be NaN");
        }
        Ok(())
    }
}

macro_rules! sgd_builders {
    ($t:ty) => {
        impl $t {
            /// Sets the penalty.
            #[must_use]
            pub const fn with_penalty(mut self, penalty: SgdPenalty) -> Self {
                self.params.penalty = penalty;
                self
            }
            /// Sets `alpha`.
            #[must_use]
            pub const fn with_alpha(mut self, alpha: f64) -> Self {
                self.params.alpha = alpha;
                self
            }
            /// Sets `l1_ratio`.
            #[must_use]
            pub const fn with_l1_ratio(mut self, l1_ratio: f64) -> Self {
                self.params.l1_ratio = l1_ratio;
                self
            }
            /// Sets `fit_intercept`.
            #[must_use]
            pub const fn with_fit_intercept(mut self, fit_intercept: bool) -> Self {
                self.params.fit_intercept = fit_intercept;
                self
            }
            /// Sets `max_iter` (epochs).
            #[must_use]
            pub const fn with_max_iter(mut self, max_iter: usize) -> Self {
                self.params.max_iter = max_iter;
                self
            }
            /// Sets `tol` (`None` disables early stopping).
            #[must_use]
            pub const fn with_tol(mut self, tol: Option<f64>) -> Self {
                self.params.tol = tol;
                self
            }
            /// Sets `n_iter_no_change`.
            #[must_use]
            pub const fn with_n_iter_no_change(mut self, n: usize) -> Self {
                self.params.n_iter_no_change = n;
                self
            }
            /// Sets `shuffle`.
            #[must_use]
            pub const fn with_shuffle(mut self, shuffle: bool) -> Self {
                self.params.shuffle = shuffle;
                self
            }
            /// Sets the shuffling seed.
            #[must_use]
            pub const fn with_seed(mut self, seed: u64) -> Self {
                self.params.seed = seed;
                self
            }
            /// Sets the learning-rate schedule.
            #[must_use]
            pub const fn with_learning_rate(mut self, learning_rate: LearningRate) -> Self {
                self.params.learning_rate = learning_rate;
                self
            }
            /// Sets `eta0`.
            #[must_use]
            pub const fn with_eta0(mut self, eta0: f64) -> Self {
                self.params.eta0 = eta0;
                self
            }
            /// Sets `power_t`.
            #[must_use]
            pub const fn with_power_t(mut self, power_t: f64) -> Self {
                self.params.power_t = power_t;
                self
            }
            /// Sets `epsilon`.
            #[must_use]
            pub const fn with_epsilon(mut self, epsilon: f64) -> Self {
                self.params.epsilon = epsilon;
                self
            }
        }
    };
}

/// One binary/regression SGD problem.
struct Task<'a, F> {
    x: MatrixView<'a, F>,
    y: &'a [F],
    sw: Option<&'a [F]>,
    weight_pos: F,
    weight_neg: F,
}

/// Final state of a run.
struct Run {
    n_iter: usize,
    converged: bool,
}

/// Weight vector stored as `wscale · w`, so the L2 decay is O(1) per step.
struct Weights<'a, F> {
    w: &'a mut [F],
    scale: F,
    sq_norm: F,
    l1_norm: F,
}

impl<F: Float> Weights<'_, F> {
    fn dot(&self, x: &[F]) -> F {
        dot(self.w, x) * self.scale
    }

    fn rescale(&mut self, c: F) {
        self.scale *= c;
        self.sq_norm *= c * c;
        self.l1_norm *= c.abs();
        let threshold = if F::EPSILON.to_f64() > 1e-10 {
            1e-6
        } else {
            1e-9
        };
        if self.scale < F::from_f64(threshold) {
            self.flush();
        }
    }

    fn flush(&mut self) {
        let s = self.scale;
        for v in self.w.iter_mut() {
            *v *= s;
        }
        self.scale = F::ONE;
    }

    fn add(&mut self, x: &[F], c: F) {
        let f = c / self.scale;
        let (mut sq, mut l1) = (F::ZERO, F::ZERO);
        for (v, &xi) in self.w.iter_mut().zip(x) {
            *v += f * xi;
            sq += *v * *v;
            l1 += v.abs();
        }
        self.sq_norm = sq * self.scale * self.scale;
        self.l1_norm = l1 * self.scale;
    }

    /// Cumulative truncated-gradient L1 step (Tsuruoka et al., 2009).
    fn l1_step(&mut self, q: &mut [F], u: F) {
        let s = self.scale;
        for (v, qj) in self.w.iter_mut().zip(q.iter_mut()) {
            let z = *v;
            if s * z > F::ZERO {
                *v = (*v - (u + *qj) / s).max(F::ZERO);
            } else if s * z < F::ZERO {
                *v = (*v + (u - *qj) / s).min(F::ZERO);
            }
            *qj += s * (*v - z);
        }
    }
}

/// Runs up to `epochs` epochs of plain SGD (sklearn `_plain_sgd`).
#[allow(
    clippy::too_many_lines,
    clippy::cognitive_complexity,
    reason = "one loop mirroring the reference implementation step by step"
)]
fn plain_sgd<F: Float>(
    params: &SgdParams,
    loss: LossFn<F>,
    task: &Task<'_, F>,
    coef: &mut [F],
    intercept: &mut F,
    t_start: f64,
    epochs: usize,
    rng: &mut Rng,
) -> Result<Run> {
    let n = task.x.nrows();
    let alpha = F::from_f64(params.alpha);
    let l1_ratio = F::from_f64(match params.penalty {
        SgdPenalty::L2 | SgdPenalty::None => 0.0,
        SgdPenalty::L1 => 1.0,
        SgdPenalty::ElasticNet => params.l1_ratio,
    });
    let decay = matches!(params.penalty, SgdPenalty::L2 | SgdPenalty::ElasticNet);
    let truncate = matches!(params.penalty, SgdPenalty::L1 | SgdPenalty::ElasticNet);
    let penalised = params.penalty != SgdPenalty::None;
    let mut q = if truncate {
        vec![F::ZERO; coef.len()]
    } else {
        Vec::new()
    };
    let mut u = F::ZERO;
    let mut w = Weights {
        sq_norm: dot(coef, coef),
        l1_norm: coef.iter().map(|v| v.abs()).sum(),
        w: coef,
        scale: F::ONE,
    };
    let eta0 = F::from_f64(params.eta0);
    let power_t = F::from_f64(params.power_t);
    let mut eta = eta0;
    let optimal_init = if params.learning_rate == LearningRate::Optimal {
        let typw = F::ONE / alpha.sqrt().sqrt();
        let initial = typw / F::ONE.max(loss.dloss(F::ONE, -typw));
        F::ONE / (initial * alpha)
    } else {
        F::ZERO
    };
    let max_dloss = F::from_f64(1e12);
    let half = F::from_f64(0.5);
    let tol = params.tol.map(F::from_f64);
    let mut best = F::INFINITY;
    let mut no_improvement = 0;
    let mut t = F::from_f64(t_start);
    let mut order: Vec<usize> = (0..n).collect();
    let nf = F::from_usize(n);
    for epoch in 0..epochs {
        if params.shuffle {
            rng.shuffle(&mut order);
        }
        let mut objective = F::ZERO;
        for &i in &order {
            let xi = task.x.row(i);
            let yi = task.y[i];
            let p = w.dot(xi) + *intercept;
            match params.learning_rate {
                LearningRate::Optimal => eta = F::ONE / (alpha * (optimal_init + t - F::ONE)),
                LearningRate::InvScaling => eta = eta0 / t.powf(power_t),
                LearningRate::Constant | LearningRate::Adaptive => {}
            }
            objective += loss.loss(yi, p);
            if penalised {
                objective +=
                    alpha * ((F::ONE - l1_ratio) * half * w.sq_norm + l1_ratio * w.l1_norm);
            }
            let class_weight = if yi > F::ZERO {
                task.weight_pos
            } else {
                task.weight_neg
            };
            let dloss = loss.dloss(yi, p).max(-max_dloss).min(max_dloss);
            let sample_weight = task.sw.map_or(F::ONE, |s| s[i]);
            let update = -eta * dloss * class_weight * sample_weight;
            if decay {
                w.rescale(F::ZERO.max(F::ONE - (F::ONE - l1_ratio) * eta * alpha));
            }
            if update != F::ZERO {
                w.add(xi, update);
            }
            if params.fit_intercept && update != F::ZERO {
                *intercept += update;
            }
            if truncate {
                u += l1_ratio * eta * alpha;
                w.l1_step(&mut q, u);
            }
            t += F::ONE;
        }
        if !intercept.is_finite() || w.w.iter().any(|v| !v.is_finite()) {
            return Err(LinearError::Diverged { epoch: epoch + 1 });
        }
        if let Some(tol) = tol {
            let obj = objective / nf;
            if obj > best - tol {
                no_improvement += 1;
            } else {
                no_improvement = 0;
            }
            if obj < best {
                best = obj;
            }
        }
        if no_improvement >= params.n_iter_no_change {
            if params.learning_rate == LearningRate::Adaptive && eta > F::from_f64(1e-6) {
                eta /= F::from_f64(5.0);
                no_improvement = 0;
            } else {
                w.flush();
                return Ok(Run {
                    n_iter: epoch + 1,
                    converged: true,
                });
            }
        }
    }
    w.flush();
    Ok(Run {
        n_iter: epochs,
        converged: tol.is_none(),
    })
}

/// Linear regression fitted by SGD (sklearn `SGDRegressor`).
///
/// ```
/// use rune_linear_model::{LearningRate, SgdPenalty, SgdRegressor};
/// use rune_ml_core::Matrix;
///
/// let rows: Vec<[f64; 1]> = (0..50).map(|i| [f64::from(i) / 50.0]).collect();
/// let y: Vec<f64> = rows.iter().map(|r| 3.0 * r[0] - 1.0).collect();
/// let x = Matrix::from_rows(&rows)?;
/// let model = SgdRegressor::new()
///     .with_penalty(SgdPenalty::None)
///     .with_learning_rate(LearningRate::Constant)
///     .with_eta0(0.1)
///     .with_tol(None)
///     .with_max_iter(500)
///     .fit(x.view(), &y)?;
/// assert!((model.coef()[0] - 3.0).abs() < 1e-3);
/// assert!((model.intercept() + 1.0).abs() < 1e-3);
/// # Ok::<(), rune_linear_model::LinearError>(())
/// ```
#[derive(Debug, Clone, Copy, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SgdRegressor {
    /// Loss function. Default [`RegressorLoss::SquaredError`].
    pub loss: RegressorLoss,
    /// Shared hyper-parameters (sklearn defaults: inverse-scaling rate with
    /// `eta0 = 0.01`, `power_t = 0.25`).
    pub params: SgdParams,
}

sgd_builders!(SgdRegressor);

impl Default for SgdRegressor {
    fn default() -> Self {
        Self::new()
    }
}

impl SgdRegressor {
    /// sklearn defaults.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            loss: RegressorLoss::SquaredError,
            params: SgdParams::defaults(LearningRate::InvScaling, 0.25),
        }
    }

    /// Sets the loss.
    #[must_use]
    pub const fn with_loss(mut self, loss: RegressorLoss) -> Self {
        self.loss = loss;
        self
    }

    fn loss_fn<F: Float>(&self) -> LossFn<F> {
        let e = F::from_f64(self.params.epsilon);
        match self.loss {
            RegressorLoss::SquaredError => LossFn::Squared,
            RegressorLoss::Huber => LossFn::Huber(e),
            RegressorLoss::EpsilonInsensitive => LossFn::EpsIns(e),
            RegressorLoss::SquaredEpsilonInsensitive => LossFn::SqEpsIns(e),
        }
    }

    /// Fits from zero weights for up to `max_iter` epochs.
    pub fn fit<F: Float>(&self, x: MatrixView<'_, F>, y: &[F]) -> Result<SgdRegressorModel<F>> {
        self.fit_weighted(x, y, None)
    }

    /// Fits with optional per-sample weights.
    pub fn fit_weighted<F: Float>(
        &self,
        x: MatrixView<'_, F>,
        y: &[F],
        sample_weight: Option<&[F]>,
    ) -> Result<SgdRegressorModel<F>> {
        let mut model = self.empty(x.ncols());
        model.train(x, y, sample_weight, self.params.max_iter)?;
        Ok(model)
    }

    /// Starts a streaming model with one epoch over the first batch
    /// (sklearn `partial_fit`). Continue with
    /// [`SgdRegressorModel::partial_fit`].
    pub fn partial_fit<F: Float>(
        &self,
        x: MatrixView<'_, F>,
        y: &[F],
        sample_weight: Option<&[F]>,
    ) -> Result<SgdRegressorModel<F>> {
        let mut model = self.empty(x.ncols());
        model.train(x, y, sample_weight, 1)?;
        Ok(model)
    }

    fn empty<F: Float>(&self, p: usize) -> SgdRegressorModel<F> {
        SgdRegressorModel {
            config: *self,
            linear: LinearModel::new(vec![F::ZERO; p], F::ZERO),
            t: 1.0,
            n_iter: 0,
            converged: false,
            rng: Rng::new(self.params.seed),
        }
    }
}

impl<'a, F: Float> Fit<(MatrixView<'a, F>, &'a [F])> for SgdRegressor {
    type Model = SgdRegressorModel<F>;
    type Error = LinearError;
    fn fit(&self, data: &(MatrixView<'a, F>, &'a [F])) -> Result<SgdRegressorModel<F>> {
        Self::fit(self, data.0, data.1)
    }
}

/// A fitted [`SgdRegressor`]; can keep learning with
/// [`partial_fit`](Self::partial_fit).
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SgdRegressorModel<F> {
    config: SgdRegressor,
    linear: LinearModel<F>,
    t: f64,
    n_iter: usize,
    converged: bool,
    rng: Rng,
}

impl<F: Float> SgdRegressorModel<F> {
    fn train(
        &mut self,
        x: MatrixView<'_, F>,
        y: &[F],
        sw: Option<&[F]>,
        epochs: usize,
    ) -> Result<()> {
        self.config.params.validate()?;
        check_x(x)?;
        check_y(y, x.nrows())?;
        check_weights(sw, x.nrows())?;
        if x.ncols() != self.linear.coef.len() {
            return Err(LinearError::FeatureMismatch {
                expected: self.linear.coef.len(),
                found: x.ncols(),
            });
        }
        let task = Task {
            x,
            y,
            sw,
            weight_pos: F::ONE,
            weight_neg: F::ONE,
        };
        let mut coef = self.linear.coef.clone();
        let mut intercept = self.linear.intercept;
        let run = plain_sgd(
            &self.config.params,
            self.config.loss_fn(),
            &task,
            &mut coef,
            &mut intercept,
            self.t,
            epochs,
            &mut self.rng,
        )?;
        self.linear = LinearModel::new(coef, intercept);
        self.t += (run.n_iter * x.nrows()) as f64;
        self.n_iter = run.n_iter;
        self.converged = run.converged;
        Ok(())
    }

    /// One more epoch over a new batch (sklearn `partial_fit`).
    pub fn partial_fit(
        &mut self,
        x: MatrixView<'_, F>,
        y: &[F],
        sample_weight: Option<&[F]>,
    ) -> Result<()> {
        self.train(x, y, sample_weight, 1)
    }

    /// Coefficients (sklearn `coef_`).
    #[must_use]
    pub fn coef(&self) -> &[F] {
        self.linear.coef()
    }

    /// Intercept (sklearn `intercept_`).
    #[must_use]
    pub const fn intercept(&self) -> F {
        self.linear.intercept()
    }

    /// Epochs run by the last `fit` / `partial_fit` (sklearn `n_iter_`).
    #[must_use]
    pub const fn n_iter(&self) -> usize {
        self.n_iter
    }

    /// Samples seen plus one (sklearn `t_`).
    #[must_use]
    pub const fn t(&self) -> f64 {
        self.t
    }

    /// `false` when `max_iter` ran out before the stopping rule fired.
    #[must_use]
    pub const fn converged(&self) -> bool {
        self.converged
    }

    /// The plain linear model.
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

impl<'a, F: Float> Predict<MatrixView<'a, F>> for SgdRegressorModel<F> {
    type Output = Vec<F>;
    type Error = LinearError;
    fn predict(&self, x: &MatrixView<'a, F>) -> Result<Vec<F>> {
        self.linear.predict(*x)
    }
}

/// Linear classifier fitted by SGD (sklearn `SGDClassifier`):
/// a linear SVM by default, logistic regression with
/// [`ClassifierLoss::LogLoss`]. More than two classes are handled
/// one-vs-rest, like sklearn.
///
/// ```
/// use rune_linear_model::{ClassifierLoss, SgdClassifier};
/// use rune_ml_core::Matrix;
///
/// let x = Matrix::from_rows(&[[-2.0, -1.0], [-1.0, -1.0], [1.0, 1.0], [2.0, 1.0]])?;
/// let y = [0, 0, 1, 1];
/// let model = SgdClassifier::new().with_loss(ClassifierLoss::LogLoss).fit(x.view(), &y)?;
/// assert_eq!(model.predict(x.view())?, y);
/// let proba = model.predict_proba(x.view())?;
/// assert!(proba[(3, 1)] > 0.5);
/// # Ok::<(), rune_linear_model::LinearError>(())
/// ```
#[derive(Debug, Clone, Copy, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SgdClassifier {
    /// Loss function. Default [`ClassifierLoss::Hinge`].
    pub loss: ClassifierLoss,
    /// Shared hyper-parameters (sklearn defaults: optimal rate).
    pub params: SgdParams,
    /// Class weighting (not allowed with `partial_fit`).
    pub class_weight: ClassWeight,
}

sgd_builders!(SgdClassifier);

impl Default for SgdClassifier {
    fn default() -> Self {
        Self::new()
    }
}

impl SgdClassifier {
    /// sklearn defaults.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            loss: ClassifierLoss::Hinge,
            params: SgdParams::defaults(LearningRate::Optimal, 0.5),
            class_weight: ClassWeight::Uniform,
        }
    }

    /// Sets the loss.
    #[must_use]
    pub const fn with_loss(mut self, loss: ClassifierLoss) -> Self {
        self.loss = loss;
        self
    }

    /// Sets the class weighting.
    #[must_use]
    pub const fn with_class_weight(mut self, class_weight: ClassWeight) -> Self {
        self.class_weight = class_weight;
        self
    }

    fn loss_fn<F: Float>(&self) -> LossFn<F> {
        let e = F::from_f64(self.params.epsilon);
        match self.loss {
            ClassifierLoss::Hinge => LossFn::Hinge(F::ONE),
            ClassifierLoss::Perceptron => LossFn::Hinge(F::ZERO),
            ClassifierLoss::LogLoss => LossFn::Log,
            ClassifierLoss::ModifiedHuber => LossFn::ModifiedHuber,
            ClassifierLoss::SquaredHinge => LossFn::SquaredHinge,
            ClassifierLoss::SquaredError => LossFn::Squared,
            ClassifierLoss::Huber => LossFn::Huber(e),
            ClassifierLoss::EpsilonInsensitive => LossFn::EpsIns(e),
            ClassifierLoss::SquaredEpsilonInsensitive => LossFn::SqEpsIns(e),
        }
    }

    /// Fits from zero weights for up to `max_iter` epochs.
    pub fn fit<F: Float, L: Ord + Clone>(
        &self,
        x: MatrixView<'_, F>,
        y: &[L],
    ) -> Result<SgdClassifierModel<F, L>> {
        self.fit_weighted(x, y, None)
    }

    /// Fits with optional per-sample weights.
    pub fn fit_weighted<F: Float, L: Ord + Clone>(
        &self,
        x: MatrixView<'_, F>,
        y: &[L],
        sample_weight: Option<&[F]>,
    ) -> Result<SgdClassifierModel<F, L>> {
        check_len(x.nrows(), y.len())?;
        let (classes, codes) = encode_labels(y);
        if classes.len() < 2 {
            return Err(LinearError::TooFewClasses {
                found: classes.len(),
            });
        }
        let class_weights = match self.class_weight {
            ClassWeight::Uniform => vec![F::ONE; classes.len()],
            ClassWeight::Balanced => balanced_weights(&codes, classes.len(), None::<&[F]>),
        };
        let mut model = self.empty(classes, class_weights, x.ncols())?;
        model.train(x, &codes, sample_weight, self.params.max_iter)?;
        Ok(model)
    }

    /// Starts a streaming model (sklearn `partial_fit`): `classes` lists
    /// every label the stream can contain; runs one epoch over the batch.
    pub fn partial_fit<F: Float, L: Ord + Clone>(
        &self,
        x: MatrixView<'_, F>,
        y: &[L],
        classes: &[L],
        sample_weight: Option<&[F]>,
    ) -> Result<SgdClassifierModel<F, L>> {
        if self.class_weight == ClassWeight::Balanced {
            return Err(LinearError::param(
                "class_weight",
                "balanced weights need the full data; use fit or per-sample weights",
            ));
        }
        let (classes, _) = encode_labels(classes);
        if classes.len() < 2 {
            return Err(LinearError::TooFewClasses {
                found: classes.len(),
            });
        }
        let k = classes.len();
        let mut model = self.empty(classes, vec![F::ONE; k], x.ncols())?;
        model.partial_fit(x, y, sample_weight)?;
        Ok(model)
    }

    fn empty<F: Float, L>(
        &self,
        classes: Vec<L>,
        class_weights: Vec<F>,
        p: usize,
    ) -> Result<SgdClassifierModel<F, L>> {
        let rows = if classes.len() == 2 { 1 } else { classes.len() };
        Ok(SgdClassifierModel {
            config: *self,
            classes,
            class_weights,
            coef: Matrix::zeros(rows, p)?,
            intercept: vec![F::ZERO; rows],
            t: 1.0,
            n_iter: 0,
            converged: false,
            rng: Rng::new(self.params.seed),
        })
    }
}

impl<'a, F: Float, L: Ord + Clone> Fit<(MatrixView<'a, F>, &'a [L])> for SgdClassifier {
    type Model = SgdClassifierModel<F, L>;
    type Error = LinearError;
    fn fit(&self, data: &(MatrixView<'a, F>, &'a [L])) -> Result<SgdClassifierModel<F, L>> {
        Self::fit(self, data.0, data.1)
    }
}

/// A fitted [`SgdClassifier`]; can keep learning with
/// [`partial_fit`](Self::partial_fit).
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SgdClassifierModel<F, L> {
    config: SgdClassifier,
    classes: Vec<L>,
    class_weights: Vec<F>,
    coef: Matrix<F>,
    intercept: Vec<F>,
    t: f64,
    n_iter: usize,
    converged: bool,
    rng: Rng,
}

impl<F: Float, L: Ord + Clone> SgdClassifierModel<F, L> {
    fn train(
        &mut self,
        x: MatrixView<'_, F>,
        codes: &[usize],
        sw: Option<&[F]>,
        epochs: usize,
    ) -> Result<()> {
        self.config.params.validate()?;
        check_shape(&self.classes, &self.coef, &self.intercept)?;
        check_x(x)?;
        check_len(x.nrows(), codes.len())?;
        check_weights(sw, x.nrows())?;
        if x.ncols() != self.coef.ncols() || self.class_weights.len() != self.classes.len() {
            return Err(LinearError::FeatureMismatch {
                expected: self.coef.ncols(),
                found: x.ncols(),
            });
        }
        let loss = self.config.loss_fn::<F>();
        let negative = if matches!(loss, LossFn::Log) {
            F::ZERO
        } else {
            -F::ONE
        };
        let rows = self.coef.nrows();
        let mut coef = self.coef.clone();
        let mut intercept = self.intercept.clone();
        let mut target = vec![F::ZERO; x.nrows()];
        let mut n_iter = 0;
        let mut converged = true;
        for k in 0..rows {
            // Binary: one problem for classes[1]; otherwise one per class.
            let positive = if rows == 1 { 1 } else { k };
            for (t, &c) in target.iter_mut().zip(codes) {
                *t = if c == positive { F::ONE } else { negative };
            }
            let (weight_pos, weight_neg) = if rows == 1 {
                (self.class_weights[1], self.class_weights[0])
            } else {
                (self.class_weights[k], F::ONE)
            };
            let task = Task {
                x,
                y: &target,
                sw,
                weight_pos,
                weight_neg,
            };
            let mut rng = if rows == 1 {
                self.rng.clone()
            } else {
                self.rng.fork()
            };
            let run = plain_sgd(
                &self.config.params,
                loss,
                &task,
                coef.row_mut(k),
                &mut intercept[k],
                self.t,
                epochs,
                &mut rng,
            )?;
            if rows == 1 {
                self.rng = rng;
            }
            n_iter = n_iter.max(run.n_iter);
            converged &= run.converged;
        }
        self.coef = coef;
        self.intercept = intercept;
        self.t += (n_iter * x.nrows()) as f64;
        self.n_iter = n_iter;
        self.converged = converged;
        Ok(())
    }

    /// One more epoch over a new batch; labels must be among `classes()`.
    pub fn partial_fit(
        &mut self,
        x: MatrixView<'_, F>,
        y: &[L],
        sample_weight: Option<&[F]>,
    ) -> Result<()> {
        check_len(x.nrows(), y.len())?;
        let codes = encode_known(&self.classes, y)?;
        self.train(x, &codes, sample_weight, 1)
    }

    /// Sorted class labels (sklearn `classes_`).
    #[must_use]
    pub fn classes(&self) -> &[L] {
        &self.classes
    }

    /// Coefficients: one row (binary) or one per class (sklearn `coef_`).
    #[must_use]
    pub const fn coef(&self) -> &Matrix<F> {
        &self.coef
    }

    /// Intercepts, one per row of [`coef`](Self::coef).
    #[must_use]
    pub fn intercept(&self) -> &[F] {
        &self.intercept
    }

    /// Epochs run by the last `fit` / `partial_fit` (max over classes).
    #[must_use]
    pub const fn n_iter(&self) -> usize {
        self.n_iter
    }

    /// Samples seen plus one (sklearn `t_`).
    #[must_use]
    pub const fn t(&self) -> f64 {
        self.t
    }

    /// `false` when `max_iter` ran out before the stopping rule fired.
    #[must_use]
    pub const fn converged(&self) -> bool {
        self.converged
    }

    /// Signed distances to the hyperplanes: `n × 1` (binary) or
    /// `n × n_classes`.
    pub fn decision_function(&self, x: MatrixView<'_, F>) -> Result<Matrix<F>> {
        check_shape(&self.classes, &self.coef, &self.intercept)?;
        decision(&self.coef, &self.intercept, x)
    }

    /// Predicted class for every row.
    pub fn predict(&self, x: MatrixView<'_, F>) -> Result<Vec<L>> {
        Ok(labels_from_scores(
            &self.decision_function(x)?,
            &self.classes,
        ))
    }

    /// Class probabilities for [`ClassifierLoss::LogLoss`] and
    /// [`ClassifierLoss::ModifiedHuber`] (one-vs-rest scores normalised,
    /// like sklearn). Other losses return an error.
    pub fn predict_proba(&self, x: MatrixView<'_, F>) -> Result<Matrix<F>> {
        let link: fn(F) -> F = match self.config.loss {
            ClassifierLoss::LogLoss => sigmoid,
            ClassifierLoss::ModifiedHuber => {
                |s: F| (s.max(-F::ONE).min(F::ONE) + F::ONE) / F::from_f64(2.0)
            }
            _ => {
                return Err(LinearError::param(
                    "loss",
                    "predict_proba needs LogLoss or ModifiedHuber",
                ));
            }
        };
        let scores = self.decision_function(x)?;
        let k = self.classes.len();
        let mut out = Matrix::zeros(scores.nrows(), k)?;
        for (o, s) in out.rows_mut().zip(scores.rows()) {
            if s.len() == 1 {
                let p = link(s[0]);
                o[0] = F::ONE - p;
                o[1] = p;
                continue;
            }
            let mut sum = F::ZERO;
            for (v, &si) in o.iter_mut().zip(s) {
                *v = link(si);
                sum += *v;
            }
            let uniform = F::ONE / F::from_usize(k);
            for v in o.iter_mut() {
                *v = if sum > F::ZERO { *v / sum } else { uniform };
            }
        }
        Ok(out)
    }

    /// Mean accuracy on `(x, y)`.
    pub fn score(&self, x: MatrixView<'_, F>, y: &[L]) -> Result<f64> {
        let pred = self.predict(x)?;
        Ok(rune_ml_metrics::accuracy_score(y, &pred)?)
    }

    /// Number of features the model expects.
    #[must_use]
    pub const fn n_features(&self) -> usize {
        self.coef.ncols()
    }
}

impl<'a, F: Float, L: Ord + Clone> Predict<MatrixView<'a, F>> for SgdClassifierModel<F, L> {
    type Output = Vec<L>;
    type Error = LinearError;
    fn predict(&self, x: &MatrixView<'a, F>) -> Result<Vec<L>> {
        Self::predict(self, *x)
    }
}
