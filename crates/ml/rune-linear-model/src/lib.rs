//! Linear models for regression and classification: the runes take on
//! `sklearn.linear_model`.
//!
//! | Estimator | Model | sklearn | Solver |
//! |-----------|-------|---------|--------|
//! | [`LinearRegression`] | [`LinearModel`] | `LinearRegression` | Householder QR |
//! | [`Ridge`] | [`LinearModel`] | `Ridge` | Cholesky, primal or dual |
//! | [`ElasticNet`], [`ElasticNet::lasso`] | [`ElasticNetModel`] | `ElasticNet`, `Lasso` | Coordinate descent |
//! | [`LogisticRegression`] | [`LogisticModel`] | `LogisticRegression` | L-BFGS (L2), FISTA (L1 / elastic net) |
//! | [`SgdRegressor`] | [`SgdRegressorModel`] | `SGDRegressor` | Plain SGD, `partial_fit` |
//! | [`SgdClassifier`] | [`SgdClassifierModel`] | `SGDClassifier` | Plain SGD, one-vs-rest, `partial_fit` |
//!
//! Estimators are plain configuration structs (hyper-parameters as `f64`);
//! `fit` borrows the data and returns a separate fitted model. Everything is
//! generic over `f32` / `f64` through [`Float`]. Inputs are
//! [`MatrixView`]s (row-major, one sample per row); targets are `&[F]`
//! for regressors and any `Ord + Clone` label for classifiers.
//!
//! Hyper-parameters, objectives and defaults follow scikit-learn, and the
//! tests pin coefficients computed with scikit-learn 1.9. Iterative solvers
//! never print warnings: each model reports `n_iter()` and `converged()`.
//!
//! # Example
//!
//! ```
//! use rune_linear_model::{ElasticNet, LinearRegression, LogisticRegression, Ridge};
//! use rune_ml_core::Matrix;
//!
//! let x = Matrix::from_rows(&[[1.0, 0.5], [2.0, 1.0], [3.0, 0.0], [4.0, 2.0], [5.0, 1.5]])?;
//! let y = [3.1, 5.0, 6.8, 9.2, 11.1];
//!
//! let ols = LinearRegression::new().fit(x.view(), &y)?;
//! let ridge = Ridge::new(0.5).fit(x.view(), &y)?;
//! let lasso = ElasticNet::lasso(0.1).fit(x.view(), &y)?;
//! assert!(ols.score(x.view(), &y)? > 0.99);
//! assert!(ridge.coef()[0] < ols.coef()[0]);
//! assert!(lasso.converged());
//!
//! let labels = ["low", "low", "low", "high", "high"];
//! let clf = LogisticRegression::new().fit(x.view(), &labels)?;
//! let proba = clf.predict_proba(x.view())?; // columns: ["high", "low"]
//! assert!(proba[(4, 0)] > 0.5);
//! # Ok::<(), rune_linear_model::LinearError>(())
//! ```
//!
//! # Features
//!
//! * `serde` — `Serialize` / `Deserialize` for estimators and fitted
//!   models. A deserialized model with inconsistent parts is rejected at
//!   prediction time with [`LinearError::InvalidModel`] or
//!   [`LinearError::FeatureMismatch`], never a panic.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![allow(
    clippy::many_single_char_names,
    clippy::similar_names,
    clippy::suboptimal_flops,
    clippy::cast_precision_loss,
    clippy::too_many_arguments,
    clippy::needless_range_loop,
    reason = "numerical code: textbook names (x, y, w, p, n), formulas written as in the papers"
)]

mod cd;
mod data;
mod error;
mod linear;
mod logistic;
mod optim;
mod sgd;

pub use cd::{ElasticNet, ElasticNetModel, Selection};
pub use error::{LinearError, Result};
pub use linear::{LinearModel, LinearRegression, Ridge, RidgeSolver};
pub use logistic::{ClassWeight, LogisticModel, LogisticRegression};
pub use rune_ml_core::{Float, Matrix, MatrixView};
pub use sgd::{
    ClassifierLoss, LearningRate, RegressorLoss, SgdClassifier, SgdClassifierModel, SgdParams,
    SgdPenalty, SgdRegressor, SgdRegressorModel,
};

/// Compiles and runs the README examples.
#[cfg(doctest)]
#[doc = include_str!("../README.md")]
struct ReadmeDoctests;
