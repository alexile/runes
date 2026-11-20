# rune-linear-model

> Linear models — OLS, ridge, lasso, elastic net, logistic regression and SGD, matching scikit-learn

[![crates.io](https://img.shields.io/crates/v/rune-linear-model)](https://crates.io/crates/rune-linear-model)
[![docs.rs](https://img.shields.io/docsrs/rune-linear-model)](https://docs.rs/rune-linear-model)
[![license](https://img.shields.io/crates/l/rune-linear-model)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

## What it does

The `sklearn.linear_model` toolbox for Rust. Same objectives, same
hyper-parameter names and defaults, same answers: the tests pin
coefficients, intercepts and probabilities computed with scikit-learn 1.9,
and the SGD estimators follow scikit-learn's update rule step for step.

- **Regression:** ordinary least squares (Householder QR), ridge (Cholesky,
  primal or dual), lasso and elastic net (coordinate descent with the
  duality-gap stopping rule, warm starts), `SgdRegressor`.
- **Classification:** logistic regression (binary or multinomial, L2 by
  L-BFGS, L1 / elastic net by FISTA, `predict_proba`, `decision_function`,
  balanced class weights), `SgdClassifier` (hinge, log, modified Huber, ...,
  one-vs-rest, `predict_proba`).
- **Streaming:** `partial_fit` on both SGD models.
- **Everywhere:** `f32` or `f64`, per-sample weights, labels of any `Ord`
  type, errors instead of panics or `NaN` coefficients.

## Installation

```toml
[dependencies]
rune-linear-model = "0.1"
rune-ml-core = "0.1"
```

Optional features:

- `serde` — serialize estimators and fitted models (including the streaming
  state of the SGD models).

## Quickstart

```rust
use rune_linear_model::{ElasticNet, LinearRegression, LogisticRegression, Ridge};
use rune_ml_core::Matrix;

// One sample per row.
let x = Matrix::from_rows(&[[1.0, 0.5], [2.0, 1.0], [3.0, 0.0], [4.0, 2.0], [5.0, 1.5]])?;
let y = [3.1, 5.0, 6.8, 9.2, 11.1];

let ols = LinearRegression::new().fit(x.view(), &y)?;
println!("coef = {:?}, intercept = {}", ols.coef(), ols.intercept());

let ridge = Ridge::new(0.5).fit(x.view(), &y)?;
let lasso = ElasticNet::lasso(0.1).fit(x.view(), &y)?;
assert!(lasso.converged()); // no warnings printed: check the flag
let r2 = ridge.score(x.view(), &y)?;
assert!(r2 > 0.95);

// Classifiers take any Ord + Clone labels; classes are sorted.
let labels = ["low", "low", "low", "high", "high"];
let clf = LogisticRegression::new().with_c(10.0).fit(x.view(), &labels)?;
assert_eq!(clf.classes(), ["high", "low"]);
let proba = clf.predict_proba(x.view())?; // n × 2, columns in classes() order
assert!(proba[(4, 0)] > 0.5);
assert_eq!(clf.predict(x.view())?, labels);
# Ok::<(), rune_linear_model::LinearError>(())
```

Streaming with `partial_fit`:

```rust
use rune_linear_model::{ClassifierLoss, SgdClassifier};
use rune_ml_core::Matrix;

let batch1 = Matrix::from_rows(&[[-2.0, -1.0], [2.0, 1.0]])?;
let batch2 = Matrix::from_rows(&[[-1.0, -1.5], [1.5, 2.0]])?;

let est = SgdClassifier::new().with_loss(ClassifierLoss::LogLoss).with_seed(7);
// The first call names every class the stream can contain.
let mut model = est.partial_fit(batch1.view(), &[0, 1], &[0, 1], None)?;
for _ in 0..10 {
    model.partial_fit(batch2.view(), &[0, 1], None)?;
    model.partial_fit(batch1.view(), &[0, 1], None)?;
}
assert_eq!(model.predict(batch2.view())?, [0, 1]);
# Ok::<(), rune_linear_model::LinearError>(())
```

## scikit-learn mapping

| scikit-learn | rune-linear-model |
|--------------|-------------------|
| `LinearRegression(fit_intercept=...)` | `LinearRegression::new().with_fit_intercept(..)` |
| `Ridge(alpha=a)` | `Ridge::new(a)`; `.with_solver(RidgeSolver::Primal / Dual)` |
| `Lasso(alpha=a)` | `ElasticNet::lasso(a)` |
| `ElasticNet(alpha=a, l1_ratio=r)` | `ElasticNet::new(a, r)` |
| `tol`, `max_iter`, `selection="random"`, `random_state` | `.with_tol`, `.with_max_iter`, `.with_selection(Selection::Random)`, `.with_seed` |
| `warm_start=True` | `est.fit_warm(x, y, None, &previous_model)` |
| `LogisticRegression(C=c, l1_ratio=r)` | `LogisticRegression::new().with_c(c).with_l1_ratio(r)` |
| `C=np.inf` (no penalty) | `.with_c(f64::INFINITY)` |
| `class_weight="balanced"` | `.with_class_weight(ClassWeight::Balanced)` |
| `SGDRegressor(loss=..., penalty=..., learning_rate=...)` | `SgdRegressor::new().with_loss(RegressorLoss::..).with_penalty(SgdPenalty::..).with_learning_rate(LearningRate::..)` |
| `SGDClassifier(loss="hinge" / "log_loss" / "modified_huber" / ...)` | `SgdClassifier::new().with_loss(ClassifierLoss::Hinge / LogLoss / ModifiedHuber / ..)` |
| `tol=None` | `.with_tol(None)` |
| `fit(X, y, sample_weight=w)` | `fit_weighted(x, y, Some(&w))` |
| `partial_fit(X, y, classes=c)` | `est.partial_fit(x, y, &c, None)`, then `model.partial_fit(x, y, None)` |
| `predict`, `predict_proba`, `decision_function`, `score` | same names on the fitted model |
| `coef_`, `intercept_`, `classes_`, `n_iter_`, `dual_gap_`, `t_` | `coef()`, `intercept()`, `classes()`, `n_iter()`, `dual_gap()`, `t()` |
| `ConvergenceWarning` | `model.converged() == false` |

`coef()` of a classifier is a `Matrix` with one row for a binary problem
(for `classes()[1]`) and one row per class otherwise, exactly like `coef_`.

## Conventions

- **Objectives.** Lasso / elastic net minimise
  `1/(2n)‖y − Xβ‖² + α·ρ‖β‖₁ + α(1 − ρ)/2‖β‖²`; with sample weights the loss
  is `1/(2Σw) Σ wᵢrᵢ²`. Logistic regression minimises
  `C·Σ wᵢℓᵢ + (1 − ρ)/2‖W‖² + ρ‖W‖₁`. Intercepts are never penalised.
- **Errors.** Empty input, mismatched lengths, `NaN`/`inf` in `x`, `y` or the
  weights, negative weights, values whose squares overflow, unknown labels at
  `partial_fit` and invalid hyper-parameters are errors. `LinearRegression`
  on collinear or constant features returns `LinearError::Singular` instead
  of a minimum-norm solution: use `Ridge` there. SGD overflow is
  `LinearError::Diverged`.
- **Convergence.** Iterative models expose `n_iter()` and `converged()`;
  nothing is printed.
- **Determinism.** Same input, same seed, same output. SGD shuffling and
  random coordinate selection use `rune_ml_core::Rng`. With
  `shuffle = false` SGD matches scikit-learn to rounding error; with
  shuffling the order differs from NumPy's.
- **Not covered (yet).** Multi-output targets, sparse input, `LassoCV` /
  path helpers, `averaged` SGD, passive-aggressive and one-class SGD.

## Performance

- Coordinate descent works on a column-major copy of the centred data and
  keeps the residual up to date after every coordinate step, so a sweep is
  `O(n·p)` with contiguous dot products and no allocation.
- Ridge forms the `p × p` Gram matrix (or the `n × n` kernel when
  `p > n`) with row-wise rank-1 updates; memory is `min(n, p)²`.
- L-BFGS and FISTA allocate their history and work vectors once; each
  objective evaluation is one row-major pass over `x`.
- SGD uses a lazily scaled weight vector (L2 decay is O(1) per step) and
  scikit-learn's cumulative L1 truncation.

## License

MIT
