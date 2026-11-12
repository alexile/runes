//! Principal component analysis (PCA): exact and randomized solvers, whitening
//! and inverse transform.
//!
//! PCA finds the orthonormal directions (principal components) along which
//! centred data varies most. Projecting onto the first `k` components gives the
//! best rank-`k` linear approximation of the data in the least-squares sense.
//!
//! Three solvers are available, selected with [`Solver`]:
//!
//! - [`Solver::Covariance`]: eigendecomposition of the `d × d` covariance
//!   matrix (Householder tridiagonalisation + implicit QL). Fast when there are
//!   many more samples than features.
//! - [`Solver::Svd`]: one-sided Jacobi SVD of the centred data matrix. Slower but
//!   numerically the most accurate, since it never forms `XᵀX`.
//! - [`Solver::Randomized`]: the randomized range finder with power iterations of
//!   Halko, Martinsson & Tropp, *Finding structure with randomness* (SIAM Review
//!   53(2), 2011), Algorithms 4.4 and 5.1. Computes only the leading `k`
//!   components, in `O(n·d·k)` time.
//!
//! [`Solver::Auto`] (the default) picks randomized SVD for large inputs where a
//! few components are requested, and an exact solver otherwise, as scikit-learn
//! does.
//!
//! Component signs are fixed deterministically (the largest-magnitude loading of
//! every component is positive), so all solvers agree on the output and results
//! are reproducible across runs and thread counts.
//!
//! # Example
//!
//! ```
//! use rune_pca::Pca;
//!
//! // The example from scikit-learn's `PCA` documentation.
//! let x = vec![
//!     vec![-1.0, -1.0], vec![-2.0, -1.0], vec![-3.0, -2.0],
//!     vec![1.0, 1.0], vec![2.0, 1.0], vec![3.0, 2.0],
//! ];
//! let model = Pca::new(2).fit(&x)?;
//! let ratio = model.explained_variance_ratio();
//! assert!((ratio[0] - 0.992_443).abs() < 1e-6);
//! assert!((model.singular_values()[0] - 6.300_612).abs() < 1e-6);
//!
//! // Project, then map back: with every component kept the round trip is exact.
//! let projected = model.transform(&x)?;
//! let restored = model.inverse_transform(&projected)?;
//! assert!((restored[2][0] - x[2][0]).abs() < 1e-12);
//!
//! // Keep as many components as needed to explain 99.9% of the variance.
//! let reduced = Pca::with_variance_ratio(0.999).fit(&x)?;
//! assert_eq!(reduced.n_components(), 2);
//! # Ok::<(), rune_pca::PcaError>(())
//! ```
//!
//! # Features
//!
//! - `serde`: `Serialize`/`Deserialize` for [`Pca`], [`PcaModel`], [`Solver`] and
//!   [`Components`], so fitted models can be stored and reloaded.
//! - `cli`: the `rune-pca` command-line tool.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod linalg;
mod rng;

use linalg::NoConvergence;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Above this many samples or features, [`Solver::Auto`] considers the
/// randomized solver.
const AUTO_RANDOMIZED_MIN_SIZE: usize = 500;

/// Errors returned when fitting or applying a PCA model.
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
#[non_exhaustive]
pub enum PcaError {
    /// Fewer than two samples were supplied (the variance is undefined).
    #[error("PCA requires at least 2 samples, got {n}")]
    TooFewSamples {
        /// Number of samples supplied.
        n: usize,
    },
    /// The samples have no features.
    #[error("samples have no features")]
    NoFeatures,
    /// A row has a different number of features from the first row (when
    /// fitting) or from the model (when transforming).
    #[error("row {index} has {found} values, expected {expected}")]
    DimensionMismatch {
        /// Index of the offending row.
        index: usize,
        /// Expected number of values.
        expected: usize,
        /// Number of values found.
        found: usize,
    },
    /// A row contains a NaN or infinite value.
    #[error("row {index} has a non-finite value")]
    NonFiniteInput {
        /// Index of the offending row.
        index: usize,
    },
    /// The requested number of components is zero or exceeds
    /// `min(n_samples, n_features)`.
    #[error("n_components must be in 1..={max}, got {requested}")]
    InvalidComponents {
        /// The requested number of components.
        requested: usize,
        /// The largest valid value, `min(n_samples, n_features)`.
        max: usize,
    },
    /// The explained-variance target is not in `(0, 1]`.
    #[error("variance ratio must be in (0, 1], got {0}")]
    InvalidVarianceRatio(f64),
    /// [`Components::VarianceRatio`] needs the full spectrum, which
    /// [`Solver::Randomized`] does not compute.
    #[error("selecting components by variance ratio requires an exact solver")]
    RandomizedNeedsCount,
    /// The data is too large in magnitude: its variance overflows `f64`.
    #[error("data magnitude overflows f64 arithmetic")]
    NumericalOverflow,
    /// An iterative decomposition failed to converge.
    #[error("the {0} decomposition did not converge")]
    NoConvergence(&'static str),
    /// A (deserialized) model is internally inconsistent.
    #[error("inconsistent PCA model: {0}")]
    InvalidModel(&'static str),
}

/// The algorithm used to compute the principal components.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[non_exhaustive]
pub enum Solver {
    /// Randomized SVD when `max(n, d) > 500` and fewer than 80% of
    /// `min(n, d)` components are requested by count; otherwise
    /// [`Solver::Covariance`] when `n ≥ d` and [`Solver::Svd`] when `n < d`.
    #[default]
    Auto,
    /// Eigendecomposition of the covariance matrix. `O(n·d² + d³)`.
    Covariance,
    /// One-sided Jacobi SVD of the centred data. `O(n·d·min(n, d))` per sweep.
    Svd,
    /// Randomized SVD (Halko et al. 2011). Approximate, `O(n·d·k)`.
    Randomized,
}

/// How many components to keep.
#[derive(Debug, Clone, Copy, PartialEq, Default)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[non_exhaustive]
pub enum Components {
    /// Exactly this many components, in `1..=min(n_samples, n_features)`.
    Count(usize),
    /// The fewest components whose cumulative explained-variance ratio reaches
    /// this fraction, in `(0, 1]`. Requires an exact solver.
    VarianceRatio(f64),
    /// All `min(n_samples, n_features)` components.
    #[default]
    All,
}

/// PCA configuration. Build with [`Pca::new`] (or [`Pca::default`] for all
/// components), adjust with the `with_*` methods, then call [`Pca::fit`].
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[non_exhaustive]
pub struct Pca {
    /// How many components to keep.
    pub components: Components,
    /// Which solver to use.
    pub solver: Solver,
    /// Whether [`PcaModel::transform`] scales outputs to unit variance.
    pub whiten: bool,
    /// Extra random directions sampled by the randomized solver.
    pub n_oversamples: usize,
    /// Power iterations of the randomized solver; `None` picks 7 when fewer
    /// than 10% of `min(n, d)` components are requested and 4 otherwise.
    pub n_power_iter: Option<usize>,
    /// Seed for the randomized solver's test matrix.
    pub random_seed: u64,
}

impl Default for Pca {
    fn default() -> Self {
        Self {
            components: Components::All,
            solver: Solver::Auto,
            whiten: false,
            n_oversamples: 10,
            n_power_iter: None,
            random_seed: 0,
        }
    }
}

impl Pca {
    /// PCA keeping `n_components` components, with every other setting at
    /// its default (automatic solver, no whitening).
    #[must_use]
    pub fn new(n_components: usize) -> Self {
        Self::default().with_components(Components::Count(n_components))
    }

    /// PCA keeping the fewest components that explain at least `ratio` of
    /// the variance (see [`Components::VarianceRatio`]).
    #[must_use]
    pub fn with_variance_ratio(ratio: f64) -> Self {
        Self::default().with_components(Components::VarianceRatio(ratio))
    }

    /// Sets [`Pca::components`].
    #[must_use]
    pub const fn with_components(mut self, components: Components) -> Self {
        self.components = components;
        self
    }

    /// Sets [`Pca::solver`].
    #[must_use]
    pub const fn with_solver(mut self, solver: Solver) -> Self {
        self.solver = solver;
        self
    }

    /// Sets [`Pca::whiten`]: when `true`, projected components are divided by
    /// the square root of their explained variance, so each has unit variance.
    #[must_use]
    pub const fn with_whiten(mut self, whiten: bool) -> Self {
        self.whiten = whiten;
        self
    }

    /// Sets [`Pca::n_oversamples`] (default 10).
    #[must_use]
    pub const fn with_oversamples(mut self, n: usize) -> Self {
        self.n_oversamples = n;
        self
    }

    /// Sets [`Pca::n_power_iter`].
    #[must_use]
    pub const fn with_power_iterations(mut self, n: usize) -> Self {
        self.n_power_iter = Some(n);
        self
    }

    /// Sets [`Pca::random_seed`] (default 0).
    #[must_use]
    pub const fn with_seed(mut self, seed: u64) -> Self {
        self.random_seed = seed;
        self
    }

    /// Fits the model to `data`, one row per sample.
    ///
    /// # Errors
    ///
    /// [`PcaError::TooFewSamples`], [`PcaError::NoFeatures`],
    /// [`PcaError::DimensionMismatch`] and [`PcaError::NonFiniteInput`] for
    /// invalid data; [`PcaError::InvalidComponents`],
    /// [`PcaError::InvalidVarianceRatio`] and [`PcaError::RandomizedNeedsCount`]
    /// for an invalid configuration; [`PcaError::NumericalOverflow`] and
    /// [`PcaError::NoConvergence`] for data the solvers cannot handle.
    #[allow(
        clippy::cast_precision_loss,
        reason = "sample counts stay far below 2^52, so the f64 conversion is exact"
    )]
    pub fn fit(&self, data: &[Vec<f64>]) -> Result<PcaModel, PcaError> {
        let n = data.len();
        if n < 2 {
            return Err(PcaError::TooFewSamples { n });
        }
        let d = data[0].len();
        if d == 0 {
            return Err(PcaError::NoFeatures);
        }
        validate_rows(data, d)?;
        let max_k = n.min(d);

        let k_requested = match self.components {
            Components::Count(k) => {
                if k == 0 || k > max_k {
                    return Err(PcaError::InvalidComponents {
                        requested: k,
                        max: max_k,
                    });
                }
                Some(k)
            }
            Components::VarianceRatio(r) => {
                if !(r > 0.0 && r <= 1.0) {
                    return Err(PcaError::InvalidVarianceRatio(r));
                }
                None
            }
            Components::All => Some(max_k),
        };
        let solver = match (self.solver, k_requested) {
            (Solver::Randomized, None) => return Err(PcaError::RandomizedNeedsCount),
            (Solver::Auto, Some(k))
                if n.max(d) > AUTO_RANDOMIZED_MIN_SIZE && (k as f64) < 0.8 * max_k as f64 =>
            {
                Solver::Randomized
            }
            (Solver::Auto, _) if n >= d => Solver::Covariance,
            (Solver::Auto, _) => Solver::Svd,
            (s, _) => s,
        };

        // Centre, then scale to unit max-magnitude so the solvers never
        // overflow or underflow; variances are scaled back at the end.
        let nf = n as f64;
        let mut mean = vec![0.0; d];
        for row in data {
            for (m, &x) in mean.iter_mut().zip(row) {
                *m += x / nf;
            }
        }
        let mut centred: Vec<Vec<f64>> = data
            .iter()
            .map(|row| row.iter().zip(&mean).map(|(x, m)| x - m).collect())
            .collect();
        let scale = centred
            .iter()
            .flatten()
            .fold(0.0f64, |acc, x| acc.max(x.abs()));
        if !scale.is_finite() || mean.iter().any(|m| !m.is_finite()) {
            return Err(PcaError::NumericalOverflow);
        }
        let scale = if scale > 0.0 { scale } else { 1.0 };
        centred.iter_mut().flatten().for_each(|x| *x /= scale);
        let total_var_s: f64 = centred.iter().flatten().map(|x| x * x).sum::<f64>() / (nf - 1.0);

        let (mut sigma_s, mut comps) = match solver {
            Solver::Randomized => {
                let k = k_requested.unwrap_or(max_k);
                self.randomized(&centred, d, k, max_k)?
            }
            Solver::Svd => exact_svd(&centred, n, d)?,
            _ => exact_covariance(&centred, d)?,
        };
        let keep = sigma_s.len().min(max_k);
        sigma_s.truncate(keep);
        comps.truncate(keep);
        finish_basis(&sigma_s, &mut comps);

        let ev_s: Vec<f64> = sigma_s.iter().map(|s| s * s / (nf - 1.0)).collect();
        let ratio: Vec<f64> = ev_s
            .iter()
            .map(|v| {
                if total_var_s > 0.0 {
                    v / total_var_s
                } else {
                    0.0
                }
            })
            .collect();
        let k = k_requested.unwrap_or_else(|| {
            let target = match self.components {
                Components::VarianceRatio(r) => r,
                _ => 1.0,
            };
            let mut cum = 0.0;
            ratio
                .iter()
                .position(|r| {
                    cum += r;
                    cum >= target * (1.0 - 1e-12)
                })
                .map_or(keep, |i| i + 1)
        });
        let k = k.min(keep).max(1);

        let scale_sq = scale * scale;
        let explained_variance: Vec<f64> = ev_s[..k].iter().map(|v| v * scale_sq).collect();
        let total_var = total_var_s * scale_sq;
        if !total_var.is_finite() || explained_variance.iter().any(|v| !v.is_finite()) {
            return Err(PcaError::NumericalOverflow);
        }
        let noise_variance = if k < max_k {
            let rest = (total_var_s - ev_s[..k].iter().sum::<f64>()).max(0.0);
            rest / (max_k - k) as f64 * scale_sq
        } else {
            0.0
        };
        comps.truncate(k);

        Ok(PcaModel {
            mean,
            components: comps,
            explained_variance,
            explained_variance_ratio: ratio[..k].to_vec(),
            singular_values: sigma_s[..k].iter().map(|s| s * scale).collect(),
            noise_variance,
            n_samples: n,
            whiten: self.whiten,
            solver,
        })
    }

    /// Fits the model and returns it together with the projected `data`.
    ///
    /// # Errors
    ///
    /// As [`Pca::fit`].
    pub fn fit_transform(&self, data: &[Vec<f64>]) -> Result<(PcaModel, Vec<Vec<f64>>), PcaError> {
        let model = self.fit(data)?;
        let projected = model.transform(data)?;
        Ok((model, projected))
    }

    /// Randomized SVD of the (centred, scaled) data: Halko et al. 2011,
    /// Algorithm 4.4 (randomized subspace iteration) + Algorithm 5.1.
    #[allow(
        clippy::cast_precision_loss,
        reason = "component counts stay far below 2^52"
    )]
    #[allow(
        clippy::many_single_char_names,
        reason = "matrix names follow Halko et al. (A, Ω, Y, Q, B)"
    )]
    fn randomized(
        &self,
        a: &[Vec<f64>],
        d: usize,
        k: usize,
        max_k: usize,
    ) -> Result<(Vec<f64>, Vec<Vec<f64>>), PcaError> {
        let l = k.saturating_add(self.n_oversamples).min(max_k);
        let power = self
            .n_power_iter
            .unwrap_or(if (k as f64) < 0.1 * max_k as f64 {
                7
            } else {
                4
            });
        let mut rng = rng::Rng::new(self.random_seed);
        let omega: Vec<Vec<f64>> = (0..l)
            .map(|_| (0..d).map(|_| rng.next_gaussian()).collect())
            .collect();
        let mut y = linalg::mul_cols(a, &omega);
        for _ in 0..power {
            linalg::orthonormalize(&mut y);
            let mut z = linalg::mul_t_cols(a, &y, d);
            linalg::orthonormalize(&mut z);
            y = linalg::mul_cols(a, &z);
        }
        linalg::orthonormalize(&mut y);
        // Rows of B = Qᵀ·A, i.e. Aᵀ·q for every column q of Q.
        let mut b_rows = linalg::mul_t_cols(a, &y, d);
        linalg::one_sided_jacobi(&mut b_rows, false)
            .map_err(|NoConvergence| PcaError::NoConvergence("randomized SVD"))?;
        let (sigma, comps) = sorted_from_columns(b_rows);
        Ok((sigma, comps))
    }
}

/// Checks every row has `d` finite values.
fn validate_rows(data: &[Vec<f64>], d: usize) -> Result<(), PcaError> {
    for (index, row) in data.iter().enumerate() {
        if row.len() != d {
            return Err(PcaError::DimensionMismatch {
                index,
                expected: d,
                found: row.len(),
            });
        }
        if !row.iter().all(|x| x.is_finite()) {
            return Err(PcaError::NonFiniteInput { index });
        }
    }
    Ok(())
}

/// Transposes `n × d` rows into `d` columns of length `n`.
fn columns(a: &[Vec<f64>], d: usize) -> Vec<Vec<f64>> {
    (0..d)
        .map(|j| a.iter().map(|row| row[j]).collect())
        .collect()
}

/// Exact PCA via eigendecomposition of `AᵀA`.
fn exact_covariance(a: &[Vec<f64>], d: usize) -> Result<(Vec<f64>, Vec<Vec<f64>>), PcaError> {
    let g = linalg::gram(&columns(a, d));
    let (values, vectors) = linalg::symmetric_eigen(g)
        .map_err(|NoConvergence| PcaError::NoConvergence("covariance eigen"))?;
    let sigma = values.iter().map(|v| v.max(0.0).sqrt()).collect();
    Ok((sigma, vectors))
}

/// Exact PCA via one-sided Jacobi SVD of `A` (or `Aᵀ` when it is wide).
fn exact_svd(a: &[Vec<f64>], n: usize, d: usize) -> Result<(Vec<f64>, Vec<Vec<f64>>), PcaError> {
    let err = |NoConvergence| PcaError::NoConvergence("SVD");
    if n >= d {
        let mut cols = columns(a, d);
        let w = linalg::one_sided_jacobi(&mut cols, true)
            .map_err(err)?
            .unwrap_or_default();
        let sigma: Vec<f64> = cols.iter().map(|c| linalg::norm(c)).collect();
        let mut order: Vec<usize> = (0..d).collect();
        order.sort_by(|&x, &y| sigma[y].total_cmp(&sigma[x]).then(x.cmp(&y)));
        Ok((
            order.iter().map(|&i| sigma[i]).collect(),
            order.iter().map(|&i| w[i].clone()).collect(),
        ))
    } else {
        let mut rows = a.to_vec();
        linalg::one_sided_jacobi(&mut rows, false).map_err(err)?;
        Ok(sorted_from_columns(rows))
    }
}

/// Given orthogonal vectors, returns their norms (descending) and unit
/// directions. Zero vectors are kept as-is for [`finish_basis`] to replace.
fn sorted_from_columns(cols: Vec<Vec<f64>>) -> (Vec<f64>, Vec<Vec<f64>>) {
    let mut pairs: Vec<(f64, Vec<f64>)> = cols
        .into_iter()
        .map(|mut c| {
            let s = linalg::norm(&c);
            if s > 0.0 {
                for x in &mut c {
                    *x /= s;
                }
            }
            (s, c)
        })
        .collect();
    pairs.sort_by(|a, b| b.0.total_cmp(&a.0));
    pairs.into_iter().unzip()
}

/// Makes the components an orthonormal set (replacing directions of
/// numerically null singular values) and fixes their signs so the
/// largest-magnitude loading is positive.
fn finish_basis(sigma: &[f64], comps: &mut [Vec<f64>]) {
    let top = sigma.first().copied().unwrap_or(0.0);
    let first_null = sigma
        .iter()
        .position(|&s| s <= top * 1e-13 || s == 0.0)
        .unwrap_or(sigma.len());
    linalg::complete_orthonormal(comps, first_null);
    for c in comps.iter_mut() {
        let pivot = c
            .iter()
            .enumerate()
            .fold((0, 0.0f64), |best, (i, &x)| {
                if x.abs() > best.1 { (i, x.abs()) } else { best }
            })
            .0;
        if c.get(pivot).is_some_and(|&x| x < 0.0) {
            for x in c.iter_mut() {
                *x = -*x;
            }
        }
    }
}

/// A fitted PCA model.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct PcaModel {
    mean: Vec<f64>,
    components: Vec<Vec<f64>>,
    explained_variance: Vec<f64>,
    explained_variance_ratio: Vec<f64>,
    singular_values: Vec<f64>,
    noise_variance: f64,
    n_samples: usize,
    whiten: bool,
    solver: Solver,
}

impl PcaModel {
    /// Number of components kept.
    #[must_use]
    pub const fn n_components(&self) -> usize {
        self.components.len()
    }

    /// Number of features of the training data.
    #[must_use]
    pub const fn n_features(&self) -> usize {
        self.mean.len()
    }

    /// Number of samples of the training data.
    #[must_use]
    pub const fn n_samples(&self) -> usize {
        self.n_samples
    }

    /// Per-feature mean of the training data.
    #[must_use]
    pub fn mean(&self) -> &[f64] {
        &self.mean
    }

    /// Principal axes, one unit vector per component, ordered by decreasing
    /// explained variance.
    #[must_use]
    pub fn components(&self) -> &[Vec<f64>] {
        &self.components
    }

    /// Variance explained by each component (sample variance, `n − 1`
    /// denominator).
    #[must_use]
    pub fn explained_variance(&self) -> &[f64] {
        &self.explained_variance
    }

    /// Fraction of the total variance explained by each component.
    #[must_use]
    pub fn explained_variance_ratio(&self) -> &[f64] {
        &self.explained_variance_ratio
    }

    /// Singular values of the centred data for each component.
    #[must_use]
    pub fn singular_values(&self) -> &[f64] {
        &self.singular_values
    }

    /// Average variance of the discarded components (the noise variance of
    /// probabilistic PCA); `0` when every component is kept.
    #[must_use]
    pub const fn noise_variance(&self) -> f64 {
        self.noise_variance
    }

    /// Whether [`PcaModel::transform`] whitens its output.
    #[must_use]
    pub const fn whiten(&self) -> bool {
        self.whiten
    }

    /// The solver that produced the model ([`Solver::Auto`] resolved).
    #[must_use]
    pub const fn solver(&self) -> Solver {
        self.solver
    }

    /// Projects `data` onto the principal components.
    ///
    /// # Errors
    ///
    /// [`PcaError::DimensionMismatch`] or [`PcaError::NonFiniteInput`] for a
    /// bad row, [`PcaError::InvalidModel`] for an inconsistent (deserialized)
    /// model.
    pub fn transform(&self, data: &[Vec<f64>]) -> Result<Vec<Vec<f64>>, PcaError> {
        self.check()?;
        validate_rows(data, self.n_features())?;
        Ok(data
            .iter()
            .map(|row| {
                let centred: Vec<f64> = row.iter().zip(&self.mean).map(|(x, m)| x - m).collect();
                self.components
                    .iter()
                    .zip(&self.explained_variance)
                    .map(|(c, &ev)| {
                        let y = linalg::dot(c, &centred);
                        if self.whiten {
                            whiten_scale(ev).map_or(0.0, |s| y / s)
                        } else {
                            y
                        }
                    })
                    .collect()
            })
            .collect())
    }

    /// Maps projected `data` (as returned by [`PcaModel::transform`]) back to
    /// the original feature space. Exact when every component is kept; the
    /// best rank-`k` approximation otherwise.
    ///
    /// # Errors
    ///
    /// [`PcaError::DimensionMismatch`] if a row does not have
    /// [`PcaModel::n_components`] values, [`PcaError::NonFiniteInput`] for a
    /// non-finite value, [`PcaError::InvalidModel`] for an inconsistent model.
    pub fn inverse_transform(&self, data: &[Vec<f64>]) -> Result<Vec<Vec<f64>>, PcaError> {
        self.check()?;
        validate_rows(data, self.n_components())?;
        Ok(data
            .iter()
            .map(|row| {
                let mut out = self.mean.clone();
                for ((&y, c), &ev) in row
                    .iter()
                    .zip(&self.components)
                    .zip(&self.explained_variance)
                {
                    let y = if self.whiten {
                        whiten_scale(ev).map_or(0.0, |s| y * s)
                    } else {
                        y
                    };
                    for (o, &cv) in out.iter_mut().zip(c) {
                        *o = y.mul_add(cv, *o);
                    }
                }
                out
            })
            .collect())
    }

    /// Validates internal consistency (relevant for deserialized models).
    fn check(&self) -> Result<(), PcaError> {
        let d = self.mean.len();
        let k = self.components.len();
        if d == 0 || k == 0 {
            return Err(PcaError::InvalidModel("no features or no components"));
        }
        if self.components.iter().any(|c| c.len() != d) {
            return Err(PcaError::InvalidModel("component length differs from mean"));
        }
        if self.explained_variance.len() != k {
            return Err(PcaError::InvalidModel(
                "explained variance length differs from component count",
            ));
        }
        Ok(())
    }
}

/// Standard deviation used to whiten a component, `None` for a null one.
fn whiten_scale(ev: f64) -> Option<f64> {
    let s = ev.sqrt();
    (s > 0.0 && s.is_finite()).then_some(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identical_rows_give_zero_variance_and_orthonormal_axes() {
        let x = vec![vec![1.0, 2.0, 3.0]; 4];
        let m = Pca::default().fit(&x).unwrap();
        assert_eq!(m.n_components(), 3);
        assert!(m.explained_variance().iter().all(|&v| v == 0.0));
        assert!(m.explained_variance_ratio().iter().all(|&v| v == 0.0));
        for i in 0..3 {
            for j in 0..3 {
                let want = if i == j { 1.0 } else { 0.0 };
                let got = linalg::dot(&m.components()[i], &m.components()[j]);
                assert!((got - want).abs() < 1e-12);
            }
        }
    }

    #[test]
    fn auto_solver_resolution() {
        let small = vec![vec![1.0, 2.0], vec![2.0, 1.0], vec![0.0, 0.5]];
        assert_eq!(
            Pca::new(1).fit(&small).unwrap().solver(),
            Solver::Covariance
        );
        let wide = vec![vec![1.0, 2.0, 3.0], vec![2.0, 1.0, 0.0]];
        assert_eq!(Pca::new(1).fit(&wide).unwrap().solver(), Solver::Svd);
    }
}
