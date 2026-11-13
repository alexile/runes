//! Incremental (out-of-core) PCA: fit one batch at a time.

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::{PcaError, PcaModel, Solver, exact_svd, finish_basis, validate_rows};

/// Incremental PCA (Ross, Lim, Lin & Yang, *Incremental learning for robust
/// visual tracking*, IJCV 77, 2008), as in scikit-learn's `IncrementalPCA`.
///
/// Feed the data in batches with [`IncrementalPca::partial_fit`] and read the
/// model with [`IncrementalPca::model`] at any point. Memory stays at
/// `O((k + b) · d)` for `k` components and batches of `b` rows, so data sets
/// that do not fit in memory can be decomposed in a single pass.
///
/// Each batch is merged by an exact SVD of the stacked matrix
///
/// ```text
/// [ diag(σ) · V       ]   previous components, weighted
/// [ Xᵦ − mean(Xᵦ)     ]   centred batch
/// [ √(n·nᵦ/(n+nᵦ)) Δμ ]   mean-shift correction
/// ```
///
/// so the result equals batch PCA when every component is kept, and is a
/// close approximation otherwise (exactly as in the reference algorithm).
/// The per-feature variances used for the explained-variance ratio are
/// tracked exactly with Chan et al.'s parallel update.
///
/// # Example
///
/// ```
/// use rune_pca::{IncrementalPca, Pca};
///
/// let x: Vec<Vec<f64>> = (0..40)
///     .map(|i| {
///         let t = f64::from(i);
///         vec![t, 0.5 * t + (t * 1.3).sin(), (t * 0.7).cos()]
///     })
///     .collect();
///
/// let mut ipca = IncrementalPca::new(3);
/// for batch in x.chunks(10) {
///     ipca.partial_fit(batch)?;
/// }
/// let model = ipca.model()?;
///
/// // With every component kept, incremental and batch PCA agree.
/// let batch = Pca::new(3).fit(&x)?;
/// for (a, b) in model.explained_variance().iter().zip(batch.explained_variance()) {
///     assert!((a - b).abs() < 1e-9 * b.max(1.0));
/// }
/// # Ok::<(), rune_pca::PcaError>(())
/// ```
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct IncrementalPca {
    n_components: usize,
    whiten: bool,
    state: Option<State>,
}

/// What has been learned so far.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
struct State {
    n_seen: usize,
    mean: Vec<f64>,
    /// Per-feature sum of squared deviations from the mean.
    m2: Vec<f64>,
    singular_values: Vec<f64>,
    components: Vec<Vec<f64>>,
}

impl IncrementalPca {
    /// Incremental PCA keeping `n_components` components. The count is
    /// checked against the data by the first [`IncrementalPca::partial_fit`].
    #[must_use]
    pub const fn new(n_components: usize) -> Self {
        Self {
            n_components,
            whiten: false,
            state: None,
        }
    }

    /// Sets whether models returned by [`IncrementalPca::model`] whiten
    /// their output (see [`crate::Pca::with_whiten`]).
    #[must_use]
    pub const fn with_whiten(mut self, whiten: bool) -> Self {
        self.whiten = whiten;
        self
    }

    /// Number of samples seen so far.
    #[must_use]
    pub fn n_samples_seen(&self) -> usize {
        self.state.as_ref().map_or(0, |s| s.n_seen)
    }

    /// Fits a fresh model by splitting `data` into batches of `batch_size`
    /// rows. Any previous state is discarded.
    ///
    /// # Errors
    ///
    /// [`PcaError::InvalidBatchSize`] for a zero batch size, otherwise as
    /// [`IncrementalPca::partial_fit`] and [`IncrementalPca::model`].
    ///
    /// # Example
    ///
    /// ```
    /// use rune_pca::IncrementalPca;
    ///
    /// let x = vec![vec![2.0, 2.0], vec![-2.0, -2.0], vec![1.0, -1.0], vec![-1.0, 1.0]];
    /// let model = IncrementalPca::new(1).fit_batches(&x, 2)?;
    /// assert!((model.explained_variance_ratio()[0] - 0.8).abs() < 1e-12);
    /// # Ok::<(), rune_pca::PcaError>(())
    /// ```
    pub fn fit_batches(
        &mut self,
        data: &[Vec<f64>],
        batch_size: usize,
    ) -> Result<PcaModel, PcaError> {
        if batch_size == 0 {
            return Err(PcaError::InvalidBatchSize);
        }
        self.state = None;
        for batch in data.chunks(batch_size) {
            self.partial_fit(batch)?;
        }
        self.model()
    }

    /// Updates the decomposition with one batch of rows.
    ///
    /// On error the state is left unchanged, so a bad batch can be skipped.
    ///
    /// # Errors
    ///
    /// - [`PcaError::NoFeatures`], [`PcaError::DimensionMismatch`] or
    ///   [`PcaError::NonFiniteInput`] for invalid rows (every batch must
    ///   have the width of the first one);
    /// - [`PcaError::InvalidComponents`] if `n_components` is zero or exceeds
    ///   the number of features;
    /// - [`PcaError::BatchTooSmall`] if the first batch has fewer rows than
    ///   `n_components`;
    /// - [`PcaError::NumericalOverflow`] or [`PcaError::NoConvergence`] when
    ///   the data cannot be decomposed.
    #[allow(
        clippy::cast_precision_loss,
        reason = "sample counts stay far below 2^52, so the f64 conversion is exact"
    )]
    pub fn partial_fit(&mut self, batch: &[Vec<f64>]) -> Result<(), PcaError> {
        if batch.is_empty() {
            return Ok(());
        }
        let d = self
            .state
            .as_ref()
            .map_or_else(|| batch[0].len(), |s| s.mean.len());
        if d == 0 {
            return Err(PcaError::NoFeatures);
        }
        validate_rows(batch, d)?;
        let k = self.n_components;
        if k == 0 || k > d {
            return Err(PcaError::InvalidComponents {
                requested: k,
                max: d,
            });
        }
        if self.state.is_none() && batch.len() < k {
            return Err(PcaError::BatchTooSmall {
                rows: batch.len(),
                n_components: k,
            });
        }

        let nb = batch.len();
        let nbf = nb as f64;
        let mut batch_mean = vec![0.0; d];
        for row in batch {
            for (m, &x) in batch_mean.iter_mut().zip(row) {
                *m += x / nbf;
            }
        }
        let centred: Vec<Vec<f64>> = batch
            .iter()
            .map(|row| row.iter().zip(&batch_mean).map(|(x, m)| x - m).collect())
            .collect();
        let mut batch_m2 = vec![0.0; d];
        for row in &centred {
            for (s, &x) in batch_m2.iter_mut().zip(row) {
                *s = x.mul_add(x, *s);
            }
        }

        let (n_seen, mean, m2, mut stacked) = match &self.state {
            None => (nb, batch_mean, batch_m2, centred),
            Some(s) => {
                let n_old = s.n_seen as f64;
                let n_new = n_old + nbf;
                let delta: Vec<f64> = batch_mean.iter().zip(&s.mean).map(|(b, a)| b - a).collect();
                let mean: Vec<f64> = s
                    .mean
                    .iter()
                    .zip(&delta)
                    .map(|(a, dl)| dl.mul_add(nbf / n_new, *a))
                    .collect();
                let m2: Vec<f64> =
                    s.m2.iter()
                        .zip(&batch_m2)
                        .zip(&delta)
                        .map(|((a, b), dl)| (dl * dl).mul_add(n_old * nbf / n_new, a + b))
                        .collect();
                let mut stacked: Vec<Vec<f64>> = s
                    .singular_values
                    .iter()
                    .zip(&s.components)
                    .map(|(sv, c)| c.iter().map(|x| sv * x).collect())
                    .collect();
                stacked.extend(centred);
                let w = (n_old * nbf / n_new).sqrt();
                stacked.push(delta.iter().map(|dl| -w * dl).collect());
                (s.n_seen + nb, mean, m2, stacked)
            }
        };

        // Scale to unit max-magnitude before the SVD, as the batch solver does.
        let scale = stacked
            .iter()
            .flatten()
            .fold(0.0f64, |acc, x| acc.max(x.abs()));
        if !scale.is_finite() || m2.iter().chain(&mean).any(|v| !v.is_finite()) {
            return Err(PcaError::NumericalOverflow);
        }
        let scale = if scale > 0.0 { scale } else { 1.0 };
        stacked.iter_mut().flatten().for_each(|x| *x /= scale);
        let rows = stacked.len();
        let (mut sigma, mut comps) = exact_svd(&stacked, rows, d)?;
        let keep = k.min(sigma.len());
        sigma.truncate(keep);
        comps.truncate(keep);
        finish_basis(&sigma, &mut comps);
        for s in &mut sigma {
            *s *= scale;
        }

        self.state = Some(State {
            n_seen,
            mean,
            m2,
            singular_values: sigma,
            components: comps,
        });
        Ok(())
    }

    /// The model learned from every batch so far.
    ///
    /// [`PcaModel::solver`] reports [`Solver::Svd`], the decomposition used
    /// for each batch.
    ///
    /// # Errors
    ///
    /// [`PcaError::TooFewSamples`] if fewer than two samples have been seen,
    /// [`PcaError::NumericalOverflow`] if the variances overflow.
    #[allow(
        clippy::cast_precision_loss,
        reason = "sample counts stay far below 2^52, so the f64 conversion is exact"
    )]
    pub fn model(&self) -> Result<PcaModel, PcaError> {
        let s = self
            .state
            .as_ref()
            .filter(|s| s.n_seen >= 2)
            .ok_or_else(|| PcaError::TooFewSamples {
                n: self.n_samples_seen(),
            })?;
        let d = s.mean.len();
        let nm1 = (s.n_seen - 1) as f64;
        let total_ss: f64 = s.m2.iter().sum();
        let explained_variance: Vec<f64> =
            s.singular_values.iter().map(|sv| sv * sv / nm1).collect();
        let explained_variance_ratio: Vec<f64> = s
            .singular_values
            .iter()
            .map(|sv| {
                if total_ss > 0.0 {
                    (sv * sv / total_ss).min(1.0)
                } else {
                    0.0
                }
            })
            .collect();
        let k = s.components.len();
        let max_k = s.n_seen.min(d);
        let noise_variance = if k < max_k {
            (total_ss / nm1 - explained_variance.iter().sum::<f64>()).max(0.0) / (max_k - k) as f64
        } else {
            0.0
        };
        if !total_ss.is_finite() || explained_variance.iter().any(|v| !v.is_finite()) {
            return Err(PcaError::NumericalOverflow);
        }
        Ok(PcaModel {
            mean: s.mean.clone(),
            components: s.components.clone(),
            explained_variance,
            explained_variance_ratio,
            singular_values: s.singular_values.clone(),
            noise_variance,
            n_samples: s.n_seen,
            whiten: self.whiten,
            solver: Solver::Svd,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bad_batches_leave_the_state_alone() {
        let mut ipca = IncrementalPca::new(1);
        ipca.partial_fit(&[vec![1.0, 2.0], vec![3.0, 1.0]]).unwrap();
        let before = ipca.clone();
        assert!(ipca.partial_fit(&[vec![1.0]]).is_err());
        assert!(ipca.partial_fit(&[vec![f64::NAN, 1.0]]).is_err());
        assert_eq!(ipca, before);
        assert!(ipca.partial_fit(&[]).is_ok());
        assert_eq!(ipca.n_samples_seen(), 2);
    }
}
