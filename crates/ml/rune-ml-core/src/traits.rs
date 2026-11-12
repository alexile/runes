//! Estimator traits shared by the ML runes.
//!
//! The split follows the usual "configuration → fitted model" pattern:
//!
//! * an **estimator** is a plain, cloneable configuration struct
//!   (hyper-parameters, seed) that implements [`Fit`];
//! * [`Fit::fit`] borrows the estimator and the data and returns a separate
//!   **model** value, so one configuration can be fitted many times and a
//!   model can never be used unfitted;
//! * the model implements [`Predict`] (e.g. assign clusters to new points)
//!   and/or [`Transform`] (e.g. project into an embedding).
//!
//! Algorithms that cannot apply a model to unseen data (HDBSCAN labels,
//! t-SNE embeddings) implement [`FitPredict`] or [`FitTransform`] on the
//! estimator directly.
//!
//! The data type `D` is a generic parameter, usually
//! [`MatrixView<'_, F>`](crate::MatrixView), so algorithms over graphs or
//! other inputs can share the same vocabulary. Each crate keeps its own
//! error type through the `Error` associated type.
//!
//! ```
//! use rune_ml_core::{Fit, MatrixView, MlError, Predict, Metric};
//!
//! /// Nearest-centroid "estimator" with a single centroid: the mean.
//! struct MeanModel;
//! struct Fitted { centroid: Vec<f64> }
//!
//! impl<'a> Fit<MatrixView<'a, f64>> for MeanModel {
//!     type Model = Fitted;
//!     type Error = MlError;
//!     fn fit(&self, x: &MatrixView<'a, f64>) -> Result<Fitted, MlError> {
//!         Ok(Fitted { centroid: x.column_means() })
//!     }
//! }
//!
//! impl<'a> Predict<MatrixView<'a, f64>> for Fitted {
//!     type Output = Vec<f64>;
//!     type Error = MlError;
//!     fn predict(&self, x: &MatrixView<'a, f64>) -> Result<Vec<f64>, MlError> {
//!         Ok(x.rows().map(|r| Metric::Euclidean.distance(r, &self.centroid)).collect())
//!     }
//! }
//!
//! let buf = [0.0, 0.0, 2.0, 0.0];
//! let x = MatrixView::new(&buf, 2, 2)?;
//! let model = MeanModel.fit(&x)?;
//! assert_eq!(model.predict(&x)?, vec![1.0, 1.0]);
//! # Ok::<(), MlError>(())
//! ```

/// Learns a model from data.
pub trait Fit<D: ?Sized> {
    /// The fitted model.
    type Model;
    /// Error returned when fitting fails (invalid parameters, bad data).
    type Error;

    /// Fits a model to `data`. The estimator itself is not modified.
    fn fit(&self, data: &D) -> Result<Self::Model, Self::Error>;
}

/// Produces one prediction per sample (labels, scores, values).
pub trait Predict<D: ?Sized> {
    /// The predictions, e.g. `Vec<usize>` cluster labels.
    type Output;
    /// Error returned when prediction fails (e.g. wrong feature count).
    type Error;

    /// Predicts for every sample in `data`.
    fn predict(&self, data: &D) -> Result<Self::Output, Self::Error>;
}

/// Maps data into another representation (projection, embedding, scaling).
pub trait Transform<D: ?Sized> {
    /// The transformed data, e.g. `Matrix<F>`.
    type Output;
    /// Error returned when the transform fails.
    type Error;

    /// Transforms `data`.
    fn transform(&self, data: &D) -> Result<Self::Output, Self::Error>;
}

/// Fits and labels the training data in one step (clustering).
pub trait FitPredict<D: ?Sized> {
    /// The predictions for the training data.
    type Output;
    /// Error returned on failure.
    type Error;

    /// Fits on `data` and returns predictions for the same samples.
    fn fit_predict(&self, data: &D) -> Result<Self::Output, Self::Error>;
}

/// Fits and transforms the training data in one step (embeddings).
pub trait FitTransform<D: ?Sized> {
    /// The transformed training data.
    type Output;
    /// Error returned on failure.
    type Error;

    /// Fits on `data` and returns it transformed.
    fn fit_transform(&self, data: &D) -> Result<Self::Output, Self::Error>;
}

/// Runs [`Fit::fit`] then [`Predict::predict`] on the same data: a ready
/// body for `FitPredict` when the model can also predict.
pub fn fit_then_predict<E, D>(
    estimator: &E,
    data: &D,
) -> Result<<E::Model as Predict<D>>::Output, E::Error>
where
    D: ?Sized,
    E: Fit<D>,
    E::Model: Predict<D, Error = E::Error>,
{
    estimator.fit(data)?.predict(data)
}

/// Runs [`Fit::fit`] then [`Transform::transform`] on the same data.
pub fn fit_then_transform<E, D>(
    estimator: &E,
    data: &D,
) -> Result<<E::Model as Transform<D>>::Output, E::Error>
where
    D: ?Sized,
    E: Fit<D>,
    E::Model: Transform<D, Error = E::Error>,
{
    estimator.fit(data)?.transform(data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{MatrixView, MlError};

    struct Center;
    struct Centered(Vec<f64>);

    impl Fit<MatrixView<'_, f64>> for Center {
        type Model = Centered;
        type Error = MlError;
        fn fit(&self, x: &MatrixView<'_, f64>) -> Result<Centered, MlError> {
            if x.is_empty() {
                return Err(MlError::TooFewSamples { needed: 1, got: 0 });
            }
            Ok(Centered(x.column_means()))
        }
    }

    impl Transform<MatrixView<'_, f64>> for Centered {
        type Output = Vec<Vec<f64>>;
        type Error = MlError;
        fn transform(&self, x: &MatrixView<'_, f64>) -> Result<Vec<Vec<f64>>, MlError> {
            Ok(x.rows()
                .map(|r| r.iter().zip(&self.0).map(|(a, m)| a - m).collect())
                .collect())
        }
    }

    impl FitTransform<MatrixView<'_, f64>> for Center {
        type Output = Vec<Vec<f64>>;
        type Error = MlError;
        fn fit_transform(&self, x: &MatrixView<'_, f64>) -> Result<Vec<Vec<f64>>, MlError> {
            fit_then_transform(self, x)
        }
    }

    impl Predict<[f64]> for Centered {
        type Output = usize;
        type Error = MlError;
        fn predict(&self, x: &[f64]) -> Result<usize, MlError> {
            Ok(x.len() + self.0.len())
        }
    }

    #[test]
    fn fit_transform_via_helper() {
        let buf = [1.0, 3.0, 3.0, 5.0];
        let x = MatrixView::new(&buf, 2, 2).unwrap();
        assert_eq!(
            Center.fit_transform(&x).unwrap(),
            vec![vec![-1.0, -1.0], vec![1.0, 1.0]]
        );
        let empty = MatrixView::<f64>::new(&[], 0, 2).unwrap();
        assert!(Center.fit_transform(&empty).is_err());
    }

    #[test]
    fn unsized_input() {
        let m = Centered(vec![0.0]);
        assert_eq!(m.predict(&[1.0, 2.0][..]).unwrap(), 3);
    }
}
