//! Shared core for the runes ML crates: row-major matrices, distance
//! metrics, a deterministic RNG and estimator traits.
//!
//! | Item | What it is |
//! |------|------------|
//! | [`Float`] | Sealed scalar trait for `f32` / `f64` |
//! | [`Matrix`], [`MatrixView`] | Owned / borrowed row-major dense matrix over a flat buffer |
//! | [`Metric`] | Euclidean, squared Euclidean, Manhattan, cosine, Chebyshev; `pairwise`, `cdist`, `nearest` |
//! | [`kernels`] | Unrolled, auto-vectorisable slice kernels (`dot`, `sq_euclidean`, …) |
//! | [`trustworthiness`] | Neighbourhood-preservation score of an embedding (Venna & Kaski) |
//! | [`Rng`], [`SplitMix64`] | Reproducible xoshiro256++ / `SplitMix64` generators |
//! | [`Fit`], [`Predict`], [`Transform`], [`FitPredict`], [`FitTransform`] | Estimator vocabulary |
//! | [`MlError`] | Shared error enum (wrap it in your crate's error) |
//!
//! # Features
//!
//! * `serde` — `Serialize`/`Deserialize` for [`Matrix`] (shape validated on
//!   load), [`Metric`], [`Rng`] and [`SplitMix64`].
//! * `rayon` — parallel [`Metric::pairwise`] / [`Metric::cdist`] and
//!   `par_rows()` iterators.
//!
//! # Example
//!
//! ```
//! use rune_ml_core::{Matrix, Metric, Rng};
//!
//! // Migrate from nested vectors.
//! let points = vec![vec![0.0, 0.0], vec![3.0, 4.0], vec![1.0, 1.0]];
//! let x = Matrix::from_rows(&points)?;
//!
//! let d = Metric::Euclidean.pairwise(x.view())?;
//! assert_eq!(d[(0, 1)], 5.0);
//! assert_eq!(Metric::Euclidean.nearest(&[2.5, 3.5], x.view())?, Some((1, 0.5_f64.sqrt())));
//!
//! // Deterministic sampling.
//! let mut rng = Rng::new(42);
//! let sample = x.select_rows(&rng.sample_indices(x.nrows(), 2))?;
//! assert_eq!(sample.shape(), (2, 2));
//! # Ok::<(), rune_ml_core::MlError>(())
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod error;
mod float;
pub mod kernels;
mod matrix;
mod metric;
mod quality;
mod rng;
mod traits;

pub use error::MlError;
pub use float::Float;
pub use matrix::{Matrix, MatrixView, Rows};
pub use metric::Metric;
pub use quality::trustworthiness;
pub use rng::{Rng, SplitMix64};
pub use traits::{
    Fit, FitPredict, FitTransform, Predict, Transform, fit_then_predict, fit_then_transform,
};
