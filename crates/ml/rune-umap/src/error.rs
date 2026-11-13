/// Errors reported by the fallible UMAP entry points ([`crate::Umap::try_fit`],
/// [`crate::FittedUmap::try_transform`], [`crate::trustworthiness`], …).
#[derive(Clone, Debug, PartialEq, thiserror::Error)]
#[non_exhaustive]
pub enum UmapError {
    /// No points were supplied.
    #[error("input contains no points")]
    Empty,
    /// The points have zero features.
    #[error("points have no features")]
    NoFeatures,
    /// A row has a different number of features from the first row (when
    /// fitting) or from the training data (when transforming).
    #[error("row {index} has {found} values, expected {expected}")]
    DimensionMismatch {
        /// Index of the offending row.
        index: usize,
        /// Number of values in that row.
        found: usize,
        /// Number of values expected.
        expected: usize,
    },
    /// A value is `NaN` or infinite.
    #[error("row {row}, column {col} is not finite ({value})")]
    NonFinite {
        /// Row of the offending value.
        row: usize,
        /// Column of the offending value.
        col: usize,
        /// The offending value.
        value: f64,
    },
    /// `n_neighbors` must be strictly less than the number of samples.
    #[error("n_neighbors ({n_neighbors}) must be less than the number of samples ({n_samples})")]
    TooFewSamples {
        /// Configured neighbourhood size.
        n_neighbors: usize,
        /// Number of samples supplied.
        n_samples: usize,
    },
    /// The label slice length differs from the number of points.
    #[error("got {labels} labels for {points} points")]
    LabelLengthMismatch {
        /// Number of labels.
        labels: usize,
        /// Number of points.
        points: usize,
    },
    /// A numeric parameter is out of range or not finite.
    #[error("invalid parameter {name} = {value}: {reason}")]
    InvalidParameter {
        /// Parameter name.
        name: &'static str,
        /// Offending value.
        value: f64,
        /// Why the value is rejected.
        reason: &'static str,
    },
    /// An error reported by the shared `rune-ml-core` routines that some
    /// entry points delegate to.
    #[error(transparent)]
    Core(#[from] rune_ml_core::MlError),
}
