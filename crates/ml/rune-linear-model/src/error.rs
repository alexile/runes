//! The crate error type, [`LinearError`].

use rune_ml_core::MlError;
use rune_ml_metrics::MetricsError;

/// Errors returned by the estimators and fitted models.
///
/// Bad input never panics and never produces `NaN` coefficients silently:
/// it comes back as one of these variants.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum LinearError {
    /// Shape, finiteness or parameter error from the shared core
    /// (`TooFewSamples`, `NonFinite`, `InvalidParameter`, ...).
    #[error(transparent)]
    Core(#[from] MlError),
    /// Error from a scoring helper.
    #[error(transparent)]
    Metrics(#[from] MetricsError),
    /// `y` (or `sample_weight`) does not have one entry per row of `x`.
    #[error("expected {expected} targets or weights (one per sample), found {found}")]
    LengthMismatch {
        /// Number of samples in `x`.
        expected: usize,
        /// Length of the offending slice.
        found: usize,
    },
    /// A target value is `NaN` or infinite.
    #[error("non-finite target at index {index}")]
    NonFiniteTarget {
        /// Index of the first offending sample.
        index: usize,
    },
    /// A sample weight is negative, `NaN` or infinite.
    #[error("sample weight at index {index} must be finite and non-negative")]
    InvalidSampleWeight {
        /// Index of the first offending weight.
        index: usize,
    },
    /// All sample weights are zero.
    #[error("sample weights sum to zero")]
    ZeroWeightSum,
    /// The input has a different number of features than the model.
    #[error("model has {expected} features, input has {found}")]
    FeatureMismatch {
        /// Features seen during fit.
        expected: usize,
        /// Features in the input.
        found: usize,
    },
    /// A classifier needs at least two distinct classes.
    #[error("need samples of at least 2 classes, found {found}")]
    TooFewClasses {
        /// Number of distinct labels in `y`.
        found: usize,
    },
    /// A label is not one of the classes the model knows.
    #[error("label at index {index} is not one of the model's classes")]
    UnknownLabel {
        /// Index of the first offending sample.
        index: usize,
    },
    /// The least-squares system is singular (collinear or constant
    /// features, or fewer samples than features) and there is no
    /// regularisation to fix it. Use `Ridge` or drop features.
    #[error("singular system: features are collinear or constant; add regularisation")]
    Singular,
    /// SGD weights overflowed. Scale the inputs or lower the learning rate.
    #[error("SGD diverged at epoch {epoch}: weights are no longer finite")]
    Diverged {
        /// 1-based epoch at which the overflow was detected.
        epoch: usize,
    },
    /// Values are so large that their squares overflow; rescale the data.
    #[error("{0} values are too large: their squares overflow, rescale the data")]
    Overflow(&'static str),
    /// A deserialized model has inconsistent parts.
    #[error("inconsistent model: {0}")]
    InvalidModel(&'static str),
}

impl LinearError {
    pub(crate) fn param(name: &'static str, reason: impl Into<String>) -> Self {
        Self::Core(MlError::invalid_parameter(name, reason))
    }
}

pub fn map_singular(e: MlError) -> LinearError {
    match e {
        MlError::Singular { .. } => LinearError::Singular,
        e => LinearError::Core(e),
    }
}

/// Shorthand for `Result<T, LinearError>`.
pub type Result<T> = core::result::Result<T, LinearError>;
