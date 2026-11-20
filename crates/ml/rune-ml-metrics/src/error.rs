//! The crate error type, [`MetricsError`].

use rune_ml_core::MlError;

/// Errors returned by the metric functions.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum MetricsError {
    /// The input has no samples.
    #[error("input is empty")]
    Empty,
    /// Two inputs that must be the same length are not.
    #[error("length mismatch: expected {expected}, found {found}")]
    LengthMismatch {
        /// Length of the first input.
        expected: usize,
        /// Length of the offending input.
        found: usize,
    },
    /// A score, target or probability is `NaN` or infinite.
    #[error("non-finite value at index {index}")]
    NonFinite {
        /// Index of the first offending sample.
        index: usize,
    },
    /// A probability lies outside `[0, 1]`.
    #[error("probability at index {index} is outside [0, 1]")]
    InvalidProbability {
        /// Flat index of the offending value.
        index: usize,
    },
    /// The metric needs more samples than it got.
    #[error("not enough samples: need at least {needed}, got {got}")]
    TooFewSamples {
        /// Minimum number of samples required.
        needed: usize,
        /// Number of samples received.
        got: usize,
    },
    /// `Average::Binary` was asked for, but the labels are multiclass.
    #[error("average=binary needs at most 2 distinct labels, found {found}")]
    NotBinary {
        /// Number of distinct labels in `y_true` and `y_pred`.
        found: usize,
    },
    /// The positive label of `Average::Binary` is not one of the two labels present.
    #[error("pos_label is not one of the labels present in the data")]
    UnknownPosLabel,
    /// A ranking metric needs both classes (ROC) or at least one positive
    /// (precision-recall), and `y_true` does not have them.
    #[error("y_true has no {missing} samples, the metric is undefined")]
    MissingClass {
        /// `"positive"` or `"negative"`.
        missing: &'static str,
    },
    /// A label in `y_true` is not in the label list.
    #[error("label at index {index} is not in the label list")]
    UnknownLabel {
        /// Index of the first offending sample.
        index: usize,
    },
    /// Wrong number of classes or clusters for the metric.
    #[error("invalid number of labels: {reason}")]
    InvalidLabelCount {
        /// What was expected.
        reason: String,
    },
    /// A parameter is outside its valid range.
    #[error("invalid parameter `{name}`: {reason}")]
    InvalidParameter {
        /// Parameter name.
        name: &'static str,
        /// Why the value was rejected.
        reason: String,
    },
    /// An error from the shared ML core (matrix shape, non-finite feature, ...).
    #[error(transparent)]
    Core(#[from] MlError),
}

impl MetricsError {
    pub(crate) fn label_count(reason: impl Into<String>) -> Self {
        Self::InvalidLabelCount {
            reason: reason.into(),
        }
    }

    pub(crate) fn parameter(name: &'static str, reason: impl Into<String>) -> Self {
        Self::InvalidParameter {
            name,
            reason: reason.into(),
        }
    }
}

/// Shorthand result type for this crate.
pub type Result<T, E = MetricsError> = core::result::Result<T, E>;
