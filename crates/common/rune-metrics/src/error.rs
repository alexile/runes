/// Errors returned by this crate.
///
/// Every error comes from registration or label lookup; recording a value
/// never fails.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// A metric name does not match `[a-zA-Z_:][a-zA-Z0-9_:]*`.
    #[error("invalid metric name {0:?}")]
    InvalidName(String),
    /// A label name does not match `[a-zA-Z_][a-zA-Z0-9_]*`, starts with the
    /// reserved `__`, or is reserved for the metric type (`le` on a
    /// histogram).
    #[error("invalid label name {0:?}")]
    InvalidLabelName(String),
    /// The same label name appears twice in one family.
    #[error("duplicate label name {0:?}")]
    DuplicateLabelName(String),
    /// A unit is not a valid name fragment, or the metric name does not end
    /// with `_<unit>` as `OpenMetrics` requires.
    #[error("metric {name:?} does not end with its unit {unit:?}")]
    InvalidUnit {
        /// The metric name.
        name: String,
        /// The declared unit.
        unit: String,
    },
    /// A metric with this name is already registered.
    #[error("metric {0:?} is already registered")]
    AlreadyRegistered(String),
    /// Histogram buckets are empty, not finite or not strictly increasing.
    #[error("histogram buckets must be finite and strictly increasing")]
    InvalidBuckets,
    /// The number of label values does not match the family's label names.
    #[error("expected {expected} label values, got {got}")]
    LabelCount {
        /// Number of label names the family was registered with.
        expected: usize,
        /// Number of values passed.
        got: usize,
    },
}
