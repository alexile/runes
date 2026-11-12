//! The crate's error type.

use crate::Version;

/// Errors returned by this crate.
///
/// Every variant comes from reading untrusted text: a vector string, or a
/// score given as a number. Scoring itself cannot fail.
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The text does not start with `CVSS:`.
    #[error("vector does not start with a `CVSS:<version>/` prefix")]
    MissingPrefix,
    /// The prefix names a CVSS version this crate does not implement.
    #[error("unsupported CVSS version `{0}`; expected 3.0, 3.1 or 4.0")]
    UnsupportedVersion(String),
    /// A `/`-separated part is not `NAME:VALUE` (it is empty, or has no `:`).
    #[error("malformed metric `{0}`; expected `NAME:VALUE`")]
    MalformedMetric(String),
    /// The metric name is not defined by this CVSS version.
    #[error("unknown metric `{name}` in a CVSS {version} vector")]
    UnknownMetric {
        /// The metric name as written.
        name: String,
        /// The vector's version.
        version: Version,
    },
    /// The value is not one the metric allows (values are case sensitive).
    #[error("invalid value `{value}` for metric {metric}")]
    InvalidValue {
        /// The metric's abbreviated name.
        metric: &'static str,
        /// The value as written.
        value: String,
    },
    /// A metric appears more than once.
    #[error("metric {0} appears more than once")]
    DuplicateMetric(&'static str),
    /// A mandatory base metric is missing.
    #[error("mandatory base metric {0} is missing")]
    MissingMetric(&'static str),
    /// A CVSS v4.0 metric is out of the specification's fixed order.
    #[error("metric {0} is out of order; CVSS v4.0 vectors list metrics in specification order")]
    OutOfOrder(&'static str),
    /// A number is not a CVSS score: a multiple of 0.1 from 0.0 to 10.0.
    #[error("{0} is not a CVSS score (a multiple of 0.1 from 0.0 to 10.0)")]
    InvalidScore(f64),
    /// The text is not a qualitative severity rating.
    #[error("unknown severity `{0}`; expected none, low, medium, high or critical")]
    UnknownSeverity(String),
}
