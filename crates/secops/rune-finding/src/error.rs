//! The crate's error type.

/// Errors returned by this crate.
///
/// Parsing a [`Severity`](crate::Severity) or [`Confidence`](crate::Confidence)
/// from text, and validating a [`Cvss`](crate::Cvss) score or vector, are
/// the only fallible operations. Deserialization errors come from the serde format
/// in use, not from this type.
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The text is not a known severity name.
    #[error("unknown severity `{0}`; expected informational, low, medium, high or critical")]
    UnknownSeverity(String),
    /// The text is not a known confidence name.
    #[error("unknown confidence `{0}`; expected tentative, firm or certain")]
    UnknownConfidence(String),
    /// A CVSS base score is not a finite number between 0.0 and 10.0.
    #[error("CVSS base score {0} is not between 0.0 and 10.0")]
    CvssScoreOutOfRange(f64),
    /// A CVSS vector string does not parse (`cvss` feature).
    #[cfg(feature = "cvss")]
    #[error("invalid CVSS vector: {0}")]
    InvalidCvssVector(#[from] rune_cvss::Error),
    /// A stored CVSS base score is not the score of its vector (`cvss`
    /// feature).
    #[cfg(feature = "cvss")]
    #[error("CVSS base score {stated} does not match {computed}, the score of the vector")]
    CvssScoreMismatch {
        /// The score stored with the vector.
        stated: f64,
        /// The score computed from the vector.
        computed: f64,
    },
}
