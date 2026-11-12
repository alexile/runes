//! The crate's error type.

/// Errors returned by this crate.
///
/// Correlation itself cannot fail; only reading a SARIF log and building a
/// [`Route`](crate::Route) from a malformed pattern can.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The SARIF input does not parse, or is not SARIF 2.1.0.
    #[error(transparent)]
    Sarif(#[from] rune_sarif::Error),
    /// A route pattern or file is malformed.
    #[error("invalid route `{pattern}`: {reason}")]
    InvalidRoute {
        /// The pattern as given.
        pattern: String,
        /// What is wrong with it.
        reason: &'static str,
    },
}
