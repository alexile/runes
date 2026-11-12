//! The crate's error type.

/// Errors returned by this crate.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The input is not a valid absolute URL, or a reference could not be
    /// resolved against its base.
    #[error("invalid URL: {0}")]
    Parse(#[from] url::ParseError),
    /// A scope rule could not be parsed.
    #[error("invalid scope rule {rule:?}: {reason}")]
    InvalidRule {
        /// The rule as given.
        rule: String,
        /// Why it was rejected.
        reason: String,
    },
}
