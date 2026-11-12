//! The crate's error type.

/// Errors returned by this crate.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// A custom mask pattern is not a valid regex.
    #[error("invalid mask pattern {pattern:?}: {reason}")]
    Pattern {
        /// The pattern.
        pattern: String,
        /// Why it was rejected.
        reason: String,
    },
    /// An ignored JSON pointer does not start with `/`.
    #[error("invalid JSON pointer {0:?}: must be empty or start with '/'")]
    JsonPointer(String),
}
