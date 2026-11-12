//! The crate's error type.

/// Errors returned by this crate.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// A pattern is malformed.
    #[error("invalid pattern {pattern:?}: {reason}")]
    InvalidPattern {
        /// The pattern as given.
        pattern: String,
        /// What is wrong with it.
        reason: &'static str,
    },

    /// A pattern uses a variable that is neither built in nor a payload.
    #[error("pattern {pattern:?} uses unknown variable {{{{{name}}}}}")]
    UnknownVariable {
        /// The pattern as given.
        pattern: String,
        /// The variable name.
        name: String,
    },

    /// A payload name is not a valid variable name (`[a-z0-9_]+`) or
    /// clashes with a built-in variable.
    #[error("invalid payload name {name:?}: {reason}")]
    InvalidPayloadName {
        /// The name as given.
        name: String,
        /// What is wrong with it.
        reason: &'static str,
    },

    /// A seed is not a usable domain name.
    #[error("invalid seed {seed:?}: {reason}")]
    InvalidSeed {
        /// The seed as given.
        seed: String,
        /// Why it was rejected.
        reason: String,
    },
}
