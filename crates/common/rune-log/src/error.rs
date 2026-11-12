//! The crate's error type.

/// Errors returned by this crate.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The level filter is not valid `tracing` directive syntax
    /// (`info`, `warn,my_crate=debug`, …).
    #[error("invalid log filter {value:?}: {reason}")]
    InvalidFilter {
        /// The rejected filter text.
        value: String,
        /// Why it was rejected.
        reason: String,
    },
    /// The log format is not one of `full`, `text`, `compact` or `json`.
    #[error("invalid log format {0:?}: expected full, text, compact or json")]
    InvalidFormat(String),
    /// The redaction scope is not `fields` or `line`.
    #[error("invalid redaction scope {0:?}: expected fields or line")]
    InvalidScope(String),
    /// A global default subscriber is already installed.
    #[error("a global tracing subscriber is already installed")]
    AlreadyInitialized,
}
