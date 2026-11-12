//! The crate error type.

/// Errors from compiling a [`Policy`](crate::Policy) into a
/// [`Redactor`](crate::Redactor).
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// An extra `rune-leak` rule is malformed or its pattern does not compile.
    #[error("invalid secret rule: {0}")]
    Rules(#[from] rune_leak::Error),
    /// [`Replacement::Hash`](crate::Replacement::Hash) is used but no hash key
    /// was set.
    #[error("hash replacement needs a key; set one with Policy::with_hash_key")]
    MissingHashKey,
    /// The entropy threshold is NaN, infinite or negative.
    #[error("entropy threshold must be finite and non-negative")]
    InvalidEntropyThreshold,
}

impl Error {
    /// A stable, machine-readable code for the error.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Rules(_) => "invalid_rule",
            Self::MissingHashKey => "missing_hash_key",
            Self::InvalidEntropyThreshold => "invalid_entropy_threshold",
        }
    }
}
