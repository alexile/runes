//! The crate's error type.

/// Errors returned by this crate.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The base URL of a probe plan does not parse or is not `http`/`https`.
    #[error("invalid base URL {url:?}: {message}")]
    InvalidUrl {
        /// The URL (truncated to 200 characters).
        url: String,
        /// Why it was rejected.
        message: String,
    },
    /// The probe nonce is empty, too long or not `[A-Za-z0-9_-]`.
    #[error("invalid nonce {0:?}: expected 1 to 64 characters of [A-Za-z0-9_-]")]
    InvalidNonce(String),
    /// A signature's matcher or version extractor failed to compile.
    #[error("signature {signature:?}: {source}")]
    Signature {
        /// The signature name.
        signature: String,
        /// The compile error.
        source: rune_matchers::MatchError,
    },
}

impl Error {
    /// A stable, machine-readable kind an agent can branch on.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::InvalidUrl { .. } => "invalid_url",
            Self::InvalidNonce(_) => "invalid_nonce",
            Self::Signature { .. } => "invalid_signature",
        }
    }
}

/// Truncates user input echoed in errors.
pub fn clip(text: &str) -> String {
    text.chars().take(200).collect()
}
