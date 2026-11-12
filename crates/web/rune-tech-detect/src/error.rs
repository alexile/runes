//! The crate's error type.

/// Errors returned by this crate.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The rule file is not valid JSON.
    #[error("invalid JSON: {0}")]
    Json(String),
    /// A technology or one of its fields has the wrong shape.
    #[error("technology {technology:?}, field {field:?}: {message}")]
    InvalidRule {
        /// The technology name (truncated to 200 characters).
        technology: String,
        /// The field, e.g. `headers`.
        field: String,
        /// What is wrong.
        message: String,
    },
    /// A pattern does not compile (only from [`Detector::strict`](crate::Detector::strict)).
    #[error("technology {technology:?}: {source}")]
    Pattern {
        /// The technology name (truncated to 200 characters).
        technology: String,
        /// The compile error.
        source: rune_matchers::MatchError,
    },
}

impl Error {
    /// A stable, machine-readable kind an agent can branch on.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Json(_) => "invalid_json",
            Self::InvalidRule { .. } => "invalid_rule",
            Self::Pattern { .. } => "invalid_pattern",
        }
    }
}

/// Truncates user input echoed in errors.
pub fn clip(text: &str) -> String {
    text.chars().take(200).collect()
}
