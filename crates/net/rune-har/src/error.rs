//! The crate's error type.

/// What went wrong while reading or writing HAR.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum HarError {
    /// The input is not valid JSON.
    #[error("invalid JSON: {0}")]
    Json(String),
    /// The input is JSON but not a HAR document.
    #[error("not a HAR document: {0}")]
    NotHar(&'static str),
    /// Serializing a document failed.
    #[error("cannot serialize HAR: {0}")]
    Write(String),
    /// The writer failed.
    #[error("I/O error writing HAR: {0}")]
    Io(#[from] std::io::Error),
}

impl HarError {
    /// A stable, machine-readable kind an agent can branch on.
    ///
    /// ```
    /// let error = rune_har::parse(b"{}").unwrap_err();
    /// assert_eq!(error.code(), "not_har");
    /// ```
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Json(_) => "invalid_json",
            Self::NotHar(_) => "not_har",
            Self::Write(_) => "write",
            Self::Io(_) => "io",
        }
    }
}
