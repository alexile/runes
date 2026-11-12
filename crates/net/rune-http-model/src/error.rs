//! The crate's error type.

/// What went wrong while building an HTTP model value.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum HttpModelError {
    /// A body given as base64 could not be decoded.
    #[error("invalid base64 body: {0}")]
    InvalidBase64(String),
    /// Text that names no known HTTP version.
    #[error("unknown HTTP version `{0}`")]
    UnknownVersion(String),
}

impl HttpModelError {
    /// A stable, machine-readable kind an agent can branch on.
    ///
    /// ```
    /// use rune_http_model::HttpBody;
    ///
    /// let error = HttpBody::from_base64("not base64!").unwrap_err();
    /// assert_eq!(error.code(), "invalid_base64");
    /// ```
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::InvalidBase64(_) => "invalid_base64",
            Self::UnknownVersion(_) => "unknown_http_version",
        }
    }
}
