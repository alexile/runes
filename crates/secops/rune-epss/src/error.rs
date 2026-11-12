//! The crate's [`Error`] type.

/// Errors returned by this crate.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// A row of the EPSS CSV is malformed.
    #[error("EPSS CSV line {line}: {reason}")]
    Csv {
        /// 1-based line number.
        line: usize,
        /// What is wrong with it.
        reason: String,
    },
    /// The JSON does not follow the EPSS API or KEV catalog schema.
    #[error("invalid JSON: {0}")]
    Json(#[from] serde_json::Error),
    /// A date is not `YYYY-MM-DD`.
    #[error("invalid date {0:?}: expected YYYY-MM-DD")]
    InvalidDate(String),
    /// The EPSS API answered with an error status.
    #[error("EPSS API error: {0}")]
    Api(String),
    /// The gzip stream is corrupt.
    #[cfg(feature = "gzip")]
    #[error("gzip: {0}")]
    Gzip(#[source] std::io::Error),
    /// The decompressed feed is larger than the limit.
    #[cfg(feature = "gzip")]
    #[error("decompressed feed exceeds {0} bytes")]
    TooLarge(u64),
    /// The caller's transport failed.
    #[cfg(feature = "fetch")]
    #[error("transport error: {0}")]
    Transport(#[source] rune_cve::fetch::TransportError),
}
