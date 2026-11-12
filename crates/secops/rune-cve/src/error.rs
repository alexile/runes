//! The crate's [`Error`] type.

/// Errors returned by this crate.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The text is not a CVE id such as `CVE-2021-44228`.
    #[error("invalid CVE id {0:?}: expected CVE-YYYY-NNNN")]
    InvalidCveId(String),
    /// The text is not a CPE 2.3 formatted string or CPE 2.2 URI.
    #[error("invalid CPE name {input:?}: {reason}")]
    InvalidCpe {
        /// The rejected text, truncated to 256 bytes.
        input: String,
        /// What is wrong with it.
        reason: &'static str,
    },
    /// The JSON does not follow the NVD CVE API 2.0 schema.
    #[error("invalid NVD JSON: {0}")]
    Json(#[from] serde_json::Error),
    /// The CVSS metric's version has no scorer in `rune-cvss` (CVSS v2).
    #[error("CVSS version {0} is not supported")]
    UnsupportedCvssVersion(String),
    /// The CVSS vector string does not parse.
    #[error(transparent)]
    Cvss(#[from] rune_cvss::Error),
    /// The caller's transport failed to fetch a page.
    #[cfg(feature = "fetch")]
    #[error("transport error: {0}")]
    Transport(#[source] Box<dyn std::error::Error + Send + Sync>),
    /// The NVD API returned pages that do not add up (an empty page before
    /// `totalResults` was reached, or more pages than the configured limit).
    #[cfg(feature = "fetch")]
    #[error("inconsistent NVD API paging: {0}")]
    Paging(&'static str),
}

impl Error {
    pub(crate) fn cpe(input: &str, reason: &'static str) -> Self {
        let mut end = input.len().min(256);
        while !input.is_char_boundary(end) {
            end -= 1;
        }
        Self::InvalidCpe {
            input: input[..end].to_owned(),
            reason,
        }
    }
}
