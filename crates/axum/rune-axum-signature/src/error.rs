//! Verification errors.

use http::StatusCode;
use std::fmt;

/// Why a webhook was rejected.
///
/// Messages name headers and limits but never contain secrets, signatures or
/// body content, so they are safe to log.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum VerifyError {
    /// A required header is absent (or not visible ASCII).
    MissingHeader(String),
    /// A header is present but cannot be parsed.
    MalformedHeader(String),
    /// No signature matched any configured secret.
    SignatureMismatch,
    /// The signed timestamp is further from now than the tolerance allows.
    TimestampOutOfTolerance,
    /// This message was already accepted once.
    Replayed,
    /// The body is larger than the configured limit.
    BodyTooLarge {
        /// The configured limit in bytes.
        limit: usize,
    },
    /// The body stream failed before it was fully read.
    BodyRead,
    /// The replay store could not be reached; the request is refused.
    ReplayStoreUnavailable,
}

impl VerifyError {
    /// HTTP status the layer answers with.
    ///
    /// `413` for an oversized body, `400` for a broken body stream, `503`
    /// when the replay store fails, `401` for everything else.
    #[must_use]
    pub const fn status(&self) -> StatusCode {
        match self {
            Self::BodyTooLarge { .. } => StatusCode::PAYLOAD_TOO_LARGE,
            Self::BodyRead => StatusCode::BAD_REQUEST,
            Self::ReplayStoreUnavailable => StatusCode::SERVICE_UNAVAILABLE,
            _ => StatusCode::UNAUTHORIZED,
        }
    }
}

impl fmt::Display for VerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingHeader(h) => write!(f, "missing header `{h}`"),
            Self::MalformedHeader(h) => write!(f, "malformed header `{h}`"),
            Self::SignatureMismatch => f.write_str("no valid signature"),
            Self::TimestampOutOfTolerance => f.write_str("timestamp outside tolerance"),
            Self::Replayed => f.write_str("message already processed"),
            Self::BodyTooLarge { limit } => write!(f, "body larger than {limit} bytes"),
            Self::BodyRead => f.write_str("failed to read body"),
            Self::ReplayStoreUnavailable => f.write_str("replay store unavailable"),
        }
    }
}

impl std::error::Error for VerifyError {}
