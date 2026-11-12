//! The crate's error type.

use std::time::Duration;

/// Errors returned by this crate.
///
/// No variant ever carries a webhook URL, token or other secret: URLs are
/// [`SecretValue`](rune_secret_ref::SecretValue)s and are left out of every
/// message.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// A sink's endpoint URL is not an absolute `http` or `https` URL.
    #[error("{sink}: invalid endpoint URL: {reason}")]
    InvalidUrl {
        /// The sink the URL was given to.
        sink: &'static str,
        /// Why the URL was rejected. Never contains the URL itself.
        reason: String,
    },
    /// A sink option is invalid (an empty project key, a header name with
    /// spaces, a header value with a line break).
    #[error("{sink}: invalid configuration: {reason}")]
    InvalidConfig {
        /// The sink being configured.
        sink: &'static str,
        /// What is wrong.
        reason: String,
    },
    /// A message template does not parse.
    #[error("template error at byte {position}: {reason}")]
    Template {
        /// Byte offset in the template text.
        position: usize,
        /// What is wrong.
        reason: String,
    },
    /// The transport could not complete the request (connection refused,
    /// timeout, TLS failure).
    #[error("transport error: {message}")]
    Transport {
        /// The transport's description of the failure.
        message: String,
        /// Whether a later attempt may succeed.
        retryable: bool,
    },
    /// The provider throttled the request (HTTP 429).
    #[error("{sink}: rate limited (HTTP {status})")]
    RateLimited {
        /// The sink that was throttled.
        sink: &'static str,
        /// The HTTP status, normally 429.
        status: u16,
        /// How long the provider asked the caller to wait, if it said.
        retry_after: Option<Duration>,
    },
    /// The provider failed on its side (HTTP 5xx or 408). Retryable.
    #[error("{sink}: server error (HTTP {status}): {detail}")]
    Server {
        /// The sink whose provider failed.
        sink: &'static str,
        /// The HTTP status.
        status: u16,
        /// The start of the response body.
        detail: String,
    },
    /// The provider rejected the request (any other non-2xx status). Not
    /// retryable: the payload, the URL or the credentials are wrong.
    #[error("{sink}: rejected (HTTP {status}): {detail}")]
    Rejected {
        /// The sink whose provider rejected the request.
        sink: &'static str,
        /// The HTTP status.
        status: u16,
        /// The start of the response body (Slack's `invalid_token`, Jira's
        /// `errorMessages`).
        detail: String,
    },
    /// The provider answered 2xx with a body the sink cannot read.
    #[error("{sink}: unexpected response: {reason}")]
    InvalidResponse {
        /// The sink that read the response.
        sink: &'static str,
        /// What is wrong with it.
        reason: String,
    },
}

impl Error {
    /// Whether sending the same message again later may succeed: transport
    /// failures marked retryable, rate limits and server errors.
    #[must_use]
    pub const fn is_retryable(&self) -> bool {
        match self {
            Self::Transport { retryable, .. } => *retryable,
            Self::RateLimited { .. } | Self::Server { .. } => true,
            _ => false,
        }
    }

    /// The wait the provider asked for, from a rate-limit response.
    #[must_use]
    pub const fn retry_after(&self) -> Option<Duration> {
        match self {
            Self::RateLimited { retry_after, .. } => *retry_after,
            _ => None,
        }
    }
}
