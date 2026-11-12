use std::fmt;
use std::time::Duration;

use thiserror::Error;

/// Errors produced by a [`Chain`](crate::Chain) during execution.
#[derive(Debug, Error)]
pub enum ChainError {
    /// The underlying LLM returned an error.
    #[error("LLM error: {0}")]
    LlmError(#[from] LlmError),
    /// A required prompt variable was missing from the input map.
    #[error("missing prompt variable: {0}")]
    MissingVariable(String),
    /// The chain's memory layer failed.
    #[error("memory error: {0}")]
    MemoryError(String),
    /// A tool invoked by an agent returned an error.
    #[error("tool error: {0}")]
    ToolError(#[from] ToolError),
    /// Output could not be parsed into the expected type.
    #[error("parse error: {0}")]
    ParseError(String),
    /// Any error not covered by the variants above.
    #[error("{0}")]
    Other(String),
}

/// What kind of failure an [`LlmError`] is.
///
/// Providers classify their failures (from the HTTP status, the provider's
/// error type, or the transport error) so callers such as retry and fallback
/// layers can decide what to do without parsing message text.
///
/// The enum is `#[non_exhaustive]`: match it with a wildcard arm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum LlmErrorKind {
    /// Too many requests or tokens per time window (HTTP 429).
    RateLimit,
    /// The provider is temporarily overloaded or unavailable (HTTP 503,
    /// Anthropic's 529 `overloaded_error`).
    Overloaded,
    /// Authentication, permission or billing failure (HTTP 401 / 403, an
    /// exhausted quota).
    Auth,
    /// The request is malformed or names something that does not exist
    /// (HTTP 400 / 404 / 413 / 422).
    InvalidRequest,
    /// The prompt (plus the requested output) does not fit the model's
    /// context window.
    ContextLengthExceeded,
    /// The request, or the provider's processing of it, timed out.
    Timeout,
    /// A transport-level failure: connection refused or reset, DNS, TLS, a
    /// stream cut off mid-response.
    Network,
    /// Any other server-side fault (HTTP 5xx).
    Server,
    /// The provider answered, but the response could not be decoded.
    InvalidResponse,
    /// The provider or model lacks a capability (tool calling, streaming,
    /// a response format).
    Unsupported,
    /// The provider reported an error that fits none of the kinds above.
    Provider,
    /// A local failure that never reached a provider (configuration, request
    /// encoding, a budget, …).
    Other,
}

impl LlmErrorKind {
    /// Classify an HTTP status code from a provider's API.
    ///
    /// Returns [`Provider`](Self::Provider) for codes with no specific
    /// meaning (including non-error codes).
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_chain_core::LlmErrorKind;
    ///
    /// assert_eq!(LlmErrorKind::from_status(429), LlmErrorKind::RateLimit);
    /// assert_eq!(LlmErrorKind::from_status(529), LlmErrorKind::Overloaded);
    /// assert_eq!(LlmErrorKind::from_status(401), LlmErrorKind::Auth);
    /// assert_eq!(LlmErrorKind::from_status(502), LlmErrorKind::Server);
    /// ```
    #[must_use]
    pub const fn from_status(status: u16) -> Self {
        match status {
            401..=403 => Self::Auth,
            408 | 504 => Self::Timeout,
            429 => Self::RateLimit,
            503 | 529 => Self::Overloaded,
            400 | 404 | 405 | 409 | 413 | 415 | 422 => Self::InvalidRequest,
            500..=599 => Self::Server,
            _ => Self::Provider,
        }
    }

    /// `true` if sending the same request again later may succeed: rate
    /// limits, overload, timeouts, network and server faults.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_chain_core::LlmErrorKind;
    ///
    /// assert!(LlmErrorKind::Overloaded.is_retryable());
    /// assert!(!LlmErrorKind::ContextLengthExceeded.is_retryable());
    /// ```
    #[must_use]
    pub const fn is_retryable(self) -> bool {
        matches!(
            self,
            Self::RateLimit | Self::Overloaded | Self::Timeout | Self::Network | Self::Server
        )
    }

    /// A short lower-case label, also used as the [`LlmError`] message prefix.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RateLimit => "rate limited",
            Self::Overloaded => "provider overloaded",
            Self::Auth => "authentication failed",
            Self::InvalidRequest => "invalid request",
            Self::ContextLengthExceeded => "context length exceeded",
            Self::Timeout => "timed out",
            Self::Network => "request failed",
            Self::Server => "server error",
            Self::InvalidResponse => "invalid response",
            Self::Unsupported => "not supported",
            Self::Provider => "provider error",
            Self::Other => "error",
        }
    }
}

impl fmt::Display for LlmErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Errors produced by an [`Llm`](crate::Llm) during generation.
///
/// An `LlmError` carries a [`kind`](Self::kind), a human-readable
/// [`message`](Self::message), and, when the failure came from an HTTP API,
/// the [`status`](Self::status) code and the provider's requested
/// [`retry_after`](Self::retry_after) delay. Build one with a kind-specific
/// constructor and the `with_*` builders; read it with the accessors. New
/// fields can be added without breaking callers.
///
/// It displays as `"<kind>: <message>"` ([`LlmErrorKind::Other`] shows just
/// the message).
///
/// # Example
///
/// ```rust
/// use std::time::Duration;
/// use rune_chain_core::{LlmError, LlmErrorKind};
///
/// let e = LlmError::from_status(429, "Rate limit reached")
///     .with_retry_after(Duration::from_secs(2));
/// assert_eq!(e.kind(), LlmErrorKind::RateLimit);
/// assert_eq!(e.status(), Some(429));
/// assert_eq!(e.retry_after(), Some(Duration::from_secs(2)));
/// assert!(e.is_retryable());
/// assert_eq!(e.to_string(), "rate limited: Rate limit reached");
///
/// let e = LlmError::other("OPENAI_API_KEY is not set");
/// assert!(!e.is_retryable());
/// assert_eq!(e.to_string(), "OPENAI_API_KEY is not set");
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct LlmError {
    kind: LlmErrorKind,
    message: String,
    status: Option<u16>,
    retry_after: Option<Duration>,
}

impl fmt::Display for LlmError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.kind {
            LlmErrorKind::Other => f.write_str(&self.message),
            kind => write!(f, "{kind}: {}", self.message),
        }
    }
}

impl std::error::Error for LlmError {}

impl LlmError {
    /// An error of `kind` with a human-readable `message`.
    pub fn new(kind: LlmErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
            status: None,
            retry_after: None,
        }
    }

    /// An HTTP error response: the kind is derived from `status` with
    /// [`LlmErrorKind::from_status`], and the status is recorded.
    pub fn from_status(status: u16, message: impl Into<String>) -> Self {
        Self::new(LlmErrorKind::from_status(status), message).with_status(status)
    }

    /// A transport-level failure ([`LlmErrorKind::Network`]).
    pub fn request_failed(message: impl Into<String>) -> Self {
        Self::new(LlmErrorKind::Network, message)
    }

    /// The request timed out ([`LlmErrorKind::Timeout`]).
    pub fn timeout(message: impl Into<String>) -> Self {
        Self::new(LlmErrorKind::Timeout, message)
    }

    /// An unclassified error reported by the provider
    /// ([`LlmErrorKind::Provider`]).
    pub fn provider(message: impl Into<String>) -> Self {
        Self::new(LlmErrorKind::Provider, message)
    }

    /// The provider's response could not be decoded
    /// ([`LlmErrorKind::InvalidResponse`]).
    pub fn invalid_response(message: impl Into<String>) -> Self {
        Self::new(LlmErrorKind::InvalidResponse, message)
    }

    /// The provider lacks a capability ([`LlmErrorKind::Unsupported`]), such
    /// as native tool calling or streaming.
    pub fn unsupported(message: impl Into<String>) -> Self {
        Self::new(LlmErrorKind::Unsupported, message)
    }

    /// A local failure that never reached a provider
    /// ([`LlmErrorKind::Other`]).
    pub fn other(message: impl Into<String>) -> Self {
        Self::new(LlmErrorKind::Other, message)
    }

    /// Replace the kind (builder style), e.g. after inspecting a provider's
    /// error code.
    #[must_use]
    pub const fn with_kind(mut self, kind: LlmErrorKind) -> Self {
        self.kind = kind;
        self
    }

    /// Record the HTTP status code (builder style). The kind is unchanged.
    #[must_use]
    pub const fn with_status(mut self, status: u16) -> Self {
        self.status = Some(status);
        self
    }

    /// Record the delay the provider asked for before a retry (builder
    /// style), typically from a `Retry-After` header.
    #[must_use]
    pub const fn with_retry_after(mut self, retry_after: Duration) -> Self {
        self.retry_after = Some(retry_after);
        self
    }

    /// Rewrite the message, keeping everything else (e.g. to scrub secrets).
    #[must_use]
    pub fn map_message(mut self, f: impl FnOnce(String) -> String) -> Self {
        self.message = f(self.message);
        self
    }

    /// What kind of failure this is.
    #[must_use]
    pub const fn kind(&self) -> LlmErrorKind {
        self.kind
    }

    /// The human-readable message, without the kind prefix.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }

    /// The HTTP status code of the provider's response, if any.
    #[must_use]
    pub const fn status(&self) -> Option<u16> {
        self.status
    }

    /// How long the provider asked the caller to wait before retrying.
    #[must_use]
    pub const fn retry_after(&self) -> Option<Duration> {
        self.retry_after
    }

    /// `true` if sending the same request again later may succeed (see
    /// [`LlmErrorKind::is_retryable`]).
    #[must_use]
    pub const fn is_retryable(&self) -> bool {
        self.kind.is_retryable()
    }

    /// `true` for [`LlmErrorKind::RateLimit`].
    #[must_use]
    pub fn is_rate_limit(&self) -> bool {
        self.kind == LlmErrorKind::RateLimit
    }

    /// `true` for [`LlmErrorKind::ContextLengthExceeded`].
    #[must_use]
    pub fn is_context_length_exceeded(&self) -> bool {
        self.kind == LlmErrorKind::ContextLengthExceeded
    }
}

/// Errors produced by a [`Tool`](crate::Tool) during execution.
#[derive(Debug, Error, Clone)]
pub enum ToolError {
    /// The input provided to the tool was invalid or could not be parsed.
    #[error("invalid input: {0}")]
    InvalidInput(String),
    /// The tool's operation failed at runtime.
    #[error("execution failed: {0}")]
    ExecutionFailed(String),
    /// Any error not covered by the variants above.
    #[error("{0}")]
    Other(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_classification() {
        use LlmErrorKind as K;
        for (status, kind) in [
            (400, K::InvalidRequest),
            (401, K::Auth),
            (403, K::Auth),
            (404, K::InvalidRequest),
            (408, K::Timeout),
            (413, K::InvalidRequest),
            (422, K::InvalidRequest),
            (429, K::RateLimit),
            (500, K::Server),
            (502, K::Server),
            (503, K::Overloaded),
            (504, K::Timeout),
            (529, K::Overloaded),
            (200, K::Provider),
            (302, K::Provider),
        ] {
            assert_eq!(K::from_status(status), kind, "{status}");
        }
    }

    #[test]
    fn builders_and_accessors() {
        let e = LlmError::provider("boom")
            .with_kind(LlmErrorKind::ContextLengthExceeded)
            .with_status(400)
            .with_retry_after(Duration::from_millis(5))
            .map_message(|m| m.to_uppercase());
        assert_eq!(e.kind(), LlmErrorKind::ContextLengthExceeded);
        assert_eq!(e.message(), "BOOM");
        assert_eq!(e.status(), Some(400));
        assert_eq!(e.retry_after(), Some(Duration::from_millis(5)));
        assert!(e.is_context_length_exceeded());
        assert!(!e.is_retryable());
        assert_eq!(e.to_string(), "context length exceeded: BOOM");
    }

    #[test]
    fn retryable_kinds() {
        assert!(LlmError::request_failed("reset").is_retryable());
        assert!(LlmError::timeout("slow").is_retryable());
        assert!(LlmError::from_status(500, "x").is_retryable());
        assert!(LlmError::from_status(429, "x").is_rate_limit());
        for e in [
            LlmError::provider("x"),
            LlmError::invalid_response("x"),
            LlmError::unsupported("x"),
            LlmError::other("x"),
            LlmError::from_status(401, "x"),
        ] {
            assert!(!e.is_retryable(), "{e}");
        }
    }

    #[test]
    fn converts_into_chain_error() {
        let chain: ChainError = LlmError::request_failed("down").into();
        assert_eq!(chain.to_string(), "LLM error: request failed: down");
    }
}
