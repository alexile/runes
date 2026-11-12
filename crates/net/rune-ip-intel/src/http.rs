//! The HTTP boundary: requests the providers build, responses they read,
//! and the [`Transport`] trait a caller implements to move bytes between
//! them.

use std::fmt;
use std::time::Duration;

use rune_secret_ref::SecretValue;

use crate::Error;

/// HTTP request method.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Method {
    /// `GET`.
    Get,
    /// `POST`.
    Post,
}

impl Method {
    /// The method name as sent on the wire.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Post => "POST",
        }
    }
}

impl fmt::Display for Method {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A request header value: plain text, or a secret that `Debug` redacts.
#[derive(Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum HeaderValue {
    /// A value safe to log, such as `application/json`.
    Plain(String),
    /// A credential, such as an API key.
    Secret(SecretValue),
}

impl HeaderValue {
    /// The value to put on the wire. Never log it.
    #[must_use]
    pub fn expose(&self) -> &str {
        match self {
            Self::Plain(value) => value,
            Self::Secret(value) => value.expose(),
        }
    }

    /// Whether the value is a secret.
    #[must_use]
    pub const fn is_secret(&self) -> bool {
        matches!(self, Self::Secret(_))
    }
}

impl fmt::Debug for HeaderValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Plain(value) => fmt::Debug::fmt(value, f),
            Self::Secret(value) => fmt::Debug::fmt(value, f),
        }
    }
}

/// An HTTP request a provider built, for a [`Transport`] to send.
///
/// Credentials travel only in [`HeaderValue::Secret`] headers, never in
/// the URL, so the URL is safe to log; `Debug` redacts secret headers.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct HttpRequest {
    /// Request method.
    pub method: Method,
    /// Absolute `https` URL.
    pub url: String,
    /// Headers in order. Compare names case-insensitively.
    pub headers: Vec<(String, HeaderValue)>,
    /// Request body (empty for every built-in provider).
    pub body: Vec<u8>,
}

impl HttpRequest {
    /// A `GET` request with no headers.
    #[must_use]
    pub fn get(url: impl Into<String>) -> Self {
        Self {
            method: Method::Get,
            url: url.into(),
            headers: Vec::new(),
            body: Vec::new(),
        }
    }

    /// Appends a plain header.
    #[must_use]
    pub fn with_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers
            .push((name.into(), HeaderValue::Plain(value.into())));
        self
    }

    /// Appends a secret header.
    #[must_use]
    pub fn with_secret_header(mut self, name: impl Into<String>, value: SecretValue) -> Self {
        self.headers.push((name.into(), HeaderValue::Secret(value)));
        self
    }

    /// The first header with this name, compared case-insensitively.
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&HeaderValue> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value)
    }
}

/// An HTTP response a [`Transport`] received.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct HttpResponse {
    /// Status code.
    pub status: u16,
    /// Response headers in order.
    pub headers: Vec<(String, String)>,
    /// Response body. Transports should cap its size (a few hundred KiB
    /// covers every provider answer).
    pub body: Vec<u8>,
}

impl HttpResponse {
    /// A response with this status, no headers and an empty body.
    #[must_use]
    pub const fn new(status: u16) -> Self {
        Self {
            status,
            headers: Vec::new(),
            body: Vec::new(),
        }
    }

    /// Appends a header.
    #[must_use]
    pub fn with_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }

    /// Sets the body.
    #[must_use]
    pub fn with_body(mut self, body: impl Into<Vec<u8>>) -> Self {
        self.body = body.into();
        self
    }

    /// The first header with this name, compared case-insensitively.
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    /// Whether the status is 2xx.
    #[must_use]
    pub const fn is_success(&self) -> bool {
        self.status >= 200 && self.status < 300
    }

    /// The `Retry-After` header as a number of seconds (the HTTP-date form
    /// is not read).
    #[must_use]
    pub fn retry_after(&self) -> Option<Duration> {
        let value = self.header("retry-after")?.trim();
        if let Ok(secs) = value.parse::<u64>() {
            return Some(Duration::from_secs(secs));
        }
        Duration::try_from_secs_f64(value.parse::<f64>().ok()?).ok()
    }
}

/// A failure inside a [`Transport`]: no HTTP response was received.
///
/// Its message must not contain secret headers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransportError {
    message: String,
    retryable: bool,
}

impl TransportError {
    /// A failure that may go away on its own (refused connection, timeout).
    #[must_use]
    pub fn retryable(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            retryable: true,
        }
    }

    /// A failure that will repeat (bad TLS configuration, unsupported
    /// scheme).
    #[must_use]
    pub fn permanent(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            retryable: false,
        }
    }

    /// The description of the failure.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }

    /// Whether a later attempt may succeed.
    #[must_use]
    pub const fn is_retryable(&self) -> bool {
        self.retryable
    }
}

impl fmt::Display for TransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for TransportError {}

impl From<TransportError> for Error {
    fn from(error: TransportError) -> Self {
        Self::Transport {
            message: error.message,
            retryable: error.retryable,
        }
    }
}

/// Sends an [`HttpRequest`] and returns the [`HttpResponse`].
///
/// The crate has no HTTP client and does no I/O: wrap the client you
/// already use (`ureq`, `reqwest::blocking`, a test double). Apply a
/// timeout and a body-size cap. Any closure
/// `Fn(&HttpRequest) -> Result<HttpResponse, TransportError>` is a
/// transport.
///
/// Async callers can skip this trait and drive a provider with
/// [`ReputationProvider::request`](crate::ReputationProvider::request) and
/// [`ReputationProvider::parse`](crate::ReputationProvider::parse).
pub trait Transport {
    /// Sends one request.
    ///
    /// # Errors
    ///
    /// A [`TransportError`] when no response was received. Any HTTP status,
    /// including 4xx and 5xx, is a successful `send`.
    fn send(&self, request: &HttpRequest) -> Result<HttpResponse, TransportError>;
}

impl<F> Transport for F
where
    F: Fn(&HttpRequest) -> Result<HttpResponse, TransportError>,
{
    fn send(&self, request: &HttpRequest) -> Result<HttpResponse, TransportError> {
        self(request)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_redacts_secret_headers() {
        let request = HttpRequest::get("https://api.example/check")
            .with_header("Accept", "application/json")
            .with_secret_header("Key", SecretValue::new("s3cr3t"));
        let debug = format!("{request:?}");
        assert!(!debug.contains("s3cr3t"));
        assert!(debug.contains("application/json"));
        assert_eq!(
            request.header("key").map(HeaderValue::expose),
            Some("s3cr3t")
        );
        assert!(request.header("KEY").is_some_and(HeaderValue::is_secret));
    }

    #[test]
    fn retry_after_reads_seconds() {
        let r = HttpResponse::new(429).with_header("Retry-After", "7");
        assert_eq!(r.retry_after(), Some(Duration::from_secs(7)));
        let r = HttpResponse::new(429).with_header("retry-after", "0.5");
        assert_eq!(r.retry_after(), Some(Duration::from_millis(500)));
        let r = HttpResponse::new(429).with_header("Retry-After", "Wed, 21 Oct 2015");
        assert_eq!(r.retry_after(), None);
        assert_eq!(HttpResponse::new(429).retry_after(), None);
    }
}
