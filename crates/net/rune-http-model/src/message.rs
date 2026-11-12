//! Requests and responses.

use crate::header::{has_header, header_value, header_values, remove_header, set_header};
use crate::{HeaderEntry, HttpBody, HttpVersion};

/// An HTTP request, recorded or about to be sent.
///
/// Every field is kept verbatim: the method is not upper-cased, the URL is
/// not parsed or normalised (it may be malformed on purpose) and headers
/// stay in wire order with duplicates.
///
/// ```
/// use rune_http_model::{HttpBody, HttpRequest};
///
/// let request = HttpRequest::new("POST", "https://api.example.test/login")
///     .with_header("Content-Type", "application/json")
///     .with_body(HttpBody::from_text(r#"{"user":"a"}"#));
/// assert_eq!(request.content_type(), Some("application/json"));
/// assert_eq!(request.parsed_url()?.path(), "/login");
/// # Ok::<(), rune_http_model::UrlParseError>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[non_exhaustive]
pub struct HttpRequest {
    /// Request method, verbatim (not normalised).
    pub method: String,
    /// Request target URL, verbatim. May be malformed on purpose.
    pub url: String,
    /// Protocol version.
    #[cfg_attr(feature = "serde", serde(default))]
    pub http_version: HttpVersion,
    /// Header fields in wire order.
    #[cfg_attr(feature = "serde", serde(default))]
    pub headers: Vec<HeaderEntry>,
    /// Request body.
    #[cfg_attr(feature = "serde", serde(default))]
    pub body: HttpBody,
    /// Exact request bytes as sent on the wire, when known.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub raw: Option<HttpBody>,
}

impl HttpRequest {
    /// Creates an HTTP/1.1 request with no headers and an empty body.
    #[must_use]
    pub fn new(method: impl Into<String>, url: impl Into<String>) -> Self {
        Self {
            method: method.into(),
            url: url.into(),
            http_version: HttpVersion::default(),
            headers: Vec::new(),
            body: HttpBody::empty(),
            raw: None,
        }
    }

    /// Creates a `GET` request.
    #[must_use]
    pub fn get(url: impl Into<String>) -> Self {
        Self::new("GET", url)
    }

    /// Creates a `POST` request.
    #[must_use]
    pub fn post(url: impl Into<String>) -> Self {
        Self::new("POST", url)
    }

    /// Appends a header.
    #[must_use]
    pub fn with_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.push(HeaderEntry::new(name, value));
        self
    }

    /// Appends several headers, keeping their order.
    #[must_use]
    pub fn with_headers<I, H>(mut self, headers: I) -> Self
    where
        I: IntoIterator<Item = H>,
        H: Into<HeaderEntry>,
    {
        self.headers.extend(headers.into_iter().map(Into::into));
        self
    }

    /// Sets the body.
    #[must_use]
    pub fn with_body(mut self, body: impl Into<HttpBody>) -> Self {
        self.body = body.into();
        self
    }

    /// Sets the protocol version.
    #[must_use]
    pub const fn with_version(mut self, version: HttpVersion) -> Self {
        self.http_version = version;
        self
    }

    /// Sets the exact wire bytes.
    #[must_use]
    pub fn with_raw(mut self, raw: impl Into<HttpBody>) -> Self {
        self.raw = Some(raw.into());
        self
    }

    /// Value of the first header called `name`, ignoring case.
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&str> {
        header_value(&self.headers, name)
    }

    /// Values of every header called `name`, ignoring case, in order.
    pub fn header_values<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a str> {
        header_values(&self.headers, name)
    }

    /// Whether a header called `name` is present, ignoring case.
    #[must_use]
    pub fn has_header(&self, name: &str) -> bool {
        has_header(&self.headers, name)
    }

    /// Sets `name` to a single value; see [`set_header`](crate::set_header).
    pub fn set_header(&mut self, name: &str, value: impl Into<String>) {
        set_header(&mut self.headers, name, value);
    }

    /// Removes every header called `name` and returns how many were removed.
    pub fn remove_header(&mut self, name: &str) -> usize {
        remove_header(&mut self.headers, name)
    }

    /// Value of the `Content-Type` header.
    #[must_use]
    pub fn content_type(&self) -> Option<&str> {
        self.header("content-type")
    }

    /// Parses the target URL.
    ///
    /// # Errors
    /// Returns the parse error when the URL is malformed.
    pub fn parsed_url(&self) -> Result<url::Url, url::ParseError> {
        url::Url::parse(&self.url)
    }
}

/// An HTTP response.
///
/// ```
/// use rune_http_model::HttpResponse;
///
/// let response = HttpResponse::new(302)
///     .with_reason("Found")
///     .with_header("Location", "/home");
/// assert!(response.is_redirect());
/// assert_eq!(response.header("location"), Some("/home"));
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[non_exhaustive]
pub struct HttpResponse {
    /// Status code. Kept as received, even outside 100–599.
    pub status: u16,
    /// Reason phrase, when the server sent one.
    #[cfg_attr(feature = "serde", serde(default))]
    pub reason: Option<String>,
    /// Protocol version.
    #[cfg_attr(feature = "serde", serde(default))]
    pub http_version: HttpVersion,
    /// Header fields in wire order.
    #[cfg_attr(feature = "serde", serde(default))]
    pub headers: Vec<HeaderEntry>,
    /// Response body.
    #[cfg_attr(feature = "serde", serde(default))]
    pub body: HttpBody,
    /// Exact response bytes as received on the wire, when known.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub raw: Option<HttpBody>,
}

impl HttpResponse {
    /// Creates an HTTP/1.1 response with no headers and an empty body.
    #[must_use]
    pub fn new(status: u16) -> Self {
        Self {
            status,
            reason: None,
            http_version: HttpVersion::default(),
            headers: Vec::new(),
            body: HttpBody::empty(),
            raw: None,
        }
    }

    /// Sets the reason phrase.
    #[must_use]
    pub fn with_reason(mut self, reason: impl Into<String>) -> Self {
        self.reason = Some(reason.into());
        self
    }

    /// Appends a header.
    #[must_use]
    pub fn with_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.push(HeaderEntry::new(name, value));
        self
    }

    /// Appends several headers, keeping their order.
    #[must_use]
    pub fn with_headers<I, H>(mut self, headers: I) -> Self
    where
        I: IntoIterator<Item = H>,
        H: Into<HeaderEntry>,
    {
        self.headers.extend(headers.into_iter().map(Into::into));
        self
    }

    /// Sets the body.
    #[must_use]
    pub fn with_body(mut self, body: impl Into<HttpBody>) -> Self {
        self.body = body.into();
        self
    }

    /// Sets the protocol version.
    #[must_use]
    pub const fn with_version(mut self, version: HttpVersion) -> Self {
        self.http_version = version;
        self
    }

    /// Sets the exact wire bytes.
    #[must_use]
    pub fn with_raw(mut self, raw: impl Into<HttpBody>) -> Self {
        self.raw = Some(raw.into());
        self
    }

    /// Value of the first header called `name`, ignoring case.
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&str> {
        header_value(&self.headers, name)
    }

    /// Values of every header called `name`, ignoring case, in order.
    pub fn header_values<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a str> {
        header_values(&self.headers, name)
    }

    /// Whether a header called `name` is present, ignoring case.
    #[must_use]
    pub fn has_header(&self, name: &str) -> bool {
        has_header(&self.headers, name)
    }

    /// Sets `name` to a single value; see [`set_header`](crate::set_header).
    pub fn set_header(&mut self, name: &str, value: impl Into<String>) {
        set_header(&mut self.headers, name, value);
    }

    /// Removes every header called `name` and returns how many were removed.
    pub fn remove_header(&mut self, name: &str) -> usize {
        remove_header(&mut self.headers, name)
    }

    /// Value of the `Content-Type` header.
    #[must_use]
    pub fn content_type(&self) -> Option<&str> {
        self.header("content-type")
    }

    /// Value of the `Location` header.
    #[must_use]
    pub fn location(&self) -> Option<&str> {
        self.header("location")
    }

    /// Whether the status is informational (1xx).
    #[must_use]
    pub const fn is_informational(&self) -> bool {
        matches!(self.status, 100..=199)
    }

    /// Whether the status is a success (2xx).
    #[must_use]
    pub const fn is_success(&self) -> bool {
        matches!(self.status, 200..=299)
    }

    /// Whether the status is a redirection (3xx).
    #[must_use]
    pub const fn is_redirect(&self) -> bool {
        matches!(self.status, 300..=399)
    }

    /// Whether the status is a client error (4xx).
    #[must_use]
    pub const fn is_client_error(&self) -> bool {
        matches!(self.status, 400..=499)
    }

    /// Whether the status is a server error (5xx).
    #[must_use]
    pub const fn is_server_error(&self) -> bool {
        matches!(self.status, 500..=599)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_builders_and_headers() {
        let mut request = HttpRequest::post("http://h/a")
            .with_headers([("Accept", "*/*"), ("X-A", "1")])
            .with_header("x-a", "2")
            .with_body("k=v")
            .with_version(HttpVersion::Http2)
            .with_raw(b"POST /a HTTP/2\r\n\r\n".to_vec());
        assert_eq!(request.method, "POST");
        assert_eq!(request.header_values("X-A").collect::<Vec<_>>(), ["1", "2"]);
        assert!(request.has_header("accept"));
        request.set_header("X-A", "3");
        assert_eq!(request.header_values("x-a").collect::<Vec<_>>(), ["3"]);
        assert_eq!(request.remove_header("accept"), 1);
        assert_eq!(request.content_type(), None);
        assert_eq!(request.body.as_utf8(), Some("k=v"));
        assert!(request.raw.is_some());
        assert_eq!(request.http_version, HttpVersion::Http2);
    }

    #[test]
    fn method_and_url_stay_verbatim() {
        let request = HttpRequest::new("pOsT", "::bad");
        assert_eq!(request.method, "pOsT");
        assert_eq!(request.url, "::bad");
        assert!(request.parsed_url().is_err());
        assert!(HttpRequest::get("http://h/").parsed_url().is_ok());
    }

    #[test]
    fn response_status_classes() {
        let classes = |status| {
            let response = HttpResponse::new(status);
            [
                response.is_informational(),
                response.is_success(),
                response.is_redirect(),
                response.is_client_error(),
                response.is_server_error(),
            ]
        };
        assert_eq!(classes(101), [true, false, false, false, false]);
        assert_eq!(classes(204), [false, true, false, false, false]);
        assert_eq!(classes(307), [false, false, true, false, false]);
        assert_eq!(classes(404), [false, false, false, true, false]);
        assert_eq!(classes(503), [false, false, false, false, true]);
        assert_eq!(classes(999), [false; 5]);
    }

    #[test]
    fn response_headers() {
        let mut response = HttpResponse::new(301)
            .with_header("CONTENT-TYPE", "x/y")
            .with_headers([HeaderEntry::new("Location", "/b")]);
        assert_eq!(response.content_type(), Some("x/y"));
        assert_eq!(response.location(), Some("/b"));
        response.set_header("content-type", "text/html");
        assert_eq!(
            response.headers[0],
            HeaderEntry::new("CONTENT-TYPE", "text/html")
        );
        assert_eq!(response.remove_header("location"), 1);
        assert!(!response.has_header("location"));
    }
}
