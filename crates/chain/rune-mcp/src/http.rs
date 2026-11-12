//! [`HttpClientConfig`]: a checked Streamable HTTP endpoint for
//! [`McpClient::connect_http`](crate::McpClient::connect_http)
//! (`http-client` feature).

use std::collections::HashMap;
use std::fmt;

use http::{HeaderName, HeaderValue, Uri};
use rmcp::transport::streamable_http_client::StreamableHttpClientTransportConfig;

use crate::Error;

/// Headers a caller may not set: the transport owns them.
const RESERVED_HEADERS: &[&str] = &[
    "host",
    "content-length",
    "content-type",
    "transfer-encoding",
    "connection",
    "mcp-session-id",
    "mcp-protocol-version",
];

/// Where and how to reach a remote MCP server over Streamable HTTP.
///
/// - The URL must be `https://`, or `http://` to a loopback host
///   (`localhost`, `*.localhost`, `127.0.0.0/8`, `::1`); other plain-HTTP
///   URLs are refused unless [`allow_insecure_http`](Self::allow_insecure_http)
///   is set. URLs with user info (`user:pass@`) are refused: use
///   [`with_bearer_token`](Self::with_bearer_token) or a header instead.
/// - The bearer token and every custom header value are secrets to `Debug`
///   and show as `[REDACTED]`.
///
/// ```
/// use rune_mcp::HttpClientConfig;
///
/// let config = HttpClientConfig::new("https://mcp.example.com/mcp")
///     .with_bearer_token("sk-123")
///     .with_header("x-tenant", "acme");
/// assert!(config.validate().is_ok());
/// assert!(!format!("{config:?}").contains("sk-123"));
///
/// assert!(HttpClientConfig::new("http://mcp.example.com/mcp").validate().is_err());
/// assert!(HttpClientConfig::new("http://127.0.0.1:8080/mcp").validate().is_ok());
/// ```
#[derive(Clone)]
pub struct HttpClientConfig {
    url: String,
    bearer_token: Option<String>,
    headers: Vec<(String, String)>,
    allow_insecure_http: bool,
}

impl fmt::Debug for HttpClientConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpClientConfig")
            .field("url", &self.url)
            .field(
                "bearer_token",
                &self.bearer_token.as_ref().map(|_| "[REDACTED]"),
            )
            .field(
                "headers",
                &self
                    .headers
                    .iter()
                    .map(|(name, _)| (name.as_str(), "[REDACTED]"))
                    .collect::<Vec<_>>(),
            )
            .field("allow_insecure_http", &self.allow_insecure_http)
            .finish()
    }
}

/// Whether `host` is a loopback name or address.
fn is_loopback_host(host: &str) -> bool {
    let host = host.trim_start_matches('[').trim_end_matches(']');
    host.eq_ignore_ascii_case("localhost")
        || host.to_ascii_lowercase().ends_with(".localhost")
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback())
}

impl HttpClientConfig {
    /// An endpoint URL, such as `https://mcp.example.com/mcp`.
    #[must_use]
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            bearer_token: None,
            headers: Vec::new(),
            allow_insecure_http: false,
        }
    }

    /// Send `Authorization: Bearer <token>` with every request.
    #[must_use]
    pub fn with_bearer_token(mut self, token: impl Into<String>) -> Self {
        self.bearer_token = Some(token.into());
        self
    }

    /// Send a custom header (an API key header, a tenant id) with every
    /// request. Checked by [`validate`](Self::validate).
    #[must_use]
    pub fn with_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }

    /// Allow plain HTTP to a non-loopback host (default: refused). Only for
    /// a trusted network: the token and every result travel in clear text.
    #[must_use]
    pub const fn allow_insecure_http(mut self, allow: bool) -> Self {
        self.allow_insecure_http = allow;
        self
    }

    /// The endpoint URL.
    #[must_use]
    pub fn url(&self) -> &str {
        &self.url
    }

    /// Check the URL and headers.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidConfig`] naming the problem (never a secret value).
    pub fn validate(&self) -> Result<(), Error> {
        self.parts().map(drop)
    }

    fn parts(&self) -> Result<HashMap<HeaderName, HeaderValue>, Error> {
        let invalid = |msg: String| Error::InvalidConfig(msg);
        let uri: Uri = self
            .url
            .parse()
            .map_err(|err| invalid(format!("invalid URL: {err}")))?;
        let host = uri
            .host()
            .ok_or_else(|| invalid("the URL has no host".to_owned()))?;
        if uri
            .authority()
            .is_some_and(|authority| authority.as_str().contains('@'))
        {
            return Err(invalid(
                "credentials in the URL are not allowed; use a bearer token or header".to_owned(),
            ));
        }
        match uri.scheme_str() {
            Some("https") => {}
            Some("http") if self.allow_insecure_http || is_loopback_host(host) => {}
            Some("http") => {
                return Err(invalid(format!(
                    "plain HTTP to {host} is refused; use https:// (or allow_insecure_http)"
                )));
            }
            _ => return Err(invalid("the URL must be http:// or https://".to_owned())),
        }
        let mut headers = HashMap::new();
        for (name, value) in &self.headers {
            let header = HeaderName::from_bytes(name.as_bytes())
                .map_err(|_| invalid(format!("invalid header name {name:?}")))?;
            if RESERVED_HEADERS.contains(&header.as_str()) || header == http::header::AUTHORIZATION
            {
                return Err(invalid(format!(
                    "header {name:?} is set by the transport{}",
                    if header == http::header::AUTHORIZATION {
                        "; use with_bearer_token"
                    } else {
                        ""
                    }
                )));
            }
            let mut value = HeaderValue::from_str(value)
                .map_err(|_| invalid(format!("invalid value for header {name:?}")))?;
            value.set_sensitive(true);
            headers.insert(header, value);
        }
        if let Some(token) = &self.bearer_token
            && HeaderValue::from_str(token).is_err()
        {
            return Err(invalid(
                "the bearer token is not a valid header value".to_owned(),
            ));
        }
        Ok(headers)
    }

    /// The rmcp transport configuration, after [`validate`](Self::validate).
    ///
    /// # Errors
    ///
    /// As [`Self::validate`].
    pub fn to_transport_config(&self) -> Result<StreamableHttpClientTransportConfig, Error> {
        let headers = self.parts()?;
        let mut config = StreamableHttpClientTransportConfig::with_uri(self.url.as_str())
            .custom_headers(headers);
        if let Some(token) = &self.bearer_token {
            config = config.auth_header(token.clone());
        }
        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urls() {
        for ok in [
            "https://example.com/mcp",
            "http://localhost:3000/mcp",
            "http://mcp.localhost/mcp",
            "http://127.0.0.2/mcp",
            "http://[::1]:8080/mcp",
        ] {
            assert!(HttpClientConfig::new(ok).validate().is_ok(), "{ok}");
        }
        for bad in [
            "http://example.com/mcp",
            "http://localhost.evil.com/mcp",
            "ftp://example.com/",
            "https://user:pass@example.com/mcp",
            "/relative",
            "not a url",
        ] {
            assert!(HttpClientConfig::new(bad).validate().is_err(), "{bad}");
        }
        assert!(
            HttpClientConfig::new("http://10.0.0.1/mcp")
                .allow_insecure_http(true)
                .validate()
                .is_ok()
        );
    }

    #[test]
    fn headers_are_checked_and_redacted() {
        let base = HttpClientConfig::new("https://example.com/mcp");
        assert!(
            base.clone()
                .with_header("authorization", "x")
                .validate()
                .is_err()
        );
        assert!(base.clone().with_header("Host", "x").validate().is_err());
        assert!(
            base.clone()
                .with_header("bad name", "x")
                .validate()
                .is_err()
        );
        assert!(
            base.clone()
                .with_header("x-key", "a\nb")
                .validate()
                .is_err()
        );
        assert!(base.clone().with_bearer_token("a\nb").validate().is_err());

        let config = base
            .with_bearer_token("tok-SECRET")
            .with_header("x-api-key", "key-SECRET");
        let shown = format!("{config:?}");
        assert!(!shown.contains("SECRET"), "{shown}");
        assert!(shown.contains("x-api-key"));

        let transport = config.to_transport_config().unwrap();
        assert_eq!(transport.auth_header.as_deref(), Some("tok-SECRET"));
        let value = &transport.custom_headers[&HeaderName::from_static("x-api-key")];
        assert!(value.is_sensitive());
    }
}
