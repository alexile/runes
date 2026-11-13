//! Shared HTTP transport for the providers: secret redaction, URL policy,
//! bounded body reads, truncated errors, timeouts and retries.

use std::fmt;
use std::time::Duration;

use futures::StreamExt;
use reqwest::StatusCode;
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE, HeaderMap, HeaderValue};
use serde::Serialize;

use crate::EmbedError;

/// Default whole-request timeout, per attempt; see the providers' `timeout`.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(60);
/// TCP/TLS connect timeout of the default HTTP client.
pub const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Default retries after a 429, a 5xx, a timeout or a connection failure.
pub const DEFAULT_MAX_RETRIES: u32 = 2;
/// Default response-size cap (64 MiB); see the providers' `max_response_bytes`.
pub const DEFAULT_MAX_RESPONSE_BYTES: usize = 64 << 20;
/// Default number of requests a provider keeps in flight when a batch is
/// split into several requests.
pub const DEFAULT_MAX_CONCURRENCY: usize = 4;
/// Longest server-requested `Retry-After` the client waits for; a longer one
/// is returned as the error instead.
pub const MAX_RETRY_AFTER: Duration = Duration::from_secs(60);
/// Longest error-body excerpt kept in an error message, in characters.
pub const MAX_ERROR_CHARS: usize = 512;
/// Most bytes read from an error body.
const MAX_ERROR_BODY: usize = 64 * 1024;
/// Cap on computed exponential backoff.
const MAX_BACKOFF: Duration = Duration::from_secs(8);
const DEFAULT_RETRY_DELAY: Duration = Duration::from_millis(500);

/// An API key whose `Debug` output never shows the secret.
#[derive(Clone, Default)]
pub struct ApiKey(String);

impl ApiKey {
    pub fn new(key: impl Into<String>) -> Self {
        Self(key.into())
    }

    pub const fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    #[cfg(test)]
    pub fn expose(&self) -> &str {
        &self.0
    }

    /// Replace every occurrence of the key in `text` with `[REDACTED]`.
    /// Keys shorter than 8 bytes are not scrubbed (too likely to match
    /// ordinary text, and not real secrets).
    pub fn scrub(&self, text: String) -> String {
        if self.0.len() >= 8 && text.contains(&self.0) {
            text.replace(&self.0, "[REDACTED]")
        } else {
            text
        }
    }

    fn header(&self) -> Result<HeaderValue, EmbedError> {
        let mut value = HeaderValue::from_str(&format!("Bearer {}", self.0)).map_err(|_| {
            EmbedError::InvalidConfig(
                "the API key contains characters not allowed in a header".into(),
            )
        })?;
        value.set_sensitive(true);
        Ok(value)
    }
}

impl fmt::Debug for ApiKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.0.is_empty() {
            f.write_str("ApiKey(<none>)")
        } else {
            f.write_str("ApiKey([REDACTED])")
        }
    }
}

fn default_http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .connect_timeout(DEFAULT_CONNECT_TIMEOUT)
        // Never follow redirects: one could downgrade to plain HTTP or send
        // the request to a host the caller did not choose.
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap_or_default()
}

/// Whether plain HTTP to `host` is acceptable without an explicit allowance.
pub fn is_loopback_host(host: &str) -> bool {
    let host = host.trim_start_matches('[').trim_end_matches(']');
    host.eq_ignore_ascii_case("localhost")
        || host.to_ascii_lowercase().ends_with(".localhost")
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback())
}

/// Parse `url` and enforce the transport policy: `https`, or `http` to a
/// loopback host or a host in `allowed_http_hosts`.
pub fn check_url(url: &str, allowed_http_hosts: &[String]) -> Result<reqwest::Url, EmbedError> {
    let parsed = reqwest::Url::parse(url)
        .map_err(|e| EmbedError::InvalidConfig(format!("invalid base URL: {e}")))?;
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(EmbedError::InvalidConfig(
            "base URL must not embed credentials; use the API key".into(),
        ));
    }
    let host = parsed.host_str().unwrap_or_default();
    match parsed.scheme() {
        "https" => Ok(parsed),
        "http"
            if is_loopback_host(host)
                || allowed_http_hosts
                    .iter()
                    .any(|h| h.eq_ignore_ascii_case(host)) =>
        {
            Ok(parsed)
        }
        "http" => Err(EmbedError::InvalidConfig(format!(
            "refusing plain HTTP to `{host}`: the API key would travel unencrypted; \
             use https or allow the host with `.allow_http_host(\"{host}\")`"
        ))),
        other => Err(EmbedError::InvalidConfig(format!(
            "unsupported base URL scheme `{other}`"
        ))),
    }
}

/// Truncate to at most `max` characters, marking the cut.
pub fn truncate(text: &str, max: usize) -> String {
    let text = text.trim();
    match text.char_indices().nth(max) {
        Some((cut, _)) => format!("{}… [truncated]", &text[..cut]),
        None => text.to_string(),
    }
}

/// Read a body of at most `limit` bytes. With `truncate_at_limit` the read
/// stops quietly at the limit (for error bodies); otherwise exceeding it is
/// an error.
async fn read_body(
    response: reqwest::Response,
    limit: usize,
    truncate_at_limit: bool,
) -> Result<Vec<u8>, EmbedError> {
    let too_big =
        || EmbedError::InvalidResponse(format!("response body exceeds the {limit}-byte limit"));
    if !truncate_at_limit
        && response
            .content_length()
            .is_some_and(|len| len > limit as u64)
    {
        return Err(too_big());
    }
    let mut body = Vec::new();
    let mut chunks = response.bytes_stream();
    while let Some(chunk) = chunks.next().await {
        let chunk = chunk.map_err(|e| EmbedError::RequestFailed(e.without_url().to_string()))?;
        if body.len() + chunk.len() > limit {
            if truncate_at_limit {
                body.extend_from_slice(&chunk[..limit - body.len()]);
                break;
            }
            return Err(too_big());
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

/// The server's requested delay: `retry-after-ms`, else `Retry-After` in
/// (possibly fractional) seconds. HTTP-date values are not interpreted.
pub fn retry_after(headers: &HeaderMap) -> Option<Duration> {
    let get = |name: &str| {
        headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.trim().parse::<f64>().ok())
            .filter(|v| v.is_finite() && *v >= 0.0)
    };
    // A value too large for a `Duration` saturates (and is then refused as
    // longer than `MAX_RETRY_AFTER`) instead of panicking.
    let secs = |s: f64| Duration::try_from_secs_f64(s).unwrap_or(Duration::MAX);
    get("retry-after-ms")
        .map(|ms| secs(ms / 1000.0))
        .or_else(|| get("retry-after").map(secs))
}

/// Exponential backoff `base · 2^attempt`, capped at 8 s, plus up to 25 %
/// jitter.
fn backoff(attempt: u32, base: Duration) -> Duration {
    let backoff = base.saturating_mul(1 << attempt.min(16)).min(MAX_BACKOFF);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.subsec_nanos());
    backoff + backoff.mul_f64(f64::from(nanos % 1000) / 4000.0)
}

/// Delay before retry number `attempt` (0-based): the server's `Retry-After`
/// when present (`None` if it exceeds [`MAX_RETRY_AFTER`]), else [`backoff`].
fn retry_delay(headers: &HeaderMap, attempt: u32, base: Duration) -> Option<Duration> {
    retry_after(headers).map_or_else(
        || Some(backoff(attempt, base)),
        |wait| (wait <= MAX_RETRY_AFTER).then_some(wait),
    )
}

/// Whether a status is worth retrying: 429 and 5xx.
fn is_retryable(status: StatusCode) -> bool {
    status == StatusCode::TOO_MANY_REQUESTS || status.is_server_error()
}

/// Map a non-success body to an error. JSON error shapes understood:
/// `{"error":{"message":…}}` (`OpenAI`, Jina), `{"error":"…"}`,
/// `{"message":"…"}` (Cohere) and `{"detail":"…"}` (Voyage, Jina).
/// Anything else keeps the raw body. Both are truncated.
fn decode_error(status: StatusCode, body: &[u8]) -> EmbedError {
    let message = serde_json::from_slice::<serde_json::Value>(body)
        .ok()
        .and_then(|v| {
            let s = |v: Option<&serde_json::Value>| v.and_then(|v| v.as_str()).map(str::to_owned);
            s(v.pointer("/error/message"))
                .or_else(|| s(v.get("error")))
                .or_else(|| s(v.get("message")))
                .or_else(|| s(v.get("detail")))
        });
    let code = status.as_u16();
    message.map_or_else(
        || {
            EmbedError::RequestFailed(format!(
                "HTTP {code}: {}",
                truncate(&String::from_utf8_lossy(body), MAX_ERROR_CHARS)
            ))
        },
        |m| EmbedError::ProviderError(format!("{} (HTTP {code})", truncate(&m, MAX_ERROR_CHARS))),
    )
}

/// Connection settings shared by every provider.
#[derive(Debug, Clone)]
pub struct Transport {
    pub api_key: ApiKey,
    pub base_url: String,
    pub allowed_http_hosts: Vec<String>,
    pub timeout: Option<Duration>,
    pub max_retries: u32,
    pub retry_delay: Duration,
    pub max_response_bytes: usize,
    pub max_batch_size: usize,
    pub max_concurrency: usize,
    pub client: reqwest::Client,
}

impl Transport {
    pub fn new(api_key: impl Into<String>, base_url: &str, max_batch_size: usize) -> Self {
        Self {
            api_key: ApiKey::new(api_key),
            base_url: base_url.to_string(),
            allowed_http_hosts: Vec::new(),
            timeout: Some(DEFAULT_TIMEOUT),
            max_retries: DEFAULT_MAX_RETRIES,
            retry_delay: DEFAULT_RETRY_DELAY,
            max_response_bytes: DEFAULT_MAX_RESPONSE_BYTES,
            max_batch_size,
            max_concurrency: DEFAULT_MAX_CONCURRENCY,
            client: default_http_client(),
        }
    }

    /// The endpoint URL `base_url + path`, checked against the URL policy.
    pub fn url(&self, path: &str) -> Result<reqwest::Url, EmbedError> {
        check_url(
            &format!("{}{path}", self.base_url),
            &self.allowed_http_hosts,
        )
    }

    fn scrub(&self, err: EmbedError) -> EmbedError {
        let s = |m: String| self.api_key.scrub(m);
        match err {
            EmbedError::RequestFailed(m) => EmbedError::RequestFailed(s(m)),
            EmbedError::ProviderError(m) => EmbedError::ProviderError(s(m)),
            EmbedError::InvalidResponse(m) => EmbedError::InvalidResponse(s(m)),
            EmbedError::InvalidConfig(m) => EmbedError::InvalidConfig(s(m)),
            EmbedError::Other(m) => EmbedError::Other(s(m)),
            other @ EmbedError::DimensionMismatch { .. } => other,
        }
    }

    /// POST `body` as JSON to `path`, retrying 429/5xx (honouring
    /// `Retry-After`), timeouts and connection failures; returns the
    /// size-capped success body.
    pub async fn post_json(
        &self,
        path: &str,
        body: &(impl Serialize + Sync),
    ) -> Result<Vec<u8>, EmbedError> {
        self.post_json_inner(path, body)
            .await
            .map_err(|e| self.scrub(e))
    }

    async fn post_json_inner(
        &self,
        path: &str,
        body: &(impl Serialize + Sync),
    ) -> Result<Vec<u8>, EmbedError> {
        let url = self.url(path)?;
        let payload = serde_json::to_vec(body)
            .map_err(|e| EmbedError::Other(format!("encode request: {e}")))?;
        let auth = if self.api_key.is_empty() {
            None
        } else {
            Some(self.api_key.header()?)
        };
        let mut attempt = 0;
        loop {
            let mut req = self
                .client
                .post(url.clone())
                .header(CONTENT_TYPE, "application/json")
                .body(payload.clone());
            if let Some(t) = self.timeout {
                req = req.timeout(t);
            }
            if let Some(auth) = &auth {
                req = req.header(AUTHORIZATION, auth.clone());
            }
            let response = match req.send().await {
                Ok(response) => response,
                Err(e) if (e.is_timeout() || e.is_connect()) && attempt < self.max_retries => {
                    tokio::time::sleep(backoff(attempt, self.retry_delay)).await;
                    attempt += 1;
                    continue;
                }
                Err(e) => return Err(EmbedError::RequestFailed(e.without_url().to_string())),
            };
            let status = response.status();
            if status.is_success() {
                return read_body(response, self.max_response_bytes, false).await;
            }
            if is_retryable(status)
                && attempt < self.max_retries
                && let Some(delay) = retry_delay(response.headers(), attempt, self.retry_delay)
            {
                drop(response);
                tokio::time::sleep(delay).await;
                attempt += 1;
                continue;
            }
            let body = read_body(response, MAX_ERROR_BODY, true)
                .await
                .unwrap_or_default();
            return Err(decode_error(status, &body));
        }
    }
}

/// Builder methods shared by every HTTP provider (a struct with a
/// `transport: Transport` field).
macro_rules! transport_builders {
    ($ty:ty, $default_base:expr) => {
        impl $ty {
            #[doc = concat!("Set the API base URL (default [`", stringify!($default_base), "`]), e.g. a")]
            /// proxy, a compatible server, or a local mock server in tests.
            /// The endpoint path is appended; a trailing slash is ignored.
            ///
            /// The URL is checked when a request is made: it must be `https`,
            /// or `http` to a loopback host (`localhost`, `127.0.0.1`, `[::1]`)
            /// or to a host allowed with
            /// [`allow_http_host`](Self::allow_http_host). Otherwise requests
            /// fail with [`EmbedError::InvalidConfig`](crate::EmbedError::InvalidConfig).
            #[must_use]
            pub fn base_url(mut self, url: impl Into<String>) -> Self {
                self.transport.base_url = url.into().trim_end_matches('/').to_string();
                self
            }

            /// Allow plain HTTP to `host` (e.g. a server on a private
            /// network). The API key then travels unencrypted.
            #[must_use]
            pub fn allow_http_host(mut self, host: impl Into<String>) -> Self {
                self.transport.allowed_http_hosts.push(host.into());
                self
            }

            /// Whole-request timeout per attempt (default
            /// [`DEFAULT_TIMEOUT`](crate::DEFAULT_TIMEOUT)); overrides any
            /// timeout on a custom [`http_client`](Self::http_client).
            #[must_use]
            pub const fn timeout(mut self, timeout: std::time::Duration) -> Self {
                self.transport.timeout = Some(timeout);
                self
            }

            /// Retries after a 429, a 5xx, a timeout or a connection failure
            /// (default [`DEFAULT_MAX_RETRIES`](crate::DEFAULT_MAX_RETRIES);
            /// `0` disables). A `Retry-After` / `retry-after-ms` header is
            /// honoured up to [`MAX_RETRY_AFTER`](crate::MAX_RETRY_AFTER);
            /// otherwise the wait is exponential backoff with jitter.
            #[must_use]
            pub const fn max_retries(mut self, retries: u32) -> Self {
                self.transport.max_retries = retries;
                self
            }

            /// Base delay of the exponential backoff (default 500 ms).
            #[must_use]
            pub const fn retry_base_delay(mut self, delay: std::time::Duration) -> Self {
                self.transport.retry_delay = delay;
                self
            }

            /// Largest accepted response body in bytes (default
            /// [`DEFAULT_MAX_RESPONSE_BYTES`](crate::DEFAULT_MAX_RESPONSE_BYTES)).
            /// A larger response fails with
            /// [`EmbedError::InvalidResponse`](crate::EmbedError::InvalidResponse).
            #[must_use]
            pub const fn max_response_bytes(mut self, bytes: usize) -> Self {
                self.transport.max_response_bytes = bytes;
                self
            }

            /// Most inputs sent in one request; a larger batch is split into
            /// several requests whose results are concatenated in input order.
            /// `0` makes every request fail with
            /// [`EmbedError::InvalidConfig`](crate::EmbedError::InvalidConfig).
            #[must_use]
            pub const fn max_batch_size(mut self, size: usize) -> Self {
                self.transport.max_batch_size = size;
                self
            }

            /// Most requests in flight at once when a batch is split (default
            /// [`DEFAULT_MAX_CONCURRENCY`](crate::DEFAULT_MAX_CONCURRENCY)).
            #[must_use]
            pub const fn max_concurrency(mut self, requests: usize) -> Self {
                self.transport.max_concurrency = requests;
                self
            }

            /// Use a preconfigured HTTP client (proxies, TLS settings). The
            /// default client has a connect timeout and does not follow
            /// redirects; consider doing the same.
            #[must_use]
            pub fn http_client(mut self, client: reqwest::Client) -> Self {
                self.transport.client = client;
                self
            }

            async fn batched<'a, F, Fut>(
                &'a self,
                texts: &'a [&'a str],
                expected_dims: Option<usize>,
                f: F,
            ) -> Result<Vec<Vec<f32>>, crate::EmbedError>
            where
                F: FnMut(&'a [&'a str]) -> Fut,
                Fut: std::future::Future<Output = Result<Vec<Vec<f32>>, crate::EmbedError>>,
            {
                let vectors = crate::batch::run_batched(
                    texts,
                    self.transport.max_batch_size,
                    self.transport.max_concurrency,
                    f,
                )
                .await?;
                crate::check_dimensions(&vectors, expected_dims)?;
                Ok(vectors)
            }
        }
    };
}

pub(crate) use transport_builders;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn api_key_debug_is_redacted() {
        let key = ApiKey::new("sk-secret-123456");
        assert_eq!(format!("{key:?}"), "ApiKey([REDACTED])");
        assert_eq!(format!("{:?}", ApiKey::default()), "ApiKey(<none>)");
        assert_eq!(
            key.scrub("bad key sk-secret-123456!".into()),
            "bad key [REDACTED]!"
        );
        assert_eq!(ApiKey::new("short").scrub("short".into()), "short");
        assert!(ApiKey::new("bad\nkey").header().is_err());
        assert!(key.header().unwrap().is_sensitive());
    }

    #[test]
    fn url_policy() {
        let ok = |u: &str| check_url(u, &[]).is_ok();
        assert!(ok("https://api.openai.com/v1"));
        assert!(ok("http://localhost:8000/v1"));
        assert!(ok("http://127.0.0.1:1/v1"));
        assert!(ok("http://[::1]:1/v1"));
        assert!(ok("http://foo.localhost/v1"));
        assert!(!ok("http://10.0.0.5:8000/v1"));
        assert!(!ok("http://localhost.evil.com/v1"));
        assert!(!ok("ftp://example.com"));
        assert!(!ok("https://user:pw@example.com"));
        assert!(!ok("not a url"));
        assert!(check_url("http://gpu-box:8000/v1", &["GPU-box".into()]).is_ok());
        assert!(matches!(
            check_url("http://example.com", &[]),
            Err(EmbedError::InvalidConfig(_))
        ));
    }

    #[test]
    fn truncation_is_char_safe() {
        assert_eq!(truncate("  short ", 10), "short");
        let t = truncate(&"é".repeat(600), MAX_ERROR_CHARS);
        assert!(t.ends_with("[truncated]"));
        assert_eq!(t.chars().filter(|c| *c == 'é').count(), MAX_ERROR_CHARS);
    }

    #[test]
    fn retry_after_parsing() {
        let mut h = HeaderMap::new();
        assert_eq!(retry_after(&h), None);
        h.insert("retry-after", HeaderValue::from_static("2"));
        assert_eq!(retry_after(&h), Some(Duration::from_secs(2)));
        h.insert("retry-after-ms", HeaderValue::from_static("250"));
        assert_eq!(retry_after(&h), Some(Duration::from_millis(250)));
        let mut long = HeaderMap::new();
        long.insert("retry-after", HeaderValue::from_static("3600"));
        assert_eq!(retry_delay(&long, 0, Duration::ZERO), None);
        let mut date = HeaderMap::new();
        date.insert(
            "retry-after",
            HeaderValue::from_static("Wed, 21 Oct 2015 07:28:00 GMT"),
        );
        assert_eq!(retry_after(&date), None);
        let d = retry_delay(&date, 2, Duration::from_millis(100)).unwrap();
        assert!(d >= Duration::from_millis(400) && d <= Duration::from_millis(500));
        let capped = backoff(30, Duration::from_secs(1));
        assert!(capped <= MAX_BACKOFF + MAX_BACKOFF / 4);
    }

    #[test]
    fn huge_retry_after_does_not_panic() {
        for (name, value) in [
            ("retry-after", "1e300"),
            ("retry-after-ms", "1e300"),
            ("retry-after", "18446744073709551616"),
        ] {
            let mut h = HeaderMap::new();
            h.insert(name, HeaderValue::from_static(value));
            assert!(retry_after(&h).is_some_and(|d| d > MAX_RETRY_AFTER));
            assert_eq!(retry_delay(&h, 0, Duration::ZERO), None);
        }
    }

    #[test]
    fn retryable_statuses() {
        assert!(is_retryable(StatusCode::TOO_MANY_REQUESTS));
        assert!(is_retryable(StatusCode::BAD_GATEWAY));
        assert!(!is_retryable(StatusCode::BAD_REQUEST));
        assert!(!is_retryable(StatusCode::UNAUTHORIZED));
    }

    #[test]
    fn error_shapes() {
        let pe = |body: &str| match decode_error(StatusCode::BAD_REQUEST, body.as_bytes()) {
            EmbedError::ProviderError(m) => m,
            other => panic!("{other:?}"),
        };
        assert_eq!(pe(r#"{"error":{"message":"bad"}}"#), "bad (HTTP 400)");
        assert_eq!(pe(r#"{"error":"bad"}"#), "bad (HTTP 400)");
        assert_eq!(pe(r#"{"message":"bad"}"#), "bad (HTTP 400)");
        assert_eq!(pe(r#"{"detail":"bad"}"#), "bad (HTTP 400)");
        assert!(matches!(
            decode_error(StatusCode::BAD_GATEWAY, b"oops"),
            EmbedError::RequestFailed(m) if m == "HTTP 502: oops"
        ));
        let long = "x".repeat(10_000);
        let EmbedError::RequestFailed(m) = decode_error(StatusCode::BAD_GATEWAY, long.as_bytes())
        else {
            panic!()
        };
        assert!(m.len() < 600 && m.ends_with("[truncated]"));
    }
}
