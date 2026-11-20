//! Transport hardening: credentials, origin checks, retries honouring
//! `Retry-After` and `RetryInfo`, bounded bodies and error sanitising.

use std::fmt;
use std::time::Duration;

use futures::StreamExt;
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE, HeaderMap, HeaderName, HeaderValue};
use rune_chain_core::{LlmError, LlmErrorKind};
use serde::Serialize;
use serde_json::Value;

/// Longest error text kept in an error message.
pub const MAX_ERROR_BODY_CHARS: usize = 1024;
/// Longest error body read from the wire.
const MAX_ERROR_BODY_BYTES: usize = 64 << 10;
/// Longest server-requested wait honoured before giving up on a retry.
const MAX_RETRY_AFTER: Duration = Duration::from_secs(60);
const BASE_BACKOFF: Duration = Duration::from_millis(500);
const MAX_BACKOFF: Duration = Duration::from_secs(8);
const API_KEY_HEADER: &str = "x-goog-api-key";

/// Default number of retries after a retryable failure (HTTP 408, 429,
/// 5xx, or a connection error).
pub const DEFAULT_MAX_RETRIES: u32 = 2;
/// Default total timeout of a blocking request.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(600);
/// Default connect timeout of the built-in HTTP client.
pub const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
/// Default cap on a blocking response body.
pub const DEFAULT_MAX_RESPONSE_BYTES: usize = 32 << 20;

/// How requests authenticate. Neither form ever appears in `Debug` output
/// or error messages, and neither is ever put in a URL.
#[derive(Clone)]
pub enum Credential {
    /// Gemini API key, sent as `x-goog-api-key`.
    ApiKey(String),
    /// OAuth access token (Vertex AI), sent as `Authorization: Bearer`.
    Bearer(String),
}

impl Credential {
    fn secret(&self) -> &str {
        match self {
            Self::ApiKey(s) | Self::Bearer(s) => s,
        }
    }

    /// The header carrying the credential, marked sensitive so HTTP-layer
    /// logging redacts it too.
    pub fn header(&self) -> Result<(HeaderName, HeaderValue), LlmError> {
        let (name, raw) = match self {
            Self::ApiKey(key) => (HeaderName::from_static(API_KEY_HEADER), key.clone()),
            Self::Bearer(token) => (AUTHORIZATION, format!("Bearer {token}")),
        };
        let mut value = HeaderValue::from_str(&raw).map_err(|_| {
            LlmError::other("credential contains characters not allowed in a header")
        })?;
        value.set_sensitive(true);
        Ok((name, value))
    }

    /// Replace any occurrence of the secret in `text`.
    pub fn scrub(&self, text: &str) -> String {
        let secret = self.secret();
        if secret.len() < 8 {
            return text.to_string();
        }
        text.replace(secret, "[REDACTED]")
    }
}

impl fmt::Debug for Credential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ApiKey(_) => f.write_str("ApiKey([REDACTED])"),
            Self::Bearer(_) => f.write_str("Bearer([REDACTED])"),
        }
    }
}

fn default_http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .connect_timeout(DEFAULT_CONNECT_TIMEOUT)
        .read_timeout(DEFAULT_TIMEOUT)
        // Never follow redirects: reqwest keeps custom headers such as
        // `x-goog-api-key` on a cross-origin redirect, and a redirect could
        // also downgrade to plain HTTP.
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap_or_default()
}

/// Connection settings shared by the chat client and the embedder.
#[derive(Clone)]
pub struct Transport {
    pub credential: Credential,
    pub base_url: String,
    pub client: reqwest::Client,
    pub max_retries: u32,
    pub timeout: Duration,
    pub max_response_bytes: usize,
}

impl fmt::Debug for Transport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Transport")
            .field("credential", &self.credential)
            .field("base_url", &self.base_url)
            .field("max_retries", &self.max_retries)
            .field("timeout", &self.timeout)
            .field("max_response_bytes", &self.max_response_bytes)
            .finish_non_exhaustive()
    }
}

impl Transport {
    pub fn new(credential: Credential, base_url: &str) -> Self {
        Self {
            credential,
            base_url: base_url.trim_end_matches('/').to_string(),
            client: default_http_client(),
            max_retries: DEFAULT_MAX_RETRIES,
            timeout: DEFAULT_TIMEOUT,
            max_response_bytes: DEFAULT_MAX_RESPONSE_BYTES,
        }
    }

    /// `true` when talking to Vertex AI (bearer-token auth).
    #[cfg(feature = "embed")]
    pub const fn is_bearer(&self) -> bool {
        matches!(self.credential, Credential::Bearer(_))
    }

    /// The URL of `method` on `model`, e.g. `…/models/gemini-2.5-flash:generateContent`.
    pub fn model_url(&self, model: &str, method: &str) -> Result<String, LlmError> {
        check_base_url(&self.base_url)?;
        check_model_id(model)?;
        Ok(format!("{}/models/{model}:{method}", self.base_url))
    }

    /// POST `body` to `url`, retrying retryable failures. Returns the
    /// successful response with its body unread.
    pub async fn send<B: Serialize + Sync>(
        &self,
        url: &str,
        body: &B,
        streaming: bool,
    ) -> Result<reqwest::Response, LlmError> {
        let payload = serde_json::to_vec(body)
            .map_err(|e| LlmError::other(format!("failed to encode request: {e}")))?;
        let (auth_name, auth_value) = self.credential.header()?;
        let mut attempt = 0;
        loop {
            let mut request = self
                .client
                .post(url)
                .header(auth_name.clone(), auth_value.clone())
                .header(CONTENT_TYPE, HeaderValue::from_static("application/json"))
                .body(payload.clone());
            if !streaming {
                request = request.timeout(self.timeout);
            }
            let (retry_wait, error) = match request.send().await {
                Ok(response) if response.status().is_success() => return Ok(response),
                Ok(response) => {
                    let status = response.status().as_u16();
                    let error = error_from_response(response, &self.credential).await;
                    let wait = (is_retryable(status) && attempt < self.max_retries)
                        .then(|| retry_delay(attempt, error.retry_after()))
                        .flatten();
                    (wait, error)
                }
                Err(e) => {
                    let wait = (e.is_connect() && attempt < self.max_retries)
                        .then(|| retry_delay(attempt, None))
                        .flatten();
                    (wait, transport_error(&e, &self.credential))
                }
            };
            let Some(wait) = retry_wait else {
                return Err(error);
            };
            tokio::time::sleep(wait).await;
            attempt += 1;
        }
    }

    /// [`send`](Self::send) a blocking request and read its size-capped body.
    pub async fn post_json<B: Serialize + Sync>(
        &self,
        url: &str,
        body: &B,
    ) -> Result<Vec<u8>, LlmError> {
        let response = self.send(url, body, false).await?;
        read_capped(response, self.max_response_bytes).await
    }
}

/// Require HTTPS, except for loopback hosts (local gateways, mock servers),
/// and a plain origin-and-path base URL.
pub fn check_base_url(base_url: &str) -> Result<(), LlmError> {
    let url = reqwest::Url::parse(base_url)
        .map_err(|e| LlmError::other(format!("invalid base URL: {e}")))?;
    if !url.username().is_empty() || url.password().is_some() {
        return Err(LlmError::other("base URL must not embed credentials"));
    }
    if url.query().is_some() || url.fragment().is_some() {
        return Err(LlmError::other(
            "base URL must not have a query or fragment",
        ));
    }
    match url.scheme() {
        "https" => Ok(()),
        "http" if is_loopback(&url) => Ok(()),
        "http" => Err(LlmError::other(
            "refusing to send credentials over plain HTTP; use an https:// base URL \
             (http:// is allowed only for localhost)",
        )),
        other => Err(LlmError::other(format!(
            "unsupported base URL scheme `{other}`"
        ))),
    }
}

fn is_loopback(url: &reqwest::Url) -> bool {
    let Some(host) = url.host_str() else {
        return false;
    };
    let host = host.trim_start_matches('[').trim_end_matches(']');
    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback())
}

/// Longest model id accepted.
const MAX_MODEL_ID_LEN: usize = 128;

/// A model id goes into the URL path, so only plain id characters pass.
pub fn check_model_id(model: &str) -> Result<(), LlmError> {
    let ok = !model.is_empty()
        && model.len() <= MAX_MODEL_ID_LEN
        && model
            .bytes()
            .next()
            .is_some_and(|b| b.is_ascii_alphanumeric())
        && model
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_'));
    if ok {
        Ok(())
    } else {
        Err(LlmError::other(
            "invalid model id: use letters, digits, '-', '.' and '_' only (e.g. `gemini-2.5-flash`)",
        ))
    }
}

/// Whether a status is worth retrying: request timeout, rate limit and
/// every server error.
pub const fn is_retryable(status: u16) -> bool {
    matches!(status, 408 | 429) || status >= 500
}

/// How long to wait before retry number `attempt` (0-based): the server's
/// hint when given, else jittered exponential backoff. `None` means the
/// server asked for a longer wait than we are willing to honour.
pub fn retry_delay(attempt: u32, hint: Option<Duration>) -> Option<Duration> {
    if let Some(wait) = hint {
        return (wait <= MAX_RETRY_AFTER).then_some(wait);
    }
    let exp = BASE_BACKOFF
        .saturating_mul(1u32.checked_shl(attempt.min(16)).unwrap_or(u32::MAX))
        .min(MAX_BACKOFF);
    // Jitter in [75 %, 100 %] without a RNG dependency.
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.subsec_nanos());
    let pct = 75 + u64::from(nanos % 26);
    let ms = u64::try_from(exp.as_millis()).unwrap_or(u64::MAX);
    Some(Duration::from_millis(ms.saturating_mul(pct) / 100))
}

/// `Retry-After` in seconds (HTTP-date values are not interpreted).
fn retry_after_header(headers: &HeaderMap) -> Option<Duration> {
    let secs = headers
        .get("retry-after")?
        .to_str()
        .ok()?
        .trim()
        .parse::<f64>()
        .ok()?;
    duration_secs(secs)
}

fn duration_secs(secs: f64) -> Option<Duration> {
    (secs.is_finite() && secs >= 0.0).then(|| Duration::from_secs_f64(secs.min(86_400.0)))
}

/// Read a body, failing once it exceeds `max` bytes.
pub async fn read_capped(response: reqwest::Response, max: usize) -> Result<Vec<u8>, LlmError> {
    if response
        .content_length()
        .is_some_and(|n| usize::try_from(n).map_or(true, |n| n > max))
    {
        return Err(too_large(max));
    }
    let mut out = Vec::new();
    let mut body = response.bytes_stream();
    while let Some(chunk) = body.next().await {
        let chunk = chunk.map_err(|e| LlmError::request_failed(e.without_url().to_string()))?;
        if out.len().saturating_add(chunk.len()) > max {
            return Err(too_large(max));
        }
        out.extend_from_slice(&chunk);
    }
    Ok(out)
}

fn too_large(max: usize) -> LlmError {
    LlmError::invalid_response(format!("response body exceeds the {max}-byte limit"))
}

/// Map a non-success response to an error: the provider's message when the
/// body is a Google API error object, the raw body otherwise. The kind comes
/// from the status, refined by `error.status`, `ErrorInfo.reason` and the
/// message; the HTTP status and the retry hint (`Retry-After`, else
/// `RetryInfo.retryDelay`) are recorded. Bodies are read up to a bound,
/// truncated, and scrubbed of the credential.
pub async fn error_from_response(response: reqwest::Response, credential: &Credential) -> LlmError {
    let status = response.status().as_u16();
    let header_wait = retry_after_header(response.headers());
    let body = read_capped_lossy(response).await;
    let err = decode_error(status, &body, credential);
    match header_wait {
        Some(wait) => err.with_retry_after(wait),
        None => err,
    }
}

async fn read_capped_lossy(response: reqwest::Response) -> String {
    let mut out = Vec::new();
    let mut body = response.bytes_stream();
    while let Some(chunk) = body.next().await {
        let Ok(chunk) = chunk else { break };
        let room = MAX_ERROR_BODY_BYTES.saturating_sub(out.len());
        out.extend_from_slice(&chunk[..chunk.len().min(room)]);
        if room <= chunk.len() {
            break;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Decode an error body (see [`error_from_response`]). Google APIs answer
/// with `{"error": {...}}`, and the streaming endpoint sometimes with a
/// one-element array of it.
pub fn decode_error(status: u16, body: &str, credential: &Credential) -> LlmError {
    let parsed = serde_json::from_str::<Value>(body).ok();
    let error = parsed.as_ref().and_then(|v| match v {
        Value::Array(items) => items.first()?.get("error"),
        other => other.get("error"),
    });
    match error {
        Some(error) => {
            let err = api_error(error, credential).with_status(status);
            if err.kind() == LlmErrorKind::Provider {
                err.with_kind(LlmErrorKind::from_status(status))
            } else {
                err
            }
        }
        None if body.trim().is_empty() => {
            LlmError::from_status(status, format!("HTTP {status} with an empty body"))
        }
        None => LlmError::from_status(status, sanitize(body, credential)),
    }
}

/// The portable error for a Google API error object (`error.code`,
/// `error.message`, `error.status`, `error.details`), without an HTTP status.
pub fn api_error(error: &Value, credential: &Credential) -> LlmError {
    let message = error
        .get("message")
        .and_then(Value::as_str)
        .unwrap_or("unknown error");
    let status = error.get("status").and_then(Value::as_str).unwrap_or("");
    let details = error
        .get("details")
        .and_then(Value::as_array)
        .map_or(&[][..], Vec::as_slice);
    let kind = error_kind(status, message, details).unwrap_or(LlmErrorKind::Provider);
    let err = LlmError::new(kind, sanitize(message, credential));
    match retry_info(details) {
        Some(wait) => err.with_retry_after(wait),
        None => err,
    }
}

/// Classify by `ErrorInfo.reason`, the message wording and `error.status`;
/// `None` when they say nothing beyond the HTTP status.
fn error_kind(status: &str, message: &str, details: &[Value]) -> Option<LlmErrorKind> {
    let reason = |want: &str| {
        details
            .iter()
            .any(|d| d.get("reason").and_then(Value::as_str) == Some(want))
    };
    let lower = message.to_ascii_lowercase();
    if reason("API_KEY_INVALID") || lower.contains("api key not valid") {
        return Some(LlmErrorKind::Auth);
    }
    if lower.contains("input token count")
        || lower.contains("exceeds the maximum number of tokens")
        || lower.contains("context window")
    {
        return Some(LlmErrorKind::ContextLengthExceeded);
    }
    Some(match status {
        "RESOURCE_EXHAUSTED" => LlmErrorKind::RateLimit,
        "UNAVAILABLE" => LlmErrorKind::Overloaded,
        "DEADLINE_EXCEEDED" => LlmErrorKind::Timeout,
        "UNAUTHENTICATED" | "PERMISSION_DENIED" => LlmErrorKind::Auth,
        "INVALID_ARGUMENT" | "FAILED_PRECONDITION" | "NOT_FOUND" | "OUT_OF_RANGE" => {
            LlmErrorKind::InvalidRequest
        }
        "INTERNAL" | "UNKNOWN" | "DATA_LOSS" => LlmErrorKind::Server,
        _ => return None,
    })
}

/// `RetryInfo.retryDelay` (a protobuf duration such as `"36s"` or `"1.5s"`).
fn retry_info(details: &[Value]) -> Option<Duration> {
    details.iter().find_map(|d| {
        let kind = d.get("@type").and_then(Value::as_str)?;
        if !kind.ends_with("google.rpc.RetryInfo") {
            return None;
        }
        let delay = d.get("retryDelay").and_then(Value::as_str)?;
        let secs = delay.strip_suffix('s')?.parse::<f64>().ok()?;
        duration_secs(secs)
    })
}

/// Scrub the credential and truncate to [`MAX_ERROR_BODY_CHARS`] characters.
pub fn sanitize(text: &str, credential: &Credential) -> String {
    let text = credential.scrub(text);
    match text.char_indices().nth(MAX_ERROR_BODY_CHARS) {
        None => text,
        Some((cut, _)) => format!("{}… [truncated]", &text[..cut]),
    }
}

/// Describe a transport error without echoing anything secret.
pub fn transport_error(e: &reqwest::Error, credential: &Credential) -> LlmError {
    use std::error::Error as _;
    let mut message = e.to_string();
    let mut source = e.source();
    while let Some(s) = source {
        message.push_str(": ");
        message.push_str(&s.to_string());
        source = s.source();
    }
    let message = sanitize(&message, credential);
    if e.is_timeout() {
        LlmError::timeout(message)
    } else {
        LlmError::request_failed(message)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "tests")]

    use super::*;

    fn key() -> Credential {
        Credential::ApiKey("AIzaSy-secret-key-123".into())
    }

    #[test]
    fn credential_is_redacted_everywhere() {
        let k = key();
        assert_eq!(format!("{k:?}"), "ApiKey([REDACTED])");
        assert_eq!(
            format!("{:?}", Credential::Bearer("ya29.token-abcdef".into())),
            "Bearer([REDACTED])"
        );
        assert_eq!(
            k.scrub("bad key AIzaSy-secret-key-123!"),
            "bad key [REDACTED]!"
        );
        let (name, value) = k.header().unwrap();
        assert_eq!(name.as_str(), "x-goog-api-key");
        assert!(value.is_sensitive());
        let (name, value) = Credential::Bearer("tok".into()).header().unwrap();
        assert_eq!(name, AUTHORIZATION);
        assert_eq!(value.to_str().unwrap(), "Bearer tok");
        assert!(Credential::ApiKey("bad\nkey".into()).header().is_err());
    }

    #[test]
    fn base_url_rules() {
        assert!(check_base_url("https://generativelanguage.googleapis.com/v1beta").is_ok());
        assert!(check_base_url("http://127.0.0.1:8080/v1beta").is_ok());
        assert!(check_base_url("http://[::1]:8080").is_ok());
        assert!(check_base_url("http://example.com/v1beta").is_err());
        assert!(check_base_url("https://u:p@example.com").is_err());
        assert!(check_base_url("https://example.com/v1?key=x").is_err());
        assert!(check_base_url("ftp://example.com").is_err());
        assert!(check_base_url("not a url").is_err());
    }

    #[test]
    fn model_ids_cannot_escape_the_path() {
        assert!(check_model_id("gemini-2.5-flash").is_ok());
        assert!(check_model_id("gemini-3-pro-preview").is_ok());
        for bad in [
            "",
            "../files",
            "a/b",
            "m?x=1",
            "m#f",
            "m:streamGenerateContent",
            "-x",
            "m%2F",
            "m n",
        ] {
            assert!(check_model_id(bad).is_err(), "{bad}");
        }
        assert!(check_model_id(&"a".repeat(129)).is_err());
    }

    #[test]
    fn decodes_google_errors() {
        let k = key();
        let body = r#"{"error":{"code":429,"message":"Quota exceeded","status":"RESOURCE_EXHAUSTED",
            "details":[{"@type":"type.googleapis.com/google.rpc.RetryInfo","retryDelay":"36s"}]}}"#;
        let e = decode_error(429, body, &k);
        assert_eq!(e.kind(), LlmErrorKind::RateLimit);
        assert_eq!(e.status(), Some(429));
        assert_eq!(e.message(), "Quota exceeded");
        assert_eq!(e.retry_after(), Some(Duration::from_secs(36)));

        let body = r#"{"error":{"code":400,"message":"API key not valid. Please pass a valid API key.","status":"INVALID_ARGUMENT",
            "details":[{"@type":"type.googleapis.com/google.rpc.ErrorInfo","reason":"API_KEY_INVALID"}]}}"#;
        assert_eq!(decode_error(400, body, &k).kind(), LlmErrorKind::Auth);

        let body = r#"[{"error":{"code":400,"message":"The input token count (2000000) exceeds the maximum number of tokens allowed (1048576).","status":"INVALID_ARGUMENT"}}]"#;
        assert_eq!(
            decode_error(400, body, &k).kind(),
            LlmErrorKind::ContextLengthExceeded
        );

        let body =
            r#"{"error":{"code":503,"message":"The model is overloaded.","status":"UNAVAILABLE"}}"#;
        assert_eq!(decode_error(503, body, &k).kind(), LlmErrorKind::Overloaded);

        let body = r#"{"error":{"code":418,"message":"odd","status":"SOMETHING_NEW"}}"#;
        assert_eq!(decode_error(418, body, &k).kind(), LlmErrorKind::Provider);
        let body = r#"{"error":{"code":500,"message":"odd","status":"SOMETHING_NEW"}}"#;
        assert_eq!(decode_error(500, body, &k).kind(), LlmErrorKind::Server);

        let e = decode_error(502, "<html>bad gateway</html>", &k);
        assert_eq!(e.kind(), LlmErrorKind::Server);
        assert_eq!(e.message(), "<html>bad gateway</html>");
        assert!(decode_error(500, "  ", &k).message().contains("empty body"));
    }

    #[test]
    fn error_text_is_scrubbed_and_truncated() {
        let k = key();
        let body = format!(
            r#"{{"error":{{"message":"key AIzaSy-secret-key-123 {}","status":"INVALID_ARGUMENT"}}}}"#,
            "x".repeat(5000)
        );
        let e = decode_error(400, &body, &k);
        assert!(!e.message().contains("AIzaSy-secret-key-123"));
        assert!(e.message().ends_with("… [truncated]"));
        assert!(e.message().chars().count() < MAX_ERROR_BODY_CHARS + 20);
    }

    #[test]
    fn retry_hints() {
        let mut headers = HeaderMap::new();
        headers.insert("retry-after", HeaderValue::from_static("2"));
        assert_eq!(retry_after_header(&headers), Some(Duration::from_secs(2)));
        headers.insert("retry-after", HeaderValue::from_static("-1"));
        assert_eq!(retry_after_header(&headers), None);
        headers.insert("retry-after", HeaderValue::from_static("NaN"));
        assert_eq!(retry_after_header(&headers), None);

        assert_eq!(
            retry_delay(0, Some(Duration::from_secs(3))),
            Some(Duration::from_secs(3))
        );
        assert_eq!(retry_delay(0, Some(Duration::from_secs(3600))), None);
        let d = retry_delay(30, None).unwrap();
        assert!(d <= MAX_BACKOFF && d >= MAX_BACKOFF * 3 / 4);

        let details = [serde_json::json!({
            "@type": "type.googleapis.com/google.rpc.RetryInfo",
            "retryDelay": "1.5s"
        })];
        assert_eq!(retry_info(&details), Some(Duration::from_millis(1500)));
        let details = [serde_json::json!({
            "@type": "type.googleapis.com/google.rpc.RetryInfo",
            "retryDelay": "1e400s"
        })];
        assert_eq!(retry_info(&details), None);
    }

    #[test]
    fn retryable_statuses() {
        for s in [408, 429, 500, 502, 503, 504] {
            assert!(is_retryable(s), "{s}");
        }
        for s in [400, 401, 403, 404, 409, 413] {
            assert!(!is_retryable(s), "{s}");
        }
    }
}
