//! Transport hardening: secret handling, origin checks, retries with
//! `retry-after`, bounded bodies and error-body sanitising.

use std::fmt;
use std::time::Duration;

use futures::StreamExt;
use reqwest::header::{HeaderMap, HeaderValue};
use rune_chain_core::LlmError;

use crate::types::ErrorResponse;

/// Longest error body text kept in an error message.
pub const MAX_ERROR_BODY_CHARS: usize = 1024;
/// Longest error body read from the wire.
const MAX_ERROR_BODY_BYTES: usize = 64 << 10;
/// Longest server-requested wait honoured before giving up on a retry.
const MAX_RETRY_AFTER: Duration = Duration::from_secs(60);
const BASE_BACKOFF: Duration = Duration::from_millis(500);
const MAX_BACKOFF: Duration = Duration::from_secs(8);

/// An API key that never appears in `Debug` output.
#[derive(Clone)]
pub struct ApiKey(String);

impl ApiKey {
    pub const fn new(key: String) -> Self {
        Self(key)
    }

    /// The `x-api-key` header value, marked sensitive so HTTP-layer logging
    /// redacts it too.
    pub fn header_value(&self) -> Result<HeaderValue, LlmError> {
        let mut value = HeaderValue::from_str(&self.0)
            .map_err(|_| LlmError::other("API key contains characters not allowed in a header"))?;
        value.set_sensitive(true);
        Ok(value)
    }

    /// Replace any occurrence of the key in `text`.
    pub fn scrub(&self, text: &str) -> String {
        if self.0.len() < 8 {
            return text.to_string();
        }
        text.replace(&self.0, "[REDACTED]")
    }
}

impl fmt::Debug for ApiKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ApiKey([REDACTED])")
    }
}

/// Require HTTPS, except for loopback hosts (local gateways, mock servers).
pub fn check_base_url(base_url: &str) -> Result<(), LlmError> {
    let url = reqwest::Url::parse(base_url)
        .map_err(|e| LlmError::other(format!("invalid base URL: {e}")))?;
    if !url.username().is_empty() || url.password().is_some() {
        return Err(LlmError::other("base URL must not embed credentials"));
    }
    match url.scheme() {
        "https" => Ok(()),
        "http" if is_loopback(&url) => Ok(()),
        "http" => Err(LlmError::other(
            "refusing to send the API key over plain HTTP; use an https:// base URL \
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

/// Whether a status is worth retrying: request timeout, conflict/lock,
/// rate limit, and every server error (including 529 overloaded).
pub const fn is_retryable(status: u16) -> bool {
    matches!(status, 408 | 409 | 429) || status >= 500
}

/// How long to wait before retry number `attempt` (0-based). `None` means
/// the server asked for a longer wait than we are willing to honour.
pub fn retry_delay(attempt: u32, headers: &HeaderMap) -> Option<Duration> {
    if let Some(wait) = retry_after(headers) {
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

/// `retry-after-ms` (milliseconds) or `retry-after` (seconds). HTTP-date
/// values are not interpreted.
fn retry_after(headers: &HeaderMap) -> Option<Duration> {
    let header = |name: &str| headers.get(name)?.to_str().ok()?.trim().parse::<f64>().ok();
    let valid = |v: f64| v.is_finite() && v >= 0.0;
    if let Some(ms) = header("retry-after-ms").filter(|v| valid(*v)) {
        return Some(Duration::from_secs_f64((ms / 1000.0).min(86_400.0)));
    }
    header("retry-after")
        .filter(|v| valid(*v))
        .map(|s| Duration::from_secs_f64(s.min(86_400.0)))
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
        let chunk = chunk.map_err(|e| LlmError::request_failed(e.to_string()))?;
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
/// body is an Anthropic error object, the raw body otherwise. The kind comes
/// from the status, refined by `error.type`; the status and any
/// `Retry-After` are recorded. Bodies are read up to a bound, truncated, and
/// scrubbed of the API key.
pub async fn error_from_response(response: reqwest::Response, key: &ApiKey) -> LlmError {
    let status = response.status().as_u16();
    let wait = retry_after(response.headers());
    let body = read_capped_lossy(response).await;
    let err = decode_error(status, &body, key);
    match wait {
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

/// Decode an error body (see [`error_from_response`]).
pub fn decode_error(status: u16, body: &str, key: &ApiKey) -> LlmError {
    match serde_json::from_str::<ErrorResponse>(body) {
        Ok(err) => {
            let message = sanitize(&err.error.message, key);
            let base = LlmError::from_status(status, message);
            match err.error.error_kind() {
                Some(kind) => base.with_kind(kind),
                None => base,
            }
        }
        Err(_) if body.trim().is_empty() => {
            LlmError::from_status(status, format!("HTTP {status} with an empty body"))
        }
        Err(_) => LlmError::from_status(status, sanitize(body, key)),
    }
}

/// Scrub the key and truncate to [`MAX_ERROR_BODY_CHARS`] characters.
pub fn sanitize(text: &str, key: &ApiKey) -> String {
    let text = key.scrub(text);
    match text.char_indices().nth(MAX_ERROR_BODY_CHARS) {
        None => text,
        Some((cut, _)) => format!("{}… [truncated]", &text[..cut]),
    }
}

/// Describe a transport error without echoing anything secret.
pub fn transport_error(e: &reqwest::Error, key: &ApiKey) -> LlmError {
    use std::error::Error as _;
    let mut message = e.to_string();
    let mut source = e.source();
    while let Some(s) = source {
        message.push_str(": ");
        message.push_str(&s.to_string());
        source = s.source();
    }
    let message = sanitize(&message, key);
    if e.is_timeout() {
        LlmError::timeout(message)
    } else {
        LlmError::request_failed(message)
    }
}
