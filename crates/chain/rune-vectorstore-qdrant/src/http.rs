//! HTTP transport: API key handling, retries, bounded bodies and error mapping.

use std::fmt;
use std::time::Duration;

use bytes::Bytes;
use futures::StreamExt;
use reqwest::header::{CONTENT_TYPE, HeaderValue};
use reqwest::{Method, StatusCode};
use rune_vectorstore::StoreError;
use serde_json::Value;

/// Longest error text kept in an error message.
const MAX_ERROR_CHARS: usize = 1024;
/// Longest error body read from the wire.
const MAX_ERROR_BODY_BYTES: usize = 64 << 10;
/// Longest server-requested wait honoured before giving up on a retry.
const MAX_RETRY_AFTER: Duration = Duration::from_secs(30);
const BASE_BACKOFF: Duration = Duration::from_millis(250);
const MAX_BACKOFF: Duration = Duration::from_secs(4);

/// An API key, sent as the `api-key` header. Never shown by `Debug` and
/// scrubbed from error messages.
#[derive(Clone)]
pub struct ApiKey(String);

impl ApiKey {
    pub fn new(key: impl Into<String>) -> Self {
        Self(key.into())
    }

    fn header(&self) -> Result<HeaderValue, StoreError> {
        let mut v = HeaderValue::from_str(&self.0).map_err(|_| {
            StoreError::Backend("API key contains characters not allowed in a header".into())
        })?;
        v.set_sensitive(true);
        Ok(v)
    }

    fn scrub(&self, text: &str) -> String {
        if self.0.len() < 4 {
            return text.to_owned();
        }
        text.replace(&self.0, "[REDACTED]")
    }
}

impl fmt::Debug for ApiKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

/// Everything needed to talk to one Qdrant server.
#[derive(Clone)]
pub struct Transport {
    pub base_url: String,
    pub api_key: Option<ApiKey>,
    pub client: reqwest::Client,
    pub timeout: Duration,
    pub max_retries: u32,
    pub max_response_bytes: usize,
}

impl fmt::Debug for Transport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Transport")
            .field("base_url", &self.base_url)
            .field("api_key", &self.api_key)
            .field("timeout", &self.timeout)
            .field("max_retries", &self.max_retries)
            .field("max_response_bytes", &self.max_response_bytes)
            .finish_non_exhaustive()
    }
}

/// A failed call: either the server answered with an error status, or the
/// request never completed.
#[derive(Debug)]
pub enum CallError {
    Status { status: u16, message: String },
    Store(StoreError),
}

impl CallError {
    /// `true` for Qdrant's "collection doesn't exist" answer.
    pub fn is_missing_collection(&self) -> bool {
        matches!(self, Self::Status { status: 404, message }
            if message.contains("Collection") || message.contains("collection"))
    }

    pub fn into_store(self) -> StoreError {
        match self {
            Self::Store(e) => e,
            Self::Status { status, message } => status_error(status, &message),
        }
    }
}

impl From<StoreError> for CallError {
    fn from(e: StoreError) -> Self {
        Self::Store(e)
    }
}

impl Transport {
    /// Send a request and return the parsed JSON body of a success.
    ///
    /// Every call this crate makes is idempotent (upserts carry fixed ids),
    /// so rate limits, 502/503/504 and connection failures are retried.
    pub async fn call(
        &self,
        method: Method,
        path: &str,
        body: Option<Bytes>,
    ) -> Result<Value, CallError> {
        let url = format!("{}{path}", self.base_url);
        let key = self.api_key.as_ref().map(ApiKey::header).transpose()?;
        let mut attempt = 0;
        loop {
            let mut req = self
                .client
                .request(method.clone(), &url)
                .timeout(self.timeout);
            if let Some(k) = &key {
                req = req.header("api-key", k.clone());
            }
            if let Some(b) = &body {
                req = req
                    .header(CONTENT_TYPE, HeaderValue::from_static("application/json"))
                    .body(b.clone());
            }
            let (wait, err) = match req.send().await {
                Ok(resp) if resp.status().is_success() => {
                    let bytes = read_capped(resp, self.max_response_bytes).await?;
                    return serde_json::from_slice(&bytes).map_err(|e| {
                        CallError::Store(StoreError::Backend(format!(
                            "qdrant sent invalid JSON: {e}"
                        )))
                    });
                }
                Ok(resp) => {
                    let status = resp.status();
                    let hint = retry_after(resp.headers());
                    let message = self.error_message(resp).await;
                    let wait = (retryable(status) && attempt < self.max_retries)
                        .then(|| backoff(attempt, hint))
                        .flatten();
                    (
                        wait,
                        CallError::Status {
                            status: status.as_u16(),
                            message,
                        },
                    )
                }
                Err(e) => {
                    let wait = (e.is_connect() && attempt < self.max_retries)
                        .then(|| backoff(attempt, None))
                        .flatten();
                    (wait, CallError::Store(self.transport_error(&e)))
                }
            };
            let Some(wait) = wait else { return Err(err) };
            tokio::time::sleep(wait).await;
            attempt += 1;
        }
    }

    /// Qdrant's `status.error` text, or the raw body, bounded and scrubbed.
    async fn error_message(&self, resp: reqwest::Response) -> String {
        let raw = read_lossy(resp).await;
        let text = serde_json::from_str::<Value>(&raw)
            .ok()
            .and_then(|v| {
                v.pointer("/status/error")
                    .and_then(Value::as_str)
                    .map(str::to_owned)
            })
            .unwrap_or(raw);
        self.sanitize(text.trim())
    }

    fn sanitize(&self, text: &str) -> String {
        let text = self
            .api_key
            .as_ref()
            .map_or_else(|| text.to_owned(), |k| k.scrub(text));
        match text.char_indices().nth(MAX_ERROR_CHARS) {
            None => text,
            Some((cut, _)) => format!("{}… [truncated]", &text[..cut]),
        }
    }

    fn transport_error(&self, e: &reqwest::Error) -> StoreError {
        use std::error::Error as _;
        let mut message = e.to_string();
        let mut source = e.source();
        while let Some(s) = source {
            message.push_str(": ");
            message.push_str(&s.to_string());
            source = s.source();
        }
        let what = if e.is_timeout() {
            "timed out"
        } else {
            "request failed"
        };
        StoreError::Backend(format!("qdrant {what}: {}", self.sanitize(&message)))
    }
}

/// Map an error status to a [`StoreError`]. Dimension errors become
/// [`StoreError::DimensionMismatch`]; everything else is a
/// [`StoreError::Backend`] naming the status.
pub fn status_error(status: u16, message: &str) -> StoreError {
    if let Some((expected, actual)) = parse_dimension_error(message) {
        return StoreError::DimensionMismatch { expected, actual };
    }
    let what = match status {
        400 | 422 => "rejected the request",
        401 | 403 => "refused the credentials",
        404 => "has no such resource",
        408 | 504 => "timed out",
        409 => "reported a conflict",
        413 => "found the request too large (lower max_batch_bytes)",
        429 => "is rate limiting",
        _ if status >= 500 => "failed",
        _ => "returned an error",
    };
    let message = if message.is_empty() {
        "(empty body)"
    } else {
        message
    };
    StoreError::Backend(format!("qdrant {what} (HTTP {status}): {message}"))
}

/// Qdrant reports `Wrong input: Vector dimension error: expected dim: 3, got 2`.
fn parse_dimension_error(message: &str) -> Option<(usize, usize)> {
    let rest = &message[message.find("expected dim:")? + "expected dim:".len()..];
    let (expected, rest) = rest.split_once(',')?;
    let actual = rest.trim_start().strip_prefix("got")?;
    let digits: String = actual
        .trim_start()
        .chars()
        .take_while(char::is_ascii_digit)
        .collect();
    Some((expected.trim().parse().ok()?, digits.parse().ok()?))
}

const fn retryable(status: StatusCode) -> bool {
    matches!(status.as_u16(), 429 | 502 | 503 | 504)
}

fn retry_after(headers: &reqwest::header::HeaderMap) -> Option<Duration> {
    let secs: f64 = headers
        .get("retry-after")?
        .to_str()
        .ok()?
        .trim()
        .parse()
        .ok()?;
    (secs.is_finite() && secs >= 0.0).then(|| Duration::from_secs_f64(secs.min(86_400.0)))
}

/// The wait before retry `attempt` (0-based): the server's hint when given,
/// else jittered exponential backoff. `None` when the server wants a longer
/// wait than we honour.
pub fn backoff(attempt: u32, hint: Option<Duration>) -> Option<Duration> {
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

async fn read_capped(resp: reqwest::Response, max: usize) -> Result<Vec<u8>, StoreError> {
    let too_large = |actual: u64| StoreError::LimitExceeded {
        what: "qdrant response size",
        limit: max as u64,
        actual,
    };
    if let Some(n) = resp.content_length()
        && usize::try_from(n).map_or(true, |n| n > max)
    {
        return Err(too_large(n));
    }
    let mut out = Vec::new();
    let mut body = resp.bytes_stream();
    while let Some(chunk) = body.next().await {
        let chunk = chunk.map_err(|e| {
            StoreError::Backend(format!("qdrant response failed: {}", e.without_url()))
        })?;
        let total = out.len().saturating_add(chunk.len());
        if total > max {
            return Err(too_large(total as u64));
        }
        out.extend_from_slice(&chunk);
    }
    Ok(out)
}

async fn read_lossy(resp: reqwest::Response) -> String {
    let mut out = Vec::new();
    let mut body = resp.bytes_stream();
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn api_key_is_redacted() {
        let k = ApiKey::new("secret-key-123");
        assert_eq!(format!("{k:?}"), "[REDACTED]");
        assert_eq!(k.scrub("bad secret-key-123!"), "bad [REDACTED]!");
        assert!(k.header().unwrap().is_sensitive());
        assert!(ApiKey::new("bad\nkey").header().is_err());
    }

    #[test]
    fn status_mapping() {
        assert_eq!(
            status_error(
                400,
                "Wrong input: Vector dimension error: expected dim: 3, got 2"
            ),
            StoreError::DimensionMismatch {
                expected: 3,
                actual: 2
            }
        );
        let e = status_error(401, "Invalid api-key").to_string();
        assert!(e.contains("credentials") && e.contains("401"), "{e}");
        let e = status_error(503, "").to_string();
        assert!(e.contains("failed") && e.contains("empty body"), "{e}");
        assert!(
            status_error(413, "x")
                .to_string()
                .contains("max_batch_bytes")
        );
        assert_eq!(parse_dimension_error("expected dim: x, got 2"), None);
        assert_eq!(parse_dimension_error("nothing here"), None);
    }

    #[test]
    fn retry_policy() {
        assert!(retryable(StatusCode::TOO_MANY_REQUESTS));
        assert!(retryable(StatusCode::SERVICE_UNAVAILABLE));
        assert!(!retryable(StatusCode::INTERNAL_SERVER_ERROR));
        assert!(!retryable(StatusCode::BAD_REQUEST));
        assert_eq!(
            backoff(0, Some(Duration::from_secs(2))),
            Some(Duration::from_secs(2))
        );
        assert_eq!(backoff(0, Some(Duration::from_secs(3600))), None);
        let d = backoff(40, None).unwrap();
        assert!(d <= MAX_BACKOFF && d >= MAX_BACKOFF * 3 / 4);
    }

    #[test]
    fn missing_collection_detection() {
        let e = CallError::Status {
            status: 404,
            message: "Not found: Collection `docs` doesn't exist!".into(),
        };
        assert!(e.is_missing_collection());
        let e = CallError::Status {
            status: 404,
            message: "Not found".into(),
        };
        assert!(!e.is_missing_collection());
    }
}
