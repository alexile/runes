//! Transport hardening: secret redaction, URL policy, bounded body reads,
//! error truncation and retry timing.

use std::fmt;
use std::time::Duration;

use futures::StreamExt;
use reqwest::header::HeaderMap;
use rune_chain_core::LlmError;

/// Longest error-body excerpt kept in an error message, in characters.
pub const MAX_ERROR_CHARS: usize = 512;
/// Most bytes read from an error body.
pub const MAX_ERROR_BODY: usize = 64 * 1024;
/// Longest `Retry-After` the client waits for; a longer one is returned as
/// the error instead.
pub const MAX_RETRY_AFTER: Duration = Duration::from_secs(60);
/// Cap on computed exponential backoff.
const MAX_BACKOFF: Duration = Duration::from_secs(8);

/// An API key whose `Debug` output never shows the secret.
#[derive(Clone, Default)]
pub struct ApiKey(String);

impl ApiKey {
    pub fn new(key: impl Into<String>) -> Self {
        Self(key.into())
    }

    pub fn expose(&self) -> &str {
        &self.0
    }

    pub const fn is_empty(&self) -> bool {
        self.0.is_empty()
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
pub fn check_url(url: &str, allowed_http_hosts: &[String]) -> Result<reqwest::Url, LlmError> {
    let parsed =
        reqwest::Url::parse(url).map_err(|e| LlmError::other(format!("invalid base URL: {e}")))?;
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(LlmError::other(
            "base URL must not embed credentials; use the API key",
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
        "http" => Err(LlmError::other(format!(
            "refusing plain HTTP to `{host}`: the API key would travel unencrypted; \
             use https or allow the host with `.allow_http_host(\"{host}\")`"
        ))),
        other => Err(LlmError::other(format!(
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
pub async fn read_body(
    response: reqwest::Response,
    limit: usize,
    truncate_at_limit: bool,
) -> Result<Vec<u8>, LlmError> {
    let too_big =
        || LlmError::invalid_response(format!("response body exceeds the {limit}-byte limit"));
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
        let chunk = chunk.map_err(|e| LlmError::request_failed(e.without_url().to_string()))?;
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

/// The server's requested delay: `retry-after-ms` (`OpenAI`), else
/// `Retry-After` in (possibly fractional) seconds. HTTP-date values are not
/// interpreted.
pub fn retry_after(headers: &HeaderMap) -> Option<Duration> {
    let get = |name: &str| {
        headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.trim().parse::<f64>().ok())
            .filter(|v| v.is_finite() && *v >= 0.0)
    };
    get("retry-after-ms")
        .map(|ms| Duration::from_secs_f64(ms / 1000.0))
        .or_else(|| get("retry-after").map(Duration::from_secs_f64))
}

/// Delay before retry number `attempt` (0-based): the server's
/// `Retry-After` when present (`None` if it exceeds [`MAX_RETRY_AFTER`]),
/// else `base · 2^attempt` capped at 8 s, plus up to 25 % jitter.
pub fn retry_delay(headers: &HeaderMap, attempt: u32, base: Duration) -> Option<Duration> {
    if let Some(wait) = retry_after(headers) {
        return (wait <= MAX_RETRY_AFTER).then_some(wait);
    }
    let backoff = base.saturating_mul(1 << attempt.min(16)).min(MAX_BACKOFF);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.subsec_nanos());
    Some(backoff + backoff.mul_f64(f64::from(nanos % 1000) / 4000.0))
}

/// Whether a status is worth retrying: 429 and 5xx.
pub fn is_retryable(status: reqwest::StatusCode) -> bool {
    status == reqwest::StatusCode::TOO_MANY_REQUESTS || status.is_server_error()
}

#[cfg(test)]
mod tests {
    use reqwest::header::HeaderValue;

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
        let capped = retry_delay(&HeaderMap::new(), 30, Duration::from_secs(1)).unwrap();
        assert!(capped <= MAX_BACKOFF + MAX_BACKOFF / 4);
    }

    #[test]
    fn retryable_statuses() {
        use reqwest::StatusCode;
        assert!(is_retryable(StatusCode::TOO_MANY_REQUESTS));
        assert!(is_retryable(StatusCode::BAD_GATEWAY));
        assert!(!is_retryable(StatusCode::BAD_REQUEST));
        assert!(!is_retryable(StatusCode::UNAUTHORIZED));
    }
}
