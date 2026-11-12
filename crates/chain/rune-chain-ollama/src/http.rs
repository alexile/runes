//! Transport hardening: secret redaction, base-URL policy, bounded body
//! reads and error truncation.

use std::fmt;

use futures::StreamExt;
use rune_chain_core::LlmError;

/// Longest error-body excerpt kept in an error message, in characters.
pub const MAX_ERROR_CHARS: usize = 512;
/// Most bytes read from an error body.
pub const MAX_ERROR_BODY: usize = 64 * 1024;

/// A bearer token whose `Debug` output never shows the secret.
#[derive(Clone, Default)]
pub struct Secret(String);

impl Secret {
    pub fn new(token: impl Into<String>) -> Self {
        Self(token.into())
    }

    pub fn expose(&self) -> &str {
        &self.0
    }

    pub const fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Replace every occurrence of the secret in `text` with `[REDACTED]`.
    /// Secrets shorter than 8 bytes are not scrubbed (too likely to match
    /// ordinary text).
    pub fn scrub(&self, text: String) -> String {
        if self.0.len() >= 8 && text.contains(&self.0) {
            text.replace(&self.0, "[REDACTED]")
        } else {
            text
        }
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.0.is_empty() {
            f.write_str("<none>")
        } else {
            f.write_str("[REDACTED]")
        }
    }
}

/// Whether `host` is a loopback name or address.
pub fn is_loopback_host(host: &str) -> bool {
    let host = host.trim_start_matches('[').trim_end_matches(']');
    host.eq_ignore_ascii_case("localhost")
        || host.to_ascii_lowercase().ends_with(".localhost")
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback())
}

/// Which plain-HTTP hosts the caller has accepted.
#[derive(Debug, Clone, Default)]
pub struct HttpPolicy {
    /// Hosts allowed over plain HTTP besides loopback.
    pub allowed_hosts: Vec<String>,
    /// Allow plain HTTP to any host.
    pub allow_any: bool,
}

impl HttpPolicy {
    fn allows(&self, host: &str) -> bool {
        self.allow_any
            || is_loopback_host(host)
            || self
                .allowed_hosts
                .iter()
                .any(|h| h.eq_ignore_ascii_case(host))
    }
}

/// Parse `url` and enforce the transport policy: `https` anywhere; `http`
/// only to loopback or a host the policy allows (Ollama has no
/// authentication, so plain HTTP to a remote host exposes prompts, outputs
/// and any bearer token to the network); no credentials in the URL.
pub fn check_url(url: &str, policy: &HttpPolicy) -> Result<reqwest::Url, LlmError> {
    let parsed =
        reqwest::Url::parse(url).map_err(|e| LlmError::other(format!("invalid base URL: {e}")))?;
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(LlmError::other(
            "base URL must not embed credentials; use `.bearer_token(..)` or a custom \
             `http_client` with default headers",
        ));
    }
    let host = parsed.host_str().unwrap_or_default();
    match parsed.scheme() {
        "https" => Ok(parsed),
        "http" if policy.allows(host) => Ok(parsed),
        "http" => Err(LlmError::other(format!(
            "refusing plain HTTP to non-loopback host `{host}`: Ollama has no authentication \
             and prompts, outputs (and any bearer token) would cross the network unencrypted; \
             use https (e.g. a TLS reverse proxy) or accept the exposure with \
             `.allow_http_host(\"{host}\")`"
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
        let chunk = chunk.map_err(|e| LlmError::request_failed(e.to_string()))?;
        if body.len().saturating_add(chunk.len()) > limit {
            if truncate_at_limit {
                let room = limit.saturating_sub(body.len());
                body.extend_from_slice(&chunk[..room.min(chunk.len())]);
                break;
            }
            return Err(too_big());
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

/// Map a non-success response to an error, preferring Ollama's
/// `{"error": "..."}` message over the raw body. Both are truncated to
/// [`MAX_ERROR_CHARS`]. The kind comes from `status` (a full queue is a 503,
/// [`Overloaded`](rune_chain_core::LlmErrorKind::Overloaded)); a
/// `Retry-After` delay is attached by the caller.
pub fn decode_error(status: u16, body: &[u8]) -> LlmError {
    let text = String::from_utf8_lossy(body);
    let msg = serde_json::from_str::<serde_json::Value>(&text)
        .ok()
        .and_then(|v| v.get("error").and_then(|e| e.as_str()).map(str::to_string))
        .unwrap_or_else(|| text.into_owned());
    LlmError::from_status(status, truncate(&msg, MAX_ERROR_CHARS))
}

/// `Retry-After` in (possibly fractional) seconds, if present and sane.
pub fn retry_after(headers: &reqwest::header::HeaderMap) -> Option<std::time::Duration> {
    headers
        .get(reqwest::header::RETRY_AFTER)?
        .to_str()
        .ok()?
        .trim()
        .parse::<f64>()
        .ok()
        .filter(|v| v.is_finite() && *v >= 0.0)
        .map(|v| std::time::Duration::from_secs_f64(v.min(86_400.0)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rune_chain_core::LlmErrorKind;

    #[test]
    fn secret_debug_is_redacted() {
        let t = Secret::new("tok-secret-123456");
        assert_eq!(format!("{t:?}"), "[REDACTED]");
        assert_eq!(format!("{:?}", Secret::default()), "<none>");
        assert_eq!(t.scrub("bad tok-secret-123456!".into()), "bad [REDACTED]!");
        assert_eq!(Secret::new("short").scrub("short".into()), "short");
    }

    #[test]
    fn url_policy() {
        let none = HttpPolicy::default();
        let ok = |u: &str| check_url(u, &none).is_ok();
        assert!(ok("http://localhost:11434"));
        assert!(ok("http://127.0.0.1:11434"));
        assert!(ok("http://[::1]:11434"));
        assert!(ok("http://ollama.localhost"));
        assert!(ok("https://ollama.example.com"));
        assert!(!ok("http://10.0.0.5:11434"));
        assert!(!ok("http://localhost.evil.com"));
        assert!(!ok("ftp://example.com"));
        assert!(!ok("https://user:pw@example.com"));
        assert!(!ok("not a url"));

        let some = HttpPolicy {
            allowed_hosts: vec!["GPU-box".into()],
            allow_any: false,
        };
        assert!(check_url("http://gpu-box:11434", &some).is_ok());
        assert!(check_url("http://other:11434", &some).is_err());
        let any = HttpPolicy {
            allow_any: true,
            ..HttpPolicy::default()
        };
        assert!(check_url("http://10.0.0.5:11434", &any).is_ok());
    }

    #[test]
    fn remote_http_error_explains_the_opt_in() {
        let err = check_url("http://gpu-box:11434", &HttpPolicy::default()).unwrap_err();
        assert!(
            matches!(&err, m if m.kind() == LlmErrorKind::Other && m.message().contains("allow_http_host(\"gpu-box\")")),
            "{err:?}"
        );
    }

    #[test]
    fn truncation_is_char_safe() {
        assert_eq!(truncate("  short ", 10), "short");
        let t = truncate(&"é".repeat(600), MAX_ERROR_CHARS);
        assert!(t.ends_with("[truncated]"));
        assert_eq!(t.chars().filter(|c| *c == 'é').count(), MAX_ERROR_CHARS);
    }

    #[test]
    fn error_bodies_are_decoded_and_truncated() {
        assert!(matches!(
            decode_error(404, br#"{"error":"model not found"}"#),
            m if m.kind() == LlmErrorKind::InvalidRequest && m.status() == Some(404) && m.message() == "model not found"
        ));
        assert!(matches!(
            decode_error(404, b"404 page not found"),
            m if m.kind() == LlmErrorKind::InvalidRequest && m.message() == "404 page not found"
        ));
        let long = "x".repeat(10_000);
        assert!(matches!(
            decode_error(500, long.as_bytes()),
            m if m.kind() == LlmErrorKind::Server && m.message().len() < 600 && m.message().ends_with("[truncated]")
        ));
        assert_eq!(
            decode_error(503, br#"{"error":"server busy, please try again"}"#).kind(),
            LlmErrorKind::Overloaded
        );
        assert_eq!(
            decode_error(299, &[0xff, 0xfe]).kind(),
            LlmErrorKind::Provider
        );
    }

    #[test]
    fn retry_after_header() {
        let mut h = reqwest::header::HeaderMap::new();
        assert_eq!(retry_after(&h), None);
        h.insert("retry-after", "2".parse().unwrap());
        assert_eq!(retry_after(&h), Some(std::time::Duration::from_secs(2)));
        h.insert(
            "retry-after",
            "Wed, 21 Oct 2015 07:28:00 GMT".parse().unwrap(),
        );
        assert_eq!(retry_after(&h), None);
    }
}
