//! Classification of [`LlmError`]s into retry / fallback decisions.
//!
//! The `rune-chain-*` providers classify their failures themselves
//! ([`LlmError::kind`], plus the HTTP status and the server's
//! `Retry-After` in [`LlmError::retry_after`]), so [`classify`] and
//! [`retry_after`] read those first. Only errors left unclassified
//! ([`LlmErrorKind::Provider`], or [`LlmErrorKind::Network`] without a
//! status), typically from third-party [`Llm`](rune_chain_core::Llm)
//! implementations, fall back to recognising the wording (and any embedded
//! status code) that LLM APIs use for rate limits, overload, server faults,
//! timeouts, authentication failures and invalid requests.

use std::time::Duration;

use rune_chain_core::{LlmError, LlmErrorKind};

/// Longest provider retry-after hint [`retry_after`] accepts (one hour).
/// Anything larger is treated as noise.
pub const MAX_RETRY_AFTER_HINT: Duration = Duration::from_secs(3600);

/// What kind of failure an [`LlmError`] represents.
///
/// Drives three decisions: whether to retry the same provider
/// ([`is_retryable`](Self::is_retryable)), whether a router may move on to
/// another provider ([`should_fallback`](Self::should_fallback)) and whether
/// the failure counts against a provider's circuit breaker
/// ([`trips_breaker`](Self::trips_breaker)).
///
/// # Example
///
/// ```rust
/// use rune_chain_core::LlmError;
/// use rune_chain_retry::{ErrorClass, classify};
///
/// // A classified error maps directly.
/// let e = LlmError::from_status(529, "Overloaded");
/// assert_eq!(classify(&e), ErrorClass::Overloaded);
/// assert!(classify(&e).is_retryable());
///
/// // An unclassified one is recognised by its wording.
/// let e = LlmError::provider("Rate limit reached. Please try again in 2s.");
/// assert_eq!(classify(&e), ErrorClass::RateLimited);
///
/// let e = LlmError::provider("invalid x-api-key");
/// assert_eq!(classify(&e), ErrorClass::Auth);
/// assert!(!classify(&e).is_retryable());
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ErrorClass {
    /// HTTP 429 / per-minute token or request limits.
    RateLimited,
    /// The provider is overloaded or unavailable (HTTP 503 / 529).
    Overloaded,
    /// Any other 5xx server fault.
    ServerError,
    /// The request, or one attempt of it, timed out.
    Timeout,
    /// A transport-level failure (connection reset, DNS, TLS, …).
    Network,
    /// Authentication, permission or billing failure (HTTP 401 / 403,
    /// exhausted quota). Never retried.
    Auth,
    /// The prompt does not fit the model's context window. Never retried,
    /// but a router may try a model with a larger window.
    ContextLength,
    /// The request itself is malformed (HTTP 400 / 404 / 422). Never retried
    /// and never sent to another provider.
    InvalidRequest,
    /// The provider lacks a capability (tool calling, streaming).
    Unsupported,
    /// The model answered, but the response could not be decoded.
    InvalidResponse,
    /// A provider error whose message matched nothing above. Retried, since
    /// most unrecognised provider errors are transient.
    Unknown,
    /// [`LlmErrorKind::Other`]: a local, non-provider failure. Never retried.
    Other,
}

impl ErrorClass {
    /// `true` if retrying the same provider may succeed.
    #[must_use]
    pub const fn is_retryable(self) -> bool {
        matches!(
            self,
            Self::RateLimited
                | Self::Overloaded
                | Self::ServerError
                | Self::Timeout
                | Self::Network
                | Self::Unknown
        )
    }

    /// `true` if a router may try another provider after this failure.
    ///
    /// Everything except [`InvalidRequest`](Self::InvalidRequest), which
    /// would fail the same way everywhere.
    #[must_use]
    pub const fn should_fallback(self) -> bool {
        !matches!(self, Self::InvalidRequest)
    }

    /// `true` if the failure says something about the provider's health and
    /// counts towards opening its circuit breaker.
    ///
    /// Rate limits do not count: they put the provider in a cooldown instead.
    #[must_use]
    pub const fn trips_breaker(self) -> bool {
        matches!(
            self,
            Self::Overloaded
                | Self::ServerError
                | Self::Timeout
                | Self::Network
                | Self::Unknown
                | Self::Auth
        )
    }
}

/// Classify an [`LlmError`].
///
/// The error's [`kind`](LlmError::kind) maps directly onto an
/// [`ErrorClass`]. For [`LlmErrorKind::Provider`] and for
/// [`LlmErrorKind::Network`] without an HTTP status (both used by providers
/// that do not classify their errors) the message is matched,
/// case-insensitively, against well-known phrases and HTTP status codes; an
/// unrecognised `Network` error stays [`ErrorClass::Network`] and an
/// unrecognised `Provider` error is [`ErrorClass::Unknown`] (both retried).
/// An [`LlmErrorKind::Other`] error mentioning "not supported" is
/// [`ErrorClass::Unsupported`].
#[must_use]
pub fn classify(error: &LlmError) -> ErrorClass {
    let message = error.message();
    match error.kind() {
        LlmErrorKind::RateLimit => ErrorClass::RateLimited,
        LlmErrorKind::Overloaded => ErrorClass::Overloaded,
        LlmErrorKind::Server => ErrorClass::ServerError,
        LlmErrorKind::Timeout => ErrorClass::Timeout,
        LlmErrorKind::Auth => ErrorClass::Auth,
        LlmErrorKind::ContextLengthExceeded => ErrorClass::ContextLength,
        LlmErrorKind::InvalidRequest => ErrorClass::InvalidRequest,
        LlmErrorKind::InvalidResponse => ErrorClass::InvalidResponse,
        LlmErrorKind::Unsupported => ErrorClass::Unsupported,
        LlmErrorKind::Network if error.status().is_none() => {
            classify_message(message).unwrap_or(ErrorClass::Network)
        }
        LlmErrorKind::Network => ErrorClass::Network,
        LlmErrorKind::Other => {
            if message.to_ascii_lowercase().contains("not supported") {
                ErrorClass::Unsupported
            } else {
                ErrorClass::Other
            }
        }
        // `Provider`, and kinds added to core later.
        _ => classify_message(message).unwrap_or(ErrorClass::Unknown),
    }
}

fn classify_message(message: &str) -> Option<ErrorClass> {
    let m = message.to_ascii_lowercase();
    let any = |needles: &[&str]| needles.iter().any(|n| m.contains(n));
    let code = |codes: &[&str]| codes.iter().any(|c| has_status_code(&m, c));

    // Billing / quota exhaustion looks like a rate limit but never clears by
    // waiting, so test for it first.
    if any(&[
        "insufficient_quota",
        "exceeded your current quota",
        "billing",
        "credit balance",
    ]) {
        return Some(ErrorClass::Auth);
    }
    if any(&[
        "context length",
        "context_length",
        "context window",
        "maximum context",
        "prompt is too long",
        "too many tokens",
        "reduce the length",
    ]) {
        return Some(ErrorClass::ContextLength);
    }
    if any(&["rate limit", "rate_limit", "ratelimit", "too many requests"]) || code(&["429"]) {
        return Some(ErrorClass::RateLimited);
    }
    if any(&[
        "overloaded",
        "over capacity",
        "service unavailable",
        "temporarily unavailable",
    ]) || code(&["503", "529"])
    {
        return Some(ErrorClass::Overloaded);
    }
    if any(&["timed out", "timeout", "deadline exceeded"]) || code(&["408", "504"]) {
        return Some(ErrorClass::Timeout);
    }
    if any(&[
        "unauthorized",
        "unauthenticated",
        "authentication",
        "forbidden",
        "permission",
        "invalid api key",
        "invalid x-api-key",
        "incorrect api key",
        "api key not valid",
    ]) || code(&["401", "403"])
    {
        return Some(ErrorClass::Auth);
    }
    if any(&[
        "internal server error",
        "internal error",
        "bad gateway",
        "server error",
        "api_error",
    ]) || code(&["500", "502"])
    {
        return Some(ErrorClass::ServerError);
    }
    if any(&[
        "invalid request",
        "invalid_request",
        "bad request",
        "unprocessable",
        "model not found",
        "does not exist",
    ]) || code(&["400", "404", "413", "422"])
    {
        return Some(ErrorClass::InvalidRequest);
    }
    if any(&[
        "connection",
        "connect error",
        "dns",
        "broken pipe",
        "reset by peer",
        "unexpected eof",
    ]) {
        return Some(ErrorClass::Network);
    }
    None
}

/// `true` if `code` occurs in `haystack` as a standalone number (not part of a
/// longer digit run such as `14290` or a price like `4.29`).
fn has_status_code(haystack: &str, code: &str) -> bool {
    let bytes = haystack.as_bytes();
    let mut from = 0;
    while let Some(pos) = haystack.get(from..).and_then(|s| s.find(code)) {
        let start = from + pos;
        let end = start + code.len();
        let standalone = |i: Option<usize>| {
            i.and_then(|i| bytes.get(i))
                .is_none_or(|b| !b.is_ascii_digit() && *b != b'.')
        };
        if standalone(start.checked_sub(1)) && standalone(Some(end)) {
            return true;
        }
        from = end;
    }
    false
}

/// The delay a provider asked for before retrying, if any.
///
/// [`LlmError::retry_after`] (set by providers from the `Retry-After`
/// header) wins. Otherwise, for [`LlmErrorKind::Provider`],
/// [`LlmErrorKind::Network`] and [`LlmErrorKind::RateLimit`] errors, the
/// message is searched for `retry-after: 12`, `retry after 3 seconds`,
/// `try again in 1.5s`, `try again in 250ms` and `in 2 minutes`-style
/// phrasing; a bare number is taken as seconds. Hints above
/// [`MAX_RETRY_AFTER_HINT`] are ignored.
///
/// # Example
///
/// ```rust
/// use std::time::Duration;
/// use rune_chain_core::LlmError;
/// use rune_chain_retry::retry_after;
///
/// let e = LlmError::from_status(429, "slow down").with_retry_after(Duration::from_secs(3));
/// assert_eq!(retry_after(&e), Some(Duration::from_secs(3)));
/// let e = LlmError::provider("Rate limit reached. Please try again in 1.5s.");
/// assert_eq!(retry_after(&e), Some(Duration::from_millis(1500)));
/// assert_eq!(retry_after(&LlmError::provider("Overloaded")), None);
/// ```
#[must_use]
pub fn retry_after(error: &LlmError) -> Option<Duration> {
    if let Some(wait) = error.retry_after() {
        return (wait <= MAX_RETRY_AFTER_HINT).then_some(wait);
    }
    if !matches!(
        error.kind(),
        LlmErrorKind::Provider | LlmErrorKind::Network | LlmErrorKind::RateLimit
    ) {
        return None;
    }
    let m = error.message().to_ascii_lowercase();
    ["retry-after", "retry_after", "retry after", "try again in"]
        .iter()
        .find_map(|key| {
            let rest = &m[m.find(key)? + key.len()..];
            parse_duration(rest)
        })
        .filter(|d| *d <= MAX_RETRY_AFTER_HINT)
}

/// Parse `[:= ]*<number>[ ]<unit>` at the start of `s`.
fn parse_duration(s: &str) -> Option<Duration> {
    let s = s.trim_start_matches(|c: char| c == ':' || c == '=' || c.is_whitespace() || c == '"');
    let s = s.strip_prefix("in ").unwrap_or(s);
    let num_len = s
        .find(|c: char| !(c.is_ascii_digit() || c == '.'))
        .unwrap_or(s.len());
    let value: f64 = s.get(..num_len)?.parse().ok()?;
    let unit = s.get(num_len..)?.trim_start();
    let secs = if unit.starts_with("ms") || unit.starts_with("milli") {
        value / 1000.0
    } else if unit.starts_with("min") || (unit.starts_with('m') && !unit.starts_with("ms")) {
        value * 60.0
    } else if unit.starts_with('h') {
        value * 3600.0
    } else {
        value
    };
    Duration::try_from_secs_f64(secs).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(m: &str) -> ErrorClass {
        classify(&LlmError::provider(m))
    }

    #[test]
    fn provider_messages() {
        assert_eq!(p("Overloaded"), ErrorClass::Overloaded);
        assert_eq!(
            p("Number of request tokens has exceeded your per-minute rate limit"),
            ErrorClass::RateLimited
        );
        assert_eq!(p("HTTP 429"), ErrorClass::RateLimited);
        assert_eq!(p("status 502 from upstream"), ErrorClass::ServerError);
        assert_eq!(p("invalid x-api-key"), ErrorClass::Auth);
        assert_eq!(p("You exceeded your current quota"), ErrorClass::Auth);
        assert_eq!(
            p("prompt is too long: 250000 tokens > 200000 maximum"),
            ErrorClass::ContextLength
        );
        assert_eq!(
            p("messages: field required (invalid_request_error)"),
            ErrorClass::InvalidRequest
        );
        assert_eq!(p("something odd"), ErrorClass::Unknown);
        assert_eq!(
            classify(&LlmError::request_failed("error sending request")),
            ErrorClass::Network
        );
        assert_eq!(
            classify(&LlmError::request_failed("operation timed out")),
            ErrorClass::Timeout
        );
        assert_eq!(
            classify(&LlmError::other("streaming is not supported")),
            ErrorClass::Unsupported
        );
        assert_eq!(classify(&LlmError::other("budget")), ErrorClass::Other);
    }

    #[test]
    fn status_codes_need_word_boundaries() {
        assert_eq!(p("request id 14290"), ErrorClass::Unknown);
        assert_eq!(p("cost $4.29"), ErrorClass::Unknown);
        assert_eq!(p("(429)"), ErrorClass::RateLimited);
    }

    #[test]
    fn retry_after_forms() {
        let r = |m: &str| retry_after(&LlmError::provider(m));
        assert_eq!(r("Retry-After: 12"), Some(Duration::from_secs(12)));
        assert_eq!(
            r("please retry after 3 seconds"),
            Some(Duration::from_secs(3))
        );
        assert_eq!(r("try again in 250ms"), Some(Duration::from_millis(250)));
        assert_eq!(r("try again in 2 minutes"), Some(Duration::from_secs(120)));
        assert_eq!(r("retry after 99999 hours"), None);
        assert_eq!(r("retry after soon"), None);
        assert_eq!(retry_after(&LlmError::other("retry after 1")), None);
    }

    #[test]
    fn kinds_win_over_wording() {
        use LlmErrorKind as K;
        for (kind, class) in [
            (K::RateLimit, ErrorClass::RateLimited),
            (K::Overloaded, ErrorClass::Overloaded),
            (K::Server, ErrorClass::ServerError),
            (K::Timeout, ErrorClass::Timeout),
            (K::Network, ErrorClass::Network),
            (K::Auth, ErrorClass::Auth),
            (K::ContextLengthExceeded, ErrorClass::ContextLength),
            (K::InvalidRequest, ErrorClass::InvalidRequest),
            (K::InvalidResponse, ErrorClass::InvalidResponse),
            (K::Unsupported, ErrorClass::Unsupported),
            (K::Other, ErrorClass::Other),
        ] {
            // A misleading message never overrides a provider's classification.
            let e = LlmError::new(kind, "rate limit overloaded 401").with_status(299);
            assert_eq!(classify(&e), class, "{kind:?}");
        }
        assert_eq!(
            classify(&LlmError::from_status(429, "quota exceeded")),
            ErrorClass::RateLimited
        );
        assert_eq!(
            classify(&LlmError::from_status(503, "")),
            ErrorClass::Overloaded
        );
        // Unclassified provider errors still fall back to their wording.
        assert_eq!(
            classify(&LlmError::from_status(418, "Overloaded")),
            ErrorClass::Overloaded
        );
    }

    #[test]
    fn structured_retry_after_wins() {
        let e =
            LlmError::from_status(429, "try again in 5s").with_retry_after(Duration::from_secs(1));
        assert_eq!(retry_after(&e), Some(Duration::from_secs(1)));
        let e = LlmError::from_status(429, "try again in 5s");
        assert_eq!(retry_after(&e), Some(Duration::from_secs(5)));
        let e = LlmError::from_status(503, "x").with_retry_after(MAX_RETRY_AFTER_HINT * 2);
        assert_eq!(retry_after(&e), None);
        let e = LlmError::from_status(400, "retry after 3");
        assert_eq!(retry_after(&e), None);
    }

    #[test]
    fn decisions() {
        assert!(!ErrorClass::Auth.is_retryable());
        assert!(ErrorClass::Auth.should_fallback());
        assert!(!ErrorClass::InvalidRequest.should_fallback());
        assert!(!ErrorClass::RateLimited.trips_breaker());
        assert!(ErrorClass::Overloaded.trips_breaker());
    }
}
