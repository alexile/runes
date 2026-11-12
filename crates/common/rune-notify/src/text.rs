//! Helpers shared by the sinks: length limits, URL checks and status
//! classification.

use rune_secret_ref::SecretValue;

use crate::{Error, HttpResponse};

/// The marker appended to text cut to a provider's length limit.
pub const ELLIPSIS: char = '…';

/// Longest response-body excerpt kept in an error.
const DETAIL_CHARS: usize = 300;

/// `text` cut to at most `max` characters, ending in `…` when cut.
pub fn truncate(text: &str, max: usize) -> String {
    if max == 0 {
        return String::new();
    }
    if text.char_indices().nth(max).is_none() {
        return text.to_owned();
    }
    let end = text
        .char_indices()
        .nth(max - 1)
        .map_or(text.len(), |(i, _)| i);
    let mut out = String::with_capacity(end + ELLIPSIS.len_utf8());
    out.push_str(&text[..end]);
    out.push(ELLIPSIS);
    out
}

/// `text` with every run of whitespace, line breaks included, made one space.
pub fn one_line(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Number of characters in `text`.
pub fn chars(text: &str) -> usize {
    text.chars().count()
}

/// Checks that `url` is an absolute `http`/`https` URL with a host, without
/// ever putting the URL into the error.
pub fn check_url(sink: &'static str, url: &SecretValue) -> Result<url::Url, Error> {
    let parsed = url::Url::parse(url.expose()).map_err(|e| Error::InvalidUrl {
        sink,
        reason: e.to_string(),
    })?;
    if !matches!(parsed.scheme(), "http" | "https") {
        return Err(Error::InvalidUrl {
            sink,
            reason: "scheme must be http or https".to_owned(),
        });
    }
    if parsed.host_str().is_none_or(str::is_empty) {
        return Err(Error::InvalidUrl {
            sink,
            reason: "URL has no host".to_owned(),
        });
    }
    Ok(parsed)
}

/// Whether `link` is safe to render as a clickable link: absolute
/// `http`/`https`, no whitespace or control characters.
pub fn is_web_link(link: &str) -> bool {
    !link.chars().any(|c| c.is_whitespace() || c.is_control())
        && url::Url::parse(link).is_ok_and(|u| matches!(u.scheme(), "http" | "https"))
}

/// The start of the response body, for an error message.
pub fn detail(response: &HttpResponse) -> String {
    let head = &response.body[..response.body.len().min(DETAIL_CHARS * 4)];
    let text = String::from_utf8_lossy(head);
    let line: String = text
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    truncate(line.trim(), DETAIL_CHARS)
}

/// Maps a non-2xx response to the matching [`Error`].
pub fn status_error(
    sink: &'static str,
    response: &HttpResponse,
    retry_after: Option<std::time::Duration>,
) -> Error {
    let status = response.status;
    match status {
        429 => Error::RateLimited {
            sink,
            status,
            retry_after: retry_after.or_else(|| response.retry_after()),
        },
        408 | 500..=599 => Error::Server {
            sink,
            status,
            detail: detail(response),
        },
        _ => Error::Rejected {
            sink,
            status,
            detail: detail(response),
        },
    }
}

/// Validates a header name (RFC 9110 token) and value (no CR, LF or NUL).
pub fn check_header(sink: &'static str, name: &str, value: &str) -> Result<(), Error> {
    let token = |c: char| c.is_ascii_alphanumeric() || "!#$%&'*+-.^_`|~".contains(c);
    if name.is_empty() || !name.chars().all(token) {
        return Err(Error::InvalidConfig {
            sink,
            reason: format!("header name {name:?} is not an HTTP token"),
        });
    }
    if value.chars().any(|c| matches!(c, '\r' | '\n' | '\0')) {
        return Err(Error::InvalidConfig {
            sink,
            reason: format!("value of header {name:?} contains a line break or NUL"),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncate_counts_chars() {
        assert_eq!(truncate("hello", 5), "hello");
        assert_eq!(truncate("hello", 4), "hel…");
        assert_eq!(truncate("héllo wörld", 3), "hé…");
        assert_eq!(truncate("abc", 1), "…");
        assert_eq!(truncate("abc", 0), "");
        assert_eq!(chars(&truncate(&"é".repeat(500), 150)), 150);
    }

    #[test]
    fn urls_are_checked_without_leaking() {
        let ok = SecretValue::new("https://hooks.slack.com/services/T/B/secret");
        assert!(check_url("slack", &ok).is_ok());
        for bad in ["ftp://x/secret", "not a url secret", "file:///secret"] {
            let err = check_url("slack", &SecretValue::new(bad)).err();
            assert!(err.is_some(), "{bad}");
            assert!(!format!("{err:?}").contains("secret"), "{bad}");
        }
    }

    #[test]
    fn web_links() {
        assert!(is_web_link("https://example.test/a?b=c"));
        assert!(!is_web_link("javascript:alert(1)"));
        assert!(!is_web_link("https://example.test/a b"));
        assert!(!is_web_link("/relative"));
    }

    #[test]
    fn statuses_classify() {
        let r = HttpResponse::new(503).with_body("busy");
        assert!(status_error("x", &r, None).is_retryable());
        let r = HttpResponse::new(404).with_body("no_service\n");
        let e = status_error("x", &r, None);
        assert!(!e.is_retryable());
        assert_eq!(
            e,
            Error::Rejected {
                sink: "x",
                status: 404,
                detail: "no_service".into()
            }
        );
        let r = HttpResponse::new(429).with_header("Retry-After", "2");
        assert_eq!(
            status_error("x", &r, None).retry_after(),
            Some(std::time::Duration::from_secs(2))
        );
    }

    #[test]
    fn headers_are_checked() {
        assert!(check_header("w", "X-Token", "abc").is_ok());
        assert!(check_header("w", "X Token", "abc").is_err());
        assert!(check_header("w", "", "abc").is_err());
        assert!(check_header("w", "X-Token", "a\r\nInjected: 1").is_err());
    }
}
