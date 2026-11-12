//! Origin / Referer / Fetch Metadata verification (defense in depth).

use http::{HeaderMap, Uri, header};

/// Outcome of the source-origin check for a state-changing request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// The request provably comes from this site or a trusted origin.
    SameOrigin,
    /// No `Origin`, `Referer` or `Sec-Fetch-Site` header: rely on the token alone.
    Unknown,
    /// The request comes from another origin.
    CrossOrigin,
}

/// `scheme://authority` of an absolute URL, lowercased; `None` if malformed.
fn origin_of(url: &str) -> Option<String> {
    let (scheme, rest) = url.split_once("://")?;
    if scheme.is_empty()
        || !scheme
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"+-.".contains(&b))
    {
        return None;
    }
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    // Userinfo in an Origin/Referer is never legitimate; refuse it.
    if authority.is_empty() || authority.contains('@') {
        return None;
    }
    Some(format!(
        "{}://{}",
        scheme.to_ascii_lowercase(),
        authority.to_ascii_lowercase()
    ))
}

/// Normalizes a configured trusted origin (`https://app.example.com`).
pub fn normalize_origin(origin: &str) -> Option<String> {
    origin_of(origin.trim().trim_end_matches('/'))
}

fn request_host(headers: &HeaderMap, uri: &Uri) -> Option<String> {
    headers
        .get(header::HOST)
        .and_then(|h| h.to_str().ok())
        .map(str::to_owned)
        .or_else(|| uri.authority().map(|a| a.as_str().to_owned()))
        .map(|h| h.to_ascii_lowercase())
}

fn matches(origin: &str, host: Option<&str>, trusted: &[String]) -> bool {
    if trusted.iter().any(|t| t == origin) {
        return true;
    }
    let Some(host) = host else { return false };
    origin
        .split_once("://")
        .is_some_and(|(_, authority)| authority == host)
}

/// Checks `Origin`, then `Sec-Fetch-Site`, then `Referer`.
///
/// The request is same-origin when its source's `host[:port]` equals the
/// request's `Host` (or URI authority), or its full origin is in `trusted`.
pub fn check(headers: &HeaderMap, uri: &Uri, trusted: &[String]) -> Verdict {
    let host = request_host(headers, uri);
    if let Some(origin) = headers.get(header::ORIGIN) {
        // `Origin: null` (sandboxed iframes, data: URLs, some redirects) is
        // always treated as cross-origin, as is an unparsable value.
        return match origin.to_str().ok().and_then(origin_of) {
            Some(o) if matches(&o, host.as_deref(), trusted) => Verdict::SameOrigin,
            _ => Verdict::CrossOrigin,
        };
    }
    if headers
        .get("sec-fetch-site")
        .is_some_and(|v| v.as_bytes().eq_ignore_ascii_case(b"cross-site"))
    {
        return Verdict::CrossOrigin;
    }
    if let Some(referer) = headers.get(header::REFERER) {
        return match referer.to_str().ok().and_then(origin_of) {
            Some(o) if matches(&o, host.as_deref(), trusted) => Verdict::SameOrigin,
            _ => Verdict::CrossOrigin,
        };
    }
    Verdict::Unknown
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::HeaderValue;

    fn hdrs(pairs: &[(&'static str, &'static str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            h.insert(*k, HeaderValue::from_static(v));
        }
        h
    }

    fn uri() -> Uri {
        Uri::from_static("/submit")
    }

    #[test]
    fn same_origin() {
        let h = hdrs(&[("host", "example.com"), ("origin", "https://example.com")]);
        assert_eq!(check(&h, &uri(), &[]), Verdict::SameOrigin);
    }

    #[test]
    fn host_compare_is_case_insensitive_and_includes_port() {
        let h = hdrs(&[
            ("host", "Example.com:8080"),
            ("origin", "http://example.COM:8080"),
        ]);
        assert_eq!(check(&h, &uri(), &[]), Verdict::SameOrigin);
        let h = hdrs(&[
            ("host", "example.com:8080"),
            ("origin", "http://example.com:9090"),
        ]);
        assert_eq!(check(&h, &uri(), &[]), Verdict::CrossOrigin);
    }

    #[test]
    fn cross_origin_and_subdomain() {
        let h = hdrs(&[("host", "example.com"), ("origin", "https://evil.com")]);
        assert_eq!(check(&h, &uri(), &[]), Verdict::CrossOrigin);
        let h = hdrs(&[
            ("host", "example.com"),
            ("origin", "https://sub.example.com"),
        ]);
        assert_eq!(check(&h, &uri(), &[]), Verdict::CrossOrigin);
    }

    #[test]
    fn null_and_garbage_origin() {
        for o in ["null", "example.com", "https://", "https://u@example.com"] {
            let mut h = hdrs(&[("host", "example.com")]);
            h.insert("origin", HeaderValue::from_str(o).unwrap());
            assert_eq!(check(&h, &uri(), &[]), Verdict::CrossOrigin, "{o}");
        }
    }

    #[test]
    fn trusted_origin() {
        let trusted = vec![normalize_origin("https://App.example.com/").unwrap()];
        let h = hdrs(&[
            ("host", "api.example.com"),
            ("origin", "https://app.example.com"),
        ]);
        assert_eq!(check(&h, &uri(), &trusted), Verdict::SameOrigin);
    }

    #[test]
    fn fetch_metadata_cross_site() {
        let h = hdrs(&[("host", "example.com"), ("sec-fetch-site", "cross-site")]);
        assert_eq!(check(&h, &uri(), &[]), Verdict::CrossOrigin);
        let h = hdrs(&[("host", "example.com"), ("sec-fetch-site", "same-origin")]);
        assert_eq!(check(&h, &uri(), &[]), Verdict::Unknown);
    }

    #[test]
    fn referer_fallback() {
        let h = hdrs(&[
            ("host", "example.com"),
            ("referer", "https://example.com/form?x=1"),
        ]);
        assert_eq!(check(&h, &uri(), &[]), Verdict::SameOrigin);
        let h = hdrs(&[
            ("host", "example.com"),
            ("referer", "https://evil.com/example.com"),
        ]);
        assert_eq!(check(&h, &uri(), &[]), Verdict::CrossOrigin);
    }

    #[test]
    fn no_headers_unknown() {
        assert_eq!(
            check(&hdrs(&[("host", "example.com")]), &uri(), &[]),
            Verdict::Unknown
        );
    }

    #[test]
    fn uri_authority_used_without_host() {
        let h = hdrs(&[("origin", "https://example.com")]);
        let u = Uri::from_static("https://example.com/submit");
        assert_eq!(check(&h, &u, &[]), Verdict::SameOrigin);
    }
}
