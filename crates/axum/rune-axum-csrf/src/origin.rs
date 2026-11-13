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
    let scheme = scheme.to_ascii_lowercase();
    let authority = strip_default_port(&scheme, &authority.to_ascii_lowercase()).to_owned();
    Some(format!("{scheme}://{authority}"))
}

/// Drops `:443` from an `https` authority and `:80` from an `http` one, so
/// `example.com:443` and `example.com` compare equal the way browsers see them.
fn strip_default_port<'a>(scheme: &str, authority: &'a str) -> &'a str {
    let port = match scheme {
        "https" => ":443",
        "http" => ":80",
        _ => return authority,
    };
    authority.strip_suffix(port).unwrap_or(authority)
}

/// Hosts browsers treat as a secure context even over plain `http`, where a
/// `Secure` cookie still works.
fn is_loopback(authority: &str) -> bool {
    let host = if authority.starts_with('[') {
        authority.split_inclusive(']').next().unwrap_or(authority)
    } else {
        authority.rsplit_once(':').map_or(authority, |(h, _)| h)
    };
    host == "localhost"
        || host.ends_with(".localhost")
        || host == "[::1]"
        || host.strip_prefix("127.").is_some_and(|rest| {
            rest.split('.').count() == 3
                && rest
                    .split('.')
                    .all(|o| !o.is_empty() && o.bytes().all(|b| b.is_ascii_digit()))
        })
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

fn matches(origin: &str, host: Option<&str>, trusted: &[String], secure: bool) -> bool {
    if trusted.iter().any(|t| t == origin) {
        return true;
    }
    let Some(host) = host else { return false };
    let Some((scheme, authority)) = origin.split_once("://") else {
        return false;
    };
    // The `Host` header carries no scheme. With a `Secure` cookie the site is
    // served over https, so a plain-http page claiming the same host is a
    // different origin (outside loopback, where browsers allow it).
    if secure && scheme != "https" && !(scheme == "http" && is_loopback(authority)) {
        return false;
    }
    authority == strip_default_port(scheme, host)
}

/// Checks `Origin`, then `Sec-Fetch-Site`, then `Referer`.
///
/// The request is same-origin when its source's `host[:port]` equals the
/// request's `Host` (or URI authority), default ports aside, or its full origin
/// is in `trusted`. With `secure` set, only an `https` source (or `http` on a
/// loopback host) can match the `Host`.
pub fn check(headers: &HeaderMap, uri: &Uri, trusted: &[String], secure: bool) -> Verdict {
    let host = request_host(headers, uri);
    if let Some(origin) = headers.get(header::ORIGIN) {
        // `Origin: null` (sandboxed iframes, data: URLs, some redirects) is
        // always treated as cross-origin, as is an unparsable value.
        return match origin.to_str().ok().and_then(origin_of) {
            Some(o) if matches(&o, host.as_deref(), trusted, secure) => Verdict::SameOrigin,
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
            Some(o) if matches(&o, host.as_deref(), trusted, secure) => Verdict::SameOrigin,
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
        assert_eq!(check(&h, &uri(), &[], true), Verdict::SameOrigin);
    }

    #[test]
    fn host_compare_is_case_insensitive_and_includes_port() {
        let h = hdrs(&[
            ("host", "Example.com:8080"),
            ("origin", "http://example.COM:8080"),
        ]);
        assert_eq!(check(&h, &uri(), &[], false), Verdict::SameOrigin);
        let h = hdrs(&[
            ("host", "example.com:8080"),
            ("origin", "http://example.com:9090"),
        ]);
        assert_eq!(check(&h, &uri(), &[], true), Verdict::CrossOrigin);
    }

    #[test]
    fn cross_origin_and_subdomain() {
        let h = hdrs(&[("host", "example.com"), ("origin", "https://evil.com")]);
        assert_eq!(check(&h, &uri(), &[], true), Verdict::CrossOrigin);
        let h = hdrs(&[
            ("host", "example.com"),
            ("origin", "https://sub.example.com"),
        ]);
        assert_eq!(check(&h, &uri(), &[], true), Verdict::CrossOrigin);
    }

    #[test]
    fn null_and_garbage_origin() {
        for o in ["null", "example.com", "https://", "https://u@example.com"] {
            let mut h = hdrs(&[("host", "example.com")]);
            h.insert("origin", HeaderValue::from_str(o).unwrap());
            assert_eq!(check(&h, &uri(), &[], true), Verdict::CrossOrigin, "{o}");
        }
    }

    #[test]
    fn trusted_origin() {
        let trusted = vec![normalize_origin("https://App.example.com/").unwrap()];
        let h = hdrs(&[
            ("host", "api.example.com"),
            ("origin", "https://app.example.com"),
        ]);
        assert_eq!(check(&h, &uri(), &trusted, true), Verdict::SameOrigin);
    }

    #[test]
    fn fetch_metadata_cross_site() {
        let h = hdrs(&[("host", "example.com"), ("sec-fetch-site", "cross-site")]);
        assert_eq!(check(&h, &uri(), &[], true), Verdict::CrossOrigin);
        let h = hdrs(&[("host", "example.com"), ("sec-fetch-site", "same-origin")]);
        assert_eq!(check(&h, &uri(), &[], true), Verdict::Unknown);
    }

    #[test]
    fn referer_fallback() {
        let h = hdrs(&[
            ("host", "example.com"),
            ("referer", "https://example.com/form?x=1"),
        ]);
        assert_eq!(check(&h, &uri(), &[], true), Verdict::SameOrigin);
        let h = hdrs(&[
            ("host", "example.com"),
            ("referer", "https://evil.com/example.com"),
        ]);
        assert_eq!(check(&h, &uri(), &[], true), Verdict::CrossOrigin);
    }

    #[test]
    fn no_headers_unknown() {
        assert_eq!(
            check(&hdrs(&[("host", "example.com")]), &uri(), &[], true),
            Verdict::Unknown
        );
    }

    #[test]
    fn uri_authority_used_without_host() {
        let h = hdrs(&[("origin", "https://example.com")]);
        let u = Uri::from_static("https://example.com/submit");
        assert_eq!(check(&h, &u, &[], true), Verdict::SameOrigin);
    }

    #[test]
    fn default_ports_are_normalised() {
        for (host, origin) in [
            ("example.com:443", "https://example.com"),
            ("example.com", "https://example.com:443"),
            ("example.com:443", "https://example.com:443"),
            ("example.com:80", "http://example.com"),
            ("[::1]:443", "https://[::1]"),
        ] {
            let mut h = hdrs(&[]);
            h.insert("host", HeaderValue::from_static(host));
            h.insert("origin", HeaderValue::from_static(origin));
            assert_eq!(
                check(&h, &uri(), &[], false),
                Verdict::SameOrigin,
                "{host} {origin}"
            );
        }
        // Another scheme's default port is a different origin.
        let h = hdrs(&[
            ("host", "example.com:80"),
            ("origin", "https://example.com"),
        ]);
        assert_eq!(check(&h, &uri(), &[], false), Verdict::CrossOrigin);
        let h = hdrs(&[
            ("host", "example.com:4430"),
            ("origin", "https://example.com"),
        ]);
        assert_eq!(check(&h, &uri(), &[], false), Verdict::CrossOrigin);
        // Trusted origins written with the default port match a browser's Origin.
        let trusted = vec![normalize_origin("https://app.example.com:443").unwrap()];
        let h = hdrs(&[
            ("host", "api.example.com"),
            ("origin", "https://app.example.com"),
        ]);
        assert_eq!(check(&h, &uri(), &trusted, false), Verdict::SameOrigin);
    }

    #[test]
    fn plain_http_source_rejected_when_cookie_is_secure() {
        let h = hdrs(&[("host", "example.com"), ("origin", "http://example.com")]);
        assert_eq!(check(&h, &uri(), &[], true), Verdict::CrossOrigin);
        assert_eq!(check(&h, &uri(), &[], false), Verdict::SameOrigin);
        let h = hdrs(&[
            ("host", "example.com"),
            ("referer", "http://example.com/form"),
        ]);
        assert_eq!(check(&h, &uri(), &[], true), Verdict::CrossOrigin);
        let h = hdrs(&[("host", "example.com"), ("origin", "https://example.com")]);
        assert_eq!(check(&h, &uri(), &[], true), Verdict::SameOrigin);
        // Browsers treat loopback as a secure context, so http works there.
        for (host, origin) in [
            ("localhost:3000", "http://localhost:3000"),
            ("app.localhost", "http://app.localhost"),
            ("127.0.0.1:8080", "http://127.0.0.1:8080"),
            ("[::1]:8080", "http://[::1]:8080"),
        ] {
            let mut h = hdrs(&[]);
            h.insert("host", HeaderValue::from_static(host));
            h.insert("origin", HeaderValue::from_static(origin));
            assert_eq!(
                check(&h, &uri(), &[], true),
                Verdict::SameOrigin,
                "{origin}"
            );
        }
        // An explicitly trusted http origin still passes.
        let trusted = vec![normalize_origin("http://legacy.example.com").unwrap()];
        let h = hdrs(&[
            ("host", "example.com"),
            ("origin", "http://legacy.example.com"),
        ]);
        assert_eq!(check(&h, &uri(), &trusted, true), Verdict::SameOrigin);
    }
}
