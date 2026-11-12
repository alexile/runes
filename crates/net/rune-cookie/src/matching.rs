//! Domain and path matching ([RFC 6265 §5.1.3], [§5.1.4]) and the site
//! relation used by `SameSite` ([RFC 6265bis §5.2]).
//!
//! [RFC 6265 §5.1.3]: https://www.rfc-editor.org/rfc/rfc6265#section-5.1.3
//! [§5.1.4]: https://www.rfc-editor.org/rfc/rfc6265#section-5.1.4
//! [RFC 6265bis §5.2]: https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-rfc6265bis#section-5.2

use std::net::IpAddr;

use url::{Host, Url};

/// Whether `host` domain-matches `domain` ([RFC 6265 §5.1.3]).
///
/// Both must already be canonicalized (lowercase A-labels). `host` matches
/// when it is identical to `domain`, or when it is a name (not an IP
/// address) ending in `.` followed by `domain`.
///
/// ```
/// use rune_cookie::domain_match;
///
/// assert!(domain_match("www.example.com", "example.com"));
/// assert!(domain_match("example.com", "example.com"));
/// assert!(!domain_match("badexample.com", "example.com"));
/// assert!(!domain_match("10.0.0.1", "0.0.1"));
/// ```
///
/// [RFC 6265 §5.1.3]: https://www.rfc-editor.org/rfc/rfc6265#section-5.1.3
#[must_use]
pub fn domain_match(host: &str, domain: &str) -> bool {
    if host == domain {
        return true;
    }
    !domain.is_empty()
        && host
            .strip_suffix(domain)
            .is_some_and(|head| head.ends_with('.'))
        && !is_ip_literal(host)
}

/// Whether `request_path` path-matches `cookie_path` ([RFC 6265 §5.1.4]).
///
/// ```
/// use rune_cookie::path_match;
///
/// assert!(path_match("/docs/web", "/docs"));
/// assert!(path_match("/docs/", "/docs/"));
/// assert!(!path_match("/docsets", "/docs"));
/// ```
///
/// [RFC 6265 §5.1.4]: https://www.rfc-editor.org/rfc/rfc6265#section-5.1.4
#[must_use]
pub fn path_match(request_path: &str, cookie_path: &str) -> bool {
    request_path
        .strip_prefix(cookie_path)
        .is_some_and(|rest| rest.is_empty() || cookie_path.ends_with('/') || rest.starts_with('/'))
}

/// The default cookie path for a request path ([RFC 6265 §5.1.4]): the
/// path up to, but not including, its last `/`, or `/` if that would be
/// empty or the path does not start with `/`.
///
/// ```
/// use rune_cookie::default_path;
///
/// assert_eq!(default_path("/docs/web/cookies"), "/docs/web");
/// assert_eq!(default_path("/docs"), "/");
/// assert_eq!(default_path(""), "/");
/// ```
///
/// [RFC 6265 §5.1.4]: https://www.rfc-editor.org/rfc/rfc6265#section-5.1.4
#[must_use]
pub fn default_path(request_path: &str) -> &str {
    if !request_path.starts_with('/') {
        return "/";
    }
    match request_path.rfind('/') {
        Some(0) | None => "/",
        Some(last) => request_path.get(..last).unwrap_or("/"),
    }
}

/// The canonical host of `url` ([RFC 6265 §5.1.2]): lowercase A-labels for
/// a name, the dotted quad for IPv4, the bracketed form for IPv6. `None`
/// when the URL has no host.
///
/// [RFC 6265 §5.1.2]: https://www.rfc-editor.org/rfc/rfc6265#section-5.1.2
#[must_use]
pub fn canonical_host(url: &Url) -> Option<String> {
    match url.host()? {
        Host::Domain(name) => {
            let name = name.to_ascii_lowercase();
            (!name.is_empty()).then_some(name)
        }
        Host::Ipv4(ip) => Some(ip.to_string()),
        Host::Ipv6(ip) => Some(format!("[{ip}]")),
    }
}

/// Canonicalizes a `Domain` attribute value: IDNA to lowercase A-labels.
/// `None` if it is not a valid host.
pub fn canonicalize_domain(domain: &str) -> Option<String> {
    if domain.is_ascii() {
        return Some(domain.to_ascii_lowercase());
    }
    match Host::parse(domain).ok()? {
        Host::Domain(name) => Some(name.to_ascii_lowercase()),
        Host::Ipv4(ip) => Some(ip.to_string()),
        Host::Ipv6(ip) => Some(format!("[{ip}]")),
    }
}

/// Whether `host` is an IPv4 literal or a bracketed IPv6 literal.
pub fn is_ip_literal(host: &str) -> bool {
    host.parse::<IpAddr>().is_ok()
        || host
            .strip_prefix('[')
            .and_then(|rest| rest.strip_suffix(']'))
            .is_some_and(|inner| inner.parse::<IpAddr>().is_ok())
}

/// Whether the URL's scheme is a secure protocol for cookies (`https`,
/// `wss`).
#[must_use]
pub fn is_secure_scheme(url: &Url) -> bool {
    matches!(url.scheme(), "https" | "wss")
}

/// The site of a URL ([RFC 6265bis §5.2], schemeful): its scheme (with
/// `ws`/`wss` mapped to `http`/`https`) and its registrable domain, or its
/// host when it has none (an IP address, a public suffix, `localhost`).
fn site(url: &Url, list: &rune_psl::List) -> Option<(&'static str, String)> {
    let scheme = match url.scheme() {
        "https" | "wss" => "https",
        "http" | "ws" => "http",
        _ => "other",
    };
    let host = canonical_host(url)?;
    if is_ip_literal(&host) {
        return Some((scheme, host));
    }
    let site = list.registrable_domain(&host).unwrap_or(host);
    Some((scheme, site.trim_end_matches('.').to_owned()))
}

/// Whether two URLs are *same-site* in the schemeful sense of
/// [RFC 6265bis §5.2]: same scheme family and same registrable domain
/// (eTLD+1), judged with `list`.
///
/// URLs without a host are never same-site.
///
/// ```
/// use rune_cookie::is_same_site;
/// use url::Url;
///
/// let list = rune_psl::List::embedded();
/// let a = Url::parse("https://www.example.co.uk/").unwrap();
/// let b = Url::parse("https://login.example.co.uk/").unwrap();
/// let c = Url::parse("https://other.co.uk/").unwrap();
/// let d = Url::parse("http://www.example.co.uk/").unwrap();
/// assert!(is_same_site(&a, &b, &list));
/// assert!(!is_same_site(&a, &c, &list));
/// assert!(!is_same_site(&a, &d, &list)); // schemeful
/// ```
///
/// [RFC 6265bis §5.2]: https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-rfc6265bis#section-5.2
#[must_use]
pub fn is_same_site(a: &Url, b: &Url, list: &rune_psl::List) -> bool {
    match (site(a, list), site(b, list)) {
        (Some(a), Some(b)) => a == b,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domain_matching() {
        assert!(domain_match("a.b.example.com", "example.com"));
        assert!(!domain_match("example.com", "www.example.com"));
        assert!(!domain_match("com", ""));
        assert!(!domain_match("x.example.com", ".example.com"));
        assert!(domain_match("1.2.3.4", "1.2.3.4"));
        assert!(!domain_match("[::1]", ":1]"));
    }

    #[test]
    fn path_matching() {
        assert!(path_match("/", "/"));
        assert!(path_match("/a", "/"));
        assert!(path_match("/a/b", "/a"));
        assert!(path_match("/a", "/a"));
        assert!(!path_match("/ab", "/a"));
        assert!(!path_match("/", "/a"));
        assert!(!path_match("/A", "/a"));
        assert!(path_match("/a//b", "/a/"));
    }

    #[test]
    fn default_paths() {
        assert_eq!(default_path("/"), "/");
        assert_eq!(default_path("/a/"), "/a");
        assert_eq!(default_path("/a/b"), "/a");
        assert_eq!(default_path("a/b"), "/");
        assert_eq!(default_path("//"), "/");
    }

    #[test]
    fn hosts() {
        let url = Url::parse("http://WWW.Example.COM./x").unwrap();
        assert_eq!(canonical_host(&url).as_deref(), Some("www.example.com."));
        let url = Url::parse("http://[::1]:80/").unwrap();
        assert_eq!(canonical_host(&url).as_deref(), Some("[::1]"));
        let url = Url::parse("http://bücher.example/").unwrap();
        assert_eq!(
            canonical_host(&url).as_deref(),
            Some("xn--bcher-kva.example")
        );
        assert_eq!(
            canonical_host(&Url::parse("data:text/plain,x").unwrap()),
            None
        );
        assert_eq!(
            canonicalize_domain("Bücher.Example").as_deref(),
            Some("xn--bcher-kva.example")
        );
        assert!(is_ip_literal("[2001:db8::1]"));
        assert!(!is_ip_literal("example.com"));
    }

    #[test]
    fn same_site() {
        let list = rune_psl::List::embedded();
        let url = |s: &str| Url::parse(s).unwrap();
        assert!(is_same_site(
            &url("https://a.github.io/"),
            &url("https://a.github.io/x"),
            &list
        ));
        assert!(!is_same_site(
            &url("https://a.github.io/"),
            &url("https://b.github.io/"),
            &list
        ));
        assert!(is_same_site(
            &url("wss://x.example.com/"),
            &url("https://example.com/"),
            &list
        ));
        assert!(is_same_site(
            &url("http://127.0.0.1/"),
            &url("http://127.0.0.1:8080/"),
            &list
        ));
        assert!(!is_same_site(&url("data:,x"), &url("data:,x"), &list));
    }
}
