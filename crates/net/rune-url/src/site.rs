//! Origins, sites and host helpers.

use std::net::IpAddr;

use rune_psl::List;
use url::{Host, Position, Url};

/// Whether `a` and `b` have the same
/// [origin](https://html.spec.whatwg.org/multipage/browsers.html#same-origin):
/// scheme, host and port. URLs with an opaque origin (`data:`, `file:`,
/// `mailto:` …) are never same-origin, not even with themselves.
///
/// ```
/// use rune_url::{Url, same_origin};
///
/// let a = Url::parse("https://example.com/a")?;
/// assert!(same_origin(&a, &Url::parse("https://EXAMPLE.com:443/b?x")?));
/// assert!(!same_origin(&a, &Url::parse("http://example.com/a")?));
/// assert!(!same_origin(&a, &Url::parse("https://www.example.com/a")?));
/// # Ok::<(), url::ParseError>(())
/// ```
#[must_use]
pub fn same_origin(a: &Url, b: &Url) -> bool {
    let (origin_a, origin_b) = (a.origin(), b.origin());
    origin_a.is_tuple() && origin_a == origin_b
}

/// The registrable domain (eTLD+1) of `url`'s host, from the embedded
/// Public Suffix List. `None` for IP hosts, hosts that are a public suffix
/// themselves, and URLs without a host.
///
/// ```
/// use rune_url::{Url, registrable_domain};
///
/// let url = Url::parse("https://a.b.example.co.uk/")?;
/// assert_eq!(registrable_domain(&url).as_deref(), Some("example.co.uk"));
/// # Ok::<(), url::ParseError>(())
/// ```
#[must_use]
pub fn registrable_domain(url: &Url) -> Option<String> {
    registrable_domain_with(&List::embedded(), url)
}

/// [`registrable_domain`] with a caller-supplied list.
#[must_use]
pub fn registrable_domain_with(list: &List, url: &Url) -> Option<String> {
    match url.host()? {
        Host::Domain(domain) => list.registrable_domain(domain.trim_end_matches('.')),
        Host::Ipv4(_) | Host::Ipv6(_) => None,
    }
}

/// The [site](https://html.spec.whatwg.org/multipage/browsers.html#obtain-a-site)
/// of `url`, as `scheme://registrable-domain`. Hosts without a registrable
/// domain (IP addresses, `localhost`, public suffixes such as `github.io`)
/// are their own site. `None` for URLs without a host.
///
/// ```
/// use rune_url::{Url, site};
///
/// assert_eq!(site(&Url::parse("https://docs.rust-lang.org/std")?).as_deref(), Some("https://rust-lang.org"));
/// assert_eq!(site(&Url::parse("http://10.0.0.1:8080/")?).as_deref(), Some("http://10.0.0.1"));
/// # Ok::<(), url::ParseError>(())
/// ```
#[must_use]
pub fn site(url: &Url) -> Option<String> {
    site_with(&List::embedded(), url)
}

/// [`site`] with a caller-supplied list.
#[must_use]
pub fn site_with(list: &List, url: &Url) -> Option<String> {
    let host = site_host(list, url)?;
    Some(format!("{}://{host}", url.scheme()))
}

fn site_host(list: &List, url: &Url) -> Option<String> {
    let host = url.host_str()?;
    if host.is_empty() {
        return None;
    }
    Some(
        registrable_domain_with(list, url)
            .unwrap_or_else(|| host.trim_end_matches('.').to_owned())
            .to_ascii_lowercase(),
    )
}

/// Whether `a` and `b` are
/// [schemefully same-site](https://html.spec.whatwg.org/multipage/browsers.html#schemelessly-same-site):
/// the same scheme and the same registrable domain (or the same host, when
/// it has none). Ports do not matter.
///
/// ```
/// use rune_url::{Url, same_site};
///
/// let a = Url::parse("https://app.example.com/")?;
/// assert!(same_site(&a, &Url::parse("https://api.example.com:8443/")?));
/// assert!(!same_site(&a, &Url::parse("http://api.example.com/")?));
/// // github.io is a public suffix: each user's pages are their own site.
/// assert!(!same_site(
///     &Url::parse("https://alice.github.io/")?,
///     &Url::parse("https://bob.github.io/")?,
/// ));
/// # Ok::<(), url::ParseError>(())
/// ```
#[must_use]
pub fn same_site(a: &Url, b: &Url) -> bool {
    same_site_with(&List::embedded(), a, b)
}

/// [`same_site`] with a caller-supplied list.
#[must_use]
pub fn same_site_with(list: &List, a: &Url, b: &Url) -> bool {
    a.scheme() == b.scheme() && schemelessly_same_site_with(list, a, b)
}

/// Whether `a` and `b` share a registrable domain (or host), whatever
/// their schemes: `http://example.com` and `https://www.example.com` are
/// schemelessly same-site.
#[must_use]
pub fn schemelessly_same_site(a: &Url, b: &Url) -> bool {
    schemelessly_same_site_with(&List::embedded(), a, b)
}

/// [`schemelessly_same_site`] with a caller-supplied list.
#[must_use]
pub fn schemelessly_same_site_with(list: &List, a: &Url, b: &Url) -> bool {
    match (site_host(list, a), site_host(list, b)) {
        (Some(a), Some(b)) => a == b,
        _ => false,
    }
}

/// The IP address of `url`'s host, when it is an IP literal.
///
/// ```
/// use rune_url::{Url, host_ip};
///
/// // WHATWG parsing already turns `0x7f.1` into 127.0.0.1.
/// assert_eq!(host_ip(&Url::parse("http://0x7f.1/")?), Some([127, 0, 0, 1].into()));
/// assert_eq!(host_ip(&Url::parse("http://localhost/")?), None);
/// # Ok::<(), url::ParseError>(())
/// ```
#[must_use]
pub fn host_ip(url: &Url) -> Option<IpAddr> {
    match url.host()? {
        Host::Ipv4(ip) => Some(IpAddr::V4(ip)),
        Host::Ipv6(ip) => Some(IpAddr::V6(ip)),
        Host::Domain(_) => None,
    }
}

/// Whether `url`'s host is internal: a non-global IP literal or `localhost`.
///
/// That is an IP literal that is not globally routable (loopback, private,
/// link-local, documentation …, per [`rune_ip::is_global`]), or the name
/// `localhost` or a name under `.localhost`. A scanner usually keeps such targets out of scope unless
/// they were asked for.
///
/// ```
/// use rune_url::{Url, is_internal_host};
///
/// assert!(is_internal_host(&Url::parse("http://[::ffff:192.168.1.1]/")?));
/// assert!(is_internal_host(&Url::parse("http://api.localhost/")?));
/// assert!(!is_internal_host(&Url::parse("http://8.8.8.8/")?));
/// assert!(!is_internal_host(&Url::parse("https://example.com/")?));
/// # Ok::<(), url::ParseError>(())
/// ```
#[must_use]
pub fn is_internal_host(url: &Url) -> bool {
    match url.host() {
        Some(Host::Ipv4(ip)) => !rune_ip::is_global(rune_ip::canonical(IpAddr::V4(ip))),
        Some(Host::Ipv6(ip)) => !rune_ip::is_global(rune_ip::canonical(IpAddr::V6(ip))),
        Some(Host::Domain(domain)) => {
            let domain = domain.trim_end_matches('.').to_ascii_lowercase();
            domain == "localhost" || domain.ends_with(".localhost")
        }
        None => false,
    }
}

/// `url`'s host for display, in Unicode.
///
/// A-labels are converted back to Unicode with
/// [`rune_idna::to_unicode`]. Falls back to the ASCII form when the
/// conversion fails. Show it next to a homograph check
/// ([`rune_idna::DomainReport`]) when the audience is human.
///
/// ```
/// use rune_url::{Url, display_host};
///
/// let url = Url::parse("https://Bücher.example/")?;
/// assert_eq!(url.host_str(), Some("xn--bcher-kva.example"));
/// assert_eq!(display_host(&url).as_deref(), Some("bücher.example"));
/// # Ok::<(), url::ParseError>(())
/// ```
#[must_use]
pub fn display_host(url: &Url) -> Option<String> {
    match url.host()? {
        Host::Domain(domain) => Some(
            rune_idna::to_unicode(domain, &rune_idna::Options::default())
                .unwrap_or_else(|_| domain.to_owned()),
        ),
        Host::Ipv4(_) | Host::Ipv6(_) => url.host_str().map(str::to_owned),
    }
}

/// `url` as text with its host in Unicode (see [`display_host`]); every
/// other component is left as serialized. For logs and reports, not for
/// requests.
///
/// ```
/// use rune_url::{Url, to_display_string};
///
/// let url = Url::parse("https://xn--bcher-kva.example/a?b")?;
/// assert_eq!(to_display_string(&url), "https://bücher.example/a?b");
/// # Ok::<(), url::ParseError>(())
/// ```
#[must_use]
pub fn to_display_string(url: &Url) -> String {
    match display_host(url) {
        Some(host) if url.host_str() != Some(host.as_str()) => format!(
            "{}{host}{}",
            &url[..Position::BeforeHost],
            &url[Position::AfterHost..]
        ),
        _ => url.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(input: &str) -> Url {
        Url::parse(input).unwrap()
    }

    #[test]
    fn opaque_origins_are_never_same_origin() {
        let data = parse("data:text/plain,x");
        assert!(!same_origin(&data, &data));
        assert!(same_origin(&parse("ws://h:80/"), &parse("ws://H/x")));
    }

    #[test]
    fn sites() {
        assert!(same_site(
            &parse("http://a.example.com./"),
            &parse("http://example.com/")
        ));
        assert!(same_site(
            &parse("http://[::1]/"),
            &parse("http://[::1]:81/")
        ));
        assert!(!same_site(
            &parse("http://[::1]/"),
            &parse("http://127.0.0.1/")
        ));
        assert!(!same_site(&parse("mailto:a@b"), &parse("mailto:a@b")));
        assert!(schemelessly_same_site(
            &parse("http://example.com/"),
            &parse("wss://www.example.com/")
        ));
        assert_eq!(
            site(&parse("https://github.io/")).as_deref(),
            Some("https://github.io")
        );
        assert_eq!(site(&parse("data:,x")), None);
        assert_eq!(registrable_domain(&parse("http://1.2.3.4/")), None);
    }

    #[test]
    fn custom_list() {
        let list = List::embedded();
        assert!(same_site_with(
            &list,
            &parse("https://a.example.org/"),
            &parse("https://b.example.org/")
        ));
        assert_eq!(
            site_with(&list, &parse("https://x.y.example.org/")).as_deref(),
            Some("https://example.org")
        );
    }

    #[test]
    fn internal_hosts() {
        assert!(is_internal_host(&parse("http://127.0.0.1/")));
        assert!(is_internal_host(&parse("http://10.1.2.3/")));
        assert!(is_internal_host(&parse("http://[fe80::1]/")));
        assert!(is_internal_host(&parse("http://LOCALHOST./")));
        assert!(!is_internal_host(&parse("http://notlocalhost/")));
        assert!(!is_internal_host(&parse("mailto:x@y")));
    }

    #[test]
    fn display_forms() {
        assert_eq!(
            display_host(&parse("http://[::1]/")).as_deref(),
            Some("[::1]")
        );
        assert_eq!(
            to_display_string(&parse("http://u@h:81/p")),
            "http://u@h:81/p"
        );
        assert_eq!(display_host(&parse("mailto:x")), None);
    }
}
