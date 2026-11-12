//! URL canonicalization.

use std::net::IpAddr;

use url::{Host, Position, Url};

use crate::Error;
use crate::percent::{lowercase_preserving_escapes, normalize_percent_encoding};
use crate::query::{ParamFilter, QueryParams};

/// Settings for [`canonicalize`].
///
/// Parsing with the [`url`] crate already applies the
/// [WHATWG URL Standard](https://url.spec.whatwg.org/) rules: the scheme
/// and special-scheme hosts are lowercased, internationalized hosts become
/// A-labels, IPv4 hosts in any notation (`0x7f.1`) become dotted decimal,
/// IPv6 hosts are compressed, default ports are removed, `.` and `..`
/// segments (also as `%2e`) are resolved and an empty `http` path becomes
/// `/`. [`canonicalize`] adds, always:
///
/// - percent-encoding normalization of the user info, path, query and
///   fragment ([RFC 3986 §6.2.2.2](https://www.rfc-editor.org/rfc/rfc3986#section-6.2.2.2)):
///   escapes of unreserved characters are decoded, other escapes get
///   uppercase hex;
/// - lowercasing of opaque hosts of non-special schemes
///   (`foo://HOST/`), which RFC 3986 makes case-insensitive.
///
/// Those steps never change which resource a URL names. The options below
/// are the ones that may, and are all off in [`Options::default`].
/// [`Options::crawler`] turns on the ones a crawler or scanner wants.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
#[allow(
    clippy::struct_excessive_bools,
    reason = "independent normalization switches, set through builders"
)]
pub struct Options {
    /// Remove the fragment (`#…`), which is never sent to the server.
    pub remove_fragment: bool,
    /// Remove a `?` with nothing after it (`/a?` → `/a`).
    pub remove_empty_query: bool,
    /// Sort query parameters by name (stable, so repeated names keep their
    /// order). When the query is rebuilt this way, empty pieces (`&&`) are
    /// dropped as well.
    pub sort_query: bool,
    /// Drop query parameters, and `;name=value` path parameters (as in
    /// `/a;jsessionid=…`), whose names this filter matches. An emptied
    /// query loses its `?`; empty pieces (`&&`) are dropped.
    pub drop_params: Option<ParamFilter>,
    /// Remove the trailing dot of a fully qualified host
    /// (`example.com.` → `example.com`).
    pub strip_trailing_dot: bool,
    /// Remove the user name and password.
    pub remove_userinfo: bool,
    /// Rewrite IPv4-mapped and IPv4-compatible IPv6 hosts as IPv4
    /// (`[::ffff:10.0.0.1]` → `10.0.0.1`), using [`rune_ip::canonical`].
    pub unmap_ipv4: bool,
}

impl Options {
    /// The settings for crawlers and scanners: on top of the defaults,
    /// remove the fragment, an empty query, tracking parameters
    /// ([`ParamFilter::tracking`]) and a host's trailing dot, and unmap
    /// IPv4-mapped IPv6 hosts. The query order is kept: sort it in a dedup
    /// key ([`crate::KeyOptions`]) rather than in the URL you request.
    #[must_use]
    pub fn crawler() -> Self {
        Self {
            remove_fragment: true,
            remove_empty_query: true,
            sort_query: false,
            drop_params: Some(ParamFilter::tracking()),
            strip_trailing_dot: true,
            remove_userinfo: false,
            unmap_ipv4: true,
        }
    }

    /// Sets [`Options::remove_fragment`].
    #[must_use]
    pub const fn with_remove_fragment(mut self, yes: bool) -> Self {
        self.remove_fragment = yes;
        self
    }

    /// Sets [`Options::remove_empty_query`].
    #[must_use]
    pub const fn with_remove_empty_query(mut self, yes: bool) -> Self {
        self.remove_empty_query = yes;
        self
    }

    /// Sets [`Options::sort_query`].
    #[must_use]
    pub const fn with_sort_query(mut self, yes: bool) -> Self {
        self.sort_query = yes;
        self
    }

    /// Sets [`Options::drop_params`].
    #[must_use]
    pub fn with_drop_params(mut self, filter: Option<ParamFilter>) -> Self {
        self.drop_params = filter;
        self
    }

    /// Sets [`Options::strip_trailing_dot`].
    #[must_use]
    pub const fn with_strip_trailing_dot(mut self, yes: bool) -> Self {
        self.strip_trailing_dot = yes;
        self
    }

    /// Sets [`Options::remove_userinfo`].
    #[must_use]
    pub const fn with_remove_userinfo(mut self, yes: bool) -> Self {
        self.remove_userinfo = yes;
        self
    }

    /// Sets [`Options::unmap_ipv4`].
    #[must_use]
    pub const fn with_unmap_ipv4(mut self, yes: bool) -> Self {
        self.unmap_ipv4 = yes;
        self
    }
}

/// Parses `input` as an absolute URL and canonicalizes it.
///
/// ```
/// use rune_url::{Options, canonicalize};
///
/// let url = canonicalize("HTTP://Example.COM:80/a/./b/../%7euser/%3a?q=%41", &Options::default())?;
/// assert_eq!(url.as_str(), "http://example.com/a/~user/%3A?q=A");
/// # Ok::<(), rune_url::Error>(())
/// ```
///
/// # Errors
///
/// [`Error::Parse`] if `input` is not a valid absolute URL.
pub fn canonicalize(input: &str, options: &Options) -> Result<Url, Error> {
    let url = Url::parse(input)?;
    Ok(canonicalize_url(&url, options))
}

/// Resolves `reference` (an `href`, a `Location` header) against `base`
/// ([RFC 3986 §5](https://www.rfc-editor.org/rfc/rfc3986#section-5)) and
/// canonicalizes the result.
///
/// ```
/// use rune_url::{Options, Url, resolve};
///
/// let base = Url::parse("http://a/b/c/d;p?q")?;
/// assert_eq!(resolve(&base, "../g", &Options::default())?.as_str(), "http://a/b/g");
/// assert_eq!(resolve(&base, "//G/%7e", &Options::default())?.as_str(), "http://g/~");
/// # Ok::<(), rune_url::Error>(())
/// ```
///
/// # Errors
///
/// [`Error::Parse`] if the reference cannot be resolved.
pub fn resolve(base: &Url, reference: &str, options: &Options) -> Result<Url, Error> {
    let url = base.join(reference)?;
    Ok(canonicalize_url(&url, options))
}

/// Canonicalizes an already parsed URL. See [`Options`] for the steps.
///
/// The result is a fixed point: canonicalizing it again changes nothing.
#[must_use]
pub fn canonicalize_url(url: &Url, options: &Options) -> Url {
    // Some steps (decoding `%2E`, dropping path parameters) can expose
    // something `Url` normalizes on re-parse, so run to a fixed point; two
    // rounds settle every input seen so far, the bound is a safety net.
    let mut current = canonicalize_once(url.clone(), options);
    for _ in 0..4 {
        let Ok(reparsed) = Url::parse(current.as_str()) else {
            break;
        };
        let next = canonicalize_once(reparsed, options);
        let settled = next.as_str() == current.as_str();
        // Keep the re-parsed URL even when the text is unchanged: setters can
        // leave a `Url` whose structure (host or no host) differs from what
        // its own text parses to.
        current = next;
        if settled {
            break;
        }
    }
    current
}

fn canonicalize_once(mut url: Url, options: &Options) -> Url {
    normalize_host(&mut url, options);
    normalize_userinfo(&mut url, options);
    normalize_path(&mut url, options.drop_params.as_ref());
    normalize_query(&mut url, options);
    normalize_fragment(&mut url, options);
    url
}

fn normalize_host(url: &mut Url, options: &Options) {
    let replacement = match url.host() {
        Some(Host::Domain(domain)) => {
            let mut host = if url.has_authority() && is_special(url) {
                domain.to_owned()
            } else {
                lowercase_preserving_escapes(domain)
            };
            if options.strip_trailing_dot {
                let trimmed = host.trim_end_matches('.');
                if !trimmed.is_empty() {
                    host.truncate(trimmed.len());
                }
            }
            (host != domain).then_some(host)
        }
        Some(Host::Ipv6(ip)) if options.unmap_ipv4 => match rune_ip::canonical(IpAddr::V6(ip)) {
            IpAddr::V4(v4) => Some(v4.to_string()),
            IpAddr::V6(_) => None,
        },
        _ => None,
    };
    if let Some(host) = replacement {
        // Best effort: a host the URL rejects is left as it was.
        let _ = url.set_host(Some(&host));
    }
}

fn is_special(url: &Url) -> bool {
    matches!(
        url.scheme(),
        "http" | "https" | "ws" | "wss" | "ftp" | "file"
    )
}

fn normalize_userinfo(url: &mut Url, options: &Options) {
    if options.remove_userinfo {
        let _ = url.set_password(None);
        let _ = url.set_username("");
        return;
    }
    let username = normalize_percent_encoding(url.username());
    if username != url.username() {
        let _ = url.set_username(&username);
    }
    if let Some(password) = url.password() {
        let normalized = normalize_percent_encoding(password);
        if normalized != password {
            let _ = url.set_password(Some(&normalized));
        }
    }
}

fn normalize_path(url: &mut Url, drop: Option<&ParamFilter>) {
    let original = url.path();
    let mut path = normalize_percent_encoding(original);
    if let Some(filter) = drop
        && !url.cannot_be_a_base()
    {
        path = drop_path_params(&path, filter);
    }
    if path == original {
        return;
    }
    if !url.has_host() && !url.cannot_be_a_base() && path.starts_with("//") {
        // `Url::set_path` does not add the `/.` the WHATWG serializer puts
        // in front of a hostless path starting with `//` (it would read back
        // as a host), so go through the parser instead.
        let text = format!("{}:/.{path}{}", url.scheme(), &url[Position::AfterPath..]);
        if let Ok(parsed) = Url::parse(&text) {
            *url = parsed;
        }
        return;
    }
    url.set_path(&path);
}

/// Removes `;name=value` parameters whose names `filter` matches from
/// every path segment.
fn drop_path_params(path: &str, filter: &ParamFilter) -> String {
    if !path.contains(';') {
        return path.to_owned();
    }
    let segments: Vec<String> = path
        .split('/')
        .map(|segment| {
            let mut parts = segment.split(';');
            let mut kept = parts.next().unwrap_or_default().to_owned();
            for param in parts {
                let name = param.split_once('=').map_or(param, |(name, _)| name);
                let decoded = rune_url_encode::decode_lossy(name);
                if !filter.matches(&decoded) {
                    kept.push(';');
                    kept.push_str(param);
                }
            }
            kept
        })
        .collect();
    segments.join("/")
}

fn normalize_query(url: &mut Url, options: &Options) {
    let Some(original) = url.query() else {
        return;
    };
    let normalized = normalize_percent_encoding(original);
    let rebuild = options.sort_query || options.drop_params.is_some();
    if rebuild {
        let mut params = QueryParams::parse(&normalized);
        params.remove_empty();
        if let Some(filter) = &options.drop_params {
            params.remove_matching(filter);
        }
        if options.sort_query {
            params.sort_by_name();
        }
        if params.is_empty() && (options.remove_empty_query || !normalized.is_empty()) {
            url.set_query(None);
        } else {
            let query = params.to_string();
            if query != original {
                url.set_query(Some(&query));
            }
        }
    } else if normalized.is_empty() && options.remove_empty_query {
        url.set_query(None);
    } else if normalized != original {
        url.set_query(Some(&normalized));
    }
}

fn normalize_fragment(url: &mut Url, options: &Options) {
    if options.remove_fragment {
        url.set_fragment(None);
        return;
    }
    if let Some(fragment) = url.fragment() {
        let normalized = normalize_percent_encoding(fragment);
        if normalized != fragment {
            url.set_fragment(Some(&normalized));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn canon(input: &str) -> String {
        canonicalize(input, &Options::default())
            .unwrap()
            .to_string()
    }

    fn crawl_url(input: &str) -> Url {
        canonicalize(input, &Options::crawler()).unwrap()
    }

    fn crawl(input: &str) -> String {
        canonicalize(input, &Options::crawler())
            .unwrap()
            .to_string()
    }

    #[test]
    fn default_steps() {
        assert_eq!(canon("HTTP://EXAMPLE.com:80"), "http://example.com/");
        assert_eq!(canon("http://u%7e:p%3a@h/"), "http://u~:p%3A@h/");
        assert_eq!(canon("http://h/?a=%7e#%7e%2f"), "http://h/?a=~#~%2F");
        assert_eq!(canon("foo://HoSt/P"), "foo://host/P");
        assert_eq!(canon("http://h/a?"), "http://h/a?");
        assert_eq!(canon("http://h./"), "http://h./");
        assert_eq!(canon("http://h/#frag"), "http://h/#frag");
    }

    #[test]
    fn crawler_steps() {
        assert_eq!(crawl("http://h./a?#x"), "http://h/a");
        assert_eq!(
            crawl("http://h/a?utm_source=x&id=1&&fbclid=y"),
            "http://h/a?id=1"
        );
        assert_eq!(crawl("http://h/a?utm_source=x"), "http://h/a");
        assert_eq!(crawl("http://[::ffff:10.0.0.1]/"), "http://10.0.0.1/");
        assert_eq!(crawl("http://[2001:db8::1]/"), "http://[2001:db8::1]/");
        // Regression: every trailing dot goes, in one pass.
        assert_eq!(crawl("http://é%2e..%2e.../"), "http://xn--9ca/");
        // Regression: dropping `;pk_…` leaves a hostless path that
        // starts with `//`; the result must have the structure its text has.
        let url = crawl_url("h:/;pk_x//p");
        let reparsed = Url::parse(url.as_str()).unwrap();
        assert_eq!(url.has_host(), reparsed.has_host());
        assert_eq!(url.path(), reparsed.path());
        let url = crawl_url("h:/;pk_x/:/x");
        assert_eq!(url.as_str(), "h:/.//:/x");
        assert_eq!(Url::parse(url.as_str()).unwrap(), url);
        assert_eq!(crawl("http://h/?b=1&a=2"), "http://h/?b=1&a=2");
    }

    #[test]
    fn path_parameters() {
        let options = Options::default().with_drop_params(Some(ParamFilter::session_ids()));
        let url =
            canonicalize("http://h/a;jsessionid=ABC/b;v=1;JSESSIONID=x?x=1", &options).unwrap();
        assert_eq!(url.as_str(), "http://h/a/b;v=1?x=1");
    }

    #[test]
    fn sorted_query() {
        let options = Options::default().with_sort_query(true);
        assert_eq!(
            canonicalize("http://h/?b=1&&a=2&a=1", &options)
                .unwrap()
                .as_str(),
            "http://h/?a=2&a=1&b=1"
        );
        assert_eq!(
            canonicalize("http://h/?", &options).unwrap().as_str(),
            "http://h/?"
        );
        let both = options.with_remove_empty_query(true);
        assert_eq!(
            canonicalize("http://h/?&", &both).unwrap().as_str(),
            "http://h/"
        );
    }

    #[test]
    fn userinfo_removed() {
        let options = Options::default().with_remove_userinfo(true);
        assert_eq!(
            canonicalize("http://u:p@h/", &options).unwrap().as_str(),
            "http://h/"
        );
    }

    #[test]
    fn decoded_dots_do_not_reintroduce_segments() {
        assert_eq!(canon("http://h/a/.%2E%2e/b"), "http://h/a/.../b");
        assert_eq!(canon("http://h/a/%2e%2E/b"), "http://h/b");
    }

    #[test]
    fn opaque_urls() {
        assert_eq!(
            canon("mailto:Joe%2eX@Example.COM"),
            "mailto:Joe.X@Example.COM"
        );
        assert_eq!(canon("data:text/plain,%7e"), "data:text/plain,~");
    }

    #[test]
    fn rejects_relative_input() {
        assert!(matches!(
            canonicalize("/relative", &Options::default()),
            Err(Error::Parse(_))
        ));
    }
}
