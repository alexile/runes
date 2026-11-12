//! Scan scope: which URLs a crawler or scanner may touch.

use std::fmt;
use std::str::FromStr;

use rune_cidr::Cidr;
use rune_host_match::{HostPattern, Hostname};
use url::{Host, Url};

use crate::Error;
use crate::canon::{Options, canonicalize_url};
use crate::site::{host_ip, is_internal_host};

/// One scope rule. Parse one from text with [`ScopeRule::parse`]:
///
/// | Text | Rule | Matches |
/// | --- | --- | --- |
/// | `https://example.com/app` | [`ScopeRule::Prefix`] | that origin, path `/app` and below (not `/apple`) |
/// | `10.0.0.0/8`, `192.0.2.7`, `[2001:db8::]/32` | [`ScopeRule::Cidr`] | IP-literal hosts in the range |
/// | `.example.com` | [`ScopeRule::Domain`] | `example.com` and every subdomain |
/// | `*.example.com` | [`ScopeRule::Host`] | every subdomain, not the apex |
/// | `example.com`, `api.*.example.com` | [`ScopeRule::Host`] | that exact host / pattern |
///
/// Unicode host names are converted to A-labels first, so `.bücher.de`
/// and `.xn--bcher-kva.de` are the same rule.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ScopeRule {
    /// A host name or `rune-host-match` allowlist pattern.
    Host(HostPattern),
    /// A host name and all of its subdomains.
    Domain(Hostname),
    /// IP-literal hosts in a range. IPv4-mapped IPv6 hosts are compared as
    /// IPv4.
    Cidr(Cidr),
    /// A canonical URL prefix: same scheme, host and port, and a path equal
    /// to the prefix's or below it on a segment boundary. The prefix's query
    /// and fragment are ignored.
    Prefix(Url),
    /// Hosts that are not globally routable: see
    /// [`is_internal_host`](crate::is_internal_host). Mostly useful as an
    /// exclusion.
    InternalHosts,
}

impl ScopeRule {
    /// Parses a rule; see the table on [`ScopeRule`].
    ///
    /// # Errors
    ///
    /// [`Error::InvalidRule`] if the text is no valid URL, range, host name
    /// or pattern.
    pub fn parse(text: &str) -> Result<Self, Error> {
        let text = text.trim();
        let invalid = |reason: String| Error::InvalidRule {
            rule: text.to_owned(),
            reason,
        };
        if text.contains("://") {
            let url = Url::parse(text).map_err(|err| invalid(err.to_string()))?;
            if url.cannot_be_a_base() || !url.has_host() {
                return Err(invalid("a URL prefix needs a host".to_owned()));
            }
            return Ok(Self::Prefix(canonicalize_url(&url, &scope_options())));
        }
        let unbracketed = text.replacen('[', "", 1).replacen(']', "", 1);
        if let Ok(cidr) = Cidr::parse(&unbracketed) {
            return Ok(Self::Cidr(cidr));
        }
        if let Some(domain) = text.strip_prefix('.') {
            let ascii = to_ascii_pattern(domain).map_err(invalid)?;
            let name = Hostname::parse(&ascii).map_err(|err| invalid(err.to_string()))?;
            return Ok(Self::Domain(name));
        }
        let ascii = to_ascii_pattern(text).map_err(invalid)?;
        HostPattern::parse(&ascii)
            .map(Self::Host)
            .map_err(|err| invalid(err.to_string()))
    }

    /// Whether `url` matches this rule. `url` is compared as it is; a
    /// [`Scope`] canonicalizes it first.
    #[must_use]
    pub fn matches(&self, url: &Url) -> bool {
        match self {
            Self::Host(pattern) => match url.host() {
                Some(Host::Domain(domain)) => pattern.matches(domain),
                _ => false,
            },
            Self::Domain(parent) => match url.host() {
                Some(Host::Domain(domain)) => Hostname::parse(domain)
                    .is_ok_and(|host| host == *parent || host.is_subdomain_of(parent)),
                _ => false,
            },
            Self::Cidr(range) => host_ip(url)
                .is_some_and(|ip| range.contains(ip) || range.contains(rune_ip::canonical(ip))),
            Self::Prefix(prefix) => prefix_matches(prefix, url),
            Self::InternalHosts => is_internal_host(url),
        }
    }
}

impl FromStr for ScopeRule {
    type Err = Error;

    fn from_str(text: &str) -> Result<Self, Error> {
        Self::parse(text)
    }
}

impl fmt::Display for ScopeRule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Host(pattern) => f.write_str(pattern.as_str()),
            Self::Domain(name) => write!(f, ".{name}"),
            Self::Cidr(range) => write!(f, "{range}"),
            Self::Prefix(url) => f.write_str(url.as_str()),
            Self::InternalHosts => f.write_str("<internal hosts>"),
        }
    }
}

/// Converts the labels of a host name or pattern to A-labels, leaving `*`
/// labels alone.
fn to_ascii_pattern(text: &str) -> Result<String, String> {
    if text.is_ascii() {
        return Ok(text.to_owned());
    }
    let options = rune_idna::Options::default();
    let labels: Result<Vec<String>, String> = text
        .split('.')
        .map(|label| {
            if label == "*" || label.is_empty() || label.is_ascii() {
                Ok(label.to_owned())
            } else {
                rune_idna::to_ascii(label, &options).map_err(|err| err.to_string())
            }
        })
        .collect();
    Ok(labels?.join("."))
}

/// What a scope does to a URL before matching: the semantics-preserving
/// steps plus a host's trailing dot and IPv4-mapped IPv6, so that no
/// spelling of a URL slips past a rule.
fn scope_options() -> Options {
    Options::default()
        .with_strip_trailing_dot(true)
        .with_unmap_ipv4(true)
        .with_remove_fragment(true)
}

fn prefix_matches(prefix: &Url, url: &Url) -> bool {
    if prefix.scheme() != url.scheme()
        || prefix.host_str() != url.host_str()
        || prefix.port_or_known_default() != url.port_or_known_default()
    {
        return false;
    }
    let base = prefix.path();
    let path = url.path();
    if base.ends_with('/') {
        return path.starts_with(base) || path == base.trim_end_matches('/');
    }
    path == base
        || path
            .strip_prefix(base)
            .is_some_and(|rest| rest.starts_with('/'))
}

/// A scan scope: URLs that match an include rule, no exclude rule, and use
/// an allowed scheme.
///
/// URLs are canonicalized before matching (dot segments, percent-encoding,
/// trailing dots, IPv4-mapped IPv6), so `http://example.com./admin/%2e%2e/x`
/// is judged as `http://example.com/x`.
///
/// ```
/// use rune_url::{Scope, Url};
///
/// let scope = Scope::parse(
///     [".example.com", "https://partner.test/api", "203.0.113.0/24"],
///     ["admin.example.com", "https://example.com/logout"],
/// )?;
/// assert!(scope.contains_str("https://www.example.com/a"));
/// assert!(scope.contains_str("https://EXAMPLE.com./b"));
/// assert!(scope.contains_str("https://partner.test/api/v1"));
/// assert!(!scope.contains_str("https://partner.test/apiv2"));
/// assert!(scope.contains_str("http://203.0.113.9:8080/"));
/// assert!(!scope.contains_str("https://admin.example.com/"));
/// assert!(!scope.contains_str("https://example.com/logout?next=/"));
/// assert!(!scope.contains_str("ftp://example.com/")); // http and https only
/// assert!(!scope.contains_str("https://example.org/"));
/// # Ok::<(), rune_url::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Scope {
    include: Vec<ScopeRule>,
    exclude: Vec<ScopeRule>,
    schemes: Vec<String>,
}

impl Default for Scope {
    fn default() -> Self {
        Self::new()
    }
}

impl Scope {
    /// An empty scope (nothing is in it) allowing `http` and `https`.
    #[must_use]
    pub fn new() -> Self {
        Self {
            include: Vec::new(),
            exclude: Vec::new(),
            schemes: vec!["http".to_owned(), "https".to_owned()],
        }
    }

    /// A scope from include and exclude rules in text form.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidRule`] for the first rule that does not parse.
    pub fn parse<I, E>(include: I, exclude: E) -> Result<Self, Error>
    where
        I: IntoIterator,
        I::Item: AsRef<str>,
        E: IntoIterator,
        E::Item: AsRef<str>,
    {
        let mut scope = Self::new();
        for rule in include {
            scope.include.push(ScopeRule::parse(rule.as_ref())?);
        }
        for rule in exclude {
            scope.exclude.push(ScopeRule::parse(rule.as_ref())?);
        }
        Ok(scope)
    }

    /// Adds an include rule.
    #[must_use]
    pub fn include(mut self, rule: ScopeRule) -> Self {
        self.include.push(rule);
        self
    }

    /// Adds an exclude rule.
    #[must_use]
    pub fn exclude(mut self, rule: ScopeRule) -> Self {
        self.exclude.push(rule);
        self
    }

    /// Replaces the allowed schemes (lowercase, without `:`). An empty list
    /// allows every scheme.
    #[must_use]
    pub fn with_schemes<I>(mut self, schemes: I) -> Self
    where
        I: IntoIterator,
        I::Item: AsRef<str>,
    {
        self.schemes = schemes
            .into_iter()
            .map(|scheme| scheme.as_ref().to_ascii_lowercase())
            .collect();
        self
    }

    /// The include rules.
    #[must_use]
    pub fn includes(&self) -> &[ScopeRule] {
        &self.include
    }

    /// The exclude rules.
    #[must_use]
    pub fn excludes(&self) -> &[ScopeRule] {
        &self.exclude
    }

    /// Whether `url` is in scope.
    #[must_use]
    pub fn contains(&self, url: &Url) -> bool {
        if !self.schemes.is_empty() && !self.schemes.iter().any(|scheme| scheme == url.scheme()) {
            return false;
        }
        let url = canonicalize_url(url, &scope_options());
        self.include.iter().any(|rule| rule.matches(&url))
            && !self.exclude.iter().any(|rule| rule.matches(&url))
    }

    /// Whether `input` parses as an absolute URL that is in scope.
    #[must_use]
    pub fn contains_str(&self, input: &str) -> bool {
        Url::parse(input).is_ok_and(|url| self.contains(&url))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn url(input: &str) -> Url {
        Url::parse(input).unwrap()
    }

    #[test]
    fn parses_each_kind() {
        assert!(matches!(
            ScopeRule::parse("https://h/app").unwrap(),
            ScopeRule::Prefix(_)
        ));
        assert!(matches!(
            ScopeRule::parse("10.0.0.0/8").unwrap(),
            ScopeRule::Cidr(_)
        ));
        assert!(matches!(
            ScopeRule::parse("[2001:db8::1]").unwrap(),
            ScopeRule::Cidr(_)
        ));
        assert!(matches!(
            ScopeRule::parse("::1").unwrap(),
            ScopeRule::Cidr(_)
        ));
        assert!(matches!(
            ScopeRule::parse(".example.com").unwrap(),
            ScopeRule::Domain(_)
        ));
        assert!(matches!(
            ScopeRule::parse("*.example.com").unwrap(),
            ScopeRule::Host(_)
        ));
        assert!(matches!(
            "3com.com".parse::<ScopeRule>().unwrap(),
            ScopeRule::Host(_)
        ));
        for bad in [
            "",
            "mailto:x://",
            "a..b",
            "*",
            ".",
            "10.0.0.0/33x",
            "data://",
        ] {
            assert!(ScopeRule::parse(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn unicode_rules() {
        let rule = ScopeRule::parse(".bücher.de").unwrap();
        assert_eq!(rule.to_string(), ".xn--bcher-kva.de");
        assert!(rule.matches(&url("http://www.bücher.de/")));
        let wildcard = ScopeRule::parse("*.bücher.de").unwrap();
        assert!(wildcard.matches(&url("http://a.xn--bcher-kva.de/")));
    }

    #[test]
    fn rule_matching() {
        let host = ScopeRule::parse("example.com").unwrap();
        assert!(host.matches(&url("http://example.com/")));
        assert!(!host.matches(&url("http://a.example.com/")));
        assert!(!host.matches(&url("http://93.184.216.34/")));

        let cidr = ScopeRule::parse("10.0.0.0/8").unwrap();
        assert!(cidr.matches(&url("http://10.2.3.4/")));
        assert!(cidr.matches(&url("http://[::ffff:10.2.3.4]/")));
        assert!(!cidr.matches(&url("http://example.com/")));

        let dir = ScopeRule::parse("https://h/app/").unwrap();
        assert!(dir.matches(&url("https://h/app/x")));
        assert!(dir.matches(&url("https://h/app")));
        assert!(!dir.matches(&url("https://h/apple")));
        assert!(!dir.matches(&url("https://h:8443/app/")));
        assert!(!dir.matches(&url("http://h/app/")));

        let root = ScopeRule::parse("https://h").unwrap();
        assert!(root.matches(&url("https://h/anything")));
        assert_eq!(ScopeRule::InternalHosts.to_string(), "<internal hosts>");
    }

    #[test]
    fn scope_canonicalizes_before_matching() {
        let scope = Scope::parse(["https://h/public/"], Vec::<&str>::new()).unwrap();
        assert!(!scope.contains_str("https://h/public/%2e%2e/admin"));
        assert!(!scope.contains_str("https://h/public/../admin"));
        assert!(scope.contains_str("https://H./public/%7Ex"));
        assert!(!scope.contains_str("not a url"));
    }

    #[test]
    fn exclusions_and_schemes() {
        let scope = Scope::new()
            .include(ScopeRule::parse(".example.com").unwrap())
            .exclude(ScopeRule::InternalHosts)
            .with_schemes(["HTTPS", "wss"]);
        assert!(scope.contains_str("wss://example.com/socket"));
        assert!(!scope.contains_str("http://example.com/"));
        assert_eq!(scope.includes().len(), 1);
        assert_eq!(scope.excludes(), [ScopeRule::InternalHosts]);

        let internal = Scope::new()
            .include(ScopeRule::parse("0.0.0.0/0").unwrap())
            .exclude(ScopeRule::InternalHosts)
            .with_schemes(Vec::<String>::new());
        assert!(internal.contains_str("ftp://8.8.8.8/"));
        assert!(!internal.contains_str("http://127.0.0.1/"));
        assert!(!Scope::default().contains_str("http://example.com/"));
    }
}
