//! HSTS preload list: submission eligibility and membership.

use std::collections::BTreeMap;
use std::fmt;

use rune_finding::{Confidence, Evidence, Finding, Location, Remediation, Severity, TaxonomyRef};

use crate::{Error, Hsts};

/// Smallest `max-age` the preload list accepts: one year
/// (<https://hstspreload.org/#submission-requirements>).
pub const PRELOAD_MIN_MAX_AGE: u64 = 31_536_000;

/// Submission requirements.
const PRELOAD_URL: &str = "https://hstspreload.org/#submission-requirements";
/// RFC 6797.
pub const RFC_URL: &str = "https://www.rfc-editor.org/rfc/rfc6797";

/// What the plain-HTTP origin (`http://<domain>/`, port 80) does.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
#[non_exhaustive]
pub enum HttpBehavior {
    /// Not observed; the redirect requirement is not checked.
    #[default]
    Unknown,
    /// Nothing listens on port 80, which the preload list accepts.
    NotListening,
    /// A redirect, with its `Location` header value.
    Redirect {
        /// The `Location` header value.
        location: String,
    },
    /// A response that is not a redirect.
    NoRedirect,
}

/// Facts about a site, gathered by the caller, for [`check_preload`].
///
/// The crate does no I/O: fetch `https://<domain>/` (without following
/// redirects) and `http://<domain>/`, and pass what you saw. The HSTS header
/// must come from that first HTTPS response, even if it is a redirect, as
/// the preload list requires.
///
/// The other published requirements — a valid certificate, and every
/// subdomain served over HTTPS — cannot be judged from these facts and are
/// left to the caller.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct Site {
    /// The domain to submit, e.g. `example.com`.
    pub domain: String,
    /// The `Strict-Transport-Security` value on `https://<domain>/`, if any.
    pub https_header: Option<String>,
    /// What `http://<domain>/` does.
    pub http: HttpBehavior,
}

impl Site {
    /// A site with no observations yet.
    #[must_use]
    pub fn new(domain: impl Into<String>) -> Self {
        Self {
            domain: domain.into(),
            https_header: None,
            http: HttpBehavior::Unknown,
        }
    }

    /// Sets [`Site::https_header`].
    #[must_use]
    pub fn with_https_header(mut self, header: impl Into<String>) -> Self {
        self.https_header = Some(header.into());
        self
    }

    /// Sets [`Site::http`].
    #[must_use]
    pub fn with_http(mut self, http: HttpBehavior) -> Self {
        self.http = http;
        self
    }

    /// Sets [`Site::http`] to a redirect to `location`.
    #[must_use]
    pub fn with_http_redirect(self, location: impl Into<String>) -> Self {
        self.with_http(HttpBehavior::Redirect {
            location: location.into(),
        })
    }
}

/// A preload requirement a site does not meet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[non_exhaustive]
pub enum PreloadIssueKind {
    /// The domain is not a valid ASCII host name (or is an IP address).
    InvalidDomain,
    /// The domain is a subdomain or a public suffix, not a registrable
    /// domain (eTLD+1). Needs the `psl` feature.
    NotRegistrableDomain,
    /// The HTTPS response has no HSTS header.
    MissingHeader,
    /// The HSTS header is invalid, so browsers ignore it.
    InvalidHeader,
    /// `max-age` is below one year.
    MaxAgeTooLow,
    /// `includeSubDomains` is missing.
    MissingIncludeSubdomains,
    /// `preload` is missing.
    MissingPreload,
    /// `http://<domain>/` answers without redirecting.
    NoHttpRedirect,
    /// The HTTP redirect does not go to `https://`.
    RedirectNotHttps,
    /// The HTTP redirect goes to HTTPS on another host first.
    RedirectToOtherHost,
}

impl PreloadIssueKind {
    /// The `snake_case` name, used in [`PreloadIssueKind::check_id`].
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidDomain => "invalid_domain",
            Self::NotRegistrableDomain => "not_registrable_domain",
            Self::MissingHeader => "missing_header",
            Self::InvalidHeader => "invalid_header",
            Self::MaxAgeTooLow => "max_age_too_low",
            Self::MissingIncludeSubdomains => "missing_include_subdomains",
            Self::MissingPreload => "missing_preload",
            Self::NoHttpRedirect => "no_http_redirect",
            Self::RedirectNotHttps => "redirect_not_https",
            Self::RedirectToOtherHost => "redirect_to_other_host",
        }
    }

    /// The stable `rune_finding` check id, `hsts.preload_<kind>`.
    #[must_use]
    pub fn check_id(self) -> String {
        format!("hsts.preload_{}", self.as_str())
    }

    /// What to do about it.
    #[must_use]
    pub const fn remediation(self) -> &'static str {
        match self {
            Self::InvalidDomain | Self::NotRegistrableDomain => {
                "Submit the registrable domain (e.g. example.com); subdomains are covered by its \
                 includeSubDomains."
            }
            Self::MissingHeader
            | Self::InvalidHeader
            | Self::MaxAgeTooLow
            | Self::MissingIncludeSubdomains
            | Self::MissingPreload => {
                "Send Strict-Transport-Security: max-age=63072000; includeSubDomains; preload \
                 on every HTTPS response of the base domain."
            }
            Self::NoHttpRedirect | Self::RedirectNotHttps | Self::RedirectToOtherHost => {
                "Redirect http://<domain>/ straight to https://<domain>/ before any other host."
            }
        }
    }

    const fn severity(self) -> Severity {
        match self {
            Self::NoHttpRedirect | Self::RedirectNotHttps => Severity::Medium,
            _ => Severity::Low,
        }
    }
}

impl fmt::Display for PreloadIssueKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One unmet preload requirement.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct PreloadIssue {
    /// Which requirement.
    pub kind: PreloadIssueKind,
    /// A human-readable explanation.
    pub message: String,
}

impl PreloadIssue {
    fn new(kind: PreloadIssueKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }

    /// Converts the issue into a [`rune_finding::Finding`] with check id
    /// `hsts.preload_<kind>`.
    #[must_use]
    pub fn to_finding<X: Default>(&self, domain: &str, location: &Location) -> Finding<X> {
        Finding::<X>::new(
            self.kind.check_id(),
            self.message.clone(),
            self.kind.severity(),
            Confidence::Firm,
            location.clone(),
        )
        .with_remediation(
            Remediation::new(self.kind.remediation())
                .push_reference(PRELOAD_URL)
                .push_reference(RFC_URL),
        )
        .push_taxonomy(TaxonomyRef::cwe(693))
        .push_taxonomy(TaxonomyRef::cwe(319))
        .push_evidence(Evidence::new("domain", domain.to_owned()))
    }
}

/// The result of [`check_preload`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Eligibility {
    /// The domain, lowercased and without a trailing dot.
    pub domain: String,
    /// The parsed header, when it parsed.
    pub hsts: Option<Hsts>,
    /// Unmet requirements; empty when the site is eligible.
    pub issues: Vec<PreloadIssue>,
}

impl Eligibility {
    /// No requirement checked here is unmet.
    #[must_use]
    pub const fn is_eligible(&self) -> bool {
        self.issues.is_empty()
    }

    /// Whether a requirement of `kind` is unmet.
    #[must_use]
    pub fn has(&self, kind: PreloadIssueKind) -> bool {
        self.issues.iter().any(|i| i.kind == kind)
    }

    /// Every issue as a [`rune_finding::Finding`] at `location`.
    #[must_use]
    pub fn to_findings<X: Default>(&self, location: &Location) -> Vec<Finding<X>> {
        self.issues
            .iter()
            .map(|i| i.to_finding(&self.domain, location))
            .collect()
    }
}

/// Checks a site against the published
/// [preload submission requirements](https://hstspreload.org/#submission-requirements):
///
/// 1. the domain is a registrable domain (eTLD+1; with the `psl` feature),
/// 2. `http://<domain>/` redirects to `https://<domain>/` first, if port 80
///    listens,
/// 3. the HTTPS response carries a valid HSTS header with
///    `max-age` ≥ [`PRELOAD_MIN_MAX_AGE`], `includeSubDomains` and `preload`.
///
/// Every unmet requirement is reported, not only the first.
#[must_use]
pub fn check_preload(site: &Site) -> Eligibility {
    let domain = normalize_host(&site.domain);
    let mut issues = Vec::new();
    domain_issues(&domain, &mut issues);
    let hsts = match &site.https_header {
        None => {
            issues.push(PreloadIssue::new(
                PreloadIssueKind::MissingHeader,
                format!("https://{domain}/ sends no Strict-Transport-Security header"),
            ));
            None
        }
        Some(value) => match Hsts::parse(value.trim()) {
            Ok(h) => {
                issues.extend(header_issues(&h));
                Some(h)
            }
            Err(e) => {
                issues.push(PreloadIssue::new(
                    PreloadIssueKind::InvalidHeader,
                    format!("Strict-Transport-Security header is invalid: {e}"),
                ));
                None
            }
        },
    };
    redirect_issues(&domain, &site.http, &mut issues);
    Eligibility {
        domain,
        hsts,
        issues,
    }
}

/// The header requirements alone: `max-age` of a year or more,
/// `includeSubDomains` and `preload`.
#[must_use]
pub fn header_issues(hsts: &Hsts) -> Vec<PreloadIssue> {
    let mut issues = Vec::new();
    if hsts.max_age < PRELOAD_MIN_MAX_AGE {
        issues.push(PreloadIssue::new(
            PreloadIssueKind::MaxAgeTooLow,
            format!(
                "max-age={} is below the {PRELOAD_MIN_MAX_AGE} seconds (one year) the preload \
                 list requires",
                hsts.max_age
            ),
        ));
    }
    if !hsts.include_subdomains {
        issues.push(PreloadIssue::new(
            PreloadIssueKind::MissingIncludeSubdomains,
            "includeSubDomains is missing; the preload list requires it",
        ));
    }
    if !hsts.preload {
        issues.push(PreloadIssue::new(
            PreloadIssueKind::MissingPreload,
            "The preload token is missing; the preload list requires it as consent",
        ));
    }
    issues
}

fn domain_issues(domain: &str, issues: &mut Vec<PreloadIssue>) {
    if !is_valid_host(domain) {
        issues.push(PreloadIssue::new(
            PreloadIssueKind::InvalidDomain,
            format!("{domain:?} is not a valid ASCII domain name"),
        ));
    } else if let Some(issue) = registrable_issue(domain) {
        issues.push(issue);
    }
}

/// The eTLD+1 requirement, from the embedded Public Suffix List.
#[cfg(feature = "psl")]
fn registrable_issue(domain: &str) -> Option<PreloadIssue> {
    let message = match rune_psl::registrable_domain(domain) {
        Some(r) if r == domain => return None,
        Some(r) => {
            format!("{domain} is a subdomain; only the registrable domain {r} can be preloaded")
        }
        None => format!("{domain} is a public suffix and cannot be preloaded"),
    };
    Some(PreloadIssue::new(
        PreloadIssueKind::NotRegistrableDomain,
        message,
    ))
}

/// Without the `psl` feature the eTLD+1 requirement is not checked.
#[cfg(not(feature = "psl"))]
const fn registrable_issue(_domain: &str) -> Option<PreloadIssue> {
    None
}

fn redirect_issues(domain: &str, http: &HttpBehavior, issues: &mut Vec<PreloadIssue>) {
    match http {
        HttpBehavior::Unknown | HttpBehavior::NotListening => {}
        HttpBehavior::NoRedirect => issues.push(PreloadIssue::new(
            PreloadIssueKind::NoHttpRedirect,
            format!("http://{domain}/ does not redirect to HTTPS"),
        )),
        HttpBehavior::Redirect { location } => {
            let location = location.trim();
            let Some(host) = https_host(location) else {
                issues.push(PreloadIssue::new(
                    PreloadIssueKind::RedirectNotHttps,
                    format!("http://{domain}/ redirects to {location:?}, not to HTTPS"),
                ));
                return;
            };
            if host != domain {
                issues.push(PreloadIssue::new(
                    PreloadIssueKind::RedirectToOtherHost,
                    format!(
                        "http://{domain}/ redirects to HTTPS on {host}, not on {domain}; the \
                         browser never sees {domain}'s HSTS header on the way"
                    ),
                ));
            }
        }
    }
}

/// The normalized host of an absolute `https://` URL.
fn https_host(location: &str) -> Option<String> {
    let scheme = location.get(..8)?;
    if !scheme.eq_ignore_ascii_case("https://") {
        return None;
    }
    let rest = &location[8..];
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    let host_port = authority.rsplit('@').next().unwrap_or_default();
    let host = if host_port.starts_with('[') {
        host_port.split_inclusive(']').next().unwrap_or_default()
    } else {
        host_port.split(':').next().unwrap_or_default()
    };
    Some(normalize_host(host))
}

/// Lowercases and strips one trailing dot.
pub fn normalize_host(host: &str) -> String {
    let host = host.trim();
    host.strip_suffix('.').unwrap_or(host).to_ascii_lowercase()
}

/// A dotted ASCII host name of LDH labels, at least two labels, not an IPv4
/// literal.
fn is_valid_host(host: &str) -> bool {
    if host.is_empty() || host.len() > 253 {
        return false;
    }
    let labels: Vec<&str> = host.split('.').collect();
    labels.len() >= 2
        && labels.iter().all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && !l.starts_with('-')
                && !l.ends_with('-')
                && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
        && labels
            .last()
            .is_some_and(|tld| !tld.bytes().all(|b| b.is_ascii_digit()))
}

/// One entry of a [`PreloadList`].
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct PreloadEntry {
    /// Lowercase domain name.
    pub name: String,
    /// The entry also covers every subdomain.
    pub include_subdomains: bool,
    /// The entry enforces HTTPS (Chromium `"mode": "force-https"`). Entries
    /// without it only carry other policies, such as key pins.
    pub force_https: bool,
}

impl PreloadEntry {
    /// An HSTS (`force-https`) entry.
    #[must_use]
    pub fn new(name: &str, include_subdomains: bool) -> Self {
        Self {
            name: normalize_host(name),
            include_subdomains,
            force_https: true,
        }
    }
}

/// The entry that decides a host's preload status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct PreloadMatch<'a> {
    /// The deciding entry.
    pub entry: &'a PreloadEntry,
    /// The entry is the host itself, not an ancestor.
    pub exact: bool,
}

impl PreloadMatch<'_> {
    /// Browsers load the host over HTTPS only.
    #[must_use]
    pub const fn is_hsts(&self) -> bool {
        self.entry.force_https
    }
}

/// A preload list, loaded by the caller — the crate never fetches it.
///
/// Lookups follow Chromium: the most specific entry that is the host itself,
/// or an ancestor with `include_subdomains`, decides.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PreloadList {
    entries: BTreeMap<String, PreloadEntry>,
}

impl PreloadList {
    /// An empty list.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds or replaces an entry.
    pub fn insert(&mut self, entry: PreloadEntry) {
        self.entries.insert(entry.name.clone(), entry);
    }

    /// Number of entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// The list has no entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The entries, sorted by name.
    pub fn entries(&self) -> impl Iterator<Item = &PreloadEntry> {
        self.entries.values()
    }

    /// Parses a plain list: one domain per line, optionally followed by
    /// `include_subdomains` (or `includeSubDomains`). Blank lines and
    /// lines starting with `#` or `//` are skipped.
    ///
    /// ```text
    /// # HSTS preload snapshot
    /// example.com include_subdomains
    /// www.example.org
    /// ```
    ///
    /// # Errors
    ///
    /// [`Error::InvalidList`] for an invalid domain or an unknown flag.
    pub fn parse(text: &str) -> Result<Self, Error> {
        let mut list = Self::new();
        for (index, line) in text.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') || line.starts_with("//") {
                continue;
            }
            let err = |message: String| Error::InvalidList {
                line: index + 1,
                message,
            };
            let mut words = line.split_ascii_whitespace();
            let name = normalize_host(words.next().unwrap_or_default());
            if !is_list_name(&name) {
                return Err(err(format!("invalid domain {name:?}")));
            }
            let mut include_subdomains = false;
            for flag in words {
                if flag.eq_ignore_ascii_case("include_subdomains")
                    || flag.eq_ignore_ascii_case("includesubdomains")
                {
                    include_subdomains = true;
                } else {
                    return Err(err(format!("unknown flag {flag:?}")));
                }
            }
            list.insert(PreloadEntry::new(&name, include_subdomains));
        }
        Ok(list)
    }

    /// Reads Chromium's `transport_security_state_static.json` (the source
    /// of the preload list), with its `//` comment lines. Entries keep
    /// their `include_subdomains` and whether `mode` is `force-https`.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidList`] when the text is not valid JSON of that shape
    /// or an entry name is invalid.
    #[cfg(feature = "chromium")]
    pub fn from_chromium_json(text: &str) -> Result<Self, Error> {
        #[derive(serde::Deserialize)]
        struct File {
            entries: Vec<Entry>,
        }
        #[derive(serde::Deserialize)]
        struct Entry {
            name: String,
            #[serde(default)]
            include_subdomains: bool,
            #[serde(default)]
            mode: Option<String>,
        }
        // Chromium's file only has whole-line comments, so dropping those
        // lines keeps line numbers intact and never touches strings.
        let json: String = text
            .lines()
            .map(|l| {
                if l.trim_start().starts_with("//") {
                    ""
                } else {
                    l
                }
            })
            .collect::<Vec<_>>()
            .join("\n");
        let file: File = serde_json::from_str(&json).map_err(|e| Error::InvalidList {
            line: e.line(),
            message: e.to_string(),
        })?;
        let mut list = Self::new();
        for entry in file.entries {
            let name = normalize_host(&entry.name);
            if !is_list_name(&name) {
                return Err(Error::InvalidList {
                    line: 0,
                    message: format!("invalid entry name {name:?}"),
                });
            }
            list.insert(PreloadEntry {
                name,
                include_subdomains: entry.include_subdomains,
                force_https: entry.mode.as_deref() == Some("force-https"),
            });
        }
        Ok(list)
    }

    /// The entry that decides `host`'s preload status, if any.
    #[must_use]
    pub fn lookup(&self, host: &str) -> Option<PreloadMatch<'_>> {
        let host = normalize_host(host);
        let mut suffix = host.as_str();
        let mut exact = true;
        loop {
            if let Some(entry) = self.entries.get(suffix)
                && (exact || entry.include_subdomains)
            {
                return Some(PreloadMatch { entry, exact });
            }
            let (_, parent) = suffix.split_once('.')?;
            suffix = parent;
            exact = false;
        }
    }

    /// Browsers load `host` over HTTPS only because of this list.
    #[must_use]
    pub fn is_preloaded(&self, host: &str) -> bool {
        self.lookup(host).is_some_and(|m| m.is_hsts())
    }
}

/// A list entry name: LDH labels; single-label names (whole TLDs such as
/// `dev`) are allowed.
fn is_list_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 253
        && name.split('.').all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && l.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hosts() {
        assert!(is_valid_host("example.com"));
        assert!(is_valid_host("xn--bcher-kva.example"));
        assert!(!is_valid_host("com"));
        assert!(!is_valid_host("192.168.0.1"));
        assert!(!is_valid_host("-a.com"));
        assert!(!is_valid_host("a..com"));
        assert!(!is_valid_host("ex ample.com"));
        assert_eq!(normalize_host(" Example.COM. "), "example.com");
    }

    #[test]
    fn https_hosts() {
        assert_eq!(
            https_host("HTTPS://Example.com:443/path?q").as_deref(),
            Some("example.com")
        );
        assert_eq!(
            https_host("https://user@www.example.com#x").as_deref(),
            Some("www.example.com")
        );
        assert_eq!(https_host("https://[::1]:8443/").as_deref(), Some("[::1]"));
        assert_eq!(https_host("http://example.com/"), None);
        assert_eq!(https_host("/relative"), None);
        assert_eq!(https_host("https:é"), None);
    }

    #[test]
    fn header_requirements() {
        let h = Hsts::new(PRELOAD_MIN_MAX_AGE)
            .with_include_subdomains(true)
            .with_preload(true);
        assert_eq!(header_issues(&h), []);
        let kinds: Vec<_> = header_issues(&Hsts::new(PRELOAD_MIN_MAX_AGE - 1))
            .into_iter()
            .map(|i| i.kind)
            .collect();
        assert_eq!(
            kinds,
            [
                PreloadIssueKind::MaxAgeTooLow,
                PreloadIssueKind::MissingIncludeSubdomains,
                PreloadIssueKind::MissingPreload
            ]
        );
    }

    #[test]
    fn list_names() {
        assert!(is_list_name("dev"));
        assert!(is_list_name("_dmarc.example.com"));
        assert!(!is_list_name("a..b"));
        assert!(!is_list_name(""));
    }
}
