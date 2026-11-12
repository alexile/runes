//! Weakness analysis and the mapping to `rune_finding`.

use std::fmt;
use std::time::{Duration, SystemTime};

use rune_cookie::{
    CookieJar, Error, JarOptions, MAX_ATTRIBUTE_VALUE_LEN, RawAttribute, Rejection, RequestContext,
    SameSite, SetCookie, is_secure_scheme, is_valid_name, is_valid_value, parse_cookie_date,
    response_set_cookies,
};
use rune_finding::{Confidence, Evidence, Finding, Location, Remediation, Severity, TaxonomyRef};
use rune_http_model::HttpResponse;
use url::Url;

/// RFC 6265, the cookie specification.
const RFC_URL: &str = "https://www.rfc-editor.org/rfc/rfc6265";
/// RFC 6265bis, which adds `SameSite`, prefixes and the browser limits.
const RFC_BIS_URL: &str = "https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-rfc6265bis";
/// OWASP cheat sheet with cookie guidance.
const CHEAT_SHEET_URL: &str =
    "https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html";

/// One day.
const DAY: Duration = Duration::from_secs(86_400);

/// Substrings (lowercase) of cookie names that hold sessions or
/// credentials, used by [`Options::default`].
pub const DEFAULT_SENSITIVE_PATTERNS: &[&str] = &[
    "sess",
    "sid",
    "auth",
    "token",
    "jwt",
    "login",
    "remember",
    "saml",
    "oauth",
    "identity",
    "credential",
];

/// Substrings (lowercase) of anti-CSRF cookie names, which script often
/// has to read (double-submit pattern), so a missing `HttpOnly` is not
/// reported for them.
const SCRIPT_READABLE: &[&str] = &["csrf", "xsrf"];

/// Attribute names (lowercase) the analysis knows. `Priority` is a
/// Chromium extension.
const KNOWN_ATTRIBUTES: &[&str] = &[
    "expires",
    "max-age",
    "domain",
    "path",
    "secure",
    "httponly",
    "samesite",
    "partitioned",
    "priority",
];

/// Attribute names (lowercase) that look like a known attribute
/// misspelled; browsers ignore them, so the intended protection is absent.
const MISSPELLINGS: &[(&str, &str)] = &[
    ("http-only", "HttpOnly"),
    ("http_only", "HttpOnly"),
    ("httponly;", "HttpOnly"),
    ("htponly", "HttpOnly"),
    ("httpsonly", "HttpOnly"),
    ("secured", "Secure"),
    ("secure-only", "Secure"),
    ("secureonly", "Secure"),
    ("same-site", "SameSite"),
    ("same_site", "SameSite"),
    ("samesites", "SameSite"),
    ("max_age", "Max-Age"),
    ("maxage", "Max-Age"),
    ("expire", "Expires"),
    ("expiry", "Expires"),
    ("expiration", "Expires"),
    ("domains", "Domain"),
    ("paths", "Path"),
];

/// The class of a [`Weakness`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[non_exhaustive]
pub enum WeaknessKind {
    /// The header does not parse, so browsers ignore the cookie.
    InvalidHeader,
    /// The name breaks the strict `token` grammar of RFC 6265 §4.1.1.
    InvalidName,
    /// The value breaks the strict `cookie-value` grammar of RFC 6265
    /// §4.1.1.
    InvalidValue,
    /// No `Secure`: the cookie also goes out over plain HTTP.
    MissingSecure,
    /// No `HttpOnly`: script, and so cross-site scripting, can read it.
    MissingHttpOnly,
    /// No `SameSite`: browsers differ on the default, and some send the
    /// cookie with cross-site requests (CSRF).
    MissingSameSite,
    /// `SameSite=None`: the cookie goes with every cross-site request.
    SameSiteNone,
    /// `SameSite=None` without `Secure`: browsers reject the cookie.
    SameSiteNoneWithoutSecure,
    /// A `SameSite` value browsers do not recognise; they treat it as
    /// absent.
    InvalidSameSite,
    /// A `Domain` attribute: the cookie is shared with every subdomain.
    BroadDomain,
    /// `Domain` is a public suffix: browsers reject the cookie.
    PublicSuffixDomain,
    /// The request host is not within `Domain`: browsers reject the cookie.
    DomainMismatch,
    /// `Domain` is not a valid host name: browsers reject the cookie.
    InvalidDomain,
    /// No `Path`: the scope depends on the request URL, so the cookie can
    /// be duplicated or shadowed under other paths.
    MissingPath,
    /// A `__Secure-` cookie without `Secure` or from an insecure origin:
    /// browsers reject it.
    SecurePrefix,
    /// A `__Host-` cookie that is not `Secure`, host-only and `Path=/`:
    /// browsers reject it.
    HostPrefix,
    /// A sensitive cookie that qualifies for the `__Host-` prefix without
    /// using it; the prefix stops subdomains from overwriting it.
    MissingHostPrefix,
    /// A `Secure` cookie set over plain HTTP: browsers reject it.
    SecureFromInsecureOrigin,
    /// The cookie was set over plain HTTP, where it can be read and
    /// tampered with.
    InsecureTransport,
    /// The cookie lives longer than the configured limit.
    LongLifetime,
    /// `Partitioned` without `Secure`: browsers reject the cookie.
    PartitionedWithoutSecure,
    /// An attribute whose value browsers ignore (bad `Expires`, `Max-Age`
    /// or `Path`, empty `Domain`, oversized value, a value on a flag).
    InvalidAttribute,
    /// An attribute name that looks like a misspelled known attribute.
    MisspelledAttribute,
    /// An attribute repeated; the last valid one wins.
    DuplicateAttribute,
    /// An attribute no specification defines; browsers ignore it.
    UnknownAttribute,
    /// The response sets the same cookie (name, domain, path) more than
    /// once; the last one wins.
    DuplicateCookie,
    /// Browsers reject the cookie for another [`Rejection`].
    Rejected,
}

impl WeaknessKind {
    /// The `snake_case` name, used in [`WeaknessKind::check_id`].
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidHeader => "invalid_header",
            Self::InvalidName => "invalid_name",
            Self::InvalidValue => "invalid_value",
            Self::MissingSecure => "missing_secure",
            Self::MissingHttpOnly => "missing_http_only",
            Self::MissingSameSite => "missing_same_site",
            Self::SameSiteNone => "same_site_none",
            Self::SameSiteNoneWithoutSecure => "same_site_none_without_secure",
            Self::InvalidSameSite => "invalid_same_site",
            Self::BroadDomain => "broad_domain",
            Self::PublicSuffixDomain => "public_suffix_domain",
            Self::DomainMismatch => "domain_mismatch",
            Self::InvalidDomain => "invalid_domain",
            Self::MissingPath => "missing_path",
            Self::SecurePrefix => "secure_prefix",
            Self::HostPrefix => "host_prefix",
            Self::MissingHostPrefix => "missing_host_prefix",
            Self::SecureFromInsecureOrigin => "secure_from_insecure_origin",
            Self::InsecureTransport => "insecure_transport",
            Self::LongLifetime => "long_lifetime",
            Self::PartitionedWithoutSecure => "partitioned_without_secure",
            Self::InvalidAttribute => "invalid_attribute",
            Self::MisspelledAttribute => "misspelled_attribute",
            Self::DuplicateAttribute => "duplicate_attribute",
            Self::UnknownAttribute => "unknown_attribute",
            Self::DuplicateCookie => "duplicate_cookie",
            Self::Rejected => "rejected",
        }
    }

    /// The stable `rune_finding` check id, `cookie.<kind>`.
    #[must_use]
    pub fn check_id(self) -> String {
        format!("cookie.{}", self.as_str())
    }

    /// The kind for a reason a cookie jar refuses a cookie.
    #[must_use]
    pub const fn from_rejection(rejection: &Rejection) -> Self {
        match rejection {
            Rejection::DomainMismatch { .. } => Self::DomainMismatch,
            Rejection::PublicSuffix { .. } => Self::PublicSuffixDomain,
            Rejection::InvalidDomain { .. } => Self::InvalidDomain,
            Rejection::SecureFromInsecureOrigin => Self::SecureFromInsecureOrigin,
            Rejection::SecurePrefix => Self::SecurePrefix,
            Rejection::HostPrefix => Self::HostPrefix,
            Rejection::SameSiteNoneWithoutSecure => Self::SameSiteNoneWithoutSecure,
            _ => Self::Rejected,
        }
    }

    /// What to do about it.
    #[must_use]
    pub const fn remediation(self) -> &'static str {
        match self {
            Self::InvalidHeader | Self::InvalidName | Self::InvalidValue => {
                "Send name=value with a token name and a value of cookie-octets (encode \
                 anything else, for example with base64url)."
            }
            Self::MissingSecure | Self::InsecureTransport => {
                "Serve the site over HTTPS only and add Secure to the cookie."
            }
            Self::MissingHttpOnly => {
                "Add HttpOnly unless client-side script genuinely needs to read the cookie."
            }
            Self::MissingSameSite | Self::InvalidSameSite => {
                "Add SameSite=Lax (or Strict for cookies that never need to follow cross-site \
                 links)."
            }
            Self::SameSiteNone => {
                "Use SameSite=Lax or Strict unless the cookie must be sent in cross-site \
                 contexts; then protect state-changing requests against CSRF."
            }
            Self::SameSiteNoneWithoutSecure | Self::PartitionedWithoutSecure => {
                "Add Secure, which SameSite=None and Partitioned require."
            }
            Self::BroadDomain => {
                "Omit Domain so the cookie stays host-only, unless subdomains must share it."
            }
            Self::PublicSuffixDomain | Self::DomainMismatch | Self::InvalidDomain => {
                "Set Domain to the responding host or one of its parent domains below the \
                 public suffix, or omit it."
            }
            Self::MissingPath => "Set Path=/ (or the intended path) explicitly.",
            Self::SecurePrefix => "Add Secure and set __Secure- cookies only over HTTPS.",
            Self::HostPrefix => {
                "Give __Host- cookies Secure and Path=/, omit Domain, and set them over HTTPS."
            }
            Self::MissingHostPrefix => {
                "Rename the cookie with the __Host- prefix so subdomains cannot overwrite it."
            }
            Self::SecureFromInsecureOrigin => "Set Secure cookies only over HTTPS.",
            Self::LongLifetime => {
                "Shorten Max-Age/Expires; session credentials should expire within hours or days."
            }
            Self::InvalidAttribute => {
                "Fix the attribute value: an IMF-fixdate Expires, an integer Max-Age, a Path \
                 starting with /, and no value on Secure, HttpOnly or Partitioned."
            }
            Self::MisspelledAttribute => {
                "Fix the attribute name: Expires, Max-Age, Domain, Path, Secure, HttpOnly, \
                 SameSite, Partitioned."
            }
            Self::DuplicateAttribute => "List each attribute once.",
            Self::UnknownAttribute => "Remove the attribute; browsers ignore it.",
            Self::DuplicateCookie => "Set each cookie once per response.",
            Self::Rejected => "Fix the cookie so browsers store it.",
        }
    }

    /// CWE references.
    const fn cwes(self) -> &'static [u32] {
        match self {
            Self::MissingSecure => &[614],
            Self::InsecureTransport => &[319, 614],
            Self::MissingHttpOnly => &[1004],
            Self::MissingSameSite
            | Self::SameSiteNone
            | Self::InvalidSameSite
            | Self::SameSiteNoneWithoutSecure => &[1275, 352],
            Self::LongLifetime => &[613],
            _ => &[693],
        }
    }
}

impl fmt::Display for WeaknessKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One weakness found in a `Set-Cookie` header.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct Weakness {
    /// The class of weakness.
    pub kind: WeaknessKind,
    /// How much it matters, in context.
    pub severity: Severity,
    /// The cookie name, when the header parsed.
    pub cookie: Option<String>,
    /// The attribute concerned, as written, when there is one.
    pub attribute: Option<String>,
    /// A human-readable explanation.
    pub message: String,
}

impl Weakness {
    fn new(kind: WeaknessKind, severity: Severity, message: impl Into<String>) -> Self {
        Self {
            kind,
            severity,
            cookie: None,
            attribute: None,
            message: message.into(),
        }
    }

    fn of(mut self, cookie: &str) -> Self {
        self.cookie = Some(cookie.to_owned());
        self
    }

    fn at(mut self, attribute: &str) -> Self {
        self.attribute = Some(attribute.to_owned());
        self
    }

    /// Converts the weakness into a [`rune_finding::Finding`] with check id
    /// `cookie.<kind>`, CWE references and a remediation. The cookie name,
    /// when there is one, becomes the location parameter; it and the
    /// attribute become evidence.
    #[must_use]
    pub fn to_finding<X: Default>(&self, location: &Location) -> Finding<X> {
        let location = self.cookie.as_ref().map_or_else(
            || location.clone(),
            |c| location.clone().with_parameter(c.clone()),
        );
        let mut finding = Finding::<X>::new(
            self.kind.check_id(),
            self.message.clone(),
            self.severity,
            Confidence::Firm,
            location,
        )
        .with_remediation(
            Remediation::new(self.kind.remediation())
                .push_reference(RFC_URL)
                .push_reference(RFC_BIS_URL)
                .push_reference(CHEAT_SHEET_URL),
        );
        for cwe in self.kind.cwes() {
            finding = finding.push_taxonomy(TaxonomyRef::cwe(*cwe));
        }
        if let Some(c) = &self.cookie {
            finding = finding.push_evidence(Evidence::new("cookie", c.clone()));
        }
        if let Some(a) = &self.attribute {
            finding = finding.push_evidence(Evidence::new("attribute", a.clone()));
        }
        finding
    }
}

/// Settings for [`run`], [`run_fields`], [`run_response`] and [`analyze`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Options {
    /// The cookies came over HTTPS. Default: `true`. Off adds
    /// [`WeaknessKind::InsecureTransport`] and rejects `Secure` and
    /// prefixed cookies, as browsers do.
    pub https: bool,
    /// The URL of the request that received the cookies. When set,
    /// `Domain` is checked against its host and the public suffix list
    /// (with `rune-cookie`'s jar rules), and [`Options::https`] follows its
    /// scheme.
    pub request_url: Option<Url>,
    /// The current time, to judge `Expires`. Without it only `Max-Age`
    /// counts towards [`WeaknessKind::LongLifetime`].
    pub now: Option<SystemTime>,
    /// Longest lifetime for an ordinary cookie. Default: 400 days, the cap
    /// browsers apply (RFC 6265bis).
    pub max_lifetime: Duration,
    /// Longest lifetime for a sensitive cookie. Default: 30 days.
    pub max_sensitive_lifetime: Duration,
    /// Lowercase substrings that mark a cookie name as sensitive (session
    /// or credential). Sensitive cookies get stricter severities. Default:
    /// [`DEFAULT_SENSITIVE_PATTERNS`].
    pub sensitive_patterns: Vec<String>,
    /// Treat every cookie as sensitive. Default: off.
    pub all_sensitive: bool,
    /// Report a missing or `None` `SameSite`. Default: on.
    pub check_same_site: bool,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            https: true,
            request_url: None,
            now: None,
            max_lifetime: DAY * 400,
            max_sensitive_lifetime: DAY * 30,
            sensitive_patterns: DEFAULT_SENSITIVE_PATTERNS
                .iter()
                .map(|p| (*p).to_owned())
                .collect(),
            all_sensitive: false,
            check_same_site: true,
        }
    }
}

impl Options {
    /// Sets [`Options::https`].
    #[must_use]
    pub const fn with_https(mut self, https: bool) -> Self {
        self.https = https;
        self
    }

    /// Sets [`Options::request_url`], and [`Options::https`] from its
    /// scheme.
    #[must_use]
    pub fn with_request_url(mut self, url: Url) -> Self {
        self.https = is_secure_scheme(&url);
        self.request_url = Some(url);
        self
    }

    /// Sets [`Options::now`].
    #[must_use]
    pub const fn with_now(mut self, now: SystemTime) -> Self {
        self.now = Some(now);
        self
    }

    /// Sets [`Options::max_lifetime`].
    #[must_use]
    pub const fn with_max_lifetime(mut self, max: Duration) -> Self {
        self.max_lifetime = max;
        self
    }

    /// Sets [`Options::max_sensitive_lifetime`].
    #[must_use]
    pub const fn with_max_sensitive_lifetime(mut self, max: Duration) -> Self {
        self.max_sensitive_lifetime = max;
        self
    }

    /// Replaces [`Options::sensitive_patterns`]; patterns are lowercased.
    #[must_use]
    pub fn with_sensitive_patterns<S: AsRef<str>>(
        mut self,
        patterns: impl IntoIterator<Item = S>,
    ) -> Self {
        self.sensitive_patterns = patterns
            .into_iter()
            .map(|p| p.as_ref().to_ascii_lowercase())
            .collect();
        self
    }

    /// Sets [`Options::all_sensitive`].
    #[must_use]
    pub const fn with_all_sensitive(mut self, all: bool) -> Self {
        self.all_sensitive = all;
        self
    }

    /// Sets [`Options::check_same_site`].
    #[must_use]
    pub const fn with_check_same_site(mut self, check: bool) -> Self {
        self.check_same_site = check;
        self
    }

    /// Whether a cookie name counts as sensitive under these options.
    #[must_use]
    pub fn is_sensitive(&self, name: &str) -> bool {
        if self.all_sensitive {
            return true;
        }
        let name = name.to_ascii_lowercase();
        self.sensitive_patterns
            .iter()
            .any(|p| !p.is_empty() && name.contains(p.as_str()))
    }
}

/// The result of [`run`], [`run_fields`] and [`run_response`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Report {
    /// Each `Set-Cookie` header, parsed or not, in wire order.
    pub cookies: Vec<Result<SetCookie, Error>>,
    /// Weaknesses of every cookie, most severe first (wire order within a
    /// severity).
    pub weaknesses: Vec<Weakness>,
}

impl Report {
    /// The most severe weakness level, if any.
    #[must_use]
    pub fn max_severity(&self) -> Option<Severity> {
        self.weaknesses.iter().map(|w| w.severity).max()
    }

    /// Whether no weakness was found.
    #[must_use]
    pub const fn is_clean(&self) -> bool {
        self.weaknesses.is_empty()
    }

    /// The weaknesses of the cookie called `name`.
    pub fn weaknesses_of<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a Weakness> + 'a {
        self.weaknesses
            .iter()
            .filter(move |w| w.cookie.as_deref() == Some(name))
    }

    /// Every weakness as a [`rune_finding::Finding`] at `location`.
    #[must_use]
    pub fn to_findings<X: Default>(&self, location: &Location) -> Vec<Finding<X>> {
        self.weaknesses
            .iter()
            .map(|w| w.to_finding(location))
            .collect()
    }
}

/// Parses and analyzes one `Set-Cookie` header value.
#[must_use]
pub fn run(header: &str, options: &Options) -> Report {
    run_fields([header], options)
}

/// Parses and analyzes every `Set-Cookie` header value of one response.
#[must_use]
pub fn run_fields<'a>(fields: impl IntoIterator<Item = &'a str>, options: &Options) -> Report {
    report(fields.into_iter().map(SetCookie::parse).collect(), options)
}

/// Analyzes every `Set-Cookie` header of `response`.
///
/// When [`Options::request_url`] is unset, the response's own URL is not
/// known either; set it to check `Domain` against the host.
#[must_use]
pub fn run_response(response: &HttpResponse, options: &Options) -> Report {
    report(response_set_cookies(response).collect(), options)
}

fn report(cookies: Vec<Result<SetCookie, Error>>, options: &Options) -> Report {
    let mut weaknesses = Vec::new();
    let mut seen: Vec<(&str, Option<&str>, Option<&str>)> = Vec::new();
    for cookie in &cookies {
        match cookie {
            Ok(c) => {
                weaknesses.extend(analyze(c, options));
                let identity = (c.name.as_str(), c.domain.as_deref(), c.path.as_deref());
                if seen.contains(&identity) {
                    weaknesses.push(
                        Weakness::new(
                            WeaknessKind::DuplicateCookie,
                            Severity::Informational,
                            format!("Cookie {} is set more than once; the last one wins", c.name),
                        )
                        .of(&c.name),
                    );
                } else {
                    seen.push(identity);
                }
            }
            Err(e) => weaknesses.push(Weakness::new(
                WeaknessKind::InvalidHeader,
                Severity::Low,
                format!("Set-Cookie is ignored by browsers: {e}"),
            )),
        }
    }
    sort(&mut weaknesses);
    Report {
        cookies,
        weaknesses,
    }
}

/// Analyzes one parsed cookie; weaknesses come most severe first.
///
/// A cookie that deletes itself (`Max-Age` ≤ 0, or `Expires` before
/// [`Options::now`]) is not held to the attribute recommendations, but
/// still to the rules that make browsers reject it.
#[must_use]
pub fn analyze(cookie: &SetCookie, options: &Options) -> Vec<Weakness> {
    let name = cookie.name.as_str();
    let sensitive = options.is_sensitive(name);
    let pick = |hi: Severity, lo: Severity| if sensitive { hi } else { lo };
    let deletion = is_deletion(cookie, options.now);
    let mut out = Vec::new();
    let mut push = |w: Weakness| out.push(w.of(name));

    if !is_valid_name(name) {
        push(Weakness::new(
            WeaknessKind::InvalidName,
            Severity::Low,
            format!(
                "Cookie name {name:?} is not a valid token; servers and browsers may disagree on it"
            ),
        ));
    }
    if !is_valid_value(&cookie.value) {
        push(Weakness::new(
            WeaknessKind::InvalidValue,
            Severity::Informational,
            format!("Value of cookie {name} has characters outside cookie-octet"),
        ));
    }

    let same_site_invalid = attribute_checks(&cookie.attributes, &mut push);

    // Transport.
    if !options.https {
        if cookie.secure {
            push(Weakness::new(
                WeaknessKind::SecureFromInsecureOrigin,
                Severity::Low,
                format!("Secure cookie {name} was set over plain HTTP; browsers reject it"),
            ));
        } else if !deletion {
            push(Weakness::new(
                WeaknessKind::InsecureTransport,
                pick(Severity::Medium, Severity::Low),
                format!("Cookie {name} was set over plain HTTP, where it can be read and changed"),
            ));
        }
    }

    // Rules that make browsers reject the cookie.
    if cookie.same_site == Some(SameSite::None) && !cookie.secure {
        push(
            Weakness::new(
                WeaknessKind::SameSiteNoneWithoutSecure,
                Severity::Medium,
                format!("Cookie {name} has SameSite=None without Secure; browsers reject it"),
            )
            .at("SameSite"),
        );
    }
    if cookie.partitioned && !cookie.secure {
        push(
            Weakness::new(
                WeaknessKind::PartitionedWithoutSecure,
                Severity::Low,
                format!("Cookie {name} is Partitioned without Secure; browsers reject it"),
            )
            .at("Partitioned"),
        );
    }
    let has_domain_attribute = cookie
        .attributes
        .iter()
        .any(|a| a.name.eq_ignore_ascii_case("domain"));
    if cookie.has_host_prefix() {
        if !(cookie.secure
            && options.https
            && !has_domain_attribute
            && cookie.path.as_deref() == Some("/"))
        {
            push(Weakness::new(
                WeaknessKind::HostPrefix,
                Severity::Medium,
                format!(
                    "__Host- cookie {name} must be Secure, set over HTTPS, have Path=/ and no \
                     Domain; browsers reject it"
                ),
            ));
        }
    } else if cookie.has_secure_prefix() && !(cookie.secure && options.https) {
        push(Weakness::new(
            WeaknessKind::SecurePrefix,
            Severity::Medium,
            format!(
                "__Secure- cookie {name} must be Secure and set over HTTPS; browsers reject it"
            ),
        ));
    }

    // Recommendations, for cookies that are being set.
    if !deletion {
        if options.https && !cookie.secure {
            push(Weakness::new(
                WeaknessKind::MissingSecure,
                pick(Severity::Medium, Severity::Low),
                format!("Cookie {name} has no Secure attribute and is also sent over plain HTTP"),
            ));
        }
        let script_readable = {
            let lower = name.to_ascii_lowercase();
            SCRIPT_READABLE.iter().any(|p| lower.contains(p))
        };
        if !cookie.http_only && !script_readable {
            push(Weakness::new(
                WeaknessKind::MissingHttpOnly,
                pick(Severity::Medium, Severity::Informational),
                format!("Cookie {name} has no HttpOnly attribute; script can read it"),
            ));
        }
        if options.check_same_site {
            match cookie.same_site {
                None if !same_site_invalid => push(Weakness::new(
                    WeaknessKind::MissingSameSite,
                    pick(Severity::Low, Severity::Informational),
                    format!(
                        "Cookie {name} has no SameSite attribute; some browsers send it with \
                         cross-site requests"
                    ),
                )),
                Some(SameSite::None) if cookie.secure => push(
                    Weakness::new(
                        WeaknessKind::SameSiteNone,
                        pick(Severity::Low, Severity::Informational),
                        format!(
                            "Cookie {name} has SameSite=None and goes with cross-site requests"
                        ),
                    )
                    .at("SameSite"),
                ),
                _ => {}
            }
        }
        if let Some(lifetime) = lifetime(cookie, options.now) {
            let limit = if sensitive {
                options.max_sensitive_lifetime
            } else {
                options.max_lifetime
            };
            if lifetime > limit {
                push(Weakness::new(
                    WeaknessKind::LongLifetime,
                    pick(Severity::Low, Severity::Informational),
                    format!(
                        "Cookie {name} lives {} days, more than the {} days allowed",
                        lifetime.as_secs() / DAY.as_secs(),
                        limit.as_secs() / DAY.as_secs()
                    ),
                ));
            }
        }
        if cookie.path.is_none() {
            push(Weakness::new(
                WeaknessKind::MissingPath,
                Severity::Informational,
                format!(
                    "Cookie {name} has no valid Path; its scope depends on the URL that set it"
                ),
            ));
        }
        if sensitive
            && cookie.secure
            && options.https
            && !has_domain_attribute
            && cookie.path.as_deref() == Some("/")
            && !cookie.has_host_prefix()
        {
            push(Weakness::new(
                WeaknessKind::MissingHostPrefix,
                Severity::Informational,
                format!(
                    "Cookie {name} could use the __Host- prefix to resist subdomain overwrites"
                ),
            ));
        }
    }

    // Domain scope.
    if let Some(domain) = &cookie.domain {
        push(
            Weakness::new(
                WeaknessKind::BroadDomain,
                pick(Severity::Low, Severity::Informational),
                format!("Cookie {name} has Domain={domain} and is sent to every subdomain of it"),
            )
            .at("Domain"),
        );
    }
    if let Some(w) = jar_rejection(cookie, options, &out) {
        out.push(w);
    }

    sort(&mut out);
    out
}

/// The reason `rune-cookie`'s jar refuses the cookie for
/// [`Options::request_url`], unless `found` already reports it.
fn jar_rejection(cookie: &SetCookie, options: &Options, found: &[Weakness]) -> Option<Weakness> {
    let url = options.request_url.as_ref()?;
    let now = options.now.unwrap_or(SystemTime::UNIX_EPOCH);
    let mut jar = CookieJar::with_options(JarOptions::default());
    let Err(Error::Rejected(rejection)) =
        jar.store_parsed(url, cookie, &RequestContext::http(), now)
    else {
        return None;
    };
    let kind = WeaknessKind::from_rejection(&rejection);
    if found.iter().any(|w| w.kind == kind) {
        return None;
    }
    let w = Weakness::new(
        kind,
        Severity::Medium,
        format!("Browsers reject cookie {}: {rejection}", cookie.name),
    )
    .of(&cookie.name);
    Some(match rejection {
        Rejection::DomainMismatch { .. }
        | Rejection::PublicSuffix { .. }
        | Rejection::InvalidDomain { .. } => w.at("Domain"),
        _ => w,
    })
}

/// Checks the raw attributes; returns whether a `SameSite` attribute was
/// present but none had a recognised value.
fn attribute_checks(attributes: &[RawAttribute], push: &mut impl FnMut(Weakness)) -> bool {
    let mut seen: Vec<String> = Vec::new();
    let mut same_site_seen = false;
    let mut same_site_valid = false;
    for attr in attributes {
        let raw = attr.name.as_str();
        let lower = raw.to_ascii_lowercase();
        let value = attr.value.as_deref().unwrap_or("");
        let weakness =
            |kind, severity, message: String| Weakness::new(kind, severity, message).at(raw);

        if !KNOWN_ATTRIBUTES.contains(&lower.as_str()) {
            if let Some((_, correct)) = MISSPELLINGS.iter().find(|(m, _)| *m == lower) {
                push(weakness(
                    WeaknessKind::MisspelledAttribute,
                    Severity::Low,
                    format!("Attribute {raw} looks like a misspelling of {correct} and is ignored"),
                ));
            } else {
                push(weakness(
                    WeaknessKind::UnknownAttribute,
                    Severity::Informational,
                    format!("Unknown attribute {raw:?} is ignored"),
                ));
            }
            continue;
        }

        if seen.contains(&lower) {
            push(weakness(
                WeaknessKind::DuplicateAttribute,
                Severity::Informational,
                format!("Attribute {raw} is repeated; the last valid one wins"),
            ));
        } else {
            seen.push(lower.clone());
        }

        if value.len() > MAX_ATTRIBUTE_VALUE_LEN {
            push(weakness(
                WeaknessKind::InvalidAttribute,
                Severity::Informational,
                format!(
                    "Attribute {raw} has a {}-byte value, over the {MAX_ATTRIBUTE_VALUE_LEN}-byte \
                     limit, and is ignored",
                    value.len()
                ),
            ));
            if lower == "samesite" {
                same_site_seen = true;
            }
            continue;
        }

        let problem = match lower.as_str() {
            "expires" => parse_cookie_date(value)
                .is_none()
                .then(|| format!("Expires={value:?} is not a date and is ignored")),
            "max-age" => (!is_valid_max_age(value))
                .then(|| format!("Max-Age={value:?} is not an integer and is ignored")),
            "path" => (!value.starts_with('/')).then(|| {
                format!("Path={value:?} does not start with / and is ignored (default path used)")
            }),
            "domain" => value
                .is_empty()
                .then(|| "Empty Domain is ignored".to_owned()),
            "secure" | "httponly" | "partitioned" => attr
                .value
                .is_some()
                .then(|| format!("{raw} takes no value; the value is ignored")),
            "samesite" => {
                same_site_seen = true;
                if SameSite::from_attribute(value).is_some() {
                    same_site_valid = true;
                } else {
                    push(weakness(
                        WeaknessKind::InvalidSameSite,
                        Severity::Low,
                        format!("SameSite={value:?} is not Strict, Lax or None and is ignored"),
                    ));
                }
                None
            }
            _ => None,
        };
        if let Some(message) = problem {
            push(weakness(
                WeaknessKind::InvalidAttribute,
                Severity::Informational,
                message,
            ));
        }
    }
    same_site_seen && !same_site_valid
}

/// RFC 6265 §5.2.2: an optional `-` then one or more digits.
fn is_valid_max_age(value: &str) -> bool {
    let digits = value.strip_prefix('-').unwrap_or(value);
    !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit())
}

/// Whether the cookie deletes itself.
fn is_deletion(cookie: &SetCookie, now: Option<SystemTime>) -> bool {
    match (cookie.max_age, cookie.expires, now) {
        (Some(age), _, _) => age <= 0,
        (None, Some(expires), Some(now)) => expires <= now,
        _ => false,
    }
}

/// How long the cookie lives, when it is persistent and that is known.
fn lifetime(cookie: &SetCookie, now: Option<SystemTime>) -> Option<Duration> {
    match (cookie.max_age, cookie.expires, now) {
        (Some(age), _, _) => (age > 0).then(|| Duration::from_secs(age.unsigned_abs())),
        (None, Some(expires), Some(now)) => expires.duration_since(now).ok(),
        _ => None,
    }
}

fn sort(weaknesses: &mut [Weakness]) {
    weaknesses.sort_by_key(|w| std::cmp::Reverse(w.severity));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kinds(header: &str, options: &Options) -> Vec<(WeaknessKind, Severity)> {
        run(header, options)
            .weaknesses
            .into_iter()
            .map(|w| (w.kind, w.severity))
            .collect()
    }

    #[test]
    fn hardened_cookie_is_clean() {
        let o = Options::default();
        assert_eq!(
            kinds("__Host-sid=abc; Path=/; Secure; HttpOnly; SameSite=Lax", &o),
            []
        );
        assert_eq!(
            kinds(
                "theme=dark; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=3600",
                &o
            ),
            []
        );
    }

    #[test]
    fn sensitivity_raises_severity() {
        let o = Options::default();
        let k = kinds("sessionid=1; Path=/", &o);
        assert!(k.contains(&(WeaknessKind::MissingSecure, Severity::Medium)));
        assert!(k.contains(&(WeaknessKind::MissingHttpOnly, Severity::Medium)));
        assert!(k.contains(&(WeaknessKind::MissingSameSite, Severity::Low)));
        let k = kinds("theme=1; Path=/", &o);
        assert!(k.contains(&(WeaknessKind::MissingSecure, Severity::Low)));
        assert!(k.contains(&(WeaknessKind::MissingHttpOnly, Severity::Informational)));
        assert!(k.contains(&(WeaknessKind::MissingSameSite, Severity::Informational)));
        let o = Options::default().with_all_sensitive(true);
        assert!(
            kinds("theme=1; Path=/", &o).contains(&(WeaknessKind::MissingSecure, Severity::Medium))
        );
        let o = Options::default().with_sensitive_patterns(["THEME"]);
        assert!(o.is_sensitive("Theme"));
        assert!(!o.is_sensitive("sid"));
    }

    #[test]
    fn csrf_cookie_may_be_script_readable() {
        let k = kinds(
            "XSRF-TOKEN=1; Path=/; Secure; SameSite=Strict",
            &Options::default(),
        );
        assert!(
            !k.iter()
                .any(|(kind, _)| *kind == WeaknessKind::MissingHttpOnly)
        );
    }

    #[test]
    fn deletion_skips_recommendations() {
        let k = kinds("sid=; Max-Age=0; Path=/", &Options::default());
        assert_eq!(k, []);
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let o = Options::default().with_now(now);
        assert_eq!(
            kinds("sid=; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Path=/", &o),
            []
        );
        // Still rejected by browsers, so it cannot delete anything.
        assert_eq!(
            kinds("__Host-sid=; Max-Age=0; Path=/", &o),
            [(WeaknessKind::HostPrefix, Severity::Medium)]
        );
    }

    #[test]
    fn rejection_mapping() {
        assert_eq!(
            WeaknessKind::from_rejection(&Rejection::PublicSuffix {
                domain: "com".into()
            }),
            WeaknessKind::PublicSuffixDomain
        );
        assert_eq!(
            WeaknessKind::from_rejection(&Rejection::OverwritesSecure),
            WeaknessKind::Rejected
        );
        assert_eq!(
            WeaknessKind::LongLifetime.check_id(),
            "cookie.long_lifetime"
        );
    }

    #[test]
    fn max_age_grammar() {
        assert!(is_valid_max_age("0"));
        assert!(is_valid_max_age("-5"));
        assert!(!is_valid_max_age("-"));
        assert!(!is_valid_max_age(""));
        assert!(!is_valid_max_age("1h"));
    }
}
