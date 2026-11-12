//! The CORS check, origin classification, weakness analysis and the
//! mapping to `rune_finding`.

use std::collections::BTreeSet;
use std::fmt;

use rune_finding::{Confidence, Evidence, Finding, Location, Remediation, Severity, TaxonomyRef};

use crate::headers::{AllowOrigin, CorsHeaders};
use crate::origin::Origin;

/// Fetch standard, CORS protocol.
const SPEC_URL: &str = "https://fetch.spec.whatwg.org/#http-cors-protocol";
/// OWASP testing guide entry for CORS.
const OWASP_URL: &str = "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/07-Testing_Cross_Origin_Resource_Sharing";

/// Host label used to build attacker-controlled probe origins.
const PROBE_LABEL: &str = "rune-cors-probe";

/// What a browser lets a page at the request origin read, per the
/// [Fetch CORS check](https://fetch.spec.whatwg.org/#cors-check).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[non_exhaustive]
pub enum Exposure {
    /// The response is not shared with the origin.
    None,
    /// Readable by requests without credentials (`credentials: "omit"` or
    /// `"same-origin"`).
    Anonymous,
    /// Readable by credentialed requests too: cookies and HTTP
    /// authentication are sent and the response is shared.
    Credentialed,
}

impl Exposure {
    /// A lowercase name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Anonymous => "anonymous",
            Self::Credentialed => "credentialed",
        }
    }
}

impl fmt::Display for Exposure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Runs the Fetch CORS check for a request from `origin` (a serialized
/// origin or `null`) against `headers`.
///
/// ```
/// use rune_cors::{CorsHeaders, Exposure, cors_check};
///
/// let h = CorsHeaders::from_pairs([("access-control-allow-origin", "*")]);
/// assert_eq!(cors_check("https://a.example", &h), Exposure::Anonymous);
///
/// // `*` never shares credentialed responses, even with credentials allowed.
/// let h = CorsHeaders::from_pairs([
///     ("access-control-allow-origin", "*"),
///     ("access-control-allow-credentials", "true"),
/// ]);
/// assert_eq!(cors_check("https://a.example", &h), Exposure::Anonymous);
/// ```
#[must_use]
pub fn cors_check(origin: &str, headers: &CorsHeaders) -> Exposure {
    match headers.allow_origin.as_deref() {
        Some("*") => Exposure::Anonymous,
        Some(v) if v == origin => {
            if headers.allows_credentials() {
                Exposure::Credentialed
            } else {
                Exposure::Anonymous
            }
        }
        _ => Exposure::None,
    }
}

/// How a request origin relates to the site under test
/// ([`Options::target`]) and its [`Options::trusted`] origins.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[non_exhaustive]
pub enum OriginClass {
    /// The target origin itself.
    SameOrigin,
    /// Listed in [`Options::trusted`], or a subdomain of a trusted origin
    /// when [`Options::trust_subdomains`] is set.
    Trusted,
    /// A subdomain of the target or a trusted origin (or the same host on
    /// another port), over a scheme at least as secure.
    Subdomain,
    /// The target or a trusted host (or a subdomain) over plain `http`/`ws`
    /// while the trusted origin is secure: a network attacker can forge it.
    InsecureScheme,
    /// The trusted host with an attacker prefix and no dot boundary,
    /// `evilexample.com`: passes a naive "ends with" check.
    UnanchoredSuffix,
    /// The trusted host followed by an attacker suffix,
    /// `example.com.evil.net`: passes a naive "starts with" check.
    UnanchoredPrefix,
    /// The opaque origin `null`, which sandboxed frames and `data:` URLs
    /// carry and any attacker can produce.
    Null,
    /// Unrelated to the target and not trusted, or not a valid origin.
    Arbitrary,
}

impl OriginClass {
    /// The `snake_case` name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SameOrigin => "same_origin",
            Self::Trusted => "trusted",
            Self::Subdomain => "subdomain",
            Self::InsecureScheme => "insecure_scheme",
            Self::UnanchoredSuffix => "unanchored_suffix",
            Self::UnanchoredPrefix => "unanchored_prefix",
            Self::Null => "null",
            Self::Arbitrary => "arbitrary",
        }
    }

    /// Whether an attacker can be expected to control a page at such an
    /// origin. [`OriginClass::Subdomain`] is not counted: it needs a
    /// subdomain takeover or XSS first.
    #[must_use]
    pub const fn is_attacker_controlled(self) -> bool {
        matches!(
            self,
            Self::InsecureScheme
                | Self::UnanchoredSuffix
                | Self::UnanchoredPrefix
                | Self::Null
                | Self::Arbitrary
        )
    }
}

impl fmt::Display for OriginClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The class of a [`Weakness`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[non_exhaustive]
pub enum WeaknessKind {
    /// An arbitrary request origin is echoed back in
    /// `Access-Control-Allow-Origin`. Critical with credentials.
    OriginReflection,
    /// `Access-Control-Allow-Origin: null` is granted. Any page can obtain
    /// a `null` origin through a sandboxed iframe.
    NullOrigin,
    /// An origin that only passes an unanchored allowlist check
    /// (`evilexample.com`, `example.com.evil.net`) is granted.
    UnanchoredAllowlist,
    /// A plain-`http` variant of a secure trusted origin is granted, so a
    /// network attacker can read responses.
    InsecureOrigin,
    /// Arbitrary subdomains are granted: one subdomain takeover or XSS
    /// exposes the API.
    SubdomainOrigin,
    /// `*` combined with `Access-Control-Allow-Credentials: true`. Browsers
    /// refuse it, but it shows credentials were meant to be shared and the
    /// usual "fix" is origin reflection.
    WildcardWithCredentials,
    /// `Access-Control-Allow-Origin: *`: any site can read anonymous
    /// responses.
    WildcardOrigin,
    /// The request origin is echoed but `Vary` does not list `Origin`, so a
    /// shared cache can serve one origin's grant to another.
    MissingVaryOrigin,
    /// `Access-Control-Allow-Private-Network: true` is granted to an
    /// attacker-controlled origin.
    PrivateNetworkAccess,
    /// `Access-Control-Allow-Origin` can never match: several values, a
    /// list, non-canonical case or port, or garbage.
    InvalidAllowOrigin,
    /// `Access-Control-Allow-Credentials` is present with a value other than
    /// `true`, which browsers ignore.
    InvalidAllowCredentials,
    /// `*` in `Access-Control-Allow-Methods`, `-Allow-Headers` or
    /// `-Expose-Headers` on a credentialed response, where it is a literal
    /// name rather than a wildcard.
    WildcardListWithCredentials,
}

impl WeaknessKind {
    /// The `snake_case` name, used in [`WeaknessKind::check_id`].
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::OriginReflection => "origin_reflection",
            Self::NullOrigin => "null_origin",
            Self::UnanchoredAllowlist => "unanchored_allowlist",
            Self::InsecureOrigin => "insecure_origin",
            Self::SubdomainOrigin => "subdomain_origin",
            Self::WildcardWithCredentials => "wildcard_with_credentials",
            Self::WildcardOrigin => "wildcard_origin",
            Self::MissingVaryOrigin => "missing_vary_origin",
            Self::PrivateNetworkAccess => "private_network_access",
            Self::InvalidAllowOrigin => "invalid_allow_origin",
            Self::InvalidAllowCredentials => "invalid_allow_credentials",
            Self::WildcardListWithCredentials => "wildcard_list_with_credentials",
        }
    }

    /// The stable `rune_finding` check id, `cors.<kind>`.
    #[must_use]
    pub fn check_id(self) -> String {
        format!("cors.{}", self.as_str())
    }

    /// What to do about it.
    #[must_use]
    pub const fn remediation(self) -> &'static str {
        match self {
            Self::OriginReflection | Self::UnanchoredAllowlist | Self::SubdomainOrigin => {
                "Compare the Origin header against an exact allowlist of trusted origins \
                 (full scheme://host:port equality, no substring or regex matching) and \
                 only then echo it."
            }
            Self::NullOrigin => "Never allow the null origin; remove it from the allowlist.",
            Self::InsecureOrigin => "Allow only https:// origins.",
            Self::WildcardWithCredentials => {
                "Decide whether credentials are needed: drop Access-Control-Allow-Credentials \
                 for public data, or replace * with an exact origin allowlist."
            }
            Self::WildcardOrigin => {
                "Use * only for public, unauthenticated resources; otherwise use an exact \
                 origin allowlist."
            }
            Self::MissingVaryOrigin => {
                "Send Vary: Origin on every response whose Access-Control-Allow-Origin \
                 depends on the request."
            }
            Self::PrivateNetworkAccess => {
                "Grant Access-Control-Allow-Private-Network only to exact trusted origins."
            }
            Self::InvalidAllowOrigin => {
                "Send exactly one Access-Control-Allow-Origin with *, or the single \
                 requesting origin serialized as browsers send it."
            }
            Self::InvalidAllowCredentials => {
                "Send Access-Control-Allow-Credentials: true, or omit the header."
            }
            Self::WildcardListWithCredentials => {
                "List methods and headers explicitly on credentialed responses."
            }
        }
    }

    /// CWE classification.
    const fn cwes(self) -> &'static [u32] {
        match self {
            Self::OriginReflection
            | Self::NullOrigin
            | Self::UnanchoredAllowlist
            | Self::SubdomainOrigin
            | Self::WildcardWithCredentials
            | Self::WildcardOrigin
            | Self::PrivateNetworkAccess => &[942],
            Self::InsecureOrigin => &[942, 346],
            Self::MissingVaryOrigin => &[524],
            Self::InvalidAllowOrigin
            | Self::InvalidAllowCredentials
            | Self::WildcardListWithCredentials => &[16],
        }
    }
}

impl fmt::Display for WeaknessKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One weakness found in an exchange.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct Weakness {
    /// The class of weakness.
    pub kind: WeaknessKind,
    /// How much it matters, given credentials and the origin class.
    pub severity: Severity,
    /// Index of the exchange in the [`run`] input (0 for [`analyze`]).
    pub exchange: usize,
    /// The request `Origin`, when the exchange had one.
    pub origin: Option<String>,
    /// The `Access-Control-Allow-Origin` value, when present.
    pub allow_origin: Option<String>,
    /// A human-readable explanation.
    pub message: String,
}

impl Weakness {
    /// Converts the weakness into a [`rune_finding::Finding`] with check id
    /// `cors.<kind>`, CWE references, a remediation and the request origin
    /// and `Access-Control-Allow-Origin` as evidence.
    ///
    /// The location is used as is, so the same weakness seen with several
    /// probe origins fingerprints once.
    #[must_use]
    pub fn to_finding<X: Default>(&self, location: &Location) -> Finding<X> {
        let mut finding = Finding::<X>::new(
            self.kind.check_id(),
            self.message.clone(),
            self.severity,
            Confidence::Firm,
            location.clone(),
        )
        .with_remediation(
            Remediation::new(self.kind.remediation())
                .push_reference(SPEC_URL)
                .push_reference(OWASP_URL),
        );
        for cwe in self.kind.cwes() {
            finding = finding.push_taxonomy(TaxonomyRef::cwe(*cwe));
        }
        if let Some(o) = &self.origin {
            finding = finding.push_evidence(Evidence::new("origin", o.clone()));
        }
        if let Some(a) = &self.allow_origin {
            finding =
                finding.push_evidence(Evidence::new("access-control-allow-origin", a.clone()));
        }
        finding
    }
}

/// Settings for [`run`], [`analyze`] and [`classify`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct Options {
    /// The origin of the site under test. Probe origins are classified
    /// relative to it and to [`Options::trusted`].
    pub target: Option<Origin>,
    /// Origins the site deliberately shares with. Granting them is not a
    /// weakness. Without a target and trusted origins, every echoed
    /// non-`null` origin counts as arbitrary.
    pub trusted: Vec<Origin>,
    /// Treat subdomains of the target and trusted origins (over a scheme at
    /// least as secure) as trusted. Off by default.
    pub trust_subdomains: bool,
}

impl Options {
    /// Options for a site at `target`.
    #[must_use]
    pub fn for_target(target: Origin) -> Self {
        Self::default().with_target(target)
    }

    /// Sets [`Options::target`].
    #[must_use]
    pub fn with_target(mut self, target: Origin) -> Self {
        self.target = Some(target);
        self
    }

    /// Adds a [`Options::trusted`] origin.
    #[must_use]
    pub fn with_trusted(mut self, origin: Origin) -> Self {
        self.trusted.push(origin);
        self
    }

    /// Sets [`Options::trust_subdomains`].
    #[must_use]
    pub const fn with_trust_subdomains(mut self, trust: bool) -> Self {
        self.trust_subdomains = trust;
        self
    }
}

/// Classifies a request origin (a serialized origin or `null`) relative to
/// [`Options::target`] and [`Options::trusted`]. When it relates to several
/// of them, the least risky class wins.
///
/// ```
/// use rune_cors::{Options, OriginClass, classify};
///
/// let opts = Options::for_target("https://example.com".parse()?);
/// assert_eq!(classify("https://example.com", &opts), OriginClass::SameOrigin);
/// assert_eq!(classify("https://api.example.com", &opts), OriginClass::Subdomain);
/// assert_eq!(classify("http://example.com", &opts), OriginClass::InsecureScheme);
/// assert_eq!(classify("https://evilexample.com", &opts), OriginClass::UnanchoredSuffix);
/// assert_eq!(classify("https://example.com.evil.net", &opts), OriginClass::UnanchoredPrefix);
/// assert_eq!(classify("null", &opts), OriginClass::Null);
/// assert_eq!(classify("https://evil.net", &opts), OriginClass::Arbitrary);
/// # Ok::<(), rune_cors::Error>(())
/// ```
#[must_use]
pub fn classify(origin: &str, options: &Options) -> OriginClass {
    if origin == "null" {
        return OriginClass::Null;
    }
    let Ok(o) = Origin::parse(origin) else {
        return OriginClass::Arbitrary;
    };
    if options.target.as_ref() == Some(&o) {
        return OriginClass::SameOrigin;
    }
    if options.trusted.contains(&o) {
        return OriginClass::Trusted;
    }
    let mut best = OriginClass::Arbitrary;
    for anchor in options.target.iter().chain(&options.trusted) {
        let class = match relate(&o, anchor) {
            OriginClass::Subdomain if options.trust_subdomains => OriginClass::Trusted,
            class => class,
        };
        best = best.min(class);
    }
    best
}

/// Relates `o` to one trusted `anchor`.
fn relate(o: &Origin, anchor: &Origin) -> OriginClass {
    let host = o.host();
    let a = anchor.host();
    let related = host == a || o.is_subdomain_of(anchor);
    if related {
        if anchor.is_secure() && !o.is_secure() {
            OriginClass::InsecureScheme
        } else {
            OriginClass::Subdomain
        }
    } else if !a.contains('.') || a.starts_with('[') {
        // Single-label hosts and IP literals are too short to be mimicked
        // meaningfully.
        OriginClass::Arbitrary
    } else if host.ends_with(a) {
        OriginClass::UnanchoredSuffix
    } else if host.starts_with(a) {
        OriginClass::UnanchoredPrefix
    } else {
        OriginClass::Arbitrary
    }
}

/// A request origin to send when testing a site, with the class it has
/// relative to that site.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct Probe {
    /// The `Origin` header value to send.
    pub origin: String,
    /// Its class relative to the target.
    pub class: OriginClass,
}

/// The standard probe origins for a site, one per [`OriginClass`].
///
/// They are the target itself, an unrelated origin, `null`, a subdomain,
/// the plain-`http` variant (for a secure target), and the
/// unanchored-suffix and unanchored-prefix lookalikes.
///
/// Send each as the `Origin` request header, collect the responses into
/// [`Exchange`]s and pass them to [`run`] with [`Options::for_target`].
///
/// ```
/// use rune_cors::{Options, classify, probes};
///
/// let target = "https://example.com".parse()?;
/// let opts = Options::for_target(target);
/// for p in probes(opts.target.as_ref().unwrap()) {
///     assert_eq!(classify(&p.origin, &opts), p.class);
/// }
/// # Ok::<(), rune_cors::Error>(())
/// ```
#[must_use]
pub fn probes(target: &Origin) -> Vec<Probe> {
    let scheme = target.scheme();
    let host = target.host();
    let port = target.port().map(|p| format!(":{p}")).unwrap_or_default();
    let mut out = vec![
        Probe {
            origin: target.to_string(),
            class: OriginClass::SameOrigin,
        },
        Probe {
            origin: ["example", "test", "invalid"]
                .iter()
                .map(|tld| format!("https://{PROBE_LABEL}.{tld}"))
                .find(|o| {
                    Origin::parse(o).is_ok_and(|o| relate(&o, target) == OriginClass::Arbitrary)
                })
                .unwrap_or_else(|| format!("https://{PROBE_LABEL}.invalid")),
            class: OriginClass::Arbitrary,
        },
        Probe {
            origin: "null".to_owned(),
            class: OriginClass::Null,
        },
    ];
    // Hostname-based probes do not apply to IP literals, and lookalikes
    // need a dotted name.
    let is_ip = host.starts_with('[') || host.bytes().all(|b| b.is_ascii_digit() || b == b'.');
    if !is_ip {
        out.push(Probe {
            origin: format!("{scheme}://{PROBE_LABEL}.{host}{port}"),
            class: OriginClass::Subdomain,
        });
    }
    if target.is_secure() {
        let insecure = if scheme == "wss" { "ws" } else { "http" };
        out.push(Probe {
            origin: format!("{insecure}://{host}{port}"),
            class: OriginClass::InsecureScheme,
        });
    }
    if !is_ip && host.contains('.') {
        out.push(Probe {
            origin: format!("{scheme}://{PROBE_LABEL}{host}{port}"),
            class: OriginClass::UnanchoredSuffix,
        });
        out.push(Probe {
            origin: format!("{scheme}://{host}.{PROBE_LABEL}.example{port}"),
            class: OriginClass::UnanchoredPrefix,
        });
    }
    out
}

/// One request/response pair: the `Origin` the request carried and the
/// CORS headers of the response.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct Exchange {
    /// The request `Origin` header. `None` analyzes the response headers
    /// on their own: the origin named in `Access-Control-Allow-Origin` is
    /// taken as the requester.
    pub origin: Option<String>,
    /// The response's CORS headers.
    pub headers: CorsHeaders,
}

impl Exchange {
    /// An exchange with the given request origin and response headers.
    #[must_use]
    pub fn new(origin: Option<&str>, headers: CorsHeaders) -> Self {
        Self {
            origin: origin.map(str::to_owned),
            headers,
        }
    }
}

/// One line of the verdict table: what the request origin can read.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct Row {
    /// The request origin or, without one, the origin the response grants.
    /// `None` when neither is known (for `*`, any origin).
    pub origin: Option<String>,
    /// The class of [`Row::origin`].
    pub class: Option<OriginClass>,
    /// Whether `Access-Control-Allow-Origin` echoes the request origin.
    pub reflected: bool,
    /// What the origin can read.
    pub exposure: Exposure,
    /// The most severe weakness in this exchange.
    pub severity: Option<Severity>,
}

/// The result of [`run`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Report {
    /// One row per exchange, in input order.
    pub rows: Vec<Row>,
    /// Weaknesses across all exchanges, most severe first.
    pub weaknesses: Vec<Weakness>,
}

impl Report {
    /// The most severe weakness level, if any.
    #[must_use]
    pub fn max_severity(&self) -> Option<Severity> {
        self.weaknesses.iter().map(|w| w.severity).max()
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

/// Analyzes a set of exchanges with the same resource, typically one per
/// [`probes`] origin.
///
/// Besides the per-exchange checks of [`analyze`], an origin-dependent
/// `Access-Control-Allow-Origin` (two exchanges echoing different origins)
/// without `Vary: Origin` is reported even for trusted origins.
#[must_use]
pub fn run(exchanges: &[Exchange], options: &Options) -> Report {
    let echoed: BTreeSet<&str> = exchanges
        .iter()
        .filter(|e| is_reflected(e))
        .filter_map(|e| e.origin.as_deref())
        .collect();
    let dynamic = echoed.len() > 1;
    let mut rows = Vec::with_capacity(exchanges.len());
    let mut weaknesses = Vec::new();
    for (index, exchange) in exchanges.iter().enumerate() {
        let found = analyze_at(exchange, index, options, dynamic);
        let requester = requester(exchange);
        let exposure = match requester.as_deref() {
            Some(o) => cors_check(o, &exchange.headers),
            None if exchange.headers.allow_origin() == AllowOrigin::Any => Exposure::Anonymous,
            None => Exposure::None,
        };
        rows.push(Row {
            class: requester.as_deref().map(|o| classify(o, options)),
            reflected: is_reflected(exchange),
            exposure,
            severity: found.iter().map(|w| w.severity).max(),
            origin: requester,
        });
        weaknesses.extend(found);
    }
    sort(&mut weaknesses);
    Report { rows, weaknesses }
}

/// Analyzes one exchange; weaknesses carry exchange index 0, most severe
/// first.
#[must_use]
pub fn analyze(exchange: &Exchange, options: &Options) -> Vec<Weakness> {
    let mut weaknesses = analyze_at(exchange, 0, options, false);
    sort(&mut weaknesses);
    weaknesses
}

fn sort(weaknesses: &mut [Weakness]) {
    weaknesses.sort_by_key(|w| std::cmp::Reverse(w.severity));
}

/// The request origin, or the origin the response grants when there is
/// none.
fn requester(exchange: &Exchange) -> Option<String> {
    exchange
        .origin
        .clone()
        .or_else(|| exchange.headers.allow_origin().granted())
}

fn is_reflected(exchange: &Exchange) -> bool {
    exchange.origin.is_some() && exchange.origin == exchange.headers.allow_origin
}

/// Picks one of two severities depending on credentials.
const fn by_credentials(credentials: bool, with: Severity, without: Severity) -> Severity {
    if credentials { with } else { without }
}

fn analyze_at(
    exchange: &Exchange,
    index: usize,
    options: &Options,
    dynamic: bool,
) -> Vec<Weakness> {
    let h = &exchange.headers;
    let credentials = h.allows_credentials();
    let reflected = is_reflected(exchange);
    let acao = h.allow_origin();
    let mut out = Vec::new();
    let mut push = |kind: WeaknessKind, severity: Severity, message: String| {
        out.push(Weakness {
            kind,
            severity,
            exchange: index,
            origin: exchange.origin.clone(),
            allow_origin: h.allow_origin.clone(),
            message,
        });
    };
    let creds_note = if credentials {
        "with credentials: authenticated responses can be read"
    } else {
        "without credentials"
    };

    let mut attacker_granted = false;
    match &acao {
        AllowOrigin::Missing => {}
        AllowOrigin::Invalid(v) => push(
            WeaknessKind::InvalidAllowOrigin,
            Severity::Informational,
            format!("Access-Control-Allow-Origin {v:?} can never match a request origin"),
        ),
        AllowOrigin::Any => {
            attacker_granted = true;
            if credentials {
                push(
                    WeaknessKind::WildcardWithCredentials,
                    Severity::Low,
                    "Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true; \
                     browsers refuse credentialed reads, but credentials were meant to be shared"
                        .to_owned(),
                );
            } else {
                push(
                    WeaknessKind::WildcardOrigin,
                    Severity::Informational,
                    "Access-Control-Allow-Origin: * lets any site read anonymous responses"
                        .to_owned(),
                );
            }
        }
        AllowOrigin::Null | AllowOrigin::Origin(_) => {
            let granted = acao.granted().unwrap_or_default();
            let class = classify(&granted, options);
            // A fixed grant of an unrelated origin or a specific subdomain is
            // a deliberate choice; it is only suspicious when echoed.
            attacker_granted =
                class.is_attacker_controlled() && (reflected || class != OriginClass::Arbitrary);
            match class {
                OriginClass::Null => push(
                    WeaknessKind::NullOrigin,
                    by_credentials(credentials, Severity::High, Severity::Low),
                    format!(
                        "The null origin is allowed {creds_note}; any page can obtain it \
                         from a sandboxed iframe"
                    ),
                ),
                OriginClass::Arbitrary if reflected => push(
                    WeaknessKind::OriginReflection,
                    by_credentials(credentials, Severity::Critical, Severity::Low),
                    format!("Arbitrary origin {granted} is reflected {creds_note}"),
                ),
                OriginClass::UnanchoredSuffix | OriginClass::UnanchoredPrefix => push(
                    WeaknessKind::UnanchoredAllowlist,
                    by_credentials(credentials, Severity::High, Severity::Low),
                    format!(
                        "Lookalike origin {granted} passes an unanchored allowlist match \
                         ({class}) {creds_note}"
                    ),
                ),
                OriginClass::InsecureScheme => push(
                    WeaknessKind::InsecureOrigin,
                    by_credentials(credentials, Severity::Medium, Severity::Informational),
                    format!(
                        "Plain-text origin {granted} is allowed {creds_note}; a network \
                         attacker can forge it"
                    ),
                ),
                OriginClass::Subdomain if reflected => push(
                    WeaknessKind::SubdomainOrigin,
                    by_credentials(credentials, Severity::Low, Severity::Informational),
                    format!(
                        "Arbitrary subdomain {granted} is allowed {creds_note}; a subdomain \
                         takeover or XSS exposes this resource"
                    ),
                ),
                _ => {}
            }
            let trusted = matches!(class, OriginClass::SameOrigin | OriginClass::Trusted);
            if reflected && !h.varies_on_origin() && (dynamic || !trusted) {
                push(
                    WeaknessKind::MissingVaryOrigin,
                    Severity::Low,
                    "Access-Control-Allow-Origin echoes the request origin without \
                     Vary: Origin; shared caches can serve it to other origins"
                        .to_owned(),
                );
            }
        }
    }

    if h.allow_credentials.is_some() && !credentials {
        push(
            WeaknessKind::InvalidAllowCredentials,
            Severity::Informational,
            format!(
                "Access-Control-Allow-Credentials {:?} is ignored; only \"true\" is accepted",
                h.allow_credentials.as_deref().unwrap_or_default()
            ),
        );
    }
    let star = |list: &[String]| list.iter().any(|v| v == "*");
    if credentials
        && !matches!(acao, AllowOrigin::Any)
        && (star(&h.allow_methods) || star(&h.allow_headers) || star(&h.expose_headers))
    {
        push(
            WeaknessKind::WildcardListWithCredentials,
            Severity::Informational,
            "* in an Access-Control-Allow-Methods/-Headers or -Expose-Headers list is a literal \
             name on credentialed responses, not a wildcard"
                .to_owned(),
        );
    }
    if h.allows_private_network() && attacker_granted {
        push(
            WeaknessKind::PrivateNetworkAccess,
            Severity::Medium,
            "Private network access is granted to an attacker-controllable origin".to_owned(),
        );
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target() -> Options {
        Options::for_target(Origin::parse("https://example.com").unwrap())
    }

    fn exchange(origin: Option<&str>, headers: &[(&str, &str)]) -> Exchange {
        Exchange::new(origin, CorsHeaders::from_pairs(headers.iter().copied()))
    }

    fn kinds(w: &[Weakness]) -> Vec<WeaknessKind> {
        w.iter().map(|w| w.kind).collect()
    }

    #[test]
    fn check_ids_are_unique() {
        let all = [
            WeaknessKind::OriginReflection,
            WeaknessKind::NullOrigin,
            WeaknessKind::UnanchoredAllowlist,
            WeaknessKind::InsecureOrigin,
            WeaknessKind::SubdomainOrigin,
            WeaknessKind::WildcardWithCredentials,
            WeaknessKind::WildcardOrigin,
            WeaknessKind::MissingVaryOrigin,
            WeaknessKind::PrivateNetworkAccess,
            WeaknessKind::InvalidAllowOrigin,
            WeaknessKind::InvalidAllowCredentials,
            WeaknessKind::WildcardListWithCredentials,
        ];
        let ids: BTreeSet<String> = all.iter().map(|k| k.check_id()).collect();
        assert_eq!(ids.len(), all.len());
        assert!(ids.iter().all(|id| id.starts_with("cors.")));
        assert!(all.iter().all(|k| !k.remediation().is_empty()));
    }

    #[test]
    fn cors_check_follows_fetch() {
        let h = CorsHeaders::from_pairs([
            ("access-control-allow-origin", "https://a.example"),
            ("access-control-allow-credentials", "true"),
        ]);
        assert_eq!(cors_check("https://a.example", &h), Exposure::Credentialed);
        assert_eq!(cors_check("https://b.example", &h), Exposure::None);
        assert_eq!(
            cors_check("https://a.example", &CorsHeaders::default()),
            Exposure::None
        );
        let null = CorsHeaders::from_pairs([("access-control-allow-origin", "null")]);
        assert_eq!(cors_check("null", &null), Exposure::Anonymous);
    }

    #[test]
    fn trusted_origins_and_subdomains() {
        let opts = target().with_trusted(Origin::parse("https://partner.example").unwrap());
        assert_eq!(
            classify("https://partner.example", &opts),
            OriginClass::Trusted
        );
        assert_eq!(
            classify("https://x.partner.example", &opts),
            OriginClass::Subdomain
        );
        assert_eq!(
            classify("http://partner.example", &opts),
            OriginClass::InsecureScheme
        );
        assert_eq!(
            classify("https://example.com:8443", &opts),
            OriginClass::Subdomain
        );
        assert_eq!(classify("not an origin", &opts), OriginClass::Arbitrary);
        let opts = opts.with_trust_subdomains(true);
        assert_eq!(
            classify("https://x.partner.example", &opts),
            OriginClass::Trusted
        );
        assert_eq!(
            classify("http://x.example.com", &opts),
            OriginClass::InsecureScheme
        );
        // No anchors: everything but null is arbitrary.
        assert_eq!(
            classify("https://example.com", &Options::default()),
            OriginClass::Arbitrary
        );
    }

    #[test]
    fn probes_cover_classes() {
        let t = Origin::parse("https://example.com:8443").unwrap();
        let opts = Options::for_target(t.clone());
        let p = probes(&t);
        assert_eq!(p.len(), 7);
        for probe in &p {
            assert_eq!(
                classify(&probe.origin, &opts),
                probe.class,
                "{}",
                probe.origin
            );
            assert!(probe.origin == "null" || Origin::parse(&probe.origin).is_ok());
        }
        let ip = Origin::parse("http://127.0.0.1:8080").unwrap();
        assert_eq!(probes(&ip).len(), 3);
    }

    #[test]
    fn reflection_with_credentials_is_critical() {
        let o = "https://evil.net";
        let w = analyze(
            &exchange(
                Some(o),
                &[
                    ("access-control-allow-origin", o),
                    ("access-control-allow-credentials", "true"),
                    ("vary", "Origin"),
                ],
            ),
            &target(),
        );
        assert_eq!(kinds(&w), [WeaknessKind::OriginReflection]);
        assert_eq!(w[0].severity, Severity::Critical);
    }

    #[test]
    fn static_grants_are_not_reflection() {
        let w = analyze(
            &exchange(
                None,
                &[
                    ("access-control-allow-origin", "https://partner.example"),
                    ("access-control-allow-credentials", "true"),
                ],
            ),
            &target(),
        );
        assert!(w.is_empty(), "{w:?}");
    }

    #[test]
    fn dynamic_trusted_echo_needs_vary() {
        let opts = target().with_trusted(Origin::parse("https://partner.example").unwrap());
        let ex = [
            exchange(
                Some("https://example.com"),
                &[("access-control-allow-origin", "https://example.com")],
            ),
            exchange(
                Some("https://partner.example"),
                &[("access-control-allow-origin", "https://partner.example")],
            ),
        ];
        let r = run(&ex, &opts);
        assert_eq!(
            kinds(&r.weaknesses),
            [
                WeaknessKind::MissingVaryOrigin,
                WeaknessKind::MissingVaryOrigin
            ]
        );
        assert_eq!(analyze(&ex[0], &opts), []);
    }

    #[test]
    fn private_network_to_attacker() {
        let w = analyze(
            &exchange(
                Some("null"),
                &[
                    ("access-control-allow-origin", "null"),
                    ("access-control-allow-private-network", "true"),
                    ("vary", "origin"),
                ],
            ),
            &target(),
        );
        assert_eq!(
            kinds(&w),
            [WeaknessKind::PrivateNetworkAccess, WeaknessKind::NullOrigin]
        );
    }

    #[test]
    fn findings_carry_evidence() {
        let o = "https://evil.net";
        let w = analyze(
            &exchange(Some(o), &[("access-control-allow-origin", o)]),
            &target(),
        );
        let f: Finding = w[0].to_finding(&Location::url("https://example.com/api"));
        assert_eq!(f.check_id, "cors.origin_reflection");
        assert_eq!(f.evidence.len(), 2);
    }
}
