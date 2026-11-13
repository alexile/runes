//! The CORS policy: the builder, the sans-I/O decisions the service makes,
//! and the audit through `rune-cors`.

use std::collections::BTreeSet;
use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use http::{HeaderName, HeaderValue, Method, StatusCode, header};
use rune_cors::{CorsHeaders, Exchange, Options, Origin, Report, Weakness, WeaknessKind};
use rune_finding::Severity;

use crate::Error;

/// Header/value pairs the middleware adds to a response.
pub type HeaderList = Vec<(HeaderName, HeaderValue)>;

/// A caller-supplied origin predicate.
type Predicate = Arc<dyn Fn(&str) -> bool + Send + Sync>;

/// Request header carrying the Private Network Access opt-in.
pub const REQUEST_PRIVATE_NETWORK: HeaderName =
    HeaderName::from_static("access-control-request-private-network");
/// Response header granting Private Network Access.
const ALLOW_PRIVATE_NETWORK: HeaderName =
    HeaderName::from_static("access-control-allow-private-network");

/// Host used for the generic attacker-origin probes of the audit.
const PROBE_HOST: &str = "rune-axum-cors-probe.example";

/// The severity at or above which a weakness is always fatal, whatever
/// [`Cors::reject_at`] says.
const HARD_FLOOR: Severity = Severity::High;

/// The largest `Access-Control-Max-Age` the middleware sends: two hours,
/// the limit Chromium applies. Longer values given to [`Cors::max_age`]
/// are clamped, so a policy change reaches browsers within that time.
pub const MAX_AGE_CAP: Duration = Duration::from_secs(7200);

/// How deep a subdomain wildcard reaches.
///
/// Written in an origin pattern as `*.` (one label) or `**.` (any depth);
/// see [`Cors::allow_origin`]. Neither form matches the apex domain itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SubdomainDepth {
    /// Exactly one label: `https://*.example.com` matches
    /// `https://a.example.com` but not `https://a.b.example.com`.
    One,
    /// One or more labels: `https://**.example.com` matches both
    /// `https://a.example.com` and `https://a.b.example.com`.
    Any,
}

/// What a preflight from a disallowed origin (or asking for a method,
/// header or Private Network Access the policy does not grant) gets back.
///
/// Either way the response carries no `Access-Control-*` headers, so the
/// browser fails the preflight and never sends the actual request. Actual
/// (non-preflight) requests from disallowed origins are always passed on
/// unchanged, minus CORS headers: CORS decides what a browser may read, it
/// is not access control.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Rejection {
    /// Answer with this status (default `403 Forbidden`), which shows up
    /// clearly in browser devtools and server logs.
    Status(StatusCode),
    /// Answer `204 No Content`, like an allowed preflight, only without the
    /// CORS headers. A prober cannot tell a refusal from the status alone.
    OmitHeaders,
}

impl Default for Rejection {
    fn default() -> Self {
        Self::Status(StatusCode::FORBIDDEN)
    }
}

impl Rejection {
    /// The status code of a refused preflight.
    #[must_use]
    pub const fn status(self) -> StatusCode {
        match self {
            Self::Status(status) => status,
            Self::OmitHeaders => StatusCode::NO_CONTENT,
        }
    }
}

/// A subdomain wildcard such as `https://*.example.com`.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Pattern {
    base: Origin,
    depth: SubdomainDepth,
}

impl Pattern {
    /// Whether canonical origin `o` is a subdomain of the base at the
    /// allowed depth, with the base's scheme and port.
    fn matches(&self, o: &Origin) -> bool {
        o.scheme() == self.base.scheme()
            && o.port() == self.base.port()
            && subdomain_labels(o.host(), self.base.host())
                .is_some_and(|n| self.depth == SubdomainDepth::Any || n == 1)
    }
}

impl fmt::Display for Pattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let stars = match self.depth {
            SubdomainDepth::One => "*",
            SubdomainDepth::Any => "**",
        };
        write!(f, "{}://{stars}.{}", self.base.scheme(), self.base.host())?;
        if let Some(p) = self.base.port() {
            write!(f, ":{p}")?;
        }
        Ok(())
    }
}

/// The number of labels `host` has in front of `base`, when `host` is a
/// strict subdomain of `base` made of well-formed labels.
fn subdomain_labels(host: &str, base: &str) -> Option<usize> {
    let prefix = host.strip_suffix(base)?.strip_suffix('.')?;
    let mut count = 0;
    for label in prefix.split('.') {
        if !valid_label(label) {
            return None;
        }
        count += 1;
    }
    Some(count)
}

/// A non-empty DNS label of letters, digits, `-` and `_`.
fn valid_label(label: &str) -> bool {
    !label.is_empty()
        && label.len() <= 63
        && label
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
}

/// Whether `host` is an IP literal rather than a domain name.
fn is_ip(host: &str) -> bool {
    host.starts_with('[') || host.bytes().all(|b| b.is_ascii_digit() || b == b'.')
}

/// A CORS policy.
///
/// Build with [`Cors::new()`], which allows no cross-origin access at all,
/// and chain methods to open it up. Then pass it to
/// [`CorsLayer::new()`](crate::CorsLayer::new), which audits it with
/// [`rune_cors`] and refuses it if it is insecure.
///
/// # Examples
///
/// ```rust
/// use http::{HeaderName, Method};
/// use rune_axum_cors::Cors;
///
/// let cors = Cors::new()
///     .allow_origin("https://app.example.com")
///     .allow_origin("https://*.tenants.example.com")
///     .allow_credentials(true)
///     .allow_methods([Method::GET, Method::POST, Method::DELETE])
///     .allow_headers([HeaderName::from_static("content-type")]);
///
/// assert!(cors.is_allowed("https://app.example.com"));
/// assert!(cors.is_allowed("https://acme.tenants.example.com"));
/// assert!(!cors.is_allowed("https://tenants.example.com"));
/// assert!(!cors.is_allowed("https://evil.example"));
/// assert!(cors.audit().weaknesses.is_empty());
/// ```
#[derive(Clone)]
#[non_exhaustive]
#[allow(
    clippy::struct_excessive_bools,
    reason = "independent CORS switches, each set by its own builder method"
)]
pub struct Cors {
    site: Option<Origin>,
    any_origin: bool,
    origins: Vec<Origin>,
    patterns: Vec<Pattern>,
    allow_null: bool,
    allow_subdomains: bool,
    predicate: Option<Predicate>,
    credentials: bool,
    methods: Vec<Method>,
    allow_headers: Vec<HeaderName>,
    expose_headers: Vec<HeaderName>,
    max_age: Option<Duration>,
    private_network: bool,
    reject_at: Severity,
    rejection: Rejection,
    /// The first invalid builder input, reported by `CorsLayer::new`.
    error: Option<Error>,
}

impl Default for Cors {
    fn default() -> Self {
        Self {
            site: None,
            any_origin: false,
            origins: Vec::new(),
            patterns: Vec::new(),
            allow_null: false,
            allow_subdomains: false,
            predicate: None,
            credentials: false,
            methods: vec![Method::GET, Method::HEAD, Method::POST],
            allow_headers: Vec::new(),
            expose_headers: Vec::new(),
            max_age: None,
            private_network: false,
            reject_at: Severity::Low,
            rejection: Rejection::default(),
            error: None,
        }
    }
}

impl fmt::Debug for Cors {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Cors")
            .field("site", &self.site)
            .field("any_origin", &self.any_origin)
            .field("origins", &self.origins)
            .field(
                "patterns",
                &self
                    .patterns
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>(),
            )
            .field("allow_null", &self.allow_null)
            .field("allow_subdomains", &self.allow_subdomains)
            .field(
                "predicate",
                &self.predicate.as_ref().map(|_| "Fn(&str) -> bool"),
            )
            .field("credentials", &self.credentials)
            .field("methods", &self.methods)
            .field("allow_headers", &self.allow_headers)
            .field("expose_headers", &self.expose_headers)
            .field("max_age", &self.max_age)
            .field("private_network", &self.private_network)
            .field("reject_at", &self.reject_at)
            .field("rejection", &self.rejection)
            .field("error", &self.error)
            .finish()
    }
}

impl Cors {
    /// Creates a policy that grants no cross-origin access: no origins,
    /// no credentials, methods `GET`, `HEAD` and `POST`, no extra request
    /// or exposed headers, no `Access-Control-Max-Age`, refused preflights
    /// answered with `403 Forbidden`, and weaknesses of severity `Low` or
    /// above rejected.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the origin of the site this policy protects.
    ///
    /// It is only used by the audit: allowed origins are judged relative to
    /// it, so a plain-`http` variant of an `https` site, or a lookalike such
    /// as `https://evilexample.com` for `https://example.com`, is caught.
    #[must_use]
    pub fn site(mut self, origin: impl AsRef<str>) -> Self {
        match parse_origin(origin.as_ref()) {
            Ok(o) => self.site = Some(o),
            Err(e) => self.record(e),
        }
        self
    }

    /// Allows one origin, written as `scheme://host[:port]`, or a family of
    /// subdomains written as `scheme://*.host[:port]` (exactly one extra
    /// label) or `scheme://**.host[:port]` (any number of labels).
    ///
    /// Exact origins are normalised the way browsers serialise them
    /// (lowercase, no default port) and requests must match byte for byte:
    /// `https://App.example.com`, `https://app.example.com:443` or
    /// `https://app.example.com.` sent by a non-browser client match
    /// nothing.
    ///
    /// Wildcards keep the scheme and port, never match the apex (list
    /// `https://example.com` separately if it should be allowed), and need
    /// a domain with at least two labels: `https://*.com` and IP addresses
    /// are refused. Remember that every host under a wildcard, including a
    /// forgotten one taken over by someone else, can then read responses.
    ///
    /// `"null"` allows the opaque origin and `"*"` is the same as
    /// [`allow_any_origin`](Self::allow_any_origin); the audit rejects both
    /// in most configurations.
    ///
    /// Internationalised domains must be written in punycode
    /// (`https://xn--bcher-kva.example`), which is what browsers send.
    /// Invalid input (a path, a trailing dot, an empty label, a wildcard
    /// anywhere but the first label, non-ASCII text) makes
    /// [`CorsLayer::new()`](crate::CorsLayer::new) fail.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rune_axum_cors::Cors;
    ///
    /// let cors = Cors::new()
    ///     .allow_origin("https://example.com")
    ///     .allow_origin("https://*.example.com");
    /// assert!(cors.is_allowed("https://example.com"));
    /// assert!(cors.is_allowed("https://app.example.com"));
    /// assert!(!cors.is_allowed("https://a.b.example.com"));
    /// assert!(!cors.is_allowed("http://app.example.com"));
    /// assert!(!cors.is_allowed("https://app.example.com.evil.net"));
    /// ```
    #[must_use]
    pub fn allow_origin(mut self, origin: impl AsRef<str>) -> Self {
        match origin.as_ref() {
            "*" => self.any_origin = true,
            "null" => self.allow_null = true,
            raw if raw.contains('*') => match parse_pattern(raw) {
                Ok(p) => {
                    if !self.patterns.contains(&p) {
                        self.patterns.push(p);
                    }
                }
                Err(e) => self.record(e),
            },
            raw => match parse_origin(raw) {
                Ok(o) => {
                    if !self.origins.contains(&o) {
                        self.origins.push(o);
                    }
                }
                Err(e) => self.record(e),
            },
        }
        self
    }

    /// Allows each origin in `origins`; see
    /// [`allow_origin`](Self::allow_origin).
    #[must_use]
    pub fn allow_origins<I>(self, origins: I) -> Self
    where
        I: IntoIterator,
        I::Item: AsRef<str>,
    {
        origins.into_iter().fold(self, Self::allow_origin)
    }

    /// Answers every origin with `Access-Control-Allow-Origin: *`.
    ///
    /// Only suitable for public, unauthenticated resources. Combined with
    /// [`allow_credentials`](Self::allow_credentials) or
    /// [`allow_private_network`](Self::allow_private_network) the policy is
    /// rejected.
    #[must_use]
    pub const fn allow_any_origin(mut self) -> Self {
        self.any_origin = true;
        self
    }

    /// Also allows subdomains, at any depth, of every exact
    /// [`allow_origin`](Self::allow_origin) origin, with the same scheme
    /// and port: `https://a.example.com` for `https://example.com`, but not
    /// `http://a.example.com` nor `https://evilexample.com`. Off by
    /// default.
    ///
    /// The same as adding `**.` patterns for each origin; prefer explicit
    /// `*.` / `**.` patterns, which say which origins they widen.
    #[must_use]
    pub const fn allow_subdomains(mut self, allow: bool) -> Self {
        self.allow_subdomains = allow;
        self
    }

    /// Also allows every origin for which `predicate` returns `true`, for
    /// origins that are only known at run time (tenants in a database, a
    /// reloadable list).
    ///
    /// # Security
    ///
    /// A predicate is the classic way CORS goes wrong. Whatever it accepts
    /// is echoed back in `Access-Control-Allow-Origin`, so a predicate that
    /// accepts too much turns into origin reflection: any site can read the
    /// responses, with the user's cookies when credentials are on.
    ///
    /// - Compare whole origins (`set.contains(origin)`), never substrings,
    ///   prefixes, suffixes or unanchored regexes: `ends_with("example.com")`
    ///   lets `https://evilexample.com` in and `starts_with("https://example.com")`
    ///   lets `https://example.com.evil.net` in.
    /// - Check the scheme: `http://` origins can be forged by anyone on the
    ///   network path.
    /// - Never return `true` for input you have not checked against
    ///   something you control.
    ///
    /// The predicate sees the request `Origin` exactly as browsers send it
    /// (lowercase, no default port, punycode); it is never called for `null`
    /// or non-canonical values. Because it is opaque, the audit probes it
    /// with attacker-style origins derived from the [`site`](Self::site) and
    /// the allowed origins (an unrelated site, `null`, subdomains,
    /// plain-`http` variants and unanchored lookalikes) and rejects the
    /// policy if it grants any of them. Probing cannot prove a predicate
    /// safe, so prefer exact origins and wildcards where you can. Origins
    /// granted only by the predicate never get Private Network Access.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use std::collections::HashSet;
    /// use std::sync::{Arc, RwLock};
    /// use rune_axum_cors::{Cors, CorsLayer};
    ///
    /// let tenants = Arc::new(RwLock::new(HashSet::from([
    ///     "https://acme.example".to_owned(),
    /// ])));
    /// let lookup = Arc::clone(&tenants);
    /// let cors = Cors::new()
    ///     .site("https://example.com")
    ///     .allow_origin_fn(move |origin| {
    ///         lookup.read().is_ok_and(|set| set.contains(origin))
    ///     })
    ///     .allow_credentials(true);
    /// assert!(cors.is_allowed("https://acme.example"));
    /// assert!(CorsLayer::new(cors).is_ok());
    ///
    /// tenants.write().unwrap().insert("https://globex.example".to_owned());
    /// ```
    #[must_use]
    pub fn allow_origin_fn<F>(mut self, predicate: F) -> Self
    where
        F: Fn(&str) -> bool + Send + Sync + 'static,
    {
        self.predicate = Some(Arc::new(predicate));
        self
    }

    /// Sends `Access-Control-Allow-Credentials: true`, so browsers share
    /// responses to requests that carry cookies or HTTP authentication.
    /// Off by default.
    #[must_use]
    pub const fn allow_credentials(mut self, allow: bool) -> Self {
        self.credentials = allow;
        self
    }

    /// Replaces the methods allowed in preflights. Defaults to `GET`,
    /// `HEAD` and `POST`. The CORS-safelisted `GET`, `HEAD` and `POST` are
    /// always accepted, as browsers do not restrict them.
    ///
    /// `*` allows any method, but only without credentials: on a
    /// credentialed response browsers read it as a literal method name.
    #[must_use]
    pub fn allow_methods(mut self, methods: impl IntoIterator<Item = Method>) -> Self {
        self.methods = dedup(methods);
        self
    }

    /// Replaces the request headers allowed in preflights. Empty by
    /// default; CORS-safelisted headers need no listing. Requested headers
    /// are never mirrored back: the response lists exactly these names.
    ///
    /// `*` allows any header, but only without credentials: on a
    /// credentialed response it is a literal header name, so a
    /// credentialed policy has to list its headers.
    #[must_use]
    pub fn allow_headers(mut self, headers: impl IntoIterator<Item = HeaderName>) -> Self {
        self.allow_headers = dedup(headers);
        self
    }

    /// Replaces the response headers exposed to scripts through
    /// `Access-Control-Expose-Headers`. Empty by default, so scripts only
    /// see the CORS-safelisted response headers (`Content-Type`,
    /// `Cache-Control`, ...).
    ///
    /// `*` exposes every header, but only without credentials; browsers
    /// never expose `Set-Cookie`.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use http::HeaderName;
    /// use rune_axum_cors::Cors;
    ///
    /// let cors = Cors::new()
    ///     .allow_origin("https://app.example.com")
    ///     .expose_headers([
    ///         HeaderName::from_static("x-request-id"),
    ///         HeaderName::from_static("x-total-count"),
    ///     ]);
    /// # let _ = cors;
    /// ```
    #[must_use]
    pub fn expose_headers(mut self, headers: impl IntoIterator<Item = HeaderName>) -> Self {
        self.expose_headers = dedup(headers);
        self
    }

    /// Sets `Access-Control-Max-Age` on successful preflights, in whole
    /// seconds, clamped to [`MAX_AGE_CAP`] (two hours). Not sent by default
    /// (browsers then cache preflights for 5 seconds).
    ///
    /// A long cache keeps browsers using a granted preflight after the
    /// policy has been tightened, which is why it is capped.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use std::time::Duration;
    /// use rune_axum_cors::{Cors, MAX_AGE_CAP};
    ///
    /// let cors = Cors::new().max_age(Duration::from_secs(86_400));
    /// assert_eq!(cors.max_age_value(), Some(MAX_AGE_CAP));
    /// ```
    #[must_use]
    pub fn max_age(mut self, max_age: Duration) -> Self {
        self.max_age = Some(max_age.min(MAX_AGE_CAP));
        self
    }

    /// The `Access-Control-Max-Age` this policy sends, after clamping.
    #[must_use]
    pub const fn max_age_value(&self) -> Option<Duration> {
        self.max_age
    }

    /// Answers preflights that carry
    /// `Access-Control-Request-Private-Network: true` with
    /// `Access-Control-Allow-Private-Network: true`. Off by default.
    ///
    /// Private Network Access lets a public site talk to a server on the
    /// visitor's local network, so it is only granted to origins listed
    /// exactly with [`allow_origin`](Self::allow_origin): never to `*`,
    /// wildcards, [`allow_subdomains`](Self::allow_subdomains) or the
    /// predicate. Such preflights from any other origin, or any such
    /// preflight while this is off, are refused.
    #[must_use]
    pub const fn allow_private_network(mut self, allow: bool) -> Self {
        self.private_network = allow;
        self
    }

    /// Sets the severity at which an audit weakness rejects the policy.
    /// Defaults to `Low`.
    ///
    /// Raising it accepts more weaknesses, but never past `High`:
    /// high and critical weaknesses, and `*` with credentials, are always
    /// rejected.
    #[must_use]
    pub const fn reject_at(mut self, severity: Severity) -> Self {
        self.reject_at = severity;
        self
    }

    /// Sets how refused preflights are answered; see [`Rejection`].
    /// Defaults to `403 Forbidden`.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rune_axum_cors::{Cors, Rejection};
    ///
    /// let cors = Cors::new()
    ///     .allow_origin("https://app.example.com")
    ///     .rejection(Rejection::OmitHeaders);
    /// # let _ = cors;
    /// ```
    #[must_use]
    pub const fn rejection(mut self, rejection: Rejection) -> Self {
        self.rejection = rejection;
        self
    }

    /// Shorthand for [`rejection`](Self::rejection) with
    /// `Rejection::Status(status)`.
    #[must_use]
    pub const fn deny_status(self, status: StatusCode) -> Self {
        self.rejection(Rejection::Status(status))
    }

    /// Whether a request from `origin` (the `Origin` header value) is
    /// granted access.
    #[must_use]
    pub fn is_allowed(&self, origin: &str) -> bool {
        if self.any_origin {
            return true;
        }
        if origin == "null" {
            return self.allow_null;
        }
        let Some(parsed) = canonical(origin) else {
            return false;
        };
        self.structural(&parsed) || self.predicate.as_ref().is_some_and(|p| p(origin))
    }

    /// Whether a canonical origin is granted by the exact list, the
    /// wildcards or [`Cors::allow_subdomains`], i.e. without the predicate.
    fn structural(&self, o: &Origin) -> bool {
        self.origins.contains(o)
            || self.patterns.iter().any(|p| p.matches(o))
            || (self.allow_subdomains
                && self.origins.iter().any(|anchor| {
                    Pattern {
                        base: anchor.clone(),
                        depth: SubdomainDepth::Any,
                    }
                    .matches(o)
                }))
    }

    /// Whether `origin` is listed exactly (the Private Network Access rule).
    fn is_exact(&self, origin: &str) -> bool {
        canonical(origin).is_some_and(|o| self.origins.contains(&o))
    }

    /// How refused preflights are answered.
    pub(crate) const fn rejection_mode(&self) -> Rejection {
        self.rejection
    }

    /// Whether `Access-Control-Allow-Origin` depends on the request origin,
    /// so responses need `Vary: Origin`.
    pub(crate) const fn varies(&self) -> bool {
        !self.any_origin
    }

    /// The `Access-Control-Allow-Origin` value for `origin`, if granted.
    /// Only an origin that passed [`Cors::is_allowed`] is ever echoed.
    fn grant(&self, origin: Option<&str>) -> Option<HeaderValue> {
        if self.any_origin {
            return Some(HeaderValue::from_static("*"));
        }
        let origin = origin?;
        if self.is_allowed(origin) {
            HeaderValue::from_str(origin).ok()
        } else {
            None
        }
    }

    /// Headers for an actual (non-preflight) response to a request from
    /// `origin`. Empty when the origin is not allowed. `Vary` is not
    /// included; see [`Cors::varies`].
    pub(crate) fn actual_headers(&self, origin: Option<&str>) -> HeaderList {
        let Some(acao) = self.grant(origin) else {
            return Vec::new();
        };
        let mut out = vec![(header::ACCESS_CONTROL_ALLOW_ORIGIN, acao)];
        if self.credentials {
            out.push((
                header::ACCESS_CONTROL_ALLOW_CREDENTIALS,
                HeaderValue::from_static("true"),
            ));
        }
        if let Some(v) = join(&self.expose_headers) {
            out.push((header::ACCESS_CONTROL_EXPOSE_HEADERS, v));
        }
        out
    }

    /// Headers for a successful preflight, or `None` when the preflight is
    /// refused: origin not allowed, method not allowed, a requested header
    /// not allowed, or Private Network Access asked for and not granted.
    pub(crate) fn preflight_headers(
        &self,
        origin: &str,
        method: &str,
        request_headers: Option<&str>,
        private_network: bool,
    ) -> Option<HeaderList> {
        let acao = self.grant(Some(origin))?;
        if private_network && !(self.private_network && self.is_exact(origin)) {
            return None;
        }
        let safelisted = matches!(method, "GET" | "HEAD" | "POST");
        let any_method = !self.credentials && self.methods.iter().any(|m| m.as_str() == "*");
        if !safelisted && !any_method && !self.methods.iter().any(|m| m.as_str() == method) {
            return None;
        }
        let any_header = !self.credentials && self.allow_headers.iter().any(|h| h.as_str() == "*");
        let headers_ok = request_headers
            .into_iter()
            .flat_map(|list| list.split(','))
            .map(str::trim)
            .filter(|name| !name.is_empty())
            .all(|name| {
                any_header
                    || self
                        .allow_headers
                        .iter()
                        .any(|h| h.as_str().eq_ignore_ascii_case(name))
            });
        if !headers_ok {
            return None;
        }
        let mut out = vec![(header::ACCESS_CONTROL_ALLOW_ORIGIN, acao)];
        if self.credentials {
            out.push((
                header::ACCESS_CONTROL_ALLOW_CREDENTIALS,
                HeaderValue::from_static("true"),
            ));
        }
        if let Some(v) = join(&self.methods) {
            out.push((header::ACCESS_CONTROL_ALLOW_METHODS, v));
        }
        if let Some(v) = join(&self.allow_headers) {
            out.push((header::ACCESS_CONTROL_ALLOW_HEADERS, v));
        }
        if let Some(age) = self.max_age {
            out.push((
                header::ACCESS_CONTROL_MAX_AGE,
                HeaderValue::from(age.as_secs()),
            ));
        }
        if private_network {
            out.push((ALLOW_PRIVATE_NETWORK, HeaderValue::from_static("true")));
        }
        Some(out)
    }

    /// Audits the policy with [`rune_cors`].
    ///
    /// Every probe origin (the [`site`](Self::site), the allowed origins
    /// and wildcard bases, [`rune_cors::probes`] of each, `null`, and
    /// unrelated `https` and `http` sites) is run through the same code the
    /// middleware uses to answer actual requests and preflights. The
    /// resulting [`Exchange`]s are analysed with [`rune_cors::run`], with
    /// the allowed origins as trusted (except plain-`http` variants of a
    /// secure site or allowed origin). Subdomains are trusted only where a
    /// wildcard or [`allow_subdomains`](Self::allow_subdomains) grants them;
    /// a subdomain the predicate lets in is still reported.
    ///
    /// Private Network Access is audited as if it were granted to every
    /// allowed origin, which is broader than what the middleware does.
    ///
    /// The report lists every weakness, including the ones below the
    /// [`reject_at`](Self::reject_at) threshold.
    #[must_use]
    pub fn audit(&self) -> Report {
        let anchors: Vec<&Origin> = self
            .site
            .iter()
            .chain(&self.origins)
            .chain(self.patterns.iter().map(|p| &p.base))
            .collect();
        let shadowed = |o: &Origin| {
            !o.is_secure()
                && anchors
                    .iter()
                    .any(|a| a.is_secure() && (a.host() == o.host() || o.is_subdomain_of(a)))
        };
        let mut options = Options::default();
        if let Some(site) = &self.site {
            options = options.with_target(site.clone());
        }
        let trusted = self
            .origins
            .iter()
            .chain(self.patterns.iter().map(|p| &p.base));
        for o in trusted.filter(|o| !shadowed(o)) {
            options = options.with_trusted(o.clone());
        }

        let mut origins: BTreeSet<String> = [
            "null".to_owned(),
            format!("https://{PROBE_HOST}"),
            format!("http://{PROBE_HOST}"),
        ]
        .into();
        for anchor in &anchors {
            origins.insert(anchor.to_string());
            origins.extend(rune_cors::probes(anchor).into_iter().map(|p| p.origin));
            if anchor.is_secure() {
                // A plain-http subdomain, which `probes` does not cover.
                let port = anchor.port().map(|p| format!(":{p}")).unwrap_or_default();
                origins.insert(format!("http://rune-cors-probe.{}{port}", anchor.host()));
            }
        }

        let request_headers = self
            .allow_headers
            .iter()
            .map(HeaderName::as_str)
            .collect::<Vec<_>>()
            .join(", ");
        let request_headers = (!request_headers.is_empty()).then_some(request_headers.as_str());
        let method = self
            .methods
            .iter()
            .find(|m| !matches!(m.as_str(), "GET" | "HEAD" | "POST"))
            .map_or("GET", Method::as_str);

        let mut exchanges = Vec::with_capacity(origins.len() * 2);
        let mut structural = Vec::with_capacity(origins.len() * 2);
        for origin in &origins {
            let by_rule = canonical(origin).is_some_and(|o| self.structural(&o));
            let actual = self.actual_headers(Some(origin));
            exchanges.push(self.exchange(origin, &actual));
            structural.push(by_rule);
            if let Some(mut pre) = self.preflight_headers(origin, method, request_headers, false) {
                if self.private_network {
                    pre.push((ALLOW_PRIVATE_NETWORK, HeaderValue::from_static("true")));
                }
                exchanges.push(self.exchange(origin, &pre));
                structural.push(by_rule);
            }
        }

        let strict = rune_cors::run(&exchanges, &options);
        if !self.allow_subdomains && self.patterns.is_empty() {
            return strict;
        }
        // Subdomains granted by a wildcard are a deliberate choice; judge
        // those exchanges with subdomain trust and everything else without.
        let mut report = rune_cors::run(&exchanges, &options.with_trust_subdomains(true));
        for (row, (strict_row, &by_rule)) in report
            .rows
            .iter_mut()
            .zip(strict.rows.iter().zip(&structural))
        {
            if !by_rule {
                row.clone_from(strict_row);
            }
        }
        let by_rule = |w: &Weakness| structural.get(w.exchange).copied().unwrap_or(false);
        report.weaknesses.retain(|w| by_rule(w));
        report
            .weaknesses
            .extend(strict.weaknesses.into_iter().filter(|w| !by_rule(w)));
        report
            .weaknesses
            .sort_by_key(|w| std::cmp::Reverse(w.severity));
        report
    }

    /// The weaknesses in `report` that reject this policy: the most severe
    /// instance of each kind, most severe first.
    pub(crate) fn fatal(&self, report: &Report) -> Vec<Weakness> {
        let threshold = self.reject_at.min(HARD_FLOOR);
        let mut out: Vec<Weakness> = Vec::new();
        for w in &report.weaknesses {
            let fatal = w.severity >= threshold || w.kind == WeaknessKind::WildcardWithCredentials;
            if fatal && !out.iter().any(|seen| seen.kind == w.kind) {
                out.push(w.clone());
            }
        }
        out
    }

    /// Takes the first invalid builder input, if any.
    pub(crate) const fn take_error(&mut self) -> Option<Error> {
        self.error.take()
    }

    /// A policy that grants nothing but answers refusals like this one.
    pub(crate) fn deny_all(&self) -> Self {
        Self::new().rejection(self.rejection)
    }

    /// Builds an [`Exchange`] from the headers the middleware would send.
    fn exchange(&self, origin: &str, headers: &HeaderList) -> Exchange {
        let mut h = CorsHeaders::from_pairs(
            headers
                .iter()
                .filter_map(|(n, v)| Some((n.as_str(), v.to_str().ok()?))),
        );
        if self.varies() {
            h.push("vary", "Origin");
        }
        Exchange::new(Some(origin), h)
    }

    /// Keeps the first builder error.
    fn record(&mut self, error: Error) {
        if self.error.is_none() {
            self.error = Some(error);
        }
    }
}

/// Parses a request `Origin` value, accepting only the exact serialization
/// browsers send. Anything else (uppercase, a default port, a trailing dot,
/// empty labels) comes from a non-browser client and matches no rule.
fn canonical(origin: &str) -> Option<Origin> {
    let parsed = Origin::parse(origin).ok()?;
    let host = parsed.host();
    let labels_ok = is_ip(host) || host.split('.').all(valid_label);
    (labels_ok && parsed.to_string() == origin).then_some(parsed)
}

/// Builds an [`Error::InvalidInput`].
fn invalid(input: &str, reason: &'static str) -> Error {
    Error::InvalidInput {
        input: input.to_owned(),
        reason,
    }
}

/// Parses an exact origin from the builder, with the checks browsers'
/// serialization implies.
fn parse_origin(input: &str) -> Result<Origin, Error> {
    if !input.is_ascii() {
        return Err(invalid(
            input,
            "non-ASCII host; write internationalised domain names in punycode (xn--), \
             as browsers send them",
        ));
    }
    let origin = Origin::parse(input)?;
    let host = origin.host();
    if !is_ip(host) {
        if host.ends_with('.') {
            return Err(invalid(
                input,
                "trailing dot in host; browsers treat `example.com.` as a different origin",
            ));
        }
        if !host.split('.').all(valid_label) {
            return Err(invalid(input, "empty or malformed label in host"));
        }
    }
    Ok(origin)
}

/// Parses `scheme://*.host[:port]` or `scheme://**.host[:port]`.
fn parse_pattern(input: &str) -> Result<Pattern, Error> {
    let Some((scheme, rest)) = input.split_once("://") else {
        return Err(invalid(input, "missing \"://\""));
    };
    let (depth, base) = if let Some(base) = rest.strip_prefix("**.") {
        (SubdomainDepth::Any, base)
    } else if let Some(base) = rest.strip_prefix("*.") {
        (SubdomainDepth::One, base)
    } else {
        return Err(invalid(
            input,
            "a wildcard must be the whole first label: `*.` or `**.`",
        ));
    };
    if base.contains('*') {
        return Err(invalid(input, "only the first label can be a wildcard"));
    }
    let base = parse_origin(&format!("{scheme}://{base}")).map_err(|e| match e {
        Error::InvalidInput { reason, .. } => invalid(input, reason),
        other => other,
    })?;
    let host = base.host();
    if is_ip(host) {
        return Err(invalid(input, "a wildcard needs a domain name, not an IP"));
    }
    if !host.contains('.') && host != "localhost" {
        return Err(invalid(
            input,
            "a wildcard needs at least two labels after it; `*.com` would allow every site",
        ));
    }
    Ok(Pattern { base, depth })
}

/// Removes duplicates, keeping the first occurrence.
fn dedup<T: PartialEq>(items: impl IntoIterator<Item = T>) -> Vec<T> {
    let mut out: Vec<T> = Vec::new();
    for item in items {
        if !out.contains(&item) {
            out.push(item);
        }
    }
    out
}

/// Joins names into one comma-separated header value; `None` when empty.
fn join<T: AsRef<str>>(items: &[T]) -> Option<HeaderValue> {
    if items.is_empty() {
        return None;
    }
    let text = items
        .iter()
        .map(AsRef::as_ref)
        .collect::<Vec<_>>()
        .join(", ");
    HeaderValue::from_str(&text).ok()
}

#[cfg(test)]
#[allow(clippy::assert_is_empty, reason = "emptiness is the expectation")]
mod tests {
    use super::*;

    fn kinds(cors: &Cors) -> Vec<WeaknessKind> {
        cors.fatal(&cors.audit()).iter().map(|w| w.kind).collect()
    }

    fn value<'a>(list: &'a HeaderList, name: &HeaderName) -> Option<&'a str> {
        list.iter()
            .find(|(n, _)| n == name)
            .and_then(|(_, v)| v.to_str().ok())
    }

    fn input_error(mut cors: Cors) -> &'static str {
        match cors.take_error() {
            Some(Error::InvalidInput { reason, .. }) => reason,
            other => panic!("expected InvalidInput, got {other:?}"),
        }
    }

    #[test]
    fn default_allows_nothing_and_is_clean() {
        let cors = Cors::new();
        assert!(!cors.is_allowed("https://a.example"));
        assert!(!cors.is_allowed("null"));
        assert!(cors.actual_headers(Some("https://a.example")).is_empty());
        assert!(cors.audit().weaknesses.is_empty());
    }

    #[test]
    fn exact_origins_are_normalised_and_matched_exactly() {
        let cors = Cors::new().allow_origin("HTTPS://App.Example.com:443");
        assert!(cors.is_allowed("https://app.example.com"));
        assert!(!cors.is_allowed("https://App.example.com"));
        assert!(!cors.is_allowed("https://app.example.com:443"));
        assert!(!cors.is_allowed("http://app.example.com"));
        assert!(!cors.is_allowed("https://app.example.com:8443"));
        assert!(!cors.is_allowed("https://x.app.example.com"));
        assert!(!cors.is_allowed("https://app.example.com.evil.net"));
        assert!(!cors.is_allowed("https://evil-app.example.com"));
        assert!(!cors.is_allowed("https://app.example.com/"));
        assert!(!cors.is_allowed(" https://app.example.com"));
    }

    #[test]
    fn trailing_dots_never_match() {
        let cors = Cors::new()
            .allow_origin("https://example.com")
            .allow_origin("https://**.example.com");
        assert!(!cors.is_allowed("https://example.com."));
        assert!(!cors.is_allowed("https://a.example.com."));
        assert!(!cors.is_allowed("https://a..example.com"));
        assert!(!cors.is_allowed("https://.example.com"));
        assert!(input_error(Cors::new().allow_origin("https://example.com.")).contains("trailing"));
        assert!(input_error(Cors::new().allow_origin("https://a..example.com")).contains("label"));
    }

    #[test]
    fn idn_must_be_punycode() {
        assert!(
            input_error(Cors::new().allow_origin("https://bücher.example")).contains("punycode")
        );
        let cors = Cors::new().allow_origin("https://XN--bcher-kva.example");
        assert!(cors.is_allowed("https://xn--bcher-kva.example"));
        // A Unicode lookalike can never be a canonical Origin value.
        assert!(!cors.is_allowed("https://bücher.example"));
    }

    #[test]
    fn one_level_wildcard() {
        let cors = Cors::new().allow_origin("https://*.example.com");
        assert!(cors.is_allowed("https://a.example.com"));
        assert!(!cors.is_allowed("https://a.b.example.com"));
        assert!(
            !cors.is_allowed("https://example.com"),
            "apex is not implied"
        );
        assert!(!cors.is_allowed("http://a.example.com"));
        assert!(!cors.is_allowed("https://a.example.com:8443"));
        assert!(!cors.is_allowed("https://evil-example.com"));
        assert!(!cors.is_allowed("https://evilexample.com"));
        assert!(!cors.is_allowed("https://a.example.com.evil.net"));
        assert!(!cors.is_allowed("https://example.com.evil.net"));
        assert!(kinds(&cors.allow_credentials(true)).is_empty());
    }

    #[test]
    fn any_depth_wildcard_keeps_port() {
        let cors = Cors::new().allow_origin("https://**.example.com:8443");
        assert!(cors.is_allowed("https://a.example.com:8443"));
        assert!(cors.is_allowed("https://a.b.example.com:8443"));
        assert!(!cors.is_allowed("https://a.example.com"));
        assert!(!cors.is_allowed("https://example.com:8443"));
    }

    #[test]
    fn bad_wildcards_are_refused() {
        for bad in [
            "https://*example.com",
            "https://a.*.example.com",
            "https://*.*.example.com",
            "*://example.com",
            "https://*.com",
            "https://*.127.0.0.1",
            "https://*.[::1]",
            "https://*.example.com.",
            "https://*.example.com/path",
            "https://***.example.com",
        ] {
            let mut cors = Cors::new().allow_origin(bad);
            assert!(cors.take_error().is_some(), "{bad}");
        }
        let cors = Cors::new().allow_origin("http://*.localhost:3000");
        assert!(cors.is_allowed("http://app.localhost:3000"));
    }

    #[test]
    fn insecure_wildcard_next_to_secure_site_is_caught() {
        let cors = Cors::new()
            .site("https://example.com")
            .allow_origin("http://*.example.com")
            .allow_credentials(true);
        assert!(kinds(&cors).contains(&WeaknessKind::InsecureOrigin));
    }

    #[test]
    fn wildcard_does_not_hide_predicate_subdomains() {
        // The wildcard trusts subdomains of tenants.example.com, but a
        // predicate letting in any subdomain of app.example.com is still
        // reported.
        let cors = Cors::new()
            .allow_origin("https://app.example.com")
            .allow_origin("https://*.tenants.example.com")
            .allow_origin_fn(|o| o.ends_with(".app.example.com"))
            .allow_credentials(true);
        assert!(kinds(&cors).contains(&WeaknessKind::SubdomainOrigin));
    }

    #[test]
    fn subdomains_keep_scheme_and_port() {
        let cors = Cors::new()
            .allow_origin("https://example.com")
            .allow_subdomains(true);
        assert!(cors.is_allowed("https://a.b.example.com"));
        assert!(!cors.is_allowed("http://a.example.com"));
        assert!(!cors.is_allowed("https://a.example.com:8443"));
        assert!(!cors.is_allowed("https://evilexample.com"));
        assert!(kinds(&cors.allow_credentials(true)).is_empty());
    }

    #[test]
    fn invalid_origin_is_recorded() {
        let mut cors = Cors::new()
            .allow_origin("https://ok.example")
            .allow_origin("https://bad.example/path");
        assert!(matches!(cors.take_error(), Some(Error::InvalidOrigin(_))));
        let mut cors = Cors::new().site("nope");
        assert!(cors.take_error().is_some());
    }

    #[test]
    fn actual_headers() {
        let cors = Cors::new()
            .allow_origin("https://a.example")
            .allow_credentials(true)
            .expose_headers([
                HeaderName::from_static("x-total"),
                HeaderName::from_static("etag"),
            ]);
        let h = cors.actual_headers(Some("https://a.example"));
        assert_eq!(
            value(&h, &header::ACCESS_CONTROL_ALLOW_ORIGIN),
            Some("https://a.example")
        );
        assert_eq!(
            value(&h, &header::ACCESS_CONTROL_ALLOW_CREDENTIALS),
            Some("true")
        );
        assert_eq!(
            value(&h, &header::ACCESS_CONTROL_EXPOSE_HEADERS),
            Some("x-total, etag")
        );
        assert!(cors.actual_headers(None).is_empty());
        assert!(cors.varies());

        let any = Cors::new().allow_any_origin();
        assert_eq!(
            value(
                &any.actual_headers(None),
                &header::ACCESS_CONTROL_ALLOW_ORIGIN
            ),
            Some("*")
        );
        assert!(!any.varies());
    }

    #[test]
    fn preflight_checks_method_and_headers() {
        let cors = Cors::new()
            .allow_origin("https://a.example")
            .allow_methods([Method::GET, Method::PUT])
            .allow_headers([HeaderName::from_static("content-type")])
            .max_age(Duration::from_secs(600))
            .allow_private_network(true);
        let o = "https://a.example";
        let h = cors
            .preflight_headers(o, "PUT", Some("Content-Type"), true)
            .unwrap();
        assert_eq!(
            value(&h, &header::ACCESS_CONTROL_ALLOW_METHODS),
            Some("GET, PUT")
        );
        assert_eq!(
            value(&h, &header::ACCESS_CONTROL_ALLOW_HEADERS),
            Some("content-type")
        );
        assert_eq!(value(&h, &header::ACCESS_CONTROL_MAX_AGE), Some("600"));
        assert_eq!(value(&h, &ALLOW_PRIVATE_NETWORK), Some("true"));
        assert!(cors.preflight_headers(o, "POST", None, false).is_some());
        assert!(cors.preflight_headers(o, "DELETE", None, false).is_none());
        assert!(
            cors.preflight_headers(o, "PUT", Some("x-secret"), false)
                .is_none()
        );
        assert!(
            cors.preflight_headers(o, "PUT", Some(" , "), false)
                .is_some()
        );
        assert!(
            cors.preflight_headers("https://b.example", "GET", None, false)
                .is_none()
        );
        let h = cors.preflight_headers(o, "GET", None, false).unwrap();
        assert_eq!(value(&h, &ALLOW_PRIVATE_NETWORK), None);
    }

    #[test]
    fn requested_headers_are_never_mirrored() {
        let cors = Cors::new()
            .allow_origin("https://a.example")
            .allow_headers([HeaderName::from_static("content-type")]);
        let h = cors
            .preflight_headers("https://a.example", "GET", Some("CONTENT-TYPE"), false)
            .unwrap();
        assert_eq!(
            value(&h, &header::ACCESS_CONTROL_ALLOW_HEADERS),
            Some("content-type")
        );
    }

    #[test]
    fn max_age_is_capped() {
        let cors = Cors::new()
            .allow_origin("https://a.example")
            .max_age(Duration::MAX);
        let h = cors
            .preflight_headers("https://a.example", "GET", None, false)
            .unwrap();
        assert_eq!(value(&h, &header::ACCESS_CONTROL_MAX_AGE), Some("7200"));
        let zero = Cors::new().max_age(Duration::ZERO);
        assert_eq!(zero.max_age_value(), Some(Duration::ZERO));
    }

    #[test]
    fn private_network_only_for_exact_origins() {
        let cors = Cors::new()
            .allow_origin("https://a.example.com")
            .allow_origin("https://*.example.com")
            .allow_origin_fn(|o| o == "https://dyn.example")
            .allow_private_network(true);
        assert!(
            cors.preflight_headers("https://a.example.com", "GET", None, true)
                .is_some()
        );
        for other in ["https://b.example.com", "https://dyn.example"] {
            assert!(cors.is_allowed(other));
            assert!(cors.preflight_headers(other, "GET", None, true).is_none());
            assert!(cors.preflight_headers(other, "GET", None, false).is_some());
        }
        // Asked for while the policy does not grant it: refused.
        let off = Cors::new().allow_origin("https://a.example.com");
        assert!(
            off.preflight_headers("https://a.example.com", "GET", None, true)
                .is_none()
        );
    }

    #[test]
    fn star_header_is_a_wildcard_only_without_credentials() {
        let star = [HeaderName::from_static("*")];
        let open = Cors::new().allow_any_origin().allow_headers(star.clone());
        assert!(
            open.preflight_headers("https://x", "GET", Some("x-any"), false)
                .is_some()
        );
        let creds = Cors::new()
            .allow_origin("https://a.example")
            .allow_credentials(true)
            .allow_headers(star);
        assert!(
            creds
                .preflight_headers("https://a.example", "GET", Some("x-any"), false)
                .is_none()
        );
        assert!(
            creds
                .audit()
                .weaknesses
                .iter()
                .any(|w| w.kind == WeaknessKind::WildcardListWithCredentials)
        );
    }

    #[test]
    fn star_method_is_a_wildcard_only_without_credentials() {
        let star = [Method::from_bytes(b"*").unwrap()];
        let open = Cors::new()
            .allow_origin("https://a.example")
            .allow_methods(star);
        assert!(
            open.preflight_headers("https://a.example", "PATCH", None, false)
                .is_some()
        );
        let creds = open.allow_credentials(true);
        assert!(
            creds
                .preflight_headers("https://a.example", "PATCH", None, false)
                .is_none()
        );
    }

    #[test]
    fn wildcard_with_credentials_is_always_fatal() {
        let cors = Cors::new()
            .allow_any_origin()
            .allow_credentials(true)
            .reject_at(Severity::Critical);
        assert_eq!(kinds(&cors), [WeaknessKind::WildcardWithCredentials]);
    }

    #[test]
    fn wildcard_without_credentials_is_only_noted() {
        let cors = Cors::new().allow_origin("*");
        assert!(kinds(&cors).is_empty());
        assert!(
            cors.audit()
                .weaknesses
                .iter()
                .all(|w| w.kind == WeaknessKind::WildcardOrigin)
        );
    }

    #[test]
    fn null_origin_is_rejected() {
        assert!(kinds(&Cors::new().allow_origin("null")).contains(&WeaknessKind::NullOrigin));
        // High with credentials: cannot be waived.
        let cors = Cors::new()
            .allow_origin("null")
            .allow_credentials(true)
            .reject_at(Severity::Critical);
        assert!(kinds(&cors).contains(&WeaknessKind::NullOrigin));
        // A predicate never sees `null`.
        let cors = Cors::new().allow_origin_fn(|_| true);
        assert!(!cors.is_allowed("null"));
    }

    #[test]
    fn reflecting_predicate_is_critical() {
        let cors = Cors::new()
            .allow_origin_fn(|_| true)
            .allow_credentials(true);
        let report = cors.audit();
        assert_eq!(report.max_severity(), Some(Severity::Critical));
        assert!(kinds(&cors).contains(&WeaknessKind::OriginReflection));
    }

    #[test]
    fn predicate_only_sees_canonical_origins() {
        let cors = Cors::new().allow_origin_fn(|o| o.contains("example"));
        assert!(!cors.is_allowed("HTTPS://example.com"));
        assert!(!cors.is_allowed("https://example.com:443"));
        assert!(!cors.is_allowed("https://example.com."));
        assert!(!cors.is_allowed("https://example.com/x"));
        assert!(
            cors.actual_headers(Some("https://example.com/x"))
                .is_empty()
        );
    }

    #[test]
    fn unanchored_predicate_is_caught() {
        let cors = Cors::new()
            .site("https://example.com")
            .allow_origin_fn(|o| o.ends_with("example.com"))
            .allow_credentials(true);
        let k = kinds(&cors);
        assert!(k.contains(&WeaknessKind::UnanchoredAllowlist), "{k:?}");
        let cors = Cors::new()
            .site("https://example.com")
            .allow_origin_fn(|o| o.starts_with("https://example.com"));
        assert!(kinds(&cors).contains(&WeaknessKind::UnanchoredAllowlist));
    }

    #[test]
    fn insecure_subdomain_predicate_is_caught() {
        let cors = Cors::new()
            .site("https://example.com")
            .allow_origin_fn(|o| o.ends_with(".example.com"))
            .allow_credentials(true);
        assert!(kinds(&cors).contains(&WeaknessKind::InsecureOrigin));
    }

    #[test]
    fn plain_http_variant_of_secure_origin_is_caught() {
        let cors = Cors::new()
            .allow_origins(["https://app.example.com", "http://app.example.com"])
            .allow_credentials(true);
        assert_eq!(kinds(&cors), [WeaknessKind::InsecureOrigin]);
        // A plain-http origin with no secure counterpart is a deliberate
        // choice (local development) and passes.
        let dev = Cors::new()
            .allow_origin("http://localhost:3000")
            .allow_credentials(true);
        assert!(kinds(&dev).is_empty());
    }

    #[test]
    fn private_network_needs_exact_origins() {
        let cors = Cors::new().allow_any_origin().allow_private_network(true);
        assert!(kinds(&cors).contains(&WeaknessKind::PrivateNetworkAccess));
        let cors = Cors::new()
            .site("https://example.com")
            .allow_origin_fn(|o| o.ends_with("example.com"))
            .allow_private_network(true);
        assert!(kinds(&cors).contains(&WeaknessKind::PrivateNetworkAccess));
        let cors = Cors::new()
            .allow_origin("https://a.example")
            .allow_private_network(true);
        assert!(kinds(&cors).is_empty());
    }

    #[test]
    fn threshold_can_waive_low_findings_only() {
        let cors = Cors::new().allow_origin("null").reject_at(Severity::Medium);
        assert!(kinds(&cors).is_empty());
        assert!(!cors.audit().weaknesses.is_empty());
    }

    #[test]
    fn rejection_modes() {
        assert_eq!(Cors::new().rejection_mode().status(), StatusCode::FORBIDDEN);
        let omit = Cors::new().rejection(Rejection::OmitHeaders);
        assert_eq!(omit.rejection_mode().status(), StatusCode::NO_CONTENT);
        assert_eq!(omit.deny_all().rejection_mode(), Rejection::OmitHeaders);
        let teapot = Cors::new().deny_status(StatusCode::IM_A_TEAPOT);
        assert_eq!(
            teapot.rejection_mode(),
            Rejection::Status(StatusCode::IM_A_TEAPOT)
        );
    }

    #[test]
    fn debug_hides_predicate_and_shows_patterns() {
        let s = format!(
            "{:?}",
            Cors::new()
                .allow_origin_fn(|_| false)
                .allow_origin("https://**.example.com")
        );
        assert!(s.contains("Fn(&str) -> bool"));
        assert!(s.contains("https://**.example.com"));
    }
}
