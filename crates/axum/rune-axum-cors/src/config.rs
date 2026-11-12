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
///     .allow_credentials(true)
///     .allow_methods([Method::GET, Method::POST, Method::DELETE])
///     .allow_headers([HeaderName::from_static("content-type")]);
///
/// assert!(cors.is_allowed("https://app.example.com"));
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
    deny_status: StatusCode,
    /// The first invalid builder input, reported by `CorsLayer::new`.
    error: Option<Error>,
}

impl Default for Cors {
    fn default() -> Self {
        Self {
            site: None,
            any_origin: false,
            origins: Vec::new(),
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
            deny_status: StatusCode::FORBIDDEN,
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
            .field("deny_status", &self.deny_status)
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
        match Origin::parse(origin.as_ref()) {
            Ok(o) => self.site = Some(o),
            Err(e) => self.record(e.into()),
        }
        self
    }

    /// Allows one origin, written as `scheme://host[:port]`.
    ///
    /// The origin is normalised the way browsers serialise it (lowercase,
    /// no default port), and requests are matched against it exactly.
    /// `"null"` allows the opaque origin, and `"*"` is the same as
    /// [`allow_any_origin`](Self::allow_any_origin); the audit rejects both
    /// in most configurations. An invalid origin makes
    /// [`CorsLayer::new()`](crate::CorsLayer::new) fail.
    #[must_use]
    pub fn allow_origin(mut self, origin: impl AsRef<str>) -> Self {
        match origin.as_ref() {
            "*" => self.any_origin = true,
            "null" => self.allow_null = true,
            raw => match Origin::parse(raw) {
                Ok(o) => {
                    if !self.origins.contains(&o) {
                        self.origins.push(o);
                    }
                }
                Err(e) => self.record(e.into()),
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

    /// Also allows subdomains of the [`allow_origin`](Self::allow_origin)
    /// origins, with the same scheme and port: `https://a.example.com` for
    /// `https://example.com`, but not `http://a.example.com` nor
    /// `https://evilexample.com`. Off by default.
    #[must_use]
    pub const fn allow_subdomains(mut self, allow: bool) -> Self {
        self.allow_subdomains = allow;
        self
    }

    /// Also allows every origin for which `predicate` returns `true`.
    ///
    /// The predicate sees the request `Origin` exactly as the browser sent
    /// it (lowercase, no default port); it is never called for `null` or
    /// non-canonical values. Because it is opaque, the audit probes it with
    /// attacker-style origins derived from the [`site`](Self::site) and the
    /// allowed origins (an unrelated site, `null`, subdomains, plain-`http`
    /// variants and unanchored lookalikes) and rejects the policy if it
    /// grants any of them. Probing cannot prove a predicate safe; prefer
    /// exact origins.
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
    #[must_use]
    pub fn allow_methods(mut self, methods: impl IntoIterator<Item = Method>) -> Self {
        self.methods = dedup(methods);
        self
    }

    /// Replaces the request headers allowed in preflights. Empty by
    /// default; CORS-safelisted headers need no listing.
    ///
    /// `*` allows any header, but only without credentials: on a
    /// credentialed response it is a literal header name.
    #[must_use]
    pub fn allow_headers(mut self, headers: impl IntoIterator<Item = HeaderName>) -> Self {
        self.allow_headers = dedup(headers);
        self
    }

    /// Replaces the response headers exposed to scripts through
    /// `Access-Control-Expose-Headers`. Empty by default.
    #[must_use]
    pub fn expose_headers(mut self, headers: impl IntoIterator<Item = HeaderName>) -> Self {
        self.expose_headers = dedup(headers);
        self
    }

    /// Sets `Access-Control-Max-Age` on successful preflights, in whole
    /// seconds. Not sent by default (browsers then cache for 5 seconds).
    #[must_use]
    pub const fn max_age(mut self, max_age: Duration) -> Self {
        self.max_age = Some(max_age);
        self
    }

    /// Answers preflights that carry
    /// `Access-Control-Request-Private-Network: true` from allowed origins
    /// with `Access-Control-Allow-Private-Network: true`. Off by default.
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

    /// Sets the status code of refused preflights (origin, method or a
    /// header not allowed). Defaults to `403 Forbidden`.
    #[must_use]
    pub const fn deny_status(mut self, status: StatusCode) -> Self {
        self.deny_status = status;
        self
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
        let Ok(parsed) = Origin::parse(origin) else {
            return false;
        };
        // Browsers send the canonical serialization; anything else is not
        // a browser and must not match a lenient rule.
        if parsed.to_string() != origin {
            return false;
        }
        self.origins.contains(&parsed)
            || (self.allow_subdomains
                && self.origins.iter().any(|anchor| {
                    parsed.scheme() == anchor.scheme()
                        && parsed.effective_port() == anchor.effective_port()
                        && parsed.is_subdomain_of(anchor)
                }))
            || self.predicate.as_ref().is_some_and(|p| p(origin))
    }

    /// The status code of refused preflights.
    pub(crate) const fn deny_status_code(&self) -> StatusCode {
        self.deny_status
    }

    /// Whether `Access-Control-Allow-Origin` depends on the request origin,
    /// so responses need `Vary: Origin`.
    pub(crate) const fn varies(&self) -> bool {
        !self.any_origin
    }

    /// The `Access-Control-Allow-Origin` value for `origin`, if granted.
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
    /// refused: origin not allowed, method not allowed, or a requested
    /// header not allowed.
    pub(crate) fn preflight_headers(
        &self,
        origin: &str,
        method: &str,
        request_headers: Option<&str>,
        private_network: bool,
    ) -> Option<HeaderList> {
        let acao = self.grant(Some(origin))?;
        let safelisted = matches!(method, "GET" | "HEAD" | "POST");
        if !safelisted && !self.methods.iter().any(|m| m.as_str() == method) {
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
        if private_network && self.private_network {
            out.push((ALLOW_PRIVATE_NETWORK, HeaderValue::from_static("true")));
        }
        Some(out)
    }

    /// Audits the policy with [`rune_cors`].
    ///
    /// Every probe origin (the [`site`](Self::site) and allowed origins,
    /// [`rune_cors::probes`] of each, `null`, and unrelated `https` and
    /// `http` sites) is run through the same code the middleware uses to
    /// answer actual requests and preflights. The resulting
    /// [`Exchange`]s are analysed with [`rune_cors::run`], with the
    /// allowed origins as trusted (except plain-`http` variants of a
    /// secure site or allowed origin).
    ///
    /// The report lists every weakness, including the ones below the
    /// [`reject_at`](Self::reject_at) threshold.
    #[must_use]
    pub fn audit(&self) -> Report {
        let anchors: Vec<&Origin> = self.site.iter().chain(&self.origins).collect();
        let shadowed = |o: &Origin| {
            !o.is_secure()
                && anchors
                    .iter()
                    .any(|a| a.is_secure() && (a.host() == o.host() || o.is_subdomain_of(a)))
        };
        let mut options = Options::default().with_trust_subdomains(self.allow_subdomains);
        if let Some(site) = &self.site {
            options = options.with_target(site.clone());
        }
        for o in self.origins.iter().filter(|o| !shadowed(o)) {
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
        for origin in &origins {
            let actual = self.actual_headers(Some(origin));
            exchanges.push(self.exchange(origin, &actual));
            if let Some(pre) = self.preflight_headers(origin, method, request_headers, true) {
                exchanges.push(self.exchange(origin, &pre));
            }
        }
        rune_cors::run(&exchanges, &options)
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
        assert!(!cors.is_allowed("https://x.app.example.com"));
        assert!(!cors.is_allowed("https://app.example.com.evil.net"));
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
    fn debug_hides_predicate() {
        let s = format!("{:?}", Cors::new().allow_origin_fn(|_| false));
        assert!(s.contains("Fn(&str) -> bool"));
    }
}
