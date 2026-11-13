use http::{HeaderMap, HeaderName, HeaderValue, header};

pub use rune_referrer_policy::ReferrerPolicy;

use crate::Error;
use crate::csp::{CSP, CSP_REPORT_ONLY, CompiledCsp, CspBuilder, CspNonce};

const PERMISSIONS_POLICY: &str = "Permissions-Policy";
const COEP: &str = "Cross-Origin-Embedder-Policy";
const COEP_REPORT_ONLY: &str = "Cross-Origin-Embedder-Policy-Report-Only";

/// The `Permissions-Policy` that [`Helmet::new`] sends: powerful features
/// are off for every origin, including this one, except fullscreen and
/// passkeys (`WebAuthn`), which stay available to the page itself.
pub const DEFAULT_PERMISSIONS_POLICY: &str = "accelerometer=(), autoplay=(), bluetooth=(), \
browsing-topics=(), camera=(), clipboard-read=(), display-capture=(), encrypted-media=(), \
fullscreen=(self), gamepad=(), geolocation=(), gyroscope=(), hid=(), idle-detection=(), \
keyboard-map=(), local-fonts=(), magnetometer=(), microphone=(), midi=(), payment=(), \
picture-in-picture=(), publickey-credentials-create=(self), publickey-credentials-get=(self), \
screen-wake-lock=(), serial=(), usb=(), web-share=(), window-management=(), \
xr-spatial-tracking=()";

/// A CSP as configured: a raw string is parsed when the layer is built.
#[derive(Clone, Debug)]
enum CspSource {
    Raw(String),
    Builder(CspBuilder),
}

impl CspSource {
    fn into_builder(self, header: &'static str) -> Result<CspBuilder, Error> {
        match self {
            Self::Raw(s) => CspBuilder::parse_for(&s, header),
            Self::Builder(b) => Ok(b),
        }
    }
}

/// The security headers to set, as a builder.
///
/// [`Helmet::new`] (also [`Default`]) starts from the defaults listed in
/// the [crate docs](crate#default-headers); every header has a setter and
/// a `no_*` method to drop it. [`Helmet::empty`] starts from nothing.
/// Values are checked when the layer is built ([`HelmetLayer::new`] or
/// [`Helmet::build`]), so a bad CSP directive is an [`Error`] at startup,
/// never a broken header.
///
/// [`HelmetLayer::new`]: crate::HelmetLayer::new
///
/// # Examples
///
/// ```rust
/// use rune_axum_helmet::{CspBuilder, Helmet, Hsts, XFrameOptions};
///
/// let layer = Helmet::new()
///     .frame_options(XFrameOptions::SameOrigin)
///     .hsts(Hsts::new().max_age(63_072_000).preload())
///     .csp_from(CspBuilder::recommended().frame_ancestors(&["'self'"]).script_nonce())
///     .build()?;
/// # Ok::<(), rune_axum_helmet::Error>(())
/// ```
#[derive(Clone, Debug)]
#[allow(clippy::struct_excessive_bools)]
pub struct Helmet {
    content_type_options: bool,
    xss_protection: bool,
    frame_options: Option<XFrameOptions>,
    referrer_policy: Option<ReferrerPolicy>,
    hsts: Option<Hsts>,
    csp: Option<CspSource>,
    csp_report_only: Option<CspSource>,
    cross_origin_opener_policy: Option<CrossOriginOpenerPolicy>,
    cross_origin_resource_policy: Option<CrossOriginResourcePolicy>,
    cross_origin_embedder_policy: Option<CrossOriginEmbedderPolicy>,
    cross_origin_embedder_policy_report_only: Option<CrossOriginEmbedderPolicy>,
    cross_origin_embedder_policy_report_to: Option<String>,
    origin_agent_cluster: bool,
    dns_prefetch_control: Option<bool>,
    permitted_cross_domain_policies: Option<PermittedCrossDomainPolicies>,
    permissions_policy: Option<String>,
    reporting_endpoints: Vec<(String, String)>,
    remove_headers: Vec<HeaderName>,
    overwrite: bool,
}

impl Default for Helmet {
    fn default() -> Self {
        Self::new()
    }
}

impl Helmet {
    /// The secure defaults (see the [crate docs](crate#default-headers)).
    #[must_use]
    pub fn new() -> Self {
        Self {
            content_type_options: true,
            xss_protection: true,
            frame_options: Some(XFrameOptions::Deny),
            referrer_policy: Some(ReferrerPolicy::StrictOriginWhenCrossOrigin),
            hsts: Some(Hsts::new()),
            csp: Some(CspSource::Builder(CspBuilder::recommended())),
            csp_report_only: None,
            cross_origin_opener_policy: Some(CrossOriginOpenerPolicy::SameOrigin),
            cross_origin_resource_policy: Some(CrossOriginResourcePolicy::SameOrigin),
            cross_origin_embedder_policy: None,
            cross_origin_embedder_policy_report_only: None,
            cross_origin_embedder_policy_report_to: None,
            origin_agent_cluster: true,
            dns_prefetch_control: Some(false),
            permitted_cross_domain_policies: Some(PermittedCrossDomainPolicies::None),
            permissions_policy: Some(DEFAULT_PERMISSIONS_POLICY.to_owned()),
            reporting_endpoints: Vec::new(),
            remove_headers: vec![HeaderName::from_static("x-powered-by"), header::SERVER],
            overwrite: false,
        }
    }

    /// No headers at all and nothing removed; add only what you want.
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            content_type_options: false,
            xss_protection: false,
            frame_options: None,
            referrer_policy: None,
            hsts: None,
            csp: None,
            csp_report_only: None,
            cross_origin_opener_policy: None,
            cross_origin_resource_policy: None,
            cross_origin_embedder_policy: None,
            cross_origin_embedder_policy_report_only: None,
            cross_origin_embedder_policy_report_to: None,
            origin_agent_cluster: false,
            dns_prefetch_control: None,
            permitted_cross_domain_policies: None,
            permissions_policy: None,
            reporting_endpoints: Vec::new(),
            remove_headers: Vec::new(),
            overwrite: false,
        }
    }

    /// Checks the configuration and builds the layer; same as
    /// [`HelmetLayer::new`](crate::HelmetLayer::new).
    ///
    /// # Errors
    ///
    /// See [`Helmet::validate`].
    pub fn build(self) -> Result<crate::HelmetLayer, Error> {
        crate::HelmetLayer::new(self)
    }

    /// Checks every configured value without building a layer.
    ///
    /// # Errors
    ///
    /// - CSP problems from [`CspBuilder::validate`], for the enforced and
    ///   the report-only policy.
    /// - [`Error::PermissionsPolicy`] for a malformed `Permissions-Policy`.
    /// - [`Error::HstsPreload`] when [`Hsts::preload`] is set but the
    ///   header does not qualify for the preload list.
    /// - [`Error::InvalidReportingEndpoint`] for a bad endpoint name or URL,
    ///   [`Error::UnknownReportingEndpoint`] when a header reports to an
    ///   endpoint that is not configured.
    pub fn validate(&self) -> Result<(), Error> {
        self.clone().compile().map(drop)
    }

    // --- per-header setters ---

    /// Sets `X-Frame-Options` (default `DENY`).
    ///
    /// Browsers that support CSP use its `frame-ancestors` directive
    /// instead; keep the two in step.
    #[must_use]
    pub const fn frame_options(mut self, value: XFrameOptions) -> Self {
        self.frame_options = Some(value);
        self
    }

    /// Drops `X-Frame-Options`.
    #[must_use]
    pub const fn no_frame_options(mut self) -> Self {
        self.frame_options = None;
        self
    }

    /// Drops `X-Content-Type-Options: nosniff`.
    #[must_use]
    pub const fn no_content_type_options(mut self) -> Self {
        self.content_type_options = false;
        self
    }

    /// Drops `X-XSS-Protection: 0`.
    ///
    /// The header is sent as `0` to switch off the legacy XSS auditor of
    /// old browsers, which OWASP recommends because the auditor itself
    /// enabled attacks. Modern browsers ignore it either way.
    #[must_use]
    pub const fn no_xss_protection(mut self) -> Self {
        self.xss_protection = false;
        self
    }

    /// Sets `Strict-Transport-Security` (default: one year,
    /// `includeSubDomains`, not sent on plain-HTTP requests).
    #[must_use]
    pub const fn hsts(mut self, hsts: Hsts) -> Self {
        self.hsts = Some(hsts);
        self
    }

    /// Drops `Strict-Transport-Security`.
    #[must_use]
    pub const fn no_hsts(mut self) -> Self {
        self.hsts = None;
        self
    }

    /// Sets `Content-Security-Policy` from a policy string, parsed and
    /// checked at build time.
    #[must_use]
    pub fn csp(mut self, policy: impl Into<String>) -> Self {
        self.csp = Some(CspSource::Raw(policy.into()));
        self
    }

    /// Sets `Content-Security-Policy` from a [`CspBuilder`] (default:
    /// [`CspBuilder::recommended`]).
    #[must_use]
    pub fn csp_from(mut self, builder: CspBuilder) -> Self {
        self.csp = Some(CspSource::Builder(builder));
        self
    }

    /// Drops `Content-Security-Policy`.
    #[must_use]
    pub fn no_csp(mut self) -> Self {
        self.csp = None;
        self
    }

    /// Sets `Content-Security-Policy-Report-Only` from a policy string.
    ///
    /// A report-only policy is never enforced; browsers only report what it
    /// would have blocked. Use it to try a stricter policy next to the
    /// enforced one.
    #[must_use]
    pub fn report_only_csp(mut self, policy: impl Into<String>) -> Self {
        self.csp_report_only = Some(CspSource::Raw(policy.into()));
        self
    }

    /// Sets `Content-Security-Policy-Report-Only` from a [`CspBuilder`].
    /// A nonce slot gets the same per-request nonce as the enforced policy.
    ///
    /// ```rust
    /// use rune_axum_helmet::{CspBuilder, Helmet};
    ///
    /// let helmet = Helmet::new()
    ///     .reporting_endpoint("csp", "https://reports.example/csp")
    ///     .report_only_csp_from(CspBuilder::strict().report_to("csp"));
    /// assert!(helmet.validate().is_ok());
    /// ```
    #[must_use]
    pub fn report_only_csp_from(mut self, builder: CspBuilder) -> Self {
        self.csp_report_only = Some(CspSource::Builder(builder));
        self
    }

    /// Sets `Referrer-Policy` (default `strict-origin-when-cross-origin`).
    #[must_use]
    pub const fn referrer_policy(mut self, policy: ReferrerPolicy) -> Self {
        self.referrer_policy = Some(policy);
        self
    }

    /// Drops `Referrer-Policy`.
    #[must_use]
    pub const fn no_referrer_policy(mut self) -> Self {
        self.referrer_policy = None;
        self
    }

    /// Sets `Cross-Origin-Opener-Policy` (default `same-origin`).
    #[must_use]
    pub const fn cross_origin_opener_policy(mut self, policy: CrossOriginOpenerPolicy) -> Self {
        self.cross_origin_opener_policy = Some(policy);
        self
    }

    /// Drops `Cross-Origin-Opener-Policy`.
    #[must_use]
    pub const fn no_cross_origin_opener_policy(mut self) -> Self {
        self.cross_origin_opener_policy = None;
        self
    }

    /// Sets `Cross-Origin-Resource-Policy` (default `same-origin`).
    ///
    /// Use [`CrossOriginResourcePolicy::CrossOrigin`] for assets other
    /// sites embed (a CDN, public images, an API called from browsers).
    #[must_use]
    pub const fn cross_origin_resource_policy(mut self, policy: CrossOriginResourcePolicy) -> Self {
        self.cross_origin_resource_policy = Some(policy);
        self
    }

    /// Drops `Cross-Origin-Resource-Policy`.
    #[must_use]
    pub const fn no_cross_origin_resource_policy(mut self) -> Self {
        self.cross_origin_resource_policy = None;
        self
    }

    /// Sets `Cross-Origin-Embedder-Policy` (off by default: it blocks every
    /// cross-origin subresource that does not opt in).
    #[must_use]
    pub const fn cross_origin_embedder_policy(mut self, policy: CrossOriginEmbedderPolicy) -> Self {
        self.cross_origin_embedder_policy = Some(policy);
        self
    }

    /// Sets `Cross-Origin-Embedder-Policy-Report-Only`, to find what an
    /// embedder policy would break before enforcing it.
    ///
    /// ```rust
    /// use rune_axum_helmet::{CrossOriginEmbedderPolicy, Helmet};
    ///
    /// let helmet = Helmet::new()
    ///     .reporting_endpoint("coep", "/reports/coep")
    ///     .report_only_cross_origin_embedder_policy(CrossOriginEmbedderPolicy::RequireCorp)
    ///     .cross_origin_embedder_policy_report_to("coep");
    /// assert!(helmet.validate().is_ok());
    /// ```
    #[must_use]
    pub const fn report_only_cross_origin_embedder_policy(
        mut self,
        policy: CrossOriginEmbedderPolicy,
    ) -> Self {
        self.cross_origin_embedder_policy_report_only = Some(policy);
        self
    }

    /// Adds `report-to="<endpoint>"` to both embedder-policy headers.
    #[must_use]
    pub fn cross_origin_embedder_policy_report_to(mut self, endpoint: impl Into<String>) -> Self {
        self.cross_origin_embedder_policy_report_to = Some(endpoint.into());
        self
    }

    /// Turns `Origin-Agent-Cluster: ?1` on or off (default on). It asks the
    /// browser to isolate the origin in its own agent cluster.
    #[must_use]
    pub const fn origin_agent_cluster(mut self, enabled: bool) -> Self {
        self.origin_agent_cluster = enabled;
        self
    }

    /// Sets `X-DNS-Prefetch-Control` to `on` (`true`) or `off` (`false`,
    /// the default).
    #[must_use]
    pub const fn dns_prefetch_control(mut self, allow: bool) -> Self {
        self.dns_prefetch_control = Some(allow);
        self
    }

    /// Drops `X-DNS-Prefetch-Control`.
    #[must_use]
    pub const fn no_dns_prefetch_control(mut self) -> Self {
        self.dns_prefetch_control = None;
        self
    }

    /// Sets `X-Permitted-Cross-Domain-Policies` (default `none`).
    #[must_use]
    pub const fn permitted_cross_domain_policies(
        mut self,
        policy: PermittedCrossDomainPolicies,
    ) -> Self {
        self.permitted_cross_domain_policies = Some(policy);
        self
    }

    /// Drops `X-Permitted-Cross-Domain-Policies`.
    #[must_use]
    pub const fn no_permitted_cross_domain_policies(mut self) -> Self {
        self.permitted_cross_domain_policies = None;
        self
    }

    /// Sets `Permissions-Policy` (default [`DEFAULT_PERMISSIONS_POLICY`]).
    /// The value is parsed at build time.
    ///
    /// ```rust
    /// use rune_axum_helmet::Helmet;
    ///
    /// let ok = Helmet::new().permissions_policy("camera=(), geolocation=(self)");
    /// assert!(ok.validate().is_ok());
    /// let broken = Helmet::new().permissions_policy("camera=(self");
    /// assert!(broken.validate().is_err());
    /// ```
    #[must_use]
    pub fn permissions_policy(mut self, policy: impl Into<String>) -> Self {
        self.permissions_policy = Some(policy.into());
        self
    }

    /// Drops `Permissions-Policy`.
    #[must_use]
    pub fn no_permissions_policy(mut self) -> Self {
        self.permissions_policy = None;
        self
    }

    /// Declares a reporting endpoint, sent in `Reporting-Endpoints`.
    /// CSP `report-to` and the embedder policy's `report-to` must name one
    /// of these. Declaring a name again replaces its URL.
    ///
    /// The name is a structured-field key (lowercase letters, digits, `_`,
    /// `-`, `.`, `*`, starting with a letter); the URL is `https://`, a
    /// path starting with `/`, or `http://localhost` for development.
    #[must_use]
    pub fn reporting_endpoint(mut self, name: impl Into<String>, url: impl Into<String>) -> Self {
        let name = name.into();
        let url = url.into();
        if let Some(slot) = self
            .reporting_endpoints
            .iter_mut()
            .find(|(n, _)| *n == name)
        {
            slot.1 = url;
        } else {
            self.reporting_endpoints.push((name, url));
        }
        self
    }

    /// Removes `name` from every response (default: `X-Powered-By` and
    /// `Server`, which only advertise the stack to attackers).
    #[must_use]
    pub fn remove_header(mut self, name: HeaderName) -> Self {
        if !self.remove_headers.contains(&name) {
            self.remove_headers.push(name);
        }
        self
    }

    /// Stops removing `name`, e.g. `keep_header(http::header::SERVER)`.
    #[must_use]
    pub fn keep_header(mut self, name: &HeaderName) -> Self {
        self.remove_headers.retain(|n| n != name);
        self
    }

    /// Whether to replace headers the handler already set (default
    /// `false`: a value the handler chose wins, as with Helmet.js).
    #[must_use]
    pub const fn overwrite(mut self, overwrite: bool) -> Self {
        self.overwrite = overwrite;
        self
    }

    pub(crate) fn compile(self) -> Result<Compiled, Error> {
        for (name, url) in &self.reporting_endpoints {
            check_endpoint(name, url)?;
        }
        let known_endpoint = |header: &'static str, name: &str| {
            if self.reporting_endpoints.iter().any(|(n, _)| n == name) {
                Ok(())
            } else {
                Err(Error::UnknownReportingEndpoint {
                    header,
                    name: name.to_owned(),
                })
            }
        };

        let mut headers = Vec::new();
        let mut push = |name: &'static str, value: HeaderValue| {
            headers.push((HeaderName::from_static(name), value));
        };
        if self.content_type_options {
            push(
                "x-content-type-options",
                HeaderValue::from_static("nosniff"),
            );
        }
        if self.xss_protection {
            push("x-xss-protection", HeaderValue::from_static("0"));
        }
        if let Some(v) = self.frame_options {
            push("x-frame-options", HeaderValue::from_static(v.as_str()));
        }
        if let Some(v) = self.referrer_policy {
            push("referrer-policy", HeaderValue::from_static(v.as_str()));
        }
        if let Some(v) = self.cross_origin_opener_policy {
            push(
                "cross-origin-opener-policy",
                HeaderValue::from_static(v.as_str()),
            );
        }
        if let Some(v) = self.cross_origin_resource_policy {
            push(
                "cross-origin-resource-policy",
                HeaderValue::from_static(v.as_str()),
            );
        }
        let coep_report_to = self.cross_origin_embedder_policy_report_to.as_deref();
        if let Some(endpoint) = coep_report_to {
            let header = if self.cross_origin_embedder_policy_report_only.is_some() {
                COEP_REPORT_ONLY
            } else {
                COEP
            };
            known_endpoint(header, endpoint)?;
        }
        for (name, label, policy) in [
            (
                "cross-origin-embedder-policy",
                COEP,
                self.cross_origin_embedder_policy,
            ),
            (
                "cross-origin-embedder-policy-report-only",
                COEP_REPORT_ONLY,
                self.cross_origin_embedder_policy_report_only,
            ),
        ] {
            if let Some(policy) = policy {
                let value = coep_report_to.map_or_else(
                    || policy.as_str().to_owned(),
                    |e| format!("{}; report-to=\"{e}\"", policy.as_str()),
                );
                let value = HeaderValue::from_str(&value)
                    .map_err(|_| Error::InvalidHeaderValue { header: label })?;
                push(name, value);
            }
        }
        if self.origin_agent_cluster {
            push("origin-agent-cluster", HeaderValue::from_static("?1"));
        }
        if let Some(allow) = self.dns_prefetch_control {
            push(
                "x-dns-prefetch-control",
                HeaderValue::from_static(if allow { "on" } else { "off" }),
            );
        }
        if let Some(v) = self.permitted_cross_domain_policies {
            push(
                "x-permitted-cross-domain-policies",
                HeaderValue::from_static(v.as_str()),
            );
        }
        if let Some(policy) = &self.permissions_policy {
            rune_permissions_policy::PermissionsPolicy::parse(policy)?;
            let value = HeaderValue::from_str(policy).map_err(|_| Error::InvalidHeaderValue {
                header: PERMISSIONS_POLICY,
            })?;
            push("permissions-policy", value);
        }
        if !self.reporting_endpoints.is_empty() {
            let value = self
                .reporting_endpoints
                .iter()
                .map(|(n, u)| format!("{n}=\"{u}\""))
                .collect::<Vec<_>>()
                .join(", ");
            let value = HeaderValue::from_str(&value).map_err(|_| Error::InvalidHeaderValue {
                header: "Reporting-Endpoints",
            })?;
            push("reporting-endpoints", value);
        }

        let mut csp = Vec::new();
        for (name, label, source) in [
            ("content-security-policy", CSP, self.csp),
            (
                "content-security-policy-report-only",
                CSP_REPORT_ONLY,
                self.csp_report_only,
            ),
        ] {
            if let Some(source) = source {
                let builder = source.into_builder(label)?;
                if let Some(endpoint) = builder.report_to_endpoint() {
                    known_endpoint(label, endpoint)?;
                }
                csp.push((
                    HeaderName::from_static(name),
                    CompiledCsp::new(builder, label)?,
                ));
            }
        }

        let hsts = match self.hsts {
            Some(h) => Some((h.header_value()?, h.mode)),
            None => None,
        };

        Ok(Compiled {
            headers,
            csp,
            hsts,
            remove: self.remove_headers,
            overwrite: self.overwrite,
        })
    }
}

/// Checks a `Reporting-Endpoints` name (an RFC 8941 key) and URL.
fn check_endpoint(name: &str, url: &str) -> Result<(), Error> {
    let fail = |reason| {
        Err(Error::InvalidReportingEndpoint {
            name: name.to_owned(),
            reason,
        })
    };
    let mut chars = name.bytes();
    let valid_name = chars
        .next()
        .is_some_and(|b| b.is_ascii_lowercase() || b == b'*')
        && chars.all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"_-.*".contains(&b));
    if !valid_name {
        return fail(
            "the name must be lowercase letters, digits, `_`, `-`, `.` or `*`, starting with a letter",
        );
    }
    if url.is_empty()
        || !url
            .bytes()
            .all(|b| b.is_ascii_graphic() && b != b'"' && b != b'\\')
    {
        return fail("the URL must be printable ASCII without quotes or backslashes");
    }
    let lower = url.to_ascii_lowercase();
    let local = ["http://localhost", "http://127.0.0.1", "http://[::1]"]
        .iter()
        .any(|p| {
            lower
                .strip_prefix(p)
                .is_some_and(|rest| rest.is_empty() || rest.starts_with([':', '/']))
        });
    if !(lower.starts_with("https://") || (url.starts_with('/') && !url.starts_with("//")) || local)
    {
        return fail("the URL must use https (or be a path, or localhost)");
    }
    Ok(())
}

/// A validated [`Helmet`], ready to apply to responses.
#[derive(Clone, Debug)]
pub struct Compiled {
    headers: Vec<(HeaderName, HeaderValue)>,
    csp: Vec<(HeaderName, CompiledCsp)>,
    hsts: Option<(HeaderValue, HstsMode)>,
    remove: Vec<HeaderName>,
    overwrite: bool,
}

/// What the layer knows about the request when the response comes back.
#[derive(Clone, Debug, Default)]
pub struct RequestInfo {
    pub nonce: Option<CspNonce>,
    /// `Some(true)` for HTTPS, `Some(false)` for plain HTTP, `None` when
    /// the request does not say.
    pub https: Option<bool>,
}

impl Compiled {
    /// Sets and removes nothing.
    pub const fn empty() -> Self {
        Self {
            headers: Vec::new(),
            csp: Vec::new(),
            hsts: None,
            remove: Vec::new(),
            overwrite: false,
        }
    }

    pub fn uses_nonce(&self) -> bool {
        self.csp.iter().any(|(_, c)| c.uses_nonce())
    }

    /// Sets the configured headers on `headers`, leaving out `skip`.
    pub fn apply(&self, headers: &mut HeaderMap, info: &RequestInfo, skip: &[HeaderName]) {
        let overwrite = self.overwrite;
        let mut set = |name: &HeaderName, value: HeaderValue| {
            if !skip.contains(name) && (overwrite || !headers.contains_key(name)) {
                headers.insert(name.clone(), value);
            }
        };
        for (name, value) in &self.headers {
            set(name, value.clone());
        }
        // A replacement policy may want a nonce the outer layer did not
        // generate; a fresh one still blocks injected inline code.
        let nonce = info
            .nonce
            .clone()
            .or_else(|| self.uses_nonce().then(CspNonce::generate));
        for (name, csp) in &self.csp {
            if let Some(value) = csp.value(nonce.as_ref()) {
                set(name, value);
            }
        }
        if let Some((value, mode)) = &self.hsts
            && mode.sends(info.https)
        {
            set(&header::STRICT_TRANSPORT_SECURITY, value.clone());
        }
        for name in &self.remove {
            if !skip.contains(name) {
                headers.remove(name);
            }
        }
    }
}

// --- header values ---

/// Value of `X-Frame-Options`.
///
/// Superseded by CSP `frame-ancestors`, but still honoured by browsers
/// that predate it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum XFrameOptions {
    /// `DENY`: no page may frame this response (the default).
    Deny,
    /// `SAMEORIGIN`: only same-origin pages may frame it.
    SameOrigin,
}

impl XFrameOptions {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Deny => "DENY",
            Self::SameOrigin => "SAMEORIGIN",
        }
    }
}

/// When `Strict-Transport-Security` is sent.
///
/// Browsers ignore HSTS received over plain HTTP (RFC 6797 §8.1), and
/// servers must not send it there (§7.2). The layer learns the scheme from
/// `Forwarded: proto=`, `X-Forwarded-Proto`, or an absolute request URI.
/// A server that terminates TLS itself usually sees none of these, which is
/// why the default only skips requests known to be plain HTTP.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum HstsMode {
    /// Skip requests known to be plain HTTP; send on all others (default).
    #[default]
    ExceptHttp,
    /// Send only on requests known to be HTTPS, e.g. behind a proxy that
    /// always sets `X-Forwarded-Proto`.
    HttpsOnly,
    /// Send on every response.
    Always,
}

impl HstsMode {
    const fn sends(self, https: Option<bool>) -> bool {
        match self {
            Self::ExceptHttp => !matches!(https, Some(false)),
            Self::HttpsOnly => matches!(https, Some(true)),
            Self::Always => true,
        }
    }
}

/// Configuration of `Strict-Transport-Security`.
///
/// [`Hsts::new`] gives `max-age=31536000; includeSubDomains` (one year, as
/// in Helmet.js), sent as described in [`HstsMode`].
///
/// # Examples
///
/// ```rust
/// use rune_axum_helmet::{Helmet, Hsts, HstsMode};
///
/// // Ready for https://hstspreload.org: two years, subdomains, preload.
/// let hsts = Hsts::new().max_age(63_072_000).preload();
/// assert!(Helmet::new().hsts(hsts).validate().is_ok());
///
/// // Preload needs at least a year and includeSubDomains.
/// let short = Hsts::new().max_age(86_400).preload();
/// assert!(Helmet::new().hsts(short).validate().is_err());
///
/// // Behind a proxy that always sets X-Forwarded-Proto.
/// let strict = Hsts::new().mode(HstsMode::HttpsOnly);
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Hsts {
    max_age_secs: u64,
    include_subdomains: bool,
    preload: bool,
    mode: HstsMode,
}

impl Default for Hsts {
    fn default() -> Self {
        Self::new()
    }
}

impl Hsts {
    /// One year, `includeSubDomains`, no `preload`, [`HstsMode::ExceptHttp`].
    #[must_use]
    pub const fn new() -> Self {
        Self {
            max_age_secs: 31_536_000,
            include_subdomains: true,
            preload: false,
            mode: HstsMode::ExceptHttp,
        }
    }

    /// Sets `max-age` in seconds. `0` tells browsers to forget the policy.
    #[must_use]
    pub const fn max_age(mut self, secs: u64) -> Self {
        self.max_age_secs = secs;
        self
    }

    /// Adds `includeSubDomains` (on by default).
    #[must_use]
    pub const fn include_subdomains(mut self) -> Self {
        self.include_subdomains = true;
        self
    }

    /// Removes `includeSubDomains`, for a parent domain whose subdomains
    /// are not all on HTTPS yet.
    #[must_use]
    pub const fn exclude_subdomains(mut self) -> Self {
        self.include_subdomains = false;
        self
    }

    /// Adds `preload`. Build fails unless the header meets the preload
    /// list's requirements (checked with `rune-hsts`): `max-age` of at
    /// least a year and `includeSubDomains`.
    #[must_use]
    pub const fn preload(mut self) -> Self {
        self.preload = true;
        self
    }

    /// Sets when the header is sent.
    #[must_use]
    pub const fn mode(mut self, mode: HstsMode) -> Self {
        self.mode = mode;
        self
    }

    fn header_value(&self) -> Result<HeaderValue, Error> {
        let hsts = rune_hsts::Hsts::new(self.max_age_secs)
            .with_include_subdomains(self.include_subdomains)
            .with_preload(self.preload);
        if self.preload {
            let issues = rune_hsts::header_issues(&hsts);
            if !issues.is_empty() {
                let reasons = issues
                    .iter()
                    .map(|i| i.message.as_str())
                    .collect::<Vec<_>>()
                    .join("; ");
                return Err(Error::HstsPreload { reasons });
            }
        }
        HeaderValue::from_str(&hsts.to_string()).map_err(|_| Error::InvalidHeaderValue {
            header: "Strict-Transport-Security",
        })
    }
}

/// Value of `Cross-Origin-Opener-Policy`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum CrossOriginOpenerPolicy {
    /// `same-origin`: cross-origin windows lose their handle to this page
    /// (the default).
    SameOrigin,
    /// `same-origin-allow-popups`: like `same-origin`, but popups this page
    /// opens keep their opener (OAuth and payment popups).
    SameOriginAllowPopups,
    /// `noopener-allow-popups`: always severs the opener, even from
    /// same-origin pages.
    NoopenerAllowPopups,
    /// `unsafe-none`: no isolation.
    UnsafeNone,
}

impl CrossOriginOpenerPolicy {
    const fn as_str(self) -> &'static str {
        match self {
            Self::SameOrigin => "same-origin",
            Self::SameOriginAllowPopups => "same-origin-allow-popups",
            Self::NoopenerAllowPopups => "noopener-allow-popups",
            Self::UnsafeNone => "unsafe-none",
        }
    }
}

/// Value of `Cross-Origin-Resource-Policy`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CrossOriginResourcePolicy {
    /// `same-origin`: only this origin may load the resource (the default).
    SameOrigin,
    /// `same-site`: any origin on the same site may load it.
    SameSite,
    /// `cross-origin`: anyone may load it.
    CrossOrigin,
}

impl CrossOriginResourcePolicy {
    const fn as_str(self) -> &'static str {
        match self {
            Self::SameOrigin => "same-origin",
            Self::SameSite => "same-site",
            Self::CrossOrigin => "cross-origin",
        }
    }
}

/// Value of `Cross-Origin-Embedder-Policy`.
///
/// `require-corp` or `credentialless` together with COOP `same-origin`
/// makes the page cross-origin isolated (needed for `SharedArrayBuffer`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum CrossOriginEmbedderPolicy {
    /// `require-corp`: cross-origin subresources must opt in with CORP or
    /// CORS.
    RequireCorp,
    /// `credentialless`: cross-origin no-CORS requests are sent without
    /// credentials instead of being blocked.
    Credentialless,
    /// `unsafe-none`: no restriction.
    UnsafeNone,
}

impl CrossOriginEmbedderPolicy {
    const fn as_str(self) -> &'static str {
        match self {
            Self::RequireCorp => "require-corp",
            Self::Credentialless => "credentialless",
            Self::UnsafeNone => "unsafe-none",
        }
    }
}

/// Value of `X-Permitted-Cross-Domain-Policies`, which tells Adobe
/// clients (Flash, Acrobat) whether to load cross-domain policy files.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PermittedCrossDomainPolicies {
    /// `none`: no policy file is allowed (the default).
    None,
    /// `master-only`: only `/crossdomain.xml`.
    MasterOnly,
    /// `by-content-type`: only files served as
    /// `text/x-cross-domain-policy`.
    ByContentType,
    /// `none-this-response`: not for this response.
    NoneThisResponse,
    /// `all`: any policy file.
    All,
}

impl PermittedCrossDomainPolicies {
    const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::MasterOnly => "master-only",
            Self::ByContentType => "by-content-type",
            Self::NoneThisResponse => "none-this-response",
            Self::All => "all",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_valid() {
        Helmet::new().validate().unwrap();
        Helmet::default().validate().unwrap();
        Helmet::empty().validate().unwrap();
    }

    #[test]
    fn default_permissions_policy_uses_current_features() {
        let policy =
            rune_permissions_policy::PermissionsPolicy::parse(DEFAULT_PERMISSIONS_POLICY).unwrap();
        for directive in &policy.directives {
            let feature = rune_permissions_policy::feature(&directive.feature)
                .unwrap_or_else(|| panic!("unknown feature {}", directive.feature));
            assert_eq!(
                feature.status,
                rune_permissions_policy::Status::Current,
                "{}",
                feature.name
            );
        }
        for restricted in rune_permissions_policy::RECOMMENDED_RESTRICTED {
            assert!(
                policy.get(restricted).is_some(),
                "{restricted} not restricted"
            );
        }
    }

    #[test]
    fn hsts_values() {
        assert_eq!(
            Hsts::new().header_value().unwrap(),
            "max-age=31536000; includeSubDomains"
        );
        assert_eq!(
            Hsts::new()
                .exclude_subdomains()
                .max_age(0)
                .header_value()
                .unwrap(),
            "max-age=0"
        );
        assert_eq!(
            Hsts::new().preload().header_value().unwrap(),
            "max-age=31536000; includeSubDomains; preload"
        );
    }

    #[test]
    fn hsts_preload_is_checked() {
        let err = Hsts::new()
            .exclude_subdomains()
            .max_age(600)
            .preload()
            .header_value()
            .unwrap_err();
        let Error::HstsPreload { reasons } = err else {
            panic!("{err:?}")
        };
        assert!(reasons.contains("max-age=600"), "{reasons}");
        assert!(reasons.contains("includeSubDomains"), "{reasons}");
    }

    #[test]
    fn hsts_modes() {
        for (mode, http, unknown, https) in [
            (HstsMode::ExceptHttp, false, true, true),
            (HstsMode::HttpsOnly, false, false, true),
            (HstsMode::Always, true, true, true),
        ] {
            assert_eq!(mode.sends(Some(false)), http, "{mode:?}");
            assert_eq!(mode.sends(None), unknown, "{mode:?}");
            assert_eq!(mode.sends(Some(true)), https, "{mode:?}");
        }
    }

    #[test]
    fn reporting_endpoint_checks() {
        for (name, url) in [
            ("csp", "https://r.example/csp"),
            ("csp-endpoint", "/reports"),
            ("default", "http://localhost:8080/r"),
            ("*a.b_c", "https://x"),
        ] {
            check_endpoint(name, url).unwrap();
        }
        for (name, url) in [
            ("CSP", "https://r.example"),
            ("1csp", "https://r.example"),
            ("", "https://r.example"),
            ("csp", "http://r.example"),
            ("csp", "//r.example"),
            ("csp", "https://r.example/\"x"),
            ("csp", "http://localhost.evil.example"),
            ("csp", ""),
        ] {
            assert!(
                matches!(
                    check_endpoint(name, url),
                    Err(Error::InvalidReportingEndpoint { .. })
                ),
                "{name} {url}"
            );
        }
    }

    #[test]
    fn report_to_must_name_an_endpoint() {
        let err = Helmet::new()
            .csp_from(CspBuilder::recommended().report_to("csp"))
            .validate()
            .unwrap_err();
        assert_eq!(
            err,
            Error::UnknownReportingEndpoint {
                header: CSP,
                name: "csp".into()
            }
        );
        let err = Helmet::new()
            .report_only_cross_origin_embedder_policy(CrossOriginEmbedderPolicy::RequireCorp)
            .cross_origin_embedder_policy_report_to("coep")
            .validate()
            .unwrap_err();
        assert!(matches!(
            err,
            Error::UnknownReportingEndpoint {
                header: COEP_REPORT_ONLY,
                ..
            }
        ));
    }

    #[test]
    fn raw_csp_errors_name_the_header() {
        let err = Helmet::new()
            .report_only_csp("default-src 'self'; default-src *")
            .validate()
            .unwrap_err();
        assert!(matches!(
            err,
            Error::Csp {
                header: CSP_REPORT_ONLY,
                source: rune_csp::Error::DuplicateDirective { .. }
            }
        ));
    }

    #[test]
    fn bad_permissions_policy_is_rejected() {
        assert!(matches!(
            Helmet::new().permissions_policy("camera=(self").validate(),
            Err(Error::PermissionsPolicy(_))
        ));
    }

    #[test]
    fn remove_and_keep_headers() {
        let h = Helmet::new()
            .keep_header(&header::SERVER)
            .remove_header(HeaderName::from_static("x-aspnet-version"))
            .remove_header(HeaderName::from_static("x-aspnet-version"));
        assert_eq!(
            h.remove_headers,
            vec![
                HeaderName::from_static("x-powered-by"),
                HeaderName::from_static("x-aspnet-version")
            ]
        );
    }
}
