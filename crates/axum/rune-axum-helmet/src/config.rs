use http::{
    HeaderMap, HeaderValue,
    header::{self, HeaderName},
};

/// The set of security headers to apply to every response.
///
/// All headers are configured through a builder-style API. Call
/// [`Helmet::new()`] (or [`Default::default()`]) to start from the secure
/// defaults, then chain methods to customise individual headers.
///
/// # Examples
///
/// ```rust
/// use rune_axum_helmet::{Helmet, Hsts, XFrameOptions, CspBuilder};
///
/// let helmet = Helmet::new()
///     .frame_options(XFrameOptions::Deny)
///     .hsts(Hsts::new().max_age(63_072_000))
///     .csp_from(
///         CspBuilder::new()
///             .default_src(&["'self'"])
///             .upgrade_insecure_requests(),
///     );
/// ```
#[derive(Clone, Debug, Default)]
pub struct Helmet {
    pub(crate) content_type_options: bool,
    pub(crate) xss_protection: bool,
    pub(crate) frame_options: Option<XFrameOptions>,
    pub(crate) referrer_policy: Option<ReferrerPolicy>,
    pub(crate) hsts: Option<Hsts>,
    pub(crate) csp: Option<String>,
    pub(crate) csp_report_only: Option<String>,
    pub(crate) cross_origin_opener_policy: Option<CrossOriginOpenerPolicy>,
    pub(crate) cross_origin_resource_policy: Option<CrossOriginResourcePolicy>,
    pub(crate) cross_origin_embedder_policy: Option<CrossOriginEmbedderPolicy>,
    pub(crate) permissions_policy: Option<String>,
}

impl Helmet {
    /// Creates a new `Helmet` with secure defaults applied.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            content_type_options: true,
            xss_protection: true,
            frame_options: Some(XFrameOptions::SameOrigin),
            referrer_policy: Some(ReferrerPolicy::StrictOriginWhenCrossOrigin),
            hsts: None,
            csp: None,
            csp_report_only: None,
            cross_origin_opener_policy: Some(CrossOriginOpenerPolicy::SameOrigin),
            cross_origin_resource_policy: Some(CrossOriginResourcePolicy::SameOrigin),
            cross_origin_embedder_policy: None,
            permissions_policy: None,
        }
    }

    /// Sets the `X-Frame-Options` header.
    #[must_use]
    pub const fn frame_options(mut self, value: XFrameOptions) -> Self {
        self.frame_options = Some(value);
        self
    }

    /// Removes the `X-Frame-Options` header entirely.
    #[must_use]
    pub const fn no_frame_options(mut self) -> Self {
        self.frame_options = None;
        self
    }

    /// Disables the `X-Content-Type-Options: nosniff` header.
    ///
    /// The header is enabled by default. Only disable it if your application
    /// intentionally serves content without a `Content-Type` header and relies
    /// on browser MIME sniffing.
    #[must_use]
    pub const fn no_content_type_options(mut self) -> Self {
        self.content_type_options = false;
        self
    }

    /// Disables the `X-XSS-Protection: 0` header.
    ///
    /// The header is enabled by default (sending `0`, which disables the
    /// legacy browser XSS filter). Remove it only when you have full control
    /// over your response's `Content-Type` and can guarantee no XSS surfaces.
    #[must_use]
    pub const fn no_xss_protection(mut self) -> Self {
        self.xss_protection = false;
        self
    }

    /// Sets the `Strict-Transport-Security` header.
    #[must_use]
    pub const fn hsts(mut self, hsts: Hsts) -> Self {
        self.hsts = Some(hsts);
        self
    }

    /// Sets the `Content-Security-Policy` header to a raw policy string.
    ///
    /// Prefer [`Helmet::csp_from`] with a [`CspBuilder`] for structured
    /// construction.
    #[must_use]
    pub fn csp(mut self, policy: impl Into<String>) -> Self {
        self.csp = Some(policy.into());
        self
    }

    /// Sets the `Content-Security-Policy` header from a [`CspBuilder`].
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rune_axum_helmet::{Helmet, CspBuilder};
    ///
    /// let helmet = Helmet::new().csp_from(
    ///     CspBuilder::new()
    ///         .default_src(&["'self'"])
    ///         .script_src(&["'self'", "'strict-dynamic'"])
    ///         .upgrade_insecure_requests(),
    /// );
    /// ```
    #[must_use]
    pub fn csp_from(self, builder: CspBuilder) -> Self {
        self.csp(builder.build())
    }

    /// Sets the `Content-Security-Policy-Report-Only` header to a raw policy string.
    ///
    /// Prefer [`Helmet::report_only_csp_from`] with a [`CspBuilder`] for
    /// structured construction.
    ///
    /// > [!NOTE]
    /// > Report-Only policies are never enforced; they only send violation
    /// > reports to the `report-uri` or `report-to` endpoint. Use them to
    /// > test a new policy before enabling enforcement.
    #[must_use]
    pub fn report_only_csp(mut self, policy: impl Into<String>) -> Self {
        self.csp_report_only = Some(policy.into());
        self
    }

    /// Sets the `Content-Security-Policy-Report-Only` header from a [`CspBuilder`].
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rune_axum_helmet::{Helmet, CspBuilder};
    ///
    /// let helmet = Helmet::new().report_only_csp_from(
    ///     CspBuilder::new()
    ///         .default_src(&["'self'"])
    ///         .report_to("csp-endpoint"),
    /// );
    /// ```
    #[must_use]
    pub fn report_only_csp_from(self, builder: CspBuilder) -> Self {
        self.report_only_csp(builder.build())
    }

    /// Sets the `Referrer-Policy` header.
    #[must_use]
    pub const fn referrer_policy(mut self, policy: ReferrerPolicy) -> Self {
        self.referrer_policy = Some(policy);
        self
    }

    /// Sets the `Cross-Origin-Opener-Policy` header.
    #[must_use]
    pub const fn cross_origin_opener_policy(mut self, policy: CrossOriginOpenerPolicy) -> Self {
        self.cross_origin_opener_policy = Some(policy);
        self
    }

    /// Sets the `Cross-Origin-Resource-Policy` header.
    #[must_use]
    pub const fn cross_origin_resource_policy(mut self, policy: CrossOriginResourcePolicy) -> Self {
        self.cross_origin_resource_policy = Some(policy);
        self
    }

    /// Sets the `Cross-Origin-Embedder-Policy` header.
    #[must_use]
    pub const fn cross_origin_embedder_policy(mut self, policy: CrossOriginEmbedderPolicy) -> Self {
        self.cross_origin_embedder_policy = Some(policy);
        self
    }

    /// Sets the `Permissions-Policy` header to a raw policy string.
    #[must_use]
    pub fn permissions_policy(mut self, policy: impl Into<String>) -> Self {
        self.permissions_policy = Some(policy.into());
        self
    }

    /// Writes all configured headers into `headers`.
    pub(crate) fn apply(&self, headers: &mut HeaderMap) {
        if self.content_type_options {
            headers.insert(
                header::X_CONTENT_TYPE_OPTIONS,
                HeaderValue::from_static("nosniff"),
            );
        }
        if self.xss_protection {
            headers.insert(
                HeaderName::from_static("x-xss-protection"),
                HeaderValue::from_static("0"),
            );
        }
        if let Some(policy) = &self.frame_options {
            headers.insert(header::X_FRAME_OPTIONS, policy.as_header_value());
        }
        if let Some(policy) = &self.referrer_policy {
            headers.insert(
                HeaderName::from_static("referrer-policy"),
                policy.as_header_value(),
            );
        }
        if let Some(hsts) = &self.hsts
            && let Some(value) = hsts.as_header_value()
        {
            headers.insert(header::STRICT_TRANSPORT_SECURITY, value);
        }
        if let Some(csp) = &self.csp
            && let Ok(value) = HeaderValue::from_str(csp)
        {
            headers.insert(HeaderName::from_static("content-security-policy"), value);
        }
        if let Some(csp) = &self.csp_report_only
            && let Ok(value) = HeaderValue::from_str(csp)
        {
            headers.insert(
                HeaderName::from_static("content-security-policy-report-only"),
                value,
            );
        }
        if let Some(policy) = &self.cross_origin_opener_policy {
            headers.insert(
                HeaderName::from_static("cross-origin-opener-policy"),
                policy.as_header_value(),
            );
        }
        if let Some(policy) = &self.cross_origin_resource_policy {
            headers.insert(
                HeaderName::from_static("cross-origin-resource-policy"),
                policy.as_header_value(),
            );
        }
        if let Some(policy) = &self.cross_origin_embedder_policy {
            headers.insert(
                HeaderName::from_static("cross-origin-embedder-policy"),
                policy.as_header_value(),
            );
        }
        if let Some(policy) = &self.permissions_policy
            && let Ok(value) = HeaderValue::from_str(policy)
        {
            headers.insert(HeaderName::from_static("permissions-policy"), value);
        }
    }
}

// --- Header type enums ---

/// Value for the `X-Frame-Options` header.
///
/// Controls whether the page can be embedded in an `<iframe>`.
#[derive(Clone, Debug)]
pub enum XFrameOptions {
    /// No page may embed this response in a frame.
    Deny,
    /// Only pages from the same origin may embed this response.
    SameOrigin,
}

impl XFrameOptions {
    const fn as_header_value(&self) -> HeaderValue {
        match self {
            Self::Deny => HeaderValue::from_static("DENY"),
            Self::SameOrigin => HeaderValue::from_static("SAMEORIGIN"),
        }
    }
}

/// Value for the `Referrer-Policy` header.
///
/// Controls how much referrer information is included with requests.
#[derive(Clone, Debug)]
pub enum ReferrerPolicy {
    /// `no-referrer`: never send a referrer.
    NoReferrer,
    /// `no-referrer-when-downgrade`: omit the referrer on HTTPS to HTTP navigation.
    NoReferrerWhenDowngrade,
    /// `origin`: send only the origin.
    Origin,
    /// `origin-when-cross-origin`: full URL same-origin, origin only cross-origin.
    OriginWhenCrossOrigin,
    /// `same-origin`: send the referrer only to same-origin requests.
    SameOrigin,
    /// `strict-origin`: origin only, and nothing on HTTPS to HTTP navigation.
    StrictOrigin,
    /// Sends full URL to same-origin, only origin to cross-origin. The recommended default.
    StrictOriginWhenCrossOrigin,
    /// `unsafe-url`: always send the full URL.
    UnsafeUrl,
}

impl ReferrerPolicy {
    const fn as_header_value(&self) -> HeaderValue {
        match self {
            Self::NoReferrer => HeaderValue::from_static("no-referrer"),
            Self::NoReferrerWhenDowngrade => HeaderValue::from_static("no-referrer-when-downgrade"),
            Self::Origin => HeaderValue::from_static("origin"),
            Self::OriginWhenCrossOrigin => HeaderValue::from_static("origin-when-cross-origin"),
            Self::SameOrigin => HeaderValue::from_static("same-origin"),
            Self::StrictOrigin => HeaderValue::from_static("strict-origin"),
            Self::StrictOriginWhenCrossOrigin => {
                HeaderValue::from_static("strict-origin-when-cross-origin")
            }
            Self::UnsafeUrl => HeaderValue::from_static("unsafe-url"),
        }
    }
}

/// Configuration for the `Strict-Transport-Security` header.
///
/// Tells browsers to only connect to this site over HTTPS for a given duration.
///
/// > [!WARNING]
/// > Enable HSTS only when your site is fully served over HTTPS. Setting this
/// > on an HTTP-only site can lock users out.
///
/// # Examples
///
/// ```rust
/// use rune_axum_helmet::Hsts;
///
/// // 2-year HSTS with subdomains, ready for the preload list
/// let hsts = Hsts::new()
///     .max_age(63_072_000)
///     .include_subdomains()
///     .preload();
/// ```
#[derive(Clone, Debug)]
pub struct Hsts {
    max_age_secs: u64,
    include_subdomains: bool,
    preload: bool,
}

impl Default for Hsts {
    fn default() -> Self {
        Self {
            max_age_secs: 31_536_000,
            include_subdomains: false,
            preload: false,
        }
    }
}

impl Hsts {
    /// Creates an `Hsts` value with a one-year max-age and no subdomains or preload.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the `max-age` directive in seconds.
    #[must_use]
    pub const fn max_age(mut self, secs: u64) -> Self {
        self.max_age_secs = secs;
        self
    }

    /// Adds the `includeSubDomains` directive.
    #[must_use]
    pub const fn include_subdomains(mut self) -> Self {
        self.include_subdomains = true;
        self
    }

    /// Adds the `preload` directive (requires `include_subdomains`).
    #[must_use]
    pub const fn preload(mut self) -> Self {
        self.preload = true;
        self
    }

    /// Always `Some`: the value is built from a number and fixed ASCII tokens.
    fn as_header_value(&self) -> Option<HeaderValue> {
        let mut value = format!("max-age={}", self.max_age_secs);
        if self.include_subdomains {
            value.push_str("; includeSubDomains");
        }
        if self.preload {
            value.push_str("; preload");
        }
        HeaderValue::from_str(&value).ok()
    }
}

/// Value for the `Cross-Origin-Opener-Policy` header.
#[derive(Clone, Debug)]
pub enum CrossOriginOpenerPolicy {
    /// Isolates the browsing context exclusively to same-origin documents.
    SameOrigin,
    /// Allows the document to be added to the same browsing context group as
    /// same-origin documents, and cross-origin popups.
    SameOriginAllowPopups,
    /// No isolation. The document may be accessed cross-origin.
    UnsafeNone,
}

impl CrossOriginOpenerPolicy {
    const fn as_header_value(&self) -> HeaderValue {
        match self {
            Self::SameOrigin => HeaderValue::from_static("same-origin"),
            Self::SameOriginAllowPopups => HeaderValue::from_static("same-origin-allow-popups"),
            Self::UnsafeNone => HeaderValue::from_static("unsafe-none"),
        }
    }
}

/// Value for the `Cross-Origin-Resource-Policy` header.
#[derive(Clone, Debug)]
pub enum CrossOriginResourcePolicy {
    /// Only same-origin requests may read the resource.
    SameOrigin,
    /// Only same-site requests may read the resource.
    SameSite,
    /// Any origin may read the resource.
    CrossOrigin,
}

impl CrossOriginResourcePolicy {
    const fn as_header_value(&self) -> HeaderValue {
        match self {
            Self::SameOrigin => HeaderValue::from_static("same-origin"),
            Self::SameSite => HeaderValue::from_static("same-site"),
            Self::CrossOrigin => HeaderValue::from_static("cross-origin"),
        }
    }
}

/// Value for the `Cross-Origin-Embedder-Policy` header.
///
/// Required for `SharedArrayBuffer` and `performance.measureUserAgentSpecificMemory`.
#[derive(Clone, Debug)]
pub enum CrossOriginEmbedderPolicy {
    /// Requires all subresources to opt-in to being loaded cross-origin.
    RequireCorp,
    /// No embedding restrictions.
    UnsafeNone,
}

impl CrossOriginEmbedderPolicy {
    const fn as_header_value(&self) -> HeaderValue {
        match self {
            Self::RequireCorp => HeaderValue::from_static("require-corp"),
            Self::UnsafeNone => HeaderValue::from_static("unsafe-none"),
        }
    }
}

/// Typed builder for a `Content-Security-Policy` header value.
///
/// Constructing a CSP string manually is error-prone. `CspBuilder` lets you
/// specify each directive by name and serialises them into a valid, semicolon-
/// separated policy string via [`CspBuilder::build`].
///
/// Pass the finished builder to [`Helmet::csp_from`] or
/// [`Helmet::report_only_csp_from`].
///
/// # Examples
///
/// ```rust
/// use rune_axum_helmet::CspBuilder;
///
/// let policy = CspBuilder::new()
///     .default_src(&["'self'"])
///     .script_src(&["'self'", "'strict-dynamic'"])
///     .img_src(&["'self'", "data:"])
///     .upgrade_insecure_requests()
///     .build();
///
/// assert!(policy.contains("default-src 'self'"));
/// assert!(policy.contains("upgrade-insecure-requests"));
/// ```
#[derive(Clone, Debug, Default)]
pub struct CspBuilder {
    directives: Vec<String>,
}

impl CspBuilder {
    /// Creates an empty `CspBuilder`.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a `default-src` directive.
    #[must_use]
    pub fn default_src(self, sources: &[&str]) -> Self {
        self.source_directive("default-src", sources)
    }

    /// Adds a `script-src` directive.
    #[must_use]
    pub fn script_src(self, sources: &[&str]) -> Self {
        self.source_directive("script-src", sources)
    }

    /// Adds a `style-src` directive.
    #[must_use]
    pub fn style_src(self, sources: &[&str]) -> Self {
        self.source_directive("style-src", sources)
    }

    /// Adds an `img-src` directive.
    #[must_use]
    pub fn img_src(self, sources: &[&str]) -> Self {
        self.source_directive("img-src", sources)
    }

    /// Adds a `connect-src` directive.
    #[must_use]
    pub fn connect_src(self, sources: &[&str]) -> Self {
        self.source_directive("connect-src", sources)
    }

    /// Adds a `font-src` directive.
    #[must_use]
    pub fn font_src(self, sources: &[&str]) -> Self {
        self.source_directive("font-src", sources)
    }

    /// Adds a `media-src` directive.
    #[must_use]
    pub fn media_src(self, sources: &[&str]) -> Self {
        self.source_directive("media-src", sources)
    }

    /// Adds an `object-src` directive.
    #[must_use]
    pub fn object_src(self, sources: &[&str]) -> Self {
        self.source_directive("object-src", sources)
    }

    /// Adds a `frame-src` directive.
    #[must_use]
    pub fn frame_src(self, sources: &[&str]) -> Self {
        self.source_directive("frame-src", sources)
    }

    /// Adds a `frame-ancestors` directive.
    #[must_use]
    pub fn frame_ancestors(self, sources: &[&str]) -> Self {
        self.source_directive("frame-ancestors", sources)
    }

    /// Adds a `child-src` directive.
    #[must_use]
    pub fn child_src(self, sources: &[&str]) -> Self {
        self.source_directive("child-src", sources)
    }

    /// Adds a `worker-src` directive.
    #[must_use]
    pub fn worker_src(self, sources: &[&str]) -> Self {
        self.source_directive("worker-src", sources)
    }

    /// Adds a `manifest-src` directive.
    #[must_use]
    pub fn manifest_src(self, sources: &[&str]) -> Self {
        self.source_directive("manifest-src", sources)
    }

    /// Adds a `form-action` directive.
    #[must_use]
    pub fn form_action(self, sources: &[&str]) -> Self {
        self.source_directive("form-action", sources)
    }

    /// Adds a `base-uri` directive.
    #[must_use]
    pub fn base_uri(self, sources: &[&str]) -> Self {
        self.source_directive("base-uri", sources)
    }

    /// Adds the `upgrade-insecure-requests` directive.
    #[must_use]
    pub fn upgrade_insecure_requests(mut self) -> Self {
        self.directives
            .push("upgrade-insecure-requests".to_string());
        self
    }

    /// Adds the `block-all-mixed-content` directive.
    ///
    /// > [!NOTE]
    /// > This directive is deprecated in favour of `upgrade-insecure-requests`
    /// > but is still recognised by some browsers.
    #[must_use]
    pub fn block_all_mixed_content(mut self) -> Self {
        self.directives.push("block-all-mixed-content".to_string());
        self
    }

    /// Adds a `report-uri` directive pointing at `uri`.
    ///
    /// > [!NOTE]
    /// > `report-uri` is deprecated in CSP Level 3. Prefer [`CspBuilder::report_to`]
    /// > combined with a `Reporting-Endpoints` header.
    #[must_use]
    pub fn report_uri(mut self, uri: &str) -> Self {
        self.directives.push(format!("report-uri {uri}"));
        self
    }

    /// Adds a `report-to` directive naming a reporting group.
    #[must_use]
    pub fn report_to(mut self, group: &str) -> Self {
        self.directives.push(format!("report-to {group}"));
        self
    }

    /// Serialises all directives into a `Content-Security-Policy` string.
    #[must_use]
    pub fn build(self) -> String {
        self.directives.join("; ")
    }

    fn source_directive(mut self, name: &str, sources: &[&str]) -> Self {
        self.directives
            .push(format!("{name} {}", sources.join(" ")));
        self
    }
}
