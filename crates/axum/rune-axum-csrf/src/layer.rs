use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use http::{
    HeaderMap, HeaderName, HeaderValue, Method, Request, Response, StatusCode,
    header::{CACHE_CONTROL, CONTENT_LENGTH, CONTENT_TYPE, COOKIE, SET_COOKIE},
    request::Parts,
};
use http_body_util::{BodyExt, LengthLimitError, Limited};
use tower::{Layer, Service};

use crate::form;
use crate::origin::{self, Verdict};
use crate::token::{self, CsrfKey};

const HOST_PREFIX: &str = "__Host-";

/// `SameSite` attribute of the CSRF cookie.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum SameSite {
    /// Sent on same-site requests and top-level cross-site `GET` navigations (default).
    #[default]
    Lax,
    /// Sent on same-site requests only. Note that a user arriving from an external
    /// link then has no cookie on the first request, so a fresh token is issued.
    Strict,
}

impl SameSite {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Lax => "Lax",
            Self::Strict => "Strict",
        }
    }
}

type SessionFn = dyn Fn(&Parts) -> Option<String> + Send + Sync;

#[derive(Clone)]
enum SessionSource {
    Cookie(String),
    Custom(Arc<SessionFn>),
}

impl fmt::Debug for SessionSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cookie(name) => f.debug_tuple("Cookie").field(name).finish(),
            Self::Custom(_) => f.write_str("Custom(<fn>)"),
        }
    }
}

/// Configuration for the CSRF protection middleware.
///
/// Build with [`CsrfConfig::new()`] and chain methods, then pass to
/// [`CsrfLayer::new()`]. The defaults are the secure choice; see the crate-level
/// documentation for the protocol.
///
/// The [`Debug`] output never shows the signing key.
///
/// # Examples
///
/// ```rust
/// use std::time::Duration;
/// use rune_axum_csrf::{CsrfConfig, CsrfKey, SameSite};
///
/// # let secret = [0u8; 32];
/// let config = CsrfConfig::new()
///     .key(CsrfKey::from_bytes(&secret).unwrap()) // shared by every instance
///     .session_cookie("session_id")               // bind tokens to the session
///     .same_site(SameSite::Strict)
///     .token_ttl(Duration::from_secs(8 * 3600))
///     .trusted_origin("https://app.example.com")
///     .exempt_prefix("/webhooks/");
/// assert!(!format!("{config:?}").contains("[0, 0"));
/// ```
#[derive(Clone, Debug)]
#[allow(clippy::struct_excessive_bools)] // independent builder switches
pub struct CsrfConfig {
    key: CsrfKey,
    cookie_name: String,
    host_prefix: bool,
    header_name: HeaderName,
    form_field: Option<Arc<str>>,
    max_form_bytes: usize,
    token_bytes: usize,
    status: StatusCode,
    cookie_path: String,
    secure: bool,
    http_only: bool,
    same_site: SameSite,
    ttl: Option<Duration>,
    verify_origin: bool,
    trusted_origins: Vec<String>,
    exempt_paths: Vec<String>,
    exempt_prefixes: Vec<String>,
    session: Option<SessionSource>,
}

impl Default for CsrfConfig {
    fn default() -> Self {
        Self {
            key: CsrfKey::generate(),
            cookie_name: "csrf_token".to_owned(),
            host_prefix: true,
            header_name: HeaderName::from_static("x-csrf-token"),
            form_field: Some(Arc::from("csrf_token")),
            max_form_bytes: 64 * 1024,
            token_bytes: 32,
            status: StatusCode::FORBIDDEN,
            cookie_path: "/".to_owned(),
            secure: true,
            http_only: false,
            same_site: SameSite::Lax,
            ttl: None,
            verify_origin: true,
            trusted_origins: Vec::new(),
            exempt_paths: Vec::new(),
            exempt_prefixes: Vec::new(),
            session: None,
        }
    }
}

impl CsrfConfig {
    /// Creates a `CsrfConfig` with secure defaults: a random per-process signing key,
    /// a 32-byte (256-bit) nonce, the `__Host-csrf_token` cookie (`Secure`,
    /// `Path=/`, `SameSite=Lax`), the `x-csrf-token` header or `csrf_token` form
    /// field, Origin/Referer verification on, and `403 Forbidden` rejections.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the HMAC key that signs tokens.
    ///
    /// Defaults to [`CsrfKey::generate()`], a random key per `CsrfConfig`. Set an
    /// explicit key when several processes serve the same site or tokens must
    /// survive restarts.
    #[must_use]
    pub fn key(mut self, key: CsrfKey) -> Self {
        self.key = key;
        self
    }

    /// Binds every token to the value of the named session cookie (signed
    /// double-submit). A token minted for one session never validates for another,
    /// which defeats cookie tossing from a sibling subdomain.
    #[must_use]
    pub fn session_cookie(mut self, name: impl Into<String>) -> Self {
        self.session = Some(SessionSource::Cookie(name.into()));
        self
    }

    /// Binds every token to a session identifier extracted from the request,
    /// e.g. from an extension set by your session layer. Return `None` for
    /// anonymous requests.
    #[must_use]
    pub fn session_id_with<F>(mut self, f: F) -> Self
    where
        F: Fn(&Parts) -> Option<String> + Send + Sync + 'static,
    {
        self.session = Some(SessionSource::Custom(Arc::new(f)));
        self
    }

    /// Sets the cookie name used to store the CSRF token.
    ///
    /// Defaults to `csrf_token`. While [`host_prefix`](Self::host_prefix) and
    /// [`secure`](Self::secure) are on, the cookie is sent as `__Host-<name>`.
    #[must_use]
    pub fn cookie_name(mut self, name: impl Into<String>) -> Self {
        self.cookie_name = name.into();
        self
    }

    /// Prefixes the cookie name with `__Host-` (default `true`, effective only with
    /// [`secure(true)`](Self::secure)). Browsers then refuse the cookie unless it is
    /// `Secure`, has `Path=/` and no `Domain`, so a subdomain cannot overwrite it.
    /// While the prefix is active the cookie path is always `/`.
    #[must_use]
    pub const fn host_prefix(mut self, enabled: bool) -> Self {
        self.host_prefix = enabled;
        self
    }

    /// Sets the request header name the client must use to echo the token.
    ///
    /// Defaults to `x-csrf-token`.
    #[must_use]
    pub fn header_name(mut self, name: HeaderName) -> Self {
        self.header_name = name;
        self
    }

    /// Sets the `application/x-www-form-urlencoded` field that may carry the
    /// token when the header is absent. Defaults to `csrf_token`.
    #[must_use]
    pub fn form_field(mut self, name: impl Into<String>) -> Self {
        self.form_field = Some(Arc::from(name.into()));
        self
    }

    /// Accepts the token from the header only; request bodies are never read.
    #[must_use]
    pub fn without_form_field(mut self) -> Self {
        self.form_field = None;
        self
    }

    /// Maximum urlencoded body read when looking for the form field
    /// (default 64 KiB). Larger bodies get `413 Payload Too Large`.
    #[must_use]
    pub const fn max_form_bytes(mut self, bytes: usize) -> Self {
        self.max_form_bytes = bytes;
        self
    }

    /// Sets the number of random nonce bytes in each token.
    ///
    /// Clamped to `16..=256` (at least 128 bits). Defaults to `32`.
    #[must_use]
    pub const fn token_bytes(mut self, bytes: usize) -> Self {
        self.token_bytes = bytes;
        self
    }

    /// Sets the HTTP status code returned when CSRF validation fails.
    ///
    /// Defaults to `403 Forbidden`. Oversized form bodies always get `413`.
    #[must_use]
    pub const fn status(mut self, status: StatusCode) -> Self {
        self.status = status;
        self
    }

    /// Sets the `Path` attribute on the CSRF cookie.
    ///
    /// Defaults to `/`. Ignored while the `__Host-` prefix is active.
    #[must_use]
    pub fn cookie_path(mut self, path: impl Into<String>) -> Self {
        self.cookie_path = path.into();
        self
    }

    /// Adds the `Secure` attribute to the CSRF cookie (default `true`).
    ///
    /// Browsers accept `Secure` cookies on `http://localhost`. Turn it off only
    /// for plain-HTTP development on other hosts; this also drops the `__Host-` prefix.
    #[must_use]
    pub const fn secure(mut self, secure: bool) -> Self {
        self.secure = secure;
        self
    }

    /// Adds the `HttpOnly` attribute (default `false`).
    ///
    /// Enable it when tokens reach the client only through server-rendered forms
    /// ([`CsrfToken::hidden_input`]); leave it off for SPAs that read the cookie
    /// from JavaScript to fill the header.
    #[must_use]
    pub const fn http_only(mut self, http_only: bool) -> Self {
        self.http_only = http_only;
        self
    }

    /// Sets the `SameSite` attribute (default [`SameSite::Lax`]).
    #[must_use]
    pub const fn same_site(mut self, same_site: SameSite) -> Self {
        self.same_site = same_site;
        self
    }

    /// Limits token lifetime. Expired tokens are rejected on unsafe requests and
    /// replaced on the next safe one; the cookie gets a matching `Max-Age`.
    /// Default: no expiry (the token lives as long as its session binding).
    #[must_use]
    pub const fn token_ttl(mut self, ttl: Duration) -> Self {
        self.ttl = Some(ttl);
        self
    }

    /// Checks `Origin` / `Sec-Fetch-Site` / `Referer` on unsafe requests as
    /// defense in depth (default `true`). A request whose source is another origin
    /// is rejected even with a valid token.
    #[must_use]
    pub const fn verify_origin(mut self, enabled: bool) -> Self {
        self.verify_origin = enabled;
        self
    }

    /// Accepts unsafe requests from this extra origin (`scheme://host[:port]`),
    /// e.g. a separate front-end host or the public origin behind a proxy that
    /// rewrites `Host`. Malformed values are ignored (fail closed).
    #[must_use]
    pub fn trusted_origin(mut self, origin: impl AsRef<str>) -> Self {
        if let Some(o) = origin::normalize_origin(origin.as_ref()) {
            self.trusted_origins.push(o);
        }
        self
    }

    /// Skips CSRF handling entirely for this exact path (e.g. a signed webhook).
    /// Paths are matched as the layer sees them, i.e. relative to any `nest`.
    #[must_use]
    pub fn exempt_path(mut self, path: impl Into<String>) -> Self {
        self.exempt_paths.push(path.into());
        self
    }

    /// Skips CSRF handling for every path starting with `prefix`
    /// (e.g. `/webhooks/`). Include the trailing slash to stop at a segment boundary.
    #[must_use]
    pub fn exempt_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.exempt_prefixes.push(prefix.into());
        self
    }

    fn is_exempt(&self, path: &str) -> bool {
        self.exempt_paths.iter().any(|p| p == path)
            || self
                .exempt_prefixes
                .iter()
                .any(|p| path.starts_with(p.as_str()))
    }

    const fn prefixed(&self) -> bool {
        self.host_prefix && self.secure
    }

    fn effective_cookie_name(&self) -> String {
        if self.prefixed() && !self.cookie_name.starts_with(HOST_PREFIX) {
            format!("{HOST_PREFIX}{}", self.cookie_name)
        } else {
            self.cookie_name.clone()
        }
    }

    fn session_id(&self, parts: &Parts) -> Vec<u8> {
        match &self.session {
            None => Vec::new(),
            Some(SessionSource::Cookie(name)) => cookie_values(&parts.headers, name)
                .next()
                .map(|v| v.as_bytes().to_vec())
                .unwrap_or_default(),
            Some(SessionSource::Custom(f)) => f(parts).map(String::into_bytes).unwrap_or_default(),
        }
    }

    /// `None` if the cookie name or path is not header-safe; no cookie is then set,
    /// so unsafe requests keep failing (fail closed).
    fn set_cookie_value(&self, name: &str, token: &str) -> Option<HeaderValue> {
        let path = if self.prefixed() {
            "/"
        } else {
            self.cookie_path.as_str()
        };
        let mut cookie = format!(
            "{name}={token}; Path={path}; SameSite={}",
            self.same_site.as_str()
        );
        if self.secure {
            cookie.push_str("; Secure");
        }
        if self.http_only {
            cookie.push_str("; HttpOnly");
        }
        if let Some(ttl) = self.ttl {
            cookie.push_str("; Max-Age=");
            cookie.push_str(&ttl.as_secs().to_string());
        }
        HeaderValue::from_str(&cookie).ok()
    }

    fn make_token(&self, value: String) -> CsrfToken {
        CsrfToken {
            value,
            header: self.header_name.clone(),
            field: self.form_field.clone(),
        }
    }
}

/// Iterates over every value of cookie `name` across all `Cookie` headers.
/// Duplicates matter: a tossed cookie from a subdomain arrives alongside ours.
fn cookie_values<'a>(headers: &'a HeaderMap, name: &'a str) -> impl Iterator<Item = &'a str> {
    headers
        .get_all(COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|c| c.split(';'))
        .filter_map(move |part| {
            let (n, v) = part.trim().split_once('=')?;
            (n.trim() == name).then(|| v.trim())
        })
}

/// The current CSRF token, inserted into request extensions for handlers.
///
/// Extract it with `axum::Extension<CsrfToken>` to embed in a form or page.
/// The [`Debug`] output is redacted.
///
/// # Examples
///
/// ```rust
/// use axum::{Extension, response::Html};
/// use rune_axum_csrf::CsrfToken;
///
/// async fn form(Extension(token): Extension<CsrfToken>) -> Html<String> {
///     Html(format!(
///         r#"<form method="post">{}<button>Send</button></form>"#,
///         token.hidden_input().unwrap_or_default()
///     ))
/// }
/// ```
#[derive(Clone)]
pub struct CsrfToken {
    value: String,
    header: HeaderName,
    field: Option<Arc<str>>,
}

impl CsrfToken {
    /// The token value to send back in the header or form field.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.value
    }

    /// The header that carries the token (`x-csrf-token` by default).
    #[must_use]
    pub const fn header_name(&self) -> &HeaderName {
        &self.header
    }

    /// The form field that carries the token, if form submission is enabled.
    #[must_use]
    pub fn field_name(&self) -> Option<&str> {
        self.field.as_deref()
    }

    /// An HTML `<input type="hidden">` carrying the token, if form submission is enabled.
    #[must_use]
    pub fn hidden_input(&self) -> Option<String> {
        let field = self.field.as_deref()?;
        let mut name = String::with_capacity(field.len());
        for c in field.chars() {
            match c {
                '&' => name.push_str("&amp;"),
                '<' => name.push_str("&lt;"),
                '>' => name.push_str("&gt;"),
                '"' => name.push_str("&quot;"),
                '\'' => name.push_str("&#39;"),
                c => name.push(c),
            }
        }
        // Token values are `[0-9a-f.]` only: no escaping needed.
        Some(format!(
            r#"<input type="hidden" name="{name}" value="{}">"#,
            self.value
        ))
    }
}

impl fmt::Debug for CsrfToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CsrfToken")
            .field("value", &"[redacted]")
            .field("header", &self.header)
            .field("field", &self.field)
            .finish()
    }
}

/// Insert into a **response**'s extensions to rotate the token: the middleware
/// issues a fresh token cookie with that response. Do this after login, logout
/// or privilege changes.
///
/// # Examples
///
/// ```rust
/// use axum::response::{IntoResponse, Redirect};
/// use rune_axum_csrf::CsrfRotate;
///
/// async fn login() -> impl IntoResponse {
///     // ... authenticate, set the session cookie ...
///     let mut res = Redirect::to("/").into_response();
///     res.extensions_mut().insert(CsrfRotate);
///     res
/// }
/// ```
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CsrfRotate;

/// Why a request was rejected. Attached to the rejection **response**'s
/// extensions for logging and metrics; never written to the response body.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum CsrfRejection {
    /// `Origin`, `Referer` or `Sec-Fetch-Site` shows a cross-origin source.
    CrossOrigin,
    /// No CSRF cookie was sent.
    MissingCookie,
    /// The CSRF cookie has a bad signature, another session's binding, or expired.
    InvalidCookie,
    /// Neither the header nor the form field carried a token.
    MissingToken,
    /// The submitted token does not match the cookie.
    TokenMismatch,
    /// The urlencoded body exceeded [`CsrfConfig::max_form_bytes`].
    BodyTooLarge,
    /// The request body could not be read.
    BodyError,
}

impl fmt::Display for CsrfRejection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::CrossOrigin => "cross-origin request",
            Self::MissingCookie => "missing CSRF cookie",
            Self::InvalidCookie => "invalid or expired CSRF cookie",
            Self::MissingToken => "missing CSRF token",
            Self::TokenMismatch => "CSRF token mismatch",
            Self::BodyTooLarge => "form body too large",
            Self::BodyError => "unreadable request body",
        })
    }
}

/// Tower [`Layer`] that implements the signed double-submit cookie pattern.
///
/// Apply with Axum's `.layer()` call. Use [`CsrfLayer::default()`] for secure
/// defaults or [`CsrfLayer::new()`] to supply a custom [`CsrfConfig`].
///
/// # Examples
///
/// ```rust,no_run
/// use axum::{routing::post, Router};
/// use rune_axum_csrf::CsrfLayer;
///
/// let app: Router = Router::new()
///     .route("/submit", post(|| async { "ok" }))
///     .layer(CsrfLayer::default());
/// ```
#[derive(Clone, Debug, Default)]
pub struct CsrfLayer {
    config: Arc<CsrfConfig>,
}

impl CsrfLayer {
    /// Creates a `CsrfLayer` from a custom [`CsrfConfig`].
    #[must_use]
    pub fn new(config: CsrfConfig) -> Self {
        Self {
            config: Arc::new(config),
        }
    }
}

impl<S> Layer<S> for CsrfLayer {
    type Service = CsrfService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        CsrfService {
            inner,
            config: Arc::clone(&self.config),
        }
    }
}

/// Tower [`Service`] produced by [`CsrfLayer`].
#[derive(Clone, Debug)]
pub struct CsrfService<S> {
    inner: S,
    config: Arc<CsrfConfig>,
}

const fn is_safe_method(method: &Method) -> bool {
    matches!(
        *method,
        Method::GET | Method::HEAD | Method::OPTIONS | Method::TRACE
    )
}

fn reject<B: Default>(status: StatusCode, reason: CsrfRejection) -> Response<B> {
    let mut response = Response::new(B::default());
    *response.status_mut() = if reason == CsrfRejection::BodyTooLarge {
        StatusCode::PAYLOAD_TOO_LARGE
    } else {
        status
    };
    response
        .headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response.extensions_mut().insert(reason);
    response
}

type BoxError = Box<dyn std::error::Error + Send + Sync>;

impl<S, ReqBody, ResBody> Service<Request<ReqBody>> for CsrfService<S>
where
    S: Service<Request<ReqBody>, Response = Response<ResBody>> + Clone + Send + 'static,
    S::Future: Send + 'static,
    S::Error: Send + 'static,
    ReqBody: http_body::Body + From<Bytes> + Send + 'static,
    ReqBody::Data: Send,
    ReqBody::Error: Into<BoxError>,
    ResBody: Default + Send + 'static,
{
    type Response = Response<ResBody>;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<ReqBody>) -> Self::Future {
        // Drive the instance that was polled ready; leave a fresh clone behind.
        let clone = self.inner.clone();
        let inner = std::mem::replace(&mut self.inner, clone);
        Box::pin(handle(Arc::clone(&self.config), inner, req))
    }
}

async fn handle<S, ReqBody, ResBody>(
    config: Arc<CsrfConfig>,
    mut inner: S,
    req: Request<ReqBody>,
) -> Result<Response<ResBody>, S::Error>
where
    S: Service<Request<ReqBody>, Response = Response<ResBody>>,
    ReqBody: http_body::Body + From<Bytes>,
    ReqBody::Error: Into<BoxError>,
    ResBody: Default,
{
    let (mut parts, body) = req.into_parts();
    if config.is_exempt(parts.uri.path()) {
        return inner.call(Request::from_parts(parts, body)).await;
    }

    let session = config.session_id(&parts);
    let now = token::now_secs();
    let cookie_name = config.effective_cookie_name();
    let mut saw_cookie = false;
    let valid: Vec<String> = cookie_values(&parts.headers, &cookie_name)
        .inspect(|_| saw_cookie = true)
        .filter(|t| token::verify(&config.key, &session, t, now, config.ttl).is_ok())
        .map(str::to_owned)
        .collect();
    let issue = || token::issue(&config.key, &session, config.token_bytes, now);

    if is_safe_method(&parts.method) {
        let (current, fresh) = valid
            .into_iter()
            .next()
            .map_or_else(|| (issue(), true), |t| (Some(t), false));
        if let Some(t) = &current {
            parts.extensions.insert(config.make_token(t.clone()));
        }
        let response = inner.call(Request::from_parts(parts, body)).await?;
        let to_set = if fresh { current } else { None };
        return Ok(finish(&config, &cookie_name, response, to_set, issue));
    }

    if config.verify_origin
        && origin::check(&parts.headers, &parts.uri, &config.trusted_origins)
            == Verdict::CrossOrigin
    {
        return Ok(reject(config.status, CsrfRejection::CrossOrigin));
    }
    if valid.is_empty() {
        let reason = if saw_cookie {
            CsrfRejection::InvalidCookie
        } else {
            CsrfRejection::MissingCookie
        };
        return Ok(reject(config.status, reason));
    }

    let mut submitted = parts
        .headers
        .get(&config.header_name)
        .map(|v| v.to_str().unwrap_or_default().to_owned());
    let mut body = body;
    if submitted.is_none()
        && let Some(field) = &config.form_field
        && parts
            .headers
            .get(CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .is_some_and(form::is_urlencoded)
    {
        let declared = parts
            .headers
            .get(CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok());
        if declared.is_some_and(|n| n > config.max_form_bytes as u64) {
            return Ok(reject(config.status, CsrfRejection::BodyTooLarge));
        }
        let bytes = match Limited::new(body, config.max_form_bytes).collect().await {
            Ok(collected) => collected.to_bytes(),
            Err(e) if e.is::<LengthLimitError>() => {
                return Ok(reject(config.status, CsrfRejection::BodyTooLarge));
            }
            Err(_) => return Ok(reject(config.status, CsrfRejection::BodyError)),
        };
        submitted = form::find_field(&bytes, field);
        body = ReqBody::from(bytes);
    }

    let Some(submitted) = submitted else {
        return Ok(reject(config.status, CsrfRejection::MissingToken));
    };
    // Compare against every valid cookie without short-circuiting.
    let matched = valid
        .iter()
        .fold(false, |acc, v| acc | token::ct_eq(v, &submitted));
    if !matched {
        return Ok(reject(config.status, CsrfRejection::TokenMismatch));
    }

    parts.extensions.insert(config.make_token(submitted));
    let response = inner.call(Request::from_parts(parts, body)).await?;
    Ok(finish(&config, &cookie_name, response, None, issue))
}

/// Appends `Set-Cookie` for a fresh token, or for a rotated one when the handler
/// asked for it with [`CsrfRotate`]. Appending keeps the handler's own cookies.
fn finish<B>(
    config: &CsrfConfig,
    cookie_name: &str,
    mut response: Response<B>,
    fresh: Option<String>,
    issue: impl FnOnce() -> Option<String>,
) -> Response<B> {
    let token = if response.extensions_mut().remove::<CsrfRotate>().is_some() {
        issue()
    } else {
        fresh
    };
    if let Some(value) = token.and_then(|t| config.set_cookie_value(cookie_name, &t)) {
        response.headers_mut().append(SET_COOKIE, value);
    }
    response
}
