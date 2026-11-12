//! All-in-one middleware stack for Axum.
//!
//! Composes up to sixteen [`tower::Layer`]s from the `rune-axum-*` and `rune-tower-*`
//! families into a single [`SecurityStack::apply`] call: request ids, health probes,
//! compression, problem details, security headers, HTTPS redirect, CORS, IP filtering,
//! rate limiting, concurrency limiting, circuit breaking, timeouts, body size limiting,
//! CSRF protection, retries with hedging, and HTTP caching (`Cache-Control` plus
//! `304`/`412` conditional requests).
//! Every layer is individually configurable or removable via builder methods, and
//! the stack always applies them in one fixed, documented order (see
//! [Layer order](#layer-order)).
//!
//! Re-exports the configuration types from each component crate — you only need
//! `rune-axum-stack` in `[dependencies]`.
//!
//! > [!IMPORTANT]
//! > The rate limiter (on by default) and the IP filter key on the socket peer address.
//! > Serve the router with `into_make_service_with_connect_info::<SocketAddr>()`, or
//! > they answer `500`. Behind a reverse proxy, configure a [`ClientIpConfig`] with the
//! > proxy's addresses as trusted.
//!
//! # Default stack
//!
//! [`SecurityStack::default()`] enables six layers with safe defaults:
//!
//! | Layer | Default |
//! |-------|---------|
//! | [`HelmetLayer`] | Standard security headers plus HSTS (one year, no `includeSubDomains`); CSP is opt-in |
//! | [`RedirectHttpsLayer`] | 308 permanent redirect for HTTP requests |
//! | [`RateLimitLayer`] | 100 requests per 60 s keyed by the socket peer IP (`ConnectInfo<SocketAddr>`) |
//! | [`TimeoutLayer`] | 30 s per request (`504`), bounding body reads, CSRF and the handler |
//! | [`BodyLimitLayer`] | 1 MiB `Content-Length` limit |
//! | [`CsrfLayer`] | HMAC-signed double-submit `__Host-` cookie plus `Origin` / `Sec-Fetch-Site` checks on every non-safe method |
//!
//! The default CSRF signing key is random per stack. Set one with
//! [`.csrf_key()`][SecurityStack::csrf_key] when several processes serve the same
//! site or tokens must survive restarts, and bind tokens to the session with
//! [`.csrf_session_cookie()`][SecurityStack::csrf_session_cookie] whenever the app
//! has sessions. The CSRF cookie is `Secure`: browsers accept it on `https://` and
//! `http://localhost` only.
//!
//! Every other layer is opt-in, because each needs a decision only the application
//! can make:
//!
//! | Builder | Layer | Why it is opt-in |
//! |---------|-------|------------------|
//! | [`.request_id()`][SecurityStack::request_id] | [`RequestIdLayer`] | Header name and whether to trust incoming ids depend on the proxy chain |
//! | [`.health()`][SecurityStack::health] | [`HealthLayer`] | Needs the [`HealthState`] your graceful-shutdown code shares |
//! | [`.compression()`][SecurityStack::compression] | [`CompressionLayer`] | Often done by the reverse proxy; compressing secrets next to attacker input is a BREACH risk |
//! | [`.problem()`][SecurityStack::problem] | [`ProblemLayer`] | Changes the error body format clients see |
//! | [`.cors()`][SecurityStack::cors] | [`CorsLayer`] | Needs the allowed origins |
//! | [`.ipfilter()`][SecurityStack::ipfilter] | [`IpFilterLayer`] | Needs CIDR ranges |
//! | [`.concurrency()`][SecurityStack::concurrency] | [`ConcurrencyLimitLayer`] | The right in-flight budget depends on the deployment |
//! | [`.circuit_breaker()`][SecurityStack::circuit_breaker] | [`CircuitBreakerLayer`] | Thresholds depend on the handlers' normal error rate and latency |
//! | [`.retry()`][SecurityStack::retry] | [`RetryLayer`] | Only safe when idempotent handlers really are idempotent; retries and hedges multiply handler work |
//! | [`.cache()`][SecurityStack::cache] | [`CacheLayer`] | Caching policy is per application and per path |
//!
//! # Layer order
//!
//! Requests pass through the enabled layers from top to bottom; responses travel
//! back up. Order matters: a layer only sees, and can only decorate, the responses
//! produced *below* it.
//!
//! | # | Layer | Why here |
//! |---|-------|----------|
//! | 1 | `request_id` | Outermost, so every response — probe answers and every rejection included — carries the id, and its tracing span covers the whole stack. |
//! | 2 | `health` | Probes are answered before the HTTPS redirect, IP filter and rate / concurrency limits, so orchestrator probes over plain HTTP from node addresses always get through and never spend a client's budget. Every other request is counted as in flight for graceful-shutdown draining. Readiness `503`s stay bare (no problem details). |
//! | 3 | `compression` | Compresses whatever the inner layers produce, problem documents included. |
//! | 4 | `problem` | Turns the bare `4xx`/`5xx` statuses of every layer below (`403`, `413`, `429`, `503`, `504`, refused preflights) into `application/problem+json`. It keeps the response headers, so `Retry-After`, `Access-Control-*` and the security headers survive. |
//! | 5 | `helmet` | Security headers on every response below, rejections included. |
//! | 6 | `redirect_https` | Plain-HTTP requests are redirected before any policy decision. |
//! | 7 | `cors` | Before the rejecting layers: preflights are answered (`204`/`403`) without reaching CSRF, the IP filter or the rate limiter, and `403`/`429`/`503`/`504` responses carry `Access-Control-Allow-Origin` so the browser app can read them. |
//! | 8 | `ipfilter` | Cheapest rejection: a single address check. |
//! | 9 | `ratelimit` | Per-client fairness before the global budget, so a client over its limit gets `429` and never occupies an in-flight slot. |
//! | 10 | `concurrency` | Sheds load (`503`) for admitted requests only; outside `timeout`, so a slot is held at most for the timeout. One slot per request, whatever the retries and hedges below. |
//! | 11 | `circuit_breaker` | Inside `concurrency`, so shed, rate-limited and filtered requests never count as outcomes. Outside `timeout`, so a `504` counts as a failure and the slow-call clock covers the whole budget. Outside `retry`, so it records one outcome per request, after retries. An open circuit fails fast with `503` + `Retry-After` before any body is read or the handler runs; `problem` above turns it into a problem document. Only errors and `5xx` count as failures. |
//! | 12 | `timeout` | Bounds the time spent in the body limit, CSRF check, retries (backoffs and hedges included) and handler (`504`). |
//! | 13 | `body_limit` | Rejects oversized bodies (`413`) before CSRF reads the request. |
//! | 14 | `csrf` | Closest to the handler it protects. |
//! | 15 | `retry` | Below every rejecting layer, so only admitted requests are retried and `4xx` rejections never are. Retries `502`/`503`/`504` from the handler, for idempotent methods with an empty body only (a streamed request body cannot be replayed). |
//! | 16 | `cache` | Innermost: `Cache-Control` and `304`/`412` decisions use the validators (`ETag`, `Last-Modified`) of the handler's own, uncompressed representation; empty `304`s skip compression, `412`s become problem details, and both still get CORS and security headers from the layers above. It only touches successful `GET`/`HEAD` responses, so rejections from other layers are never cached. Avoid `public` directives on pages that receive the CSRF cookie. |
//!
//! # Features
//!
//! - `br`, `zstd`: offer those encodings in the compression layer (gzip and deflate
//!   are always available).
//! - `signal`: re-export [`shutdown_signal`] (Ctrl-C / `SIGTERM`).
//!
//! # Quick Start
//!
//! ```rust
//! use axum::{routing::get, Router};
//! use rune_axum_stack::SecurityStack;
//!
//! let app: Router = SecurityStack::default().apply(
//!     Router::new().route("/", get(|| async { "ok" })),
//! );
//! ```
//!
//! # Custom Configuration
//!
//! ```rust
//! use std::time::Duration;
//! use axum::{routing::get, Router};
//! use rune_axum_stack::{
//!     FilterMode, Helmet, Hsts, IpFilterConfig, RateLimitConfig, SecurityStack, XFrameOptions,
//! };
//!
//! let app: Router = SecurityStack::new()
//!     .helmet(Helmet::new().frame_options(XFrameOptions::Deny).hsts(Hsts::new()))
//!     .ratelimit(RateLimitConfig::new().requests(200).window(Duration::from_secs(30)))
//!     .ipfilter(IpFilterConfig::new().mode(FilterMode::Blocklist).cidr("10.0.0.0/8")?)
//!     .without_csrf()
//!     .apply(Router::new().route("/", get(|| async { "ok" })));
//! # Ok::<(), rune_axum_stack::CidrParseError>(())
//! ```
//!
//! # Server-rendered forms
//!
//! ```rust
//! use axum::{Extension, response::Html, routing::get, Router};
//! use rune_axum_stack::{CsrfKey, CsrfToken, SecurityStack};
//!
//! # fn load_secret() -> Vec<u8> { vec![7u8; 32] }
//! async fn form(Extension(token): Extension<CsrfToken>) -> Html<String> {
//!     Html(format!(
//!         r#"<form method="post" action="/transfer">{}</form>"#,
//!         token.hidden_input().unwrap_or_default()
//!     ))
//! }
//!
//! let app: Router = SecurityStack::new()
//!     .csrf_key(CsrfKey::from_bytes(&load_secret())?) // shared by every instance
//!     .csrf_session_cookie("session_id")
//!     .csrf_trusted_origin("https://www.example.com")
//!     .csrf_exempt_prefix("/webhooks/") // verified by their own signatures
//!     .apply(Router::new().route("/transfer", get(form).post(|| async { "done" })));
//! # Ok::<(), rune_axum_stack::KeyTooShort>(())
//! ```
//!
//! # Production API
//!
//! ```rust
//! use std::time::Duration;
//! use axum::{routing::get, Router};
//! use rune_axum_stack::{
//!     CircuitBreaker, Compression, ConcurrencyLimit, Cors, HealthState, Problems,
//!     RequestIdConfig, Retry, SecurityStack, Timeout,
//! };
//!
//! let health = HealthState::new(); // share with `HealthState::graceful_shutdown`
//! let app: Router = SecurityStack::new()
//!     .without_csrf() // bearer-token API
//!     .request_id(RequestIdConfig::default())
//!     .health(health.clone())
//!     .compression(Compression::new())
//!     .problem(Problems::new())
//!     .cors(Cors::new().allow_origin("https://app.example.com"))?
//!     .concurrency(ConcurrencyLimit::new().max_in_flight(512))
//!     .circuit_breaker(CircuitBreaker::new().open_duration(Duration::from_secs(15)))
//!     .timeout(Timeout::new().duration(Duration::from_secs(10)))
//!     .retry(Retry::new().max_attempts(2))
//!     .apply(Router::new().route("/api/items", get(|| async { "[]" })));
//! # Ok::<(), rune_axum_stack::CorsError>(())
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub use rune_axum_cache::{
    Cache, CacheControl, CacheLayer, EntityTag, HttpDate, Precondition, Validators,
};
pub use rune_axum_compression::{Compression, CompressionLayer, Encoding, Level};
pub use rune_axum_concurrency::{ConcurrencyLimit, ConcurrencyLimitLayer, Limiter, Metrics};
pub use rune_axum_cors::{Cors, CorsLayer, Error as CorsError, Severity, WeaknessKind};
pub use rune_axum_csrf::{
    CsrfConfig, CsrfKey, CsrfLayer, CsrfRejection, CsrfRotate, CsrfService, CsrfToken, KeyTooShort,
    SameSite,
};
#[cfg(feature = "signal")]
pub use rune_axum_health::shutdown_signal;
pub use rune_axum_health::{Error as HealthError, Health, HealthLayer, HealthState, Probe};
pub use rune_axum_helmet::{
    CrossOriginEmbedderPolicy, CrossOriginOpenerPolicy, CrossOriginResourcePolicy, CspBuilder,
    Helmet, HelmetLayer, Hsts, ReferrerPolicy, XFrameOptions,
};
pub use rune_axum_ipfilter::{
    CidrParseError, ClientIpConfig, FilterMode, IpFilterConfig, IpFilterLayer, IpFilterService,
    ProxyHeader,
};
pub use rune_axum_problem::{IntoProblem, Problem, ProblemLayer, Problems};
pub use rune_axum_ratelimit::{
    Algorithm as RateLimitAlgorithm, KeyExtractor, MissingIp, RateLimitConfig, RateLimitLayer,
    RateLimitService,
};
pub use rune_axum_redirect_https::{RedirectHttps, RedirectHttpsLayer};
pub use rune_axum_requestid::{
    RequestId, RequestIdConfig, RequestIdLayer, TraceContext, TraceParent, X_REQUEST_ID,
};
pub use rune_axum_size::{BodyLimit, BodyLimitLayer, BodyLimitService};
pub use rune_axum_timeout::{Timeout, TimeoutLayer};
pub use rune_tower_circuitbreaker::{
    CircuitBreaker, CircuitBreakerLayer, CircuitHandle, ServerErrors, Snapshot as CircuitSnapshot,
    State as CircuitState,
};
pub use rune_tower_retry::{
    Backoff, Hedge, IdempotentBodiless, Jitter, Retry, RetryBudget, RetryHandle, RetryLayer,
    Stats as RetryStats, TransientHttp,
};

use std::convert::Infallible;

use axum::error_handling::HandleErrorLayer;
use axum::response::{IntoResponse, Response};

/// The circuit-breaker layer as the stack applies it: errors and `5xx` count as
/// failures.
pub type StackCircuitBreakerLayer = CircuitBreakerLayer<ServerErrors>;

/// The retry layer as the stack applies it: `502`/`503`/`504` are retried, for
/// idempotent requests with an empty body.
pub type StackRetryLayer = RetryLayer<TransientHttp, IdempotentBodiless>;

/// Composable middleware stack for Axum.
///
/// Holds an optional configuration for each supported layer. Layers set to `None` are
/// skipped in [`apply`][SecurityStack::apply]. Start from [`SecurityStack::default()`]
/// for safe production defaults, or [`SecurityStack::new()`] for the same starting point
/// and chain builder methods to enable, customise or disable individual layers.
///
/// # Layer application order
///
/// Whatever order the builder methods are called in, enabled layers always run
/// outermost-first in this order (rationale in the [crate docs](crate#layer-order)):
///
/// `request_id` → `health` → `compression` → `problem` → `helmet` → `redirect_https`
/// → `cors` → `ipfilter` → `ratelimit` → `concurrency` → `circuit_breaker` → `timeout`
/// → `body_limit` → `csrf` → `retry` → `cache` → handler
///
/// # Examples
///
/// ```rust,no_run
/// use axum::{routing::get, Router};
/// use rune_axum_stack::SecurityStack;
///
/// // Six-layer default stack
/// let app: Router = SecurityStack::default().apply(
///     Router::new().route("/api", get(|| async { "ok" })),
/// );
/// ```
///
/// ```rust,no_run
/// use axum::{routing::post, Router};
/// use rune_axum_stack::SecurityStack;
///
/// // REST API: no CSRF, no HTTPS redirect (TLS terminated upstream)
/// let app: Router = SecurityStack::new()
///     .without_csrf()
///     .without_redirect_https()
///     .apply(Router::new().route("/api/data", post(|| async { "ok" })));
/// ```
#[derive(Clone, Debug)]
pub struct SecurityStack {
    request_id: Option<RequestIdConfig>,
    health: Option<HealthLayer>,
    compression: Option<Compression>,
    problem: Option<Problems>,
    helmet: Option<Helmet>,
    redirect_https: Option<RedirectHttps>,
    cors: Option<CorsLayer>,
    ipfilter: Option<IpFilterConfig>,
    ratelimit: Option<RateLimitConfig>,
    concurrency: Option<ConcurrencyLimitLayer>,
    circuit_breaker: Option<StackCircuitBreakerLayer>,
    timeout: Option<Timeout>,
    body_limit: Option<BodyLimit>,
    csrf: Option<CsrfConfig>,
    retry: Option<StackRetryLayer>,
    cache: Option<Cache>,
}

impl Default for SecurityStack {
    fn default() -> Self {
        Self {
            request_id: None,
            health: None,
            compression: None,
            problem: None,
            // The stack redirects to HTTPS and sets `Secure` cookies by default, so
            // pin browsers to HTTPS as well.
            helmet: Some(Helmet::new().hsts(Hsts::new())),
            redirect_https: Some(RedirectHttps::new()),
            cors: None,
            ipfilter: None,
            ratelimit: Some(RateLimitConfig::new()),
            concurrency: None,
            circuit_breaker: None,
            timeout: Some(Timeout::new()),
            body_limit: Some(BodyLimit::new()),
            csrf: Some(CsrfConfig::new()),
            retry: None,
            cache: None,
        }
    }
}

impl SecurityStack {
    /// Creates a `SecurityStack` with the same safe defaults as [`Default`].
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use axum::{routing::get, Router};
    /// use rune_axum_stack::SecurityStack;
    ///
    /// let app: Router = SecurityStack::new()
    ///     .without_csrf()
    ///     .apply(Router::new().route("/", get(|| async { "ok" })));
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Enables the [`RequestIdLayer`] (outermost layer) with `config`.
    ///
    /// Every response then carries the request id header, and handlers can extract
    /// [`RequestId`] and [`TraceContext`].
    #[must_use]
    pub fn request_id(mut self, config: RequestIdConfig) -> Self {
        self.request_id = Some(config);
        self
    }

    /// Removes the [`RequestIdLayer`] from the stack (the default state).
    #[must_use]
    pub fn without_request_id(mut self) -> Self {
        self.request_id = None;
        self
    }

    /// Enables the [`HealthLayer`] with the default probe paths (`/livez`, `/readyz`).
    ///
    /// Pass a clone of the [`HealthState`] that drives graceful shutdown, so that
    /// readiness flips and in-flight requests are counted on the same state.
    #[must_use]
    pub fn health(self, state: HealthState) -> Self {
        self.health_with(Health::new(), state)
    }

    /// Enables the [`HealthLayer`] with custom probe paths.
    #[must_use]
    pub fn health_with(mut self, config: Health, state: HealthState) -> Self {
        self.health = Some(HealthLayer::with_config(config, state));
        self
    }

    /// Removes the [`HealthLayer`] from the stack (the default state).
    #[must_use]
    pub fn without_health(mut self) -> Self {
        self.health = None;
        self
    }

    /// Enables the [`CompressionLayer`] with `config`.
    ///
    /// Avoid compressing responses that mix secrets with attacker-controlled input
    /// (BREACH), or leave compression to the reverse proxy.
    #[must_use]
    pub fn compression(mut self, config: Compression) -> Self {
        self.compression = Some(config);
        self
    }

    /// Removes the [`CompressionLayer`] from the stack (the default state).
    #[must_use]
    pub fn without_compression(mut self) -> Self {
        self.compression = None;
        self
    }

    /// Enables the [`ProblemLayer`]: bare error statuses from the layers below it and
    /// from handlers become RFC 9457 `application/problem+json` responses.
    #[must_use]
    pub fn problem(mut self, config: Problems) -> Self {
        self.problem = Some(config);
        self
    }

    /// Removes the [`ProblemLayer`] from the stack (the default state).
    #[must_use]
    pub fn without_problem(mut self) -> Self {
        self.problem = None;
        self
    }

    /// Replaces the [`HelmetLayer`] configuration.
    ///
    /// The default is `Helmet::new().hsts(Hsts::new())`; a plain [`Helmet::new()`]
    /// drops `Strict-Transport-Security`.
    #[must_use]
    pub fn helmet(mut self, config: Helmet) -> Self {
        self.helmet = Some(config);
        self
    }

    /// Removes the [`HelmetLayer`] from the stack.
    #[must_use]
    pub fn without_helmet(mut self) -> Self {
        self.helmet = None;
        self
    }

    /// Replaces the [`RedirectHttpsLayer`] configuration.
    #[must_use]
    pub const fn redirect_https(mut self, config: RedirectHttps) -> Self {
        self.redirect_https = Some(config);
        self
    }

    /// Removes the [`RedirectHttpsLayer`] from the stack.
    ///
    /// Suitable when TLS is terminated by an upstream proxy that never forwards
    /// plain HTTP to the application.
    #[must_use]
    pub const fn without_redirect_https(mut self) -> Self {
        self.redirect_https = None;
        self
    }

    /// Enables the [`CorsLayer`] with `config`.
    ///
    /// The policy is audited by `rune-cors` here, at build time.
    ///
    /// # Errors
    ///
    /// Returns [`CorsError`] when an origin is malformed or the policy is rated
    /// insecure (see [`CorsLayer::new`]).
    pub fn cors(mut self, config: Cors) -> Result<Self, CorsError> {
        self.cors = Some(CorsLayer::new(config)?);
        Ok(self)
    }

    /// Enables an already-built [`CorsLayer`], e.g. one whose
    /// [`report`][CorsLayer::report] you want to log.
    #[must_use]
    pub fn cors_layer(mut self, layer: CorsLayer) -> Self {
        self.cors = Some(layer);
        self
    }

    /// Removes the [`CorsLayer`] from the stack (the default state).
    #[must_use]
    pub fn without_cors(mut self) -> Self {
        self.cors = None;
        self
    }

    /// Enables IP filtering with the given [`IpFilterConfig`].
    ///
    /// IP filtering is disabled by default; call this to opt in.
    #[must_use]
    pub fn ipfilter(mut self, config: IpFilterConfig) -> Self {
        self.ipfilter = Some(config);
        self
    }

    /// Removes the [`IpFilterLayer`] from the stack (the default state).
    #[must_use]
    pub fn without_ipfilter(mut self) -> Self {
        self.ipfilter = None;
        self
    }

    /// Replaces the [`RateLimitLayer`] configuration.
    #[must_use]
    pub fn ratelimit(mut self, config: RateLimitConfig) -> Self {
        self.ratelimit = Some(config);
        self
    }

    /// Removes the [`RateLimitLayer`] from the stack.
    #[must_use]
    pub fn without_ratelimit(mut self) -> Self {
        self.ratelimit = None;
        self
    }

    /// Enables the [`ConcurrencyLimitLayer`] with a fresh [`Limiter`] sized from
    /// `config`.
    #[must_use]
    pub fn concurrency(self, config: ConcurrencyLimit) -> Self {
        self.concurrency_layer(ConcurrencyLimitLayer::new(config))
    }

    /// Enables an already-built [`ConcurrencyLimitLayer`], so you can keep a clone of
    /// its [`Limiter`] to export [`Metrics`].
    #[must_use]
    pub fn concurrency_layer(mut self, layer: ConcurrencyLimitLayer) -> Self {
        self.concurrency = Some(layer);
        self
    }

    /// Removes the [`ConcurrencyLimitLayer`] from the stack (the default state).
    #[must_use]
    pub fn without_concurrency(mut self) -> Self {
        self.concurrency = None;
        self
    }

    /// Enables a [`CircuitBreakerLayer`] with a fresh, closed circuit configured by
    /// `config`. Errors and `5xx` responses (timeouts included) count as failures;
    /// while the circuit is open, requests get `503 Service Unavailable` with
    /// `Retry-After` without reaching the handler.
    ///
    /// The circuit is shared by every clone of the stack and of the router.
    #[must_use]
    pub fn circuit_breaker(self, config: CircuitBreaker) -> Self {
        self.circuit_breaker_layer(CircuitBreakerLayer::new(config).classify(ServerErrors))
    }

    /// Enables an already-built [`CircuitBreakerLayer`], so you can keep its
    /// [`handle`][CircuitBreakerLayer::handle] to export the [`CircuitState`] or trip
    /// and reset the circuit.
    #[must_use]
    pub fn circuit_breaker_layer(mut self, layer: StackCircuitBreakerLayer) -> Self {
        self.circuit_breaker = Some(layer);
        self
    }

    /// Removes the [`CircuitBreakerLayer`] from the stack (the default state).
    #[must_use]
    pub fn without_circuit_breaker(mut self) -> Self {
        self.circuit_breaker = None;
        self
    }

    /// Replaces the [`TimeoutLayer`] configuration (default: 30 s for every path).
    ///
    /// Give long-polling or streaming routes their own budget with
    /// [`Timeout::path`] rather than removing the layer.
    #[must_use]
    pub fn timeout(mut self, config: Timeout) -> Self {
        self.timeout = Some(config);
        self
    }

    /// Removes the [`TimeoutLayer`] from the stack.
    ///
    /// Without it, nothing bounds how long a client may take to send the body
    /// the CSRF layer reads.
    #[must_use]
    pub fn without_timeout(mut self) -> Self {
        self.timeout = None;
        self
    }

    /// Replaces the [`BodyLimitLayer`] configuration.
    #[must_use]
    pub const fn body_limit(mut self, config: BodyLimit) -> Self {
        self.body_limit = Some(config);
        self
    }

    /// Removes the [`BodyLimitLayer`] from the stack.
    #[must_use]
    pub const fn without_body_limit(mut self) -> Self {
        self.body_limit = None;
        self
    }

    /// Replaces the [`CsrfLayer`] configuration.
    ///
    /// The `csrf_*` shortcuts below adjust the current configuration instead.
    #[must_use]
    pub fn csrf(mut self, config: CsrfConfig) -> Self {
        self.csrf = Some(config);
        self
    }

    /// Applies `f` to the current CSRF configuration, starting from
    /// [`CsrfConfig::new()`] if CSRF was removed: configuring CSRF turns it on.
    fn map_csrf(mut self, f: impl FnOnce(CsrfConfig) -> CsrfConfig) -> Self {
        self.csrf = Some(f(self.csrf.take().unwrap_or_default()));
        self
    }

    /// Sets the HMAC key that signs CSRF tokens (see [`CsrfConfig::key`]).
    ///
    /// The default key is random per stack, so tokens do not survive a restart
    /// and are not accepted by other instances. Load a secret of at least 32 bytes
    /// shared by every instance in production. Enables CSRF if it was removed.
    #[must_use]
    pub fn csrf_key(self, key: CsrfKey) -> Self {
        self.map_csrf(|c| c.key(key))
    }

    /// Binds CSRF tokens to the value of the named session cookie (see
    /// [`CsrfConfig::session_cookie`]), so a token minted for one session never
    /// validates for another. Enables CSRF if it was removed.
    #[must_use]
    pub fn csrf_session_cookie(self, name: impl Into<String>) -> Self {
        self.map_csrf(|c| c.session_cookie(name))
    }

    /// Binds CSRF tokens to a session id extracted from the request (see
    /// [`CsrfConfig::session_id_with`]). Enables CSRF if it was removed.
    #[must_use]
    pub fn csrf_session_id_with<F>(self, f: F) -> Self
    where
        F: Fn(&axum::http::request::Parts) -> Option<String> + Send + Sync + 'static,
    {
        self.map_csrf(|c| c.session_id_with(f))
    }

    /// Accepts unsafe requests from this extra origin (`scheme://host[:port]`), e.g.
    /// a separate front-end host (see [`CsrfConfig::trusted_origin`]). Malformed
    /// values are ignored. Enables CSRF if it was removed.
    #[must_use]
    pub fn csrf_trusted_origin(self, origin: impl AsRef<str>) -> Self {
        self.map_csrf(|c| c.trusted_origin(origin))
    }

    /// Skips CSRF checks for this exact path (see [`CsrfConfig::exempt_path`]).
    /// Enables CSRF for every other path if it was removed.
    #[must_use]
    pub fn csrf_exempt_path(self, path: impl Into<String>) -> Self {
        self.map_csrf(|c| c.exempt_path(path))
    }

    /// Skips CSRF checks for every path starting with `prefix` (see
    /// [`CsrfConfig::exempt_prefix`]). Enables CSRF for every other path if it was
    /// removed.
    #[must_use]
    pub fn csrf_exempt_prefix(self, prefix: impl Into<String>) -> Self {
        self.map_csrf(|c| c.exempt_prefix(prefix))
    }

    /// Removes the [`CsrfLayer`] from the stack.
    ///
    /// Useful for stateless APIs that authenticate via bearer tokens or API keys
    /// where traditional CSRF protection is not applicable.
    #[must_use]
    pub fn without_csrf(mut self) -> Self {
        self.csrf = None;
        self
    }

    /// Enables a [`RetryLayer`] configured by `config`: handler responses of `502`,
    /// `503` or `504` are retried (and slow ones hedged, with [`Retry::hedge`]) for
    /// idempotent methods with an empty request body. Other requests run once.
    ///
    /// The retry budget is shared by every clone of the stack and of the router.
    #[must_use]
    pub fn retry(self, config: Retry) -> Self {
        self.retry_layer(
            RetryLayer::new(config)
                .classify(TransientHttp)
                .clone_requests(IdempotentBodiless),
        )
    }

    /// Enables an already-built [`RetryLayer`], so you can keep its
    /// [`handle`][RetryLayer::handle] to export [`RetryStats`].
    #[must_use]
    pub fn retry_layer(mut self, layer: StackRetryLayer) -> Self {
        self.retry = Some(layer);
        self
    }

    /// Removes the [`RetryLayer`] from the stack (the default state).
    #[must_use]
    pub fn without_retry(mut self) -> Self {
        self.retry = None;
        self
    }

    /// Enables the [`CacheLayer`] (innermost layer) with `config`: `Cache-Control` on
    /// successful `GET`/`HEAD` responses and `304`/`412` answers to conditional
    /// requests, based on the handler's `ETag` / `Last-Modified`.
    #[must_use]
    pub fn cache(mut self, config: Cache) -> Self {
        self.cache = Some(config);
        self
    }

    /// Removes the [`CacheLayer`] from the stack (the default state).
    #[must_use]
    pub fn without_cache(mut self) -> Self {
        self.cache = None;
        self
    }

    /// Applies all enabled layers to `router` and returns the wrapped router.
    ///
    /// Layers are composed outermost-first, independent of builder call order:
    /// `request_id` → `health` → `compression` → `problem` → `helmet` →
    /// `redirect_https` → `cors` → `ipfilter` → `ratelimit` → `concurrency` →
    /// `circuit_breaker` → `timeout` → `body_limit` → `csrf` → `retry` → `cache` →
    /// handler.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use axum::{routing::get, Router};
    /// use rune_axum_stack::SecurityStack;
    ///
    /// let app: Router = SecurityStack::default().apply(
    ///     Router::new().route("/", get(|| async { "ok" })),
    /// );
    /// ```
    pub fn apply<S>(self, router: axum::Router<S>) -> axum::Router<S>
    where
        S: Clone + Send + Sync + 'static,
    {
        let Self {
            request_id,
            health,
            compression,
            problem,
            helmet,
            redirect_https,
            cors,
            ipfilter,
            ratelimit,
            concurrency,
            circuit_breaker,
            timeout,
            body_limit,
            csrf,
            retry,
            cache,
        } = self;
        let mut r = router;

        // `Router::layer` wraps what is already there, so layers are added
        // innermost-first: the first one added is the last to see a request.
        if let Some(config) = cache {
            r = r.layer(CacheLayer::new(config));
        }
        if let Some(layer) = retry {
            r = r.layer(layer);
        }
        if let Some(config) = csrf {
            r = r.layer(CsrfLayer::new(config));
        }
        if let Some(config) = body_limit {
            r = r.layer(BodyLimitLayer::new(config));
        }
        if let Some(config) = timeout {
            r = r.layer(TimeoutLayer::new(config));
        }
        if let Some(layer) = circuit_breaker {
            r = r.layer(
                tower::ServiceBuilder::new()
                    .layer(HandleErrorLayer::new(circuit_open_response))
                    .layer(layer),
            );
        }
        if let Some(layer) = concurrency {
            r = r.layer(layer);
        }
        if let Some(config) = ratelimit {
            r = r.layer(RateLimitLayer::new(config));
        }
        if let Some(config) = ipfilter {
            r = r.layer(IpFilterLayer::new(config));
        }
        if let Some(layer) = cors {
            r = r.layer(layer);
        }
        if let Some(config) = redirect_https {
            r = r.layer(RedirectHttpsLayer::new(config));
        }
        if let Some(config) = helmet {
            r = r.layer(HelmetLayer::new(config));
        }
        if let Some(config) = problem {
            r = r.layer(ProblemLayer::new(config));
        }
        if let Some(config) = compression {
            r = r.layer(CompressionLayer::new(config));
        }
        if let Some(layer) = health {
            r = r.layer(layer);
        }
        // Added last → outermost → first to see a request.
        if let Some(config) = request_id {
            r = r.layer(RequestIdLayer::new(config));
        }

        r
    }
}

/// The response for a request the circuit breaker rejected: `503` with a
/// `Retry-After` of the remaining open time, rounded up to whole seconds.
async fn circuit_open_response(err: rune_tower_circuitbreaker::Error<Infallible>) -> Response {
    let retry_after = match err {
        rune_tower_circuitbreaker::Error::Open { retry_after } => retry_after,
        _ => std::time::Duration::ZERO,
    };
    let secs = retry_after
        .as_secs()
        .saturating_add(u64::from(retry_after.subsec_nanos() > 0));
    (
        axum::http::StatusCode::SERVICE_UNAVAILABLE,
        [(axum::http::header::RETRY_AFTER, secs.to_string())],
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        Router,
        body::Body,
        routing::{get, post},
    };
    use http::{HeaderValue, Method, StatusCode, header};
    use http_body_util::BodyExt;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;
    use tower::ServiceExt;

    /// Applies the stack, then simulates the socket peer address that
    /// `into_make_service_with_connect_info` would record: the request's
    /// `x-forwarded-for` value if a test set one, else `1.2.3.4`.
    trait ApplyPeer {
        fn apply_peer(self, router: Router) -> Router;
    }

    impl ApplyPeer for SecurityStack {
        fn apply_peer(self, router: Router) -> Router {
            self.apply(router).layer(axum::middleware::map_request(
                |mut req: http::Request<Body>| async move {
                    let ip = req
                        .headers()
                        .get("x-forwarded-for")
                        .and_then(|v| v.to_str().ok())
                        .and_then(|v| v.parse().ok())
                        .unwrap_or_else(|| std::net::IpAddr::from([1, 2, 3, 4]));
                    req.extensions_mut().insert(axum::extract::ConnectInfo(
                        std::net::SocketAddr::new(ip, 40_000),
                    ));
                    req
                },
            ))
        }
    }

    fn base_router() -> Router {
        Router::new()
            .route("/", get(|| async { "ok" }))
            .route("/submit", post(|| async { "ok" }))
    }

    async fn send(app: Router, req: http::Request<Body>) -> http::Response<Body> {
        app.oneshot(req).await.unwrap()
    }

    fn get_req() -> http::Request<Body> {
        http::Request::builder()
            .method("GET")
            .uri("/")
            .header("x-forwarded-for", "1.2.3.4")
            .body(Body::empty())
            .unwrap()
    }

    fn post_req() -> http::Request<Body> {
        http::Request::builder()
            .method("POST")
            .uri("/submit")
            .header("x-forwarded-for", "1.2.3.4")
            .body(Body::empty())
            .unwrap()
    }

    #[tokio::test]
    async fn default_stack_allows_get() {
        let app = SecurityStack::default().apply_peer(base_router());
        assert_eq!(send(app, get_req()).await.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn default_stack_sets_security_headers() {
        let app = SecurityStack::default().apply_peer(base_router());
        let resp = send(app, get_req()).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(resp.headers().contains_key("x-content-type-options"));
        assert!(resp.headers().contains_key("x-frame-options"));
    }

    #[tokio::test]
    async fn default_stack_blocks_post_without_csrf_token() {
        let app = SecurityStack::default().apply_peer(base_router());
        assert_eq!(send(app, post_req()).await.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn without_csrf_allows_post() {
        let app = SecurityStack::default()
            .without_csrf()
            .apply_peer(base_router());
        assert_eq!(send(app, post_req()).await.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn custom_ratelimit_zero_blocks_request() {
        let app = SecurityStack::new()
            .without_csrf()
            .without_redirect_https()
            .ratelimit(RateLimitConfig::new().requests(0))
            .apply_peer(base_router());
        assert_eq!(
            send(app, get_req()).await.status(),
            StatusCode::TOO_MANY_REQUESTS
        );
    }

    #[tokio::test]
    async fn without_ratelimit_passes() {
        let app = SecurityStack::new()
            .without_csrf()
            .without_redirect_https()
            .without_ratelimit()
            .apply_peer(base_router());
        assert_eq!(send(app, get_req()).await.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn body_limit_rejects_oversized_request() {
        let app = SecurityStack::new()
            .without_csrf()
            .without_redirect_https()
            .body_limit(BodyLimit::new().limit(10))
            .apply_peer(base_router());
        let req = http::Request::builder()
            .method("POST")
            .uri("/submit")
            .header("content-length", "100")
            .body(Body::empty())
            .unwrap();
        assert_eq!(send(app, req).await.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[tokio::test]
    async fn custom_helmet_deny_frame_options() {
        let app = SecurityStack::new()
            .without_csrf()
            .without_redirect_https()
            .helmet(Helmet::new().frame_options(XFrameOptions::Deny))
            .apply_peer(base_router());
        let resp = send(app, get_req()).await;
        assert_eq!(
            resp.headers()
                .get("x-frame-options")
                .unwrap()
                .to_str()
                .unwrap(),
            "DENY"
        );
    }

    #[tokio::test]
    async fn without_helmet_no_security_headers() {
        let app = SecurityStack::new()
            .without_csrf()
            .without_redirect_https()
            .without_helmet()
            .apply_peer(base_router());
        let resp = send(app, get_req()).await;
        assert!(!resp.headers().contains_key("x-content-type-options"));
    }

    #[tokio::test]
    async fn redirect_https_triggers_on_forwarded_proto() {
        let app = SecurityStack::new()
            .without_csrf()
            .apply_peer(base_router());
        let req = http::Request::builder()
            .method("GET")
            .uri("http://example.com/")
            .header("x-forwarded-proto", "http")
            .header("host", "example.com")
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            send(app, req).await.status(),
            StatusCode::PERMANENT_REDIRECT
        );
    }

    #[tokio::test]
    async fn without_redirect_https_no_redirect() {
        let app = SecurityStack::new()
            .without_csrf()
            .without_redirect_https()
            .apply_peer(base_router());
        let req = http::Request::builder()
            .method("GET")
            .uri("http://example.com/")
            .header("x-forwarded-proto", "http")
            .header("host", "example.com")
            .body(Body::empty())
            .unwrap();
        assert_eq!(send(app, req).await.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn ipfilter_blocks_configured_cidr() {
        let app = SecurityStack::new()
            .without_csrf()
            .without_redirect_https()
            .ipfilter(
                IpFilterConfig::new()
                    .mode(FilterMode::Blocklist)
                    .cidr("1.2.3.4/32")
                    .unwrap(),
            )
            .apply_peer(base_router());
        assert_eq!(send(app, get_req()).await.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn security_headers_present_on_rate_limit_rejection() {
        let app = SecurityStack::new()
            .without_csrf()
            .without_redirect_https()
            .ratelimit(RateLimitConfig::new().requests(0))
            .apply_peer(base_router());
        let resp = send(app, get_req()).await;
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        assert!(resp.headers().contains_key("x-content-type-options"));
    }

    #[tokio::test]
    async fn all_layers_disabled_passes_through() {
        let app = SecurityStack::new()
            .without_helmet()
            .without_csrf()
            .without_ratelimit()
            .without_ipfilter()
            .without_redirect_https()
            .without_body_limit()
            .apply_peer(base_router());
        assert_eq!(send(app, get_req()).await.status(), StatusCode::OK);
    }

    // ---- New optional layers and their order -------------------------------------

    const ORIGIN: &str = "https://app.example.com";
    const PROBLEM_JSON: &str = "application/problem+json";

    /// Default stack minus the layers that get in the way of plain GETs in tests.
    fn api_stack() -> SecurityStack {
        SecurityStack::new().without_csrf().without_redirect_https()
    }

    fn slow_router() -> Router {
        Router::new().route(
            "/slow",
            get(|| async {
                tokio::time::sleep(Duration::from_secs(60)).await;
                "late"
            }),
        )
    }

    fn header_str<'a>(resp: &'a http::Response<Body>, name: &str) -> Option<&'a str> {
        resp.headers().get(name).and_then(|v| v.to_str().ok())
    }

    fn content_type(resp: &http::Response<Body>) -> Option<&str> {
        header_str(resp, "content-type")
    }

    #[tokio::test]
    async fn new_layers_are_off_by_default() {
        let app = SecurityStack::default()
            .without_csrf()
            .apply_peer(base_router());
        let resp = send(app.clone(), get_req()).await;
        assert!(!resp.headers().contains_key("x-request-id"));
        let req = http::Request::builder()
            .uri("/livez")
            .body(Body::empty())
            .unwrap();
        // No health layer: `/livez` is just an unknown route.
        assert_eq!(send(app, req).await.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn request_id_set_on_success() {
        let app = api_stack()
            .request_id(RequestIdConfig::default())
            .apply_peer(base_router());
        let resp = send(app, get_req()).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(resp.headers().contains_key(X_REQUEST_ID));
    }

    #[tokio::test]
    async fn request_id_wraps_rejections_and_probes() {
        let app = api_stack()
            .request_id(RequestIdConfig::default())
            .health(HealthState::new())
            .ratelimit(RateLimitConfig::new().requests(0))
            .apply_peer(base_router());
        let resp = send(app.clone(), get_req()).await;
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        assert!(resp.headers().contains_key(X_REQUEST_ID));

        let probe = http::Request::builder()
            .uri("/readyz")
            .body(Body::empty())
            .unwrap();
        let resp = send(app, probe).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(resp.headers().contains_key(X_REQUEST_ID));
    }

    #[tokio::test]
    async fn health_probes_bypass_redirect_ipfilter_and_limits() {
        let app = SecurityStack::default() // redirect_https + CSRF on
            .health(HealthState::new())
            .ipfilter(
                IpFilterConfig::new()
                    .mode(FilterMode::Blocklist)
                    .cidr("0.0.0.0/0")
                    .unwrap(),
            )
            .ratelimit(RateLimitConfig::new().requests(0))
            .concurrency(ConcurrencyLimit::new().max_in_flight(0))
            .apply_peer(base_router());
        for path in ["/livez", "/readyz"] {
            let req = http::Request::builder()
                .uri(format!("http://node.internal{path}"))
                .header("host", "node.internal")
                .header("x-forwarded-proto", "http")
                .header("x-forwarded-for", "10.0.0.7")
                .body(Body::empty())
                .unwrap();
            assert_eq!(send(app.clone(), req).await.status(), StatusCode::OK);
        }
        // Ordinary traffic is still redirected.
        let req = http::Request::builder()
            .uri("http://node.internal/")
            .header("host", "node.internal")
            .header("x-forwarded-proto", "http")
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            send(app, req).await.status(),
            StatusCode::PERMANENT_REDIRECT
        );
    }

    #[tokio::test]
    async fn readiness_503_is_not_turned_into_a_problem() {
        let state = HealthState::new();
        let app = api_stack()
            .health(state.clone())
            .problem(Problems::new())
            .apply_peer(base_router());
        state.begin_shutdown();
        let req = http::Request::builder()
            .uri("/readyz")
            .body(Body::empty())
            .unwrap();
        let resp = send(app, req).await;
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_ne!(content_type(&resp), Some(PROBLEM_JSON));
    }

    #[tokio::test]
    async fn health_counts_in_flight_requests() {
        let state = HealthState::new();
        let app = api_stack()
            .without_ratelimit()
            .health(state.clone())
            .apply_peer(slow_router());
        let req = http::Request::builder()
            .uri("/slow")
            .body(Body::empty())
            .unwrap();
        let task = tokio::spawn(app.oneshot(req));
        for _ in 0..100 {
            if state.in_flight() == 1 {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert_eq!(state.in_flight(), 1);
        task.abort();
    }

    #[tokio::test]
    async fn problem_converts_rate_limit_and_keeps_headers() {
        let app = api_stack()
            .problem(Problems::new())
            .ratelimit(RateLimitConfig::new().requests(0))
            .apply_peer(base_router());
        let resp = send(app, get_req()).await;
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(content_type(&resp), Some(PROBLEM_JSON));
        assert!(resp.headers().contains_key("retry-after"));
        // helmet sits inside `problem`, its headers survive the conversion
        assert!(resp.headers().contains_key("x-content-type-options"));
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let problem = Problem::from_json(&body).unwrap();
        assert_eq!(problem.status(), Some(StatusCode::TOO_MANY_REQUESTS));
    }

    #[tokio::test]
    async fn problem_converts_body_limit_rejection() {
        let app = api_stack()
            .problem(Problems::new())
            .body_limit(BodyLimit::new().limit(10))
            .apply_peer(base_router());
        let req = http::Request::builder()
            .method("POST")
            .uri("/submit")
            .header("content-length", "100")
            .body(Body::empty())
            .unwrap();
        let resp = send(app, req).await;
        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(content_type(&resp), Some(PROBLEM_JSON));
    }

    #[tokio::test(start_paused = true)]
    async fn timeout_returns_504_problem_with_request_id() {
        let app = api_stack()
            .request_id(RequestIdConfig::default())
            .problem(Problems::new())
            .timeout(Timeout::new().duration(Duration::from_millis(50)))
            .apply_peer(slow_router());
        let req = http::Request::builder()
            .uri("/slow")
            .body(Body::empty())
            .unwrap();
        let resp = send(app, req).await;
        assert_eq!(resp.status(), StatusCode::GATEWAY_TIMEOUT);
        assert_eq!(content_type(&resp), Some(PROBLEM_JSON));
        assert!(resp.headers().contains_key(X_REQUEST_ID));
    }

    #[tokio::test]
    async fn concurrency_sheds_with_503_problem() {
        let app = api_stack()
            .problem(Problems::new())
            .concurrency(ConcurrencyLimit::new().max_in_flight(0))
            .apply_peer(base_router());
        let resp = send(app, get_req()).await;
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(content_type(&resp), Some(PROBLEM_JSON));
    }

    #[tokio::test]
    async fn ratelimit_rejects_before_concurrency() {
        let layer = ConcurrencyLimitLayer::new(ConcurrencyLimit::new().max_in_flight(0));
        let limiter = layer.limiter().clone();
        let app = api_stack()
            .ratelimit(RateLimitConfig::new().requests(0))
            .concurrency_layer(layer)
            .apply_peer(base_router());
        assert_eq!(
            send(app, get_req()).await.status(),
            StatusCode::TOO_MANY_REQUESTS
        );
        // The rate-limited request never reached the concurrency limiter.
        let metrics = limiter.metrics();
        assert_eq!((metrics.admitted, metrics.shed), (0, 0));
    }

    #[tokio::test(start_paused = true)]
    async fn timeout_inside_concurrency_frees_the_slot() {
        let app = api_stack()
            .concurrency(ConcurrencyLimit::new().max_in_flight(1))
            .timeout(Timeout::new().duration(Duration::from_millis(50)))
            .apply_peer(slow_router());
        for _ in 0..2 {
            let req = http::Request::builder()
                .uri("/slow")
                .body(Body::empty())
                .unwrap();
            // A slot held past the timeout would turn the second request into a 503.
            assert_eq!(
                send(app.clone(), req).await.status(),
                StatusCode::GATEWAY_TIMEOUT
            );
        }
    }

    #[tokio::test]
    async fn cors_answers_preflight_before_csrf_and_ratelimit() {
        let app = SecurityStack::new()
            .without_redirect_https()
            .ratelimit(RateLimitConfig::new().requests(0))
            .cors(
                Cors::new()
                    .allow_origin(ORIGIN)
                    .allow_methods([Method::GET, Method::POST]),
            )
            .unwrap()
            .apply_peer(base_router());
        let req = http::Request::builder()
            .method("OPTIONS")
            .uri("/submit")
            .header("origin", ORIGIN)
            .header("access-control-request-method", "POST")
            .header("x-forwarded-for", "1.2.3.4")
            .body(Body::empty())
            .unwrap();
        let resp = send(app, req).await;
        assert!(resp.status().is_success(), "status {}", resp.status());
        assert_eq!(
            header_str(&resp, "access-control-allow-origin"),
            Some(ORIGIN)
        );
    }

    #[tokio::test]
    async fn cors_headers_on_rejections() {
        let app = api_stack()
            .problem(Problems::new())
            .ratelimit(RateLimitConfig::new().requests(0))
            .cors(Cors::new().allow_origin(ORIGIN))
            .unwrap()
            .apply_peer(base_router());
        let req = http::Request::builder()
            .uri("/")
            .header("origin", ORIGIN)
            .header("x-forwarded-for", "1.2.3.4")
            .body(Body::empty())
            .unwrap();
        let resp = send(app, req).await;
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(
            header_str(&resp, "access-control-allow-origin"),
            Some(ORIGIN)
        );
        assert_eq!(content_type(&resp), Some(PROBLEM_JSON));
    }

    #[tokio::test]
    async fn refused_preflight_becomes_problem() {
        let app = api_stack()
            .problem(Problems::new())
            .cors(Cors::new().allow_origin(ORIGIN))
            .unwrap()
            .apply_peer(base_router());
        let req = http::Request::builder()
            .method("OPTIONS")
            .uri("/")
            .header("origin", "https://evil.example")
            .header("access-control-request-method", "GET")
            .body(Body::empty())
            .unwrap();
        let resp = send(app, req).await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        assert_eq!(content_type(&resp), Some(PROBLEM_JSON));
    }

    #[test]
    fn insecure_cors_is_refused_at_build_time() {
        let err = SecurityStack::new()
            .cors(Cors::new().allow_any_origin().allow_credentials(true))
            .unwrap_err();
        assert!(matches!(err, CorsError::Insecure { .. }));
    }

    #[tokio::test]
    async fn compression_wraps_handler_output() {
        let big = "a".repeat(8 * 1024);
        let router = Router::new().route("/big", get(move || async move { big }));
        let app = api_stack()
            .compression(Compression::new())
            .apply_peer(router);
        let req = http::Request::builder()
            .uri("/big")
            .header(header::ACCEPT_ENCODING, HeaderValue::from_static("gzip"))
            .header("x-forwarded-for", "1.2.3.4")
            .body(Body::empty())
            .unwrap();
        let resp = send(app, req).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(header_str(&resp, "content-encoding"), Some("gzip"));
        // helmet headers are untouched by compression
        assert!(resp.headers().contains_key("x-content-type-options"));
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        assert!(body.len() < 8 * 1024);
    }

    fn etag_router() -> Router {
        Router::new().route(
            "/doc",
            get(|| async { ([(header::ETAG, HeaderValue::from_static("\"v1\""))], "doc") }),
        )
    }

    #[tokio::test]
    async fn cache_sets_cache_control_and_answers_304() {
        let app = api_stack()
            .compression(Compression::new())
            .cors(Cors::new().allow_origin(ORIGIN))
            .unwrap()
            .cache(Cache::new())
            .apply_peer(etag_router());
        let ok = http::Request::builder()
            .uri("/doc")
            .body(Body::empty())
            .unwrap();
        let resp = send(app.clone(), ok).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(resp.headers().contains_key("cache-control"));

        let revalidate = http::Request::builder()
            .uri("/doc")
            .header(header::IF_NONE_MATCH, "\"v1\"")
            .header(header::ACCEPT_ENCODING, "gzip")
            .header("origin", ORIGIN)
            .body(Body::empty())
            .unwrap();
        let resp = send(app, revalidate).await;
        assert_eq!(resp.status(), StatusCode::NOT_MODIFIED);
        // Layers above `cache` still decorate the 304; compression leaves it alone.
        assert!(resp.headers().contains_key("x-content-type-options"));
        assert_eq!(
            header_str(&resp, "access-control-allow-origin"),
            Some(ORIGIN)
        );
        assert!(!resp.headers().contains_key("content-encoding"));
    }

    #[tokio::test]
    async fn cache_precondition_failure_becomes_problem() {
        let app = api_stack()
            .problem(Problems::new())
            .cache(Cache::new())
            .apply_peer(etag_router());
        let req = http::Request::builder()
            .uri("/doc")
            .header(header::IF_MATCH, "\"other\"")
            .body(Body::empty())
            .unwrap();
        let resp = send(app, req).await;
        assert_eq!(resp.status(), StatusCode::PRECONDITION_FAILED);
        assert_eq!(content_type(&resp), Some(PROBLEM_JSON));
    }

    #[tokio::test]
    async fn cache_leaves_rejections_alone() {
        let app = api_stack()
            .ratelimit(RateLimitConfig::new().requests(0))
            .cache(Cache::new())
            .apply_peer(base_router());
        let resp = send(app, get_req()).await;
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        assert!(!resp.headers().contains_key("cache-control"));
    }

    #[tokio::test]
    async fn builder_call_order_does_not_change_layer_order() {
        // `problem` configured after the rejecting layers, `request_id` last:
        // they still end up outside them.
        let app = api_stack()
            .ratelimit(RateLimitConfig::new().requests(0))
            .problem(Problems::new())
            .request_id(RequestIdConfig::default())
            .apply_peer(base_router());
        let resp = send(app, get_req()).await;
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(content_type(&resp), Some(PROBLEM_JSON));
        assert!(resp.headers().contains_key(X_REQUEST_ID));
    }

    #[tokio::test]
    async fn everything_enabled_serves_ok() {
        let app = SecurityStack::new()
            .without_redirect_https()
            .request_id(RequestIdConfig::default())
            .health(HealthState::new())
            .compression(Compression::new())
            .problem(Problems::new())
            .cors(Cors::new().allow_origin(ORIGIN))
            .unwrap()
            .ipfilter(
                IpFilterConfig::new()
                    .mode(FilterMode::Blocklist)
                    .cidr("10.0.0.0/8")
                    .unwrap(),
            )
            .concurrency(ConcurrencyLimit::new())
            .circuit_breaker(CircuitBreaker::new())
            .timeout(Timeout::new())
            .retry(Retry::new())
            .cache(Cache::new())
            .apply_peer(base_router());
        let resp = send(app, get_req()).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(resp.headers().contains_key(X_REQUEST_ID));
        assert!(resp.headers().contains_key("x-content-type-options"));
        assert!(resp.headers().contains_key("cache-control"));
    }

    #[tokio::test]
    async fn all_new_layers_can_be_removed() {
        let app = api_stack()
            .request_id(RequestIdConfig::default())
            .health(HealthState::new())
            .compression(Compression::new())
            .problem(Problems::new())
            .cors(Cors::new().allow_origin(ORIGIN))
            .unwrap()
            .concurrency(ConcurrencyLimit::new().max_in_flight(0))
            .circuit_breaker(CircuitBreaker::new())
            .timeout(Timeout::new())
            .retry(Retry::new())
            .cache(Cache::new())
            .without_request_id()
            .without_health()
            .without_compression()
            .without_problem()
            .without_cors()
            .without_concurrency()
            .without_circuit_breaker()
            .without_timeout()
            .without_retry()
            .without_cache()
            .apply_peer(base_router());
        let resp = send(app, get_req()).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(!resp.headers().contains_key(X_REQUEST_ID));
    }

    // ---- Secure defaults and CSRF 0.2 ---------------------------------------------

    /// GETs `/` and returns the CSRF cookie pair (`name=value`) and its token.
    async fn csrf_cookie(app: Router, extra: Option<(&str, &str)>) -> (String, String) {
        let mut req = http::Request::builder().uri("/");
        if let Some((name, value)) = extra {
            req = req.header(name, value);
        }
        let resp = send(app, req.body(Body::empty()).unwrap()).await;
        let set_cookie = header_str(&resp, "set-cookie").unwrap().to_owned();
        let pair = set_cookie.split(';').next().unwrap().to_owned();
        let token = pair.split_once('=').unwrap().1.to_owned();
        (pair, token)
    }

    fn csrf_post(cookie: &str, token: &str) -> http::Request<Body> {
        http::Request::builder()
            .method("POST")
            .uri("/submit")
            .header("cookie", cookie)
            .header("x-csrf-token", token)
            .body(Body::empty())
            .unwrap()
    }

    #[tokio::test]
    async fn default_stack_sets_hsts_and_secure_host_cookie() {
        let app = SecurityStack::default()
            .without_redirect_https()
            .apply_peer(base_router());
        let resp = send(app, get_req()).await;
        assert!(
            header_str(&resp, "strict-transport-security")
                .unwrap()
                .starts_with("max-age=31536000")
        );
        let cookie = header_str(&resp, "set-cookie").unwrap();
        assert!(cookie.starts_with("__Host-csrf_token="), "{cookie}");
        assert!(cookie.contains("Secure"), "{cookie}");
    }

    #[tokio::test(start_paused = true)]
    async fn default_stack_times_out_slow_handlers() {
        let app = SecurityStack::default()
            .without_redirect_https()
            .apply_peer(slow_router());
        let req = http::Request::builder()
            .uri("/slow")
            .body(Body::empty())
            .unwrap();
        assert_eq!(send(app, req).await.status(), StatusCode::GATEWAY_TIMEOUT);
    }

    #[tokio::test]
    async fn default_csrf_round_trip_and_token_extension() {
        let router = Router::new()
            .route(
                "/",
                get(
                    |axum::Extension(t): axum::Extension<CsrfToken>| async move {
                        t.as_str().to_owned()
                    },
                ),
            )
            .route("/submit", post(|| async { "ok" }));
        let app = SecurityStack::default()
            .without_redirect_https()
            .apply_peer(router);
        let resp = send(app.clone(), get_req()).await;
        let pair = header_str(&resp, "set-cookie")
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_owned();
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let token = String::from_utf8(body.to_vec()).unwrap();
        assert!(pair.ends_with(&token));
        assert_eq!(
            send(app.clone(), csrf_post(&pair, &token)).await.status(),
            StatusCode::OK
        );
        // A cross-site request is refused even with a valid token.
        let mut req = csrf_post(&pair, &token);
        req.headers_mut()
            .insert("sec-fetch-site", HeaderValue::from_static("cross-site"));
        assert_eq!(send(app, req).await.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn csrf_key_is_shared_across_instances() {
        let key = CsrfKey::from_bytes(&[7; 32]).unwrap();
        let a = SecurityStack::new()
            .without_redirect_https()
            .csrf_key(key.clone())
            .apply_peer(base_router());
        let b = SecurityStack::new()
            .without_redirect_https()
            .csrf_key(key)
            .apply_peer(base_router());
        let (pair, token) = csrf_cookie(a, None).await;
        assert_eq!(
            send(b, csrf_post(&pair, &token)).await.status(),
            StatusCode::OK
        );
        // Without the shared key, another instance refuses the token.
        let c = SecurityStack::new()
            .without_redirect_https()
            .apply_peer(base_router());
        assert_eq!(
            send(c, csrf_post(&pair, &token)).await.status(),
            StatusCode::FORBIDDEN
        );
    }

    #[tokio::test]
    async fn csrf_session_binding_rejects_other_sessions() {
        let app = SecurityStack::new()
            .without_redirect_https()
            .csrf_session_cookie("sid")
            .apply_peer(base_router());
        let (pair, token) = csrf_cookie(app.clone(), Some(("cookie", "sid=alice"))).await;
        let alice = format!("{pair}; sid=alice");
        let mallory = format!("{pair}; sid=mallory");
        assert_eq!(
            send(app.clone(), csrf_post(&alice, &token)).await.status(),
            StatusCode::OK
        );
        assert_eq!(
            send(app, csrf_post(&mallory, &token)).await.status(),
            StatusCode::FORBIDDEN
        );
    }

    #[tokio::test]
    async fn csrf_trusted_origin_and_exemptions() {
        let router = base_router().route("/hooks/in", post(|| async { "hook" }));
        let app = SecurityStack::new()
            .without_redirect_https()
            .csrf_trusted_origin("https://www.example.com")
            .csrf_exempt_path("/hooks/in")
            .apply_peer(router);
        let (pair, token) = csrf_cookie(app.clone(), None).await;
        let with_origin = |origin: &'static str| {
            let mut req = csrf_post(&pair, &token);
            req.headers_mut()
                .insert("origin", HeaderValue::from_static(origin));
            req
        };
        assert_eq!(
            send(app.clone(), with_origin("https://www.example.com"))
                .await
                .status(),
            StatusCode::OK
        );
        assert_eq!(
            send(app.clone(), with_origin("https://evil.example"))
                .await
                .status(),
            StatusCode::FORBIDDEN
        );
        let hook = http::Request::builder()
            .method("POST")
            .uri("/hooks/in")
            .body(Body::empty())
            .unwrap();
        assert_eq!(send(app, hook).await.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn csrf_shortcuts_reenable_removed_csrf() {
        let app = SecurityStack::new()
            .without_redirect_https()
            .without_csrf()
            .csrf_exempt_prefix("/webhooks/")
            .apply_peer(base_router());
        assert_eq!(send(app, post_req()).await.status(), StatusCode::FORBIDDEN);
    }

    // ---- Circuit breaker and retry ------------------------------------------------

    /// A router whose `n`-th request (0-based, GET or POST on `/`) answers with
    /// `statuses[n]` (the last status repeats), counting handler calls.
    fn scripted_router(statuses: &'static [u16]) -> (Router, Arc<AtomicUsize>) {
        let calls = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&calls);
        let handler = move || {
            let n = counter.fetch_add(1, Ordering::SeqCst);
            let status = statuses[n.min(statuses.len() - 1)];
            async move { StatusCode::from_u16(status).unwrap() }
        };
        let router = Router::new().route("/", get(handler.clone()).post(handler));
        (router, calls)
    }

    fn fast_retry() -> Retry {
        Retry::new()
            .backoff(Backoff::constant(Duration::from_millis(1)))
            .budget(RetryBudget::new())
    }

    fn breaker(calls: usize) -> CircuitBreaker {
        CircuitBreaker::new()
            .window(calls)
            .minimum_calls(calls)
            .open_duration(Duration::from_secs(30))
    }

    #[tokio::test]
    async fn open_circuit_fails_fast_with_503_problem() {
        let (router, calls) = scripted_router(&[500]);
        let app = api_stack()
            .request_id(RequestIdConfig::default())
            .problem(Problems::new())
            .circuit_breaker(breaker(2))
            .apply_peer(router);
        for _ in 0..2 {
            let status = send(app.clone(), get_req()).await.status();
            assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        }
        let resp = send(app, get_req()).await;
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(header_str(&resp, "retry-after"), Some("30"));
        assert_eq!(content_type(&resp), Some(PROBLEM_JSON));
        assert!(resp.headers().contains_key(X_REQUEST_ID));
        assert!(resp.headers().contains_key("x-content-type-options"));
        // The rejected request never reached the handler.
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn outer_rejections_do_not_count_and_inner_ones_are_successes() {
        let layer = CircuitBreakerLayer::new(breaker(1)).classify(ServerErrors);
        let circuit = layer.handle();
        let app = SecurityStack::new()
            .without_redirect_https()
            .circuit_breaker_layer(layer.clone())
            .ratelimit(RateLimitConfig::new().requests(0))
            .apply_peer(base_router());
        // 429 from the rate limiter, outside the breaker: not an outcome.
        assert_eq!(
            send(app, get_req()).await.status(),
            StatusCode::TOO_MANY_REQUESTS
        );
        assert_eq!(circuit.snapshot().calls, 0);

        let app = SecurityStack::new()
            .without_redirect_https()
            .circuit_breaker_layer(layer)
            .apply_peer(base_router());
        // 403 from CSRF, inside the breaker: a client error, not a failure.
        assert_eq!(send(app, post_req()).await.status(), StatusCode::FORBIDDEN);
        assert_eq!(circuit.state(), CircuitState::Closed);
    }

    #[tokio::test(start_paused = true)]
    async fn timeouts_trip_the_circuit() {
        let layer = CircuitBreakerLayer::new(breaker(1)).classify(ServerErrors);
        let circuit = layer.handle();
        let app = api_stack()
            .circuit_breaker_layer(layer)
            .timeout(Timeout::new().duration(Duration::from_millis(50)))
            .apply_peer(slow_router());
        let req = || {
            http::Request::builder()
                .uri("/slow")
                .body(Body::empty())
                .unwrap()
        };
        assert_eq!(
            send(app.clone(), req()).await.status(),
            StatusCode::GATEWAY_TIMEOUT
        );
        assert_eq!(circuit.state(), CircuitState::Open);
        assert_eq!(
            send(app, req()).await.status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
    }

    #[tokio::test]
    async fn retry_recovers_idempotent_requests_only() {
        let (router, calls) = scripted_router(&[503, 200, 503, 200]);
        let app = api_stack().retry(fast_retry()).apply_peer(router);
        assert_eq!(send(app.clone(), get_req()).await.status(), StatusCode::OK);
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        // POST is not idempotent: its 503 is returned as is.
        let post = http::Request::builder()
            .method("POST")
            .uri("/")
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            send(app, post).await.status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(calls.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn retry_leaves_rejections_and_server_errors_alone() {
        let (router, calls) = scripted_router(&[500, 200]);
        let layer = RetryLayer::new(fast_retry())
            .classify(TransientHttp)
            .clone_requests(IdempotentBodiless);
        let retries = layer.handle();
        let app = api_stack().retry_layer(layer).apply_peer(router.clone());
        // A handler 500 is a bug, not a transient condition.
        assert_eq!(
            send(app, get_req()).await.status(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
        // A body-limit 413 is decided above the retry layer.
        let app = api_stack()
            .body_limit(BodyLimit::new().limit(1))
            .retry(fast_retry())
            .apply_peer(router);
        let req = http::Request::builder()
            .uri("/")
            .header("content-length", "10")
            .body(Body::empty())
            .unwrap();
        assert_eq!(send(app, req).await.status(), StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(retries.stats().retries, 0);
    }

    #[tokio::test(start_paused = true)]
    async fn timeout_bounds_all_retries() {
        let (router, calls) = scripted_router(&[503]);
        let app = api_stack()
            .problem(Problems::new())
            .timeout(Timeout::new().duration(Duration::from_millis(100)))
            .retry(
                Retry::new()
                    .max_attempts(10)
                    .backoff(Backoff::constant(Duration::from_secs(1)))
                    .budget(RetryBudget::new()),
            )
            .apply_peer(router);
        let resp = send(app, get_req()).await;
        assert_eq!(resp.status(), StatusCode::GATEWAY_TIMEOUT);
        assert_eq!(content_type(&resp), Some(PROBLEM_JSON));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn circuit_breaker_sees_one_outcome_after_retries() {
        let (router, calls) = scripted_router(&[503, 503, 200]);
        let layer = CircuitBreakerLayer::new(breaker(1)).classify(ServerErrors);
        let circuit = layer.handle();
        // Builder order is irrelevant: retry still runs inside the breaker.
        let app = api_stack()
            .retry(fast_retry())
            .circuit_breaker_layer(layer)
            .apply_peer(router);
        assert_eq!(send(app, get_req()).await.status(), StatusCode::OK);
        assert_eq!(calls.load(Ordering::SeqCst), 3);
        let snapshot = circuit.snapshot();
        assert_eq!(snapshot.state, CircuitState::Closed);
        assert_eq!((snapshot.calls, snapshot.failure_rate), (1, 0.0));
    }
}
