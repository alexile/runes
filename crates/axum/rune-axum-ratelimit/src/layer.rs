use crate::store::{Algorithm, Decision, InMemoryStore, Quota, RateLimitStore};
use http::{HeaderName, HeaderValue, Request, Response, StatusCode};
use rune_axum_ipfilter::ClientIpConfig;
use rune_axum_ipfilter::client_ip::ipv6_prefix;
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use tower::{Layer, Service};

/// The longest header value accepted as a rate-limit key by [`KeyExtractor::Header`].
pub const MAX_KEY_LEN: usize = 256;

/// `RateLimit-Policy` response header (draft-ietf-httpapi-ratelimit-headers).
pub const RATELIMIT_POLICY: HeaderName = HeaderName::from_static("ratelimit-policy");
/// `RateLimit` response header (draft-ietf-httpapi-ratelimit-headers).
pub const RATELIMIT: HeaderName = HeaderName::from_static("ratelimit");

/// Determines the per-client key that requests are counted against.
///
/// # Examples
///
/// ```rust
/// use http::HeaderName;
/// use rune_axum_ratelimit::KeyExtractor;
///
/// // Per client IP (default): socket peer, or the client behind a trusted proxy.
/// let by_ip = KeyExtractor::ClientIp;
///
/// // Per API key, falling back to the client IP when the header is missing.
/// let by_key = KeyExtractor::Header(HeaderName::from_static("x-api-key"));
/// ```
#[derive(Clone, Debug, Default)]
#[non_exhaustive]
pub enum KeyExtractor {
    /// The client IP resolved by [`RateLimitConfig::client_ip`] (default).
    #[default]
    ClientIp,
    /// The value of a named request header, such as an API key.
    ///
    /// If the header is missing, empty or longer than [`MAX_KEY_LEN`] bytes, the request is
    /// keyed by client IP instead, so omitting the header never escapes the limit.
    ///
    /// The value is taken as sent: a client that puts a new made-up value in every request
    /// gets a fresh bucket each time. Use this only where unknown keys are refused before
    /// they cost anything, and keep an IP-keyed limit in front of it.
    Header(HeaderName),
}

/// What to do when the client IP cannot be determined because the request carries no
/// `ConnectInfo<SocketAddr>` extension.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MissingIp {
    /// Reject the request with this status (default: `500 Internal Server Error`).
    Reject(StatusCode),
    /// Count all such requests against one shared key.
    SharedKey(String),
}

impl Default for MissingIp {
    fn default() -> Self {
        Self::Reject(StatusCode::INTERNAL_SERVER_ERROR)
    }
}

/// What to do when the [`RateLimitStore`] returns an error.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OnStoreError {
    /// Reject the request with this status (default: `503 Service Unavailable`).
    Reject(StatusCode),
    /// Let the request through unlimited.
    Allow,
}

impl Default for OnStoreError {
    fn default() -> Self {
        Self::Reject(StatusCode::SERVICE_UNAVAILABLE)
    }
}

/// Configuration for the rate limiter middleware.
///
/// Build with [`RateLimitConfig::new()`] and chain methods, then pass to
/// [`RateLimitLayer::new()`].
///
/// # Examples
///
/// ```rust
/// use std::time::Duration;
/// use rune_axum_ratelimit::{Algorithm, ClientIpConfig, RateLimitConfig};
///
/// let config = RateLimitConfig::new()
///     .requests(50)
///     .window(Duration::from_secs(30))
///     .algorithm(Algorithm::Gcra)
///     .ipv6_prefix(64)
///     .client_ip(ClientIpConfig::new().trust_proxy("10.0.0.0/8")?);
/// # Ok::<(), rune_axum_ratelimit::CidrParseError>(())
/// ```
#[derive(Clone, Debug)]
pub struct RateLimitConfig {
    quota: Quota,
    status: StatusCode,
    key: KeyExtractor,
    client_ip: ClientIpConfig,
    ipv6_prefix: u8,
    missing_ip: MissingIp,
    on_store_error: OnStoreError,
    headers: bool,
    policy_name: String,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            quota: Quota::new(100, Duration::from_secs(60), Algorithm::FixedWindow),
            status: StatusCode::TOO_MANY_REQUESTS,
            key: KeyExtractor::ClientIp,
            client_ip: ClientIpConfig::new(),
            ipv6_prefix: 128,
            missing_ip: MissingIp::default(),
            on_store_error: OnStoreError::default(),
            headers: true,
            policy_name: "default".to_owned(),
        }
    }
}

impl RateLimitConfig {
    /// Creates a config with defaults: 100 requests per 60 s fixed window, keyed by the socket
    /// peer IP, `429` rejection, rate-limit headers on.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the maximum number of requests per window per client. Defaults to `100`.
    ///
    /// Also resets the GCRA burst to the same value; call [`burst`](Self::burst) afterwards
    /// to change it.
    #[must_use]
    pub const fn requests(mut self, n: u64) -> Self {
        self.quota.limit = n;
        self.quota.burst = n;
        self
    }

    /// Sets the window duration. Defaults to `60` seconds.
    #[must_use]
    pub const fn window(mut self, d: Duration) -> Self {
        self.quota.window = d;
        self
    }

    /// Selects the counting algorithm. Defaults to [`Algorithm::FixedWindow`].
    #[must_use]
    pub const fn algorithm(mut self, algorithm: Algorithm) -> Self {
        self.quota.algorithm = algorithm;
        self
    }

    /// Sets the GCRA burst: requests that may arrive back to back. Defaults to
    /// [`requests`](Self::requests). Ignored by the fixed-window algorithm.
    #[must_use]
    pub const fn burst(mut self, n: u64) -> Self {
        self.quota.burst = n;
        self
    }

    /// Sets the HTTP status returned when the limit is exceeded. Defaults to `429`.
    #[must_use]
    pub const fn status(mut self, s: StatusCode) -> Self {
        self.status = s;
        self
    }

    /// Sets the per-client key. Defaults to [`KeyExtractor::ClientIp`].
    #[must_use]
    pub fn key(mut self, k: KeyExtractor) -> Self {
        self.key = k;
        self
    }

    /// Sets how the client IP is resolved. Defaults to the socket peer address only.
    #[must_use]
    pub fn client_ip(mut self, client_ip: ClientIpConfig) -> Self {
        self.client_ip = client_ip;
        self
    }

    /// Buckets IPv6 clients by their first `prefix_len` bits, e.g. `64` to treat a whole
    /// `/64` (typically one subscriber) as one client. Defaults to `128` (per address).
    #[must_use]
    pub const fn ipv6_prefix(mut self, prefix_len: u8) -> Self {
        self.ipv6_prefix = prefix_len;
        self
    }

    /// Sets the behaviour when `ConnectInfo<SocketAddr>` is missing.
    /// Defaults to [`MissingIp::Reject`] with `500`.
    #[must_use]
    pub fn missing_ip(mut self, missing_ip: MissingIp) -> Self {
        self.missing_ip = missing_ip;
        self
    }

    /// Sets the behaviour when the store fails. Defaults to [`OnStoreError::Reject`] with
    /// `503`.
    #[must_use]
    pub const fn on_store_error(mut self, on_error: OnStoreError) -> Self {
        self.on_store_error = on_error;
        self
    }

    /// Enables or disables the `RateLimit` and `RateLimit-Policy` response headers.
    /// Defaults to enabled. `Retry-After` is always sent on rejection.
    #[must_use]
    pub const fn headers(mut self, enabled: bool) -> Self {
        self.headers = enabled;
        self
    }

    /// Sets the policy name used in the `RateLimit` headers. Defaults to `"default"`.
    ///
    /// Characters outside printable ASCII are dropped; `"` and `\` are escaped.
    #[must_use]
    pub fn policy_name(mut self, name: &str) -> Self {
        name.clone_into(&mut self.policy_name);
        self
    }

    /// Returns the configured quota.
    #[must_use]
    pub const fn quota(&self) -> &Quota {
        &self.quota
    }

    fn ip_key<B>(&self, req: &Request<B>) -> Result<String, StatusCode> {
        let Some(ip) = self.client_ip.resolve(req) else {
            return match &self.missing_ip {
                MissingIp::Reject(status) => Err(*status),
                MissingIp::SharedKey(key) => Ok(format!("missing:{key}")),
            };
        };
        Ok(format!("ip:{}", ipv6_prefix(ip, self.ipv6_prefix)))
    }

    fn extract_key<B>(&self, req: &Request<B>) -> Result<String, StatusCode> {
        if let KeyExtractor::Header(name) = &self.key {
            let value = req.headers().get(name).map(HeaderValue::as_bytes);
            if let Some(v) = value.filter(|v| !v.is_empty() && v.len() <= MAX_KEY_LEN) {
                return Ok(format!("hdr:{}", String::from_utf8_lossy(v)));
            }
        }
        self.ip_key(req)
    }

    fn sf_name(&self) -> String {
        let mut out = String::with_capacity(self.policy_name.len() + 2);
        out.push('"');
        for c in self.policy_name.chars().filter(|c| (' '..='~').contains(c)) {
            if c == '"' || c == '\\' {
                out.push('\\');
            }
            out.push(c);
        }
        out.push('"');
        out
    }
}

/// Rounds a duration up to whole seconds.
fn ceil_secs(d: Duration) -> u64 {
    d.as_secs() + u64::from(d.subsec_nanos() > 0)
}

struct Headers {
    policy: Option<HeaderValue>,
    state: Option<HeaderValue>,
    retry_after: Option<HeaderValue>,
}

impl Headers {
    fn new(config: &RateLimitConfig, d: &Decision) -> Self {
        let (policy, state) = if config.headers {
            let name = config.sf_name();
            let policy = format!("{name};q={};w={}", d.limit, ceil_secs(config.quota.window));
            let state = format!("{name};r={};t={}", d.remaining, ceil_secs(d.reset));
            (
                HeaderValue::from_str(&policy).ok(),
                HeaderValue::from_str(&state).ok(),
            )
        } else {
            (None, None)
        };
        let retry_after = d
            .retry_after
            .map(|r| HeaderValue::from(ceil_secs(r).max(1)));
        Self {
            policy,
            state,
            retry_after,
        }
    }

    fn apply<B>(self, response: &mut Response<B>) {
        let headers = response.headers_mut();
        if let Some(v) = self.policy {
            headers.insert(RATELIMIT_POLICY, v);
        }
        if let Some(v) = self.state {
            headers.insert(RATELIMIT, v);
        }
        if let Some(v) = self.retry_after {
            headers.insert(http::header::RETRY_AFTER, v);
        }
    }
}

/// Tower [`Layer`] that rate-limits requests per client.
///
/// All services produced by one layer share its store, so the limit is enforced across
/// clones and concurrent requests. [`RateLimitLayer::new`] uses a bounded
/// [`InMemoryStore`]; [`RateLimitLayer::with_store`] plugs in any [`RateLimitStore`].
///
/// # Examples
///
/// ```rust,no_run
/// use std::net::SocketAddr;
/// use axum::{routing::get, Router};
/// use rune_axum_ratelimit::RateLimitLayer;
///
/// # async fn run() -> std::io::Result<()> {
/// let app: Router = Router::new()
///     .route("/api", get(|| async { "ok" }))
///     .layer(RateLimitLayer::default());
/// let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await?;
/// axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).await
/// # }
/// ```
#[derive(Clone)]
pub struct RateLimitLayer {
    config: Arc<RateLimitConfig>,
    store: Arc<dyn RateLimitStore>,
}

impl fmt::Debug for RateLimitLayer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RateLimitLayer")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl Default for RateLimitLayer {
    fn default() -> Self {
        Self::new(RateLimitConfig::default())
    }
}

impl RateLimitLayer {
    /// Creates a layer with a fresh, bounded [`InMemoryStore`].
    #[must_use]
    pub fn new(config: RateLimitConfig) -> Self {
        Self::with_store(config, Arc::new(InMemoryStore::new()))
    }

    /// Creates a layer backed by `store`, e.g. a shared distributed store.
    #[must_use]
    pub fn with_store(config: RateLimitConfig, store: Arc<dyn RateLimitStore>) -> Self {
        Self {
            config: Arc::new(config),
            store,
        }
    }
}

impl<S> Layer<S> for RateLimitLayer {
    type Service = RateLimitService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        RateLimitService {
            inner,
            config: Arc::clone(&self.config),
            store: Arc::clone(&self.store),
        }
    }
}

/// Tower [`Service`] produced by [`RateLimitLayer`].
#[derive(Clone)]
pub struct RateLimitService<S> {
    inner: S,
    config: Arc<RateLimitConfig>,
    store: Arc<dyn RateLimitStore>,
}

impl<S: fmt::Debug> fmt::Debug for RateLimitService<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RateLimitService")
            .field("inner", &self.inner)
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

fn status_response<B: Default>(status: StatusCode) -> Response<B> {
    let mut response = Response::new(B::default());
    *response.status_mut() = status;
    response
}

impl<S, ReqBody, ResBody> Service<Request<ReqBody>> for RateLimitService<S>
where
    S: Service<Request<ReqBody>, Response = Response<ResBody>> + Clone + Send + 'static,
    S::Future: Send + 'static,
    S::Error: Send + 'static,
    ReqBody: Send + 'static,
    ResBody: Default + Send + 'static,
{
    type Response = Response<ResBody>;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<ReqBody>) -> Self::Future {
        // Take the service that was driven to readiness; leave a fresh clone behind.
        let clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, clone);
        let config = Arc::clone(&self.config);
        let store = Arc::clone(&self.store);

        Box::pin(async move {
            let key = match config.extract_key(&req) {
                Ok(key) => key,
                Err(status) => return Ok(status_response(status)),
            };
            let Ok(decision) = store.check(&key, &config.quota).await else {
                return match config.on_store_error {
                    OnStoreError::Reject(status) => Ok(status_response(status)),
                    OnStoreError::Allow => inner.call(req).await,
                };
            };
            let headers = Headers::new(&config, &decision);
            if !decision.allowed {
                let mut response = status_response(config.status);
                headers.apply(&mut response);
                return Ok(response);
            }
            let mut response = inner.call(req).await?;
            headers.apply(&mut response);
            Ok(response)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::{BoxFuture, StoreError};
    use axum::{Router, body::Body, extract::ConnectInfo, routing::get};
    use std::net::{IpAddr, SocketAddr};
    use tower::ServiceExt;

    fn build_app(config: RateLimitConfig) -> Router {
        Router::new()
            .route("/", get(|| async { "ok" }))
            .layer(RateLimitLayer::new(config))
    }

    async fn send(app: &Router, req: http::Request<Body>) -> http::Response<Body> {
        app.clone().oneshot(req).await.unwrap()
    }

    fn req_from(peer: &str, headers: &[(&str, &str)]) -> http::Request<Body> {
        let mut builder = http::Request::builder().uri("/");
        for (name, value) in headers {
            builder = builder.header(*name, *value);
        }
        let mut req = builder.body(Body::empty()).unwrap();
        let ip: IpAddr = peer.parse().unwrap();
        req.extensions_mut()
            .insert(ConnectInfo(SocketAddr::new(ip, 50_000)));
        req
    }

    fn req_with_ip(ip: &str) -> http::Request<Body> {
        req_from(ip, &[])
    }

    fn req_bare() -> http::Request<Body> {
        http::Request::builder()
            .uri("/")
            .body(Body::empty())
            .unwrap()
    }

    fn header<'a>(r: &'a http::Response<Body>, name: &str) -> &'a str {
        r.headers().get(name).unwrap().to_str().unwrap()
    }

    #[tokio::test]
    async fn passes_within_limit_then_rejects() {
        let app = build_app(RateLimitConfig::new().requests(2));
        for _ in 0..2 {
            assert_eq!(
                send(&app, req_with_ip("1.2.3.4")).await.status(),
                StatusCode::OK
            );
        }
        let r = send(&app, req_with_ip("1.2.3.4")).await;
        assert_eq!(r.status(), StatusCode::TOO_MANY_REQUESTS);
        assert!(header(&r, "retry-after").parse::<u64>().unwrap() >= 1);
    }

    #[tokio::test]
    async fn different_ips_have_independent_counters() {
        let app = build_app(RateLimitConfig::new().requests(1));
        send(&app, req_with_ip("1.1.1.1")).await;
        assert_eq!(
            send(&app, req_with_ip("2.2.2.2")).await.status(),
            StatusCode::OK
        );
    }

    #[tokio::test]
    async fn spoofed_xff_is_ignored_by_default() {
        let app = build_app(RateLimitConfig::new().requests(1));
        let r = send(&app, req_from("6.6.6.6", &[("x-forwarded-for", "1.0.0.1")])).await;
        assert_eq!(r.status(), StatusCode::OK);
        // Rotating the spoofed header does not grant a fresh bucket.
        let r = send(&app, req_from("6.6.6.6", &[("x-forwarded-for", "1.0.0.2")])).await;
        assert_eq!(r.status(), StatusCode::TOO_MANY_REQUESTS);
        // And a spoofer cannot exhaust a victim's bucket.
        let r = send(&app, req_from("7.7.7.7", &[("x-forwarded-for", "6.6.6.6")])).await;
        assert_eq!(r.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn trusted_proxy_chain_keys_by_real_client() {
        let app = build_app(
            RateLimitConfig::new()
                .requests(1)
                .client_ip(ClientIpConfig::new().trust_proxy("10.0.0.0/8").unwrap()),
        );
        let r = send(
            &app,
            req_from("10.0.0.1", &[("x-forwarded-for", "9.9.9.1, 203.0.113.5")]),
        )
        .await;
        assert_eq!(r.status(), StatusCode::OK);
        // Same real client, different spoofed prefix: limited.
        let r = send(
            &app,
            req_from(
                "10.0.0.2",
                &[("x-forwarded-for", "9.9.9.2, 203.0.113.5, 10.0.0.3")],
            ),
        )
        .await;
        assert_eq!(r.status(), StatusCode::TOO_MANY_REQUESTS);
        // Another client behind the same proxy has its own bucket.
        let r = send(
            &app,
            req_from("10.0.0.1", &[("x-forwarded-for", "203.0.113.6")]),
        )
        .await;
        assert_eq!(r.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn ipv6_bucketed_by_64() {
        let app = build_app(RateLimitConfig::new().requests(1).ipv6_prefix(64));
        let r = send(&app, req_with_ip("2001:db8:1:2::1")).await;
        assert_eq!(r.status(), StatusCode::OK);
        let r = send(&app, req_with_ip("2001:db8:1:2:ffff::9")).await;
        assert_eq!(r.status(), StatusCode::TOO_MANY_REQUESTS);
        let r = send(&app, req_with_ip("2001:db8:1:3::1")).await;
        assert_eq!(r.status(), StatusCode::OK);

        // Without bucketing every address is separate.
        let app = build_app(RateLimitConfig::new().requests(1));
        send(&app, req_with_ip("2001:db8:1:2::1")).await;
        let r = send(&app, req_with_ip("2001:db8:1:2::2")).await;
        assert_eq!(r.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn ipv4_mapped_shares_bucket_with_ipv4() {
        let app = build_app(RateLimitConfig::new().requests(1));
        send(&app, req_with_ip("192.0.2.1")).await;
        let r = send(&app, req_with_ip("::ffff:192.0.2.1")).await;
        assert_eq!(r.status(), StatusCode::TOO_MANY_REQUESTS);
    }

    #[tokio::test]
    async fn missing_connect_info_fails_closed() {
        let app = build_app(RateLimitConfig::new());
        let r = send(&app, req_bare()).await;
        assert_eq!(r.status(), StatusCode::INTERNAL_SERVER_ERROR);

        let app = build_app(
            RateLimitConfig::new()
                .requests(1)
                .missing_ip(MissingIp::SharedKey("unknown".into())),
        );
        assert_eq!(send(&app, req_bare()).await.status(), StatusCode::OK);
        assert_eq!(
            send(&app, req_bare()).await.status(),
            StatusCode::TOO_MANY_REQUESTS
        );
    }

    #[tokio::test]
    async fn header_key_extractor_falls_back_to_ip() {
        let app = build_app(
            RateLimitConfig::new()
                .requests(1)
                .key(KeyExtractor::Header(HeaderName::from_static("x-api-key"))),
        );
        let r = send(&app, req_from("1.1.1.1", &[("x-api-key", "a")])).await;
        assert_eq!(r.status(), StatusCode::OK);
        let r = send(&app, req_from("1.1.1.1", &[("x-api-key", "b")])).await;
        assert_eq!(r.status(), StatusCode::OK);
        let r = send(&app, req_from("2.2.2.2", &[("x-api-key", "a")])).await;
        assert_eq!(r.status(), StatusCode::TOO_MANY_REQUESTS);
        // No header: keyed by IP, still limited.
        assert_eq!(
            send(&app, req_with_ip("3.3.3.3")).await.status(),
            StatusCode::OK
        );
        let r = send(&app, req_with_ip("3.3.3.3")).await;
        assert_eq!(r.status(), StatusCode::TOO_MANY_REQUESTS);
        // Overlong header: keyed by IP.
        let long = "k".repeat(MAX_KEY_LEN + 1);
        let r = send(&app, req_from("3.3.3.3", &[("x-api-key", &long)])).await;
        assert_eq!(r.status(), StatusCode::TOO_MANY_REQUESTS);
    }

    #[tokio::test]
    async fn custom_rejection_status() {
        let config = RateLimitConfig::new()
            .requests(0)
            .status(StatusCode::SERVICE_UNAVAILABLE);
        let r = send(&build_app(config), req_with_ip("1.2.3.4")).await;
        assert_eq!(r.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn emits_ietf_headers() {
        let app = build_app(
            RateLimitConfig::new()
                .requests(2)
                .window(Duration::from_secs(60))
                .policy_name("api"),
        );
        let r = send(&app, req_with_ip("1.2.3.4")).await;
        assert_eq!(r.status(), StatusCode::OK);
        assert_eq!(header(&r, "ratelimit-policy"), r#""api";q=2;w=60"#);
        assert_eq!(header(&r, "ratelimit"), r#""api";r=1;t=60"#);
        assert!(r.headers().get("retry-after").is_none());
        send(&app, req_with_ip("1.2.3.4")).await;
        let r = send(&app, req_with_ip("1.2.3.4")).await;
        assert_eq!(r.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(header(&r, "ratelimit"), r#""api";r=0;t=60"#);
        assert_eq!(header(&r, "retry-after"), "60");

        let app = build_app(RateLimitConfig::new().headers(false));
        let r = send(&app, req_with_ip("1.2.3.4")).await;
        assert!(r.headers().get("ratelimit").is_none());
        assert!(r.headers().get("ratelimit-policy").is_none());
    }

    #[test]
    fn policy_name_is_escaped() {
        let c = RateLimitConfig::new().policy_name("a\"b\\c\n");
        assert_eq!(c.sf_name(), r#""a\"b\\c""#);
    }

    #[tokio::test(start_paused = true)]
    async fn fixed_window_resets_after_expiry() {
        let app = build_app(
            RateLimitConfig::new()
                .requests(1)
                .window(Duration::from_secs(10)),
        );
        assert_eq!(
            send(&app, req_with_ip("10.0.0.1")).await.status(),
            StatusCode::OK
        );
        tokio::time::advance(Duration::from_secs(9)).await;
        let r = send(&app, req_with_ip("10.0.0.1")).await;
        assert_eq!(r.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(header(&r, "retry-after"), "1");
        tokio::time::advance(Duration::from_secs(1)).await;
        assert_eq!(
            send(&app, req_with_ip("10.0.0.1")).await.status(),
            StatusCode::OK
        );
    }

    #[tokio::test(start_paused = true)]
    async fn gcra_timing() {
        // 10 requests per 10 s with a burst of 2: one token per second.
        let app = build_app(
            RateLimitConfig::new()
                .requests(10)
                .window(Duration::from_secs(10))
                .algorithm(Algorithm::Gcra)
                .burst(2),
        );
        let ip = "198.51.100.1";
        assert_eq!(send(&app, req_with_ip(ip)).await.status(), StatusCode::OK);
        let r = send(&app, req_with_ip(ip)).await;
        assert_eq!(r.status(), StatusCode::OK);
        assert_eq!(header(&r, "ratelimit"), r#""default";r=0;t=2"#);
        let r = send(&app, req_with_ip(ip)).await;
        assert_eq!(r.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(header(&r, "retry-after"), "1");

        // Half a token is not enough.
        tokio::time::advance(Duration::from_millis(500)).await;
        assert_eq!(
            send(&app, req_with_ip(ip)).await.status(),
            StatusCode::TOO_MANY_REQUESTS
        );
        // One full token: exactly one request.
        tokio::time::advance(Duration::from_millis(500)).await;
        assert_eq!(send(&app, req_with_ip(ip)).await.status(), StatusCode::OK);
        assert_eq!(
            send(&app, req_with_ip(ip)).await.status(),
            StatusCode::TOO_MANY_REQUESTS
        );
        // Steady rate of one per second is sustained without a boundary burst.
        for _ in 0..5 {
            tokio::time::advance(Duration::from_secs(1)).await;
            assert_eq!(send(&app, req_with_ip(ip)).await.status(), StatusCode::OK);
            assert_eq!(
                send(&app, req_with_ip(ip)).await.status(),
                StatusCode::TOO_MANY_REQUESTS
            );
        }
        // After a long idle period the burst is back, not more.
        tokio::time::advance(Duration::from_secs(60)).await;
        assert_eq!(send(&app, req_with_ip(ip)).await.status(), StatusCode::OK);
        assert_eq!(send(&app, req_with_ip(ip)).await.status(), StatusCode::OK);
        assert_eq!(
            send(&app, req_with_ip(ip)).await.status(),
            StatusCode::TOO_MANY_REQUESTS
        );
    }

    struct Failing;

    impl RateLimitStore for Failing {
        fn check<'a>(
            &'a self,
            _key: &'a str,
            _quota: &'a Quota,
        ) -> BoxFuture<'a, Result<Decision, StoreError>> {
            Box::pin(async { Err(StoreError::new("backend down")) })
        }
    }

    #[tokio::test]
    async fn store_errors_follow_policy() {
        let app = |config| {
            Router::new()
                .route("/", get(|| async { "ok" }))
                .layer(RateLimitLayer::with_store(config, Arc::new(Failing)))
        };
        let r = send(&app(RateLimitConfig::new()), req_with_ip("1.2.3.4")).await;
        assert_eq!(r.status(), StatusCode::SERVICE_UNAVAILABLE);
        let r = send(
            &app(RateLimitConfig::new().on_store_error(OnStoreError::Allow)),
            req_with_ip("1.2.3.4"),
        )
        .await;
        assert_eq!(r.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn shared_store_across_layers() {
        let store: Arc<dyn RateLimitStore> = Arc::new(InMemoryStore::new());
        let config = RateLimitConfig::new().requests(1);
        let a = Router::new()
            .route("/", get(|| async { "ok" }))
            .layer(RateLimitLayer::with_store(
                config.clone(),
                Arc::clone(&store),
            ));
        let b = Router::new()
            .route("/", get(|| async { "ok" }))
            .layer(RateLimitLayer::with_store(config, store));
        assert_eq!(
            send(&a, req_with_ip("1.2.3.4")).await.status(),
            StatusCode::OK
        );
        assert_eq!(
            send(&b, req_with_ip("1.2.3.4")).await.status(),
            StatusCode::TOO_MANY_REQUESTS
        );
    }

    #[tokio::test]
    async fn default_layer_uses_100_req_per_60s() {
        let app = Router::new()
            .route("/", get(|| async { "ok" }))
            .layer(RateLimitLayer::default());
        for _ in 0..100 {
            assert_eq!(
                send(&app, req_with_ip("9.9.9.9")).await.status(),
                StatusCode::OK
            );
        }
        let r = send(&app, req_with_ip("9.9.9.9")).await;
        assert_eq!(r.status(), StatusCode::TOO_MANY_REQUESTS);
    }
}
