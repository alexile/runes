use crate::client_ip::ClientIpConfig;
use http::{Request, Response, StatusCode};
use rune_cidr::{Cidr, CidrParseError};
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use tower::{Layer, Service};

/// Whether the CIDR list is an allowlist or a blocklist.
///
/// Used with [`IpFilterConfig::mode()`].
#[derive(Clone, Debug)]
pub enum FilterMode {
    /// Only requests from IPs matching a listed CIDR pass; all others are rejected.
    Allowlist,
    /// Requests from IPs matching a listed CIDR are rejected; all others pass.
    Blocklist,
}

/// Configuration for the IP filter middleware.
///
/// Build with [`IpFilterConfig::new()`] and chain methods to add CIDRs, set the filter mode,
/// rejection status, and client IP resolution. Then pass to [`IpFilterLayer::new()`].
///
/// The client IP comes from [`ClientIpConfig`]: by default the socket peer address in the
/// `ConnectInfo<SocketAddr>` extension, never a client-controlled header. A request without
/// that extension is rejected with [`IpFilterConfig::missing_ip_status`] (default
/// `500 Internal Server Error`) in both modes.
///
/// # Examples
///
/// ```rust
/// use http::StatusCode;
/// use rune_axum_ipfilter::{FilterMode, IpFilterConfig};
///
/// // Block two specific ranges
/// let config = IpFilterConfig::new()
///     .mode(FilterMode::Blocklist)
///     .cidr("10.0.0.0/8")?
///     .cidr("172.16.0.0/12")?;
/// # Ok::<(), rune_axum_ipfilter::CidrParseError>(())
/// ```
#[derive(Clone, Debug)]
pub struct IpFilterConfig {
    cidrs: Vec<Cidr>,
    mode: FilterMode,
    status: StatusCode,
    missing_ip_status: StatusCode,
    client_ip: ClientIpConfig,
}

impl Default for IpFilterConfig {
    fn default() -> Self {
        Self {
            cidrs: Vec::new(),
            mode: FilterMode::Blocklist,
            status: StatusCode::FORBIDDEN,
            missing_ip_status: StatusCode::INTERNAL_SERVER_ERROR,
            client_ip: ClientIpConfig::new(),
        }
    }
}

impl IpFilterConfig {
    /// Creates an `IpFilterConfig` with defaults: blocklist mode, empty CIDR list,
    /// `403 Forbidden` rejection, client IP from the socket peer address.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a CIDR range to the filter list.
    ///
    /// Both IPv4 (`"192.168.1.0/24"`) and IPv6 (`"2001:db8::/32"`) notation are accepted.
    /// Call multiple times to add multiple ranges.
    ///
    /// # Errors
    ///
    /// Returns [`CidrParseError`] if `cidr` is not valid CIDR notation.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rune_axum_ipfilter::IpFilterConfig;
    ///
    /// let config = IpFilterConfig::new()
    ///     .cidr("10.0.0.0/8")?
    ///     .cidr("192.168.0.0/16")?
    ///     .cidr("2001:db8::/32")?;
    /// # Ok::<(), rune_axum_ipfilter::CidrParseError>(())
    /// ```
    pub fn cidr(mut self, cidr: &str) -> Result<Self, CidrParseError> {
        self.cidrs.push(Cidr::parse(cidr)?);
        Ok(self)
    }

    /// Sets whether the CIDR list is an allowlist or a blocklist.
    ///
    /// Defaults to [`FilterMode::Blocklist`].
    #[must_use]
    pub const fn mode(mut self, mode: FilterMode) -> Self {
        self.mode = mode;
        self
    }

    /// Sets the HTTP status code returned when a request is rejected.
    ///
    /// Defaults to `403 Forbidden`.
    #[must_use]
    pub const fn status(mut self, status: StatusCode) -> Self {
        self.status = status;
        self
    }

    /// Sets the status returned when the client IP cannot be determined, i.e. when the
    /// `ConnectInfo<SocketAddr>` extension is missing because the server was not started
    /// with `into_make_service_with_connect_info::<SocketAddr>()`.
    ///
    /// Defaults to `500 Internal Server Error`: a deployment mistake, never a bypass.
    #[must_use]
    pub const fn missing_ip_status(mut self, status: StatusCode) -> Self {
        self.missing_ip_status = status;
        self
    }

    /// Sets how the client IP is resolved, e.g. which reverse proxies are trusted.
    ///
    /// Defaults to [`ClientIpConfig::new()`]: the socket peer address only.
    #[must_use]
    pub fn client_ip(mut self, client_ip: ClientIpConfig) -> Self {
        self.client_ip = client_ip;
        self
    }

    /// Returns the rejection status for `req`, or `None` if it may pass.
    fn rejection<B>(&self, req: &Request<B>) -> Option<StatusCode> {
        let Some(ip) = self.client_ip.resolve(req) else {
            return Some(self.missing_ip_status);
        };
        let matched = self.cidrs.iter().any(|cidr| cidr.contains(ip));
        let rejected = match self.mode {
            FilterMode::Allowlist => !matched,
            FilterMode::Blocklist => matched,
        };
        rejected.then_some(self.status)
    }
}

/// Tower [`Layer`] that applies CIDR-based IP allowlist or blocklist filtering.
///
/// Apply with Axum's `.layer()` call. Use [`IpFilterLayer::new()`] with a configured
/// [`IpFilterConfig`] to set your CIDR ranges and filter mode.
///
/// > [!NOTE]
/// > Requests without a `ConnectInfo<SocketAddr>` extension are rejected with
/// > [`IpFilterConfig::missing_ip_status`] regardless of mode.
///
/// # Examples
///
/// ```rust,no_run
/// use axum::{routing::get, Router};
/// use rune_axum_ipfilter::{FilterMode, IpFilterConfig, IpFilterLayer};
///
/// let app: Router = Router::new()
///     .route("/api", get(|| async { "ok" }))
///     .layer(IpFilterLayer::new(
///         IpFilterConfig::new()
///             .mode(FilterMode::Blocklist)
///             .cidr("192.168.1.100/32")?,
///     ));
/// # Ok::<(), rune_axum_ipfilter::CidrParseError>(())
/// ```
#[derive(Clone, Debug)]
pub struct IpFilterLayer {
    config: IpFilterConfig,
}

impl IpFilterLayer {
    /// Creates an `IpFilterLayer` from a custom [`IpFilterConfig`].
    pub const fn new(config: IpFilterConfig) -> Self {
        Self { config }
    }
}

impl<S> Layer<S> for IpFilterLayer {
    type Service = IpFilterService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        IpFilterService {
            inner,
            config: self.config.clone(),
        }
    }
}

/// Tower [`Service`] produced by [`IpFilterLayer`].
#[derive(Clone, Debug)]
pub struct IpFilterService<S> {
    inner: S,
    config: IpFilterConfig,
}

impl<S, ReqBody, ResBody> Service<Request<ReqBody>> for IpFilterService<S>
where
    S: Service<Request<ReqBody>, Response = Response<ResBody>>,
    S::Future: Send + 'static,
    S::Error: Send + 'static,
    ResBody: Default + Send + 'static,
{
    type Response = Response<ResBody>;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<ReqBody>) -> Self::Future {
        if let Some(status) = self.config.rejection(&req) {
            return Box::pin(async move {
                let mut response = Response::new(ResBody::default());
                *response.status_mut() = status;
                Ok(response)
            });
        }

        Box::pin(self.inner.call(req))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ProxyHeader;
    use axum::{Router, body::Body, extract::ConnectInfo, routing::get};
    use http::{HeaderName, StatusCode};
    use std::net::SocketAddr;
    use tower::ServiceExt;

    fn build_app(config: IpFilterConfig) -> Router {
        Router::new()
            .route("/", get(|| async { "ok" }))
            .layer(IpFilterLayer::new(config))
    }

    async fn send(app: Router, req: http::Request<Body>) -> http::Response<Body> {
        app.oneshot(req).await.unwrap()
    }

    fn req_from(peer: &str, headers: &[(&str, &str)]) -> http::Request<Body> {
        let mut builder = http::Request::builder().method("GET").uri("/");
        for (name, value) in headers {
            builder = builder.header(*name, *value);
        }
        let mut req = builder.body(Body::empty()).unwrap();
        let ip: std::net::IpAddr = peer.parse().unwrap();
        req.extensions_mut()
            .insert(ConnectInfo(SocketAddr::new(ip, 40_000)));
        req
    }

    fn req_with_ip(ip: &str) -> http::Request<Body> {
        req_from(ip, &[])
    }

    fn req_bare() -> http::Request<Body> {
        http::Request::builder()
            .method("GET")
            .uri("/")
            .body(Body::empty())
            .unwrap()
    }

    // --- Blocklist mode ---

    #[tokio::test]
    async fn blocklist_blocks_exact_match() {
        let app = build_app(
            IpFilterConfig::new()
                .mode(FilterMode::Blocklist)
                .cidr("1.2.3.4/32")
                .unwrap(),
        );
        let response = send(app, req_with_ip("1.2.3.4")).await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn blocklist_allows_non_matching_ip() {
        let app = build_app(
            IpFilterConfig::new()
                .mode(FilterMode::Blocklist)
                .cidr("1.2.3.4/32")
                .unwrap(),
        );
        let response = send(app, req_with_ip("1.2.3.5")).await;
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn blocklist_blocks_ip_in_subnet() {
        let app = build_app(
            IpFilterConfig::new()
                .mode(FilterMode::Blocklist)
                .cidr("192.168.1.0/24")
                .unwrap(),
        );
        let response = send(app, req_with_ip("192.168.1.100")).await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn blocklist_allows_ip_outside_subnet() {
        let app = build_app(
            IpFilterConfig::new()
                .mode(FilterMode::Blocklist)
                .cidr("192.168.1.0/24")
                .unwrap(),
        );
        let response = send(app, req_with_ip("192.168.2.1")).await;
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn blocklist_empty_list_passes_all() {
        let app = build_app(IpFilterConfig::new().mode(FilterMode::Blocklist));
        let response = send(app, req_with_ip("10.0.0.1")).await;
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn blocklist_multiple_cidrs() {
        let app = build_app(
            IpFilterConfig::new()
                .mode(FilterMode::Blocklist)
                .cidr("10.0.0.0/8")
                .unwrap()
                .cidr("172.16.0.0/12")
                .unwrap(),
        );
        assert_eq!(
            send(app.clone(), req_with_ip("10.1.2.3")).await.status(),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            send(app.clone(), req_with_ip("172.20.5.1")).await.status(),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            send(app.clone(), req_with_ip("192.168.1.1")).await.status(),
            StatusCode::OK
        );
    }

    // --- Allowlist mode ---

    #[tokio::test]
    async fn allowlist_passes_matching_ip() {
        let app = build_app(
            IpFilterConfig::new()
                .mode(FilterMode::Allowlist)
                .cidr("10.0.0.0/8")
                .unwrap(),
        );
        let response = send(app, req_with_ip("10.5.6.7")).await;
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn allowlist_blocks_non_matching_ip() {
        let app = build_app(
            IpFilterConfig::new()
                .mode(FilterMode::Allowlist)
                .cidr("10.0.0.0/8")
                .unwrap(),
        );
        let response = send(app, req_with_ip("8.8.8.8")).await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn allowlist_empty_list_blocks_all_with_ip() {
        let app = build_app(IpFilterConfig::new().mode(FilterMode::Allowlist));
        let response = send(app, req_with_ip("1.2.3.4")).await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    // --- Client IP resolution ---

    #[tokio::test]
    async fn missing_connect_info_fails_closed() {
        for mode in [FilterMode::Allowlist, FilterMode::Blocklist] {
            let app = build_app(IpFilterConfig::new().mode(mode).cidr("10.0.0.0/8").unwrap());
            let response = send(app, req_bare()).await;
            assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        }
        let app =
            build_app(IpFilterConfig::new().missing_ip_status(StatusCode::SERVICE_UNAVAILABLE));
        assert_eq!(
            send(app, req_bare()).await.status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
    }

    #[tokio::test]
    async fn spoofed_xff_is_ignored_by_default() {
        // Allowlist bypass attempt: attacker claims to be in the office range.
        let app = build_app(
            IpFilterConfig::new()
                .mode(FilterMode::Allowlist)
                .cidr("10.0.0.0/8")
                .unwrap(),
        );
        let req = req_from(
            "203.0.113.66",
            &[("x-forwarded-for", "10.1.1.1"), ("x-real-ip", "10.1.1.1")],
        );
        assert_eq!(send(app, req).await.status(), StatusCode::FORBIDDEN);

        // Blocklist evasion attempt: blocked peer claims another address.
        let app = build_app(IpFilterConfig::new().cidr("203.0.113.0/24").unwrap());
        let req = req_from("203.0.113.66", &[("x-forwarded-for", "8.8.8.8")]);
        assert_eq!(send(app, req).await.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn trusted_proxy_chain_is_resolved_from_the_right() {
        let config = IpFilterConfig::new()
            .cidr("5.5.5.5/32")
            .unwrap()
            .client_ip(ClientIpConfig::new().trust_proxy("172.16.0.0/12").unwrap());
        let app = build_app(config);
        // Real client 5.5.5.5 appended by the proxy; spoofed entry on the left.
        let req = req_from(
            "172.16.0.1",
            &[("x-forwarded-for", "8.8.8.8, 5.5.5.5, 172.16.0.2")],
        );
        assert_eq!(send(app.clone(), req).await.status(), StatusCode::FORBIDDEN);
        // Leftmost spoof alone does not get the client blocked.
        let req = req_from("172.16.0.1", &[("x-forwarded-for", "5.5.5.5, 9.9.9.9")]);
        assert_eq!(send(app.clone(), req).await.status(), StatusCode::OK);
        // Header from an untrusted peer is ignored.
        let req = req_from("9.9.9.9", &[("x-forwarded-for", "5.5.5.5")]);
        assert_eq!(send(app, req).await.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn named_header_from_trusted_proxy() {
        let config = IpFilterConfig::new().cidr("9.9.9.9/32").unwrap().client_ip(
            ClientIpConfig::new()
                .trust_proxy("127.0.0.1")
                .unwrap()
                .header(ProxyHeader::Header(HeaderName::from_static("x-real-ip"))),
        );
        let app = build_app(config);
        let req = req_from("127.0.0.1", &[("x-real-ip", "9.9.9.9")]);
        assert_eq!(send(app.clone(), req).await.status(), StatusCode::FORBIDDEN);
        let req = req_from("127.0.0.2", &[("x-real-ip", "9.9.9.9")]);
        assert_eq!(send(app, req).await.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn ipv4_mapped_peer_matches_ipv4_cidr() {
        let app = build_app(IpFilterConfig::new().cidr("192.0.2.0/24").unwrap());
        let response = send(app, req_with_ip("::ffff:192.0.2.10")).await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn custom_rejection_status() {
        let app = build_app(
            IpFilterConfig::new()
                .mode(FilterMode::Blocklist)
                .cidr("1.1.1.1/32")
                .unwrap()
                .status(StatusCode::NOT_FOUND),
        );
        let response = send(app, req_with_ip("1.1.1.1")).await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn slash_zero_matches_all_ipv4() {
        let app = build_app(
            IpFilterConfig::new()
                .mode(FilterMode::Blocklist)
                .cidr("0.0.0.0/0")
                .unwrap(),
        );
        let response = send(app, req_with_ip("8.8.8.8")).await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn ipv6_blocklist() {
        let app = build_app(
            IpFilterConfig::new()
                .mode(FilterMode::Blocklist)
                .cidr("2001:db8::/32")
                .unwrap(),
        );

        let req_blocked = req_with_ip("2001:db8::1");
        assert_eq!(
            send(app.clone(), req_blocked).await.status(),
            StatusCode::FORBIDDEN
        );

        let req_allowed = req_with_ip("2001:db9::1");
        assert_eq!(send(app, req_allowed).await.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn ipv4_not_matched_by_ipv6_cidr() {
        let app = build_app(
            IpFilterConfig::new()
                .mode(FilterMode::Blocklist)
                .cidr("2001:db8::/32")
                .unwrap(),
        );
        let response = send(app, req_with_ip("192.168.1.1")).await;
        assert_eq!(response.status(), StatusCode::OK);
    }
}
