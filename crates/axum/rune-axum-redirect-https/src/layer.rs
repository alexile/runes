use http::{
    Request, Response, StatusCode,
    header::{HOST, HeaderValue, LOCATION},
};
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use tower::{Layer, Service};

/// Configuration for the HTTP-to-HTTPS redirect middleware.
///
/// Build with [`RedirectHttps::new()`] and chain methods to adjust the redirect
/// status code or target HTTPS port, then pass to [`RedirectHttpsLayer::new()`].
///
/// # Examples
///
/// ```rust
/// use http::StatusCode;
/// use rune_axum_redirect_https::RedirectHttps;
///
/// // HTTP on :8080 → HTTPS on :8443, 301 for legacy compatibility
/// let config = RedirectHttps::new()
///     .status(StatusCode::MOVED_PERMANENTLY)
///     .https_port(8443);
/// ```
#[derive(Clone, Debug)]
pub struct RedirectHttps {
    status: StatusCode,
    https_port: Option<u16>,
}

impl Default for RedirectHttps {
    fn default() -> Self {
        Self {
            status: StatusCode::PERMANENT_REDIRECT,
            https_port: None,
        }
    }
}

impl RedirectHttps {
    /// Creates a `RedirectHttps` with defaults: `308 Permanent Redirect`, standard HTTPS port.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the redirect status code.
    ///
    /// Defaults to `308 Permanent Redirect`, which preserves the HTTP method.
    /// Use `301 Moved Permanently` when you need compatibility with older
    /// clients that do not support 308.
    ///
    /// > [!WARNING]
    /// > `301` converts POST to GET in many browsers and HTTP clients. Prefer
    /// > `308` unless you have a specific reason to use `301`.
    #[must_use]
    pub const fn status(mut self, status: StatusCode) -> Self {
        self.status = status;
        self
    }

    /// Sets the HTTPS port in the redirect `Location` URL.
    ///
    /// When set, any port in the `Host` header is stripped and replaced with
    /// this value. Useful when HTTP and HTTPS run on non-standard ports (e.g.
    /// `8080` → `8443`). When unset the port is omitted from the URL, which
    /// directs clients to the standard HTTPS port (443).
    #[must_use]
    pub const fn https_port(mut self, port: u16) -> Self {
        self.https_port = Some(port);
        self
    }

    fn is_http<B>(req: &Request<B>) -> bool {
        if let Some(proto) = req.headers().get("x-forwarded-proto") {
            return proto.as_bytes().eq_ignore_ascii_case(b"http");
        }
        req.uri().scheme() == Some(&http::uri::Scheme::HTTP)
    }

    /// The redirect target: `None` without a `Host` header, `Some(Err(()))`
    /// when the `Host` header is not a plain host name or IP literal with an
    /// optional port.
    fn location<B>(&self, req: &Request<B>) -> Option<Result<HeaderValue, ()>> {
        let host = req.headers().get(HOST)?;
        Some(
            host.to_str()
                .ok()
                .and_then(hostname)
                .and_then(|hostname| self.location_for(hostname, req))
                .ok_or(()),
        )
    }

    fn location_for<B>(&self, hostname: &str, req: &Request<B>) -> Option<HeaderValue> {
        let authority = self
            .https_port
            .map_or_else(|| hostname.to_owned(), |port| format!("{hostname}:{port}"));

        let path_and_query = req
            .uri()
            .path_and_query()
            .map_or("/", http::uri::PathAndQuery::as_str);

        HeaderValue::from_str(&format!("https://{authority}{path_and_query}")).ok()
    }
}

/// The host part of a `Host` header, or `None` unless it is a DNS name, an
/// IPv4 address or a bracketed IPv6 literal, optionally followed by a port.
///
/// The value ends up in `Location`, so anything that could change where the
/// URL points (`/`, `@`, `?`, `#`, `\`, ...) is refused rather than passed on.
fn hostname(host: &str) -> Option<&str> {
    let (name, port) = if host.starts_with('[') {
        let end = host.find(']')?;
        let (name, rest) = host.split_at(end + 1);
        let inner = name.get(1..name.len() - 1)?;
        if inner.is_empty()
            || !inner
                .bytes()
                .all(|b| b.is_ascii_hexdigit() || b == b':' || b == b'.')
        {
            return None;
        }
        (
            name,
            if rest.is_empty() {
                None
            } else {
                Some(rest.strip_prefix(':')?)
            },
        )
    } else {
        match host.rsplit_once(':') {
            Some((name, port)) => (name, Some(port)),
            None => (host, None),
        }
    };
    if let Some(port) = port
        && (port.is_empty()
            || !port.bytes().all(|b| b.is_ascii_digit())
            || port.parse::<u16>().is_err())
    {
        return None;
    }
    let plain = |b: u8| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_');
    (name.starts_with('[') || (!name.is_empty() && name.bytes().all(plain))).then_some(name)
}

/// Tower [`Layer`] that redirects HTTP requests to HTTPS.
///
/// Apply with Axum's `.layer()` call. Use [`RedirectHttpsLayer::default()`] for
/// a `308` redirect on standard ports, or [`RedirectHttpsLayer::new()`] to
/// supply a custom [`RedirectHttps`] configuration.
///
/// # Examples
///
/// ```rust,no_run
/// use axum::{routing::get, Router};
/// use rune_axum_redirect_https::RedirectHttpsLayer;
///
/// let app: Router = Router::new()
///     .route("/", get(|| async { "ok" }))
///     .layer(RedirectHttpsLayer::default());
/// ```
#[derive(Clone, Debug, Default)]
pub struct RedirectHttpsLayer {
    config: RedirectHttps,
}

impl RedirectHttpsLayer {
    /// Creates a `RedirectHttpsLayer` from a custom [`RedirectHttps`] configuration.
    #[must_use]
    pub const fn new(config: RedirectHttps) -> Self {
        Self { config }
    }
}

impl<S> Layer<S> for RedirectHttpsLayer {
    type Service = RedirectHttpsService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        RedirectHttpsService {
            inner,
            config: self.config.clone(),
        }
    }
}

/// Tower [`Service`] produced by [`RedirectHttpsLayer`].
#[derive(Clone, Debug)]
pub struct RedirectHttpsService<S> {
    inner: S,
    config: RedirectHttps,
}

impl<S, ReqBody, ResBody> Service<Request<ReqBody>> for RedirectHttpsService<S>
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
        if RedirectHttps::is_http(&req)
            && let Some(location) = self.config.location(&req)
        {
            let status = self.config.status;
            return Box::pin(async move {
                let mut response = Response::new(ResBody::default());
                match location {
                    Ok(location) => {
                        *response.status_mut() = status;
                        response.headers_mut().insert(LOCATION, location);
                    }
                    // Never redirect to whatever a forged `Host` says.
                    Err(()) => *response.status_mut() = StatusCode::BAD_REQUEST,
                }
                Ok(response)
            });
        }
        Box::pin(self.inner.call(req))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{Router, body::Body, routing::get};
    use http::StatusCode;
    use tower::ServiceExt;

    fn build_app(config: RedirectHttps) -> Router {
        Router::new()
            .route("/", get(|| async { "ok" }))
            .layer(RedirectHttpsLayer::new(config))
    }

    async fn send(app: Router, req: http::Request<Body>) -> http::Response<Body> {
        app.oneshot(req).await.unwrap()
    }

    fn forwarded_request(proto: &str, uri: &str) -> http::Request<Body> {
        http::Request::builder()
            .uri(uri)
            .header(HOST, "example.com")
            .header("x-forwarded-proto", proto)
            .body(Body::empty())
            .unwrap()
    }

    #[tokio::test]
    async fn redirects_on_x_forwarded_proto_http() {
        let response = send(
            build_app(RedirectHttps::new()),
            forwarded_request("http", "/path?q=1"),
        )
        .await;

        assert_eq!(response.status(), StatusCode::PERMANENT_REDIRECT);
        assert_eq!(
            response.headers()["location"],
            "https://example.com/path?q=1"
        );
    }

    #[tokio::test]
    async fn passes_through_on_x_forwarded_proto_https() {
        let response = send(
            build_app(RedirectHttps::new()),
            forwarded_request("https", "/"),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn redirects_on_http_uri_scheme() {
        let req = http::Request::builder()
            .uri("http://example.com/page")
            .header(HOST, "example.com")
            .body(Body::empty())
            .unwrap();
        let response = send(build_app(RedirectHttps::new()), req).await;

        assert_eq!(response.status(), StatusCode::PERMANENT_REDIRECT);
        assert_eq!(response.headers()["location"], "https://example.com/page");
    }

    #[tokio::test]
    async fn passes_through_when_no_scheme_indicator() {
        let req = http::Request::builder()
            .uri("/")
            .header(HOST, "example.com")
            .body(Body::empty())
            .unwrap();
        let response = send(build_app(RedirectHttps::new()), req).await;
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn passes_through_when_no_host_header() {
        let req = http::Request::builder()
            .uri("/")
            .header("x-forwarded-proto", "http")
            .body(Body::empty())
            .unwrap();
        let response = send(build_app(RedirectHttps::new()), req).await;
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn custom_status_301() {
        let config = RedirectHttps::new().status(StatusCode::MOVED_PERMANENTLY);
        let response = send(build_app(config), forwarded_request("http", "/")).await;
        assert_eq!(response.status(), StatusCode::MOVED_PERMANENTLY);
    }

    #[tokio::test]
    async fn strips_http_port_from_host() {
        let req = http::Request::builder()
            .uri("/path")
            .header(HOST, "example.com:80")
            .header("x-forwarded-proto", "http")
            .body(Body::empty())
            .unwrap();
        let response = send(build_app(RedirectHttps::new()), req).await;
        assert_eq!(response.headers()["location"], "https://example.com/path");
    }

    #[tokio::test]
    async fn custom_https_port() {
        let config = RedirectHttps::new().https_port(8443);
        let req = http::Request::builder()
            .uri("/path")
            .header(HOST, "example.com:8080")
            .header("x-forwarded-proto", "http")
            .body(Body::empty())
            .unwrap();
        let response = send(build_app(config), req).await;
        assert_eq!(
            response.headers()["location"],
            "https://example.com:8443/path"
        );
    }

    #[tokio::test]
    async fn default_layer_uses_308() {
        let app = Router::new()
            .route("/", get(|| async { "ok" }))
            .layer(RedirectHttpsLayer::default());
        let response = send(app, forwarded_request("http", "/")).await;
        assert_eq!(response.status(), StatusCode::PERMANENT_REDIRECT);
    }

    #[tokio::test]
    async fn hostile_host_header_never_becomes_a_redirect() {
        for host in [
            "//evil.example",
            "evil.example/",
            "good.example@evil.example",
            "evil.example#",
            "evil.example?",
            "good.example\\@evil.example",
            "",
            ":443",
            "[::1",
            "example.com:99999",
        ] {
            let req = http::Request::builder()
                .uri("/path")
                .header(HOST, host)
                .header("x-forwarded-proto", "http")
                .body(Body::empty())
                .unwrap();
            let response = send(build_app(RedirectHttps::new()), req).await;
            assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{host}");
            assert!(response.headers().get("location").is_none(), "{host}");
        }
    }

    #[tokio::test]
    async fn ip_literal_hosts_redirect() {
        for (host, location) in [
            ("[::1]:8080", "https://[::1]/"),
            ("[2001:db8::1]", "https://[2001:db8::1]/"),
            ("127.0.0.1:80", "https://127.0.0.1/"),
            ("Example.COM", "https://Example.COM/"),
        ] {
            let req = http::Request::builder()
                .uri("/")
                .header(HOST, host)
                .header("x-forwarded-proto", "http")
                .body(Body::empty())
                .unwrap();
            let response = send(build_app(RedirectHttps::new()), req).await;
            assert_eq!(response.headers()["location"], location, "{host}");
        }
    }
}
