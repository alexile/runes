use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use http::{HeaderMap, HeaderName, Request, Response};
use tower::{Layer, Service};

use crate::Error;
use crate::config::{Compiled, Helmet, RequestInfo};
use crate::csp::CspNonce;

type BoxFuture<T> = Pin<Box<dyn Future<Output = T> + Send>>;

/// Tower [`Layer`] that sets security headers on every response.
///
/// Build it from a [`Helmet`] with [`HelmetLayer::new`] (which validates the
/// configuration) or take the defaults with [`HelmetLayer::default`].
///
/// For each request the layer:
///
/// 1. generates a [`CspNonce`] when the policy has a nonce slot and puts
///    it in the request extensions (an outer helmet's nonce is reused);
/// 2. runs the inner service;
/// 3. sets the configured headers that the handler did not set itself
///    (unless [`Helmet::overwrite`] is on), honouring a [`HelmetOverride`]
///    found in the response extensions, and removes `Server` /
///    `X-Powered-By`.
///
/// # Examples
///
/// ```rust
/// use axum::{routing::get, Router};
/// use rune_axum_helmet::{Helmet, HelmetLayer};
///
/// let app: Router = Router::new()
///     .route("/", get(|| async { "ok" }))
///     .layer(HelmetLayer::new(Helmet::new().no_hsts())?);
/// # Ok::<(), rune_axum_helmet::Error>(())
/// ```
#[derive(Clone, Debug)]
pub struct HelmetLayer {
    compiled: Arc<Compiled>,
}

impl HelmetLayer {
    /// Validates `helmet` and builds the layer.
    ///
    /// # Errors
    ///
    /// See [`Helmet::validate`].
    pub fn new(helmet: Helmet) -> Result<Self, Error> {
        Ok(Self {
            compiled: Arc::new(helmet.compile()?),
        })
    }
}

impl Default for HelmetLayer {
    /// The layer for [`Helmet::new`].
    fn default() -> Self {
        // The defaults are fixed and covered by tests, so this never falls
        // back in practice.
        let compiled = Helmet::new()
            .compile()
            .unwrap_or_else(|_| Compiled::empty());
        Self {
            compiled: Arc::new(compiled),
        }
    }
}

impl<S> Layer<S> for HelmetLayer {
    type Service = HelmetService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        HelmetService {
            inner,
            compiled: Arc::clone(&self.compiled),
        }
    }
}

/// Tower [`Service`] produced by [`HelmetLayer`].
#[derive(Clone, Debug)]
pub struct HelmetService<S> {
    inner: S,
    compiled: Arc<Compiled>,
}

impl<S, ReqBody, ResBody> Service<Request<ReqBody>> for HelmetService<S>
where
    S: Service<Request<ReqBody>, Response = Response<ResBody>>,
    S::Future: Send + 'static,
    S::Error: Send + 'static,
{
    type Response = Response<ResBody>;
    type Error = S::Error;
    type Future = BoxFuture<Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: Request<ReqBody>) -> Self::Future {
        let compiled = Arc::clone(&self.compiled);
        let nonce = req.extensions().get::<CspNonce>().cloned().or_else(|| {
            compiled.uses_nonce().then(|| {
                let nonce = CspNonce::generate();
                req.extensions_mut().insert(nonce.clone());
                nonce
            })
        });
        let info = RequestInfo {
            nonce,
            https: request_is_https(req.headers(), req.uri()),
        };
        let future = self.inner.call(req);
        Box::pin(async move {
            let mut response = future.await?;
            let route = response.extensions().get::<HelmetOverride>().cloned();
            let headers = response.headers_mut();
            match route.as_ref().map(|o| &*o.0) {
                None => compiled.apply(headers, &info, &[]),
                Some(Override::Skip(skip)) => compiled.apply(headers, &info, skip),
                Some(Override::Replace(other)) => other.apply(headers, &info, &[]),
                Some(Override::Disable) => {}
            }
            Ok(response)
        })
    }
}

/// Whether the request came over HTTPS, as far as it tells, from every
/// `Forwarded: proto=` and `X-Forwarded-Proto` value and an absolute URI.
///
/// Any HTTPS signal wins. The client can write these headers too, and a
/// proxy that appends rather than replaces leaves the client's value in
/// front, so a single `http` must not be enough to drop HSTS. The reverse
/// mistake is harmless: browsers ignore HSTS sent over plain HTTP.
fn request_is_https(headers: &HeaderMap, uri: &http::Uri) -> Option<bool> {
    let forwarded = headers
        .get_all("forwarded")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split([',', ';']))
        .filter_map(|pair| {
            let (key, value) = pair.split_once('=')?;
            key.trim()
                .eq_ignore_ascii_case("proto")
                .then(|| value.trim().trim_matches('"'))
        });
    let x_forwarded = headers
        .get_all("x-forwarded-proto")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .map(str::trim);
    let mut verdict = None;
    for proto in forwarded.chain(x_forwarded).chain(uri.scheme_str()) {
        if proto.eq_ignore_ascii_case("https") || proto.eq_ignore_ascii_case("wss") {
            return Some(true);
        }
        if proto.eq_ignore_ascii_case("http") || proto.eq_ignore_ascii_case("ws") {
            verdict = Some(false);
        }
    }
    verdict
}

/// Changes what [`HelmetLayer`] does for one route or response.
///
/// The layer looks for this value in the **response** extensions. Put it
/// there from a handler (axum's `Extension` is a response part), or wrap a
/// route with it, since it is also a [`Layer`]:
///
/// ```rust
/// use axum::{Extension, Router, routing::get};
/// use http::header::X_FRAME_OPTIONS;
/// use rune_axum_helmet::{CspBuilder, Helmet, HelmetLayer, HelmetOverride};
///
/// // A widget other sites may frame: different CSP, no X-Frame-Options.
/// let embed = HelmetOverride::replace(
///     Helmet::new()
///         .no_frame_options()
///         .csp_from(CspBuilder::recommended().frame_ancestors(&["https:"])),
/// )?;
///
/// let app: Router = Router::new()
///     .route("/", get(|| async { "home" }))
///     .route("/widget", get(|| async { "widget" }).layer(embed))
///     .route(
///         "/legacy",
///         get(|| async {
///             (Extension(HelmetOverride::skip([X_FRAME_OPTIONS])), "legacy")
///         }),
///     )
///     .layer(HelmetLayer::default());
/// # Ok::<(), rune_axum_helmet::Error>(())
/// ```
///
/// When both a route layer and the handler set one, the handler's wins.
#[derive(Clone, Debug)]
pub struct HelmetOverride(Arc<Override>);

#[derive(Debug)]
enum Override {
    Disable,
    Skip(Vec<HeaderName>),
    Replace(Compiled),
}

impl HelmetOverride {
    /// Leaves the response alone: no headers set, none removed.
    #[must_use]
    pub fn disable() -> Self {
        Self(Arc::new(Override::Disable))
    }

    /// Applies the layer's configuration except for `headers`, which are
    /// neither set nor removed.
    #[must_use]
    pub fn skip(headers: impl IntoIterator<Item = HeaderName>) -> Self {
        Self(Arc::new(Override::Skip(headers.into_iter().collect())))
    }

    /// Applies `helmet` instead of the layer's configuration. A nonce slot
    /// in its CSP reuses the request's [`CspNonce`] when the layer made one.
    ///
    /// # Errors
    ///
    /// See [`Helmet::validate`].
    pub fn replace(helmet: Helmet) -> Result<Self, Error> {
        Ok(Self(Arc::new(Override::Replace(helmet.compile()?))))
    }
}

impl<S> Layer<S> for HelmetOverride {
    type Service = HelmetOverrideService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        HelmetOverrideService {
            inner,
            route: self.clone(),
        }
    }
}

/// Tower [`Service`] produced by using [`HelmetOverride`] as a layer.
#[derive(Clone, Debug)]
pub struct HelmetOverrideService<S> {
    inner: S,
    route: HelmetOverride,
}

impl<S, ReqBody, ResBody> Service<Request<ReqBody>> for HelmetOverrideService<S>
where
    S: Service<Request<ReqBody>, Response = Response<ResBody>>,
    S::Future: Send + 'static,
    S::Error: Send + 'static,
{
    type Response = Response<ResBody>;
    type Error = S::Error;
    type Future = BoxFuture<Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<ReqBody>) -> Self::Future {
        let route = self.route.clone();
        let future = self.inner.call(req);
        Box::pin(async move {
            let mut response = future.await?;
            if response.extensions().get::<HelmetOverride>().is_none() {
                response.extensions_mut().insert(route);
            }
            Ok(response)
        })
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;
    use crate::{CrossOriginEmbedderPolicy, CspBuilder, Hsts, HstsMode, XFrameOptions};
    use axum::{Extension, Router, body::Body, response::IntoResponse, routing::get};
    use http::{StatusCode, header};
    use tower::ServiceExt;

    async fn ok() -> &'static str {
        "ok"
    }

    fn app(helmet: Helmet) -> Router {
        Router::new()
            .route("/", get(ok))
            .layer(HelmetLayer::new(helmet).unwrap())
    }

    async fn send(app: Router, req: http::Request<Body>) -> Response<Body> {
        app.oneshot(req).await.unwrap()
    }

    async fn get_root(app: Router) -> Response<Body> {
        send(app, Request::get("/").body(Body::empty()).unwrap()).await
    }

    fn header<'a>(resp: &'a Response<Body>, name: &str) -> Option<&'a str> {
        resp.headers().get(name).map(|v| v.to_str().unwrap())
    }

    #[tokio::test]
    async fn default_headers() {
        let resp = get_root(
            Router::new()
                .route("/", get(ok))
                .layer(HelmetLayer::default()),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let expected = [
            ("x-content-type-options", "nosniff"),
            ("x-xss-protection", "0"),
            ("x-frame-options", "DENY"),
            ("referrer-policy", "strict-origin-when-cross-origin"),
            ("cross-origin-opener-policy", "same-origin"),
            ("cross-origin-resource-policy", "same-origin"),
            ("origin-agent-cluster", "?1"),
            ("x-dns-prefetch-control", "off"),
            ("x-permitted-cross-domain-policies", "none"),
            (
                "strict-transport-security",
                "max-age=31536000; includeSubDomains",
            ),
            ("permissions-policy", crate::DEFAULT_PERMISSIONS_POLICY),
            (
                "content-security-policy",
                "default-src 'self'; base-uri 'self'; font-src 'self' https: data:; \
                 form-action 'self'; frame-ancestors 'none'; img-src 'self' data:; \
                 object-src 'none'; script-src 'self'; script-src-attr 'none'; \
                 style-src 'self' https: 'unsafe-inline'; upgrade-insecure-requests",
            ),
        ];
        for (name, value) in expected {
            assert_eq!(header(&resp, name), Some(value), "{name}");
        }
        for absent in [
            "cross-origin-embedder-policy",
            "content-security-policy-report-only",
            "reporting-endpoints",
        ] {
            assert!(header(&resp, absent).is_none(), "{absent}");
        }
        assert_eq!(
            resp.headers().len(),
            expected.len() + 2,
            "plus content-type and content-length"
        );
    }

    #[tokio::test]
    async fn empty_sets_nothing() {
        let resp = get_root(app(Helmet::empty())).await;
        assert_eq!(resp.headers().len(), 2, "{:?}", resp.headers());
    }

    #[tokio::test]
    async fn removes_server_and_powered_by() {
        let handler = || async { ([("server", "nginx"), ("x-powered-by", "PHP")], "ok") };
        let router = Router::new().route("/", get(handler));
        let resp = get_root(router.clone().layer(HelmetLayer::default())).await;
        assert!(header(&resp, "server").is_none());
        assert!(header(&resp, "x-powered-by").is_none());

        let keep = Helmet::new().keep_header(&header::SERVER);
        let resp = get_root(router.layer(HelmetLayer::new(keep).unwrap())).await;
        assert_eq!(header(&resp, "server"), Some("nginx"));
        assert!(header(&resp, "x-powered-by").is_none());
    }

    #[tokio::test]
    async fn handler_headers_win_by_default() {
        let handler = || async { ([("x-frame-options", "SAMEORIGIN")], "ok") };
        let router = Router::new().route("/", get(handler));
        let resp = get_root(router.clone().layer(HelmetLayer::default())).await;
        assert_eq!(header(&resp, "x-frame-options"), Some("SAMEORIGIN"));

        let resp = get_root(router.layer(Helmet::new().overwrite(true).build().unwrap())).await;
        assert_eq!(header(&resp, "x-frame-options"), Some("DENY"));
    }

    #[tokio::test]
    async fn nonce_is_fresh_per_request_and_matches_extension() {
        async fn page(Extension(nonce): Extension<CspNonce>) -> String {
            nonce.to_string()
        }
        let layer = Helmet::new()
            .csp_from(CspBuilder::strict())
            .reporting_endpoint("csp", "/csp")
            .report_only_csp_from(CspBuilder::recommended().script_nonce().report_to("csp"))
            .build()
            .unwrap();
        let router = Router::new().route("/", get(page)).layer(layer);

        let mut seen = HashSet::new();
        for _ in 0..50 {
            let resp = get_root(router.clone()).await;
            let csp = header(&resp, "content-security-policy").unwrap().to_owned();
            let report_only = header(&resp, "content-security-policy-report-only")
                .unwrap()
                .to_owned();
            let body = axum::body::to_bytes(resp.into_body(), 1024).await.unwrap();
            let nonce = String::from_utf8(body.to_vec()).unwrap();
            assert_eq!(nonce.len(), 24);
            let token = format!("'nonce-{nonce}'");
            assert!(
                csp.starts_with(&format!("script-src {token} 'strict-dynamic'")),
                "{csp}"
            );
            assert!(report_only.contains(&token), "{report_only}");
            assert!(seen.insert(nonce), "nonce repeated");
        }
    }

    #[tokio::test]
    async fn no_nonce_extension_without_nonce_slot() {
        async fn page(nonce: Option<Extension<CspNonce>>) -> &'static str {
            if nonce.is_some() { "yes" } else { "no" }
        }
        let resp = get_root(
            Router::new()
                .route("/", get(page))
                .layer(HelmetLayer::default()),
        )
        .await;
        let body = axum::body::to_bytes(resp.into_body(), 64).await.unwrap();
        assert_eq!(&body[..], b"no");
    }

    fn with_proto(header_name: &str, value: &str) -> http::Request<Body> {
        Request::get("/")
            .header(header_name, value)
            .body(Body::empty())
            .unwrap()
    }

    #[tokio::test]
    async fn hsts_skips_plain_http_by_default() {
        let router = app(Helmet::new());
        for (req, sent) in [
            (with_proto("x-forwarded-proto", "http"), false),
            (with_proto("x-forwarded-proto", "https"), true),
            (with_proto("forwarded", "for=1.2.3.4;proto=http"), false),
            (with_proto("forwarded", "proto=\"https\", proto=http"), true),
            (
                Request::get("http://example.com/")
                    .body(Body::empty())
                    .unwrap(),
                false,
            ),
            (
                Request::get("https://example.com/")
                    .body(Body::empty())
                    .unwrap(),
                true,
            ),
            (Request::get("/").body(Body::empty()).unwrap(), true),
        ] {
            let desc = format!("{:?} {:?}", req.uri(), req.headers());
            let resp = send(router.clone(), req).await;
            assert_eq!(
                header(&resp, "strict-transport-security").is_some(),
                sent,
                "{desc}"
            );
        }
    }

    #[tokio::test]
    async fn hsts_is_not_suppressed_by_a_client_chosen_proto() {
        // A proxy that appends to what the client sent leaves the client's
        // value first; it must not talk the layer out of sending HSTS.
        let router = app(Helmet::new());
        for (name, value) in [
            ("forwarded", "proto=http, for=192.0.2.1;proto=https"),
            ("x-forwarded-proto", "http, https"),
        ] {
            let resp = send(router.clone(), with_proto(name, value)).await;
            assert!(
                header(&resp, "strict-transport-security").is_some(),
                "{name}: {value}"
            );
        }
        let req = Request::get("/")
            .header("x-forwarded-proto", "http")
            .header("x-forwarded-proto", "https")
            .body(Body::empty())
            .unwrap();
        let resp = send(router, req).await;
        assert!(header(&resp, "strict-transport-security").is_some());
    }

    #[tokio::test]
    async fn hsts_https_only_and_always() {
        let https_only = app(Helmet::new().hsts(Hsts::new().mode(HstsMode::HttpsOnly)));
        let resp = get_root(https_only.clone()).await;
        assert!(header(&resp, "strict-transport-security").is_none());
        let resp = send(https_only, with_proto("x-forwarded-proto", "https")).await;
        assert!(header(&resp, "strict-transport-security").is_some());

        let always = app(Helmet::new().hsts(Hsts::new().mode(HstsMode::Always)));
        let resp = send(always, with_proto("x-forwarded-proto", "http")).await;
        assert!(header(&resp, "strict-transport-security").is_some());
    }

    #[tokio::test]
    async fn route_layer_override_replaces_config() {
        let embed = HelmetOverride::replace(
            Helmet::new()
                .no_frame_options()
                .csp_from(CspBuilder::recommended().frame_ancestors(&["https:"])),
        )
        .unwrap();
        let router = Router::new()
            .route("/", get(ok))
            .route("/embed", get(ok).layer(embed))
            .layer(HelmetLayer::default());

        let resp = get_root(router.clone()).await;
        assert_eq!(header(&resp, "x-frame-options"), Some("DENY"));

        let resp = send(router, Request::get("/embed").body(Body::empty()).unwrap()).await;
        assert!(header(&resp, "x-frame-options").is_none());
        assert!(
            header(&resp, "content-security-policy")
                .unwrap()
                .contains("frame-ancestors https:")
        );
        assert_eq!(header(&resp, "x-content-type-options"), Some("nosniff"));
    }

    #[tokio::test]
    async fn handler_override_skip_and_disable() {
        let router = Router::new()
            .route(
                "/skip",
                get(|| async {
                    (
                        Extension(HelmetOverride::skip([
                            header::X_FRAME_OPTIONS,
                            header::SERVER,
                        ])),
                        [("server", "custom")],
                        "ok",
                    )
                }),
            )
            .route(
                "/off",
                get(|| async { (Extension(HelmetOverride::disable()), "ok").into_response() }),
            )
            .layer(HelmetLayer::default());

        let resp = send(
            router.clone(),
            Request::get("/skip").body(Body::empty()).unwrap(),
        )
        .await;
        assert!(header(&resp, "x-frame-options").is_none());
        assert_eq!(header(&resp, "server"), Some("custom"));
        assert!(header(&resp, "content-security-policy").is_some());

        let resp = send(router, Request::get("/off").body(Body::empty()).unwrap()).await;
        assert_eq!(resp.headers().len(), 2, "{:?}", resp.headers());
    }

    #[tokio::test]
    async fn handler_override_beats_route_layer() {
        let router = Router::new()
            .route(
                "/",
                get(|| async { (Extension(HelmetOverride::disable()), "ok") })
                    .layer(HelmetOverride::skip([header::X_FRAME_OPTIONS])),
            )
            .layer(HelmetLayer::default());
        let resp = get_root(router).await;
        assert!(header(&resp, "content-security-policy").is_none());
    }

    #[tokio::test]
    async fn override_reuses_request_nonce() {
        async fn page(Extension(nonce): Extension<CspNonce>) -> String {
            nonce.to_string()
        }
        let route = HelmetOverride::replace(
            Helmet::new().csp_from(CspBuilder::recommended().script_nonce()),
        )
        .unwrap();
        let layer = Helmet::new()
            .csp_from(CspBuilder::strict())
            .build()
            .unwrap();
        let router = Router::new()
            .route("/", get(page).layer(route))
            .layer(layer);
        let resp = get_root(router).await;
        let csp = header(&resp, "content-security-policy").unwrap().to_owned();
        let body = axum::body::to_bytes(resp.into_body(), 64).await.unwrap();
        let nonce = String::from_utf8(body.to_vec()).unwrap();
        assert!(
            csp.contains(&format!("script-src 'self' 'nonce-{nonce}'")),
            "{csp}"
        );
    }

    #[tokio::test]
    async fn report_only_coep_and_reporting_endpoints() {
        let helmet = Helmet::new()
            .reporting_endpoint("default", "https://r.example/default")
            .reporting_endpoint("coep", "/reports/coep")
            .report_only_cross_origin_embedder_policy(CrossOriginEmbedderPolicy::RequireCorp)
            .cross_origin_embedder_policy_report_to("coep");
        let resp = get_root(app(helmet)).await;
        assert_eq!(
            header(&resp, "cross-origin-embedder-policy-report-only"),
            Some("require-corp; report-to=\"coep\"")
        );
        assert!(header(&resp, "cross-origin-embedder-policy").is_none());
        assert_eq!(
            header(&resp, "reporting-endpoints"),
            Some("default=\"https://r.example/default\", coep=\"/reports/coep\"")
        );
    }

    #[tokio::test]
    async fn enforced_coep_is_opt_in() {
        let helmet =
            Helmet::new().cross_origin_embedder_policy(CrossOriginEmbedderPolicy::Credentialless);
        let resp = get_root(app(helmet)).await;
        assert_eq!(
            header(&resp, "cross-origin-embedder-policy"),
            Some("credentialless")
        );
    }

    #[tokio::test]
    async fn setters_and_disablers() {
        let helmet = Helmet::new()
            .frame_options(XFrameOptions::SameOrigin)
            .no_content_type_options()
            .no_xss_protection()
            .no_csp()
            .no_hsts()
            .no_permissions_policy()
            .no_referrer_policy()
            .no_cross_origin_opener_policy()
            .no_cross_origin_resource_policy()
            .origin_agent_cluster(false)
            .dns_prefetch_control(true)
            .no_permitted_cross_domain_policies();
        let resp = get_root(app(helmet)).await;
        assert_eq!(header(&resp, "x-frame-options"), Some("SAMEORIGIN"));
        assert_eq!(header(&resp, "x-dns-prefetch-control"), Some("on"));
        assert_eq!(resp.headers().len(), 4, "{:?}", resp.headers());
    }

    #[test]
    fn invalid_config_is_an_error_not_a_header() {
        let err = HelmetLayer::new(Helmet::new().csp("default-src 'self'; scrip-src 'self'"))
            .unwrap_err();
        assert!(matches!(err, Error::UnknownCspDirective { ref name, .. } if name == "scrip-src"));
        assert!(HelmetOverride::replace(Helmet::new().csp("")).is_err());
    }

    #[test]
    fn scheme_detection() {
        let uri: http::Uri = "/".parse().unwrap();
        let mut headers = HeaderMap::new();
        assert_eq!(request_is_https(&headers, &uri), None);
        headers.insert("x-forwarded-proto", "HTTPS, http".parse().unwrap());
        assert_eq!(request_is_https(&headers, &uri), Some(true));
        // Any HTTPS signal wins over a plain-HTTP one.
        headers.insert("forwarded", "for=x; proto=http".parse().unwrap());
        assert_eq!(request_is_https(&headers, &uri), Some(true));
        headers.insert("x-forwarded-proto", "http".parse().unwrap());
        assert_eq!(request_is_https(&headers, &uri), Some(false));
        headers.insert("forwarded", "for=x".parse().unwrap());
        assert_eq!(request_is_https(&headers, &uri), Some(false));
        headers.insert("x-forwarded-proto", "gopher".parse().unwrap());
        assert_eq!(request_is_https(&headers, &uri), None);
    }
}
