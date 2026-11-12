//! End-to-end behaviour of the token-free, origin-only mode.

#![allow(clippy::unwrap_used, reason = "fixture helpers outside #[test] fns")]

use axum::{
    Router,
    body::Body,
    routing::{get, post},
};
use http::{
    Method, Request, Response, StatusCode,
    header::{CACHE_CONTROL, SET_COOKIE},
};
use rune_axum_csrf::{CsrfLayer, CsrfOriginConfig, CsrfRejection};
use tower::ServiceExt;

fn app(layer: CsrfLayer) -> Router {
    Router::new()
        .route("/submit", get(|| async { "page" }).post(|| async { "ok" }))
        .route("/webhooks/pay", post(|| async { "hook" }))
        .route("/hooks/exact", post(|| async { "hook" }))
        .route("/hooks/exact2", post(|| async { "hook" }))
        .layer(layer)
}

fn default_app() -> Router {
    app(CsrfLayer::origin_only())
}

async fn send(app: Router, req: Request<Body>) -> Response<Body> {
    app.oneshot(req).await.unwrap()
}

/// A POST to `https://example.com/submit` (as seen by the server: Host only).
fn post_with(headers: &[(&str, &str)]) -> Request<Body> {
    request(Method::POST, "/submit", headers)
}

fn request(method: Method, path: &str, headers: &[(&str, &str)]) -> Request<Body> {
    let mut b = Request::builder()
        .method(method)
        .uri(path)
        .header("host", "example.com");
    for (k, v) in headers {
        b = b.header(*k, *v);
    }
    b.body(Body::empty()).unwrap()
}

fn rejection(res: &Response<Body>) -> Option<CsrfRejection> {
    res.extensions().get::<CsrfRejection>().copied()
}

async fn assert_ok(app: Router, req: Request<Body>) {
    let res = send(app, req).await;
    assert_eq!(res.status(), StatusCode::OK, "{:?}", rejection(&res));
    assert!(res.headers().get(SET_COOKIE).is_none());
}

async fn assert_rejected(app: Router, req: Request<Body>, reason: CsrfRejection) {
    let res = send(app, req).await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
    assert_eq!(rejection(&res), Some(reason));
    assert_eq!(res.headers()[CACHE_CONTROL], "no-store");
}

// --- modern browsers (Fetch Metadata + Origin) ---

#[tokio::test]
async fn browser_same_origin_post_allowed() {
    assert_ok(
        default_app(),
        post_with(&[
            ("sec-fetch-site", "same-origin"),
            ("origin", "https://example.com"),
        ]),
    )
    .await;
}

#[tokio::test]
async fn browser_user_initiated_navigation_allowed() {
    // Bookmarks and typed URLs send `none` and, for POST resubmits, no usable Origin.
    assert_ok(default_app(), post_with(&[("sec-fetch-site", "none")])).await;
}

#[tokio::test]
async fn browser_cross_site_post_rejected() {
    assert_rejected(
        default_app(),
        post_with(&[
            ("sec-fetch-site", "cross-site"),
            ("origin", "https://evil.example"),
        ]),
        CsrfRejection::CrossOrigin,
    )
    .await;
}

#[tokio::test]
async fn browser_same_site_subdomain_rejected() {
    assert_rejected(
        default_app(),
        post_with(&[
            ("sec-fetch-site", "same-site"),
            ("origin", "https://blog.example.com"),
        ]),
        CsrfRejection::CrossOrigin,
    )
    .await;
}

#[tokio::test]
async fn same_site_subdomain_allowed_when_trusted() {
    let app = app(CsrfLayer::origin(
        CsrfOriginConfig::new().trusted_origin("https://blog.example.com"),
    ));
    assert_ok(
        app,
        post_with(&[
            ("sec-fetch-site", "same-site"),
            ("origin", "https://blog.example.com"),
        ]),
    )
    .await;
}

#[tokio::test]
async fn cross_site_fetch_metadata_without_origin_rejected() {
    let app = app(CsrfLayer::origin(
        CsrfOriginConfig::new().allow_missing_headers(true),
    ));
    assert_rejected(
        app,
        post_with(&[("sec-fetch-site", "cross-site")]),
        CsrfRejection::CrossOrigin,
    )
    .await;
}

#[tokio::test]
async fn fetch_metadata_value_is_case_insensitive() {
    assert_ok(
        default_app(),
        post_with(&[("sec-fetch-site", "Same-Origin")]),
    )
    .await;
}

#[tokio::test]
async fn unknown_fetch_metadata_value_falls_back_to_origin() {
    assert_ok(
        default_app(),
        post_with(&[
            ("sec-fetch-site", "something-new"),
            ("origin", "https://example.com"),
        ]),
    )
    .await;
    assert_rejected(
        default_app(),
        post_with(&[
            ("sec-fetch-site", "something-new"),
            ("origin", "https://evil.example"),
        ]),
        CsrfRejection::CrossOrigin,
    )
    .await;
}

// --- browsers without Fetch Metadata (Origin only) ---

#[tokio::test]
async fn origin_only_same_origin_allowed() {
    assert_ok(
        default_app(),
        post_with(&[("origin", "https://example.com")]),
    )
    .await;
}

#[tokio::test]
async fn origin_only_cross_origin_rejected() {
    for origin in [
        "https://evil.example",
        "https://example.com.evil.example",
        "https://sub.example.com",
        "http://example.com",       // scheme downgrade
        "https://example.com:8443", // other port
    ] {
        assert_rejected(
            default_app(),
            post_with(&[("origin", origin)]),
            CsrfRejection::CrossOrigin,
        )
        .await;
    }
}

#[tokio::test]
async fn null_origin_rejected() {
    assert_rejected(
        default_app(),
        post_with(&[("origin", "null")]),
        CsrfRejection::CrossOrigin,
    )
    .await;
    // Not even `null` as a trusted origin widens anything.
    let app = app(CsrfLayer::origin(
        CsrfOriginConfig::new().trusted_origin("null"),
    ));
    assert_rejected(
        app,
        post_with(&[("origin", "null")]),
        CsrfRejection::CrossOrigin,
    )
    .await;
}

#[tokio::test]
async fn malformed_and_duplicate_origins_rejected() {
    for origin in [
        "example.com",
        "https://",
        "https://user@example.com",
        "https://example.com/path",
    ] {
        assert_rejected(
            default_app(),
            post_with(&[("origin", origin)]),
            CsrfRejection::CrossOrigin,
        )
        .await;
    }
    assert_rejected(
        default_app(),
        post_with(&[
            ("origin", "https://example.com"),
            ("origin", "https://evil.example"),
        ]),
        CsrfRejection::CrossOrigin,
    )
    .await;
}

#[tokio::test]
async fn case_and_default_port_normalised() {
    assert_ok(
        default_app(),
        post_with(&[("origin", "HTTPS://Example.COM")]),
    )
    .await;
    assert_ok(
        default_app(),
        post_with(&[("origin", "https://example.com:443")]),
    )
    .await;

    let mut req = post_with(&[("origin", "https://example.com")]);
    req.headers_mut()
        .insert("host", "EXAMPLE.com:443".parse().unwrap());
    assert_ok(default_app(), req).await;

    let mut req = post_with(&[("origin", "https://example.com:8443")]);
    req.headers_mut()
        .insert("host", "example.com:8443".parse().unwrap());
    assert_ok(default_app(), req).await;
}

#[tokio::test]
async fn trusted_origin_is_normalised() {
    let app = app(CsrfLayer::origin(
        CsrfOriginConfig::new().trusted_origin("HTTPS://App.Example.com:443/"),
    ));
    assert_ok(app, post_with(&[("origin", "https://app.example.com")])).await;
}

#[tokio::test]
async fn plain_http_needs_assume_https_off() {
    assert_rejected(
        default_app(),
        post_with(&[("origin", "http://example.com")]),
        CsrfRejection::CrossOrigin,
    )
    .await;
    let dev = app(CsrfLayer::origin(
        CsrfOriginConfig::new().assume_https(false),
    ));
    assert_ok(dev, post_with(&[("origin", "http://example.com")])).await;
}

#[tokio::test]
async fn absolute_uri_scheme_and_authority_are_used() {
    // HTTP/2 requests carry `:scheme` and `:authority` in the URI and may have no Host.
    let req = Request::builder()
        .method(Method::POST)
        .uri("http://localhost:3000/submit")
        .header("origin", "http://localhost:3000")
        .body(Body::empty())
        .unwrap();
    assert_ok(default_app(), req).await;
}

// --- missing headers ---

#[tokio::test]
async fn missing_headers_rejected_by_default() {
    assert_rejected(default_app(), post_with(&[]), CsrfRejection::MissingOrigin).await;
}

#[tokio::test]
async fn missing_headers_allowed_when_configured() {
    let app = app(CsrfLayer::origin(
        CsrfOriginConfig::new().allow_missing_headers(true),
    ));
    assert_ok(app, post_with(&[])).await;
}

#[tokio::test]
async fn referer_alone_is_not_enough() {
    assert_rejected(
        default_app(),
        post_with(&[("referer", "https://example.com/form")]),
        CsrfRejection::MissingOrigin,
    )
    .await;
}

// --- proxies ---

#[tokio::test]
async fn tls_terminating_proxy_needs_trust() {
    let behind_proxy = || {
        post_with(&[
            ("origin", "https://example.com"),
            ("x-forwarded-proto", "https"),
        ])
    };
    // Plain-HTTP hop: without trust the server sees `http` from assume_https(false).
    let untrusted = app(CsrfLayer::origin(
        CsrfOriginConfig::new().assume_https(false),
    ));
    assert_rejected(untrusted, behind_proxy(), CsrfRejection::CrossOrigin).await;
    let trusted = app(CsrfLayer::origin(
        CsrfOriginConfig::new()
            .assume_https(false)
            .trust_proxy_headers(true),
    ));
    assert_ok(trusted, behind_proxy()).await;
}

#[tokio::test]
async fn proxy_rewriting_host() {
    let req = || {
        let mut r = post_with(&[
            ("origin", "https://www.example.com"),
            ("x-forwarded-host", "www.example.com"),
            ("x-forwarded-proto", "https"),
        ]);
        r.headers_mut()
            .insert("host", "backend.internal:8080".parse().unwrap());
        r
    };
    assert_rejected(default_app(), req(), CsrfRejection::CrossOrigin).await;
    let trusted = app(CsrfLayer::origin(
        CsrfOriginConfig::new().trust_proxy_headers(true),
    ));
    assert_ok(trusted, req()).await;
}

#[tokio::test]
async fn rfc7239_forwarded_header() {
    let mut req = post_with(&[
        ("origin", "https://www.example.com"),
        (
            "forwarded",
            r#"for=192.0.2.1;proto=https;host="www.example.com""#,
        ),
    ]);
    req.headers_mut()
        .insert("host", "10.0.0.5".parse().unwrap());
    let trusted = app(CsrfLayer::origin(
        CsrfOriginConfig::new()
            .assume_https(false)
            .trust_proxy_headers(true),
    ));
    assert_ok(trusted, req).await;
}

#[tokio::test]
async fn forged_proxy_headers_ignored_by_default() {
    let req = post_with(&[
        ("origin", "https://evil.example"),
        ("x-forwarded-host", "evil.example"),
    ]);
    assert_rejected(default_app(), req, CsrfRejection::CrossOrigin).await;
}

// --- methods, exemptions, bypass, status ---

#[tokio::test]
async fn safe_methods_pass_unchecked() {
    for method in [Method::GET, Method::HEAD, Method::OPTIONS, Method::TRACE] {
        let res = send(
            default_app(),
            request(
                method.clone(),
                "/submit",
                &[("origin", "https://evil.example")],
            ),
        )
        .await;
        assert_ne!(res.status(), StatusCode::FORBIDDEN, "{method}");
        assert!(rejection(&res).is_none());
    }
}

#[tokio::test]
async fn every_unsafe_method_checked() {
    let app = Router::new()
        .route(
            "/x",
            post(|| async {})
                .put(|| async {})
                .patch(|| async {})
                .delete(|| async {}),
        )
        .layer(CsrfLayer::origin_only());
    for method in [Method::POST, Method::PUT, Method::PATCH, Method::DELETE] {
        let res = send(
            app.clone(),
            request(method.clone(), "/x", &[("origin", "https://evil.example")]),
        )
        .await;
        assert_eq!(res.status(), StatusCode::FORBIDDEN, "{method}");
    }
}

#[tokio::test]
async fn exempt_paths_and_prefixes() {
    let app = app(CsrfLayer::origin(
        CsrfOriginConfig::new()
            .exempt_prefix("/webhooks/")
            .exempt_path("/hooks/exact"),
    ));
    let evil = [("origin", "https://evil.example")];
    assert_ok(app.clone(), request(Method::POST, "/webhooks/pay", &evil)).await;
    assert_ok(app.clone(), request(Method::POST, "/hooks/exact", &evil)).await;
    assert_rejected(
        app,
        request(Method::POST, "/hooks/exact2", &evil),
        CsrfRejection::CrossOrigin,
    )
    .await;
}

#[tokio::test]
async fn insecure_bypass_hook() {
    let app = app(CsrfLayer::origin(CsrfOriginConfig::new().insecure_bypass(
        |parts| parts.headers.contains_key(http::header::AUTHORIZATION),
    )));
    assert_ok(
        app.clone(),
        post_with(&[
            ("origin", "https://evil.example"),
            ("authorization", "Bearer x"),
        ]),
    )
    .await;
    assert_rejected(
        app,
        post_with(&[("origin", "https://evil.example")]),
        CsrfRejection::CrossOrigin,
    )
    .await;
}

#[tokio::test]
async fn custom_status() {
    let app = app(CsrfLayer::origin(
        CsrfOriginConfig::new().status(StatusCode::BAD_REQUEST),
    ));
    let res = send(app, post_with(&[("origin", "https://evil.example")])).await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    assert_eq!(rejection(&res), Some(CsrfRejection::CrossOrigin));
}

#[tokio::test]
async fn token_mode_still_default() {
    // A bare POST without a token is rejected by the default (token) layer for a
    // token reason, not an origin reason.
    let res = send(
        app(CsrfLayer::default()),
        post_with(&[("origin", "https://example.com")]),
    )
    .await;
    assert_eq!(rejection(&res), Some(CsrfRejection::MissingCookie));
}
