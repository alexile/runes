//! Regression tests for the classic CORS misconfigurations, one per item,
//! run end to end through an Axum router.

#![allow(clippy::unwrap_used, clippy::panic, reason = "test helpers fail loudly")]

use std::time::Duration;

use axum::{Router, body::Body, http::StatusCode, routing::get};
use http::{HeaderName, Method, Request, Response, header};
use rune_axum_cors::{Cors, CorsLayer, Error, Rejection, Severity, WeaknessKind};
use tower::ServiceExt;

const APP: &str = "https://app.example.com";

fn router(layer: CorsLayer) -> Router {
    Router::new()
        .route("/", get(|| async { "ok" }).put(|| async { "put" }))
        .route(
            "/boom",
            get(|req: Request<Body>| async move {
                // An error path that blindly reflects the request origin.
                let origin = req
                    .headers()
                    .get(header::ORIGIN)
                    .cloned()
                    .unwrap_or(http::HeaderValue::from_static("*"));
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    [
                        (header::ACCESS_CONTROL_ALLOW_ORIGIN, origin),
                        (
                            header::ACCESS_CONTROL_ALLOW_CREDENTIALS,
                            http::HeaderValue::from_static("true"),
                        ),
                        (
                            header::ACCESS_CONTROL_ALLOW_HEADERS,
                            http::HeaderValue::from_static("*"),
                        ),
                    ],
                    "failed",
                )
            }),
        )
        .route("/public/stats", get(|| async { "42" }))
        .route("/admin/users", get(|| async { "secret" }))
        .layer(layer)
}

fn app(cors: Cors) -> Router {
    router(CorsLayer::new(cors).unwrap())
}

fn policy() -> Cors {
    Cors::new()
        .site("https://example.com")
        .allow_origin(APP)
        .allow_origin("https://*.tenants.example.com")
        .allow_credentials(true)
        .allow_methods([Method::GET, Method::PUT])
        .allow_headers([HeaderName::from_static("content-type")])
}

fn get_from(path: &str, origin: &str) -> Request<Body> {
    Request::builder()
        .uri(path)
        .header(header::ORIGIN, origin)
        .body(Body::empty())
        .unwrap()
}

fn preflight(path: &str, origin: &str, method: &str) -> http::request::Builder {
    Request::builder()
        .method(Method::OPTIONS)
        .uri(path)
        .header(header::ORIGIN, origin)
        .header(header::ACCESS_CONTROL_REQUEST_METHOD, method)
}

fn h<'a>(res: &'a Response<Body>, name: &str) -> Option<&'a str> {
    res.headers().get(name).and_then(|v| v.to_str().ok())
}

async fn send(app: Router, req: Request<Body>) -> Response<Body> {
    app.oneshot(req).await.unwrap()
}

async fn granted(app: &Router, origin: &str) -> bool {
    let res = send(app.clone(), get_from("/", origin)).await;
    let actual = h(&res, "access-control-allow-origin").is_some();
    let res = send(
        app.clone(),
        preflight("/", origin, "GET").body(Body::empty()).unwrap(),
    )
    .await;
    let pre = h(&res, "access-control-allow-origin").is_some();
    assert_eq!(actual, pre, "actual and preflight disagree for {origin}");
    actual
}

fn rejected(cors: Cors) -> Vec<WeaknessKind> {
    match CorsLayer::new(cors) {
        Err(Error::Insecure { weaknesses }) => weaknesses.iter().map(|w| w.kind).collect(),
        other => panic!("expected an insecure policy, got {other:?}"),
    }
}

#[tokio::test]
async fn arbitrary_origins_are_never_reflected() {
    let app = app(policy());
    for origin in ["https://evil.example", "https://attacker.net", "http://x"] {
        assert!(!granted(&app, origin).await, "{origin}");
    }
    let k = rejected(
        Cors::new()
            .allow_origin_fn(|_| true)
            .allow_credentials(true),
    );
    assert!(k.contains(&WeaknessKind::OriginReflection));
}

#[tokio::test]
async fn null_origin_is_not_allowed() {
    assert!(!granted(&app(policy()), "null").await);
    // Not even through a predicate that says yes to everything else.
    let cors = Cors::new()
        .site("https://example.com")
        .allow_origin_fn(|o| o == APP);
    assert!(!granted(&app(cors), "null").await);
    assert!(rejected(Cors::new().allow_origin("null")).contains(&WeaknessKind::NullOrigin));
}

#[tokio::test]
async fn lookalike_domains_do_not_match() {
    let app = app(policy());
    for origin in [
        "https://evil-example.com",
        "https://evilexample.com",
        "https://example.com.evil.net",
        "https://app.example.com.evil.net",
        "https://appexample.com",
        "https://evil-tenants.example.com",
        "https://tenants.example.com.evil.net",
        "https://xtenants.example.com",
    ] {
        assert!(!granted(&app, origin).await, "{origin}");
    }
    assert!(granted(&app, "https://acme.tenants.example.com").await);
    let k = rejected(
        Cors::new()
            .site("https://example.com")
            .allow_origin_fn(|o| o.ends_with("example.com"))
            .allow_credentials(true),
    );
    assert!(k.contains(&WeaknessKind::UnanchoredAllowlist));
}

#[test]
fn wildcard_with_credentials_is_refused_whatever_the_threshold() {
    let k = rejected(
        Cors::new()
            .allow_any_origin()
            .allow_credentials(true)
            .reject_at(Severity::Critical),
    );
    assert_eq!(k, [WeaknessKind::WildcardWithCredentials]);
}

#[tokio::test]
async fn vary_origin_on_every_origin_dependent_response() {
    let app = app(policy());
    for req in [
        get_from("/", APP),
        get_from("/", "https://evil.example"),
        Request::builder().uri("/").body(Body::empty()).unwrap(),
        get_from("/boom", APP),
        get_from("/missing", APP),
    ] {
        let res = send(app.clone(), req).await;
        assert_eq!(h(&res, "vary"), Some("Origin"));
    }
}

#[tokio::test]
async fn preflights_cannot_poison_a_cache() {
    let vary = "Origin, Access-Control-Request-Method, Access-Control-Request-Headers, \
                Access-Control-Request-Private-Network";
    let app = app(policy().max_age(Duration::from_secs(365 * 86_400)));
    let ok = send(
        app.clone(),
        preflight("/", APP, "PUT").body(Body::empty()).unwrap(),
    )
    .await;
    assert_eq!(ok.status(), StatusCode::NO_CONTENT);
    assert_eq!(h(&ok, "vary"), Some(vary));
    assert_eq!(h(&ok, "access-control-max-age"), Some("7200"));
    let denied = send(
        app,
        preflight("/", "https://evil.example", "PUT")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(h(&denied, "vary"), Some(vary));
    assert_eq!(h(&denied, "access-control-max-age"), None);
}

#[tokio::test]
async fn credentials_never_allow_every_header() {
    let cors = Cors::new()
        .allow_origin(APP)
        .allow_credentials(true)
        .allow_headers([HeaderName::from_static("*")]);
    let res = send(
        app(cors),
        preflight("/", APP, "GET")
            .header(header::ACCESS_CONTROL_REQUEST_HEADERS, "x-anything")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
    assert_eq!(h(&res, "access-control-allow-headers"), None);

    // Requested headers are not mirrored.
    let res = send(
        app(policy()),
        preflight("/", APP, "GET")
            .header(header::ACCESS_CONTROL_REQUEST_HEADERS, "Content-Type")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(
        h(&res, "access-control-allow-headers"),
        Some("content-type")
    );
}

#[tokio::test]
async fn non_canonical_origins_do_not_match() {
    let app = app(policy());
    for origin in [
        "HTTPS://app.example.com",
        "https://APP.example.com",
        "https://app.example.com:443",
        "http://app.example.com",
        "https://app.example.com:8443",
        "wss://app.example.com",
        "https://app.example.com/",
        "https://user@app.example.com",
        "https://ACME.tenants.example.com",
    ] {
        assert!(!granted(&app, origin).await, "{origin}");
    }
}

#[tokio::test]
async fn trailing_dots_do_not_match() {
    let app = app(policy());
    for origin in [
        "https://app.example.com.",
        "https://acme.tenants.example.com.",
        "https://acme..tenants.example.com",
    ] {
        assert!(!granted(&app, origin).await, "{origin}");
    }
    assert!(matches!(
        CorsLayer::new(Cors::new().allow_origin("https://app.example.com.")),
        Err(Error::InvalidInput { .. })
    ));
}

#[tokio::test]
async fn idn_origins_use_punycode() {
    assert!(matches!(
        CorsLayer::new(Cors::new().allow_origin("https://bücher.example")),
        Err(Error::InvalidInput { .. })
    ));
    let app = app(Cors::new().allow_origin("https://xn--bcher-kva.example"));
    assert!(granted(&app, "https://xn--bcher-kva.example").await);
    // A different punycode label (a homograph) is a different origin.
    assert!(!granted(&app, "https://xn--bcher-kxa.example").await);
}

#[tokio::test]
async fn private_network_access() {
    let pna = |origin: &str| {
        preflight("/", origin, "GET")
            .header("access-control-request-private-network", "true")
            .body(Body::empty())
            .unwrap()
    };
    // Off: the preflight is refused outright.
    let res = send(app(policy()), pna(APP)).await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
    assert_eq!(h(&res, "access-control-allow-private-network"), None);

    let on = app(policy().allow_private_network(true));
    let res = send(on.clone(), pna(APP)).await;
    assert_eq!(res.status(), StatusCode::NO_CONTENT);
    assert_eq!(
        h(&res, "access-control-allow-private-network"),
        Some("true")
    );
    // Wildcard-matched origins never get it.
    let res = send(on, pna("https://acme.tenants.example.com")).await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
    assert_eq!(h(&res, "access-control-allow-origin"), None);

    let k = rejected(Cors::new().allow_any_origin().allow_private_network(true));
    assert!(k.contains(&WeaknessKind::PrivateNetworkAccess));
}

#[tokio::test]
async fn error_paths_cannot_grant_access() {
    let app = app(policy());
    let res = send(app.clone(), get_from("/boom", "https://evil.example")).await;
    assert_eq!(res.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(h(&res, "access-control-allow-origin"), None);
    assert_eq!(h(&res, "access-control-allow-credentials"), None);
    assert_eq!(h(&res, "access-control-allow-headers"), None);
    let res = send(app.clone(), get_from("/boom", APP)).await;
    assert_eq!(h(&res, "access-control-allow-origin"), Some(APP));
    assert_eq!(h(&res, "access-control-allow-headers"), None);

    // Malformed preflights are refused here, not handed to the router.
    let mut dup = preflight("/", APP, "PUT").body(Body::empty()).unwrap();
    dup.headers_mut()
        .append(header::ORIGIN, "https://evil.example".parse().unwrap());
    let mut bad_method = preflight("/", APP, "PUT").body(Body::empty()).unwrap();
    bad_method.headers_mut().append(
        header::ACCESS_CONTROL_REQUEST_METHOD,
        "GET".parse().unwrap(),
    );
    let opaque = preflight("/", APP, "PUT")
        .header(
            header::ACCESS_CONTROL_REQUEST_HEADERS,
            http::HeaderValue::from_bytes(b"x-\xff").unwrap(),
        )
        .body(Body::empty())
        .unwrap();
    let missing_route = preflight("/missing", "https://evil.example", "GET")
        .body(Body::empty())
        .unwrap();
    for req in [dup, bad_method, opaque, missing_route] {
        let res = send(app.clone(), req).await;
        assert_eq!(res.status(), StatusCode::FORBIDDEN);
        assert_eq!(h(&res, "access-control-allow-origin"), None);
    }
}

#[tokio::test]
async fn omitted_headers_rejection_mode() {
    let app = app(policy().rejection(Rejection::OmitHeaders));
    let res = send(
        app,
        preflight("/", "https://evil.example", "PUT")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(res.status(), StatusCode::NO_CONTENT);
    assert_eq!(h(&res, "access-control-allow-origin"), None);
    assert_eq!(h(&res, "access-control-allow-methods"), None);
}

#[tokio::test]
async fn per_route_policies() {
    let layer = CorsLayer::new(policy())
        .unwrap()
        .route("/public", Cors::new().allow_any_origin())
        .unwrap()
        .route(
            "/admin",
            Cors::new()
                .allow_origin("https://admin.example.com")
                .allow_credentials(true),
        )
        .unwrap();
    assert!(layer.route_report("/public/").is_some());
    assert!(layer.route_report("/nope").is_none());
    let app = router(layer);
    let evil = "https://evil.example";

    let res = send(app.clone(), get_from("/public/stats", evil)).await;
    assert_eq!(h(&res, "access-control-allow-origin"), Some("*"));
    assert_eq!(h(&res, "vary"), None);

    let res = send(app.clone(), get_from("/admin/users", APP)).await;
    assert_eq!(h(&res, "access-control-allow-origin"), None);
    let res = send(
        app.clone(),
        get_from("/admin/users", "https://admin.example.com"),
    )
    .await;
    assert_eq!(
        h(&res, "access-control-allow-origin"),
        Some("https://admin.example.com")
    );

    // Paths a normalising proxy would map onto /admin get nothing.
    for path in ["//admin/users", "/public/../admin/users", "/%61dmin/users"] {
        let res = send(app.clone(), get_from(path, evil)).await;
        assert_eq!(h(&res, "access-control-allow-origin"), None, "{path}");
    }
    let res = send(
        app.clone(),
        preflight("/public/../admin/users", evil, "GET")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN);

    // Overrides are audited too.
    assert!(matches!(
        CorsLayer::new(policy())
            .unwrap()
            .route("/x", Cors::new().allow_any_origin().allow_credentials(true)),
        Err(Error::Insecure { .. })
    ));
}

#[tokio::test]
async fn dynamic_origins_through_the_predicate() {
    use std::collections::HashSet;
    use std::sync::{Arc, RwLock};

    let tenants = Arc::new(RwLock::new(HashSet::from([
        "https://acme.example".to_owned()
    ])));
    let lookup = Arc::clone(&tenants);
    let cors = Cors::new()
        .site("https://example.com")
        .allow_origin_fn(move |o| lookup.read().is_ok_and(|s| s.contains(o)))
        .allow_credentials(true);
    let app = app(cors);
    assert!(granted(&app, "https://acme.example").await);
    assert!(!granted(&app, "https://globex.example").await);
    tenants
        .write()
        .unwrap()
        .insert("https://globex.example".to_owned());
    assert!(granted(&app, "https://globex.example").await);
}
