//! End-to-end behaviour through an Axum router.

#![allow(clippy::unwrap_used, reason = "test helpers fail loudly")]

use std::time::Duration;

use axum::{Router, body::Body, routing::get};
use http::{HeaderName, Method, Request, StatusCode, header};
use rune_axum_cors::{Cors, CorsLayer, Error, Severity, WeaknessKind};
use tower::ServiceExt;

const APP: &str = "https://app.example.com";

fn app(cors: Cors) -> Router {
    Router::new()
        .route("/", get(|| async { "ok" }).put(|| async { "put" }))
        .route(
            "/leaky",
            get(|| async {
                (
                    [(header::ACCESS_CONTROL_ALLOW_ORIGIN, "*")],
                    "inner set its own CORS header",
                )
            }),
        )
        .layer(CorsLayer::new(cors).unwrap())
}

fn policy() -> Cors {
    Cors::new()
        .site("https://example.com")
        .allow_origin(APP)
        .allow_credentials(true)
        .allow_methods([Method::GET, Method::PUT])
        .allow_headers([HeaderName::from_static("content-type")])
        .expose_headers([HeaderName::from_static("x-request-id")])
        .max_age(Duration::from_secs(600))
}

fn preflight(origin: &str, method: &str, headers: Option<&str>) -> Request<Body> {
    let mut b = Request::builder()
        .method(Method::OPTIONS)
        .uri("/")
        .header(header::ORIGIN, origin)
        .header(header::ACCESS_CONTROL_REQUEST_METHOD, method);
    if let Some(h) = headers {
        b = b.header(header::ACCESS_CONTROL_REQUEST_HEADERS, h);
    }
    b.body(Body::empty()).unwrap()
}

fn get_from(path: &str, origin: Option<&str>) -> Request<Body> {
    let mut b = Request::builder().uri(path);
    if let Some(o) = origin {
        b = b.header(header::ORIGIN, o);
    }
    b.body(Body::empty()).unwrap()
}

fn h<'a>(res: &'a http::Response<axum::body::Body>, name: &str) -> Option<&'a str> {
    res.headers().get(name).and_then(|v| v.to_str().ok())
}

#[tokio::test]
async fn allowed_preflight_is_answered_without_the_handler() {
    let res = app(policy())
        .oneshot(preflight(APP, "PUT", Some("Content-Type")))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::NO_CONTENT);
    assert_eq!(h(&res, "access-control-allow-origin"), Some(APP));
    assert_eq!(h(&res, "access-control-allow-credentials"), Some("true"));
    assert_eq!(h(&res, "access-control-allow-methods"), Some("GET, PUT"));
    assert_eq!(
        h(&res, "access-control-allow-headers"),
        Some("content-type")
    );
    assert_eq!(h(&res, "access-control-max-age"), Some("600"));
    assert!(h(&res, "vary").unwrap().starts_with("Origin"));
}

#[tokio::test]
async fn refused_preflights() {
    for req in [
        preflight("https://evil.example", "PUT", None),
        preflight(APP, "DELETE", None),
        preflight(APP, "PUT", Some("x-secret")),
        preflight("https://APP.example.com", "PUT", None),
    ] {
        let res = app(policy()).oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::FORBIDDEN);
        assert_eq!(h(&res, "access-control-allow-origin"), None);
    }
    let res = app(policy().deny_status(StatusCode::NO_CONTENT))
        .oneshot(preflight("https://evil.example", "PUT", None))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::NO_CONTENT);
    assert_eq!(h(&res, "access-control-allow-origin"), None);
}

#[tokio::test]
async fn plain_options_reaches_the_router() {
    // No Access-Control-Request-Method: not a preflight.
    let req = Request::builder()
        .method(Method::OPTIONS)
        .uri("/")
        .header(header::ORIGIN, APP)
        .body(Body::empty())
        .unwrap();
    let res = app(policy()).oneshot(req).await.unwrap();
    assert_ne!(res.status(), StatusCode::NO_CONTENT);
    assert_eq!(h(&res, "access-control-allow-origin"), Some(APP));
}

#[tokio::test]
async fn actual_request_from_allowed_origin() {
    let res = app(policy())
        .oneshot(get_from("/", Some(APP)))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(h(&res, "access-control-allow-origin"), Some(APP));
    assert_eq!(h(&res, "access-control-allow-credentials"), Some("true"));
    assert_eq!(
        h(&res, "access-control-expose-headers"),
        Some("x-request-id")
    );
    assert_eq!(h(&res, "vary"), Some("Origin"));
}

#[tokio::test]
async fn actual_request_from_other_origin_gets_no_grant() {
    let res = app(policy())
        .oneshot(get_from("/", Some("https://evil.example")))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(h(&res, "access-control-allow-origin"), None);
    assert_eq!(h(&res, "access-control-allow-credentials"), None);
    assert_eq!(h(&res, "vary"), Some("Origin"));
}

#[tokio::test]
async fn same_origin_request_still_varies() {
    let res = app(policy()).oneshot(get_from("/", None)).await.unwrap();
    assert_eq!(h(&res, "access-control-allow-origin"), None);
    assert_eq!(h(&res, "vary"), Some("Origin"));
}

#[tokio::test]
async fn inner_cors_headers_are_overridden() {
    let res = app(policy())
        .oneshot(get_from("/leaky", Some("https://evil.example")))
        .await
        .unwrap();
    assert_eq!(h(&res, "access-control-allow-origin"), None);
    let res = app(policy())
        .oneshot(get_from("/leaky", Some(APP)))
        .await
        .unwrap();
    assert_eq!(h(&res, "access-control-allow-origin"), Some(APP));
}

#[tokio::test]
async fn public_wildcard() {
    let res = app(Cors::new().allow_any_origin())
        .oneshot(get_from("/", Some("https://anyone.example")))
        .await
        .unwrap();
    assert_eq!(h(&res, "access-control-allow-origin"), Some("*"));
    assert_eq!(h(&res, "access-control-allow-credentials"), None);
    assert_eq!(h(&res, "vary"), None);
}

#[tokio::test]
async fn private_network_preflight() {
    let cors = Cors::new().allow_origin(APP).allow_private_network(true);
    let mut req = preflight(APP, "GET", None);
    req.headers_mut().insert(
        "access-control-request-private-network",
        "true".parse().unwrap(),
    );
    let res = app(cors).oneshot(req).await.unwrap();
    assert_eq!(
        h(&res, "access-control-allow-private-network"),
        Some("true")
    );
}

#[test]
fn dangerous_configs_are_rejected_at_build_time() {
    let insecure = |cors: Cors| match CorsLayer::new(cors) {
        Err(Error::Insecure { weaknesses }) => weaknesses.iter().map(|w| w.kind).collect(),
        other => panic!("expected rejection, got {other:?}"),
    };
    let k: Vec<WeaknessKind> = insecure(Cors::new().allow_origin("*").allow_credentials(true));
    assert_eq!(k, [WeaknessKind::WildcardWithCredentials]);
    let k = insecure(
        Cors::new()
            .allow_origin_fn(|_| true)
            .allow_credentials(true),
    );
    assert!(k.contains(&WeaknessKind::OriginReflection));
    let k = insecure(Cors::new().allow_origin("null"));
    assert!(k.contains(&WeaknessKind::NullOrigin));
    let k = insecure(
        Cors::new()
            .site("https://example.com")
            .allow_origin_fn(|o| o.starts_with("https://example.com")),
    );
    assert!(k.contains(&WeaknessKind::UnanchoredAllowlist));
    let k = insecure(Cors::new().allow_any_origin().allow_private_network(true));
    assert!(k.contains(&WeaknessKind::PrivateNetworkAccess));

    assert!(matches!(
        CorsLayer::new(Cors::new().allow_origin("app.example.com")),
        Err(Error::InvalidOrigin(_))
    ));
}

#[test]
fn waived_weaknesses_stay_in_the_report() {
    let layer = CorsLayer::try_from(Cors::new().allow_any_origin()).unwrap();
    assert_eq!(layer.report().max_severity(), Some(Severity::Informational));
    let findings = layer
        .report()
        .to_findings::<()>(&rune_finding::Location::url("https://example.com/"));
    assert_eq!(findings[0].check_id, "cors.wildcard_origin");
}
