//! Integration tests: Cache-Control is set per config, and conditional
//! requests get 304 / 412 from the validators the handler sets.

#![allow(clippy::unwrap_used, reason = "test helpers fail loudly")]

use std::time::Duration;

use axum::{
    Router,
    body::Body,
    http::{HeaderMap, HeaderName, HeaderValue, Method, Request, StatusCode, header},
    response::{IntoResponse, Response},
    routing::get,
};
use rune_axum_cache::{
    Cache, CacheControl, CacheLayer, EntityTag, HttpDate, Precondition, Validators,
};
use tower::ServiceExt;

const BODY: &str = "the representation";
const MODIFIED: &str = "Sun, 06 Nov 1994 08:49:37 GMT";

fn etag() -> EntityTag {
    EntityTag::from_content(BODY.as_bytes())
}

async fn resource() -> Response {
    let mut headers = HeaderMap::new();
    Validators::new()
        .with_etag(etag())
        .with_last_modified(HttpDate::parse(MODIFIED).unwrap())
        .apply_to(&mut headers);
    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static("text/plain"));
    headers.insert(header::VARY, HeaderValue::from_static("accept-encoding"));
    (headers, BODY).into_response()
}

fn app(config: Cache) -> Router {
    Router::new()
        .route("/doc", get(resource).put(resource).post(resource))
        .route("/plain", get(|| async { "no validators" }))
        .route("/assets/app.js", get(|| async { "js" }))
        .route(
            "/own",
            get(|| async { ([(header::CACHE_CONTROL, "max-age=5")], "own") }),
        )
        .route("/missing", get(|| async { StatusCode::NOT_FOUND }))
        .layer(CacheLayer::new(config))
}

async fn send(app: Router, method: Method, path: &str, headers: &[(HeaderName, &str)]) -> Response {
    let mut req = Request::builder().method(method).uri(path);
    for (name, value) in headers {
        req = req.header(name, *value);
    }
    app.oneshot(req.body(Body::empty()).unwrap()).await.unwrap()
}

async fn get_with(path: &str, headers: &[(HeaderName, &str)]) -> Response {
    send(app(Cache::new()), Method::GET, path, headers).await
}

async fn body_of(res: Response) -> String {
    let bytes = axum::body::to_bytes(res.into_body(), 1 << 16)
        .await
        .unwrap();
    String::from_utf8(bytes.to_vec()).unwrap()
}

#[tokio::test]
async fn sets_default_cache_control_and_passes_body_through() {
    let res = get_with("/doc", &[]).await;
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(res.headers()[header::CACHE_CONTROL], "private, no-cache");
    assert_eq!(res.headers()[header::ETAG], etag().to_string().as_str());
    assert_eq!(body_of(res).await, BODY);
}

#[tokio::test]
async fn matching_if_none_match_gives_empty_304() {
    let tag = etag().to_string();
    let res = get_with("/doc", &[(header::IF_NONE_MATCH, &tag)]).await;
    assert_eq!(res.status(), StatusCode::NOT_MODIFIED);
    let h = res.headers();
    assert_eq!(h[header::ETAG], tag.as_str());
    assert_eq!(h[header::CACHE_CONTROL], "private, no-cache");
    assert_eq!(h[header::VARY], "accept-encoding");
    assert!(!h.contains_key(header::CONTENT_TYPE));
    assert!(!h.contains_key(header::LAST_MODIFIED));
    assert_eq!(body_of(res).await, "");
}

#[tokio::test]
async fn weak_and_listed_tags_match_for_304() {
    let weak = format!("\"other\", W/\"{}\"", etag().tag());
    let res = get_with("/doc", &[(header::IF_NONE_MATCH, &weak)]).await;
    assert_eq!(res.status(), StatusCode::NOT_MODIFIED);
    let res = get_with("/doc", &[(header::IF_NONE_MATCH, "\"other\"")]).await;
    assert_eq!(res.status(), StatusCode::OK);
}

#[tokio::test]
async fn head_requests_are_conditional_too() {
    let res = send(
        app(Cache::new()),
        Method::HEAD,
        "/doc",
        &[(header::IF_NONE_MATCH, "*")],
    )
    .await;
    assert_eq!(res.status(), StatusCode::NOT_MODIFIED);
}

#[tokio::test]
async fn if_modified_since_gives_304_only_when_not_modified() {
    let res = get_with("/doc", &[(header::IF_MODIFIED_SINCE, MODIFIED)]).await;
    assert_eq!(res.status(), StatusCode::NOT_MODIFIED);
    let res = get_with(
        "/doc",
        &[(header::IF_MODIFIED_SINCE, "Sat, 05 Nov 1994 08:49:37 GMT")],
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK);
    // If-None-Match wins over If-Modified-Since.
    let res = get_with(
        "/doc",
        &[
            (header::IF_NONE_MATCH, "\"stale\""),
            (header::IF_MODIFIED_SINCE, MODIFIED),
        ],
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK);
}

#[tokio::test]
async fn failed_if_match_on_get_gives_412() {
    let res = get_with("/doc", &[(header::IF_MATCH, "\"stale\"")]).await;
    assert_eq!(res.status(), StatusCode::PRECONDITION_FAILED);
    assert_eq!(body_of(res).await, "");
    let tag = etag().to_string();
    let res = get_with("/doc", &[(header::IF_MATCH, &tag)]).await;
    assert_eq!(res.status(), StatusCode::OK);
    let res = get_with(
        "/doc",
        &[(header::IF_UNMODIFIED_SINCE, "Sat, 05 Nov 1994 08:49:37 GMT")],
    )
    .await;
    assert_eq!(res.status(), StatusCode::PRECONDITION_FAILED);
}

#[tokio::test]
async fn unsafe_methods_are_left_to_the_handler() {
    let tag = etag().to_string();
    for method in [Method::PUT, Method::POST] {
        let res = send(
            app(Cache::new()),
            method,
            "/doc",
            &[(header::IF_NONE_MATCH, &tag)],
        )
        .await;
        assert_eq!(res.status(), StatusCode::OK);
        assert!(!res.headers().contains_key(header::CACHE_CONTROL));
    }
}

#[tokio::test]
async fn responses_without_validators_are_never_304() {
    let res = get_with("/plain", &[(header::IF_NONE_MATCH, "\"x\"")]).await;
    assert_eq!(res.status(), StatusCode::OK);
    let res = get_with("/plain", &[(header::IF_MODIFIED_SINCE, MODIFIED)]).await;
    assert_eq!(res.status(), StatusCode::OK);
}

#[tokio::test]
async fn error_responses_get_no_cache_control_or_conditionals() {
    let res = get_with("/missing", &[(header::IF_NONE_MATCH, "*")]).await;
    assert_eq!(res.status(), StatusCode::NOT_FOUND);
    assert!(!res.headers().contains_key(header::CACHE_CONTROL));
}

#[tokio::test]
async fn path_overrides_and_handler_headers() {
    let year = Duration::from_secs(31_536_000);
    let config = Cache::new()
        .path("/assets", CacheControl::immutable_asset(year))
        .skip_path("/plain");
    let res = send(app(config.clone()), Method::GET, "/assets/app.js", &[]).await;
    assert_eq!(
        res.headers()[header::CACHE_CONTROL],
        "public, max-age=31536000, immutable"
    );
    let res = send(app(config.clone()), Method::GET, "/plain", &[]).await;
    assert!(!res.headers().contains_key(header::CACHE_CONTROL));

    // The handler's own header wins unless override_existing is set.
    let res = send(app(config.clone()), Method::GET, "/own", &[]).await;
    assert_eq!(res.headers()[header::CACHE_CONTROL], "max-age=5");
    let res = send(
        app(config.override_existing(true)),
        Method::GET,
        "/own",
        &[],
    )
    .await;
    assert_eq!(res.headers()[header::CACHE_CONTROL], "private, no-cache");
}

#[tokio::test]
async fn conditional_handling_can_be_disabled() {
    let tag = etag().to_string();
    let res = send(
        app(Cache::new().conditional(false)),
        Method::GET,
        "/doc",
        &[(header::IF_NONE_MATCH, &tag)],
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK);
}

#[tokio::test]
async fn handler_can_short_circuit_with_validators() {
    async fn guarded(method: Method, headers: HeaderMap) -> Response {
        let current = Validators::new().with_etag(EntityTag::strong("v2").unwrap());
        match current.evaluate(&method, &headers) {
            Precondition::Proceed => "written".into_response(),
            other => other.status().unwrap().into_response(),
        }
    }
    let app = Router::new().route("/item", get(guarded).put(guarded));
    let res = send(
        app.clone(),
        Method::PUT,
        "/item",
        &[(header::IF_MATCH, "\"v1\"")],
    )
    .await;
    assert_eq!(res.status(), StatusCode::PRECONDITION_FAILED);
    let res = send(app, Method::PUT, "/item", &[(header::IF_MATCH, "\"v2\"")]).await;
    assert_eq!(body_of(res).await, "written");
}
