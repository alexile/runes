//! End-to-end behaviour of `RequestIdLayer` inside an Axum router.

#![allow(clippy::unwrap_used, reason = "test helpers fail loudly")]

use axum::{Router, body::Body, routing::get};
use http::{Request, Response, StatusCode};
use rune_axum_requestid::{RequestId, RequestIdConfig, RequestIdLayer, TraceContext, TraceParent};
use tower::ServiceExt;

const SPEC: &str = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";

fn app(layer: RequestIdLayer) -> Router {
    Router::new()
        .route("/id", get(|id: RequestId| async move { id.to_string() }))
        .route(
            "/trace",
            get(|trace: TraceContext| async move { trace.traceparent().to_string() }),
        )
        .route(
            "/headers",
            get(|req: Request<Body>| async move {
                format!(
                    "{} {}",
                    req.headers()["x-request-id"].to_str().unwrap(),
                    req.headers()["traceparent"].to_str().unwrap()
                )
            }),
        )
        .route(
            "/custom",
            get(|| async {
                Response::builder()
                    .header("x-request-id", "from-handler")
                    .body(Body::empty())
                    .unwrap()
            }),
        )
        .route(
            "/optional",
            get(|id: Option<RequestId>| async move { format!("{}", id.is_some()) }),
        )
        .layer(layer)
}

async fn get_req(app: Router, uri: &str, headers: &[(&str, &str)]) -> (Response<Body>, String) {
    let mut builder = Request::builder().uri(uri);
    for (k, v) in headers {
        builder = builder.header(*k, *v);
    }
    let res = app
        .oneshot(builder.body(Body::empty()).unwrap())
        .await
        .unwrap();
    let (parts, body) = res.into_parts();
    let bytes = axum::body::to_bytes(body, 4096).await.unwrap();
    let text = String::from_utf8(bytes.to_vec()).unwrap();
    (Response::from_parts(parts, Body::empty()), text)
}

#[tokio::test]
async fn incoming_id_is_propagated_to_handler_and_response() {
    let (res, body) = get_req(
        app(RequestIdLayer::default()),
        "/id",
        &[("x-request-id", "abc-123")],
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(body, "abc-123");
    assert_eq!(res.headers()["x-request-id"], "abc-123");
    assert_eq!(
        res.extensions().get::<RequestId>().map(RequestId::as_str),
        Some("abc-123")
    );
}

#[tokio::test]
async fn id_is_generated_when_absent() {
    let (res, body) = get_req(app(RequestIdLayer::default()), "/id", &[]).await;
    assert_eq!(body.len(), 36);
    assert_eq!(res.headers()["x-request-id"], body.as_str());
}

#[tokio::test]
async fn invalid_incoming_id_is_replaced_not_echoed() {
    let (res, body) = get_req(
        app(RequestIdLayer::default()),
        "/id",
        &[("x-request-id", "evil value")],
    )
    .await;
    assert_ne!(body, "evil value");
    assert_eq!(res.headers()["x-request-id"], body.as_str());
}

#[tokio::test]
async fn trace_is_continued_and_forwarded_in_request_headers() {
    let (_, body) = get_req(
        app(RequestIdLayer::default()),
        "/trace",
        &[("traceparent", SPEC)],
    )
    .await;
    let child = TraceParent::parse(&body).unwrap();
    let parent = TraceParent::parse(SPEC).unwrap();
    assert_eq!(child.trace_id(), parent.trace_id());
    assert_ne!(child.parent_id(), parent.parent_id());

    let (_, body) = get_req(
        app(RequestIdLayer::default()),
        "/headers",
        &[("traceparent", SPEC), ("x-request-id", "r1")],
    )
    .await;
    let (id, tp) = body.split_once(' ').unwrap();
    assert_eq!(id, "r1");
    assert_eq!(
        TraceParent::parse(tp).unwrap().trace_id(),
        parent.trace_id()
    );
}

#[tokio::test]
async fn handler_response_header_wins() {
    let (res, _) = get_req(
        app(RequestIdLayer::default()),
        "/custom",
        &[("x-request-id", "abc")],
    )
    .await;
    assert_eq!(res.headers()["x-request-id"], "from-handler");
}

#[tokio::test]
async fn response_header_can_be_disabled() {
    let layer = RequestIdLayer::new(RequestIdConfig::default().with_response_header(false));
    let (res, body) = get_req(app(layer), "/id", &[("x-request-id", "abc")]).await;
    assert_eq!(body, "abc");
    assert!(res.headers().get("x-request-id").is_none());
}

#[tokio::test]
async fn trace_extractor_rejects_when_disabled() {
    let layer = RequestIdLayer::new(RequestIdConfig::default().with_traceparent(false));
    let (res, _) = get_req(app(layer), "/trace", &[]).await;
    assert_eq!(res.status(), StatusCode::INTERNAL_SERVER_ERROR);
}

#[tokio::test]
async fn extractors_without_layer() {
    let router = Router::new()
        .route("/id", get(|id: RequestId| async move { id.to_string() }))
        .route(
            "/optional",
            get(|id: Option<RequestId>| async move { format!("{}", id.is_some()) }),
        );
    let (res, _) = get_req(router.clone(), "/id", &[]).await;
    assert_eq!(res.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let (_, body) = get_req(router, "/optional", &[]).await;
    assert_eq!(body, "false");

    let (_, body) = get_req(app(RequestIdLayer::default()), "/optional", &[]).await;
    assert_eq!(body, "true");
}
