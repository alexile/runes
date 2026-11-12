//! Integration tests: slow handlers time out with the configured status,
//! per path override and per route layer.
//!
//! Tokio's paused clock auto-advances while the runtime is idle, so these
//! tests run instantly without real sleeps.

#![allow(clippy::unwrap_used, reason = "test helpers fail loudly")]

use std::time::Duration;

use axum::{Router, body::Body, routing::get};
use http::{Request, StatusCode};
use rune_axum_timeout::{Timeout, TimeoutLayer};
use tower::ServiceExt;

async fn slow(delay: Duration) -> &'static str {
    tokio::time::sleep(delay).await;
    "done"
}

async fn status_of(app: Router, path: &str) -> StatusCode {
    let req = Request::builder().uri(path).body(Body::empty()).unwrap();
    app.oneshot(req).await.unwrap().status()
}

const fn ms(n: u64) -> Duration {
    Duration::from_millis(n)
}

#[tokio::test(start_paused = true)]
async fn slow_handler_times_out_with_configured_status() {
    let app = Router::new()
        .route("/slow", get(|| slow(ms(2_000))))
        .layer(TimeoutLayer::new(
            Timeout::new()
                .duration(ms(500))
                .status(StatusCode::SERVICE_UNAVAILABLE),
        ));

    let started = tokio::time::Instant::now();
    assert_eq!(
        status_of(app, "/slow").await,
        StatusCode::SERVICE_UNAVAILABLE
    );
    // The response comes at the deadline, not when the handler would finish.
    assert_eq!(started.elapsed(), ms(500));
}

#[tokio::test(start_paused = true)]
async fn timed_out_response_has_empty_body() {
    let app = Router::new()
        .route("/slow", get(|| slow(ms(2_000))))
        .layer(TimeoutLayer::new(Timeout::new().duration(ms(10))));
    let req = Request::builder().uri("/slow").body(Body::empty()).unwrap();
    let res = app.oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::GATEWAY_TIMEOUT);
    let body = axum::body::to_bytes(res.into_body(), 1024).await.unwrap();
    assert!(body.is_empty());
}

#[tokio::test(start_paused = true)]
async fn handler_within_deadline_succeeds() {
    let app = Router::new()
        .route("/slow", get(|| slow(ms(400))))
        .layer(TimeoutLayer::new(Timeout::new().duration(ms(500))));
    assert_eq!(status_of(app, "/slow").await, StatusCode::OK);
}

#[tokio::test(start_paused = true)]
async fn path_override_extends_deadline() {
    let app = Router::new()
        .route("/api/report", get(|| slow(ms(1_000))))
        .route("/api/users", get(|| slow(ms(1_000))))
        .layer(TimeoutLayer::new(
            Timeout::new()
                .duration(ms(100))
                .path("/api/report", ms(5_000)),
        ));
    assert_eq!(status_of(app.clone(), "/api/report").await, StatusCode::OK);
    assert_eq!(
        status_of(app, "/api/users").await,
        StatusCode::GATEWAY_TIMEOUT
    );
}

#[tokio::test(start_paused = true)]
async fn per_route_layer_applies_only_to_its_route() {
    let tight = TimeoutLayer::new(
        Timeout::new()
            .duration(ms(50))
            .status(StatusCode::REQUEST_TIMEOUT),
    );
    let app = Router::new()
        .route("/tight", get(|| slow(ms(200))).layer(tight))
        .route("/loose", get(|| slow(ms(200))))
        .layer(TimeoutLayer::new(Timeout::new().duration(ms(1_000))));

    assert_eq!(
        status_of(app.clone(), "/tight").await,
        StatusCode::REQUEST_TIMEOUT
    );
    assert_eq!(status_of(app, "/loose").await, StatusCode::OK);
}

#[tokio::test(start_paused = true)]
async fn timed_out_handler_is_cancelled() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    let finished = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&finished);
    let app = Router::new()
        .route(
            "/slow",
            get(move || {
                let flag = Arc::clone(&flag);
                async move {
                    tokio::time::sleep(ms(1_000)).await;
                    flag.store(true, Ordering::SeqCst);
                    "done"
                }
            }),
        )
        .layer(TimeoutLayer::new(Timeout::new().duration(ms(10))));

    assert_eq!(status_of(app, "/slow").await, StatusCode::GATEWAY_TIMEOUT);
    tokio::time::sleep(ms(5_000)).await;
    assert!(!finished.load(Ordering::SeqCst));
}
