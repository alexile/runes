//! Integration tests: probes through an Axum router, readiness flipping on
//! shutdown, and in-flight requests draining before shutdown completes.
//!
//! Tokio's paused clock auto-advances while the runtime is idle, so these
//! tests run instantly without real sleeps.

#![allow(clippy::unwrap_used, reason = "test helpers fail loudly")]

use std::time::Duration;

use axum::{Router, body::Body, routing::get};
use http::{Method, Request, StatusCode, header::CACHE_CONTROL};
use rune_axum_health::{Health, HealthLayer, HealthState};
use tokio::time::Instant;
use tower::ServiceExt;

const fn ms(n: u64) -> Duration {
    Duration::from_millis(n)
}

fn app(state: &HealthState) -> Router {
    Router::new()
        .route("/", get(|| async { "ok" }))
        .route(
            "/slow",
            get(|| async {
                tokio::time::sleep(ms(1_000)).await;
                "done"
            }),
        )
        .layer(HealthLayer::new(state.clone()))
}

async fn send(app: Router, method: Method, path: &str) -> StatusCode {
    let req = Request::builder()
        .method(method)
        .uri(path)
        .body(Body::empty())
        .unwrap();
    app.oneshot(req).await.unwrap().status()
}

async fn get_status(app: Router, path: &str) -> StatusCode {
    send(app, Method::GET, path).await
}

/// Yields until `cond` holds, so spawned requests reach the handler.
async fn until(cond: impl Fn() -> bool) {
    while !cond() {
        tokio::task::yield_now().await;
    }
}

#[tokio::test]
async fn probes_answer_ok_while_serving() {
    let state = HealthState::new();
    let req = Request::get("/readyz").body(Body::empty()).unwrap();
    let res = app(&state).oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(res.headers()[CACHE_CONTROL], "no-store");
    let body = axum::body::to_bytes(res.into_body(), 1024).await.unwrap();
    assert!(body.is_empty());

    assert_eq!(get_status(app(&state), "/livez").await, StatusCode::OK);
    assert_eq!(
        send(app(&state), Method::HEAD, "/readyz").await,
        StatusCode::OK
    );
    assert_eq!(get_status(app(&state), "/").await, StatusCode::OK);
}

#[tokio::test]
async fn readiness_flips_on_shutdown_liveness_holds() {
    let state = HealthState::new();
    state.begin_shutdown();
    assert_eq!(
        get_status(app(&state), "/readyz").await,
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(get_status(app(&state), "/livez").await, StatusCode::OK);
    // Requests still on open connections are served during the drain.
    assert_eq!(get_status(app(&state), "/").await, StatusCode::OK);
}

#[tokio::test]
async fn warm_up_and_liveness_failure() {
    let state = HealthState::new();
    state.set_ready(false);
    assert_eq!(
        get_status(app(&state), "/readyz").await,
        StatusCode::SERVICE_UNAVAILABLE
    );
    state.set_ready(true);
    assert_eq!(get_status(app(&state), "/readyz").await, StatusCode::OK);
    state.set_live(false);
    assert_eq!(
        get_status(app(&state), "/livez").await,
        StatusCode::SERVICE_UNAVAILABLE
    );
}

#[tokio::test]
async fn non_probe_methods_pass_through() {
    let state = HealthState::new();
    let app = Router::new()
        .route(
            "/readyz",
            axum::routing::post(|| async { StatusCode::ACCEPTED }),
        )
        .layer(HealthLayer::new(state.clone()));
    assert_eq!(
        send(app, Method::POST, "/readyz").await,
        StatusCode::ACCEPTED
    );
}

#[tokio::test]
async fn custom_probe_paths() {
    let state = HealthState::new();
    let app = Router::new().layer(HealthLayer::with_config(
        Health::new()
            .liveness_path("/health/live")
            .readiness_path("/health/ready"),
        state.clone(),
    ));
    assert_eq!(
        get_status(app.clone(), "/health/live").await,
        StatusCode::OK
    );
    state.begin_shutdown();
    assert_eq!(
        get_status(app.clone(), "/health/ready").await,
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(get_status(app, "/readyz").await, StatusCode::NOT_FOUND);
}

#[tokio::test(start_paused = true)]
async fn in_flight_request_drains_before_shutdown_completes() {
    let state = HealthState::new();
    let started = Instant::now();
    let slow = tokio::spawn(get_status(app(&state), "/slow"));
    until(|| state.in_flight() == 1).await;

    // Probes are answered, not tracked.
    assert_eq!(get_status(app(&state), "/livez").await, StatusCode::OK);
    assert_eq!(state.in_flight(), 1);

    state.begin_shutdown();
    assert_eq!(
        get_status(app(&state), "/readyz").await,
        StatusCode::SERVICE_UNAVAILABLE
    );

    state.drain(ms(5_000)).await.unwrap();
    assert_eq!(started.elapsed(), ms(1_000));
    assert_eq!(state.in_flight(), 0);
    assert_eq!(slow.await.unwrap(), StatusCode::OK);
}

#[tokio::test(start_paused = true)]
async fn drain_timeout_reports_stuck_requests() {
    let state = HealthState::new();
    let _slow = tokio::spawn(get_status(app(&state), "/slow"));
    until(|| state.in_flight() == 1).await;
    state.begin_shutdown();
    let err = state.drain(ms(200)).await.unwrap_err();
    assert!(matches!(
        err,
        rune_axum_health::Error::DrainTimeout { in_flight: 1, .. }
    ));
}

#[tokio::test(start_paused = true)]
async fn dropped_request_is_no_longer_in_flight() {
    let state = HealthState::new();
    let slow = tokio::spawn(get_status(app(&state), "/slow"));
    until(|| state.in_flight() == 1).await;
    // A client disconnect drops the response future.
    slow.abort();
    let _ = slow.await;
    assert_eq!(state.in_flight(), 0);
    state.drained().await;
}

#[tokio::test(start_paused = true)]
async fn graceful_shutdown_flips_readiness_then_waits_grace() {
    let state = HealthState::new();
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    let shutdown = tokio::spawn(state.graceful_shutdown(rx, ms(5_000)));
    tokio::task::yield_now().await;
    assert!(state.is_ready());

    let signalled = Instant::now();
    tx.send(()).unwrap();
    until(|| state.is_shutting_down()).await;
    assert_eq!(
        get_status(app(&state), "/readyz").await,
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert!(!shutdown.is_finished());

    shutdown.await.unwrap();
    assert_eq!(signalled.elapsed(), ms(5_000));
}

#[tokio::test(start_paused = true)]
async fn graceful_shutdown_also_follows_begin_shutdown() {
    let state = HealthState::new();
    let never = std::future::pending::<()>();
    let shutdown = tokio::spawn(state.graceful_shutdown(never, Duration::ZERO));
    tokio::task::yield_now().await;
    assert!(!shutdown.is_finished());
    state.begin_shutdown();
    shutdown.await.unwrap();
}
