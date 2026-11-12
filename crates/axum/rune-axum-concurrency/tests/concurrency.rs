//! Integration tests: within the limit requests pass, beyond it they are shed
//! with the configured response, and slots are freed when requests finish.
//!
//! Handlers block on a gate semaphore, so the tests control exactly how many
//! requests are in flight without real sleeps.

#![allow(clippy::unwrap_used, reason = "test helpers fail loudly")]

use std::sync::Arc;
use std::time::Duration;

use axum::{Router, body::Body, routing::get};
use http::{Request, StatusCode, header::RETRY_AFTER};
use rune_axum_concurrency::{ConcurrencyLimit, ConcurrencyLimitLayer, Limiter};
use tokio::sync::Semaphore;
use tokio::task::JoinHandle;
use tower::ServiceExt;

/// A route at `/` whose handler waits until the gate opens.
fn gated_app(gate: &Arc<Semaphore>, layer: ConcurrencyLimitLayer) -> Router {
    let gate = Arc::clone(gate);
    Router::new()
        .route(
            "/",
            get(move || {
                let gate = Arc::clone(&gate);
                async move {
                    gate.acquire().await.unwrap().forget();
                    "done"
                }
            }),
        )
        .route("/free", get(|| async { "free" }))
        .layer(layer)
}

fn send(app: &Router, path: &str) -> JoinHandle<http::Response<Body>> {
    let app = app.clone();
    let req = Request::builder().uri(path).body(Body::empty()).unwrap();
    tokio::spawn(async move { app.oneshot(req).await.unwrap() })
}

async fn wait_in_flight(limiter: &Limiter, n: usize) {
    while limiter.metrics().in_flight != n {
        tokio::task::yield_now().await;
    }
}

#[tokio::test]
async fn within_limit_pass_beyond_limit_shed() {
    let gate = Arc::new(Semaphore::new(0));
    let layer = ConcurrencyLimitLayer::new(ConcurrencyLimit::new().max_in_flight(3));
    let limiter = layer.limiter().clone();
    let app = gated_app(&gate, layer);

    let held: Vec<_> = (0..3).map(|_| send(&app, "/")).collect();
    wait_in_flight(&limiter, 3).await;

    // Beyond the limit: shed immediately, even for a route that would be fast.
    for path in ["/", "/free"] {
        let res = send(&app, path).await.unwrap();
        assert_eq!(res.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(res.headers().get(RETRY_AFTER).is_none());
        let body = axum::body::to_bytes(res.into_body(), 1024).await.unwrap();
        assert!(body.is_empty());
    }

    gate.add_permits(3);
    for h in held {
        assert_eq!(h.await.unwrap().status(), StatusCode::OK);
    }

    let m = limiter.metrics();
    assert_eq!(m.in_flight, 0);
    assert_eq!(m.peak, 3);
    assert_eq!(m.admitted, 3);
    assert_eq!(m.shed, 2);
}

#[tokio::test]
async fn slot_freed_after_completion_admits_next() {
    let gate = Arc::new(Semaphore::new(0));
    let layer = ConcurrencyLimitLayer::new(ConcurrencyLimit::new().max_in_flight(1));
    let limiter = layer.limiter().clone();
    let app = gated_app(&gate, layer);

    let first = send(&app, "/");
    wait_in_flight(&limiter, 1).await;
    assert_eq!(
        send(&app, "/free").await.unwrap().status(),
        StatusCode::SERVICE_UNAVAILABLE
    );

    gate.add_permits(1);
    assert_eq!(first.await.unwrap().status(), StatusCode::OK);
    assert_eq!(send(&app, "/free").await.unwrap().status(), StatusCode::OK);
}

#[tokio::test]
async fn custom_status_and_retry_after() {
    let gate = Arc::new(Semaphore::new(0));
    let layer = ConcurrencyLimitLayer::new(
        ConcurrencyLimit::new()
            .max_in_flight(1)
            .status(StatusCode::TOO_MANY_REQUESTS)
            .retry_after(Duration::from_millis(1_500)),
    );
    let limiter = layer.limiter().clone();
    let app = gated_app(&gate, layer);

    let held = send(&app, "/");
    wait_in_flight(&limiter, 1).await;
    let res = send(&app, "/").await.unwrap();
    assert_eq!(res.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(res.headers()[RETRY_AFTER], "2");

    gate.add_permits(1);
    assert_eq!(held.await.unwrap().status(), StatusCode::OK);
}

#[tokio::test]
async fn cancelled_request_frees_its_slot() {
    let gate = Arc::new(Semaphore::new(0));
    let layer = ConcurrencyLimitLayer::new(ConcurrencyLimit::new().max_in_flight(1));
    let limiter = layer.limiter().clone();
    let app = gated_app(&gate, layer);

    let held = send(&app, "/");
    wait_in_flight(&limiter, 1).await;
    held.abort();
    assert!(held.await.unwrap_err().is_cancelled());
    assert_eq!(limiter.metrics().in_flight, 0);
    assert_eq!(send(&app, "/free").await.unwrap().status(), StatusCode::OK);
}

#[tokio::test]
async fn per_route_layers_have_independent_budgets() {
    let gate = Arc::new(Semaphore::new(0));
    let tight = ConcurrencyLimitLayer::new(ConcurrencyLimit::new().max_in_flight(1));
    let tight_limiter = tight.limiter().clone();
    let g = Arc::clone(&gate);
    let app = Router::new()
        .route(
            "/tight",
            get(move || {
                let g = Arc::clone(&g);
                async move {
                    g.acquire().await.unwrap().forget();
                    "t"
                }
            })
            .layer(tight),
        )
        .route("/other", get(|| async { "o" }))
        .layer(ConcurrencyLimitLayer::new(
            ConcurrencyLimit::new().max_in_flight(10),
        ));

    let held = send(&app, "/tight");
    wait_in_flight(&tight_limiter, 1).await;
    assert_eq!(
        send(&app, "/tight").await.unwrap().status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(send(&app, "/other").await.unwrap().status(), StatusCode::OK);

    gate.add_permits(1);
    assert_eq!(held.await.unwrap().status(), StatusCode::OK);
}

#[tokio::test]
async fn propagates_inner_status() {
    let app = Router::new()
        .route("/", get(|| async { StatusCode::IM_A_TEAPOT }))
        .layer(ConcurrencyLimitLayer::default());
    assert_eq!(
        send(&app, "/").await.unwrap().status(),
        StatusCode::IM_A_TEAPOT
    );
}
