//! Scrapes a real Axum server's `/metrics` endpoint over loopback TCP.

#![allow(clippy::unwrap_used, reason = "test helpers")]

use axum::Router;
use axum::body::Body;
use axum::extract::MatchedPath;
use axum::routing::get;
use http::{Request, StatusCode};
use rune_metrics::{HttpMetricsLayer, MetricsEndpoint, ProcessCollector, Registry};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tower::ServiceExt;

fn app(registry: &Registry) -> Router {
    let layer = HttpMetricsLayer::with_route(registry, |ext| {
        ext.get::<MatchedPath>().map(|p| p.as_str().to_owned())
    })
    .unwrap();
    Router::new()
        .route("/users/{id}", get(|| async { "user" }))
        .route(
            "/fail",
            get(|| async { (StatusCode::INTERNAL_SERVER_ERROR, "boom") }),
        )
        .route_service("/metrics", MetricsEndpoint::new(registry.clone()))
        .layer(layer)
}

async fn http_get(addr: std::net::SocketAddr, path: &str, accept: &str) -> String {
    let mut stream = TcpStream::connect(addr).await.unwrap();
    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: localhost\r\nAccept: {accept}\r\nConnection: close\r\n\r\n"
    );
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).await.unwrap();
    response
}

#[tokio::test]
async fn scrape_endpoint_exposes_process_and_http_metrics() {
    let registry = Registry::new();
    registry.register_collector(ProcessCollector::new());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(axum::serve(listener, app(&registry)).into_future());

    assert!(
        http_get(addr, "/users/1", "*/*")
            .await
            .starts_with("HTTP/1.1 200")
    );
    assert!(
        http_get(addr, "/users/2", "*/*")
            .await
            .starts_with("HTTP/1.1 200")
    );
    assert!(
        http_get(addr, "/fail", "*/*")
            .await
            .starts_with("HTTP/1.1 500")
    );

    let scrape = http_get(addr, "/metrics", "text/plain").await;
    assert!(scrape.starts_with("HTTP/1.1 200"), "{scrape}");
    assert!(scrape.contains("content-type: text/plain; version=0.0.4; charset=utf-8"));
    let body = scrape.split("\r\n\r\n").nth(1).unwrap();

    assert!(body.contains("# TYPE http_server_requests_total counter\n"));
    assert!(body.contains(
        "http_server_requests_total{method=\"GET\",status=\"200\",route=\"/users/{id}\"} 2\n"
    ));
    assert!(
        body.contains(
            "http_server_requests_total{method=\"GET\",status=\"500\",route=\"/fail\"} 1\n"
        )
    );
    assert!(body.contains(
        "http_server_request_duration_seconds_bucket{method=\"GET\",status=\"200\",route=\"/users/{id}\",le=\"+Inf\"} 2\n"
    ));
    // The scrape itself is in flight while the registry is encoded.
    assert!(body.contains("http_server_requests_in_flight{method=\"GET\"} 1\n"));
    if cfg!(target_os = "linux") {
        for name in [
            "process_cpu_seconds_total",
            "process_resident_memory_bytes",
            "process_virtual_memory_bytes",
            "process_start_time_seconds",
            "process_open_fds",
            "process_max_fds",
            "process_threads",
        ] {
            assert!(
                body.contains(&format!("\n{name} ")),
                "missing {name}:\n{body}"
            );
        }
    }

    let om = http_get(
        addr,
        "/metrics",
        "application/openmetrics-text; version=1.0.0",
    )
    .await;
    assert!(
        om.contains("content-type: application/openmetrics-text; version=1.0.0; charset=utf-8")
    );
    assert!(om.contains("# TYPE http_server_requests counter\n"));
    assert!(om.contains("# UNIT http_server_request_duration_seconds seconds\n"));
    assert!(om.trim_end().ends_with("# EOF"));

    server.abort();
}

#[tokio::test]
async fn layer_without_route_label_and_oneshot() {
    let registry = Registry::new();
    let app = Router::new()
        .route("/", get(|| async { "ok" }))
        .route_service("/metrics", MetricsEndpoint::new(registry.clone()))
        .layer(HttpMetricsLayer::new(&registry).unwrap());

    let response = app
        .clone()
        .oneshot(Request::post("/").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);

    let text = registry.encode(rune_metrics::Format::Prometheus);
    assert!(text.contains("http_server_requests_total{method=\"POST\",status=\"405\"} 1\n"));
    assert!(text.contains("http_server_requests_in_flight{method=\"POST\"} 0\n"));

    let response = app
        .oneshot(Request::delete("/metrics").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
}
