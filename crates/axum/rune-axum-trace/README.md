# rune-axum-trace

> One Axum layer for OpenTelemetry traces, Prometheus HTTP metrics and redacted access logs.

[![crates.io](https://img.shields.io/crates/v/rune-axum-trace)](https://crates.io/crates/rune-axum-trace)
[![docs.rs](https://img.shields.io/docsrs/rune-axum-trace)](https://docs.rs/rune-axum-trace)
[![license](https://img.shields.io/crates/l/rune-axum-trace)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

Instruments every Axum request with an OpenTelemetry server span. Propagates
incoming W3C `traceparent` / `tracestate` context, records standard HTTP
semantic-convention attributes (`http.request.method`, `http.response.status_code`,
`http.route`, `url.path`, `user_agent.original`), and exports spans via OTLP/gRPC
to Jaeger, Grafana Tempo, Honeycomb, or any OpenTelemetry Collector.

> [!NOTE]
> Apply with `router.route_layer(TraceLayer::new())` for accurate route template
> span names (`GET /users/{id}`). With `router.layer()`, `MatchedPath` is not yet
> populated and the span name falls back to the HTTP method alone.

> [!WARNING]
> Call `TraceConfig::init` before the server starts. Spans created before a provider
> is installed are silently dropped by the OTel noop tracer.

## Installation

```toml
[dependencies]
rune-axum-trace = "0.1"
```

## Usage

```rust,no_run
use axum::{routing::get, Router};
use rune_axum_trace::{TraceConfig, TraceLayer};

#[tokio::main]
async fn main() {
    // Install the global OTLP tracer — hold the guard for the process lifetime.
    let _guard = TraceConfig::new()
        .service_name("my-api")
        .endpoint("http://localhost:4317")
        .init()
        .expect("failed to init tracer");

    let app = Router::new()
        .route("/users/{id}", get(|| async { "ok" }))
        .route_layer(TraceLayer::new()); // route_layer → MatchedPath available

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
```

If the application already configures a global OTel provider, skip `TraceConfig`
and add `TraceLayer` directly:

```rust,no_run
use axum::{routing::get, Router};
use rune_axum_trace::TraceLayer;

let app: Router = Router::new()
    .route("/", get(|| async { "ok" }))
    .route_layer(TraceLayer::new());
```

## Metrics and redacted access logs

The same layer can record HTTP server metrics in a
[`rune-metrics`](../../common/rune-metrics) registry and emit one redacted
access log event per request for [`rune-log`](../../common/rune-log) to format:

```rust,no_run
use axum::{routing::get, Router};
use rune_axum_trace::{AccessLog, TraceLayer, rune_log::LogConfig};
use rune_metrics::{MetricsEndpoint, Registry};

# fn main() -> Result<(), Box<dyn std::error::Error>> {
// Redacted text or JSON logs on stderr (RUST_LOG, LOG_FORMAT, LOG_REDACT).
let log_config = LogConfig::default().with_env(|k| std::env::var(k).ok())?;
log_config.try_init(std::io::stderr)?;

let registry = Registry::new();
let app: Router = Router::new()
    .route("/users/{id}", get(|| async { "ok" }))
    .route_layer(
        TraceLayer::new()
            .with_registry(&registry)? // http_server_* metrics, `route` label
            .with_access_log(AccessLog::new().with_redactor(log_config.redactor().clone())),
    )
    .route_service("/metrics", MetricsEndpoint::new(registry));
# Ok(())
# }
```

Metrics (from `rune_metrics::HttpMetricsLayer`):

| Metric | Type | Labels |
|--------|------|--------|
| `http_server_requests_total` | counter | `method`, `status`, `route` |
| `http_server_request_duration_seconds` | histogram | `method`, `status`, `route` |
| `http_server_requests_in_flight` | gauge | `method` |

Access log events use target `rune_axum_trace::access`, level `INFO` (or
`ERROR` for `5xx` and handler errors), and the fields `http.request.method`,
`http.route`, `url.path`, `url.query`, `user_agent.original`,
`http.response.status_code`, `duration_ms`, `trace_id` and `span_id`. Path,
query and user agent go through a `Redactor` before the event is emitted, so
`GET /users/bob@example.com?token=…` is logged as `/users/[EMAIL]` whatever
subscriber is installed. Headers (other than `User-Agent`) and bodies are never
logged.

## Configuration

| Method | Default | Effect |
|--------|---------|--------|
| `.service_name("my-api")` | `"unknown_service"` | `service.name` resource attribute |
| `.endpoint("http://host:4317")` | `"http://localhost:4317"` | OTLP/gRPC collector address |

The endpoint can also be set via the `OTEL_EXPORTER_OTLP_ENDPOINT` environment
variable, which takes precedence over the builder value.

## Span attributes

Each span is created with `SpanKind::Server` and the following attributes:

| Attribute | Value |
|-----------|-------|
| `http.request.method` | `GET`, `POST`, … |
| `http.route` | `/users/{id}` (only with `route_layer`) |
| `url.path` | `/users/42` |
| `http.response.status_code` | `200`, `404`, `500`, … |
| `user_agent.original` | Value of the `User-Agent` header |

## Layer placement

| Placement | `MatchedPath` | Span name | `route` label / field |
|-----------|--------------|-----------|-----------------------|
| `router.route_layer(TraceLayer::new())` | Available | `GET /users/{id}` | `/users/{id}` |
| `router.layer(TraceLayer::new())` | Not available | `GET` | empty |

## Output

With a local Jaeger instance (`docker run -p 16686:16686 -p 4317:4317 jaegertracing/all-in-one`),
spans appear in the Jaeger UI at `http://localhost:16686` under the configured service name.

A typical span for `GET /users/{id} → 200`:

```
Operation:   GET /users/{id}
Service:     my-api
Duration:    1.2 ms
Tags:
  http.request.method       GET
  http.route                /users/{id}
  url.path                  /users/42
  http.response.status_code 200
  user_agent.original       curl/8.4.0
  otel.status_code          OK
```

## License

MIT
