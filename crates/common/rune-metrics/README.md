# rune-metrics

> Metrics registry with counters, gauges and histograms plus a Prometheus / OpenMetrics text exporter, process collector and HTTP middleware

[![crates.io](https://img.shields.io/crates/v/rune-metrics)](https://crates.io/crates/rune-metrics)
[![docs.rs](https://img.shields.io/docsrs/rune-metrics)](https://docs.rs/rune-metrics)
[![license](https://img.shields.io/crates/l/rune-metrics)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

A small metrics facade with a scrape exporter:

- lock-free `Counter`, `Gauge` and `Histogram` handles, with labelled
  families (`CounterVec`, `GaugeVec`, `HistogramVec`);
- a `Registry` with no global state, validating names, labels, units and
  buckets at registration (errors, never panics);
- a sans-I/O encoder for the [Prometheus text format] 0.0.4 and
  [OpenMetrics] 1.0.0, with `Accept`-header negotiation;
- `ProcessCollector`: the standard `process_*` metrics (CPU, memory, start
  time, file descriptors, threads) from procfs on Linux;
- with the `tower` feature, `HttpMetricsLayer` (`http_server_*` request
  metrics for any Tower or Axum service) and `MetricsEndpoint` (the
  `/metrics` service).

[Prometheus text format]: https://prometheus.io/docs/instrumenting/exposition_formats/
[OpenMetrics]: https://github.com/prometheus/OpenMetrics/blob/main/specification/OpenMetrics.md

## Installation

```toml
[dependencies]
rune-metrics = { version = "0.1", features = ["tower"] }
```

or `cargo add rune-metrics --features tower`. Without `tower` the crate has
no dependencies beyond `thiserror`.

## Usage

### Recording and encoding

```rust
use rune_metrics::{DEFAULT_BUCKETS, Format, Opts, Registry};

let registry = Registry::new();
let jobs = registry.counter_vec(("jobs_total", "Jobs processed."), &["outcome"])?;
let latency = registry.histogram(
    Opts::new("job_duration_seconds", "Job run time.").with_unit("seconds"),
    DEFAULT_BUCKETS,
)?;

jobs.with_label_values(&["ok"])?.inc();
latency.observe(0.042);

let text = registry.encode(Format::Prometheus);
assert!(text.contains("jobs_total{outcome=\"ok\"} 1"));
```

### Axum: HTTP metrics and a `/metrics` endpoint

```rust
use axum::{Router, extract::MatchedPath, routing::get};
use rune_metrics::{HttpMetricsLayer, MetricsEndpoint, ProcessCollector, Registry};

let registry = Registry::new();
registry.register_collector(ProcessCollector::new());

// The route template (`/users/{id}`), never the raw path, keeps label
// cardinality bounded.
let http = HttpMetricsLayer::with_route(&registry, |ext| {
    ext.get::<MatchedPath>().map(|p| p.as_str().to_owned())
})?;

let app: Router = Router::new()
    .route("/users/{id}", get(|| async { "user" }))
    .route_service("/metrics", MetricsEndpoint::new(registry))
    .layer(http);
```

| Metric                                 | Type      | Labels                         |
| -------------------------------------- | --------- | ------------------------------ |
| `http_server_requests_total`           | counter   | `method`, `status`[, `route`]  |
| `http_server_request_duration_seconds` | histogram | `method`, `status`[, `route`]  |
| `http_server_requests_in_flight`       | gauge     | `method`                       |
| `process_cpu_seconds_total`            | counter   |                                |
| `process_resident_memory_bytes`        | gauge     |                                |
| `process_virtual_memory_bytes`         | gauge     |                                |
| `process_start_time_seconds`           | gauge     |                                |
| `process_open_fds` / `process_max_fds` | gauge     |                                |
| `process_threads`                      | gauge     |                                |

`MetricsEndpoint` answers `GET`/`HEAD` with OpenMetrics when the scraper
sends `Accept: application/openmetrics-text` (Prometheus does), and the
Prometheus text format otherwise.

### Custom collectors

Anything that is cheaper to read at scrape time than to keep updated can be
a `Collector` (a closure returning `Vec<MetricFamily>` works too).

## License

MIT
