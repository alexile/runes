# rune-axum-concurrency

> Concurrency limit middleware for Axum — bounded in-flight requests with 503 load shedding and metrics.

[![crates.io](https://img.shields.io/crates/v/rune-axum-concurrency)](https://crates.io/crates/rune-axum-concurrency)
[![docs.rs](https://img.shields.io/docsrs/rune-axum-concurrency)](https://docs.rs/rune-axum-concurrency)
[![license](https://img.shields.io/crates/l/rune-axum-concurrency)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

A [`tower::Layer`](https://docs.rs/tower/latest/tower/trait.Layer.html) that bounds how many requests are processed at once. Within the limit, requests pass through untouched. Beyond it they are **shed**: answered immediately with `503 Service Unavailable` (configurable, optionally with `Retry-After`) without reaching the handler. Unlike `tower::limit::ConcurrencyLimit`, nothing waits in a queue, so latency stays bounded under overload. Admission is a lock-free, runtime-agnostic `Limiter` that also tracks metrics.

> [!NOTE]
> A slot is held until the response headers are ready. Streaming the
> response body afterwards does not hold a slot.

## Installation

```toml
[dependencies]
rune-axum-concurrency = "0.1"
```

## Usage

### Defaults (1024 in flight, 503 Service Unavailable)

```rust
use axum::{routing::get, Router};
use rune_axum_concurrency::ConcurrencyLimitLayer;

let app: Router = Router::new()
    .route("/", get(handler))
    .layer(ConcurrencyLimitLayer::default());
```

### Custom configuration and metrics

```rust
use std::time::Duration;
use axum::{routing::get, Router};
use http::StatusCode;
use rune_axum_concurrency::{ConcurrencyLimit, ConcurrencyLimitLayer};

let layer = ConcurrencyLimitLayer::new(
    ConcurrencyLimit::new()
        .max_in_flight(256)
        .status(StatusCode::TOO_MANY_REQUESTS)
        .retry_after(Duration::from_secs(1)),
);
let limiter = layer.limiter().clone();

let app: Router = Router::new().route("/", get(handler)).layer(layer);

// Later, e.g. in a /metrics handler:
let m = limiter.metrics();
println!("in_flight={} peak={} admitted={} shed={}", m.in_flight, m.peak, m.admitted, m.shed);
```

### Per-route budget

Every clone of a layer shares one budget. Build a separate layer for an independent one:

```rust
use axum::{routing::get, Router};
use rune_axum_concurrency::{ConcurrencyLimit, ConcurrencyLimitLayer};

let app: Router = Router::new().route(
    "/export",
    get(handler).layer(ConcurrencyLimitLayer::new(
        ConcurrencyLimit::new().max_in_flight(4),
    )),
);
```

## Configuration

| Method | Default | Description |
|--------|---------|-------------|
| `.max_in_flight(usize)` | 1024 | Maximum requests processed at once. `0` sheds everything. |
| `.status(StatusCode)` | `503` | Status code of a shed response. |
| `.retry_after(Duration)` | none | Adds `Retry-After` (whole seconds, rounded up) to shed responses. |

## Metrics

`Limiter::metrics()` (also `ConcurrencyLimitLayer::metrics()`) returns a snapshot:

| Field | Meaning |
|-------|---------|
| `limit` | Configured maximum. |
| `in_flight` | Requests currently holding a slot. |
| `peak` | Highest `in_flight` seen. |
| `admitted` | Total requests admitted. |
| `shed` | Total requests shed. |

## Output

A request beyond the limit:

```
HTTP/1.1 503 Service Unavailable
```

## License

MIT
