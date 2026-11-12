# rune-axum-timeout

> Request timeout middleware for Axum — per-request deadline with a configurable 504 response, overridable per route.

[![crates.io](https://img.shields.io/crates/v/rune-axum-timeout)](https://crates.io/crates/rune-axum-timeout)
[![docs.rs](https://img.shields.io/docsrs/rune-axum-timeout)](https://docs.rs/rune-axum-timeout)
[![license](https://img.shields.io/crates/l/rune-axum-timeout)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

A [`tower::Layer`](https://docs.rs/tower/latest/tower/trait.Layer.html) that gives every request a deadline. If the inner service has not produced a response in time, its future is dropped (cancelling the handler) and the client gets a configurable error response, `504 Gateway Timeout` by default. Deadlines can differ per route, either through longest-prefix path overrides on one layer or by attaching a layer to individual routes. Works with Axum, Hyper, and any Tower-compatible framework on the Tokio runtime.

> [!NOTE]
> The deadline covers the time until the response headers are ready. It does
> not limit how long a streaming response body takes to send.

## Installation

```toml
[dependencies]
rune-axum-timeout = "0.1"
```

## Usage

### Defaults (30 seconds, 504 Gateway Timeout)

```rust
use axum::{routing::get, Router};
use rune_axum_timeout::TimeoutLayer;

let app: Router = Router::new()
    .route("/", get(handler))
    .layer(TimeoutLayer::default());
```

### Custom configuration and path overrides

```rust
use std::time::Duration;
use axum::{routing::get, Router};
use http::StatusCode;
use rune_axum_timeout::{Timeout, TimeoutLayer};

// 5 s everywhere, 60 s under /export, answer with 503 instead of 504.
let layer = TimeoutLayer::new(
    Timeout::new()
        .duration(Duration::from_secs(5))
        .status(StatusCode::SERVICE_UNAVAILABLE)
        .path("/export", Duration::from_secs(60)),
);

let app: Router = Router::new()
    .route("/export/csv", get(handler))
    .layer(layer);
```

### Per-route layer

```rust
use std::time::Duration;
use axum::{routing::get, Router};
use rune_axum_timeout::{Timeout, TimeoutLayer};

let app: Router = Router::new().route(
    "/ping",
    get(handler).layer(TimeoutLayer::new(
        Timeout::new().duration(Duration::from_millis(250)),
    )),
);
```

## Configuration

| Method | Default | Description |
|--------|---------|-------------|
| `.duration(Duration)` | 30 s | Deadline for requests that match no path override. |
| `.status(StatusCode)` | `504` | Status code returned when a request times out. |
| `.path(prefix, Duration)` | none | Deadline for `prefix` and everything below it, matched on `/` segment boundaries. The longest matching prefix wins. |

`Timeout::duration_for(path)` returns the deadline that applies to a path, without a runtime.

## Output

A request whose handler misses the deadline:

```
HTTP/1.1 504 Gateway Timeout
```

## License

MIT
