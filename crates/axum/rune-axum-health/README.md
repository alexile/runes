# rune-axum-health

> Health and readiness probes plus graceful shutdown for Axum — readiness flips on shutdown and in-flight requests drain before exit.

[![crates.io](https://img.shields.io/crates/v/rune-axum-health)](https://crates.io/crates/rune-axum-health)
[![docs.rs](https://img.shields.io/docsrs/rune-axum-health)](https://docs.rs/rune-axum-health)
[![license](https://img.shields.io/crates/l/rune-axum-health)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

A [`tower::Layer`](https://docs.rs/tower/latest/tower/trait.Layer.html) that answers liveness and readiness probes, plus the shutdown plumbing that makes rolling deploys lossless:

1. The orchestrator sends `SIGTERM`.
2. Readiness (`/readyz`) answers `503` at once, so load balancers stop routing new traffic here. Liveness (`/livez`) keeps answering `200`, so the process is not killed mid-drain.
3. After a grace period the server stops accepting connections.
4. Requests already in flight run to completion before the process exits.

Works with Axum, Hyper, and any Tower-compatible framework on the Tokio runtime.

## Installation

```toml
[dependencies]
rune-axum-health = { version = "0.1", features = ["signal"] }
```

## Usage

### Probes and graceful shutdown

```rust
use std::time::Duration;
use axum::{routing::get, Router};
use rune_axum_health::{shutdown_signal, HealthLayer, HealthState};

let state = HealthState::new();
let app = Router::new()
    .route("/", get(handler))
    // Outermost, so probes skip auth/rate limiting and every request is tracked.
    .layer(HealthLayer::new(state.clone()));

let listener = tokio::net::TcpListener::bind("0.0.0.0:8080").await?;
axum::serve(listener, app)
    .with_graceful_shutdown(state.graceful_shutdown(shutdown_signal(), Duration::from_secs(5)))
    .await?;

// Bound the wait for work tracked outside the server's connections.
state.drain(Duration::from_secs(30)).await?;
```

### Warm-up and custom paths

```rust
use rune_axum_health::{Health, HealthLayer, HealthState};

let state = HealthState::new();
state.set_ready(false); // not ready until caches are warm

let layer = HealthLayer::with_config(
    Health::new()
        .liveness_path("/health/live")
        .readiness_path("/health/ready"),
    state.clone(),
);

// ... later, once warm:
state.set_ready(true);
```

### Tracking work the layer cannot see

The layer counts a request as in flight until its response headers are ready. Hold an `InFlightGuard` for longer-lived work so draining waits for it too:

```rust
let guard = state.track();
tokio::spawn(async move {
    stream_export().await;
    drop(guard);
});
```

## Probes

| Request | Healthy | Unhealthy |
|---------|---------|-----------|
| `GET`/`HEAD /livez` | `200` while live | `503` after `set_live(false)` |
| `GET`/`HEAD /readyz` | `200` while ready | `503` after `set_ready(false)` or once shutdown has begun |

Probe responses have an empty body and `Cache-Control: no-store`. Other methods on a probe path pass through to your router. Probes are not counted as in flight.

## API

| Item | Description |
|------|-------------|
| `HealthState::new()` | Shared state; starts live and ready. Cheap to clone. |
| `.set_live(bool)` / `.set_ready(bool)` | Flip liveness or readiness. Readiness cannot return once shutdown has begun. |
| `.begin_shutdown()` | Fail readiness and wake `shutdown_requested()`. |
| `.graceful_shutdown(signal, grace)` | Future for `with_graceful_shutdown`: waits for `signal` (or `begin_shutdown`), flips readiness, waits `grace`. |
| `.track()` | `InFlightGuard` that counts work as in flight while it lives. |
| `.drained()` / `.drain(timeout)` | Wait for in-flight work to finish, without or with a timeout. |
| `.status(Probe)` | The status code a probe answers with right now; no runtime needed. |
| `shutdown_signal()` | `signal` feature: resolves on Ctrl-C or `SIGTERM`. |

## License

MIT
