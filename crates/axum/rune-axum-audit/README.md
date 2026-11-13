# rune-axum-audit

> Structured audit log middleware for Axum — records method, path, status, latency, and client identity.

[![crates.io](https://img.shields.io/crates/v/rune-axum-audit)](https://crates.io/crates/rune-axum-audit)
[![docs.rs](https://img.shields.io/docsrs/rune-axum-audit)](https://docs.rs/rune-axum-audit)
[![license](https://img.shields.io/crates/l/rune-axum-audit)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

## What it does

`rune-axum-audit` is a Tower [`Layer`](https://docs.rs/tower-layer/latest/tower_layer/trait.Layer.html)
that captures one [`AuditEvent`](https://docs.rs/rune-axum-audit/latest/rune_axum_audit/struct.AuditEvent.html)
per request — method, path, query string, client IP, user-agent, HTTP status, and wall-clock latency —
and delivers it to a pluggable [`AuditSink`](https://docs.rs/rune-axum-audit/latest/rune_axum_audit/trait.AuditSink.html).
The inner service and its response pass through unchanged; auditing is purely observational.

Values of credential-looking query parameters (`api_key`, `token`, `password`, `secret`,
`signature` and the like) are recorded as `[redacted]`. The client IP comes from
`X-Forwarded-For` / `X-Real-IP`, which the client controls unless a proxy overwrites them.

## Installation

```toml
[dependencies]
rune-axum-audit = "0.1"
```

## Usage

Drop `AuditLayer::stdout()` onto any Axum router:

```rust,no_run
use axum::{routing::get, Router};
use rune_axum_audit::AuditLayer;

let app: Router = Router::new()
    .route("/api", get(|| async { "ok" }))
    .layer(AuditLayer::stdout());
```

Capture events in your own sink — a channel, database, or SIEM:

```rust,no_run
use std::sync::{Arc, Mutex};
use axum::{routing::get, Router};
use rune_axum_audit::{AuditEvent, AuditLayer, CallbackSink};

let events: Arc<Mutex<Vec<AuditEvent>>> = Arc::new(Mutex::new(Vec::new()));
let captured = Arc::clone(&events);

let app: Router = Router::new()
    .route("/api", get(|| async { "ok" }))
    .layer(AuditLayer::new(CallbackSink::new(move |event| {
        captured.lock().unwrap().push(event);
    })));
```

Implement `AuditSink` for any custom destination:

```rust
use rune_axum_audit::{AuditEvent, AuditSink};

struct MySink;

impl AuditSink for MySink {
    fn record(&self, event: AuditEvent) {
        eprintln!("{event}");
    }
}
```

## Output

Each `AuditEvent` renders as a single structured line:

```
[2024-01-15T12:34:56Z] POST /api/users status=201 latency=8ms ip=1.2.3.4 ua="curl/7.68.0"
[2024-01-15T12:34:57Z] GET /api/users?page=2 status=200 latency=3ms ip=10.0.0.1 ua="Mozilla/5.0"
```

## Sinks

| Sink | Description |
|------|-------------|
| `AuditLayer::stdout()` | Print to standard output |
| `AuditLayer::stderr()` | Print to standard error |
| `NullSink` | Discard all events (tests, benchmarks) |
| `CallbackSink::new(f)` | Drive any `Fn(AuditEvent)` closure |
| Custom `impl AuditSink` | Any destination you need |

## License

MIT
