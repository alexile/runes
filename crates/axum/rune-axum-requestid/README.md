# rune-axum-requestid

> Request-id and W3C traceparent propagation layer for Axum — extensions, response header and tracing span

[![crates.io](https://img.shields.io/crates/v/rune-axum-requestid)](https://crates.io/crates/rune-axum-requestid)
[![docs.rs](https://img.shields.io/docsrs/rune-axum-requestid)](https://docs.rs/rune-axum-requestid)
[![license](https://img.shields.io/crates/l/rune-axum-requestid)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

A [`tower::Layer`](https://docs.rs/tower/latest/tower/trait.Layer.html) that gives every request a correlation id and a [W3C Trace Context](https://www.w3.org/TR/trace-context/):

- a valid incoming `x-request-id` is propagated, otherwise a random UUID v4 is generated;
- a valid incoming `traceparent` is continued with a fresh span id, otherwise a new trace starts;
- `RequestId` and `TraceContext` are inserted into the request extensions (and are Axum extractors), and the request headers are rewritten so they can be forwarded downstream;
- the id is echoed in the response header and response extensions;
- with the `tracing` feature (default), the inner service runs inside an `INFO` span named `request` carrying `request_id`, `method`, `path`, `trace_id`, `span_id` and `parent_span_id`, so every log line for the request carries them.

Incoming values are untrusted: a request id must be 1–128 bytes of visible ASCII (no spaces, line breaks or escape sequences), and `traceparent` is parsed strictly per the specification. Invalid values are replaced, never echoed.

## Installation

```toml
[dependencies]
rune-axum-requestid = "0.1"
```

| Feature | Default | Description |
|---------|---------|-------------|
| `tracing` | on | Run each request inside a `tracing` span with the ids as fields. |

## Usage

```rust
use axum::{routing::get, Router};
use rune_axum_requestid::{RequestId, RequestIdLayer, TraceContext};

async fn handler(id: RequestId, trace: TraceContext) -> String {
    tracing::info!("handling"); // carries request_id, trace_id, span_id
    format!("{id} in trace {}", trace.trace_id_hex())
}

let app: Router = Router::new()
    .route("/", get(handler))
    .layer(RequestIdLayer::default());
```

Forward the context on outgoing calls with `trace.traceparent().to_string()` as the `traceparent` header and `id.as_str()` as `x-request-id`.

### Custom configuration

```rust
use http::HeaderName;
use rune_axum_requestid::{RequestIdConfig, RequestIdLayer};

let layer = RequestIdLayer::new(
    RequestIdConfig::default()
        .with_header(HeaderName::from_static("x-correlation-id"))
        .with_trust_incoming(false)        // edge service: always mint ids
        .with_trace_id_as_request_id(true), // one key for logs and traces
);
```

### Without Tower

The decision logic is sans-I/O and works on a `HeaderMap`:

```rust
use http::HeaderMap;
use rune_axum_requestid::{RequestIdConfig, TraceParent};

let resolved = RequestIdConfig::default().resolve(&HeaderMap::new());
assert!(resolved.generated);

let tp = TraceParent::parse("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01").unwrap();
assert!(tp.sampled());
```

## Configuration

| Method | Default | Description |
|--------|---------|-------------|
| `.with_header(HeaderName)` | `x-request-id` | Header carrying the id in both directions. |
| `.with_trust_incoming(bool)` | `true` | Propagate a valid incoming id, or always generate. |
| `.with_max_len(usize)` | `128` | Longest accepted incoming id, in bytes. |
| `.with_traceparent(bool)` | `true` | Read, continue and forward W3C `traceparent`. |
| `.with_sample_new_traces(bool)` | `true` | Sampled flag for traces started here. |
| `.with_trace_id_as_request_id(bool)` | `false` | Use the trace id as the id when none arrives. |
| `.with_response_header(bool)` | `true` | Echo the id in the response (unless the handler set it). |
| `.with_generator(Fn() -> RequestId)` | UUID v4 | How new ids are made. |

## Output

```
GET / HTTP/1.1
traceparent: 00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01

HTTP/1.1 200 OK
x-request-id: 3f0c1e9a-7b2d-4c41-9e8f-5a6b7c8d9e0f
```

```
INFO request{request_id=3f0c1e9a-… method=GET path=/ trace_id=4bf92f3577b34da6a3ce929d0e0e4736 span_id=… parent_span_id=00f067aa0ba902b7}: app: handling
```

## License

MIT
