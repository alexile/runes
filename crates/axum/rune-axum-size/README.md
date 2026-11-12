# rune-axum-size

> Request body size limiter — Tower middleware for Axum.

[![crates.io](https://img.shields.io/crates/v/rune-axum-size)](https://crates.io/crates/rune-axum-size)
[![docs.rs](https://img.shields.io/docsrs/rune-axum-size)](https://docs.rs/rune-axum-size)
[![license](https://img.shields.io/crates/l/rune-axum-size)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

A [`tower::Layer`](https://docs.rs/tower/latest/tower/trait.Layer.html) that caps how many request body bytes reach your handlers. A declared `Content-Length` over the limit is rejected before the body is read; everything else is counted on the actual byte stream, so chunked uploads and clients that lie about their length are caught too. Works with Axum, Hyper, and any Tower-compatible framework.

## Security notes

- **The limit is enforced on the real body.** The body is wrapped in a `LimitedBody` that errors once the bytes received exceed the limit. Requests without `Content-Length` (chunked / streaming) are limited too. Versions 0.1.x only checked the header and let such bodies through.
- **`Content-Length` is cross-checked.** A body longer than its declared `Content-Length` is cut off and answered `400 Bad Request`. Malformed or conflicting `Content-Length` values are rejected with `400` up front.
- **Streaming handlers see the error** from `poll_frame` / `frame()`. Whatever the handler returns afterwards, the middleware replaces the response with its own rejection, so a handler that ignores the error cannot turn an oversized upload into a `200`.
- **No information leak.** Rejections are a bare status line with an empty body: no limit value, no parser detail.
- **Optional header limits.** `.max_headers(n)` and `.max_header_bytes(n)` reject with `431`. They run on already-parsed headers; keep your server's own parser limits (hyper `max_headers`, `max_buf_size`) as the first line of defence.
- **Axum's `DefaultBodyLimit` (2 MiB)** still applies to its buffering extractors (`Bytes`, `Json`, …). If this layer allows more, raise or disable that default too.

## Installation

```toml
[dependencies]
rune-axum-size = "0.2"
```

## Usage

### Secure defaults (1 MiB limit, 413 Payload Too Large)

```rust
use axum::{routing::post, Router};
use rune_axum_size::BodyLimitLayer;

let app: Router = Router::new()
    .route("/upload", post(handler))
    .layer(BodyLimitLayer::default());
```

### Custom configuration

```rust
use axum::{routing::post, Router};
use http::StatusCode;
use rune_axum_size::{BodyLimit, BodyLimitLayer};

// Allow up to 10 MiB; return 422 instead of 413
let layer = BodyLimitLayer::new(
    BodyLimit::new()
        .limit(10 * 1024 * 1024)
        .status(StatusCode::UNPROCESSABLE_ENTITY),
);

let app: Router = Router::new()
    .route("/upload", post(handler))
    .layer(layer);
```

### Per-route and per-method limits

Attach a layer to a method router to give one route or method its own limit:

```rust
use axum::{routing::post, Router};
use rune_axum_size::{BodyLimit, BodyLimitLayer};

let app: Router = Router::new()
    .route(
        "/upload",
        post(handler).layer(BodyLimitLayer::new(BodyLimit::new().limit(50 * 1024 * 1024))),
    )
    .layer(BodyLimitLayer::default());
```

## Configuration

| Method | Default | Description |
|--------|---------|-------------|
| `.limit(u64)` | `1_048_576` (1 MiB) | Maximum allowed body size in bytes, counted on the actual stream. |
| `.status(StatusCode)` | `413` | Status code returned when the limit is exceeded. |
| `.max_headers(usize)` | off | Maximum number of header fields (`431` when exceeded). |
| `.max_header_bytes(usize)` | off | Maximum total bytes of header names + values (`431`). |

| Condition | Response |
|-----------|----------|
| Declared `Content-Length` over the limit | configured status (`413`), body never read |
| Streamed bytes exceed the limit | configured status (`413`) |
| Body longer than its declared `Content-Length` | `400` |
| Malformed or conflicting `Content-Length` | `400` |
| Header count / size over limit | `431` |

## Migrating from 0.1

- `BodyLimitService` now passes `Request<LimitedBody<ReqBody>>` to the inner service and requires `ReqBody: http_body::Body`. Axum routers accept any body type, so `.layer(BodyLimitLayer::…)` code compiles unchanged. Hand-written Tower services bound to a concrete body type must accept `LimitedBody` or be generic over the body.
- Requests without `Content-Length` are now limited, and bad `Content-Length` values get `400`.
- `BodyLimit` and `BodyLimitLayer` are now `Copy`.

## Output

A POST request with a body exceeding the limit:

```
HTTP/1.1 413 Payload Too Large
```

## License

MIT
