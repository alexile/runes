# rune-axum-compression

> Response compression middleware for Axum — negotiated gzip, deflate, br and zstd with a content-type allowlist and minimum size.

[![crates.io](https://img.shields.io/crates/v/rune-axum-compression)](https://crates.io/crates/rune-axum-compression)
[![docs.rs](https://img.shields.io/docsrs/rune-axum-compression)](https://docs.rs/rune-axum-compression)
[![license](https://img.shields.io/crates/l/rune-axum-compression)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

A [`tower::Layer`](https://docs.rs/tower/latest/tower/trait.Layer.html) that compresses response bodies with the content coding the client prefers, negotiated from `Accept-Encoding` per [RFC 9110 §12.5.3](https://www.rfc-editor.org/rfc/rfc9110#section-12.5.3). Only text-like responses are compressed by default, so images, archives and other already-compressed formats pass through, and bodies of known size below a threshold (1024 bytes) are left alone. Bodies are compressed as they stream, and trailers are forwarded. Works with Axum, Hyper and any Tower-compatible framework.

The decisions are sans-I/O functions: `negotiate`, `Compression::should_compress` and `compress`.

## Installation

```toml
[dependencies]
rune-axum-compression = "0.1"
# or, with every coding:
rune-axum-compression = { version = "0.1", features = ["full"] }
```

| Feature | Coding | Default |
|---------|--------|---------|
| `gzip` | `gzip` (RFC 1952) | yes |
| `deflate` | `deflate`, a zlib stream (RFC 1950) | yes |
| `br` | `br` (RFC 7932), pure Rust | no |
| `zstd` | `zstd` (RFC 8878), builds the bundled C libzstd | no |
| `full` | all of the above | no |

## Usage

### Defaults

```rust
use axum::{routing::get, Router};
use rune_axum_compression::CompressionLayer;

let app: Router = Router::new()
    .route("/", get(handler))
    .layer(CompressionLayer::default());
```

### Custom configuration

```rust
use axum::{routing::get, Router};
use rune_axum_compression::{Compression, CompressionLayer, Encoding, Level};

let layer = CompressionLayer::new(
    Compression::new()
        .encodings([Encoding::Brotli, Encoding::Gzip]) // server preference
        .level(Level::Fastest)
        .min_size(256)
        .content_type("application/x-yaml"),
);

let app: Router = Router::new().route("/", get(handler)).layer(layer);
```

### The decisions, without a server

```rust
use http::{header, HeaderMap, StatusCode};
use rune_axum_compression::{Compression, Encoding};

let config = Compression::new();
assert_eq!(config.negotiate("deflate;q=0.5, gzip"), Encoding::Gzip);

let mut headers = HeaderMap::new();
headers.insert(header::CONTENT_TYPE, "image/png".parse().unwrap());
assert!(!config.should_compress(StatusCode::OK, &headers, Some(64 * 1024)));
```

## Configuration

| Method | Default | Description |
|--------|---------|-------------|
| `.encodings(iter)` | zstd, br, gzip, deflate (those enabled) | Codings offered, most preferred first. Client weights win; ties go to this order. Empty disables compression. |
| `.level(Level)` | `Level::Default` | `Fastest`, `Default`, `Best` or `Precise(n)`, mapped to each coding's scale. |
| `.min_size(bytes)` | 1024 | Bodies of known size below this are not compressed. Streaming bodies of unknown size always are. |
| `.content_type(pattern)` | see below | Adds an allowlist pattern: `type/subtype`, `type/*` or `+suffix`. |
| `.content_types(iter)` | see below | Replaces the allowlist. |

Default allowlist: `text/*`, `application/json`, `application/javascript`, `application/xml`, `application/wasm`, `application/x-ndjson`, `image/svg+xml`, `+json`, `+xml`. `text/event-stream` is never compressed, because the encoder would hold events back.

## Behaviour

A response is **not** compressed when the request is `HEAD`; the status is 1xx, `204`, `206` or `304`; it has `Content-Range` or a non-identity `Content-Encoding`; it has `Cache-Control: no-transform`; its `Content-Type` is missing or not allowlisted; or its size is known and below `min_size`.

When a response is compressed, the layer sets `Content-Encoding`, removes `Content-Length` and `Accept-Ranges`, and turns a strong `ETag` into a weak one. Every eligible response gets `Vary: accept-encoding`, compressed or not, so caches keep the representations apart.

## Output

```
GET /data HTTP/1.1
Accept-Encoding: gzip, deflate, br

HTTP/1.1 200 OK
content-type: application/json
content-encoding: br
vary: accept-encoding
```

## License

MIT
