# rune-axum-sanitize

> Input sanitization middleware for Axum — strips HTML tags and null bytes from query params and request bodies.

[![crates.io](https://img.shields.io/crates/v/rune-axum-sanitize)](https://crates.io/crates/rune-axum-sanitize)
[![docs.rs](https://img.shields.io/docsrs/rune-axum-sanitize)](https://docs.rs/rune-axum-sanitize)
[![license](https://img.shields.io/crates/l/rune-axum-sanitize)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

## What it does

Protects Axum applications from reflected XSS and null-byte injection by intercepting
requests before they reach any handler. HTML tags are stripped from query parameter values;
null bytes are removed from request bodies. Both transforms are individually configurable.

Security researchers and pentesters will also find the standalone `strip_html`, `escape_html`,
`strip_null_bytes`, and `sanitize_query` functions useful outside of an Axum context.

## Installation

```toml
[dependencies]
rune-axum-sanitize = "0.1"
```

## Usage

### Default layer — all sanitization enabled

```rust,no_run
use axum::{routing::get, Router};
use rune_axum_sanitize::SanitizeLayer;

#[tokio::main]
async fn main() {
    let app: Router = Router::new()
        .route("/search", get(|| async { "ok" }))
        .layer(SanitizeLayer::default());

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
```

### Custom configuration

```rust,no_run
use axum::{routing::get, Router};
use rune_axum_sanitize::{SanitizeConfig, SanitizeLayer};

#[tokio::main]
async fn main() {
    let config = SanitizeConfig {
        strip_html_from_query: true,
        strip_null_bytes_from_body: true,
        max_body_bytes: Some(1_048_576), // 1 MB limit
    };

    let app: Router = Router::new()
        .route("/", get(|| async { "ok" }))
        .layer(SanitizeLayer::new(config));

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
```

### Standalone functions

```rust
use rune_axum_sanitize::{strip_html, escape_html, strip_null_bytes, sanitize_query};

let clean = strip_html("<script>alert(1)</script>hello");
assert_eq!(clean, "hello");

let safe = escape_html("<b>bold & bright</b>");
assert_eq!(safe, "&lt;b&gt;bold &amp; bright&lt;/b&gt;");

let bytes = strip_null_bytes(b"hel\x00lo");
assert_eq!(bytes, b"hello");

let query = sanitize_query("q=<img src=x onerror=alert(1)>&page=2");
assert_eq!(query, "q=&page=2");
```

## Output

A request like:

```
GET /search?q=<script>alert(1)</script>&page=2
```

reaches the handler as:

```
GET /search?q=alert(1)&page=2
```

A POST body containing `hel\x00lo` reaches the handler as `hello`.

## Configuration

| Field | Default | Effect |
|-------|---------|--------|
| `strip_html_from_query` | `true` | Strip HTML tags from all query parameter values |
| `strip_null_bytes_from_body` | `true` | Remove 0x00 bytes from the request body |
| `max_body_bytes` | `None` | Optional cap on body bytes buffered for null-byte stripping |

## License

MIT
