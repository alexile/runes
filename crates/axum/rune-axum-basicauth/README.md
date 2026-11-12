# rune-axum-basicauth

> HTTP Basic authentication extractor and middleware for Axum with constant-time credential comparison.

[![crates.io](https://img.shields.io/crates/v/rune-axum-basicauth)](https://crates.io/crates/rune-axum-basicauth)
[![docs.rs](https://img.shields.io/docsrs/rune-axum-basicauth)](https://docs.rs/rune-axum-basicauth)
[![license](https://img.shields.io/crates/l/rune-axum-basicauth)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

Parses `Authorization: Basic <base64>` headers, decodes RFC 7617 credentials, and validates
them against a configured username and password using constant-time byte comparison to prevent
timing attacks. Returns `401 Unauthorized` with a `WWW-Authenticate` header on any failure.

> [!WARNING]
> Basic authentication encodes credentials in base64, which is trivially reversible.
> Always serve over HTTPS in production.

## Installation

```toml
[dependencies]
rune-axum-basicauth = "0.1"
```

## Usage

### Middleware — protect entire route groups

```rust,no_run
use axum::{routing::get, Router};
use rune_axum_basicauth::BasicAuthLayer;

#[tokio::main]
async fn main() {
    let app = Router::new()
        .route("/admin", get(|| async { "dashboard" }))
        .route_layer(BasicAuthLayer::new("admin", "s3cr3t"));

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
```

### Extractor — access credentials inside a handler

```rust,no_run
use axum::{routing::get, Router};
use rune_axum_basicauth::BasicAuth;

async fn handler(auth: BasicAuth) -> String {
    format!("Hello, {}!", auth.username)
}

let app: Router = Router::new().route("/", get(handler));
```

## Responses

| Condition | Status | `WWW-Authenticate` |
|-----------|--------|--------------------|
| Missing `Authorization` header | `401 Unauthorized` | `Basic realm="protected"` |
| Malformed base64 or no `:` separator | `401 Unauthorized` | `Basic realm="protected"` |
| Wrong username or password | `401 Unauthorized` | `Basic realm="protected"` |
| Correct credentials | Passes through | — |

## Constant-time comparison

[`BasicAuthLayer`] compares both username and password bytes with
[`subtle::ConstantTimeEq`](https://docs.rs/subtle), evaluating both comparisons unconditionally
before branching. This prevents timing side-channels that would allow an attacker to determine
correct credentials byte-by-byte.

## License

MIT
