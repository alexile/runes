# rune-axum-apikey

> API key extractor and middleware for Axum — validates keys from headers, bearer tokens, or query parameters.

[![crates.io](https://img.shields.io/crates/v/rune-axum-apikey)](https://crates.io/crates/rune-axum-apikey)
[![docs.rs](https://img.shields.io/docsrs/rune-axum-apikey)](https://docs.rs/rune-axum-apikey)
[![license](https://img.shields.io/crates/l/rune-axum-apikey)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

Accepts an API key from any combination of three sources — a configurable header
(default `X-Api-Key`), an `Authorization: Bearer` token, or a configurable query
parameter (default `api_key`) — and validates it with constant-time comparison
to prevent timing attacks.

## Installation

```toml
[dependencies]
rune-axum-apikey = "0.1"
```

## Usage

### Middleware — reject invalid keys before the handler

```rust,no_run
use axum::{routing::get, Router};
use rune_axum_apikey::ApiKeyLayer;

#[tokio::main]
async fn main() {
    let app = Router::new()
        .route("/data", get(|| async { "secret" }))
        .route_layer(ApiKeyLayer::new("super-secret-key"));

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
```

Clients can send the key via any of the three sources:

```bash
curl -H "X-Api-Key: super-secret-key" http://localhost:3000/data
curl -H "Authorization: Bearer super-secret-key" http://localhost:3000/data
curl "http://localhost:3000/data?api_key=super-secret-key"
```

### Extractor — access the raw key in a handler

```rust,no_run
use axum::{routing::get, Router};
use rune_axum_apikey::ApiKey;

async fn handler(ApiKey(key): ApiKey) -> String {
    format!("key ends with: ...{}", &key[key.len().saturating_sub(4)..])
}

let app: Router = Router::new().route("/", get(handler));
```

### Custom sources

```rust,no_run
use rune_axum_apikey::ApiKeyLayer;

// Accept only via a custom header — no bearer, no query param.
let layer = ApiKeyLayer::new("secret")
    .header_name("x-token")
    .bearer(false)
    .query_param("disabled");
```

## Key lookup order

1. Custom header (`X-Api-Key` by default)
2. `Authorization: Bearer <key>` (if not disabled)
3. Query parameter (`?api_key=` by default)

## Configuration

| Builder method | Default | Effect |
|----------------|---------|--------|
| `.header_name("x-token")` | `x-api-key` | Header to check |
| `.query_param("token")` | `api_key` | Query parameter to check |
| `.bearer(false)` | `true` | Enable/disable bearer token extraction |

## License

MIT
