# rune-axum-bearer

> Bearer token extractor for Axum — typed extraction from `Authorization` headers.

[![crates.io](https://img.shields.io/crates/v/rune-axum-bearer)](https://crates.io/crates/rune-axum-bearer)
[![docs.rs](https://img.shields.io/docsrs/rune-axum-bearer)](https://docs.rs/rune-axum-bearer)
[![license](https://img.shields.io/crates/l/rune-axum-bearer)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

An Axum [`FromRequestParts`](https://docs.rs/axum/latest/axum/extract/trait.FromRequestParts.html) extractor that pulls the raw token from an `Authorization: Bearer <token>` header. Requests with a missing or malformed header are rejected with `401 Unauthorized` and a `WWW-Authenticate: Bearer` response header before the handler runs.

> [!NOTE]
> This crate surfaces the raw token string — it does not verify or validate it.
> For JWT validation see [`rune-axum-jwt`](https://crates.io/crates/rune-axum-jwt).

## Installation

```toml
[dependencies]
rune-axum-bearer = "0.1"
```

## Usage

### Required bearer token

```rust
use axum::{routing::get, Router};
use rune_axum_bearer::BearerToken;

async fn handler(BearerToken(token): BearerToken) -> String {
    format!("token={token}")
}

let app: Router = Router::new().route("/api", get(handler));
```

### Optional bearer token

Wrap in `Option<BearerToken>` when the header is not always present:

```rust
use axum::{routing::get, Router};
use rune_axum_bearer::BearerToken;

async fn handler(token: Option<BearerToken>) -> String {
    match token {
        Some(BearerToken(t)) => format!("authenticated: {t}"),
        None => "anonymous".to_owned(),
    }
}

let app: Router = Router::new().route("/api", get(handler));
```

## Behaviour

| Condition | Response |
|-----------|----------|
| `Authorization: Bearer <token>` present | `200 OK` — `token` contains the raw string |
| Header absent | `401 Unauthorized` + `WWW-Authenticate: Bearer` |
| Wrong scheme (e.g. `Basic`) | `401 Unauthorized` + `WWW-Authenticate: Bearer` |
| `Authorization: Bearer` (no token) | `401 Unauthorized` + `WWW-Authenticate: Bearer` |

The scheme comparison is case-insensitive (`bearer`, `Bearer`, `BEARER` all match).
Surrounding whitespace on the token is trimmed.

## Output

A request with a missing or invalid `Authorization` header:

```
HTTP/1.1 401 Unauthorized
www-authenticate: Bearer
```

## License

MIT
