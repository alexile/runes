# rune-axum-redirect-https

> Redirect HTTP requests to HTTPS — Tower middleware for Axum.

[![crates.io](https://img.shields.io/crates/v/rune-axum-redirect-https)](https://crates.io/crates/rune-axum-redirect-https)
[![docs.rs](https://img.shields.io/docsrs/rune-axum-redirect-https)](https://docs.rs/rune-axum-redirect-https)
[![license](https://img.shields.io/crates/l/rune-axum-redirect-https)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

A [`tower::Layer`](https://docs.rs/tower/latest/tower/trait.Layer.html) that detects incoming HTTP requests and issues a permanent redirect to the equivalent HTTPS URL. HTTPS requests are forwarded to the inner service unchanged. Works with Axum, Hyper, and any Tower-compatible framework.

## How detection works

The layer checks for HTTP in this priority order:

1. `X-Forwarded-Proto: http` — set by most reverse proxies for plain HTTP upstream connections.
2. URI scheme of `http` — present in direct (non-proxy) connections.

If neither indicator is present the request passes through unchanged.

## Installation

```toml
[dependencies]
rune-axum-redirect-https = "0.1"
```

## Usage

### Secure defaults (308 Permanent Redirect)

```rust
use axum::{routing::get, Router};
use rune_axum_redirect_https::RedirectHttpsLayer;

let app: Router = Router::new()
    .route("/", get(handler))
    .layer(RedirectHttpsLayer::default());
```

### Custom configuration

```rust
use axum::{routing::get, Router};
use http::StatusCode;
use rune_axum_redirect_https::{RedirectHttps, RedirectHttpsLayer};

// HTTP on :8080 → HTTPS on :8443, using 301 for legacy clients
let layer = RedirectHttpsLayer::new(
    RedirectHttps::new()
        .status(StatusCode::MOVED_PERMANENTLY)
        .https_port(8443),
);

let app: Router = Router::new()
    .route("/", get(handler))
    .layer(layer);
```

## Configuration

| Method | Default | Description |
|--------|---------|-------------|
| `.status(StatusCode)` | `308` | Redirect status code. `308` preserves the HTTP method; use `301` for legacy compatibility. |
| `.https_port(u16)` | none | HTTPS port in the redirect URL. Useful for non-standard port setups (e.g. `8080` → `8443`). |

> [!WARNING]
> `301 Moved Permanently` causes many browsers and HTTP clients to convert POST
> requests to GET. Prefer `308 Permanent Redirect` unless you have a specific
> compatibility requirement.

> [!NOTE]
> When no `Host` header is present the request is forwarded unchanged rather than
> returning a redirect without a `Location` header.

## Output

An HTTP request to `http://example.com/login` produces:

```
HTTP/1.1 308 Permanent Redirect
location: https://example.com/login
```

## License

MIT
