# rune-axum-cors

> CORS middleware for Axum — exact origin allowlists, preflight handling, configs vetted by rune-cors at build time.

[![crates.io](https://img.shields.io/crates/v/rune-axum-cors)](https://crates.io/crates/rune-axum-cors)
[![docs.rs](https://img.shields.io/docsrs/rune-axum-cors)](https://docs.rs/rune-axum-cors)
[![license](https://img.shields.io/crates/l/rune-axum-cors)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

A [`tower::Layer`](https://docs.rs/tower/latest/tower/trait.Layer.html) implementing the server side of the [Fetch CORS protocol](https://fetch.spec.whatwg.org/#http-cors-protocol). It answers preflights and adds `Access-Control-*` headers for allowed origins. It is the writing side of [`rune-cors`](../../web/rune-cors), which analyses CORS response headers.

Every policy is **audited before it serves**. `CorsLayer::new` runs the headers the middleware would send for a set of attacker-style probe origins (an unrelated site, `null`, subdomains, plain-`http` variants, unanchored lookalikes such as `evilexample.com` and `example.com.evil.net`) through `rune_cors::run`, and refuses the policy when the analyzer rates it insecure.

| Refused configuration                                       | rune-cors check id               |
| ----------------------------------------------------------- | -------------------------------- |
| `*` with credentials (always)                               | `cors.wildcard_with_credentials` |
| Predicate that reflects any origin                          | `cors.origin_reflection`         |
| `null` origin allowed                                       | `cors.null_origin`               |
| Predicate with a suffix/prefix match that admits lookalikes | `cors.unanchored_allowlist`      |
| `http://` variant of a secure origin allowed                | `cors.insecure_origin`           |
| Private Network Access for attacker-controllable origins    | `cors.private_network_access`    |

## Installation

```toml
[dependencies]
rune-axum-cors = "0.1"
```

## Usage

```rust
use std::time::Duration;
use axum::{routing::get, Router};
use http::{HeaderName, Method};
use rune_axum_cors::{Cors, CorsLayer};

let layer = CorsLayer::new(
    Cors::new()
        .site("https://example.com")
        .allow_origins(["https://app.example.com", "https://admin.example.com"])
        .allow_credentials(true)
        .allow_methods([Method::GET, Method::POST, Method::PUT])
        .allow_headers([HeaderName::from_static("content-type")])
        .max_age(Duration::from_secs(600)),
)?;

// Weaknesses below the rejection threshold are kept for logging.
for weakness in &layer.report().weaknesses {
    eprintln!("{}: {}", weakness.kind.check_id(), weakness.message);
}

let app: Router = Router::new()
    .route("/api/items", get(handler))
    .layer(layer);
```

The dangerous configuration fails at build time:

```rust
use rune_axum_cors::{Cors, CorsLayer};

let err = CorsLayer::new(Cors::new().allow_any_origin().allow_credentials(true)).unwrap_err();
// insecure CORS policy: cors.wildcard_with_credentials (low): ...
println!("{err}");
```

## Configuration

| Method                          | Default            | Description                                                                                              |
| ------------------------------- | ------------------ | -------------------------------------------------------------------------------------------------------- |
| `.site(origin)`                 | none               | The protected site's origin; the audit judges allowed origins relative to it.                            |
| `.allow_origin(origin)`         | none               | Allow one exact origin (normalised). `"*"` = any origin, `"null"` = opaque origin.                      |
| `.allow_origins(iter)`          | none               | Allow several exact origins.                                                                             |
| `.allow_any_origin()`           | off                | `Access-Control-Allow-Origin: *`, for public resources only.                                             |
| `.allow_subdomains(bool)`       | off                | Also allow subdomains of allowed origins, same scheme and port.                                          |
| `.allow_origin_fn(f)`           | none               | Custom predicate; probed by the audit with attacker-style origins.                                       |
| `.allow_credentials(bool)`      | off                | `Access-Control-Allow-Credentials: true`.                                                                |
| `.allow_methods(iter)`          | `GET, HEAD, POST`  | Methods allowed in preflights.                                                                           |
| `.allow_headers(iter)`          | none               | Request headers allowed in preflights (`*` only without credentials).                                    |
| `.expose_headers(iter)`         | none               | `Access-Control-Expose-Headers`.                                                                         |
| `.max_age(Duration)`            | not sent           | `Access-Control-Max-Age` on preflights.                                                                  |
| `.allow_private_network(bool)`  | off                | Answer Private Network Access preflights.                                                                |
| `.reject_at(Severity)`          | `Low`              | Audit severity that rejects the policy; never above `High`.                                              |
| `.deny_status(StatusCode)`      | `403`              | Status of refused preflights.                                                                            |

## Behaviour

- **Preflight** (`OPTIONS` with `Origin` and `Access-Control-Request-Method`): answered directly with `204 No Content` and the CORS headers when the origin, method and every requested header are allowed; otherwise with the deny status and no CORS headers. Preflights never reach handlers.
- **Actual requests**: passed to the inner service. Allowed origins get `Access-Control-Allow-Origin` (the echoed origin, or `*`), credentials and exposed headers. The layer owns these headers and replaces or removes any the handler set.
- **`Vary: Origin`** is added to every response unless the policy is `*`.

## License

MIT
