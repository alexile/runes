# rune-axum-cache

> Cache-Control and conditional-request middleware for Axum — sets caching directives and validators, answers 304/412 per RFC 9110.

[![crates.io](https://img.shields.io/crates/v/rune-axum-cache)](https://crates.io/crates/rune-axum-cache)
[![docs.rs](https://img.shields.io/docsrs/rune-axum-cache)](https://docs.rs/rune-axum-cache)
[![license](https://img.shields.io/crates/l/rune-axum-cache)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

A [`tower::Layer`](https://docs.rs/tower/latest/tower/trait.Layer.html) that sets `Cache-Control` on successful `GET`/`HEAD` responses, per path, and answers conditional requests from the `ETag` / `Last-Modified` your handler sets: a current cached copy gets an empty `304 Not Modified`, a failed `If-Match` / `If-Unmodified-Since` gets `412 Precondition Failed`. A sans-I/O core (`CacheControl`, `EntityTag`, `HttpDate`, `Validators`, `evaluate`) lets handlers set validators and run the same [RFC 9110 §13.2.2](https://www.rfc-editor.org/rfc/rfc9110#section-13.2.2) precondition algorithm themselves, before doing expensive or state-changing work.

Specifications: [RFC 9110](https://www.rfc-editor.org/rfc/rfc9110) (validators, conditional requests, HTTP-date), [RFC 9111](https://www.rfc-editor.org/rfc/rfc9111) (`Cache-Control`), [RFC 8246](https://www.rfc-editor.org/rfc/rfc8246) (`immutable`), [RFC 5861](https://www.rfc-editor.org/rfc/rfc5861) (`stale-while-revalidate`, `stale-if-error`).

## Installation

```toml
[dependencies]
rune-axum-cache = "0.1"
```

## Usage

### Defaults (`private, no-cache` + 304/412)

```rust
use axum::{routing::get, Router};
use rune_axum_cache::CacheLayer;

let app: Router = Router::new()
    .route("/", get(handler))
    .layer(CacheLayer::default());
```

### Directives per path, validators from the handler

```rust
use std::time::Duration;
use axum::{http::header, routing::get, Router};
use rune_axum_cache::{Cache, CacheControl, CacheLayer, EntityTag};

async fn report() -> ([(header::HeaderName, header::HeaderValue); 1], String) {
    let body = render_report();
    let etag = EntityTag::from_content(body.as_bytes()).to_header_value();
    ([(header::ETAG, etag)], body)
}

let app: Router = Router::new()
    .route("/report", get(report))
    .layer(CacheLayer::new(
        Cache::new()
            .cache_control(CacheControl::revalidate())
            .path("/assets", CacheControl::immutable_asset(Duration::from_secs(31_536_000)))
            .path("/account", CacheControl::sensitive()),
    ));
```

A request for `/report` with `If-None-Match` set to the tag it received earlier now gets `304 Not Modified` with no body.

Directives that let shared caches store the response (`public`, `s-maxage`, `must-revalidate`, `proxy-revalidate`) are turned into their `private` form when the request carried `Authorization` or the response sets a cookie, so a CDN never hands one user's response to another.

### Guarding writes in the handler

The layer never touches unsafe methods: by the time it sees a response, the write has happened. Evaluate preconditions in the handler instead:

```rust
use axum::http::{HeaderMap, Method, StatusCode};
use rune_axum_cache::{Precondition, Validators};

async fn update(method: Method, headers: HeaderMap) -> StatusCode {
    let current = Validators::new().with_etag(current_etag());
    if let Some(status) = current.evaluate(&method, &headers).status() {
        return status; // 412: the client edited a stale version
    }
    save();
    StatusCode::NO_CONTENT
}
```

## Configuration

| Method | Default | Description |
|--------|---------|-------------|
| `.cache_control(CacheControl)` | `private, no-cache` | Directives for requests that match no path override. |
| `.no_cache_control()` | — | Send no `Cache-Control` outside path overrides. |
| `.path(prefix, CacheControl)` | none | Directives for `prefix` and everything below it, matched on `/` segment boundaries. The longest matching prefix wins. |
| `.skip_path(prefix)` | none | No `Cache-Control` under `prefix`. |
| `.override_existing(bool)` | `false` | Replace a `Cache-Control` the handler set itself. |
| `.conditional(bool)` | `true` | Answer conditional `GET`/`HEAD` requests with `304` / `412`. |

`Cache-Control` is only added to `GET`/`HEAD` responses with a 2xx or 304 status; error responses are left alone. `Cache::cache_control_for(path)` returns the directives that apply to a path, without a runtime.

### `CacheControl` builder

`public`, `private`, `no_cache`, `no_store`, `no_transform`, `must_revalidate`, `proxy_revalidate`, `must_understand`, `immutable`, `max_age`, `s_maxage`, `stale_while_revalidate`, `stale_if_error`. Presets: `sensitive()` (`no-store`), `revalidate()` (`private, no-cache`), `immutable_asset(max_age)` (`public, max-age=N, immutable`).

## Behaviour notes

- Conditional handling only applies to `200 OK` responses to `GET`/`HEAD`. The `304` keeps `Cache-Control`, `Content-Location`, `Date`, `ETag`, `Expires` and `Vary` (plus `Last-Modified` when there is no `ETag`), as RFC 9110 §15.4.5 asks.
- Malformed fields are handled conservatively: an unparseable `If-Match` fails (`412`); an unparseable `If-None-Match`, invalid dates and repeated date fields are ignored, so the full response is sent.
- The handler still runs to produce its validators; the layer saves bandwidth, not work. Short-circuit in the handler with `Validators::evaluate` when generating the body is expensive.
- `EntityTag::from_content` is the first 128 bits of SHA-256, hex-encoded: stable across restarts and deploys.

## License

MIT
