# rune-axum-ratelimit

> Rate limiter middleware for Axum — fixed-window or GCRA per client, pluggable store,
> spoof-resistant client IPs, IETF `RateLimit` headers.

[![crates.io](https://img.shields.io/crates/v/rune-axum-ratelimit)](https://crates.io/crates/rune-axum-ratelimit)
[![docs.rs](https://img.shields.io/docsrs/rune-axum-ratelimit)](https://docs.rs/rune-axum-ratelimit)
[![license](https://img.shields.io/crates/l/rune-axum-ratelimit)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

A [`tower::Layer`](https://docs.rs/tower/latest/tower/trait.Layer.html) that counts requests per
client and rejects clients over their quota with `429 Too Many Requests`, `Retry-After`, and the
`RateLimit` / `RateLimit-Policy` headers of
[draft-ietf-httpapi-ratelimit-headers](https://datatracker.ietf.org/doc/draft-ietf-httpapi-ratelimit-headers/).

- **Spoof-resistant keys.** Clients are identified by the socket peer IP. `X-Forwarded-For`,
  `Forwarded` or a header such as `CF-Connecting-IP` is used only when the peer is a proxy you
  trust, and the chain is walked from the right.
- **Two algorithms.** Fixed window (default) or GCRA for a smooth rate with a configurable burst.
- **Pluggable async store.** `RateLimitStore` trait; the bundled `InMemoryStore` is bounded
  (expired keys are swept, and at capacity the keys nearest expiry are evicted).
- **IPv6-aware.** IPv4-mapped addresses fold into IPv4; optional `/64` bucketing.

> [!IMPORTANT]
> Serve the app with `into_make_service_with_connect_info::<SocketAddr>()`. Without the
> `ConnectInfo<SocketAddr>` extension a request is rejected with `500` by default
> (`MissingIp::Reject`), or counted against one shared key (`MissingIp::SharedKey`).

## Installation

```toml
[dependencies]
rune-axum-ratelimit = "0.3"
```

## Usage

### Defaults (100 req/60 s per peer IP)

```rust
use std::net::SocketAddr;
use axum::{routing::get, Router};
use rune_axum_ratelimit::RateLimitLayer;

let app: Router = Router::new()
    .route("/api", get(handler))
    .layer(RateLimitLayer::default());

let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await?;
axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).await?;
```

### GCRA behind a reverse proxy

```rust
use std::time::Duration;
use rune_axum_ratelimit::{Algorithm, ClientIpConfig, RateLimitConfig, RateLimitLayer};

let layer = RateLimitLayer::new(
    RateLimitConfig::new()
        .requests(50)
        .window(Duration::from_secs(30))
        .algorithm(Algorithm::Gcra)
        .burst(10)
        .ipv6_prefix(64)
        .client_ip(ClientIpConfig::new().trust_proxy("10.0.0.0/8")?),
);
```

### Per-API-key limiting

```rust
use http::HeaderName;
use rune_axum_ratelimit::{KeyExtractor, RateLimitConfig, RateLimitLayer};

// Requests without the header (or with an overlong one) are keyed by client IP instead.
let layer = RateLimitLayer::new(
    RateLimitConfig::new().key(KeyExtractor::Header(HeaderName::from_static("x-api-key"))),
);
```

### A custom (e.g. distributed) store

```rust
use std::sync::Arc;
use rune_axum_ratelimit::store::{BoxFuture, Decision, Quota, RateLimitStore, StoreError};
use rune_axum_ratelimit::{RateLimitConfig, RateLimitLayer};

struct RedisStore { /* connection pool */ }

impl RateLimitStore for RedisStore {
    fn check<'a>(&'a self, key: &'a str, quota: &'a Quota)
        -> BoxFuture<'a, Result<Decision, StoreError>>
    {
        Box::pin(async move {
            // Run the GCRA or fixed-window update atomically in a Lua script, using the
            // Redis server clock, and set the key to expire after `Decision::reset`.
            todo!()
        })
    }
}

let layer = RateLimitLayer::with_store(RateLimitConfig::new(), Arc::new(RedisStore {}));
```

The algorithms are exposed as pure functions (`store::fixed_window`, `store::gcra`) that
document the exact state transition a backend must perform. No Redis implementation is bundled.

## Configuration

| Method | Default | Description |
|--------|---------|-------------|
| `.requests(u64)` | `100` | Requests per window per client (also resets `burst`). |
| `.window(Duration)` | `60 s` | Window length. |
| `.algorithm(Algorithm)` | `FixedWindow` | `FixedWindow` or `Gcra`. |
| `.burst(u64)` | `requests` | GCRA burst size. |
| `.status(StatusCode)` | `429` | Status when the limit is exceeded. |
| `.key(KeyExtractor)` | `ClientIp` | `ClientIp` or `Header(name)` (falls back to IP). |
| `.client_ip(ClientIpConfig)` | peer only | Trusted proxies and which header they set. |
| `.ipv6_prefix(u8)` | `128` | Bucket IPv6 clients by prefix; `64` is recommended for public services. |
| `.missing_ip(MissingIp)` | `Reject(500)` | Behaviour without `ConnectInfo<SocketAddr>`. |
| `.on_store_error(OnStoreError)` | `Reject(503)` | Behaviour when the store fails; `Allow` fails open. |
| `.headers(bool)` | `true` | Emit `RateLimit` / `RateLimit-Policy`. |
| `.policy_name(&str)` | `"default"` | Policy name in those headers. |

## Output

An allowed request carries the quota state:

```
HTTP/1.1 200 OK
ratelimit-policy: "default";q=100;w=60
ratelimit: "default";r=99;t=60
```

A rejected request:

```
HTTP/1.1 429 Too Many Requests
ratelimit-policy: "default";q=100;w=60
ratelimit: "default";r=0;t=42
retry-after: 42
```

## Migrating from 0.1

0.3: re-exported rune-cidr types moved to rune-cidr 0.2.

0.2 changes security-relevant defaults.

- **Clients are keyed by socket peer IP, not `X-Forwarded-For`.** 0.1 used the leftmost
  `X-Forwarded-For` entry, which let any client get a fresh bucket per request or exhaust a
  victim's bucket. Serve with `into_make_service_with_connect_info::<SocketAddr>()`, and behind a
  proxy add `.client_ip(ClientIpConfig::new().trust_proxy("<proxy CIDR>")?)`.
- **`KeyExtractor::XForwardedFor` is removed**; `KeyExtractor::ClientIp` is the default.
- **Requests without a key are no longer passed uncounted.** No `ConnectInfo` → `500` (or
  `MissingIp::SharedKey`); `KeyExtractor::Header` without the header → keyed by client IP.
- **Responses carry `RateLimit` / `RateLimit-Policy` headers**; disable with `.headers(false)`.
- **The in-memory store is bounded** (`InMemoryStore::with_max_keys`, default 100 000 keys).
- **`RateLimitService` requires `S: Clone`** (true for Axum routers and handlers).
- Tests that call the router with `oneshot` must insert
  `axum::extract::ConnectInfo(SocketAddr)` into the request extensions.

## License

MIT
