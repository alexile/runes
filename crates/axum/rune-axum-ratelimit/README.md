# rune-axum-ratelimit

> Rate limiter middleware for Axum — fixed-window or GCRA per client, in-memory or Redis
> store, spoof-resistant client IPs, IETF `RateLimit` headers.

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
- **Redis store** (`redis` feature) for one limit shared by many instances: atomic Lua
  scripts, Redis server time, expiring keys, optional hashed key names, per-call timeouts.
- **IPv6-aware.** IPv4-mapped addresses fold into IPv4; optional `/64` bucketing.

> [!IMPORTANT]
> Serve the app with `into_make_service_with_connect_info::<SocketAddr>()`. Without the
> `ConnectInfo<SocketAddr>` extension a request is rejected with `500` by default
> (`MissingIp::Reject`), or counted against one shared key (`MissingIp::SharedKey`).

## Installation

```toml
[dependencies]
rune-axum-ratelimit = "0.3"
# or, with the Redis store:
rune-axum-ratelimit = { version = "0.3", features = ["redis"] }
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

### Redis store (shared across instances)

```rust
use std::sync::Arc;
use std::time::Duration;
use rune_axum_ratelimit::redis::RedisStore;
use rune_axum_ratelimit::{Algorithm, OnStoreError, RateLimitConfig, RateLimitLayer};

let store = RedisStore::connect("redis://redis.internal:6379/0")
    .await?
    .prefix("myapp:rl")                // one prefix per app / per differently configured layer
    .hash_keys(b"long random secret")  // no client IPs or API keys in Redis key names
    .timeout(Duration::from_millis(200));

let layer = RateLimitLayer::with_store(
    RateLimitConfig::new()
        .requests(100)
        .algorithm(Algorithm::Gcra)
        // Default: Redis down or slow → 503 (fail closed). To fail open instead:
        .on_store_error(OnStoreError::Allow),
    Arc::new(store),
);
```

How it works:

- **Atomic.** Each check is one Lua script. GCRA keeps one timestamp per client; fixed window
  is `INCR` plus `PEXPIRE` in the same script, so a counter can never be left without a TTL.
  Denied requests don't bump the counter.
- **Server time.** GCRA reads the clock with Redis `TIME`, so app instances with skewed clocks
  still agree. Fixed-window expiry is a Redis TTL, which is server time too. Resolution is
  1 µs for GCRA and 1 ms for fixed window.
- **Expiring keys.** Every key's TTL is the time until that client's quota is fully restored.
- **Script cache.** Scripts run with `EVALSHA`; on `NOSCRIPT` (restart, failover,
  `SCRIPT FLUSH`) the call is retried once with `EVAL`.
- **Bounded calls.** Each check is limited by `.timeout(..)` (default 500 ms). A timeout or a
  Redis error is a store error, handled by `.on_store_error(..)`: `503` by default, or
  `OnStoreError::Allow` to fail open.
- **Key names** are `<prefix>:<fw|gcra>:{<client>}`. `<client>` is the raw key (`ip:203.0.113.7`,
  `hdr:<header value>`) unless `.hash_keys(secret)` is set, in which case it is a 128-bit
  HMAC-SHA256 of it. A plain hash would not help: the IPv4 space is small enough to reverse it.

`RedisStore` is generic over `redis::aio::ConnectionLike`, so `RedisStore::new(conn)` accepts a
configured `ConnectionManager` or a cluster connection.

### Deployment notes

- **Several instances behind a load balancer.** Point every instance at the same Redis and use
  the same prefix, quota and (if set) hashing secret; they then enforce one shared limit. With
  `InMemoryStore` each instance would allow the full quota on its own.
- **Trusted proxies.** Behind a load balancer the socket peer is the proxy, so every client
  would share one bucket. List the proxies' addresses so the client IP is taken from the
  forwarding header they set, and only from them:

  ```rust
  RateLimitConfig::new().client_ip(
      ClientIpConfig::new()
          .trust_proxy("10.0.0.0/8")?      // your load balancers / ingress
          .trust_proxy("fd00::/8")?,
  )
  ```

  Never trust `0.0.0.0/0`: any client could then pick its own key. If your proxies set a
  single-value header such as `CF-Connecting-IP`, select it with `ClientIpConfig::header(..)`.
- **Redis Cluster.** Both scripts touch a single key, so they run on any cluster node with no
  `CROSSSLOT` errors. The client part of each key is wrapped in `{..}`, a hash tag, so if you
  extend the scheme with a multi-key script (for example a per-client and a per-route key),
  keep the same `{client}` tag in every key it touches and they will hash to the same slot.
- **Persistence and failover.** Rate-limit state is short-lived; losing it on a failover only
  resets some buckets. No persistence is needed, but give the store its own logical DB or
  prefix, and set `maxmemory-policy volatile-ttl` or `allkeys-lru` if Redis is shared.
- **Latency.** Each request costs one round trip. Keep Redis close to the app and set the
  timeout well below your request budget.

### A custom store

```rust
use rune_axum_ratelimit::store::{BoxFuture, Decision, Quota, RateLimitStore, StoreError};

struct MyStore { /* connection pool */ }

impl RateLimitStore for MyStore {
    fn check<'a>(&'a self, key: &'a str, quota: &'a Quota)
        -> BoxFuture<'a, Result<Decision, StoreError>>
    {
        Box::pin(async move {
            // Apply the update atomically, using the backend's clock, and let the key
            // expire after `Decision::reset`.
            todo!()
        })
    }
}
```

The algorithms are exposed as pure functions (`store::fixed_window`, `store::gcra`) that
document the exact state transition a backend must perform.

### Testing the Redis store

The Redis tests in `tests/redis.rs` run the scripts against a real server and are skipped
unless `REDIS_URL` is set. Use a throwaway instance (one test runs `SCRIPT FLUSH`):

```sh
docker run --rm -d -p 6379:6379 redis:7
REDIS_URL=redis://127.0.0.1:6379/ cargo test -p rune-axum-ratelimit --features redis
```

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
| `.on_store_error(OnStoreError)` | `Reject(503)` | Behaviour when the store fails (including Redis errors and timeouts); `Allow` fails open. |
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
