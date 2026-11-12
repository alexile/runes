# rune-axum-brute

> Account lockout middleware for Axum — blocks repeated authentication failures per client key.

[![crates.io](https://img.shields.io/crates/v/rune-axum-brute)](https://crates.io/crates/rune-axum-brute)
[![docs.rs](https://img.shields.io/docsrs/rune-axum-brute)](https://docs.rs/rune-axum-brute)
[![license](https://img.shields.io/crates/l/rune-axum-brute)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

## What it does

Tracks authentication failures (HTTP 401/403 responses) per client key and locks
out the key after a configurable threshold. Locked keys receive `429 Too Many Requests`
with a `Retry-After` header giving the remaining lockout. A pluggable `BruteForceStore`
trait lets you swap the backend for Redis, a database, or any custom store; the bundled
`InMemoryStore` is bounded (default 100 000 keys) so a flood of distinct keys cannot exhaust
memory.

IP-based lockout uses the **socket peer address** (`ConnectInfo<SocketAddr>`), never a
client-supplied `X-Forwarded-For`, so attackers cannot rotate the header to dodge lockout or
forge a victim's IP to lock them out. Forwarding headers are honoured only from reverse
proxies you list as trusted.

> [!IMPORTANT]
> Serve your app with `into_make_service_with_connect_info::<SocketAddr>()`. With
> `BruteLayer::by_ip`, a request without `ConnectInfo<SocketAddr>` is rejected with `500`
> (configurable via `.missing_key_status(..)`).

## Installation

```toml
[dependencies]
rune-axum-brute = "0.3"
```

## Usage

### Automatic lockout with `BruteLayer`

Apply `BruteLayer` to your router. The layer inspects response status codes and
automatically records failures (401/403) and successes (2xx).

```rust
use std::sync::Arc;
use axum::{routing::post, Router};
use rune_axum_brute::{BruteLayer, InMemoryStore};

// Lock after 5 failures; lockout lasts 5 minutes.
let store = Arc::new(InMemoryStore::new(5, 300));

let app: Router = Router::new()
    .route("/login", post(|| async { "ok" }))
    .layer(BruteLayer::by_ip(store));

let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await?;
axum::serve(listener, app.into_make_service_with_connect_info::<std::net::SocketAddr>()).await?;
```

### Behind a reverse proxy

```rust
use std::sync::Arc;
use rune_axum_brute::{BruteLayer, ClientIpConfig, InMemoryStore};

// The load balancer in 10.0.0.0/8 appends to X-Forwarded-For; the chain is walked from
// the right. IPv6 clients are locked out per /64.
let layer = BruteLayer::by_client_ip(
    Arc::new(InMemoryStore::new(5, 300)),
    ClientIpConfig::new().trust_proxy("10.0.0.0/8")?,
    64,
);
```

### Custom key function

```rust
use std::sync::Arc;
use axum::{routing::post, Router};
use rune_axum_brute::{BruteLayer, InMemoryStore};

let store = Arc::new(InMemoryStore::new(3, 120));
let layer = BruteLayer::new(store, |req| {
    req.headers()
        .get("x-api-key")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("unknown")
        .to_owned()
});
```

### Manual recording with `BruteGuard`

Use `BruteGuard` when your handler decides success or failure:

```rust
use std::sync::Arc;
use axum::{extract::FromRef, http::StatusCode, routing::post, Router};
use rune_axum_brute::{BruteForceStore, BruteGuard, InMemoryStore};

#[derive(Clone)]
struct AppState {
    store: Arc<dyn BruteForceStore>,
}

impl FromRef<AppState> for Arc<dyn BruteForceStore> {
    fn from_ref(state: &AppState) -> Self {
        Arc::clone(&state.store)
    }
}

async fn login(guard: BruteGuard) -> StatusCode {
    if guard.is_locked("alice") {
        return StatusCode::TOO_MANY_REQUESTS;
    }
    // check password...
    guard.record_failure("alice");
    StatusCode::UNAUTHORIZED
}
```

### Sliding window

```rust
use rune_axum_brute::InMemoryStore;

// 5 failures within 60 s triggers a 10-minute lockout.
let store = InMemoryStore::with_window(5, 60, 600);
```

### Bounding memory

```rust
use rune_axum_brute::InMemoryStore;

// When full: stale entries go first, then the oldest unlocked ones; active lockouts last.
let store = InMemoryStore::new(5, 300).with_max_keys(10_000);
```

## Migrating from 0.1

0.3: re-exported rune-cidr types moved to rune-cidr 0.2.

0.2 changes security-relevant defaults.

- **`BruteLayer::by_ip` keys on the socket peer IP**, not `X-Forwarded-For` / `X-Real-IP`.
  0.1 let attackers rotate the header to get unlimited attempts, or forge a victim's IP to lock
  them out. Serve with `into_make_service_with_connect_info::<SocketAddr>()`; behind a proxy use
  `BruteLayer::by_client_ip(store, ClientIpConfig::new().trust_proxy("<proxy CIDR>")?, 128)`.
- **No more shared `"unknown"` key.** Without `ConnectInfo`, `by_ip` rejects with `500`
  instead of lumping every such request into one lockout bucket.
- **`BruteLayer` and `BruteService` lost their key-function type parameter**
  (`BruteLayer<F>` → `BruteLayer`, `BruteService<S, F>` → `BruteService<S>`); `BruteLayer::new`
  now needs a `Send + Sync` closure.
- **`InMemoryStore` is bounded** (`with_max_keys`, default 100 000).
- **`BruteForceStore::lockout_remaining`** (default `None`) feeds `Retry-After`; the old fixed
  `Retry-After: 300` is gone. Custom stores should implement it.
- Tests that call the router with `oneshot` must insert
  `axum::extract::ConnectInfo(SocketAddr)` into the request extensions.

## CLI

This is a library-only crate — there is no CLI binary.

## License

MIT
