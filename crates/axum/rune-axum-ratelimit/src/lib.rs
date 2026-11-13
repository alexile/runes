//! Rate limiter middleware for Axum — per-client fixed-window or GCRA limiting with a
//! pluggable store, spoof-resistant client IPs and IETF `RateLimit` headers.
//!
//! A [`tower::Layer`] that counts requests per client key and rejects clients over their
//! quota with `429 Too Many Requests`, a `Retry-After` header and the
//! `RateLimit` / `RateLimit-Policy` headers of draft-ietf-httpapi-ratelimit-headers.
//!
//! # Client identity
//!
//! By default the key is the **socket peer IP** from the `ConnectInfo<SocketAddr>` request
//! extension; `X-Forwarded-For` and similar headers are ignored, so clients cannot dodge the
//! limit (or exhaust someone else's) by forging them. Behind a reverse proxy, list the
//! proxy's addresses in a [`ClientIpConfig`]: the forwarding chain is then walked from the
//! right and the first untrusted hop is the client. IPv4-mapped IPv6 addresses are folded
//! into IPv4, and [`RateLimitConfig::ipv6_prefix`] can bucket IPv6 clients per `/64`.
//!
//! > [!IMPORTANT]
//! > Serve the app with `into_make_service_with_connect_info::<SocketAddr>()`. Without the
//! > extension requests are rejected with `500` (see [`MissingIp`]); they are never
//! > counted against a header-supplied address.
//!
//! # Algorithms and storage
//!
//! - [`Algorithm::FixedWindow`] (default) — `requests` per `window`, reset per client.
//! - [`Algorithm::Gcra`] — smooth rate of `requests / window` with a configurable burst; no
//!   window-boundary spikes.
//!
//! State lives in a [`RateLimitStore`]. The bundled [`InMemoryStore`] is bounded: expired
//! keys are swept and, at capacity, the keys nearest to expiry are evicted, so a flood of
//! distinct clients cannot grow memory without limit. For a limit shared across instances,
//! enable the `redis` feature and use `redis::RedisStore` (atomic Lua scripts, Redis server
//! time, expiring keys), or implement [`RateLimitStore`] over another backend (see
//! [`store`]).
//!
//! # Quick Start
//!
//! ```rust,no_run
//! use std::net::SocketAddr;
//! use axum::{routing::get, Router};
//! use rune_axum_ratelimit::RateLimitLayer;
//!
//! # async fn run() -> std::io::Result<()> {
//! let app: Router = Router::new()
//!     .route("/api", get(|| async { "ok" }))
//!     .layer(RateLimitLayer::default());
//! let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await?;
//! axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).await
//! # }
//! ```
//!
//! # Custom Configuration
//!
//! ```rust
//! use std::time::Duration;
//! use axum::{routing::get, Router};
//! use rune_axum_ratelimit::{Algorithm, ClientIpConfig, RateLimitConfig, RateLimitLayer};
//!
//! // 50 requests per 30 s, smoothed, per /64 for IPv6, behind a proxy in 10.0.0.0/8.
//! let layer = RateLimitLayer::new(
//!     RateLimitConfig::new()
//!         .requests(50)
//!         .window(Duration::from_secs(30))
//!         .algorithm(Algorithm::Gcra)
//!         .ipv6_prefix(64)
//!         .client_ip(ClientIpConfig::new().trust_proxy("10.0.0.0/8")?),
//! );
//!
//! let app: Router = Router::new()
//!     .route("/api", get(|| async { "ok" }))
//!     .layer(layer);
//! # Ok::<(), rune_axum_ratelimit::CidrParseError>(())
//! ```

pub use layer::{
    KeyExtractor, MAX_KEY_LEN, MissingIp, OnStoreError, RATELIMIT, RATELIMIT_POLICY,
    RateLimitConfig, RateLimitLayer, RateLimitService,
};
pub use rune_axum_ipfilter::{CidrParseError, ClientIpConfig, ProxyHeader};
pub use store::{Algorithm, Decision, InMemoryStore, Quota, RateLimitStore, StoreError};

mod layer;
#[cfg(feature = "redis")]
pub mod redis;
pub mod store;
