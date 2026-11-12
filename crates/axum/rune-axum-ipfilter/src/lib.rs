//! IP allowlist / blocklist middleware — CIDR-based IP filtering for Axum.
//!
//! A [`tower::Layer`] that inspects the client IP address on every request and either allows
//! or rejects it based on a configured list of CIDR ranges. Two modes are available:
//! [`FilterMode::Blocklist`] (reject matching IPs, pass all others) and
//! [`FilterMode::Allowlist`] (pass only matching IPs, reject all others). Both IPv4 and IPv6
//! CIDRs are supported with no external dependencies.
//!
//! # Client IP
//!
//! The client IP is the **socket peer address** from the `ConnectInfo<SocketAddr>` request
//! extension. Forwarding headers such as `X-Forwarded-For` are ignored unless the peer is a
//! reverse proxy you list in a [`ClientIpConfig`]; the chain is then walked from the right
//! and the first untrusted hop is the client (see [`client_ip`]). Serve the app with
//! `into_make_service_with_connect_info::<SocketAddr>()`.
//!
//! > [!IMPORTANT]
//! > A request without `ConnectInfo<SocketAddr>` is rejected with `500 Internal Server
//! > Error` (configurable via [`IpFilterConfig::missing_ip_status`]) in both modes. It is
//! > never let through and never resolved from headers.
//!
//! # Features
//!
//! - Blocklist or allowlist mode with a single enum variant.
//! - IPv4 and IPv6 CIDR notation (`"10.0.0.0/8"`, `"2001:db8::/32"`); IPv4-mapped IPv6
//!   addresses are normalised to IPv4 before matching.
//! - Multiple CIDR ranges per layer — chain `.cidr()` calls.
//! - Spoof-resistant client IP: socket peer by default, opt-in trusted proxies reading
//!   `X-Forwarded-For`, RFC 7239 `Forwarded` or a single header such as `CF-Connecting-IP`.
//! - Bounded, panic-free header parsing.
//! - Configurable rejection status codes.
//!
//! # Quick Start
//!
//! ```rust
//! use std::net::SocketAddr;
//! use axum::{routing::get, Router};
//! use rune_axum_ipfilter::{FilterMode, IpFilterConfig, IpFilterLayer};
//!
//! let app: Router = Router::new()
//!     .route("/api", get(|| async { "ok" }))
//!     .layer(IpFilterLayer::new(
//!         IpFilterConfig::new()
//!             .mode(FilterMode::Blocklist)
//!             .cidr("192.168.1.100/32")?
//!             .cidr("10.0.0.0/8")?,
//!     ));
//! // Required: record the socket peer address for every request.
//! let service = app.into_make_service_with_connect_info::<SocketAddr>();
//! # let _ = service;
//! # Ok::<(), rune_axum_ipfilter::CidrParseError>(())
//! ```
//!
//! # Allowlist mode behind a reverse proxy
//!
//! ```rust
//! use axum::{routing::get, Router};
//! use rune_axum_ipfilter::{ClientIpConfig, FilterMode, IpFilterConfig, IpFilterLayer};
//!
//! // Only allow the office and VPN subnets; the load balancer at 10.0.0.2 appends to
//! // X-Forwarded-For.
//! let app: Router = Router::new()
//!     .route("/admin", get(|| async { "ok" }))
//!     .layer(IpFilterLayer::new(
//!         IpFilterConfig::new()
//!             .mode(FilterMode::Allowlist)
//!             .cidr("203.0.113.0/24")?
//!             .cidr("10.8.0.0/16")?
//!             .client_ip(ClientIpConfig::new().trust_proxy("10.0.0.2")?),
//!     ));
//! # Ok::<(), rune_axum_ipfilter::CidrParseError>(())
//! ```

pub use client_ip::{ClientIpConfig, ProxyHeader};
pub use layer::{FilterMode, IpFilterConfig, IpFilterLayer, IpFilterService};
pub use rune_cidr::{Cidr, CidrParseError};

pub mod client_ip;
mod layer;
