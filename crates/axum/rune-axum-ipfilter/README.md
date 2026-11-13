# rune-axum-ipfilter

> IP allowlist / blocklist middleware — CIDR-based IP filtering for Axum.

[![crates.io](https://img.shields.io/crates/v/rune-axum-ipfilter)](https://crates.io/crates/rune-axum-ipfilter)
[![docs.rs](https://img.shields.io/docsrs/rune-axum-ipfilter)](https://docs.rs/rune-axum-ipfilter)
[![license](https://img.shields.io/crates/l/rune-axum-ipfilter)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

A [`tower::Layer`](https://docs.rs/tower/latest/tower/trait.Layer.html) that filters requests by client IP address using CIDR ranges. Supports blocklist mode (reject matching IPs) and allowlist mode (accept only matching IPs). Works with Axum, Hyper, and any Tower-compatible framework.

The client IP is the **socket peer address** (`ConnectInfo<SocketAddr>`). `X-Forwarded-For` and
similar headers are ignored unless the peer is a reverse proxy you explicitly trust, so clients
cannot spoof their way past an allowlist or out of a blocklist.

> [!IMPORTANT]
> Serve your app with `into_make_service_with_connect_info::<SocketAddr>()`. A request without
> `ConnectInfo<SocketAddr>` is rejected with `500 Internal Server Error` (configurable with
> `.missing_ip_status(..)`) in both modes; it is never let through.

## Installation

```toml
[dependencies]
rune-axum-ipfilter = "0.3"
```

## Usage

### Block specific IPs and subnets

```rust
use std::net::SocketAddr;
use axum::{routing::get, Router};
use rune_axum_ipfilter::{FilterMode, IpFilterConfig, IpFilterLayer};

let app: Router = Router::new()
    .route("/api", get(handler))
    .layer(IpFilterLayer::new(
        IpFilterConfig::new()
            .mode(FilterMode::Blocklist)
            .cidr("192.168.1.100/32")?
            .cidr("10.0.0.0/8")?,
    ));

let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await?;
axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).await?;
```

### Allow only trusted subnets, behind a load balancer

```rust
use rune_axum_ipfilter::{ClientIpConfig, FilterMode, IpFilterConfig, IpFilterLayer};

let layer = IpFilterLayer::new(
    IpFilterConfig::new()
        .mode(FilterMode::Allowlist)
        .cidr("203.0.113.0/24")?   // office
        .cidr("10.8.0.0/16")?      // VPN
        // The load balancers live in 10.0.0.0/24 and append to X-Forwarded-For.
        .client_ip(ClientIpConfig::new().trust_proxy("10.0.0.0/24")?),
);
```

### Behind Cloudflare (or any proxy with a dedicated header)

```rust
use http::HeaderName;
use rune_axum_ipfilter::{ClientIpConfig, ProxyHeader};

let client_ip = ClientIpConfig::new()
    .trust_proxy("173.245.48.0/20")?   // ...and the rest of Cloudflare's ranges
    .header(ProxyHeader::Header(HeaderName::from_static("cf-connecting-ip")));
```

## Client IP resolution

| Situation | Client IP used |
|-----------|----------------|
| No trusted proxies (default) | Socket peer address. All headers ignored. |
| Peer not in a trusted range | Socket peer address. All headers ignored. |
| Peer trusted, `ProxyHeader::XForwardedFor` (default) | `X-Forwarded-For` walked **from the right**; trusted hops are skipped, the first untrusted address wins. |
| Peer trusted, `ProxyHeader::Forwarded` | RFC 7239 `Forwarded` `for=` values, walked from the right the same way. |
| Peer trusted, `ProxyHeader::Header(name)` | The last value of that header. |
| Peer trusted, header absent or malformed | The nearest trusted hop (at worst the peer). |
| No `ConnectInfo<SocketAddr>` | Request rejected with `missing_ip_status` (500). |

IPv4-mapped IPv6 addresses (`::ffff:192.0.2.1`) are normalised to IPv4, and ranges written in
the mapped form (`::ffff:192.0.2.0/120`) match the same IPv4 clients. At most 32 hops of
at most 128 bytes each are examined; malformed input never panics.

## Configuration

| Method | Default | Description |
|--------|---------|-------------|
| `.cidr(&str)` | (none) | Add an IPv4 or IPv6 CIDR range to the filter list. Returns `Err(CidrParseError)` for invalid notation. Can be called multiple times. |
| `.mode(FilterMode)` | `Blocklist` | Whether listed CIDRs are blocked or exclusively allowed. |
| `.status(StatusCode)` | `403` | Status code returned when a request is rejected. |
| `.client_ip(ClientIpConfig)` | socket peer | How the client IP is resolved; trusted proxies and their header. |
| `.missing_ip_status(StatusCode)` | `500` | Status returned when `ConnectInfo<SocketAddr>` is missing. |

### Filter modes

| Variant | Behaviour |
|---------|-----------|
| `FilterMode::Blocklist` | IPs matching a listed CIDR are rejected; all others pass. |
| `FilterMode::Allowlist` | Only IPs matching a listed CIDR pass; all others are rejected. |

## Migrating from 0.1

0.3: re-exported rune-cidr types moved to rune-cidr 0.2.

0.2 changes security-relevant defaults.

- **Client IP now comes from the socket peer, not `X-Forwarded-For`.** 0.1 trusted the
  leftmost `X-Forwarded-For` entry, which any client can forge to bypass an allowlist or
  evade a blocklist. Serve with `into_make_service_with_connect_info::<SocketAddr>()`.
- **`IpSource` and `.source(..)` are removed.** Behind a proxy, use
  `.client_ip(ClientIpConfig::new().trust_proxy("<proxy CIDR>")?)`. Replace
  `IpSource::Header(h)` with `.header(ProxyHeader::Header(h))` on the `ClientIpConfig`,
  plus `trust_proxy` for the proxy that sets it.
- **Requests without a resolvable IP are rejected (500)**, not passed through. Tests that call
  the router with `oneshot` must insert `axum::extract::ConnectInfo(SocketAddr)` into the
  request extensions.

## Output

A request from a blocked IP:

```
HTTP/1.1 403 Forbidden
```

## License

MIT
