# rune-axum-helmet

> Security headers middleware for Axum.

[![crates.io](https://img.shields.io/crates/v/rune-axum-helmet)](https://crates.io/crates/rune-axum-helmet)
[![docs.rs](https://img.shields.io/docsrs/rune-axum-helmet)](https://docs.rs/rune-axum-helmet)
[![license](https://img.shields.io/crates/l/rune-axum-helmet)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

A [`tower::Layer`](https://docs.rs/tower/latest/tower/trait.Layer.html) that injects security-related HTTP response headers on every request. Inspired by [Helmet.js](https://helmetjs.github.io/). Works with Axum, Hyper, and any other Tower-compatible framework.

## Default headers

[`HelmetLayer::default()`](https://docs.rs/rune-axum-helmet) sets the following headers out of the box:

| Header | Value |
|--------|-------|
| `X-Content-Type-Options` | `nosniff` |
| `X-XSS-Protection` | `0` |
| `X-Frame-Options` | `SAMEORIGIN` |
| `Referrer-Policy` | `strict-origin-when-cross-origin` |
| `Cross-Origin-Opener-Policy` | `same-origin` |
| `Cross-Origin-Resource-Policy` | `same-origin` |

HSTS, CSP, and `Cross-Origin-Embedder-Policy` are **opt-in** — they require site-specific configuration and are unsafe to enable globally by default.

## Installation

```toml
[dependencies]
rune-axum-helmet = "0.2"
```

## Usage

### Secure defaults

```rust
use axum::{routing::get, Router};
use rune_axum_helmet::HelmetLayer;

let app: Router = Router::new()
    .route("/", get(handler))
    .layer(HelmetLayer::default());
```

### Custom configuration

```rust
use axum::{routing::get, Router};
use rune_axum_helmet::{CspBuilder, Helmet, HelmetLayer, Hsts, XFrameOptions};

let helmet = Helmet::new()
    .frame_options(XFrameOptions::Deny)
    .hsts(Hsts::new().max_age(63_072_000).include_subdomains())
    .csp_from(
        CspBuilder::new()
            .default_src(&["'self'"])
            .script_src(&["'self'", "'strict-dynamic'"])
            .upgrade_insecure_requests(),
    );

let app: Router = Router::new()
    .route("/", get(handler))
    .layer(HelmetLayer::new(helmet));
```

### Testing a new CSP with Report-Only mode

Deploy a candidate policy as `Content-Security-Policy-Report-Only` to collect
violation reports without breaking anything, then promote it to enforcement.

```rust
use rune_axum_helmet::{CspBuilder, Helmet, HelmetLayer};

let helmet = Helmet::new().report_only_csp_from(
    CspBuilder::new()
        .default_src(&["'self'"])
        .report_to("csp-endpoint"),
);
```

## Configurable headers

| Header | Type | Default |
|--------|------|---------|
| `X-Content-Type-Options` | `bool` | `true` |
| `X-XSS-Protection` | `bool` | `true` (sends `0`) |
| `X-Frame-Options` | `Option<XFrameOptions>` | `SameOrigin` |
| `Referrer-Policy` | `Option<ReferrerPolicy>` | `StrictOriginWhenCrossOrigin` |
| `Strict-Transport-Security` | `Option<Hsts>` | off |
| `Content-Security-Policy` | `Option<String>` | off |
| `Content-Security-Policy-Report-Only` | `Option<String>` | off |
| `Cross-Origin-Opener-Policy` | `Option<CrossOriginOpenerPolicy>` | `SameOrigin` |
| `Cross-Origin-Resource-Policy` | `Option<CrossOriginResourcePolicy>` | `SameOrigin` |
| `Cross-Origin-Embedder-Policy` | `Option<CrossOriginEmbedderPolicy>` | off |
| `Permissions-Policy` | `Option<String>` | off |

> [!WARNING]
> Enable HSTS only when your site is fully served over HTTPS. Once set, browsers
> will refuse HTTP connections for the duration of `max-age`.

> [!NOTE]
> `X-XSS-Protection: 0` is the modern recommendation. The legacy browser XSS
> filter it controls has known bypasses and can introduce vulnerabilities of its own.

## License

MIT
