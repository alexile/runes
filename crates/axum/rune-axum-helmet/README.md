# rune-axum-helmet

> Security headers middleware for Axum.

[![crates.io](https://img.shields.io/crates/v/rune-axum-helmet)](https://crates.io/crates/rune-axum-helmet)
[![docs.rs](https://img.shields.io/docsrs/rune-axum-helmet)](https://docs.rs/rune-axum-helmet)
[![license](https://img.shields.io/crates/l/rune-axum-helmet)](LICENSE)

A [`tower::Layer`](https://docs.rs/tower/latest/tower/trait.Layer.html) that sets the response headers recommended by the [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/), in the spirit of [Helmet.js](https://helmetjs.github.io/). Works with Axum, Hyper and any other Tower stack.

- A Content-Security-Policy by default, a `CspBuilder` with **per-request nonces** and `'strict-dynamic'`, and report-only mode.
- HSTS that is not sent on plain-HTTP requests, with preload checks.
- A restrictive Permissions-Policy, COOP / CORP, opt-in COEP (also report-only), `Reporting-Endpoints`.
- Headers your handler sets are kept; `HelmetOverride` changes the config per route.
- Everything is validated when the layer is built: a misspelt CSP directive is an error at startup, not a header browsers silently ignore. Validation reuses [`rune-csp`](../../web/rune-csp), [`rune-hsts`](../../web/rune-hsts) and [`rune-permissions-policy`](../../web/rune-permissions-policy).

## Installation

```toml
[dependencies]
rune-axum-helmet = "0.3"
```

## Default headers

`HelmetLayer::default()` / `Helmet::new()`:

| Header | Value |
|--------|-------|
| `Content-Security-Policy` | `default-src 'self'; base-uri 'self'; font-src 'self' https: data:; form-action 'self'; frame-ancestors 'none'; img-src 'self' data:; object-src 'none'; script-src 'self'; script-src-attr 'none'; style-src 'self' https: 'unsafe-inline'; upgrade-insecure-requests` |
| `Strict-Transport-Security` | `max-age=31536000; includeSubDomains`, skipped on requests known to be plain HTTP |
| `X-Content-Type-Options` | `nosniff` |
| `X-Frame-Options` | `DENY` |
| `Referrer-Policy` | `strict-origin-when-cross-origin` |
| `Cross-Origin-Opener-Policy` | `same-origin` |
| `Cross-Origin-Resource-Policy` | `same-origin` |
| `Origin-Agent-Cluster` | `?1` |
| `Permissions-Policy` | `accelerometer=(), autoplay=(), bluetooth=(), browsing-topics=(), camera=(), clipboard-read=(), display-capture=(), encrypted-media=(), fullscreen=(self), gamepad=(), geolocation=(), gyroscope=(), hid=(), idle-detection=(), keyboard-map=(), local-fonts=(), magnetometer=(), microphone=(), midi=(), payment=(), picture-in-picture=(), publickey-credentials-create=(self), publickey-credentials-get=(self), screen-wake-lock=(), serial=(), usb=(), web-share=(), window-management=(), xr-spatial-tracking=()` |
| `X-DNS-Prefetch-Control` | `off` |
| `X-Permitted-Cross-Domain-Policies` | `none` |
| `X-XSS-Protection` | `0` |

`Server` and `X-Powered-By` are removed. `Cross-Origin-Embedder-Policy` is opt-in because it blocks every cross-origin subresource that does not opt in.

`X-XSS-Protection: 0` switches off the XSS auditor of old browsers, as OWASP recommends: the auditor itself could be abused to leak data. Modern browsers ignore the header.

## Usage

### Defaults

```rust
use axum::{routing::get, Router};
use rune_axum_helmet::HelmetLayer;

let app: Router = Router::new()
    .route("/", get(|| async { "hello" }))
    .layer(HelmetLayer::default());
```

### Custom configuration

Every header has a setter and a `no_*` method. `build()` (or `HelmetLayer::new`) validates the result.

```rust
use rune_axum_helmet::{CspBuilder, CrossOriginResourcePolicy, Helmet, Hsts};

let layer = Helmet::new()
    .hsts(Hsts::new().max_age(63_072_000).preload()) // checked against preload rules
    .cross_origin_resource_policy(CrossOriginResourcePolicy::SameSite)
    .csp_from(CspBuilder::recommended().connect_src(&["'self'", "https://api.example"]))
    .permissions_policy("camera=(), microphone=(), geolocation=(self)")
    .build()?;
```

### CSP nonces and `strict-dynamic`

With a nonce slot, every request gets 128 fresh random bits in the header, and the same value as a `CspNonce` request extension:

```rust
use axum::{Extension, Router, response::Html, routing::get};
use rune_axum_helmet::{CspBuilder, CspNonce, Helmet};

async fn page(Extension(nonce): Extension<CspNonce>) -> Html<String> {
    Html(format!(r#"<script nonce="{nonce}" src="/app.js"></script>"#))
}

let layer = Helmet::new()
    .csp_from(CspBuilder::recommended().script_nonce().strict_dynamic())
    .build()?;
let app: Router = Router::new().route("/", get(page)).layer(layer);
```

`CspBuilder::strict()` is the nonce-based "strict CSP" (`script-src 'nonce-…' 'strict-dynamic' https: 'unsafe-inline'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'`). `'strict-dynamic'` without a nonce or hash, a hard-coded `'nonce-…'`, an unknown directive, or a `;` inside a directive name or source (which would smuggle in another directive) is a build error.

### Report-only CSP and COEP

```rust
use rune_axum_helmet::{CrossOriginEmbedderPolicy, CspBuilder, Helmet};

let layer = Helmet::new()
    .reporting_endpoint("csp", "https://reports.example/csp")
    .report_only_csp_from(CspBuilder::strict().report_to("csp"))
    .reporting_endpoint("coep", "/reports/coep")
    .report_only_cross_origin_embedder_policy(CrossOriginEmbedderPolicy::RequireCorp)
    .cross_origin_embedder_policy_report_to("coep")
    .build()?;
```

This sends `Reporting-Endpoints: csp="https://reports.example/csp", coep="/reports/coep"`. A `report-to` naming an endpoint that is not declared is a build error.

### HSTS and HTTPS detection

The layer reads the scheme from every `Forwarded: proto=` and `X-Forwarded-Proto` value and an absolute request URI; if any of them says HTTPS, the request counts as HTTPS. Clients can send these headers too, so without a proxy that overwrites them a client can make `ExceptHttp` skip HSTS on its own responses; use `Always` when the app is reached directly over TLS. `HstsMode` picks the rule:

| Mode | Sent when |
|------|-----------|
| `ExceptHttp` (default) | the request is not known to be plain HTTP; servers terminating TLS themselves usually see no scheme at all |
| `HttpsOnly` | the request is known to be HTTPS (behind a proxy that always sets `X-Forwarded-Proto`) |
| `Always` | always |

### Handler headers and per-route overrides

A header the handler sets itself wins (`Helmet::overwrite(true)` changes that). For a route that needs a different policy, use `HelmetOverride`, either as a layer on the route or as a response extension from the handler:

```rust
use axum::{Extension, Router, routing::get};
use http::header::X_FRAME_OPTIONS;
use rune_axum_helmet::{CspBuilder, Helmet, HelmetLayer, HelmetOverride};

let embed = HelmetOverride::replace(
    Helmet::new()
        .no_frame_options()
        .csp_from(CspBuilder::recommended().frame_ancestors(&["https:"])),
)?;

let app: Router = Router::new()
    .route("/widget", get(|| async { "widget" }).layer(embed))
    .route("/legacy", get(|| async {
        (Extension(HelmetOverride::skip([X_FRAME_OPTIONS])), "legacy")
    }))
    .route("/raw", get(|| async { (Extension(HelmetOverride::disable()), "raw") }))
    .layer(HelmetLayer::default());
```

## Migrating from 0.2

- **New defaults.** A CSP (`CspBuilder::recommended()`), HSTS (`max-age=31536000; includeSubDomains`), `X-Frame-Options: DENY` (was `SAMEORIGIN`), `Origin-Agent-Cluster`, `Permissions-Policy`, `X-DNS-Prefetch-Control: off` and `X-Permitted-Cross-Domain-Policies: none` are now sent, and `Server` / `X-Powered-By` are removed. Turn any of them off with `no_csp()`, `no_hsts()`, `frame_options(XFrameOptions::SameOrigin)`, `keep_header(&SERVER)` and so on, or start from `Helmet::empty()`.
- **Handler headers are kept.** 0.2 overwrote them; use `.overwrite(true)` for the old behaviour.
- **Building is fallible.** `HelmetLayer::new(helmet)` returns `Result<HelmetLayer, Error>` (also `helmet.build()`); invalid CSP, Permissions-Policy, HSTS preload or reporting settings are errors instead of silently dropped headers. `HelmetLayer::default()` is still infallible.
- `Helmet::default()` now equals `Helmet::new()` (it used to send nothing).
- `Hsts::new()` includes `includeSubDomains`; use `.exclude_subdomains()` for the old value. HSTS is no longer sent on requests known to be plain HTTP; use `.mode(HstsMode::Always)` to send it everywhere.
- `CspBuilder::build()` is gone: pass the builder to `csp_from`, or use `render(None)` for the string. Setting a directive twice now replaces it instead of producing a duplicate.
- `ReferrerPolicy` is now `rune_referrer_policy::ReferrerPolicy` (same variants). `CrossOriginOpenerPolicy` and `CrossOriginEmbedderPolicy` gained variants and are `#[non_exhaustive]`.

## License

MIT
