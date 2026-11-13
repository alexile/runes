# rune-axum-stack

> All-in-one middleware stack for Axum.

[![crates.io](https://img.shields.io/crates/v/rune-axum-stack)](https://crates.io/crates/rune-axum-stack)
[![docs.rs](https://img.shields.io/docsrs/rune-axum-stack)](https://docs.rs/rune-axum-stack)
[![license](https://img.shields.io/crates/l/rune-axum-stack)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

Composes up to sixteen `rune-axum-*` and `rune-tower-*` layers — request ids, health probes,
compression, problem details, security headers, HTTPS redirect, CORS, IP filtering, rate
limiting, concurrency limiting, circuit breaking, timeouts, body size limit, CSRF protection,
retries with hedging and HTTP caching — into a single `SecurityStack::apply` call. Every layer is individually configurable or removable via
builder methods, and the stack always applies them in one fixed, documented order.
Re-exports all config types so you only need this one crate in `[dependencies]`.

> [!NOTE]
> IP filtering is disabled by default — it requires explicit CIDR configuration via
> `.ipfilter(IpFilterConfig::new()...)`.

> [!IMPORTANT]
> The rate limiter and IP filter identify clients by the socket peer address. Serve the
> router with `into_make_service_with_connect_info::<SocketAddr>()`, otherwise those layers
> answer `500`. Behind a reverse proxy, pass
> `ClientIpConfig::new().trust_proxy("<proxy CIDR>")?` to `RateLimitConfig::client_ip` /
> `IpFilterConfig::client_ip`; `X-Forwarded-For` is ignored from untrusted peers.

## Installation

```toml
[dependencies]
rune-axum-stack = "0.2"
```

## Usage

```rust,no_run
use axum::{routing::get, Router};
use rune_axum_stack::SecurityStack;

// Six-layer default stack (helmet + HSTS, HTTPS redirect, rate limit, 30 s timeout,
// body limit, signed CSRF)
let app: Router = SecurityStack::default().apply(
    Router::new().route("/", get(|| async { "ok" })),
);
```

```rust,no_run
use std::time::Duration;
use axum::{routing::get, Router};
use rune_axum_stack::{
    FilterMode, Helmet, IpFilterConfig, RateLimitConfig, SecurityStack, XFrameOptions,
};

// Custom: same-origin framing, 200 req/30 s, block a CIDR, no CSRF (JWT API)
let app: Router = SecurityStack::new()
    .helmet(Helmet::new().frame_options(XFrameOptions::SameOrigin))?
    .ratelimit(RateLimitConfig::new().requests(200).window(Duration::from_secs(30)))
    .ipfilter(IpFilterConfig::new().mode(FilterMode::Blocklist).cidr("10.0.0.0/8")?)
    .without_csrf()
    .apply(Router::new().route("/", get(|| async { "ok" })));
```

```rust,no_run
use std::time::Duration;
use axum::{routing::get, Router};
use rune_axum_stack::{
    CircuitBreaker, Compression, ConcurrencyLimit, Cors, HealthState, Problems,
    RequestIdConfig, Retry, SecurityStack, Timeout,
};

// Production API: every optional layer switched on
let health = HealthState::new(); // share with `health.graceful_shutdown(..)`
let app: Router = SecurityStack::new()
    .without_csrf() // bearer-token API
    .request_id(RequestIdConfig::default())
    .health(health.clone())
    .compression(Compression::new())
    .problem(Problems::new())
    .cors(Cors::new().allow_origin("https://app.example.com"))?
    .concurrency(ConcurrencyLimit::new().max_in_flight(512))
    .circuit_breaker(CircuitBreaker::new().open_duration(Duration::from_secs(15)))
    .timeout(Timeout::new().duration(Duration::from_secs(10)))
    .retry(Retry::new().max_attempts(2)) // 502/503/504 on bodiless GET/PUT/DELETE…
    .apply(Router::new().route("/api/items", get(|| async { "[]" })));
```

```rust,no_run
use axum::{routing::get, Router};
use rune_axum_stack::{CsrfKey, SecurityStack};

// Server-rendered app: handlers get `Extension<CsrfToken>` for `hidden_input()`
let app: Router = SecurityStack::new()
    .csrf_key(CsrfKey::from_bytes(&std::fs::read("/run/secrets/csrf")?)?) // ≥ 32 bytes, shared
    .csrf_session_cookie("session_id")
    .csrf_trusted_origin("https://www.example.com")
    .csrf_exempt_prefix("/webhooks/")
    .apply(Router::new().route("/", get(|| async { "ok" })));
```

## Default stack

| Layer | Default |
|-------|---------|
| `HelmetLayer` | `rune-axum-helmet` defaults: CSP, HSTS (1 year, `includeSubDomains`, not on plain HTTP), Permissions-Policy, COOP/CORP, `X-Frame-Options: DENY` and more |
| `RedirectHttpsLayer` | 308 permanent redirect for HTTP requests |
| `RateLimitLayer` | 100 requests per 60 s per socket peer IP |
| `TimeoutLayer` | 30 s per request (`504`) |
| `BodyLimitLayer` | 1 MiB `Content-Length` limit |
| `CsrfLayer` | HMAC-signed double-submit `__Host-csrf_token` cookie (`Secure`, `SameSite=Lax`) + `Origin` / `Sec-Fetch-Site` checks on every non-safe method |

Every other layer is opt-in: `request_id`, `health`, `compression`, `problem`, `cors`,
`ipfilter`, `concurrency`, `circuit_breaker`, `retry` and `cache`.

The default CSRF key is random per stack: set `.csrf_key(..)` when several instances
serve the site or tokens must survive restarts. The `Secure` cookie is only stored by
browsers on `https://` and `http://localhost`.

## Configuration

| Method | Action |
|--------|--------|
| `.helmet(Helmet)?`, `.helmet_layer(HelmetLayer)` | Replace helmet config (validated) |
| `.without_helmet()` | Disable security headers |
| `.csrf(CsrfConfig)` | Replace CSRF config |
| `.csrf_origin(CsrfOriginConfig)` | Token-free origin-only CSRF (`Sec-Fetch-Site` / `Origin`, no cookie) |
| `.csrf_key(CsrfKey)`, `.csrf_session_cookie(name)`, `.csrf_session_id_with(fn)`, `.csrf_trusted_origin(origin)`, `.csrf_exempt_path(path)`, `.csrf_exempt_prefix(prefix)` | Adjust the current CSRF config (and turn CSRF back on if it was removed) |
| `.without_csrf()` | Disable CSRF (use for JWT / API-key APIs) |
| `.ratelimit(RateLimitConfig)` | Replace rate-limit config |
| `.without_ratelimit()` | Disable rate limiting |
| `.ipfilter(IpFilterConfig)` | Enable IP allow/blocklist (off by default) |
| `.without_ipfilter()` | Disable IP filtering |
| `.redirect_https(RedirectHttps)` | Replace HTTPS-redirect config |
| `.without_redirect_https()` | Disable redirect (TLS terminated upstream) |
| `.body_limit(BodyLimit)` | Replace body-limit config |
| `.without_body_limit()` | Disable body size limit |
| `.request_id(RequestIdConfig)` | Enable request-id / `traceparent` propagation |
| `.health(HealthState)` / `.health_with(Health, HealthState)` | Enable `/livez` + `/readyz` probes and in-flight tracking |
| `.compression(Compression)` | Enable negotiated response compression |
| `.problem(Problems)` | Turn bare error statuses into RFC 9457 `application/problem+json` |
| `.cors(Cors)?` / `.cors_layer(CorsLayer)` | Enable CORS (policy audited at build time, fallible) |
| `.concurrency(ConcurrencyLimit)` / `.concurrency_layer(..)` | Enable in-flight limit with `503` load shedding |
| `.circuit_breaker(CircuitBreaker)` / `.circuit_breaker_layer(..)` | Enable a circuit breaker over the handlers: errors and `5xx` (timeouts included) count as failures; an open circuit answers `503` + `Retry-After` |
| `.timeout(Timeout)` | Replace the per-request deadline (`504`); use `Timeout::path` for long-polling routes |
| `.retry(Retry)` / `.retry_layer(..)` | Enable retries (and optional hedging) of handler `502`/`503`/`504` for idempotent methods with an empty body, under a retry budget |
| `.cache(Cache)` | Enable `Cache-Control` and `304` / `412` conditional requests |
| `.without_request_id()`, `.without_health()`, `.without_compression()`, `.without_problem()`, `.without_cors()`, `.without_concurrency()`, `.without_circuit_breaker()`, `.without_retry()`, `.without_cache()` | Disable the matching layer (the default) |
| `.without_timeout()` | Disable the request deadline |

The `_layer` variants take a pre-built layer so you can keep its handle (circuit state,
retry stats). One circuit and one retry budget are shared by every clone of the router.

Cargo features: `br` and `zstd` add those encodings to the compression layer; `signal`
re-exports `shutdown_signal()`.

## Layer order

Enabled layers always run outermost-first in this order, whatever order the builder
methods are called in. A layer only sees, and can only decorate, responses produced
below it:

```
request_id → health → compression → problem → helmet → redirect_https → cors
  → ipfilter → ratelimit → concurrency → circuit_breaker → timeout → body_limit → csrf
  → retry → cache → handler
```

| Layer | Why here |
|-------|----------|
| `request_id` | Outermost: every response, probes and rejections included, carries the id. |
| `health` | Probes bypass the HTTPS redirect, IP filter and limits (kubelet probes over plain HTTP); all other requests count as in flight for graceful drain. Readiness `503`s stay bare. |
| `compression` | Compresses everything below, problem documents included. |
| `problem` | Converts bare `403`/`413`/`429`/`503`/`504` from every layer below into problem details, keeping `Retry-After`, CORS and security headers. |
| `helmet` | Security headers on every response below, rejections included. |
| `redirect_https` | Plain HTTP is redirected before any policy decision. |
| `cors` | Preflights are answered before CSRF / IP filter / rate limit see them, and rejections carry `Access-Control-Allow-Origin` so browsers can read them. |
| `ipfilter` → `ratelimit` | Cheap per-client rejections first, so blocked or over-limit clients never take an in-flight slot. |
| `concurrency` | Global load shedding for admitted requests; outside `timeout`, so a slot is held at most for the timeout. One slot per request, whatever the retries below. |
| `circuit_breaker` | Inside `concurrency`, so shed, filtered and rate-limited requests are not outcomes; outside `timeout`, so `504`s count as failures; outside `retry`, so it records one outcome per request, after retries. An open circuit fails fast (`503` + `Retry-After`, a problem document when `problem` is on) before the body is read or the handler runs. |
| `timeout` | Bounds body limit, CSRF, retries (backoffs and hedges included) and handler time. |
| `body_limit` → `csrf` | Innermost request checks, closest to the handler. |
| `retry` | Below every rejecting layer: only admitted requests are retried, and `4xx` rejections never are. Retries `502`/`503`/`504` from the handler for idempotent methods with an empty body (a streamed body cannot be replayed). Hedges multiply handler work. |
| `cache` | Innermost: `304` / `412` decisions use the handler's own (uncompressed) validators; `412`s become problem details, and rejections from other layers are never given `Cache-Control`. Avoid `public` directives on pages that get the CSRF cookie. |

## Output

A successful response with the default stack:

```
HTTP/1.1 200 OK
x-content-type-options: nosniff
x-xss-protection: 0
x-frame-options: DENY
referrer-policy: strict-origin-when-cross-origin
cross-origin-opener-policy: same-origin
cross-origin-resource-policy: same-origin
origin-agent-cluster: ?1
x-dns-prefetch-control: off
x-permitted-cross-domain-policies: none
permissions-policy: accelerometer=(), autoplay=(), bluetooth=(), ...
content-security-policy: default-src 'self'; base-uri 'self'; ...; upgrade-insecure-requests
strict-transport-security: max-age=31536000; includeSubDomains
set-cookie: __Host-csrf_token=<nonce>.<issued-at>.<hmac>; Path=/; Secure; SameSite=Lax
```

A rate-limited request (security headers are still present):

```
HTTP/1.1 429 Too Many Requests
retry-after: 42
x-content-type-options: nosniff
x-frame-options: DENY
```

## Migrating from 0.1

0.2 follows `rune-axum-csrf` 0.2 and tightens the defaults:

- **CSRF tokens are HMAC-signed** and the cookie is now `__Host-csrf_token`, `Secure`,
  `SameSite=Lax`; tokens issued by 0.1 are refused once, then replaced on the next
  `GET`. Cross-origin unsafe requests are rejected even with a valid token. Set
  `.csrf_key(..)` for multi-instance deployments, `.csrf_session_cookie(..)` if you have
  sessions, and `.csrf_trusted_origin(..)` for a separate front-end origin. For
  plain-HTTP development on hosts other than `localhost`, pass
  `.csrf(CsrfConfig::new().secure(false))`.
- Urlencoded forms may carry the token in a `csrf_token` field; handlers get
  `Extension<CsrfToken>` (`hidden_input()`). Insert `CsrfRotate` into a login
  response to rotate the token.
- New re-exports: `CsrfKey`, `KeyTooShort`, `CsrfToken`, `CsrfRotate`,
  `CsrfRejection`, `SameSite`, `CspBuilder`.
- **Helmet 0.3 defaults**: a CSP, `X-Frame-Options: DENY`, Permissions-Policy, HSTS
  `max-age=31536000; includeSubDomains` (skipped on requests known to be plain HTTP)
  and more; `Server` / `X-Powered-By` are removed. `.helmet(..)` now validates the
  config and returns `Result`; use `.helmet(Helmet::new().no_hsts())?` to drop HSTS.
  New re-exports: `HelmetError`, `HelmetOverride`, `CspNonce`, `HstsMode`,
  `PermittedCrossDomainPolicies`.
- **A 30 s timeout is on.** Use `.timeout(Timeout::new().path("/events", ..))` for
  long-lived routes or `.without_timeout()`.

## License

MIT
