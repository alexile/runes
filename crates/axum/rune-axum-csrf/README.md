# rune-axum-csrf

> CSRF protection middleware for Axum — signed double-submit cookie, or a token-free Origin / Fetch Metadata mode.

[![crates.io](https://img.shields.io/crates/v/rune-axum-csrf)](https://crates.io/crates/rune-axum-csrf)
[![docs.rs](https://img.shields.io/docsrs/rune-axum-csrf)](https://docs.rs/rune-axum-csrf)
[![license](https://img.shields.io/crates/l/rune-axum-csrf)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

A [`tower::Layer`](https://docs.rs/tower/latest/tower/trait.Layer.html) implementing the
**signed double-submit cookie** pattern from the
[OWASP CSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html),
plus `Origin` / `Referer` / `Sec-Fetch-Site` verification as defense in depth. It also has a
**token-free origin-only mode** in the style of Go's `http.CrossOriginProtection`. Works with
Axum, Hyper, and any Tower-compatible framework.

## Which mode?

| | Token mode — `CsrfLayer::token(config)` | Origin-only mode — `CsrfLayer::origin_only()` |
|---|---|---|
| What it checks | Signed cookie + echoed token, plus the request's source | `Sec-Fetch-Site`, then `Origin` |
| App changes | Token in every form / `fetch` call | None |
| Cookies | `__Host-csrf_token` | None |
| Old browsers without `Origin` | Protected by the token | Rejected (or allowed, if you opt in) |
| Untrusted sibling subdomains | Not trusted, even with a matching cookie | Rejected unless listed as trusted |

**Pick origin-only** for new apps and SPAs whose users run browsers from 2020 or later: there is
nothing to wire into templates or JavaScript, no cookie, and nothing to rotate. **Pick token mode**
if you must support older browsers, if a proxy or privacy tool in your audience strips `Origin`,
or if you want two independent defenses. `CsrfLayer::new(config)` and `CsrfLayer::default()` keep
meaning token mode.

## How token mode works

1. **Safe requests** (GET, HEAD, OPTIONS, TRACE) pass through. Without a valid token cookie the
   middleware mints a token and adds `Set-Cookie`. The token is also handed to the handler as a
   `CsrfToken` request extension, ready to embed in a form.
2. **Every other method** (POST, PUT, PATCH, DELETE, custom verbs) must pass, in order:
   - **Source check:** `Origin` (or, if absent, `Sec-Fetch-Site: cross-site`, or `Referer`) must
     match the request `Host` or a trusted origin. Requests with none of these headers rely on the
     token alone.
   - **Cookie check:** the token cookie must carry a valid HMAC-SHA256 signature for this key and
     session, and must not be older than the optional TTL.
   - **Token check:** the `x-csrf-token` header — or, if absent, the `csrf_token` field of an
     `application/x-www-form-urlencoded` body — must equal the cookie (constant-time compare).
3. Failures get a bare **`403 Forbidden`** (configurable; `413` for an oversized form) with
   `Cache-Control: no-store` and an empty body. The reason is attached as a `CsrfRejection`
   response extension for your logs.

Tokens look like `<nonce hex>.<issued-at>.<hmac hex>`: a 256-bit CSPRNG nonce (never less than
128 bits) signed together with the session binding.

## How origin-only mode works

1. **Safe requests** (GET, HEAD, OPTIONS, TRACE) pass. No cookie is set.
2. **Every other method** passes if `Sec-Fetch-Site` is `same-origin` or `none` (typed URL,
   bookmark). Otherwise (`same-site`, `cross-site`, or an older browser without Fetch Metadata)
   `Origin` must equal the request's own origin — scheme, host and port, case-insensitive, default
   ports dropped — or a trusted origin. `Origin: null` never matches.
3. A request with **neither header** is rejected with `CsrfRejection::MissingOrigin`. That is the
   secure default; every current browser sends at least one of them on a state-changing request,
   so only non-browser clients (curl, other servers) and very old browsers are affected. Opt in to
   letting them through with `.allow_missing_headers(true)`, which is what Go and tower-http do.
4. Rejections are the same as in token mode: a bare `403` with `Cache-Control: no-store` and a
   `CsrfRejection` response extension.

The request's own scheme comes from the request URI (HTTP/2), then — only with
`.trust_proxy_headers(true)` — from `Forwarded` / `X-Forwarded-Proto`, and otherwise defaults to
`https`. Use `.assume_https(false)` for plain-HTTP development servers.

```rust
use axum::{routing::post, Router};
use rune_axum_csrf::{CsrfLayer, CsrfOriginConfig};

let layer = CsrfLayer::origin(
    CsrfOriginConfig::new()
        .trusted_origin("https://app.example.com") // separate front end
        .trust_proxy_headers(true)                  // TLS ends at the load balancer
        .exempt_prefix("/webhooks/")                // verified by their own signatures
        .insecure_bypass(|parts| parts.headers.contains_key("authorization")),
);

let app: Router = Router::new()
    .route("/submit", post(handler))
    .layer(layer);
```

| Method | Default | Description |
|--------|---------|-------------|
| `.trusted_origin(origin)` | none | Extra allowed origin, e.g. `https://app.example.com`. Malformed values are ignored. |
| `.allow_missing_headers(bool)` | `false` | Let requests with neither `Origin` nor `Sec-Fetch-Site` through. |
| `.trust_proxy_headers(bool)` | `false` | Take scheme and host from `Forwarded` / `X-Forwarded-Proto` / `X-Forwarded-Host`. Only behind a proxy that overwrites them. |
| `.assume_https(bool)` | `true` | Scheme to assume when nothing else says. |
| `.exempt_path(path)` / `.exempt_prefix(prefix)` | none | Skip the check (webhooks with their own auth). |
| `.insecure_bypass(fn(&Parts) -> bool)` | none | Skip the check when the hook returns `true`, e.g. for bearer-token requests. |
| `.status(StatusCode)` | `403` | Rejection status. |

Handlers don't get a `CsrfToken` extension in this mode.

## Installation

```toml
[dependencies]
rune-axum-csrf = "0.2"
```

## Token mode usage

### Defaults

```rust
use axum::{routing::post, Router};
use rune_axum_csrf::CsrfLayer;

let app: Router = Router::new()
    .route("/submit", post(handler))
    .layer(CsrfLayer::default());
```

### Server-rendered forms with sessions (recommended)

```rust
use axum::{Extension, response::Html, routing::get, Router};
use rune_axum_csrf::{CsrfConfig, CsrfKey, CsrfLayer, CsrfToken};

async fn form(Extension(token): Extension<CsrfToken>) -> Html<String> {
    Html(format!(
        r#"<form method="post" action="/transfer">{}<button>Send</button></form>"#,
        token.hidden_input().unwrap_or_default()
    ))
}

let key = CsrfKey::from_bytes(&secret_from_vault)?; // ≥ 32 bytes, same on every instance
let layer = CsrfLayer::new(
    CsrfConfig::new()
        .key(key)
        .session_cookie("session_id") // bind tokens to the session
        .http_only(true)              // only forms need the token
        .exempt_prefix("/webhooks/"),
);

let app: Router = Router::new()
    .route("/transfer", get(form).post(transfer))
    .layer(layer);
```

### Single-page apps

Leave `http_only` off, read the `__Host-csrf_token` cookie in JavaScript and send it back:

```js
fetch("/api/items", {
  method: "POST",
  headers: { "x-csrf-token": getCookie("__Host-csrf_token") },
  body: JSON.stringify(item),
});
```

### Rotating the token

Insert `CsrfRotate` into a response (after login, logout or a privilege change) and the
middleware sets a fresh token cookie with it:

```rust
use axum::response::{IntoResponse, Redirect};
use rune_axum_csrf::CsrfRotate;

async fn login() -> impl IntoResponse {
    let mut res = Redirect::to("/").into_response();
    res.extensions_mut().insert(CsrfRotate);
    res
}
```

## Token mode configuration

| Method | Default | Description |
|--------|---------|-------------|
| `.key(CsrfKey)` | random per config | HMAC key. Set it explicitly when running several instances. |
| `.session_cookie(name)` | none | Bind tokens to this session cookie's value. |
| `.session_id_with(fn(&Parts) -> Option<String>)` | none | Bind tokens to a custom session id (e.g. from an extension). |
| `.cookie_name(name)` | `csrf_token` | Cookie name (sent as `__Host-csrf_token` while the prefix is on). |
| `.host_prefix(bool)` | `true` | Use the `__Host-` prefix (needs `Secure`; forces `Path=/`). |
| `.secure(bool)` | `true` | `Secure` attribute. Browsers accept it on `http://localhost`. |
| `.http_only(bool)` | `false` | `HttpOnly` attribute. Enable when JavaScript never reads the cookie. |
| `.same_site(SameSite)` | `Lax` | `SameSite=Lax` or `Strict`. |
| `.cookie_path(path)` | `/` | `Path` attribute (ignored while the `__Host-` prefix is on). |
| `.header_name(HeaderName)` | `x-csrf-token` | Header carrying the submitted token. |
| `.form_field(name)` / `.without_form_field()` | `csrf_token` | Urlencoded form field carrying the token. |
| `.max_form_bytes(usize)` | `65536` | Body read limit when looking for the form field; larger gets `413`. |
| `.token_bytes(usize)` | `32` | Nonce bytes, clamped to `16..=256`. |
| `.token_ttl(Duration)` | none | Token lifetime; also sets the cookie `Max-Age`. |
| `.verify_origin(bool)` | `true` | `Origin` / `Sec-Fetch-Site` / `Referer` checks. |
| `.trusted_origin(origin)` | none | Extra allowed origin, e.g. `https://app.example.com`. |
| `.exempt_path(path)` / `.exempt_prefix(prefix)` | none | Skip CSRF handling (webhooks with their own auth). |
| `.status(StatusCode)` | `403` | Rejection status. |

## Security notes

- **Bind tokens to the session.** Without `session_cookie` / `session_id_with`, the signature only
  proves the server minted the token. An attacker who controls a sibling subdomain could then plant
  ("toss") a genuine token of their own into the victim's cookie jar. The `__Host-` prefix (on by
  default) already stops subdomains from setting the cookie; session binding stops it even when
  the prefix is off.
- **Share one key across instances** and load it from a secret store. The default key is random per
  `CsrfConfig`, so tokens do not survive restarts and are not accepted by other replicas.
- **Rotate on privilege changes** with `CsrfRotate`. A safe request whose cookie is invalid for the
  current session (e.g. right after login) gets a new token automatically.
- **Never change state on GET.** Safe methods are not checked, by design.
- **Behind a reverse proxy** that rewrites `Host`, add your public origin with `trusted_origin`,
  or the `Origin` check rejects legitimate posts.
- **Multipart forms** are not parsed: send the token in the header (or switch the form to
  urlencoded). Only urlencoded bodies are read, at most `max_form_bytes`, and only when the header
  is absent; the body is then passed on to your handler unchanged.
- **XSS defeats every CSRF defense.** Keep a strict Content Security Policy.
- Pages that carry the token should not be stored in shared caches (`Cache-Control: private`).
- Token comparison and signature checks are constant time (`subtle`, `hmac`). `Debug` output of
  `CsrfConfig`, `CsrfKey` and `CsrfToken` never shows the key or token.

## Migrating from 0.1

0.2 replaces the naive double-submit scheme, which accepted any cookie value the attacker could
plant, and changes several defaults. Existing 0.1 cookies are invalid: clients get a new token on
their next GET.

- **Cookie name** is now `__Host-csrf_token` (because `secure` defaults to `true`). Update any
  JavaScript that reads `csrf_token`, or set `.host_prefix(false)` to keep the old name.
- **`secure` defaults to `true`.** For plain-HTTP development on a non-localhost host, set
  `.secure(false)`.
- **`SameSite` defaults to `Lax`** (was `Strict`); use `.same_site(SameSite::Strict)` to keep it.
- **Cross-origin posts are rejected** even with a valid token. Add `.trusted_origin(...)` for
  legitimate cross-origin front ends, or `.verify_origin(false)`.
- **Tokens are signed.** Tests that hand-craft a cookie/header pair must first fetch a token with
  a GET (or read the `CsrfToken` extension).
- **Multi-instance deployments must set `.key(...)`.**
- **Trait bounds:** the service now needs `S: Clone` and a request body implementing
  `http_body::Body + From<Bytes>` (Axum's `Body` qualifies) so it can read form bodies.
- `Set-Cookie` is now appended, so cookies set by your handler are no longer overwritten.

## License

MIT
