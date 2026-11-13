# rune-axum-signature

> Webhook signature verification for Axum: Standard Webhooks / Svix, Stripe, GitHub, Slack, Shopify and generic HMAC.

[![crates.io](https://img.shields.io/crates/v/rune-axum-signature)](https://crates.io/crates/rune-axum-signature)
[![docs.rs](https://img.shields.io/docsrs/rune-axum-signature)](https://docs.rs/rune-axum-signature)
[![license](https://img.shields.io/crates/l/rune-axum-signature)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

## What it does

A Tower layer and an extractor that check webhook signatures before your
handler runs, so you don't have to pull in a provider's whole SDK just to
verify a request.

The layer reads the body (with a size cap), checks the signature, the
timestamp and, where it makes sense, a replay store. Then it calls your
handler with the exact bytes that were verified. Take `VerifiedWebhook` in
the handler and parse the JSON from there.

| Preset | Headers | Signed content | Timestamp | Replay check |
|---|---|---|---|---|
| `standard_webhooks` / `svix` | `webhook-id`, `webhook-timestamp`, `webhook-signature` (`svix-*` too) | `id.ts.body` | yes | on by default |
| `stripe` | `Stripe-Signature: t=..,v1=..` | `t.body` | yes | opt-in |
| `github` | `X-Hub-Signature-256: sha256=<hex>` | `body` | no | n/a |
| `slack` | `X-Slack-Signature: v0=<hex>`, `X-Slack-Request-Timestamp` | `v0:ts:body` | yes | opt-in |
| `shopify` | `X-Shopify-Hmac-Sha256: <base64>` | `body` | no | n/a |
| `generic` (`HmacConfig`) | any header, optional prefix, hex | `body` | no | n/a |

## Installation

```toml
[dependencies]
rune-axum-signature = "0.3"
```

## Usage

Put the layer on the webhook route only, not on the whole app.

### Standard Webhooks / Svix

```rust,no_run
use axum::{routing::post, Router};
use rune_axum_signature::{VerifiedWebhook, WebhookLayer, WebhookVerifier};

async fn handle(hook: VerifiedWebhook) -> &'static str {
    // hook.id() is the signed webhook-id; hook.body() the verified bytes.
    // let event: MyEvent = serde_json::from_slice(hook.body())?;
    "ok"
}

let verifier = WebhookVerifier::standard_webhooks("whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw")
    .expect("valid secret");
let app: Router = Router::new()
    .route("/webhooks/svix", post(handle).layer(WebhookLayer::new(verifier)));
```

### Stripe

```rust,no_run
use axum::{routing::post, Router};
use rune_axum_signature::{VerifiedWebhook, WebhookLayer, WebhookVerifier};

async fn handle(hook: VerifiedWebhook) -> &'static str { "ok" }

// The whsec_ string is used as-is, the way Stripe's own libraries do.
let verifier = WebhookVerifier::stripe("whsec_...");
let app: Router = Router::new()
    .route("/webhooks/stripe", post(handle).layer(WebhookLayer::new(verifier)));
```

### GitHub

```rust,no_run
use axum::{routing::post, Router};
use rune_axum_signature::{VerifiedWebhook, WebhookLayer, WebhookVerifier};

async fn handle(hook: VerifiedWebhook) -> &'static str {
    // hook.id() is X-GitHub-Delivery (not signed; fine for idempotency).
    "ok"
}

// GitHub payloads can reach 25 MB; the default cap is 2 MiB.
let verifier = WebhookVerifier::github("my-secret").max_body_bytes(25 * 1024 * 1024);
let app: Router = Router::new()
    .route("/webhooks/github", post(handle).layer(WebhookLayer::new(verifier)));
```

### Slack

```rust,no_run
use axum::{routing::post, Router};
use rune_axum_signature::{VerifiedWebhook, WebhookLayer, WebhookVerifier};

async fn handle(hook: VerifiedWebhook) -> &'static str {
    // Slack slash commands are form-encoded: parse hook.body() with serde_urlencoded.
    "ok"
}

let verifier = WebhookVerifier::slack("8f742231b10e8888abcd99yyyzzz85a5");
let app: Router = Router::new()
    .route("/slack/commands", post(handle).layer(WebhookLayer::new(verifier)));
```

### Shopify

```rust,no_run
use axum::{routing::post, Router};
use rune_axum_signature::{VerifiedWebhook, WebhookLayer, WebhookVerifier};

async fn handle(hook: VerifiedWebhook) -> &'static str { "ok" }

// The app's client secret.
let verifier = WebhookVerifier::shopify("shpss_...");
let app: Router = Router::new()
    .route("/webhooks/shopify", post(handle).layer(WebhookLayer::new(verifier)));
```

### Generic HMAC

The 0.2 API, for senders that put a hex HMAC of the body in a header.
SHA-256, SHA-1 and SHA-512 are supported.

```rust,no_run
use axum::{routing::post, Router};
use rune_axum_signature::{HmacConfig, HmacLayer};

let layer = HmacLayer::new(
    HmacConfig::sha512(b"my-secret")
        .header("x-my-signature")
        .prefix("sha512="),
);
let app: Router = Router::new()
    .route("/api/events", post(|| async { "ok" }))
    .layer(layer);
```

### Without the layer

```rust,no_run
use rune_axum_signature::WebhookVerifier;

# async fn run(headers: http::HeaderMap, body: axum::body::Bytes) {
let verifier = WebhookVerifier::stripe("whsec_...");
match verifier.verify_and_record(&headers, body).await {
    Ok(hook) => { /* use hook.body() */ }
    Err(e) => eprintln!("rejected: {e} ({})", e.status()),
}
# }
```

`verify_at(&headers, body, now)` is the pure version: no clock, no store.

### Key rotation

```rust,no_run
use rune_axum_signature::{Secret, WebhookVerifier};

let stripe = WebhookVerifier::stripe("whsec_new").with_secret("whsec_old");
let svix = WebhookVerifier::svix("whsec_bmV3IGtleSBuZXcga2V5")
    .unwrap()
    .with_secret(Secret::from_whsec("whsec_b2xkIGtleSBvbGQga2V5").unwrap());
```

## Configuration

| Method | Default | |
|---|---|---|
| `.with_secret(s)` | one secret | extra accepted secrets |
| `.tolerance(d)` | 5 minutes | max distance of the signed timestamp from now, both ways |
| `.max_body_bytes(n)` | 2 MiB | larger bodies get `413` |
| `.replay_store(store)` | in-memory (Standard Webhooks only) | your own `ReplayStore`, e.g. Redis |
| `.without_replay_protection()` | | turn it off |

Rejections are empty responses: `401` for a missing or bad signature, stale
timestamp or replay, `413` for an oversized body, `400` if the body stream
breaks, `503` if the replay store fails.

## Security

- **Constant-time comparison.** Every configured secret is checked against
  every signature in the header, and all pairs are compared, so timing does
  not reveal which one matched.
- **Timestamps.** Standard Webhooks, Stripe and Slack sign a timestamp; it
  must be within the tolerance of the server clock. Keep the clock synced.
- **Replays.** Standard Webhooks deliveries are remembered by `webhook-id`
  and timestamp until they fall out of the tolerance window. A resend of a
  failed message (same id, new timestamp and signature) is accepted, so
  make handlers idempotent on `hook.id()` if a resend after success matters. The default store is in
  memory and bounded (10 000 ids, oldest evicted first), so it only covers
  one process; with several instances, implement `ReplayStore` over shared
  storage. Store errors refuse the request. Stripe and Slack have no signed
  id; `.replay_store(..)` turns on a check keyed on timestamp + body.
- **No timestamp, no replay protection.** GitHub and Shopify don't sign a
  time, so a captured request stays valid forever. Make handlers idempotent
  on the delivery id (`hook.id()`), and keep the endpoint on HTTPS.
- **Empty secrets never verify.** An unset secret (an empty string) makes
  every request fail instead of accepting signatures anyone can compute.
- **Body size.** The body is read with a hard cap; a `Content-Length` over
  the cap is refused before reading.
- **Raw body.** The handler gets exactly the bytes that were signed.
  Never verify against re-serialized JSON.
- **Secrets stay out of logs.** `Debug` on `Secret`, `HmacConfig`,
  `WebhookVerifier` and `WebhookLayer` hides key material, and errors never
  contain secrets, signatures or body content.

## Migrating from 0.2

Existing code keeps compiling: `HmacConfig`, `HmacLayer::new(config)` and
`HmacConfig::verify` work as before. What changed:

- `HmacLayer` and `HmacService` are now aliases of `WebhookLayer` and
  `WebhookService`.
- Bodies over 2 MiB are refused with `413`. Raise it with
  `HmacLayer::new(WebhookVerifier::generic(config).max_body_bytes(n))`.
- `Debug` on `HmacConfig` no longer prints the secret.
- Verified requests now carry a `VerifiedWebhook` in their extensions.
- If you used the generic mode for Stripe or GitHub, switch to
  `WebhookVerifier::stripe` / `::github`: the 0.2 Stripe recipe could not
  parse `t=..,v1=..` and never checked the timestamp.

## License

MIT
