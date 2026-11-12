//! Webhook signature verification for Axum.
//!
//! One layer and one extractor for the common webhook signing schemes, so you
//! don't need a provider's whole SDK just to check a signature:
//!
//! | Preset | Headers | Signed content |
//! |---|---|---|
//! | [`WebhookVerifier::standard_webhooks`] / [`svix`](WebhookVerifier::svix) | `webhook-id`, `webhook-timestamp`, `webhook-signature: v1,<b64> ...` | `id.timestamp.body` |
//! | [`WebhookVerifier::stripe`] | `Stripe-Signature: t=..,v1=<hex>,...` | `t.body` |
//! | [`WebhookVerifier::github`] | `X-Hub-Signature-256: sha256=<hex>` | `body` |
//! | [`WebhookVerifier::slack`] | `X-Slack-Signature: v0=<hex>`, `X-Slack-Request-Timestamp` | `v0:ts:body` |
//! | [`WebhookVerifier::shopify`] | `X-Shopify-Hmac-Sha256: <b64>` | `body` |
//! | [`WebhookVerifier::generic`] ([`HmacConfig`]) | any header, optional prefix, hex | `body` |
//!
//! All presets use HMAC-SHA256; generic mode also does SHA-1 and SHA-512.
//!
//! # Usage
//!
//! ```rust
//! use axum::{routing::post, Router};
//! use rune_axum_signature::{VerifiedWebhook, WebhookLayer, WebhookVerifier};
//!
//! async fn stripe_events(hook: VerifiedWebhook) -> &'static str {
//!     // Parse only now that the body is verified:
//!     // let event: Event = serde_json::from_slice(hook.body())?;
//!     "ok"
//! }
//!
//! let app: Router = Router::new().route(
//!     "/webhooks/stripe",
//!     post(stripe_events).layer(WebhookLayer::new(WebhookVerifier::stripe("whsec_..."))),
//! );
//! ```
//!
//! Without the layer, call [`WebhookVerifier::verify_and_record`] (or the
//! pure [`WebhookVerifier::verify_at`]) on the headers and raw body.
//!
//! # Security
//!
//! - Signatures are compared in constant time, against every configured
//!   secret and every signature in the header.
//! - Signed timestamps must be within the tolerance (default 5 minutes) of
//!   now, in both directions.
//! - Standard Webhooks messages are deduplicated by `webhook-id` in a bounded
//!   in-memory [`ReplayStore`]; plug in a shared one for multi-instance
//!   deployments. Stripe and Slack can opt in. GitHub and Shopify sign no
//!   timestamp, so a captured request stays valid; dedupe by delivery id.
//! - The body is read up to a hard limit (default 2 MiB); larger requests
//!   get `413` before any HMAC work.
//! - Handlers receive the exact verified bytes. Don't re-serialize JSON
//!   before verifying.
//! - Secrets never appear in `Debug` output or error messages.
//!
//! # Rotation
//!
//! Add the old secret with [`WebhookVerifier::with_secret`]; requests signed
//! with either are accepted until you remove it.

mod error;
mod generic;
mod layer;
mod replay;
mod secret;
mod verifier;

pub use error::VerifyError;
pub use generic::HmacConfig;
pub use layer::{HmacLayer, HmacService, MissingWebhookLayer, WebhookLayer, WebhookService};
pub use replay::{MemoryReplayStore, ReplayFuture, ReplayStore, ReplayStoreError};
pub use secret::{InvalidSecret, Secret};
pub use verifier::{
    DEFAULT_MAX_BODY_BYTES, DEFAULT_TOLERANCE, Provider, VerifiedWebhook, WebhookVerifier,
};
