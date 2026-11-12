//! CSRF protection middleware — Tower middleware for Axum.
//!
//! A [`tower::Layer`] implementing the **signed double-submit cookie** pattern
//! recommended by the OWASP CSRF Prevention Cheat Sheet, with `Origin` /
//! `Referer` / Fetch Metadata verification as defense in depth.
//!
//! # Protocol
//!
//! 1. **Safe requests** (GET, HEAD, OPTIONS, TRACE) pass through. If the request
//!    has no valid token cookie, a fresh token is minted and set with
//!    `Set-Cookie`. The current token is always available to the handler as a
//!    [`CsrfToken`] request extension.
//! 2. **Every other method** must satisfy, in order:
//!    - the source is not cross-origin (`Origin`, else `Sec-Fetch-Site`, else
//!      `Referer`; requests carrying none of them rely on the token alone);
//!    - the token cookie carries a valid HMAC-SHA256 signature for this key and
//!      session (and is not older than the optional TTL);
//!    - the `x-csrf-token` header — or, if absent, the `csrf_token` field of an
//!      `application/x-www-form-urlencoded` body (read up to 64 KiB) — equals the
//!      cookie, compared in constant time.
//!
//!    Failures return a bare `403 Forbidden` (configurable; `413` for an oversized
//!    form) with `Cache-Control: no-store`. The reason is attached as a
//!    [`CsrfRejection`] response extension for logging, never sent to the client.
//!
//! Tokens look like `<nonce hex>.<issued-at>.<hmac hex>`: a 256-bit CSPRNG nonce
//! (at least 128 bits) signed together with the session binding. Without a
//! session binding the signature only proves the token came from this server,
//! so configure [`CsrfConfig::session_cookie`] or [`CsrfConfig::session_id_with`]
//! whenever your app has sessions.
//!
//! # Quick Start
//!
//! ```rust
//! use axum::{routing::post, Router};
//! use rune_axum_csrf::CsrfLayer;
//!
//! let app: Router = Router::new()
//!     .route("/submit", post(|| async { "ok" }))
//!     .layer(CsrfLayer::default());
//! ```
//!
//! # Production configuration
//!
//! ```rust
//! use axum::{Extension, response::Html, routing::get, Router};
//! use rune_axum_csrf::{CsrfConfig, CsrfKey, CsrfLayer, CsrfToken};
//!
//! # fn load_secret() -> Vec<u8> { vec![0u8; 32] }
//! async fn form(Extension(token): Extension<CsrfToken>) -> Html<String> {
//!     Html(format!(
//!         r#"<form method="post" action="/transfer">{}</form>"#,
//!         token.hidden_input().unwrap_or_default()
//!     ))
//! }
//!
//! let key = CsrfKey::from_bytes(&load_secret()).expect("32+ byte secret");
//! let layer = CsrfLayer::new(
//!     CsrfConfig::new()
//!         .key(key)
//!         .session_cookie("session_id")
//!         .http_only(true) // forms only: JavaScript never needs the cookie
//!         .exempt_prefix("/webhooks/"),
//! );
//!
//! let app: Router = Router::new()
//!     .route("/transfer", get(form).post(|| async { "done" }))
//!     .layer(layer);
//! ```

pub use layer::{
    CsrfConfig, CsrfLayer, CsrfRejection, CsrfRotate, CsrfService, CsrfToken, SameSite,
};
pub use token::{CsrfKey, KeyTooShort};

mod form;
mod layer;
mod origin;
mod token;
