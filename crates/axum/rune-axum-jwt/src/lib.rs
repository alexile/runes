//! JWT bearer authentication for Axum 0.8.
//!
//! Verifies `Authorization: Bearer <jwt>` tokens and hands the claims to
//! handlers. Built as an OAuth 2.0 / OIDC resource server: point it
//! at your identity provider's issuer URL and it finds and caches the signing
//! keys itself.
//!
//! - **Algorithms**: HS256/384/512, RS256/384/512, PS256/384/512,
//!   ES256/384, `EdDSA` (Ed25519). Each key is pinned to one algorithm.
//! - **Keys**: [`StaticKeys`], or `JwksSource` (feature `jwks`, on by
//!   default) for a JWKS URL or OIDC discovery, cached and refreshed, with a
//!   throttled refetch on unknown `kid`. Or bring your own [`KeySource`].
//! - **Claims**: `exp` (required), `nbf`, `iat`, exact `iss`, one-of `aud`,
//!   leeway, required claims, max age, max token length.
//! - **Crypto**: `jsonwebtoken` with the pure-Rust `rust_crypto` backend
//!   (default feature) or `aws_lc_rs`.
//! - **Per route**: [`JwtLayer::require_scopes`], [`JwtLayer::require_roles`],
//!   [`JwtLayer::optional`].
//! - **Handlers**: [`Claims<T>`] (typed), [`VerifiedClaims`] (untyped), or
//!   [`Jwt<C>`] for use without the layer.
//! - **Errors**: RFC 6750 `WWW-Authenticate: Bearer error=...` with an empty
//!   body; the detailed reason is only in [`JwtRejection`] for logs.
//!
//! # Quick start (OIDC)
//!
//! ```rust,no_run
//! use axum::{routing::get, Router};
//! use rune_axum_jwt::{Claims, JwtConfig, JwtLayer};
//! use serde::Deserialize;
//!
//! #[derive(Deserialize)]
//! struct User { sub: String }
//!
//! async fn me(Claims(user): Claims<User>) -> String { user.sub }
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let jwt = JwtConfig::oidc("https://auth.example.com/")
//!         .await?
//!         .audience(&["https://api.example.com"])
//!         .leeway(30);
//!
//!     let app = Router::new()
//!         .route("/me", get(me))
//!         .route(
//!             "/admin",
//!             get(|| async { "admin" })
//!                 .layer(JwtLayer::new(jwt.clone()).require_roles(["admin"])),
//!         )
//!         .layer(JwtLayer::new(jwt));
//!
//!     let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await?;
//!     axum::serve(listener, app).await?;
//!     Ok(())
//! }
//! ```
//!
//! # Shared secret
//!
//! ```rust
//! use axum::{routing::get, Router};
//! use rune_axum_jwt::{JwtConfig, JwtLayer};
//!
//! let app: Router = Router::new()
//!     .route("/admin", get(|| async { "ok" }))
//!     .route_layer(JwtLayer::new(JwtConfig::hs256(b"a long, random shared secret")));
//! ```
//!
//! # Security notes
//!
//! - The algorithm comes from the key, never from the token. A token whose
//!   `alg` differs from its key's is rejected before signature checking, so
//!   an RSA public key is never tried as an HMAC secret and `none` is never
//!   accepted. A `crit` header is rejected.
//! - With several keys, tokens must carry a `kid`.
//! - `exp`, `nbf` and `iat` must be JSON numbers when present. A mistyped
//!   date claim rejects the token instead of counting as absent.
//! - JWKS documents are fetched over `https` only (plain `http` to loopback
//!   for development), without following redirects, with a timeout and a
//!   size cap. Symmetric keys in a remote JWKS are ignored. Header fields
//!   such as `jku`, `x5u` and `jwk` are never used to find keys.
//! - Set [`JwtConfig::audience`]: without it, any token from the same issuer
//!   is accepted, including ones minted for other services.

#![forbid(unsafe_code)]

mod config;
mod error;
mod extract;
#[cfg(feature = "jwks")]
mod jwks;
mod key;
mod layer;

pub use config::{DEFAULT_MAX_TOKEN_LEN, JwtConfig};
pub use error::JwtRejection;
pub use extract::{Claims, Jwt, VerifiedClaims};
/// Re-export of the JWT algorithm enum.
pub use jsonwebtoken::Algorithm;
/// Re-export of the JWK types accepted by [`VerifyKey::from_jwk`].
pub use jsonwebtoken::jwk;
#[cfg(feature = "jwks")]
pub use jwks::{JwksError, JwksOptions, JwksSource};
pub use key::{BoxFuture, KeyError, KeySource, LookupError, StaticKeys, VerifyKey};
pub use layer::{JwtLayer, JwtService};
