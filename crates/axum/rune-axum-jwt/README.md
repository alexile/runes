# rune-axum-jwt

> JWT bearer auth for Axum 0.8: HMAC, RSA, ECDSA and EdDSA keys, cached JWKS and OIDC discovery, scope/role checks, RFC 6750 errors.

[![crates.io](https://img.shields.io/crates/v/rune-axum-jwt)](https://crates.io/crates/rune-axum-jwt)
[![docs.rs](https://img.shields.io/docsrs/rune-axum-jwt)](https://docs.rs/rune-axum-jwt)
[![license](https://img.shields.io/crates/l/rune-axum-jwt)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

An OAuth 2.0 / OpenID Connect resource server for Axum. Point it at your
identity provider's issuer URL; it finds the signing keys through discovery,
caches them, picks up key rotation, and checks the claims you ask for.

- Algorithms: HS256/384/512, RS256/384/512, PS256/384/512, ES256/384, EdDSA (Ed25519).
- Keys: static keys, a JWKS URL, or OIDC discovery. Or implement `KeySource`.
- Claims: `exp` (required), `nbf`, `iat`, exact `iss`, one-of `aud`, leeway,
  required claims, max age, max token length.
- Per route: required scopes (`scope` / `scp`), required roles (any claim
  path, e.g. Keycloak's `realm_access.roles`), optional auth.
- Handlers get typed claims with `Claims<T>`.
- Failures answer with `WWW-Authenticate: Bearer error="..."` (RFC 6750) and
  an empty body.

## Installation

```toml
[dependencies]
rune-axum-jwt = "0.3"
serde = { version = "1", features = ["derive"] }
```

The default `jwks` feature brings in reqwest and Tokio for fetching keys.
With `default-features = false` you get static keys only.

## Usage

### OIDC provider

```rust,no_run
use axum::{routing::get, Router};
use rune_axum_jwt::{Claims, JwtConfig, JwtLayer};
use serde::Deserialize;

#[derive(Deserialize)]
struct User { sub: String }

async fn me(Claims(user): Claims<User>) -> String { user.sub }

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let jwt = JwtConfig::oidc("https://auth.example.com/")
        .await?
        .audience(&["https://api.example.com"])
        .leeway(30);

    let app = Router::new()
        .route("/me", get(me))
        .route(
            "/admin",
            get(|| async { "admin" })
                .layer(JwtLayer::new(jwt.clone()).require_roles(["admin"])),
        )
        .layer(JwtLayer::new(jwt));

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await?;
    axum::serve(listener, app).await?;
    Ok(())
}
```

`JwtConfig::oidc` fetches `{issuer}/.well-known/openid-configuration`,
requires its `issuer` to match exactly, and pins `iss` to it. For a plain
JWKS URL use `JwtConfig::jwks(url)` and set `.issuer(...)` yourself.

### Shared secret

```rust
use axum::{routing::get, Router};
use rune_axum_jwt::{JwtConfig, JwtLayer};

let app: Router = Router::new()
    .route("/admin", get(|| async { "ok" }))
    .route_layer(JwtLayer::new(JwtConfig::hs256(b"a long, random shared secret")));
```

### Static asymmetric keys

```rust,no_run
use rune_axum_jwt::{Algorithm, JwtConfig, StaticKeys, VerifyKey};

# fn main() -> Result<(), rune_axum_jwt::KeyError> {
let keys = StaticKeys::new([
    VerifyKey::rsa_pem(Algorithm::RS256, include_bytes!("old.pem"))?.with_kid("2025"),
    VerifyKey::ec_pem(Algorithm::ES256, include_bytes!("new.pem"))?.with_kid("2026"),
]);
let jwt = JwtConfig::new(keys).issuer("https://auth.example.com").audience(&["api"]);
# Ok(()) }
```

### Optional auth, scopes

```rust
use axum::{routing::{get, post}, Router};
use rune_axum_jwt::{Claims, JwtConfig, JwtLayer};
use serde_json::Value;

let jwt = JwtConfig::hs256(b"a long, random shared secret");

async fn feed(user: Option<Claims<Value>>) -> &'static str {
    if user.is_some() { "your feed" } else { "public feed" }
}

let app: Router = Router::new()
    .route("/feed", get(feed))
    .route(
        "/posts",
        post(|| async { "created" })
            .layer(JwtLayer::new(jwt.clone()).require_scopes(["posts:write"])),
    )
    .layer(JwtLayer::new(jwt).optional());
```

An inner layer with the same `JwtConfig` reuses the outer layer's result, so
the token is verified once.

## Responses

| Case | Status | `WWW-Authenticate` |
|------|--------|--------------------|
| no bearer token | 401 | `Bearer` |
| malformed `Authorization` header | 400 | `Bearer error="invalid_request"` |
| bad signature, expired, wrong `iss`/`aud`, unknown `kid`, ... | 401 | `Bearer error="invalid_token"` |
| missing scope / role | 403 | `Bearer error="insufficient_scope"` (with `scope="..."` for scopes) |
| keys could not be loaded | 503 | none |

The body is always empty. The exact reason is a `JwtRejection` variant,
logged at `debug` level through `tracing`.

## JWKS caching

| `JwksOptions` | Default | |
|---------------|---------|-|
| `refresh_interval` | 5 min | cached keys older than this are refreshed on the next request |
| `min_refetch_interval` | 30 s | smallest gap between two fetches, whatever triggers them |
| `timeout` | 5 s | per fetch, connect included |
| `max_response_bytes` | 256 KiB | larger documents are refused |

A token with an unknown `kid` triggers a refetch (key rotation), but at most
one per `min_refetch_interval`; the rest are rejected straight away. Fetches
are single-flight. If a refresh fails, the old keys stay in use.

## Security notes

- **No algorithm confusion.** Every key is pinned to one algorithm when it
  is loaded (the JWK's `alg`, or inferred from its type and curve). A token
  whose `alg` differs is rejected before the signature is checked, so an RSA
  public key is never used as an HMAC secret, and `none` is never accepted.
- **Header keys are never trusted.** `jku`, `x5u`, `jwk` and `x5c` in a token
  header are ignored. A `crit` header is rejected.
- **`kid` is required** when more than one key is configured.
- **JWKS fetching** is `https` only (plain `http` only to `localhost`,
  `127.0.0.1`, `::1`), does not follow redirects, has a timeout and a size cap.
  Symmetric (`oct`) and encryption keys in a remote JWKS are ignored.
- **Fetch storms**: unknown `kid`s cannot make the server hammer your
  identity provider; see `min_refetch_interval`. Do not set it to zero in
  production.
- **Set an audience.** Without `.audience(...)`, `aud` is not checked and a
  token the same issuer minted for another service is accepted here.
- **Token size** is capped (8 KiB by default, `max_token_len`) before any
  decoding.
- HMAC secrets should be at least as long as the hash output (32 bytes for
  HS256) and random.
- Crypto is `jsonwebtoken` 9 on top of `ring`.

## Migrating from 0.2

- Failures now carry a `WWW-Authenticate` header. A malformed `Authorization`
  header is a 400, a missing scope or role a 403, and a key-source outage a
  503. Before, everything was a bare 401.
- `JwtRejection` is now a detailed enum (`Missing`, `Expired`,
  `InvalidSignature`, ...) instead of `Missing` / `Invalid(jsonwebtoken::errors::Error)`.
- `JwtLayer` now stores the verified claims in the request extensions; read
  them with `Claims<T>` or `VerifiedClaims` instead of re-verifying with
  `Jwt<C>`. `Jwt<C>` still works with `JwtConfig` in state.
- `JwtService` returns a boxed future and needs a `Clone + Send` inner
  service (any Axum router or handler is). `JwtFuture` is gone.
- `aud` is no longer rejected when present but no audience is configured;
  it is simply not checked. Configure `.audience(...)`.
- New checks that may reject tokens 0.2 accepted: `iat` in the future,
  tokens over 8 KiB, `crit` headers, a `kid` that matches no key.
- The `Bearer` scheme is now matched case-insensitively.

`JwtConfig::hs256/hs384/hs512`, `.issuer`, `.audience` and `.leeway` keep
their signatures.

## License

MIT
