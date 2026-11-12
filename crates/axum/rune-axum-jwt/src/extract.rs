//! Extractors and the verified-claims request extension.

use std::sync::Arc;

use axum::extract::{FromRef, FromRequestParts, OptionalFromRequestParts};
use http::{HeaderMap, header, request::Parts};
use jsonwebtoken::Algorithm;
use serde::de::DeserializeOwned;
use serde_json::Value;

use crate::{JwtConfig, JwtRejection};

/// Claims of a verified token.
///
/// [`JwtLayer`](crate::JwtLayer) stores this in the request extensions;
/// extract it directly for untyped access, or use [`Claims<T>`].
#[derive(Debug, Clone)]
pub struct VerifiedClaims {
    claims: Arc<Value>,
    kid: Option<String>,
    alg: Algorithm,
    scopes: Vec<String>,
    roles: Vec<String>,
    config: Arc<()>,
}

impl VerifiedClaims {
    pub(crate) const fn new(
        claims: Arc<Value>,
        kid: Option<String>,
        alg: Algorithm,
        scopes: Vec<String>,
        roles: Vec<String>,
        config: Arc<()>,
    ) -> Self {
        Self {
            claims,
            kid,
            alg,
            scopes,
            roles,
            config,
        }
    }

    /// The whole claims set (always a JSON object).
    #[must_use]
    pub fn claims(&self) -> &Value {
        &self.claims
    }

    /// One claim by name.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&Value> {
        self.claims.get(name)
    }

    /// The `sub` claim, if it is a string.
    #[must_use]
    pub fn subject(&self) -> Option<&str> {
        self.get("sub").and_then(Value::as_str)
    }

    /// The `kid` the token was verified with, if it had one.
    #[must_use]
    pub fn kid(&self) -> Option<&str> {
        self.kid.as_deref()
    }

    /// The algorithm the token was verified with.
    #[must_use]
    pub const fn algorithm(&self) -> Algorithm {
        self.alg
    }

    /// Scopes from `scope` and `scp`, sorted and deduplicated.
    #[must_use]
    pub fn scopes(&self) -> &[String] {
        &self.scopes
    }

    /// Roles from the configured roles claim.
    #[must_use]
    pub fn roles(&self) -> &[String] {
        &self.roles
    }

    /// Whether the token grants `scope`.
    #[must_use]
    pub fn has_scope(&self, scope: &str) -> bool {
        self.scopes
            .binary_search_by(|s| s.as_str().cmp(scope))
            .is_ok()
    }

    /// Whether the token carries `role`.
    #[must_use]
    pub fn has_role(&self, role: &str) -> bool {
        self.roles.iter().any(|r| r == role)
    }

    /// Deserializes the claims into `T`.
    ///
    /// # Errors
    ///
    /// [`JwtRejection::InvalidClaims`] if they do not fit `T`.
    pub fn deserialize<T: DeserializeOwned>(&self) -> Result<T, JwtRejection> {
        T::deserialize(&*self.claims).map_err(|e| JwtRejection::InvalidClaims(e.to_string()))
    }

    pub(crate) fn verified_by(&self, config: &JwtConfig) -> bool {
        config.is(&self.config)
    }
}

/// Returns the bearer token from `headers`.
///
/// `Ok(None)` when there are no bearer credentials at all (no header, or
/// another scheme such as `Basic`).
pub fn bearer_token(headers: &HeaderMap) -> Result<Option<&str>, JwtRejection> {
    let mut values = headers.get_all(header::AUTHORIZATION).iter();
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(JwtRejection::MalformedHeader);
    }
    let value = value.to_str().map_err(|_| JwtRejection::MalformedHeader)?;
    let Some((scheme, rest)) = value.split_once(' ') else {
        return if value.eq_ignore_ascii_case("bearer") {
            Err(JwtRejection::MalformedHeader)
        } else {
            Ok(None)
        };
    };
    if !scheme.eq_ignore_ascii_case("bearer") {
        return Ok(None);
    }
    let token = rest.trim_matches(' ');
    // b64token = 1*( ALPHA / DIGIT / "-" / "." / "_" / "~" / "+" / "/" ) *"="
    let body = token.trim_end_matches('=');
    let ok = !body.is_empty()
        && body
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-._~+/".contains(&b));
    if ok {
        Ok(Some(token))
    } else {
        Err(JwtRejection::MalformedHeader)
    }
}

/// Typed claims of a request already authenticated by
/// [`JwtLayer`](crate::JwtLayer).
///
/// Rejects with 401 when the layer did not run or let the request through
/// unauthenticated (optional mode). Use `Option<Claims<T>>` on routes behind
/// an optional layer.
///
/// # Examples
///
/// ```rust
/// use axum::{routing::get, Router};
/// use rune_axum_jwt::{Claims, JwtConfig, JwtLayer};
/// use serde::Deserialize;
///
/// #[derive(Deserialize)]
/// struct User { sub: String }
///
/// async fn me(Claims(user): Claims<User>) -> String { user.sub }
///
/// let app: Router = Router::new()
///     .route("/me", get(me))
///     .layer(JwtLayer::new(JwtConfig::hs256(b"a long, random shared secret")));
/// ```
#[derive(Debug, Clone)]
pub struct Claims<T>(pub T);

impl<T, S> FromRequestParts<S> for Claims<T>
where
    T: DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = JwtRejection;

    #[allow(
        clippy::unused_async_trait_impl,
        reason = "the extractor trait is async; this implementation happens not to await"
    )]
    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<VerifiedClaims>()
            .ok_or(JwtRejection::Missing)?
            .deserialize()
            .map(Self)
    }
}

impl<T, S> OptionalFromRequestParts<S> for Claims<T>
where
    T: DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = JwtRejection;

    #[allow(
        clippy::unused_async_trait_impl,
        reason = "the extractor trait is async; this implementation happens not to await"
    )]
    async fn from_request_parts(
        parts: &mut Parts,
        _state: &S,
    ) -> Result<Option<Self>, Self::Rejection> {
        parts
            .extensions
            .get::<VerifiedClaims>()
            .map(|c| c.deserialize().map(Self))
            .transpose()
    }
}

impl<S: Send + Sync> FromRequestParts<S> for VerifiedClaims {
    type Rejection = JwtRejection;

    #[allow(
        clippy::unused_async_trait_impl,
        reason = "the extractor trait is async; this implementation happens not to await"
    )]
    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<Self>()
            .cloned()
            .ok_or(JwtRejection::Missing)
    }
}

impl<S: Send + Sync> OptionalFromRequestParts<S> for VerifiedClaims {
    type Rejection = std::convert::Infallible;

    #[allow(
        clippy::unused_async_trait_impl,
        reason = "the extractor trait is async; this implementation happens not to await"
    )]
    async fn from_request_parts(
        parts: &mut Parts,
        _state: &S,
    ) -> Result<Option<Self>, Self::Rejection> {
        Ok(parts.extensions.get::<Self>().cloned())
    }
}

/// Verifies the bearer token itself, using the [`JwtConfig`] in Axum state.
///
/// Use this when there is no [`JwtLayer`](crate::JwtLayer) in front of the
/// handler. If a layer with the same config already verified the request,
/// its result is reused.
///
/// # Examples
///
/// ```rust
/// use axum::{extract::FromRef, routing::get, Router};
/// use rune_axum_jwt::{Jwt, JwtConfig};
/// use serde::Deserialize;
///
/// #[derive(Deserialize)]
/// struct User { sub: String }
///
/// #[derive(Clone)]
/// struct AppState { jwt: JwtConfig }
///
/// impl FromRef<AppState> for JwtConfig {
///     fn from_ref(s: &AppState) -> Self { s.jwt.clone() }
/// }
///
/// async fn me(Jwt(user): Jwt<User>) -> String { user.sub }
///
/// let state = AppState { jwt: JwtConfig::hs256(b"a long, random shared secret") };
/// let app: Router = Router::new().route("/me", get(me)).with_state(state);
/// ```
#[derive(Debug, Clone)]
pub struct Jwt<C>(pub C);

pub async fn verify_parts(
    parts: &Parts,
    config: &JwtConfig,
) -> Result<Option<VerifiedClaims>, JwtRejection> {
    if let Some(done) = parts.extensions.get::<VerifiedClaims>()
        && done.verified_by(config)
    {
        return Ok(Some(done.clone()));
    }
    match bearer_token(&parts.headers)? {
        Some(token) => config.verify(token).await.map(Some),
        None => Ok(None),
    }
}

impl<C, S> FromRequestParts<S> for Jwt<C>
where
    C: DeserializeOwned + Send,
    S: Send + Sync,
    JwtConfig: FromRef<S>,
{
    type Rejection = JwtRejection;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let config = JwtConfig::from_ref(state);
        verify_parts(parts, &config)
            .await?
            .ok_or(JwtRejection::Missing)?
            .deserialize()
            .map(Self)
    }
}

impl<C, S> OptionalFromRequestParts<S> for Jwt<C>
where
    C: DeserializeOwned + Send,
    S: Send + Sync,
    JwtConfig: FromRef<S>,
{
    type Rejection = JwtRejection;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &S,
    ) -> Result<Option<Self>, Self::Rejection> {
        let config = JwtConfig::from_ref(state);
        verify_parts(parts, &config)
            .await?
            .map(|c| c.deserialize().map(Self))
            .transpose()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::HeaderValue;

    fn h(values: &[&str]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for v in values {
            map.append(header::AUTHORIZATION, HeaderValue::from_str(v).unwrap());
        }
        map
    }

    #[test]
    fn bearer_parsing() {
        assert_eq!(bearer_token(&h(&[])), Ok(None));
        assert_eq!(bearer_token(&h(&["Basic dXNlcjpw"])), Ok(None));
        assert_eq!(bearer_token(&h(&["Bearer a.b.c"])), Ok(Some("a.b.c")));
        assert_eq!(bearer_token(&h(&["bearer a.b.c"])), Ok(Some("a.b.c")));
        assert_eq!(
            bearer_token(&h(&["Bearer"])),
            Err(JwtRejection::MalformedHeader)
        );
        assert_eq!(
            bearer_token(&h(&["Bearer a b"])),
            Err(JwtRejection::MalformedHeader)
        );
        assert_eq!(
            bearer_token(&h(&["Bearer a.b.c", "Bearer d.e.f"])),
            Err(JwtRejection::MalformedHeader)
        );
    }
}
