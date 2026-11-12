//! Tower layer that authenticates requests.

use std::{
    sync::Arc,
    task::{Context, Poll},
};

use axum::response::{IntoResponse, Response};
use http::Request;
use tower_layer::Layer;
use tower_service::Service;

use crate::{JwtConfig, JwtRejection, VerifiedClaims, extract::verify_parts, key::BoxFuture};

#[derive(Debug, Clone, Default)]
struct Policy {
    optional: bool,
    scopes: Vec<String>,
    all_roles: Vec<String>,
    any_role: Vec<String>,
}

/// Tower [`Layer`] that verifies the bearer token before the handler runs.
///
/// On success the [`VerifiedClaims`] go into the request extensions, where
/// [`Claims<T>`](crate::Claims) and `VerifiedClaims` extractors find them.
/// On failure the request gets the RFC 6750 response described on
/// [`JwtRejection`].
///
/// Per-route scope and role checks are further layers. A layer reuses the
/// claims an outer layer verified with the same [`JwtConfig`], so the token
/// is only checked once.
///
/// # Examples
///
/// ```rust
/// use axum::{routing::{get, post}, Router};
/// use rune_axum_jwt::{JwtConfig, JwtLayer};
///
/// let jwt = JwtConfig::hs256(b"a long, random shared secret").audience(&["api"]);
///
/// let app: Router = Router::new()
///     .route(
///         "/orders",
///         post(|| async { "created" })
///             .layer(JwtLayer::new(jwt.clone()).require_scopes(["orders:write"])),
///     )
///     .route("/orders/{id}", get(|| async { "order" }))
///     .layer(JwtLayer::new(jwt));
/// ```
#[derive(Debug, Clone)]
pub struct JwtLayer {
    config: JwtConfig,
    policy: Arc<Policy>,
}

impl JwtLayer {
    /// A layer that requires a valid token.
    #[must_use]
    pub fn new(config: JwtConfig) -> Self {
        Self {
            config,
            policy: Arc::new(Policy::default()),
        }
    }

    fn policy_mut(&mut self) -> &mut Policy {
        Arc::make_mut(&mut self.policy)
    }

    /// Lets requests without bearer credentials through, unauthenticated.
    ///
    /// A request that does send a token still has it verified, and is
    /// rejected if it is bad. Handlers take `Option<Claims<T>>`.
    #[must_use]
    pub fn optional(mut self) -> Self {
        self.policy_mut().optional = true;
        self
    }

    /// Requires every one of `scopes` (from `scope` or `scp`). Missing ones
    /// get a 403 `insufficient_scope`.
    #[must_use]
    pub fn require_scopes<I, T>(mut self, scopes: I) -> Self
    where
        I: IntoIterator<Item = T>,
        T: Into<String>,
    {
        self.policy_mut()
            .scopes
            .extend(scopes.into_iter().map(Into::into));
        self
    }

    /// Requires every one of `roles` (see [`JwtConfig::roles_claim`]).
    #[must_use]
    pub fn require_roles<I, T>(mut self, roles: I) -> Self
    where
        I: IntoIterator<Item = T>,
        T: Into<String>,
    {
        self.policy_mut()
            .all_roles
            .extend(roles.into_iter().map(Into::into));
        self
    }

    /// Requires at least one of `roles`.
    #[must_use]
    pub fn require_any_role<I, T>(mut self, roles: I) -> Self
    where
        I: IntoIterator<Item = T>,
        T: Into<String>,
    {
        self.policy_mut()
            .any_role
            .extend(roles.into_iter().map(Into::into));
        self
    }
}

impl<S> Layer<S> for JwtLayer {
    type Service = JwtService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        JwtService {
            inner,
            config: self.config.clone(),
            policy: Arc::clone(&self.policy),
        }
    }
}

/// Tower [`Service`] produced by [`JwtLayer`].
#[derive(Debug, Clone)]
pub struct JwtService<S> {
    inner: S,
    config: JwtConfig,
    policy: Arc<Policy>,
}

impl Policy {
    fn check(&self, claims: Option<&VerifiedClaims>) -> Result<(), JwtRejection> {
        let needs_claims =
            !self.scopes.is_empty() || !self.all_roles.is_empty() || !self.any_role.is_empty();
        let Some(claims) = claims else {
            return if self.optional && !needs_claims {
                Ok(())
            } else {
                Err(JwtRejection::Missing)
            };
        };
        if !self.scopes.iter().all(|s| claims.has_scope(s)) {
            return Err(JwtRejection::InsufficientScope {
                required: self.scopes.clone(),
            });
        }
        let roles_ok = self.all_roles.iter().all(|r| claims.has_role(r))
            && (self.any_role.is_empty() || self.any_role.iter().any(|r| claims.has_role(r)));
        if !roles_ok {
            return Err(JwtRejection::InsufficientRole);
        }
        Ok(())
    }
}

impl<S, B> Service<Request<B>> for JwtService<S>
where
    S: Service<Request<B>, Response = Response> + Clone + Send + 'static,
    S::Future: Send,
    B: Send + 'static,
{
    type Response = Response;
    type Error = S::Error;
    type Future = BoxFuture<'static, Result<Response, S::Error>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<B>) -> Self::Future {
        // The ready inner service handles this request; a fresh clone takes
        // its place for the next one.
        let clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, clone);
        let config = self.config.clone();
        let policy = Arc::clone(&self.policy);
        Box::pin(async move {
            let (mut parts, body) = req.into_parts();
            let outcome = match verify_parts(&parts, &config).await {
                Ok(claims) => policy.check(claims.as_ref()).map(|()| claims),
                Err(rejection) => Err(rejection),
            };
            match outcome {
                Ok(claims) => {
                    if let Some(claims) = claims {
                        parts.extensions.insert(claims);
                    }
                    inner.call(Request::from_parts(parts, body)).await
                }
                Err(rejection) => {
                    tracing::debug!(reason = %rejection, "jwt: request rejected");
                    Ok(rejection.into_response())
                }
            }
        })
    }
}
