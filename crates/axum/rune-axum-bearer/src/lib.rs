//! Bearer token extractor for Axum — typed extraction from `Authorization` headers.
//!
//! Implements [`FromRequestParts`] for [`BearerToken`], pulling the raw token
//! from an `Authorization: Bearer <token>` header. Requests with a missing or
//! malformed header are rejected with `401 Unauthorized` and a
//! `WWW-Authenticate: Bearer` response header before the handler runs.
//!
//! > [!NOTE]
//! > This extractor surfaces the raw token string — it does not verify or validate it.
//! > Use the token with your own validation logic or pass it to a JWT library.
//!
//! # Features
//!
//! - Case-insensitive scheme matching (`Bearer`, `bearer`, `BEARER`).
//! - Trims surrounding whitespace from the extracted token.
//! - Rejects blank tokens (e.g. `Authorization: Bearer `).
//! - `401 Unauthorized` with `WWW-Authenticate: Bearer` on all failure cases.
//! - `Option<BearerToken>` works automatically for optional extraction.
//!
//! # Quick Start
//!
//! ```rust
//! use axum::{routing::get, Router};
//! use rune_axum_bearer::BearerToken;
//!
//! async fn handler(BearerToken(token): BearerToken) -> String {
//!     format!("token={token}")
//! }
//!
//! let app: Router = Router::new().route("/api", get(handler));
//! ```
//!
//! # Optional Token
//!
//! Wrap in `Option<BearerToken>` when the header is not always required:
//!
//! ```rust
//! use axum::{routing::get, Router};
//! use rune_axum_bearer::BearerToken;
//!
//! async fn handler(token: Option<BearerToken>) -> String {
//!     match token {
//!         Some(BearerToken(t)) => format!("authenticated: {t}"),
//!         None => "anonymous".to_owned(),
//!     }
//! }
//!
//! let app: Router = Router::new().route("/api", get(handler));
//! ```

use axum_core::{
    extract::{FromRequestParts, OptionalFromRequestParts},
    response::{IntoResponse, Response},
};
use http::{StatusCode, request::Parts};
use std::convert::Infallible;

/// A bearer token extracted from the `Authorization: Bearer <token>` request header.
///
/// Use as an Axum extractor in handler signatures. The inner `String` is the
/// raw token value that follows the `Bearer ` prefix, with surrounding whitespace trimmed.
///
/// Returns [`BearerRejection`] (`401 Unauthorized`) when the header is absent
/// or not in `Bearer <token>` format.
///
/// # Examples
///
/// ```rust,no_run
/// use axum::{routing::get, Router};
/// use rune_axum_bearer::BearerToken;
///
/// async fn handler(BearerToken(token): BearerToken) -> String {
///     format!("token={token}")
/// }
///
/// let app: Router = Router::new().route("/api", get(handler));
/// ```
#[derive(Debug, Clone)]
pub struct BearerToken(pub String);

/// Rejection returned by [`BearerToken`] when extraction fails.
///
/// Always responds with `401 Unauthorized` and `WWW-Authenticate: Bearer`.
#[derive(Debug)]
pub enum BearerRejection {
    /// The `Authorization` header was absent.
    Missing,
    /// The `Authorization` header was present but malformed or used a non-`Bearer` scheme.
    Invalid,
}

impl IntoResponse for BearerRejection {
    fn into_response(self) -> Response {
        let body = match self {
            Self::Missing => "missing Authorization header",
            Self::Invalid => "invalid Authorization header; expected: Bearer <token>",
        };
        (
            StatusCode::UNAUTHORIZED,
            [("www-authenticate", "Bearer")],
            body,
        )
            .into_response()
    }
}

impl<S> FromRequestParts<S> for BearerToken
where
    S: Send + Sync,
{
    type Rejection = BearerRejection;

    #[allow(
        clippy::unused_async_trait_impl,
        reason = "the extractor trait is async; this implementation happens not to await"
    )]
    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let value = parts
            .headers
            .get("authorization")
            .ok_or(BearerRejection::Missing)?
            .to_str()
            .map_err(|_| BearerRejection::Invalid)?;

        let (scheme, rest) = value.split_once(' ').ok_or(BearerRejection::Invalid)?;

        if !scheme.eq_ignore_ascii_case("bearer") {
            return Err(BearerRejection::Invalid);
        }

        let token = rest.trim();
        if token.is_empty() {
            return Err(BearerRejection::Invalid);
        }

        Ok(Self(token.to_owned()))
    }
}

impl<S> OptionalFromRequestParts<S> for BearerToken
where
    S: Send + Sync,
{
    type Rejection = Infallible;

    #[allow(
        clippy::unused_async_trait_impl,
        reason = "the extractor trait is async; this implementation happens not to await"
    )]
    async fn from_request_parts(
        parts: &mut Parts,
        _state: &S,
    ) -> Result<Option<Self>, Self::Rejection> {
        let Some(value) = parts.headers.get("authorization") else {
            return Ok(None);
        };
        let Ok(value) = value.to_str() else {
            return Ok(None);
        };
        let Some((scheme, rest)) = value.split_once(' ') else {
            return Ok(None);
        };
        if !scheme.eq_ignore_ascii_case("bearer") {
            return Ok(None);
        }
        let token = rest.trim();
        if token.is_empty() {
            return Ok(None);
        }
        Ok(Some(Self(token.to_owned())))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{Router, body::Body, routing::get};
    use http::StatusCode;
    use tower::ServiceExt;

    async fn echo_token(BearerToken(token): BearerToken) -> impl axum::response::IntoResponse {
        (StatusCode::OK, [("x-token", token)])
    }

    fn build_app() -> Router {
        Router::new().route("/", get(echo_token))
    }

    async fn send(app: Router, req: http::Request<Body>) -> http::Response<Body> {
        app.oneshot(req).await.unwrap()
    }

    fn req_with_auth(value: &str) -> http::Request<Body> {
        http::Request::builder()
            .method("GET")
            .uri("/")
            .header("authorization", value)
            .body(Body::empty())
            .unwrap()
    }

    fn req_bare() -> http::Request<Body> {
        http::Request::builder()
            .method("GET")
            .uri("/")
            .body(Body::empty())
            .unwrap()
    }

    #[tokio::test]
    async fn valid_bearer_token_extracted() {
        let response = send(build_app(), req_with_auth("Bearer my-secret-token")).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get("x-token").unwrap().to_str().unwrap(),
            "my-secret-token"
        );
    }

    #[tokio::test]
    async fn missing_header_returns_401() {
        let response = send(build_app(), req_bare()).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn wrong_scheme_returns_401() {
        let response = send(build_app(), req_with_auth("Basic dXNlcjpwYXNz")).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn bearer_without_space_returns_401() {
        let response = send(build_app(), req_with_auth("Bearer")).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn bearer_blank_token_returns_401() {
        let response = send(build_app(), req_with_auth("Bearer ")).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn bearer_only_whitespace_token_returns_401() {
        let response = send(build_app(), req_with_auth("Bearer    ")).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn lowercase_scheme_accepted() {
        let response = send(build_app(), req_with_auth("bearer my-token")).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get("x-token").unwrap().to_str().unwrap(),
            "my-token"
        );
    }

    #[tokio::test]
    async fn uppercase_scheme_accepted() {
        let response = send(build_app(), req_with_auth("BEARER my-token")).await;
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn surrounding_whitespace_trimmed() {
        let response = send(build_app(), req_with_auth("Bearer   trimmed   ")).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get("x-token").unwrap().to_str().unwrap(),
            "trimmed"
        );
    }

    #[tokio::test]
    async fn www_authenticate_header_on_missing() {
        let response = send(build_app(), req_bare()).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            response
                .headers()
                .get("www-authenticate")
                .unwrap()
                .to_str()
                .unwrap(),
            "Bearer"
        );
    }

    #[tokio::test]
    async fn www_authenticate_header_on_invalid() {
        let response = send(build_app(), req_with_auth("Basic dXNlcjpwYXNz")).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            response
                .headers()
                .get("www-authenticate")
                .unwrap()
                .to_str()
                .unwrap(),
            "Bearer"
        );
    }

    #[tokio::test]
    async fn optional_present() {
        async fn handler(token: Option<BearerToken>) -> impl axum::response::IntoResponse {
            match token {
                Some(BearerToken(t)) => (StatusCode::OK, t),
                None => (StatusCode::OK, "none".to_owned()),
            }
        }
        let app = Router::new().route("/", get(handler));
        let response = send(app, req_with_auth("Bearer abc123")).await;
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn optional_absent_passes_through() {
        async fn handler(token: Option<BearerToken>) -> StatusCode {
            if token.is_some() {
                StatusCode::OK
            } else {
                StatusCode::NO_CONTENT
            }
        }
        let app = Router::new().route("/", get(handler));
        let response = send(app, req_bare()).await;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn token_is_jwt_shaped() {
        let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.\
                   eyJzdWIiOiIxMjM0NTY3ODkwIn0.\
                   dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";
        let response = send(build_app(), req_with_auth(&format!("Bearer {jwt}"))).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get("x-token").unwrap().to_str().unwrap(),
            jwt
        );
    }
}
