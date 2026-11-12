//! Rejections and their RFC 6750 responses.

use axum::response::{IntoResponse, Response};
use http::{HeaderValue, StatusCode, header};

/// Why a request was not let through.
///
/// The variants are detailed so they can be logged. The HTTP response never
/// carries that detail: it is one of
///
/// | Case | Status | `WWW-Authenticate` |
/// |------|--------|--------------------|
/// | no bearer token | 401 | `Bearer` |
/// | malformed `Authorization` header | 400 | `Bearer error="invalid_request"` |
/// | any token problem | 401 | `Bearer error="invalid_token"` |
/// | missing scope or role | 403 | `Bearer error="insufficient_scope"` (plus `scope="..."` for scopes) |
/// | keys could not be loaded | 503 | none |
///
/// with an empty body, per [RFC 6750 §3](https://www.rfc-editor.org/rfc/rfc6750#section-3).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum JwtRejection {
    /// No `Authorization: Bearer` credentials.
    #[error("no bearer token")]
    Missing,
    /// The `Authorization` header is repeated, not ASCII, or `Bearer` is
    /// followed by something that is not a token.
    #[error("malformed Authorization header")]
    MalformedHeader,
    /// The token is longer than the configured maximum.
    #[error("token longer than {max} bytes")]
    TooLong {
        /// The configured maximum.
        max: usize,
    },
    /// The token is not a well-formed JWS compact serialization.
    #[error("malformed token: {0}")]
    Malformed(String),
    /// `alg` is missing, `none`, or not supported.
    #[error("unsupported algorithm {0:?}")]
    UnsupportedAlgorithm(String),
    /// The header carries a `crit` parameter; no extensions are understood.
    #[error("token has critical header parameters")]
    CriticalHeader,
    /// The header `alg` differs from the algorithm pinned on the key.
    #[error("token alg {token} does not match the key's {key}")]
    AlgorithmMismatch {
        /// `alg` from the token header.
        token: String,
        /// The key's pinned algorithm.
        key: String,
    },
    /// No `kid` in the token but several keys are configured.
    #[error("token has no kid but several keys are configured")]
    KidRequired,
    /// No key matches the token's `kid`.
    #[error("unknown kid")]
    UnknownKid,
    /// The signature does not verify.
    #[error("invalid signature")]
    InvalidSignature,
    /// `exp` is in the past (beyond the leeway).
    #[error("token expired")]
    Expired,
    /// `nbf` is in the future (beyond the leeway).
    #[error("token not yet valid")]
    NotYetValid,
    /// `iat` is in the future (beyond the leeway), or older than the
    /// configured maximum age.
    #[error("bad iat: {0}")]
    BadIssuedAt(&'static str),
    /// `iss` does not match.
    #[error("wrong issuer")]
    InvalidIssuer,
    /// `aud` does not contain an accepted audience.
    #[error("wrong audience")]
    InvalidAudience,
    /// A required claim is missing.
    #[error("missing claim {0:?}")]
    MissingClaim(String),
    /// The claims are not a JSON object, a registered claim has the wrong
    /// type, or they do not deserialize into the handler's claims type.
    #[error("invalid claims: {0}")]
    InvalidClaims(String),
    /// The token lacks a scope the route requires.
    #[error("missing scope; route requires {required:?}")]
    InsufficientScope {
        /// Every scope the route requires.
        required: Vec<String>,
    },
    /// The token lacks a role the route requires.
    #[error("missing role")]
    InsufficientRole,
    /// The key source could not provide keys.
    #[error("keys unavailable: {0}")]
    KeysUnavailable(String),
}

impl JwtRejection {
    /// The HTTP status this rejection maps to.
    #[must_use]
    pub const fn status(&self) -> StatusCode {
        match self {
            Self::MalformedHeader => StatusCode::BAD_REQUEST,
            Self::InsufficientScope { .. } | Self::InsufficientRole => StatusCode::FORBIDDEN,
            Self::KeysUnavailable(_) => StatusCode::SERVICE_UNAVAILABLE,
            _ => StatusCode::UNAUTHORIZED,
        }
    }

    fn challenge(&self) -> Option<String> {
        Some(match self {
            Self::Missing => "Bearer".to_owned(),
            Self::MalformedHeader => r#"Bearer error="invalid_request""#.to_owned(),
            Self::KeysUnavailable(_) => return None,
            Self::InsufficientScope { required } => {
                // Scope tokens are NQCHAR (RFC 6749 §3.3), so this cannot break
                // out of the quoted string; drop anything that would anyway.
                let scope: String = required
                    .join(" ")
                    .chars()
                    .filter(|c| *c != '"' && *c != '\\' && (' '..='~').contains(c))
                    .collect();
                format!(r#"Bearer error="insufficient_scope", scope="{scope}""#)
            }
            Self::InsufficientRole => r#"Bearer error="insufficient_scope""#.to_owned(),
            _ => r#"Bearer error="invalid_token""#.to_owned(),
        })
    }
}

impl IntoResponse for JwtRejection {
    fn into_response(self) -> Response {
        let mut response = self.status().into_response();
        if let Some(value) = self
            .challenge()
            .and_then(|c| HeaderValue::from_str(&c).ok())
        {
            response
                .headers_mut()
                .insert(header::WWW_AUTHENTICATE, value);
        }
        response
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn www(r: JwtRejection) -> (StatusCode, Option<String>) {
        let resp = r.into_response();
        (
            resp.status(),
            resp.headers()
                .get(header::WWW_AUTHENTICATE)
                .map(|v| v.to_str().unwrap().to_owned()),
        )
    }

    #[test]
    fn responses_follow_rfc6750() {
        assert_eq!(
            www(JwtRejection::Missing),
            (StatusCode::UNAUTHORIZED, Some("Bearer".into()))
        );
        assert_eq!(
            www(JwtRejection::Expired),
            (
                StatusCode::UNAUTHORIZED,
                Some(r#"Bearer error="invalid_token""#.into())
            )
        );
        assert_eq!(
            www(JwtRejection::InsufficientScope {
                required: vec!["read".into(), "wr\"ite".into()]
            }),
            (
                StatusCode::FORBIDDEN,
                Some(r#"Bearer error="insufficient_scope", scope="read write""#.into())
            )
        );
        assert_eq!(
            www(JwtRejection::KeysUnavailable("x".into())),
            (StatusCode::SERVICE_UNAVAILABLE, None)
        );
    }
}
