//! Axum extractors for the values [`RequestIdLayer`](crate::RequestIdLayer)
//! stores in the request extensions.

use std::convert::Infallible;
use std::future::{Future, ready};

use axum::extract::{FromRequestParts, OptionalFromRequestParts};
use http::StatusCode;
use http::request::Parts;

use crate::{RequestId, TraceContext};

/// Rejection when the layer is not installed: `500` with a short message,
/// since this is a server misconfiguration rather than a client error.
type MissingLayer = (StatusCode, &'static str);

const MISSING: MissingLayer = (
    StatusCode::INTERNAL_SERVER_ERROR,
    "RequestIdLayer is not installed",
);

impl<S: Send + Sync> FromRequestParts<S> for RequestId {
    type Rejection = MissingLayer;

    fn from_request_parts(
        parts: &mut Parts,
        _state: &S,
    ) -> impl Future<Output = Result<Self, Self::Rejection>> + Send {
        ready(parts.extensions.get::<Self>().cloned().ok_or(MISSING))
    }
}

impl<S: Send + Sync> OptionalFromRequestParts<S> for RequestId {
    type Rejection = Infallible;

    fn from_request_parts(
        parts: &mut Parts,
        _state: &S,
    ) -> impl Future<Output = Result<Option<Self>, Self::Rejection>> + Send {
        ready(Ok(parts.extensions.get::<Self>().cloned()))
    }
}

impl<S: Send + Sync> FromRequestParts<S> for TraceContext {
    type Rejection = MissingLayer;

    fn from_request_parts(
        parts: &mut Parts,
        _state: &S,
    ) -> impl Future<Output = Result<Self, Self::Rejection>> + Send {
        ready(parts.extensions.get::<Self>().copied().ok_or(MISSING))
    }
}

impl<S: Send + Sync> OptionalFromRequestParts<S> for TraceContext {
    type Rejection = Infallible;

    fn from_request_parts(
        parts: &mut Parts,
        _state: &S,
    ) -> impl Future<Output = Result<Option<Self>, Self::Rejection>> + Send {
        ready(Ok(parts.extensions.get::<Self>().copied()))
    }
}
