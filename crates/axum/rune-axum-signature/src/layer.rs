//! Tower layer, service and the `VerifiedWebhook` extractor.

use crate::{VerifiedWebhook, VerifyError, WebhookVerifier};
use axum::body::Body;
use axum::extract::FromRequestParts;
use axum::response::{IntoResponse, Response};
use http::request::Parts;
use http::{Request, StatusCode, header};
use http_body_util::{BodyExt, LengthLimitError, Limited};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tower_layer::Layer;
use tower_service::Service;

/// Tower layer that verifies every request with a [`WebhookVerifier`].
///
/// It reads the body (up to the verifier's limit, else `413`), checks the
/// signature, timestamp and replay store, and only then calls the inner
/// service. The handler gets the same body back, plus a [`VerifiedWebhook`]
/// in the request extensions. Rejections are empty responses with the
/// status from [`VerifyError::status`].
///
/// # Examples
///
/// ```rust
/// use axum::{routing::post, Router};
/// use rune_axum_signature::{VerifiedWebhook, WebhookLayer, WebhookVerifier};
///
/// async fn github(hook: VerifiedWebhook) -> &'static str {
///     // serde_json::from_slice(hook.body()) etc.
///     "ok"
/// }
///
/// let app: Router = Router::new()
///     .route("/webhooks/github", post(github))
///     .layer(WebhookLayer::new(WebhookVerifier::github("my-secret")));
/// ```
#[derive(Clone, Debug)]
pub struct WebhookLayer {
    verifier: Arc<WebhookVerifier>,
}

/// The 0.2 name of [`WebhookLayer`]. `HmacLayer::new(HmacConfig::sha256(..))`
/// still works.
pub type HmacLayer = WebhookLayer;

/// The 0.2 name of [`WebhookService`].
pub type HmacService<S> = WebhookService<S>;

impl WebhookLayer {
    /// Creates the layer. Accepts a [`WebhookVerifier`] or an
    /// [`HmacConfig`](crate::HmacConfig).
    #[must_use]
    pub fn new(verifier: impl Into<WebhookVerifier>) -> Self {
        Self {
            verifier: Arc::new(verifier.into()),
        }
    }

    /// The verifier this layer uses.
    #[must_use]
    pub fn verifier(&self) -> &WebhookVerifier {
        &self.verifier
    }
}

impl<S> Layer<S> for WebhookLayer {
    type Service = WebhookService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        WebhookService {
            inner,
            verifier: Arc::clone(&self.verifier),
        }
    }
}

/// Service produced by [`WebhookLayer`].
#[derive(Clone, Debug)]
pub struct WebhookService<S> {
    inner: S,
    verifier: Arc<WebhookVerifier>,
}

impl<S> Service<Request<Body>> for WebhookService<S>
where
    S: Service<Request<Body>, Response = Response> + Clone + Send + 'static,
    S::Future: Send + 'static,
    S::Error: Send + 'static,
{
    type Response = Response;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<Body>) -> Self::Future {
        // Use the clone that was driven to ready, leave a fresh one behind.
        let clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, clone);
        let verifier = Arc::clone(&self.verifier);

        Box::pin(async move {
            let (mut parts, body) = req.into_parts();
            let webhook = match verify_request(&verifier, &parts, body).await {
                Ok(webhook) => webhook,
                Err(err) => return Ok(reject(&err)),
            };
            let body = Body::from(webhook.body().clone());
            parts.extensions.insert(webhook);
            inner.call(Request::from_parts(parts, body)).await
        })
    }
}

async fn verify_request(
    verifier: &WebhookVerifier,
    parts: &Parts,
    body: Body,
) -> Result<VerifiedWebhook, VerifyError> {
    let limit = verifier.body_limit();
    let too_large = VerifyError::BodyTooLarge { limit };
    let declared = parts
        .headers
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok());
    if declared.is_some_and(|len| len > u64::try_from(limit).unwrap_or(u64::MAX)) {
        return Err(too_large);
    }
    let bytes = match Limited::new(body, limit).collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(e) if e.downcast_ref::<LengthLimitError>().is_some() => return Err(too_large),
        Err(_) => return Err(VerifyError::BodyRead),
    };
    verifier.verify_and_record(&parts.headers, bytes).await
}

fn reject(err: &VerifyError) -> Response {
    err.status().into_response()
}

/// Rejection when [`VerifiedWebhook`] is extracted on a route that is not
/// behind a [`WebhookLayer`]. Answers `500`, since that is a wiring mistake.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MissingWebhookLayer;

impl std::fmt::Display for MissingWebhookLayer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("VerifiedWebhook extracted without WebhookLayer on the route")
    }
}

impl std::error::Error for MissingWebhookLayer {}

impl IntoResponse for MissingWebhookLayer {
    fn into_response(self) -> Response {
        StatusCode::INTERNAL_SERVER_ERROR.into_response()
    }
}

impl<S: Send + Sync> FromRequestParts<S> for VerifiedWebhook {
    type Rejection = MissingWebhookLayer;

    fn from_request_parts(
        parts: &mut Parts,
        _state: &S,
    ) -> impl Future<Output = Result<Self, Self::Rejection>> + Send {
        std::future::ready(
            parts
                .extensions
                .get::<Self>()
                .cloned()
                .ok_or(MissingWebhookLayer),
        )
    }
}
