//! The Tower layer and service.

use std::{
    borrow::Cow,
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{self, Poll},
};

use axum::body::{Body, Bytes, HttpBody};
use http::{
    HeaderMap, HeaderValue, Request, Response, StatusCode, Uri,
    header::{CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_TYPE, TRANSFER_ENCODING},
    uri::PathAndQuery,
};
use http_body_util::{BodyExt, LengthLimitError, Limited};
use tower_layer::Layer;
use tower_service::Service;

use crate::{
    SanitizeConfig,
    config::{FieldAction, FieldRule, OtherBodies},
    json, urlencoded,
};

/// Tower [`Layer`] that cleans query parameters and request bodies before
/// they reach a handler.
///
/// See [`SanitizeConfig`] for what is cleaned and how. Requests the
/// middleware can't vouch for are answered directly: `413` when a body to be
/// cleaned exceeds the size cap, `400` for malformed JSON, too-deep JSON or
/// non-UTF-8 text, `415` for other bodies under [`OtherBodies::Reject`].
///
/// # Examples
///
/// ```rust
/// use axum::{routing::post, Json, Router};
/// use rune_axum_sanitize::{SanitizeConfig, SanitizeLayer};
///
/// async fn create(Json(body): Json<serde_json::Value>) -> Json<serde_json::Value> {
///     Json(body)
/// }
///
/// let app: Router = Router::new()
///     .route("/posts", post(create))
///     .layer(SanitizeLayer::new(SanitizeConfig::new().exempt_field("/posts", "/markdown")));
/// ```
#[derive(Clone, Debug, Default)]
pub struct SanitizeLayer {
    config: Arc<SanitizeConfig>,
}

impl SanitizeLayer {
    /// Creates a layer with the given configuration.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rune_axum_sanitize::{SanitizeConfig, SanitizeLayer};
    ///
    /// let layer = SanitizeLayer::new(SanitizeConfig::new().max_body_bytes(65_536));
    /// ```
    #[must_use]
    pub fn new(config: SanitizeConfig) -> Self {
        Self {
            config: Arc::new(config),
        }
    }
}

impl<S> Layer<S> for SanitizeLayer {
    type Service = SanitizeService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        SanitizeService {
            inner,
            config: Arc::clone(&self.config),
        }
    }
}

/// Tower [`Service`] produced by [`SanitizeLayer`].
///
/// # Examples
///
/// ```rust
/// use axum::{body::Body, response::Response};
/// use http::Request;
/// use rune_axum_sanitize::SanitizeLayer;
/// use tower::{Layer, service_fn};
///
/// let service = SanitizeLayer::default().layer(service_fn(|_: Request<Body>| async {
///     Ok::<_, std::convert::Infallible>(Response::new(Body::empty()))
/// }));
/// ```
#[derive(Clone, Debug)]
pub struct SanitizeService<S> {
    inner: S,
    config: Arc<SanitizeConfig>,
}

impl<S> Service<Request<Body>> for SanitizeService<S>
where
    S: Service<Request<Body>, Response = Response<Body>> + Clone + Send + 'static,
    S::Future: Send + 'static,
    S::Error: Send + 'static,
{
    type Response = Response<Body>;
    type Error = S::Error;
    type Future = SanitizeFuture<S::Error>;

    fn poll_ready(&mut self, cx: &mut task::Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, request: Request<Body>) -> Self::Future {
        // Use the instance that was polled ready, leave a fresh clone behind.
        let clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, clone);
        let config = Arc::clone(&self.config);

        SanitizeFuture {
            future: Box::pin(async move {
                match sanitize_request(&config, request).await {
                    Ok(request) => inner.call(request).await,
                    Err(rejection) => Ok(rejection.into_response()),
                }
            }),
        }
    }
}

/// Future returned by [`SanitizeService`].
pub struct SanitizeFuture<E> {
    future: Pin<Box<dyn Future<Output = Result<Response<Body>, E>> + Send>>,
}

impl<E> Future for SanitizeFuture<E> {
    type Output = Result<Response<Body>, E>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<Self::Output> {
        self.future.as_mut().poll(cx)
    }
}

impl<E> std::fmt::Debug for SanitizeFuture<E> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SanitizeFuture")
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum BodyKind {
    Json,
    Form,
    Text,
    Other,
}

/// Classifies the body the way axum's extractors do: `Json` wants
/// `application/json` or `application/*+json`, `Form` takes any
/// Content-Type that starts with `application/x-www-form-urlencoded`.
/// Anything a handler's extractor would parse must land in a cleaned kind,
/// so the checks here are at least as loose as axum's.
fn body_kind(headers: &HeaderMap) -> BodyKind {
    let Some(content_type) = headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
    else {
        return BodyKind::Other;
    };
    // axum's `Form` and `RawForm` only check this prefix, so
    // `application/x-www-form-urlencodedx` or `..., text/plain` still parse.
    if content_type.starts_with("application/x-www-form-urlencoded") {
        return BodyKind::Form;
    }
    let essence = content_type
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    match essence.split_once('/') {
        Some(("application", "json")) => BodyKind::Json,
        Some(("application", subtype)) if subtype.ends_with("+json") => BodyKind::Json,
        Some(("application", "x-www-form-urlencoded")) => BodyKind::Form,
        Some(("text", _)) => BodyKind::Text,
        _ => BodyKind::Other,
    }
}

/// A request the middleware answers itself instead of forwarding.
struct Rejection {
    status: StatusCode,
    message: &'static str,
}

impl Rejection {
    fn into_response(self) -> Response<Body> {
        let mut response = Response::new(Body::from(self.message));
        *response.status_mut() = self.status;
        response.headers_mut().insert(
            CONTENT_TYPE,
            HeaderValue::from_static("text/plain; charset=utf-8"),
        );
        response
    }
}

const fn reject(status: StatusCode, message: &'static str) -> Rejection {
    Rejection { status, message }
}

fn clean_field<'s>(
    config: &SanitizeConfig,
    rules: &[&FieldRule],
    path: &[String],
    is_key: bool,
    text: &'s str,
) -> Cow<'s, str> {
    match rules
        .iter()
        .find(|rule| rule.field.matches(path))
        .map(|rule| &rule.action)
    {
        Some(FieldAction::Skip) => Cow::Borrowed(text),
        Some(FieldAction::Mode(mode)) if !is_key => config.sanitizer.clean_with(text, mode),
        _ => config.sanitizer.clean(text),
    }
}

async fn sanitize_request(
    config: &SanitizeConfig,
    request: Request<Body>,
) -> Result<Request<Body>, Rejection> {
    let path = request.uri().path().to_owned();
    if config.is_exempt(&path) {
        return Ok(request);
    }
    let rules: Vec<&FieldRule> = config
        .field_rules
        .iter()
        .filter(|rule| rule.route.matches(&path))
        .collect();
    let (mut parts, body) = request.into_parts();

    if config.query
        && let Some(query) = parts.uri.query()
        && let Cow::Owned(cleaned) = urlencoded::clean(query, |field, is_key, text| {
            clean_field(config, &rules, field, is_key, text)
        })
    {
        parts.uri = with_query(&parts.uri, &cleaned)
            .ok_or_else(|| reject(StatusCode::BAD_REQUEST, "invalid query string"))?;
    }

    let kind = body_kind(&parts.headers);
    let enabled = match kind {
        BodyKind::Json => config.json,
        BodyKind::Form => config.form,
        BodyKind::Text => config.text,
        BodyKind::Other => false,
    };
    if !enabled {
        if kind == BodyKind::Other
            && config.other_bodies == OtherBodies::Reject
            && body.size_hint().exact() != Some(0)
        {
            return Err(reject(
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                "unsupported request body type",
            ));
        }
        return Ok(Request::from_parts(parts, body));
    }
    // Compressed bytes can't be inspected, and a decompression layer further
    // in would hand the handler content nobody looked at.
    if parts
        .headers
        .get_all(CONTENT_ENCODING)
        .iter()
        .any(|value| !is_identity(value))
    {
        return Err(reject(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "compressed request bodies must be decompressed before SanitizeLayer",
        ));
    }

    let bytes = read_body(&parts.headers, body, config.max_body_bytes).await?;
    let Ok(text) = std::str::from_utf8(&bytes) else {
        return Err(reject(
            StatusCode::BAD_REQUEST,
            "request body is not valid UTF-8",
        ));
    };
    let cleaned = match kind {
        BodyKind::Json => json::clean(text, config.max_json_depth, |field, is_key, value| {
            clean_field(config, &rules, field, is_key, value)
        })
        .map_err(|error| match error {
            json::JsonError::DuplicateKey { .. } => reject(
                StatusCode::BAD_REQUEST,
                "JSON object keys collide once cleaned",
            ),
            _ => reject(StatusCode::BAD_REQUEST, "invalid JSON body"),
        })?,
        BodyKind::Form => urlencoded::clean(text, |field, is_key, value| {
            clean_field(config, &rules, field, is_key, value)
        }),
        BodyKind::Text | BodyKind::Other => clean_field(config, &rules, &[], false, text),
    };

    let body = match cleaned {
        Cow::Borrowed(_) => Body::from(bytes),
        Cow::Owned(cleaned) => {
            parts.headers.remove(TRANSFER_ENCODING);
            parts
                .headers
                .insert(CONTENT_LENGTH, HeaderValue::from(cleaned.len()));
            Body::from(cleaned)
        }
    };
    Ok(Request::from_parts(parts, body))
}

fn is_identity(value: &HeaderValue) -> bool {
    value.to_str().is_ok_and(|value| {
        value
            .split(',')
            .all(|coding| coding.trim().eq_ignore_ascii_case("identity"))
    })
}

async fn read_body(headers: &HeaderMap, body: Body, limit: usize) -> Result<Bytes, Rejection> {
    let too_large = || reject(StatusCode::PAYLOAD_TOO_LARGE, "request body too large");
    let declared = headers
        .get(CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok());
    if declared.is_some_and(|length| length > limit as u64) {
        return Err(too_large());
    }
    match Limited::new(body, limit).collect().await {
        Ok(collected) => Ok(collected.to_bytes()),
        Err(error) if error.downcast_ref::<LengthLimitError>().is_some() => Err(too_large()),
        Err(_) => Err(reject(
            StatusCode::BAD_REQUEST,
            "failed to read request body",
        )),
    }
}

fn with_query(uri: &Uri, query: &str) -> Option<Uri> {
    let mut parts = uri.clone().into_parts();
    let path_and_query = if query.is_empty() {
        uri.path().to_owned()
    } else {
        format!("{}?{query}", uri.path())
    };
    parts.path_and_query = Some(PathAndQuery::try_from(path_and_query).ok()?);
    Uri::from_parts(parts).ok()
}
