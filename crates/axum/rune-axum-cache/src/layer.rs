use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use http::header::{
    CACHE_CONTROL, CONTENT_LOCATION, DATE, ETAG, EXPIRES, IF_MATCH, IF_MODIFIED_SINCE,
    IF_NONE_MATCH, IF_UNMODIFIED_SINCE, LAST_MODIFIED, VARY,
};
use http::{HeaderMap, HeaderValue, Method, Request, Response, StatusCode};
use tower::{Layer, Service};

use crate::{CacheControl, Precondition, Validators, evaluate};

/// Headers a `304` keeps from the `200` it replaces (RFC 9110 §15.4.5).
const NOT_MODIFIED_KEEP: [http::HeaderName; 6] =
    [CACHE_CONTROL, CONTENT_LOCATION, DATE, ETAG, EXPIRES, VARY];

/// The request headers conditional evaluation looks at.
const CONDITIONAL: [http::HeaderName; 4] = [
    IF_MATCH,
    IF_NONE_MATCH,
    IF_MODIFIED_SINCE,
    IF_UNMODIFIED_SINCE,
];

/// A `Cache-Control` value with its pre-rendered header.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Rule {
    directives: CacheControl,
    value: HeaderValue,
}

impl Rule {
    fn new(directives: CacheControl) -> Option<Self> {
        (!directives.is_empty()).then(|| Self {
            value: directives.to_header_value(),
            directives,
        })
    }
}

/// A `Cache-Control` override for every path under `prefix`.
#[derive(Clone, Debug, PartialEq, Eq)]
struct PathOverride {
    /// Normalised prefix: starts with `/`, no trailing `/` unless it is `/`.
    prefix: String,
    rule: Option<Rule>,
}

/// Configuration for the caching middleware.
///
/// Build with [`Cache::new()`] and chain methods to set the default
/// `Cache-Control` directives, per-path overrides and conditional-request
/// handling, then pass it to [`CacheLayer::new()`].
///
/// # Examples
///
/// ```rust
/// use std::time::Duration;
/// use rune_axum_cache::{Cache, CacheControl};
///
/// let config = Cache::new()
///     .cache_control(CacheControl::new().public().max_age(Duration::from_secs(60)))
///     .path("/assets", CacheControl::immutable_asset(Duration::from_secs(31_536_000)))
///     .path("/account", CacheControl::sensitive())
///     .skip_path("/legacy");
///
/// let cc = |p| config.cache_control_for(p).map(ToString::to_string);
/// assert_eq!(cc("/").as_deref(), Some("public, max-age=60"));
/// assert_eq!(cc("/account/keys").as_deref(), Some("no-store"));
/// assert_eq!(cc("/legacy/page"), None);
/// ```
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct Cache {
    default: Option<Rule>,
    /// Shared so that per-request service clones stay cheap.
    overrides: Arc<Vec<PathOverride>>,
    override_existing: bool,
    conditional: bool,
}

impl Default for Cache {
    fn default() -> Self {
        Self {
            default: Rule::new(CacheControl::revalidate()),
            overrides: Arc::new(Vec::new()),
            override_existing: false,
            conditional: true,
        }
    }
}

impl Cache {
    /// Creates a `Cache` with defaults: `Cache-Control: private, no-cache`
    /// where the handler set none, handler headers kept, and conditional
    /// requests answered with `304` / `412`.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the directives for requests that match no path override.
    /// An empty [`CacheControl`] sets no header, like
    /// [`no_cache_control`](Self::no_cache_control).
    #[must_use]
    pub fn cache_control(mut self, directives: CacheControl) -> Self {
        self.default = Rule::new(directives);
        self
    }

    /// Sets no `Cache-Control` header for requests that match no path
    /// override.
    #[must_use]
    pub fn no_cache_control(mut self) -> Self {
        self.default = None;
        self
    }

    /// Uses `directives` for every request whose path is `prefix` or lies
    /// below it.
    ///
    /// Matching is on `/` segment boundaries: `/api` matches `/api` and
    /// `/api/users` but not `/apis`. A missing leading `/` is added and a
    /// trailing `/` is ignored. The longest matching prefix wins; setting
    /// the same prefix twice keeps the last value.
    #[must_use]
    pub fn path(self, prefix: impl AsRef<str>, directives: CacheControl) -> Self {
        self.set_path(prefix.as_ref(), Rule::new(directives))
    }

    /// Sets no `Cache-Control` header under `prefix` (matched as for
    /// [`path`](Self::path)).
    #[must_use]
    pub fn skip_path(self, prefix: impl AsRef<str>) -> Self {
        self.set_path(prefix.as_ref(), None)
    }

    fn set_path(mut self, prefix: &str, rule: Option<Rule>) -> Self {
        let prefix = normalize_prefix(prefix);
        let overrides = Arc::make_mut(&mut self.overrides);
        if let Some(existing) = overrides.iter_mut().find(|o| o.prefix == prefix) {
            existing.rule = rule;
        } else {
            overrides.push(PathOverride { prefix, rule });
        }
        self
    }

    /// Whether the configured directives replace a `Cache-Control` header
    /// the handler already set. Defaults to `false`: the handler knows
    /// best.
    #[must_use]
    pub const fn override_existing(mut self, enabled: bool) -> Self {
        self.override_existing = enabled;
        self
    }

    /// Whether to answer conditional `GET`/`HEAD` requests from the
    /// response's `ETag` / `Last-Modified`. Defaults to `true`.
    #[must_use]
    pub const fn conditional(mut self, enabled: bool) -> Self {
        self.conditional = enabled;
        self
    }

    /// Returns the directives that apply to a request for `path`, or `None`
    /// when no header is set there.
    #[must_use]
    pub fn cache_control_for(&self, path: &str) -> Option<&CacheControl> {
        self.rule_for(path).map(|r| &r.directives)
    }

    fn rule_for(&self, path: &str) -> Option<&Rule> {
        self.overrides
            .iter()
            .filter(|o| prefix_matches(&o.prefix, path))
            .max_by_key(|o| o.prefix.len())
            .map_or(self.default.as_ref(), |o| o.rule.as_ref())
    }
}

fn normalize_prefix(raw: &str) -> String {
    let trimmed = raw.trim_end_matches('/');
    let trimmed = trimmed.strip_prefix('/').unwrap_or(trimmed);
    format!("/{trimmed}")
}

fn prefix_matches(prefix: &str, path: &str) -> bool {
    if prefix == "/" {
        return true;
    }
    path.strip_prefix(prefix)
        .is_some_and(|rest| rest.is_empty() || rest.starts_with('/'))
}

/// Tower [`Layer`] that sets `Cache-Control` on successful `GET`/`HEAD`
/// responses and answers conditional requests.
///
/// After the inner service responds `200 OK` to a `GET` or `HEAD`, the
/// layer reads the response's `ETag` and `Last-Modified` and evaluates the
/// request's `If-Match`, `If-Unmodified-Since`, `If-None-Match` and
/// `If-Modified-Since`. A current cached copy turns the response into an
/// empty-bodied `304 Not Modified`; a failed precondition into `412`.
///
/// The handler still runs to produce its validators. To skip that work, or
/// to guard state-changing methods (which this layer never touches), call
/// [`Validators::evaluate`] in the handler before doing anything.
///
/// # Examples
///
/// ```rust
/// use axum::{routing::get, Router};
/// use rune_axum_cache::CacheLayer;
///
/// let app: Router = Router::new()
///     .route("/", get(|| async { "ok" }))
///     .layer(CacheLayer::default());
/// ```
#[derive(Clone, Debug, Default)]
pub struct CacheLayer {
    config: Cache,
}

impl CacheLayer {
    /// Creates a `CacheLayer` from a custom [`Cache`] configuration.
    #[must_use]
    pub const fn new(config: Cache) -> Self {
        Self { config }
    }
}

impl<S> Layer<S> for CacheLayer {
    type Service = CacheService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        CacheService {
            inner,
            config: self.config.clone(),
        }
    }
}

/// Tower [`Service`] produced by [`CacheLayer`].
#[derive(Clone, Debug)]
pub struct CacheService<S> {
    inner: S,
    config: Cache,
}

impl<S, ReqBody, ResBody> Service<Request<ReqBody>> for CacheService<S>
where
    S: Service<Request<ReqBody>, Response = Response<ResBody>>,
    S::Future: Send + 'static,
    S::Error: Send + 'static,
    ResBody: Default + Send + 'static,
{
    type Response = Response<ResBody>;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<ReqBody>) -> Self::Future {
        let method = req.method().clone();
        let cacheable = method == Method::GET || method == Method::HEAD;
        let rule = cacheable
            .then(|| {
                self.config
                    .rule_for(req.uri().path())
                    .map(|r| r.value.clone())
            })
            .flatten();
        let conditions =
            (cacheable && self.config.conditional).then(|| conditions_of(req.headers()));
        let override_existing = self.config.override_existing;
        let fut = self.inner.call(req);
        Box::pin(async move {
            let mut response = fut.await?;
            let status = response.status();
            if let Some(value) = rule
                && (status.is_success() || status == StatusCode::NOT_MODIFIED)
            {
                let headers = response.headers_mut();
                if override_existing || !headers.contains_key(CACHE_CONTROL) {
                    headers.insert(CACHE_CONTROL, value);
                }
            }
            match conditions {
                Some(conditions) if status == StatusCode::OK && !conditions.is_empty() => {
                    let current = Validators::from_headers(response.headers());
                    Ok(match evaluate(&method, &conditions, Some(&current)) {
                        Precondition::NotModified => not_modified(response),
                        Precondition::Failed => precondition_failed(&response),
                        _ => response,
                    })
                }
                _ => Ok(response),
            }
        })
    }
}

/// Copies just the conditional request headers, so the request itself can
/// move into the inner service.
fn conditions_of(headers: &HeaderMap) -> HeaderMap {
    let mut out = HeaderMap::new();
    for name in CONDITIONAL {
        for value in headers.get_all(&name) {
            out.append(name.clone(), value.clone());
        }
    }
    out
}

fn not_modified<B: Default>(original: Response<B>) -> Response<B> {
    let (parts, _body) = original.into_parts();
    let mut response = Response::new(B::default());
    *response.status_mut() = StatusCode::NOT_MODIFIED;
    *response.version_mut() = parts.version;
    let keep_last_modified = !parts.headers.contains_key(ETAG);
    let headers = response.headers_mut();
    for name in NOT_MODIFIED_KEEP
        .into_iter()
        .chain(keep_last_modified.then_some(LAST_MODIFIED))
    {
        for value in parts.headers.get_all(&name) {
            headers.append(name.clone(), value.clone());
        }
    }
    response
}

fn precondition_failed<B: Default>(original: &Response<B>) -> Response<B> {
    let mut response = Response::new(B::default());
    *response.status_mut() = StatusCode::PRECONDITION_FAILED;
    *response.version_mut() = original.version();
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn secs(n: u64) -> Duration {
        Duration::from_secs(n)
    }

    #[test]
    fn defaults() {
        let c = Cache::default();
        assert_eq!(c.cache_control_for("/x"), Some(&CacheControl::revalidate()));
        assert!(c.conditional);
        assert!(!c.override_existing);
    }

    #[test]
    fn longest_prefix_wins_and_skip_path() {
        let c = Cache::new()
            .path("/api", CacheControl::sensitive())
            .path(
                "/api/public/",
                CacheControl::new().public().max_age(secs(5)),
            )
            .skip_path("api/raw");
        assert_eq!(
            c.cache_control_for("/api/x"),
            Some(&CacheControl::sensitive())
        );
        assert_eq!(
            c.cache_control_for("/api/public/x")
                .map(ToString::to_string)
                .as_deref(),
            Some("public, max-age=5")
        );
        assert_eq!(c.cache_control_for("/api/raw/x"), None);
        assert_eq!(
            c.cache_control_for("/apis"),
            Some(&CacheControl::revalidate())
        );
    }

    #[test]
    fn empty_directives_mean_no_header() {
        let c = Cache::new().cache_control(CacheControl::new());
        assert_eq!(c.cache_control_for("/"), None);
        let c = Cache::new()
            .no_cache_control()
            .path("/a", CacheControl::sensitive());
        assert_eq!(c.cache_control_for("/"), None);
        assert!(c.cache_control_for("/a").is_some());
    }

    #[test]
    fn repeated_prefix_keeps_last() {
        let c = Cache::new()
            .path("/a", CacheControl::sensitive())
            .path("/a/", CacheControl::revalidate());
        assert_eq!(c.overrides.len(), 1);
        assert_eq!(c.cache_control_for("/a"), Some(&CacheControl::revalidate()));
    }

    #[test]
    fn builder_does_not_mutate_clones() {
        let base = Cache::new().path("/a", CacheControl::sensitive());
        let derived = base.clone().path("/b", CacheControl::sensitive());
        assert_eq!(
            base.cache_control_for("/b"),
            Some(&CacheControl::revalidate())
        );
        assert_eq!(
            derived.cache_control_for("/b"),
            Some(&CacheControl::sensitive())
        );
    }

    #[test]
    fn not_modified_keeps_only_cache_metadata() {
        let response = Response::builder()
            .header(ETAG, "\"x\"")
            .header(LAST_MODIFIED, "Sun, 06 Nov 1994 08:49:37 GMT")
            .header(VARY, "accept")
            .header(VARY, "origin")
            .header("content-type", "text/plain")
            .body(String::from("body"))
            .unwrap();
        let res = not_modified(response);
        assert_eq!(res.status(), StatusCode::NOT_MODIFIED);
        assert_eq!(res.body(), "");
        assert_eq!(res.headers().get_all(VARY).iter().count(), 2);
        assert!(res.headers().contains_key(ETAG));
        assert!(!res.headers().contains_key(LAST_MODIFIED));
        assert!(!res.headers().contains_key("content-type"));

        let only_date = Response::builder()
            .header(LAST_MODIFIED, "Sun, 06 Nov 1994 08:49:37 GMT")
            .body(String::new())
            .unwrap();
        assert!(
            not_modified(only_date)
                .headers()
                .contains_key(LAST_MODIFIED)
        );
    }
}
