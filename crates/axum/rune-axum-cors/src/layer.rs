//! The Tower layer and service.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use http::{HeaderMap, HeaderName, HeaderValue, Method, Request, Response, StatusCode, header};
use rune_cors::Report;
use tower::{Layer, Service};

use crate::Error;
use crate::config::{Cors, HeaderList, REQUEST_PRIVATE_NETWORK};

/// `Vary` on preflight responses: everything the answer depends on.
const PREFLIGHT_VARY: &str = "Origin, Access-Control-Request-Method, \
     Access-Control-Request-Headers, Access-Control-Request-Private-Network";

/// CORS response headers the layer owns. Whatever an inner service sets is
/// dropped, so a handler or an error path can never grant access on its
/// own.
const OWNED: [HeaderName; 7] = [
    header::ACCESS_CONTROL_ALLOW_ORIGIN,
    header::ACCESS_CONTROL_ALLOW_CREDENTIALS,
    header::ACCESS_CONTROL_EXPOSE_HEADERS,
    header::ACCESS_CONTROL_ALLOW_METHODS,
    header::ACCESS_CONTROL_ALLOW_HEADERS,
    header::ACCESS_CONTROL_MAX_AGE,
    HeaderName::from_static("access-control-allow-private-network"),
];

/// A policy that passed its audit.
#[derive(Clone, Debug)]
struct Policy {
    cors: Cors,
    report: Report,
}

impl Policy {
    fn new(mut cors: Cors) -> Result<Self, Error> {
        if let Some(error) = cors.take_error() {
            return Err(error);
        }
        let report = cors.audit();
        let weaknesses = cors.fatal(&report);
        if !weaknesses.is_empty() {
            return Err(Error::Insecure { weaknesses });
        }
        Ok(Self { cors, report })
    }
}

/// The default policy, the per-route overrides (longest prefix first) and
/// the grant-nothing policy for paths whose override is ambiguous.
#[derive(Clone, Debug)]
struct Policies {
    default: Policy,
    routes: Vec<(String, Policy)>,
    deny: Cors,
}

impl Policies {
    /// The policy for a request path.
    ///
    /// Prefixes match the raw path on segment boundaries, as Axum routes
    /// it. When percent-decoding, `.`/`..` segments, doubled or back
    /// slashes would make a front proxy or another router see a different
    /// override, nothing is granted.
    fn select(&self, path: &str) -> &Cors {
        if self.routes.is_empty() {
            return &self.default.cors;
        }
        let raw = self.index(path);
        if raw != self.index(&normalize_path(path)) {
            return &self.deny;
        }
        raw.map_or(&self.default.cors, |i| &self.routes[i].1.cors)
    }

    fn index(&self, path: &str) -> Option<usize> {
        self.routes
            .iter()
            .position(|(prefix, _)| prefix_matches(prefix, path))
    }
}

/// Whether `prefix` covers `path` on a segment boundary: `/api` covers
/// `/api` and `/api/x`, not `/apix`.
fn prefix_matches(prefix: &str, path: &str) -> bool {
    prefix == "/"
        || path
            .strip_prefix(prefix)
            .is_some_and(|rest| rest.is_empty() || rest.starts_with('/'))
}

/// Percent-decodes `path`, turns `\` into `/`, drops empty and `.`
/// segments and resolves `..`.
fn normalize_path(path: &str) -> String {
    let bytes = path.as_bytes();
    let hex = |at: usize| {
        let digit = char::from(*bytes.get(at)?).to_digit(16)?;
        u8::try_from(digit).ok()
    };
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let byte = match bytes[i] {
            b'%' => match (hex(i + 1), hex(i + 2)) {
                (Some(high), Some(low)) => {
                    i += 2;
                    high * 16 + low
                }
                _ => b'%',
            },
            b'\\' => b'/',
            b => b,
        };
        decoded.push(byte);
        i += 1;
    }
    let decoded = String::from_utf8_lossy(&decoded);
    let mut segments: Vec<&str> = Vec::new();
    for segment in decoded.split(['/', '\\']) {
        match segment {
            "" | "." => {}
            ".." => {
                segments.pop();
            }
            s => segments.push(s),
        }
    }
    format!("/{}", segments.join("/"))
}

/// Checks and canonicalises a route prefix.
fn parse_prefix(prefix: &str) -> Result<String, Error> {
    let invalid = |reason| Error::InvalidInput {
        input: prefix.to_owned(),
        reason,
    };
    if !prefix.starts_with('/') {
        return Err(invalid("a route prefix starts with `/`"));
    }
    if !prefix.is_ascii() || prefix.contains(['%', '\\', '?', '#', '*', '{', '}', ':']) {
        return Err(invalid(
            "a route prefix is a literal path: no percent-escapes, `\\`, queries or parameters",
        ));
    }
    let trimmed = prefix.trim_end_matches('/');
    if trimmed.is_empty() {
        return Ok("/".to_owned());
    }
    if trimmed[1..]
        .split('/')
        .any(|s| s.is_empty() || s == "." || s == "..")
    {
        return Err(invalid("empty, `.` or `..` segment in route prefix"));
    }
    Ok(trimmed.to_owned())
}

/// Tower [`Layer`] that answers CORS preflights and adds CORS headers to
/// responses, according to a [`Cors`] policy that passed its audit.
///
/// The layer owns the CORS response headers: any `Access-Control-Allow-*`,
/// `-Expose-Headers` or `-Max-Age` header set by inner services (including
/// error responses from inner layers) is replaced, or removed when the
/// request origin is not allowed.
///
/// # Examples
///
/// ```rust
/// use axum::{routing::get, Router};
/// use rune_axum_cors::{Cors, CorsLayer};
///
/// let layer = CorsLayer::new(Cors::new().allow_origin("https://app.example.com"))?;
/// let app: Router = Router::new()
///     .route("/", get(|| async { "ok" }))
///     .layer(layer);
/// # Ok::<(), rune_axum_cors::Error>(())
/// ```
#[derive(Clone, Debug)]
pub struct CorsLayer {
    policies: Arc<Policies>,
}

impl CorsLayer {
    /// Audits `config` with [`rune_cors`] and builds the layer.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidOrigin`] or [`Error::InvalidInput`] when a builder
    /// input was malformed, and [`Error::Insecure`] when the audit finds
    /// weaknesses at or above [`Cors::reject_at`] (always for high and
    /// critical ones and for `*` with credentials).
    pub fn new(config: Cors) -> Result<Self, Error> {
        let default = Policy::new(config)?;
        let deny = default.cors.deny_all();
        Ok(Self {
            policies: Arc::new(Policies {
                default,
                routes: Vec::new(),
                deny,
            }),
        })
    }

    /// Uses `config` instead of the default policy for requests whose path
    /// is `prefix` or below it (`/public` covers `/public` and
    /// `/public/x`, not `/publicity`). The longest matching prefix wins.
    /// The override is audited on its own, like the default.
    ///
    /// Prefixes are compared with the raw request path, the way Axum routes
    /// it. A path that would pick a different override once
    /// percent-decoded or with `.`, `..`, `//` or `\` resolved (say
    /// `//admin` or `/public/../admin`) gets no CORS grant at all, so a
    /// proxy that normalises paths cannot be used to borrow a looser
    /// policy.
    ///
    /// Inside Axum you can also give a single route its own layer:
    /// `get(handler).layer(cors_layer)` covers preflights too, while
    /// `route_layer` does not (it skips the `OPTIONS` fallback).
    ///
    /// # Errors
    ///
    /// [`Error::InvalidInput`] when the prefix is not a literal absolute
    /// path or is already registered, and the errors of
    /// [`CorsLayer::new`] for `config`.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use axum::{routing::get, Router};
    /// use rune_axum_cors::{Cors, CorsLayer};
    ///
    /// let layer = CorsLayer::new(
    ///     Cors::new()
    ///         .allow_origin("https://app.example.com")
    ///         .allow_credentials(true),
    /// )?
    /// .route("/public", Cors::new().allow_any_origin())?;
    ///
    /// let app: Router = Router::new()
    ///     .route("/me", get(|| async { "private" }))
    ///     .route("/public/stats", get(|| async { "42" }))
    ///     .layer(layer);
    /// # Ok::<(), rune_axum_cors::Error>(())
    /// ```
    pub fn route(mut self, prefix: &str, config: Cors) -> Result<Self, Error> {
        let prefix = parse_prefix(prefix)?;
        let policy = Policy::new(config)?;
        let policies = Arc::make_mut(&mut self.policies);
        if policies.routes.iter().any(|(p, _)| *p == prefix) {
            return Err(Error::InvalidInput {
                input: prefix,
                reason: "route prefix registered twice",
            });
        }
        policies.routes.push((prefix, policy));
        policies
            .routes
            .sort_by(|(a, _), (b, _)| b.len().cmp(&a.len()).then_with(|| a.cmp(b)));
        Ok(self)
    }

    /// The audit report of the default policy: weaknesses below the
    /// rejection threshold, such as `*` without credentials. Map them to
    /// findings with [`Report::to_findings`] to log or export them.
    #[must_use]
    pub fn report(&self) -> &Report {
        &self.policies.default.report
    }

    /// The audit report of the override registered for `prefix`.
    #[must_use]
    pub fn route_report(&self, prefix: &str) -> Option<&Report> {
        let prefix = parse_prefix(prefix).ok()?;
        self.policies
            .routes
            .iter()
            .find(|(p, _)| *p == prefix)
            .map(|(_, policy)| &policy.report)
    }

    /// The default policy this layer enforces.
    #[must_use]
    pub fn config(&self) -> &Cors {
        &self.policies.default.cors
    }
}

impl TryFrom<Cors> for CorsLayer {
    type Error = Error;

    fn try_from(config: Cors) -> Result<Self, Self::Error> {
        Self::new(config)
    }
}

impl<S> Layer<S> for CorsLayer {
    type Service = CorsService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        CorsService {
            inner,
            policies: Arc::clone(&self.policies),
        }
    }
}

/// Tower [`Service`] produced by [`CorsLayer`].
///
/// Preflights (`OPTIONS` with `Origin` and
/// `Access-Control-Request-Method`) are answered directly, with `204 No
/// Content` when allowed and according to [`Cors::rejection`] otherwise;
/// they never reach the inner service. Every other request is passed on
/// and the response gets the CORS headers for its origin.
#[derive(Clone, Debug)]
pub struct CorsService<S> {
    inner: S,
    policies: Arc<Policies>,
}

impl<S, ReqBody, ResBody> Service<Request<ReqBody>> for CorsService<S>
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
        let config = self.policies.select(req.uri().path());
        let headers = req.headers();
        let origin = single(headers, &header::ORIGIN).map(str::to_owned);

        // Any OPTIONS with both headers present is a preflight, even when
        // they are repeated or malformed: such a request is refused here
        // rather than handed to the router.
        if req.method() == Method::OPTIONS
            && headers.contains_key(header::ORIGIN)
            && headers.contains_key(header::ACCESS_CONTROL_REQUEST_METHOD)
        {
            let method = single(headers, &header::ACCESS_CONTROL_REQUEST_METHOD);
            let request_headers = combined(headers, &header::ACCESS_CONTROL_REQUEST_HEADERS);
            let private_network = headers
                .get_all(&REQUEST_PRIVATE_NETWORK)
                .iter()
                .any(|v| v.as_bytes().eq_ignore_ascii_case(b"true"));
            let granted = match (origin.as_deref(), method) {
                (Some(origin), Some(method)) => config.preflight_headers(
                    origin,
                    method,
                    request_headers.as_deref(),
                    private_network,
                ),
                _ => None,
            };
            let response = preflight(config, granted);
            return Box::pin(async move { Ok(response) });
        }

        let cors = config.actual_headers(origin.as_deref());
        let vary = config.varies();
        let fut = self.inner.call(req);
        Box::pin(async move {
            let mut response = fut.await?;
            apply(response.headers_mut(), cors, vary);
            Ok(response)
        })
    }
}

/// Builds the answer to a preflight; `granted` is `None` when refused.
fn preflight<B: Default>(config: &Cors, granted: Option<HeaderList>) -> Response<B> {
    let mut response = Response::new(B::default());
    *response.status_mut() = if granted.is_some() {
        StatusCode::NO_CONTENT
    } else {
        config.rejection_mode().status()
    };
    let headers = response.headers_mut();
    headers.extend(granted.unwrap_or_default());
    headers.insert(header::VARY, HeaderValue::from_static(PREFLIGHT_VARY));
    response
}

/// The value of a header that appears exactly once and is visible ASCII.
fn single<'a>(headers: &'a HeaderMap, name: &header::HeaderName) -> Option<&'a str> {
    let mut values = headers.get_all(name).iter();
    let value = values.next()?;
    if values.next().is_some() {
        return None;
    }
    value.to_str().ok()
}

/// All values of a header joined with `,`, as a list header is combined.
/// A value that is not visible ASCII is kept as an unmatched name, so the
/// preflight is refused rather than the value skipped.
fn combined(headers: &HeaderMap, name: &header::HeaderName) -> Option<String> {
    let values: Vec<&str> = headers
        .get_all(name)
        .iter()
        .map(|v| v.to_str().unwrap_or("\u{fffd}"))
        .collect();
    (!values.is_empty()).then(|| values.join(","))
}

/// Replaces the CORS headers of an inner response and adds `Vary: Origin`.
fn apply(headers: &mut HeaderMap, cors: HeaderList, vary: bool) {
    for name in OWNED {
        headers.remove(name);
    }
    headers.extend(cors);
    let varies_already = headers
        .get_all(header::VARY)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .map(str::trim)
        .any(|v| v == "*" || v.eq_ignore_ascii_case("origin"));
    if vary && !varies_already {
        headers.append(header::VARY, HeaderValue::from_static("Origin"));
    }
}

#[cfg(test)]
#[allow(clippy::assert_is_empty, reason = "emptiness is the expectation")]
mod tests {
    use super::*;

    #[test]
    fn single_rejects_repeats() {
        let mut h = HeaderMap::new();
        assert_eq!(single(&h, &header::ORIGIN), None);
        h.append(
            header::ORIGIN,
            HeaderValue::from_static("https://a.example"),
        );
        assert_eq!(single(&h, &header::ORIGIN), Some("https://a.example"));
        h.append(
            header::ORIGIN,
            HeaderValue::from_static("https://b.example"),
        );
        assert_eq!(single(&h, &header::ORIGIN), None);
    }

    #[test]
    fn apply_keeps_existing_vary() {
        let mut h = HeaderMap::new();
        h.insert(
            header::VARY,
            HeaderValue::from_static("Accept-Encoding, origin"),
        );
        h.insert(
            header::ACCESS_CONTROL_ALLOW_ORIGIN,
            HeaderValue::from_static("*"),
        );
        apply(&mut h, Vec::new(), true);
        assert_eq!(h.get_all(header::VARY).iter().count(), 1);
        assert!(h.get(header::ACCESS_CONTROL_ALLOW_ORIGIN).is_none());

        let mut h = HeaderMap::new();
        h.insert(header::VARY, HeaderValue::from_static("Accept-Encoding"));
        apply(&mut h, Vec::new(), true);
        assert_eq!(h.get_all(header::VARY).iter().count(), 2);
    }

    #[test]
    fn apply_strips_every_owned_header() {
        let mut h = HeaderMap::new();
        for name in OWNED {
            h.insert(name, HeaderValue::from_static("x"));
        }
        apply(&mut h, Vec::new(), false);
        assert!(h.is_empty());
    }

    #[test]
    fn prefixes_match_on_segment_boundaries() {
        assert!(prefix_matches("/api", "/api"));
        assert!(prefix_matches("/api", "/api/x"));
        assert!(prefix_matches("/api", "/api/"));
        assert!(!prefix_matches("/api", "/apix"));
        assert!(!prefix_matches("/api", "/"));
        assert!(prefix_matches("/", "/anything"));
    }

    #[test]
    fn paths_normalise() {
        assert_eq!(normalize_path("/a/b"), "/a/b");
        assert_eq!(normalize_path("//a//b/"), "/a/b");
        assert_eq!(normalize_path("/a/./b/../c"), "/a/c");
        assert_eq!(normalize_path("/%61dmin"), "/admin");
        assert_eq!(normalize_path("/a%2F..%2Fadmin"), "/admin");
        assert_eq!(normalize_path("/a\\..\\admin"), "/admin");
        assert_eq!(normalize_path("/../../x"), "/x");
        assert_eq!(normalize_path("/%zz%4"), "/%zz%4");
    }

    #[test]
    fn prefixes_are_validated() {
        assert_eq!(parse_prefix("/api/").unwrap(), "/api");
        assert_eq!(parse_prefix("///").unwrap(), "/");
        for bad in [
            "api", "/a//b", "/a/../b", "/./a", "/%61", "/a\\b", "/{id}", "/a/:id", "/a/*", "/ä",
        ] {
            assert!(parse_prefix(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn ambiguous_paths_get_the_deny_policy() {
        let layer = CorsLayer::new(Cors::new().allow_any_origin())
            .unwrap()
            .route("/admin", Cors::new().allow_origin("https://a.example"))
            .unwrap();
        let p = &layer.policies;
        let origin = Some("https://evil.example");
        assert!(!p.select("/x").actual_headers(origin).is_empty());
        assert!(p.select("/admin/x").actual_headers(origin).is_empty());
        for sneaky in ["//admin", "/%61dmin/x", "/x/../admin", "/x\\..\\admin"] {
            assert!(
                p.select(sneaky).actual_headers(origin).is_empty(),
                "{sneaky}"
            );
        }
        // Harmless noise that picks the same policy either way.
        assert!(!p.select("/x//y").actual_headers(origin).is_empty());
    }
}
