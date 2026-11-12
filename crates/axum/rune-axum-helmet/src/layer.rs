use crate::config::Helmet;
use http::{Request, Response};
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use tower::{Layer, Service};

/// Tower [`Layer`] that injects security headers into every response.
///
/// Apply with Axum's `.layer()` call. Use [`HelmetLayer::default()`] for
/// secure defaults, or [`HelmetLayer::new()`] to supply a custom [`Helmet`].
///
/// # Examples
///
/// ```rust,no_run
/// use axum::{routing::get, Router};
/// use rune_axum_helmet::HelmetLayer;
///
/// // Secure defaults
/// let app: Router = Router::new()
///     .route("/", get(|| async { "ok" }))
///     .layer(HelmetLayer::default());
/// ```
#[derive(Clone, Debug)]
pub struct HelmetLayer {
    helmet: Helmet,
}

impl HelmetLayer {
    /// Creates a new `HelmetLayer` from a custom [`Helmet`] configuration.
    #[must_use]
    pub const fn new(helmet: Helmet) -> Self {
        Self { helmet }
    }
}

impl Default for HelmetLayer {
    fn default() -> Self {
        Self {
            helmet: Helmet::new(),
        }
    }
}

impl<S> Layer<S> for HelmetLayer {
    type Service = HelmetService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        HelmetService {
            inner,
            helmet: self.helmet.clone(),
        }
    }
}

/// Tower [`Service`] produced by [`HelmetLayer`].
#[derive(Clone, Debug)]
pub struct HelmetService<S> {
    inner: S,
    helmet: Helmet,
}

impl<S, ReqBody, ResBody> Service<Request<ReqBody>> for HelmetService<S>
where
    S: Service<Request<ReqBody>, Response = Response<ResBody>>,
    S::Future: Send + 'static,
    S::Error: Send + 'static,
{
    type Response = Response<ResBody>;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<ReqBody>) -> Self::Future {
        let helmet = self.helmet.clone();
        let future = self.inner.call(req);
        Box::pin(async move {
            let mut response = future.await?;
            helmet.apply(response.headers_mut());
            Ok(response)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Hsts, XFrameOptions};
    use axum::{Router, body::Body, routing::get};
    use http::StatusCode;
    use tower::ServiceExt;

    async fn ok() -> &'static str {
        "ok"
    }

    fn build_app(helmet: Helmet) -> Router {
        Router::new()
            .route("/", get(ok))
            .layer(HelmetLayer::new(helmet))
    }

    async fn get_response(app: Router) -> http::Response<Body> {
        app.oneshot(
            http::Request::builder()
                .uri("/")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn default_headers_are_present() {
        let response = get_response(build_app(Helmet::new())).await;

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()["x-content-type-options"], "nosniff");
        assert_eq!(response.headers()["x-xss-protection"], "0");
        assert_eq!(response.headers()["x-frame-options"], "SAMEORIGIN");
        assert_eq!(
            response.headers()["referrer-policy"],
            "strict-origin-when-cross-origin"
        );
        assert_eq!(
            response.headers()["cross-origin-opener-policy"],
            "same-origin"
        );
        assert_eq!(
            response.headers()["cross-origin-resource-policy"],
            "same-origin"
        );
    }

    #[tokio::test]
    async fn hsts_is_off_by_default() {
        let response = get_response(build_app(Helmet::new())).await;
        assert!(!response.headers().contains_key("strict-transport-security"));
    }

    #[tokio::test]
    async fn custom_frame_options_deny() {
        let helmet = Helmet::new().frame_options(XFrameOptions::Deny);
        let response = get_response(build_app(helmet)).await;
        assert_eq!(response.headers()["x-frame-options"], "DENY");
    }

    #[tokio::test]
    async fn hsts_with_subdomains() {
        let helmet = Helmet::new().hsts(Hsts::new().max_age(63_072_000).include_subdomains());
        let response = get_response(build_app(helmet)).await;
        assert_eq!(
            response.headers()["strict-transport-security"],
            "max-age=63072000; includeSubDomains"
        );
    }

    #[tokio::test]
    async fn csp_is_set() {
        let helmet = Helmet::new().csp("default-src 'self'");
        let response = get_response(build_app(helmet)).await;
        assert_eq!(
            response.headers()["content-security-policy"],
            "default-src 'self'"
        );
    }

    #[tokio::test]
    async fn no_frame_options_removes_header() {
        let helmet = Helmet::new().no_frame_options();
        let response = get_response(build_app(helmet)).await;
        assert!(!response.headers().contains_key("x-frame-options"));
    }

    #[tokio::test]
    async fn no_content_type_options_removes_header() {
        let helmet = Helmet::new().no_content_type_options();
        let response = get_response(build_app(helmet)).await;
        assert!(!response.headers().contains_key("x-content-type-options"));
    }

    #[tokio::test]
    async fn no_xss_protection_removes_header() {
        let helmet = Helmet::new().no_xss_protection();
        let response = get_response(build_app(helmet)).await;
        assert!(!response.headers().contains_key("x-xss-protection"));
    }

    #[tokio::test]
    async fn csp_report_only_is_set() {
        let helmet = Helmet::new().report_only_csp("default-src 'self'");
        let response = get_response(build_app(helmet)).await;
        assert_eq!(
            response.headers()["content-security-policy-report-only"],
            "default-src 'self'"
        );
        assert!(!response.headers().contains_key("content-security-policy"));
    }

    #[tokio::test]
    async fn csp_builder_produces_correct_header() {
        use crate::config::CspBuilder;
        let helmet = Helmet::new().csp_from(
            CspBuilder::new()
                .default_src(&["'self'"])
                .script_src(&["'self'", "'strict-dynamic'"])
                .upgrade_insecure_requests(),
        );
        let response = get_response(build_app(helmet)).await;
        let csp = &response.headers()["content-security-policy"];
        assert!(csp.to_str().unwrap().contains("default-src 'self'"));
        assert!(
            csp.to_str()
                .unwrap()
                .contains("script-src 'self' 'strict-dynamic'")
        );
        assert!(csp.to_str().unwrap().contains("upgrade-insecure-requests"));
    }

    #[tokio::test]
    async fn report_only_csp_builder_produces_correct_header() {
        use crate::config::CspBuilder;
        let helmet = Helmet::new().report_only_csp_from(
            CspBuilder::new()
                .default_src(&["'self'"])
                .report_to("csp-endpoint"),
        );
        let response = get_response(build_app(helmet)).await;
        let header = response.headers()["content-security-policy-report-only"]
            .to_str()
            .unwrap();
        assert!(header.contains("default-src 'self'"));
        assert!(header.contains("report-to csp-endpoint"));
    }
}
