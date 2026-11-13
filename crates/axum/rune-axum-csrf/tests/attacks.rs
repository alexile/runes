//! End-to-end behaviour and attack scenarios for the CSRF layer.

#![allow(clippy::unwrap_used, reason = "fixture helpers outside #[test] fns")]

use axum::{
    Extension, Router,
    body::{Body, to_bytes},
    response::IntoResponse,
    routing::{get, post},
};
use http::{
    HeaderName, Request, Response, StatusCode,
    header::{COOKIE, SET_COOKIE},
};
use rune_axum_csrf::{
    CsrfConfig, CsrfKey, CsrfLayer, CsrfRejection, CsrfRotate, CsrfToken, SameSite,
};
use std::time::Duration;
use tower::ServiceExt;

const COOKIE_NAME: &str = "__Host-csrf_token";

fn key() -> CsrfKey {
    CsrfKey::from_bytes(&[9u8; 32]).unwrap()
}

fn config() -> CsrfConfig {
    CsrfConfig::new().key(key())
}

async fn echo(body: String) -> String {
    body
}

fn app(config: CsrfConfig) -> Router {
    Router::new()
        .route(
            "/page",
            get(|Extension(t): Extension<CsrfToken>| async move { t.as_str().to_owned() }),
        )
        .route(
            "/submit",
            post(echo)
                .put(|| async { "ok" })
                .patch(|| async { "ok" })
                .delete(|| async { "ok" }),
        )
        .route(
            "/login",
            post(|| async {
                let mut res = "logged in".into_response();
                res.extensions_mut().insert(CsrfRotate);
                res
            }),
        )
        .route(
            "/session-page",
            get(|| async { ([(SET_COOKIE, "session_id=abc; Path=/; HttpOnly")], "hello") }),
        )
        .route("/webhooks/stripe", post(|| async { "hook" }))
        .route("/webhooks", post(|| async { "hook" }))
        .route("/webhooksX", post(|| async { "not a hook" }))
        .layer(CsrfLayer::new(config))
}

async fn send(app: Router, req: Request<Body>) -> Response<Body> {
    app.oneshot(req).await.unwrap()
}

fn set_cookies(res: &Response<Body>) -> Vec<String> {
    res.headers()
        .get_all(SET_COOKIE)
        .iter()
        .map(|v| v.to_str().unwrap().to_owned())
        .collect()
}

fn csrf_set_cookie(res: &Response<Body>) -> Option<String> {
    set_cookies(res)
        .into_iter()
        .find(|c| c.starts_with(&format!("{COOKIE_NAME}=")))
}

/// Performs a GET with the given extra cookie header and returns the token.
async fn fetch_token(cfg: CsrfConfig, cookie: Option<&str>) -> String {
    let mut req = Request::get("/page");
    if let Some(c) = cookie {
        req = req.header(COOKIE, c);
    }
    let res = send(app(cfg), req.body(Body::empty()).unwrap()).await;
    assert_eq!(res.status(), StatusCode::OK);
    let body = to_bytes(res.into_body(), usize::MAX).await.unwrap();
    String::from_utf8(body.to_vec()).unwrap()
}

fn post_req(cookie: Option<&str>, header: Option<&str>) -> http::request::Builder {
    let mut b = Request::post("/submit").header("host", "example.com");
    if let Some(c) = cookie {
        b = b.header(COOKIE, c);
    }
    if let Some(h) = header {
        b = b.header("x-csrf-token", h);
    }
    b
}

fn rejection(res: &Response<Body>) -> Option<CsrfRejection> {
    res.extensions().get::<CsrfRejection>().copied()
}

// ---------------------------------------------------------------- issuance

#[tokio::test]
async fn get_sets_secure_host_prefixed_cookie() {
    let res = send(
        app(config()),
        Request::get("/page").body(Body::empty()).unwrap(),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK);
    let c = csrf_set_cookie(&res).expect("csrf cookie");
    assert!(c.contains("; Path=/"), "{c}");
    assert!(c.contains("; SameSite=Lax"), "{c}");
    assert!(c.contains("; Secure"), "{c}");
    assert!(!c.contains("HttpOnly"), "{c}");
    assert!(!c.contains("Domain"), "{c}");
}

#[tokio::test]
async fn handler_sees_same_token_as_cookie() {
    let res = send(
        app(config()),
        Request::get("/page").body(Body::empty()).unwrap(),
    )
    .await;
    let cookie = csrf_set_cookie(&res).unwrap();
    let value = cookie
        .split(';')
        .next()
        .unwrap()
        .split_once('=')
        .unwrap()
        .1
        .to_owned();
    let body = to_bytes(res.into_body(), usize::MAX).await.unwrap();
    assert_eq!(body, value.as_bytes());
    // 32-byte nonce = 256 bits of entropy.
    assert_eq!(value.split('.').next().unwrap().len(), 64);
}

#[tokio::test]
async fn valid_cookie_is_not_reissued() {
    let t = fetch_token(config(), None).await;
    let res = send(
        app(config()),
        Request::get("/page")
            .header(COOKIE, format!("{COOKIE_NAME}={t}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert!(csrf_set_cookie(&res).is_none());
}

#[tokio::test]
async fn handler_cookies_are_preserved() {
    let res = send(
        app(config()),
        Request::get("/session-page").body(Body::empty()).unwrap(),
    )
    .await;
    let cookies = set_cookies(&res);
    assert_eq!(cookies.len(), 2, "{cookies:?}");
    assert!(cookies.iter().any(|c| c.starts_with("session_id=")));
}

#[tokio::test]
async fn cookie_attributes_configurable() {
    let cfg = config()
        .secure(false)
        .http_only(true)
        .same_site(SameSite::Strict)
        .cookie_path("/app")
        .token_ttl(Duration::from_secs(600));
    let res = send(app(cfg), Request::get("/page").body(Body::empty()).unwrap()).await;
    let c = set_cookies(&res).pop().unwrap();
    assert!(
        c.starts_with("csrf_token="),
        "no __Host- without Secure: {c}"
    );
    assert!(c.contains("; Path=/app"));
    assert!(c.contains("; SameSite=Strict"));
    assert!(c.contains("; HttpOnly"));
    assert!(c.contains("; Max-Age=600"));
    assert!(!c.contains("Secure"));
}

#[tokio::test]
async fn host_prefix_forces_root_path() {
    let res = send(
        app(config().cookie_path("/app")),
        Request::get("/page").body(Body::empty()).unwrap(),
    )
    .await;
    assert!(csrf_set_cookie(&res).unwrap().contains("; Path=/;"));
}

// ---------------------------------------------------------------- happy paths

#[tokio::test]
async fn header_token_accepted() {
    let t = fetch_token(config(), None).await;
    let cookie = format!("{COOKIE_NAME}={t}");
    let res = send(
        app(config()),
        post_req(Some(&cookie), Some(&t))
            .header("origin", "https://example.com")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK);
}

#[tokio::test]
async fn all_unsafe_methods_enforced() {
    for m in ["POST", "PUT", "PATCH", "DELETE"] {
        let res = send(
            app(config()),
            Request::builder()
                .method(m)
                .uri("/submit")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(res.status(), StatusCode::FORBIDDEN, "{m}");
    }
}

#[tokio::test]
async fn safe_methods_exempt() {
    for m in ["GET", "HEAD", "OPTIONS", "TRACE"] {
        let res = send(
            app(config()),
            Request::builder()
                .method(m)
                .uri("/page")
                .header("origin", "https://evil.com")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_ne!(res.status(), StatusCode::FORBIDDEN, "{m}");
    }
}

#[tokio::test]
async fn form_field_accepted_and_body_forwarded() {
    let t = fetch_token(config(), None).await;
    let body = format!("amount=10&csrf_token={t}&to=bob");
    let res = send(
        app(config()),
        post_req(Some(&format!("{COOKIE_NAME}={t}")), None)
            .header("content-type", "application/x-www-form-urlencoded")
            .body(Body::from(body.clone()))
            .unwrap(),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK);
    let echoed = to_bytes(res.into_body(), usize::MAX).await.unwrap();
    assert_eq!(
        echoed,
        body.as_bytes(),
        "handler must still see the full body"
    );
}

#[tokio::test]
async fn form_field_disabled() {
    let t = fetch_token(config(), None).await;
    let res = send(
        app(config().without_form_field()),
        post_req(Some(&format!("{COOKIE_NAME}={t}")), None)
            .header("content-type", "application/x-www-form-urlencoded")
            .body(Body::from(format!("csrf_token={t}")))
            .unwrap(),
    )
    .await;
    assert_eq!(rejection(&res), Some(CsrfRejection::MissingToken));
}

#[tokio::test]
async fn custom_names() {
    let cfg = || {
        config()
            .cookie_name("my_csrf")
            .header_name(HeaderName::from_static("x-my-csrf"))
    };
    let t = fetch_token(cfg(), None).await;
    let res = send(
        app(cfg()),
        Request::post("/submit")
            .header(COOKIE, format!("__Host-my_csrf={t}"))
            .header("x-my-csrf", &t)
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK);
}

// ---------------------------------------------------------------- attacks

#[tokio::test]
async fn missing_cookie_rejected() {
    let t = fetch_token(config(), None).await;
    let res = send(
        app(config()),
        post_req(None, Some(&t)).body(Body::empty()).unwrap(),
    )
    .await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
    assert_eq!(rejection(&res), Some(CsrfRejection::MissingCookie));
    assert_eq!(res.headers()["cache-control"], "no-store");
    assert!(
        to_bytes(res.into_body(), 1024).await.unwrap().is_empty(),
        "no info leak"
    );
}

#[tokio::test]
async fn missing_token_rejected() {
    let t = fetch_token(config(), None).await;
    let res = send(
        app(config()),
        post_req(Some(&format!("{COOKIE_NAME}={t}")), None)
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
    assert_eq!(rejection(&res), Some(CsrfRejection::MissingToken));
}

#[tokio::test]
async fn mismatched_token_rejected() {
    let a = fetch_token(config(), None).await;
    let b = fetch_token(config(), None).await;
    let res = send(
        app(config()),
        post_req(Some(&format!("{COOKIE_NAME}={a}")), Some(&b))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(rejection(&res), Some(CsrfRejection::TokenMismatch));
}

#[tokio::test]
async fn near_miss_token_rejected() {
    // Differs only in the final character: the compare must check every byte.
    let t = fetch_token(config(), None).await;
    let mut near = t.clone();
    let last = near.pop().unwrap();
    near.push(if last == '0' { '1' } else { '0' });
    let res = send(
        app(config()),
        post_req(Some(&format!("{COOKIE_NAME}={t}")), Some(&near))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(rejection(&res), Some(CsrfRejection::TokenMismatch));
}

#[tokio::test]
async fn naive_double_submit_forgery_rejected() {
    // Attacker plants an arbitrary cookie and echoes it: the 0.1 scheme accepted this.
    let forged = "deadbeef".repeat(8);
    let res = send(
        app(config()),
        post_req(Some(&format!("{COOKIE_NAME}={forged}")), Some(&forged))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(rejection(&res), Some(CsrfRejection::InvalidCookie));
}

#[tokio::test]
async fn tampered_signature_rejected() {
    let t = fetch_token(config(), None).await;
    let (payload, mac) = t.rsplit_once('.').unwrap();
    let flipped = if mac.starts_with('0') { "1" } else { "0" };
    let forged = format!("{payload}.{flipped}{}", &mac[1..]);
    let res = send(
        app(config()),
        post_req(Some(&format!("{COOKIE_NAME}={forged}")), Some(&forged))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(rejection(&res), Some(CsrfRejection::InvalidCookie));
}

#[tokio::test]
async fn token_from_other_key_rejected() {
    let other = CsrfConfig::new().key(CsrfKey::from_bytes(&[1u8; 32]).unwrap());
    let t = fetch_token(other, None).await;
    let res = send(
        app(config()),
        post_req(Some(&format!("{COOKIE_NAME}={t}")), Some(&t))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(rejection(&res), Some(CsrfRejection::InvalidCookie));
}

#[tokio::test]
async fn cookie_tossing_with_attackers_own_session_token_rejected() {
    let cfg = || config().session_cookie("session_id");
    // Attacker obtains a genuine token for *their* session...
    let attacker = fetch_token(cfg(), Some("session_id=attacker")).await;
    // ...tosses it into the victim's cookie jar from a subdomain and submits it.
    let res = send(
        app(cfg()),
        post_req(
            Some(&format!("session_id=victim; {COOKIE_NAME}={attacker}")),
            Some(&attacker),
        )
        .body(Body::empty())
        .unwrap(),
    )
    .await;
    assert_eq!(rejection(&res), Some(CsrfRejection::InvalidCookie));
}

#[tokio::test]
async fn tossed_duplicate_cookie_does_not_shadow_real_one() {
    let cfg = || config().session_cookie("session_id");
    let victim = fetch_token(cfg(), Some("session_id=victim")).await;
    let attacker = fetch_token(cfg(), Some("session_id=attacker")).await;
    let jar = format!("session_id=victim; {COOKIE_NAME}={attacker}; {COOKIE_NAME}={victim}");
    // The victim's own page still works...
    let ok = send(
        app(cfg()),
        post_req(Some(&jar), Some(&victim))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(ok.status(), StatusCode::OK);
    // ...and the attacker's token is useless.
    let bad = send(
        app(cfg()),
        post_req(Some(&jar), Some(&attacker))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(rejection(&bad), Some(CsrfRejection::TokenMismatch));
}

#[tokio::test]
async fn custom_session_extractor() {
    let cfg = || {
        config().session_id_with(|parts| {
            parts
                .headers
                .get("x-user")
                .and_then(|v| v.to_str().ok())
                .map(str::to_owned)
        })
    };
    let res = send(
        app(cfg()),
        Request::get("/page")
            .header("x-user", "alice")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    let t = String::from_utf8(
        to_bytes(res.into_body(), usize::MAX)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();
    let as_user = |u: &'static str| {
        post_req(Some(&format!("{COOKIE_NAME}={t}")), Some(&t))
            .header("x-user", u)
            .body(Body::empty())
            .unwrap()
    };
    assert_eq!(
        send(app(cfg()), as_user("alice")).await.status(),
        StatusCode::OK
    );
    assert_eq!(
        send(app(cfg()), as_user("bob")).await.status(),
        StatusCode::FORBIDDEN
    );
}

#[tokio::test]
async fn cross_site_origin_rejected_even_with_valid_token() {
    let t = fetch_token(config(), None).await;
    let res = send(
        app(config()),
        post_req(Some(&format!("{COOKIE_NAME}={t}")), Some(&t))
            .header("origin", "https://evil.example.net")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
    assert_eq!(rejection(&res), Some(CsrfRejection::CrossOrigin));
}

#[tokio::test]
async fn fetch_metadata_cross_site_rejected() {
    let t = fetch_token(config(), None).await;
    let res = send(
        app(config()),
        post_req(Some(&format!("{COOKIE_NAME}={t}")), Some(&t))
            .header("sec-fetch-site", "cross-site")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(rejection(&res), Some(CsrfRejection::CrossOrigin));
}

#[tokio::test]
async fn cross_site_referer_rejected() {
    let t = fetch_token(config(), None).await;
    let res = send(
        app(config()),
        post_req(Some(&format!("{COOKIE_NAME}={t}")), Some(&t))
            .header("referer", "https://evil.com/attack.html")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(rejection(&res), Some(CsrfRejection::CrossOrigin));
}

#[tokio::test]
async fn trusted_origin_and_disabled_check() {
    let t = fetch_token(config(), None).await;
    let req = || {
        post_req(Some(&format!("{COOKIE_NAME}={t}")), Some(&t))
            .header("origin", "https://app.example.org")
            .body(Body::empty())
            .unwrap()
    };
    let trusted = config().trusted_origin("https://app.example.org");
    assert_eq!(send(app(trusted), req()).await.status(), StatusCode::OK);
    let off = config().verify_origin(false);
    assert_eq!(send(app(off), req()).await.status(), StatusCode::OK);
}

#[tokio::test]
async fn expired_token_rejected_then_reissued() {
    let t = fetch_token(config(), None).await;
    let cfg = || config().token_ttl(Duration::ZERO);
    // Make the token at least one second old.
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let cookie = format!("{COOKIE_NAME}={t}");
    let res = send(
        app(cfg()),
        post_req(Some(&cookie), Some(&t))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(rejection(&res), Some(CsrfRejection::InvalidCookie));
    let res = send(
        app(cfg()),
        Request::get("/page")
            .header(COOKIE, &cookie)
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert!(
        csrf_set_cookie(&res).is_some(),
        "expired token must be rotated"
    );
}

#[tokio::test]
async fn oversized_form_rejected_without_reading_it_all() {
    let t = fetch_token(config(), None).await;
    let cookie = format!("{COOKIE_NAME}={t}");
    let big = format!("pad={}&csrf_token={t}", "a".repeat(2048));
    // Declared length over the limit.
    let res = send(
        app(config().max_form_bytes(1024)),
        post_req(Some(&cookie), None)
            .header("content-type", "application/x-www-form-urlencoded")
            .header("content-length", big.len())
            .body(Body::from(big.clone()))
            .unwrap(),
    )
    .await;
    assert_eq!(res.status(), StatusCode::PAYLOAD_TOO_LARGE);
    // Streamed body without Content-Length.
    let stream = futures_stream(big);
    let res = send(
        app(config().max_form_bytes(1024)),
        post_req(Some(&cookie), None)
            .header("content-type", "application/x-www-form-urlencoded")
            .body(stream)
            .unwrap(),
    )
    .await;
    assert_eq!(res.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(rejection(&res), Some(CsrfRejection::BodyTooLarge));
}

/// A body of 256-byte chunks with no size hint (like chunked transfer encoding).
fn futures_stream(s: String) -> Body {
    struct Chunks(std::collections::VecDeque<bytes::Bytes>);
    impl http_body::Body for Chunks {
        type Data = bytes::Bytes;
        type Error = std::convert::Infallible;
        fn poll_frame(
            mut self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Option<Result<http_body::Frame<bytes::Bytes>, Self::Error>>> {
            std::task::Poll::Ready(self.0.pop_front().map(|b| Ok(http_body::Frame::data(b))))
        }
    }
    let chunks = s
        .into_bytes()
        .chunks(256)
        .map(bytes::Bytes::copy_from_slice)
        .collect();
    Body::new(Chunks(chunks))
}

#[tokio::test]
async fn exempt_paths_skip_checks() {
    let cfg = config().exempt_prefix("/webhooks/");
    let res = send(
        app(cfg),
        Request::post("/webhooks/stripe")
            .header("origin", "https://stripe.com")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK);
    let cfg = config().exempt_path("/webhooks/stripe");
    let res = send(
        app(cfg),
        Request::post("/webhooks/stripe")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK);
    // Not exempt by default.
    let res = send(
        app(config()),
        Request::post("/webhooks/stripe")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn exempt_prefix_stops_at_segment_boundary() {
    for prefix in ["/webhooks", "/webhooks/"] {
        let post = |path: &str| Request::post(path).body(Body::empty()).unwrap();
        let cfg = config().exempt_prefix(prefix);
        for path in ["/webhooks", "/webhooks/stripe"] {
            let res = send(app(cfg.clone()), post(path)).await;
            assert_eq!(res.status(), StatusCode::OK, "{prefix} {path}");
        }
        let res = send(app(cfg), post("/webhooksX")).await;
        assert_eq!(res.status(), StatusCode::FORBIDDEN, "{prefix}");
    }
}

#[tokio::test]
async fn handler_can_rotate_token() {
    let t = fetch_token(config(), None).await;
    let res = send(
        app(config()),
        Request::post("/login")
            .header(COOKIE, format!("{COOKIE_NAME}={t}"))
            .header("x-csrf-token", &t)
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK);
    let c = csrf_set_cookie(&res).expect("rotated cookie");
    assert!(!c.contains(&t));
}

#[tokio::test]
async fn custom_status_code() {
    let res = send(
        app(config().status(StatusCode::UNPROCESSABLE_ENTITY)),
        Request::post("/submit").body(Body::empty()).unwrap(),
    )
    .await;
    assert_eq!(res.status(), StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
async fn debug_output_has_no_secrets() {
    let secret = [0xABu8; 32];
    let cfg = CsrfConfig::new().key(CsrfKey::from_bytes(&secret).unwrap());
    let dbg = format!("{cfg:?} {:?}", CsrfLayer::new(cfg.clone()));
    assert!(!dbg.contains("171"), "{dbg}");
    assert!(!dbg.to_lowercase().contains("abab"), "{dbg}");
}

#[tokio::test]
async fn token_debug_is_redacted() {
    let res =
        send(
            Router::new()
                .route(
                    "/",
                    get(|Extension(t): Extension<CsrfToken>| async move {
                        format!("{t:?}|{}", t.as_str())
                    }),
                )
                .layer(CsrfLayer::new(config())),
            Request::get("/").body(Body::empty()).unwrap(),
        )
        .await;
    let body = String::from_utf8(
        to_bytes(res.into_body(), usize::MAX)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();
    let (dbg, value) = body.split_once('|').unwrap();
    assert!(dbg.contains("[redacted]"));
    assert!(!dbg.contains(value));
}

#[tokio::test]
async fn hidden_input_renders_field() {
    let res = send(
        Router::new()
            .route(
                "/",
                get(|Extension(t): Extension<CsrfToken>| async move { t.hidden_input().unwrap() }),
            )
            .layer(CsrfLayer::new(config())),
        Request::get("/").body(Body::empty()).unwrap(),
    )
    .await;
    let html = String::from_utf8(
        to_bytes(res.into_body(), usize::MAX)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();
    assert!(
        html.starts_with(r#"<input type="hidden" name="csrf_token" value=""#),
        "{html}"
    );
}

#[tokio::test]
async fn same_site_strict_configurable() {
    let res = send(
        app(config().same_site(SameSite::Strict)),
        Request::get("/page").body(Body::empty()).unwrap(),
    )
    .await;
    assert!(csrf_set_cookie(&res).unwrap().contains("SameSite=Strict"));
}

#[test]
fn rejection_display_is_generic() {
    assert_eq!(
        CsrfRejection::TokenMismatch.to_string(),
        "CSRF token mismatch"
    );
}
