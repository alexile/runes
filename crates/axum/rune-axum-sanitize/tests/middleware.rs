//! End-to-end behaviour of the layer in front of real axum extractors.

#![allow(clippy::unwrap_used, reason = "test helpers fail loudly")]

use std::collections::HashMap;

use axum::{
    Form, Json, Router,
    body::{Body, Bytes},
    extract::Query,
    http::{HeaderMap, Request, StatusCode},
    routing::{get, post},
};
use http_body_util::BodyExt;
use rune_axum_sanitize::{Mode, OtherBodies, SanitizeConfig, SanitizeLayer};
use serde_json::{Value, json};
use tower::ServiceExt;

fn app(config: SanitizeConfig) -> Router {
    Router::new()
        .route(
            "/query",
            get(|Query(params): Query<HashMap<String, String>>| async move { Json(params) }),
        )
        .route(
            "/json",
            post(|Json(body): Json<Value>| async move { Json(body) }),
        )
        .route(
            "/posts/{id}",
            post(|Json(body): Json<Value>| async move { Json(body) }),
        )
        .route(
            "/form",
            post(|Form(form): Form<HashMap<String, String>>| async move { Json(form) }),
        )
        .route(
            "/raw",
            post(|headers: HeaderMap, body: Bytes| async move {
                let length = headers
                    .get("content-length")
                    .map(|value| value.to_str().unwrap().to_owned());
                ([("x-seen-length", length.unwrap_or_default())], body)
            }),
        )
        .layer(SanitizeLayer::new(config))
}

async fn send(app: Router, request: Request<Body>) -> (StatusCode, HeaderMap, Bytes) {
    let response = app.oneshot(request).await.unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    (status, headers, body)
}

fn post_with(uri: &str, content_type: &str, body: impl Into<Body>) -> Request<Body> {
    Request::post(uri)
        .header("content-type", content_type)
        .body(body.into())
        .unwrap()
}

async fn json_of(app: Router, request: Request<Body>) -> Value {
    let (status, _, body) = send(app, request).await;
    assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
    serde_json::from_slice(&body).unwrap()
}

#[tokio::test]
async fn percent_encoded_query_tags_are_stripped() {
    let request =
        Request::get("/query?q=%3Cscript%3Ealert(1)%3C%2Fscript%3Ehi&n=%3Cb%3E2&plain=a+b")
            .body(Body::empty())
            .unwrap();
    let body = json_of(app(SanitizeConfig::new()), request).await;
    assert_eq!(body, json!({"q": "hi", "n": "2", "plain": "a b"}));
}

#[tokio::test]
async fn query_null_bytes_are_removed() {
    let request = Request::get("/query?q=a%00b").body(Body::empty()).unwrap();
    let body = json_of(app(SanitizeConfig::new()), request).await;
    assert_eq!(body, json!({"q": "ab"}));
}

#[tokio::test]
async fn json_strings_are_cleaned_recursively() {
    let request = post_with(
        "/json",
        "application/json",
        r#"{"<b>k</b>": "v", "a": [{"b": "<img src=x onerror=alert(1)>ok"}, 1.5, null], "c": "<script>x</script>"}"#,
    );
    let body = json_of(app(SanitizeConfig::new()), request).await;
    assert_eq!(
        body,
        json!({"k": "v", "a": [{"b": "ok"}, 1.5, null], "c": ""})
    );
}

#[tokio::test]
async fn vendor_json_types_are_cleaned() {
    let request = post_with(
        "/raw",
        "application/vnd.api+json; charset=utf-8",
        r#"["<b>x</b>"]"#,
    );
    let (status, _, body) = send(app(SanitizeConfig::new()), request).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(&body[..], br#"["x"]"#);
}

#[tokio::test]
async fn content_length_follows_the_rewritten_body() {
    let request = Request::post("/raw")
        .header("content-type", "text/plain")
        .header("content-length", "12")
        .body(Body::from("<b>hello</b>"))
        .unwrap();
    let (status, headers, body) = send(app(SanitizeConfig::new()), request).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(&body[..], b"hello");
    assert_eq!(headers["x-seen-length"], "5");
}

#[tokio::test]
async fn form_bodies_are_cleaned() {
    let request = post_with(
        "/form",
        "application/x-www-form-urlencoded",
        "name=%3Ci%3EAnn%3C%2Fi%3E&bio=a%00b+c",
    );
    let body = json_of(app(SanitizeConfig::new()), request).await;
    assert_eq!(body, json!({"name": "Ann", "bio": "ab c"}));
}

#[tokio::test]
async fn binary_and_multipart_pass_through_untouched() {
    for content_type in [
        "application/octet-stream",
        "multipart/form-data; boundary=x",
        "image/png",
    ] {
        let payload: &[u8] = b"\x00<b>\x00\xff\xfe";
        let request = post_with("/raw", content_type, payload);
        let (status, _, body) = send(app(SanitizeConfig::new()), request).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(&body[..], payload, "{content_type}");
    }
}

#[tokio::test]
async fn other_bodies_can_be_rejected() {
    let config = || SanitizeConfig::new().other_bodies(OtherBodies::Reject);
    let request = post_with("/raw", "application/octet-stream", "data");
    let (status, _, _) = send(app(config()), request).await;
    assert_eq!(status, StatusCode::UNSUPPORTED_MEDIA_TYPE);

    let empty = Request::get("/query?q=1").body(Body::empty()).unwrap();
    let (status, _, _) = send(app(config()), empty).await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn oversized_bodies_get_413() {
    let config = || SanitizeConfig::new().max_body_bytes(16);
    let payload = "[\"0123456789abcdef\"]";

    let declared = Request::post("/json")
        .header("content-type", "application/json")
        .header("content-length", payload.len())
        .body(Body::from(payload))
        .unwrap();
    assert_eq!(
        send(app(config()), declared).await.0,
        StatusCode::PAYLOAD_TOO_LARGE
    );

    // No Content-Length: the body is cut off while it is read.
    let undeclared = post_with("/json", "application/json", payload);
    assert_eq!(
        send(app(config()), undeclared).await.0,
        StatusCode::PAYLOAD_TOO_LARGE
    );

    // Passed-through bodies are not buffered, so not limited here.
    let binary = post_with("/raw", "application/octet-stream", vec![0u8; 64]);
    assert_eq!(send(app(config()), binary).await.0, StatusCode::OK);
}

#[tokio::test]
async fn malformed_and_deep_json_get_400() {
    for body in ["{\"a\":", "[1,]", "[\"\\ud800\"]", "\u{feff}{}"] {
        let request = post_with("/json", "application/json", body);
        assert_eq!(
            send(app(SanitizeConfig::new()), request).await.0,
            StatusCode::BAD_REQUEST,
            "{body:?}"
        );
    }
    let deep = format!("{}{}", "[".repeat(9), "]".repeat(9));
    let request = post_with("/json", "application/json", deep);
    let config = SanitizeConfig::new().max_json_depth(8);
    assert_eq!(send(app(config), request).await.0, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn invalid_utf8_text_gets_400() {
    let request = post_with("/raw", "text/plain", &b"\xff<b>"[..]);
    assert_eq!(
        send(app(SanitizeConfig::new()), request).await.0,
        StatusCode::BAD_REQUEST
    );
}

#[tokio::test]
async fn exempt_routes_are_untouched() {
    let config = SanitizeConfig::new().exempt_route("/posts/*");
    let request = post_with("/posts/1", "application/json", r#"{"html": "<b>x</b>"}"#);
    let body = json_of(app(config), request).await;
    assert_eq!(body, json!({"html": "<b>x</b>"}));
}

#[tokio::test]
async fn exempt_fields_by_json_pointer() {
    let config = SanitizeConfig::new()
        .exempt_field("/posts/*", "/content/*/html")
        .exempt_field("/form", "raw");
    let request = post_with(
        "/posts/7",
        "application/json",
        r#"{"title": "<b>T</b>", "content": [{"html": "<b>a</b>", "text": "<b>b</b>"}]}"#,
    );
    let body = json_of(app(config.clone()), request).await;
    assert_eq!(
        body,
        json!({"title": "T", "content": [{"html": "<b>a</b>", "text": "b"}]})
    );

    // The rule is per route: /json gets no exemption.
    let request = post_with(
        "/json",
        "application/json",
        r#"{"content": [{"html": "<b>a</b>"}]}"#,
    );
    let body = json_of(app(config.clone()), request).await;
    assert_eq!(body, json!({"content": [{"html": "a"}]}));

    let request = post_with(
        "/form",
        "application/x-www-form-urlencoded",
        "raw=%3Cb%3E&other=%3Cb%3E",
    );
    let body = json_of(app(config), request).await;
    assert_eq!(body, json!({"raw": "<b>", "other": ""}));
}

#[tokio::test]
async fn field_mode_overrides_the_default() {
    let config = SanitizeConfig::new().field_mode("/json", "/comment", Mode::Escape);
    let request = post_with(
        "/json",
        "application/json",
        r#"{"comment": "a<b", "name": "<i>n</i>"}"#,
    );
    let body = json_of(app(config), request).await;
    assert_eq!(body, json!({"comment": "a&lt;b", "name": "n"}));
}

#[cfg(feature = "allowlist")]
#[tokio::test]
async fn allowlist_field_keeps_safe_markup() {
    let config = SanitizeConfig::new().field_mode("/posts/*", "/body", Mode::allowlist());
    let request = post_with(
        "/posts/1",
        "application/json",
        r#"{"body": "<p onclick=x()>hi <a href='javascript:x()'>l</a></p><script>x()</script>", "title": "<p>t</p>"}"#,
    );
    let body = json_of(app(config), request).await;
    assert_eq!(body["title"], "t");
    let html = body["body"].as_str().unwrap();
    assert!(html.starts_with("<p>hi <a"), "{html}");
    assert!(
        !html.contains("javascript") && !html.contains("onclick") && !html.contains("script"),
        "{html}"
    );
}

#[tokio::test]
async fn disabled_body_kinds_pass_through() {
    let config = SanitizeConfig::new()
        .sanitize_json(false)
        .sanitize_query(false);
    let request = post_with("/raw?q=%3Cb%3E", "application/json", r#"["<b>x</b>"]"#);
    let (status, _, body) = send(app(config), request).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(&body[..], br#"["<b>x</b>"]"#);
}

#[tokio::test]
async fn clean_requests_keep_their_bytes() {
    let raw = "{ \"n\": 1.0e3,\n  \"s\": \"plain\" }";
    let request = post_with("/raw", "application/json", raw);
    let (status, headers, body) = send(app(SanitizeConfig::new()), request).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(&body[..], raw.as_bytes());
    assert_eq!(headers["x-seen-length"], "");
}
