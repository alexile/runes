//! Integration tests: errors become `application/problem+json` responses
//! whose content type, status and shape conform to RFC 9457.

#![cfg(feature = "axum")]
#![allow(clippy::unwrap_used, reason = "test helpers fail loudly")]

use axum::{
    Router,
    body::Body,
    extract::Path,
    http::{Request, StatusCode, header},
    response::{IntoResponse, Response},
    routing::get,
};
use http_body_util::BodyExt;
use rune_axum_problem::{CONTENT_TYPE_PROBLEM_JSON, IntoProblem, Problem, ProblemLayer, Problems};
use serde_json::{Value, json};
use tower::ServiceExt;

#[derive(Debug)]
enum AppError {
    NoSuchUser(u64),
    Database,
}

impl IntoProblem for AppError {
    fn into_problem(self) -> Problem {
        match self {
            Self::NoSuchUser(id) => Problem::new(StatusCode::NOT_FOUND)
                .with_type("https://example.com/probs/no-such-user")
                .with_title("No such user")
                .with_detail(format!("user {id} does not exist"))
                .with_extension("user_id", id),
            // Internal details stay out of the response.
            Self::Database => Problem::new(StatusCode::INTERNAL_SERVER_ERROR),
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        self.into_problem().into_response()
    }
}

async fn user(Path(id): Path<u64>) -> Result<String, AppError> {
    match id {
        0 => Err(AppError::NoSuchUser(id)),
        13 => Err(AppError::Database),
        _ => Ok(format!("user {id}")),
    }
}

fn app(config: Problems) -> Router {
    Router::new()
        .route("/users/{id}", get(user))
        .route("/bare", get(|| async { StatusCode::SERVICE_UNAVAILABLE }))
        .route(
            "/shed",
            get(|| async {
                (
                    StatusCode::SERVICE_UNAVAILABLE,
                    [(header::RETRY_AFTER, "5")],
                )
            }),
        )
        .route(
            "/text-error",
            get(|| async { (StatusCode::BAD_REQUEST, "plain words") }),
        )
        .route(
            "/problem",
            get(|| async { Problem::new(StatusCode::CONFLICT).with_detail("version mismatch") }),
        )
        .layer(ProblemLayer::new(config))
}

async fn send(app: Router, path: &str) -> (StatusCode, header::HeaderMap, Vec<u8>) {
    let req = Request::builder().uri(path).body(Body::empty()).unwrap();
    let res = app.oneshot(req).await.unwrap();
    let (parts, body) = res.into_parts();
    let bytes = body.collect().await.unwrap().to_bytes().to_vec();
    (parts.status, parts.headers, bytes)
}

fn assert_problem_response(headers: &header::HeaderMap, body: &[u8]) -> Value {
    assert_eq!(headers[header::CONTENT_TYPE], CONTENT_TYPE_PROBLEM_JSON);
    assert_eq!(
        headers[header::CONTENT_LENGTH],
        body.len().to_string().as_str()
    );
    let json: Value = serde_json::from_slice(body).unwrap();
    assert!(json.is_object());
    assert!(json["type"].is_string());
    json
}

#[tokio::test]
async fn app_error_maps_to_problem() {
    let (status, headers, body) = send(app(Problems::new()), "/users/0").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let json = assert_problem_response(&headers, &body);
    assert_eq!(
        json,
        json!({
            "type": "https://example.com/probs/no-such-user",
            "title": "No such user",
            "status": 404,
            "detail": "user 0 does not exist",
            "user_id": 0
        })
    );
}

#[tokio::test]
async fn internal_error_is_opaque() {
    let (status, headers, body) = send(app(Problems::new()), "/users/13").await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    let json = assert_problem_response(&headers, &body);
    assert_eq!(
        json,
        json!({"type": "about:blank", "title": "Internal Server Error", "status": 500})
    );
}

#[tokio::test]
async fn success_untouched() {
    let (status, headers, body) = send(app(Problems::new()), "/users/7").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        headers[header::CONTENT_TYPE]
            .to_str()
            .unwrap()
            .starts_with("text/plain")
    );
    assert_eq!(body, b"user 7");
}

#[tokio::test]
async fn handler_returning_problem() {
    let (status, headers, body) = send(app(Problems::new()), "/problem").await;
    assert_eq!(status, StatusCode::CONFLICT);
    let json = assert_problem_response(&headers, &body);
    assert_eq!(json["detail"], "version mismatch");
}

#[tokio::test]
async fn bare_status_converted() {
    let (status, headers, body) = send(app(Problems::new()), "/bare").await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    let json = assert_problem_response(&headers, &body);
    assert_eq!(
        json,
        json!({"type": "about:blank", "title": "Service Unavailable", "status": 503})
    );
}

#[tokio::test]
async fn bare_status_keeps_headers() {
    let (status, headers, body) = send(app(Problems::new()), "/shed").await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(headers[header::RETRY_AFTER], "5");
    assert_problem_response(&headers, &body);
}

#[tokio::test]
async fn unmatched_route_404_converted_with_instance() {
    let config = Problems::new()
        .instance_from_path(true)
        .map(|p| p.with_type("https://example.com/probs/http"));
    let (status, headers, body) = send(app(config), "/nowhere?secret=1").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let json = assert_problem_response(&headers, &body);
    assert_eq!(json["instance"], "/nowhere");
    assert_eq!(json["type"], "https://example.com/probs/http");
}

#[tokio::test]
async fn error_with_body_untouched() {
    let (status, headers, body) = send(app(Problems::new()), "/text-error").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        headers[header::CONTENT_TYPE]
            .to_str()
            .unwrap()
            .starts_with("text/plain")
    );
    assert_eq!(body, b"plain words");
}

#[tokio::test]
async fn disabled_class_untouched() {
    let (status, headers, body) = send(app(Problems::new().server_errors(false)), "/bare").await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert!(headers.get(header::CONTENT_TYPE).is_none());
    assert_eq!(body, b"");
}
