# rune-axum-problem

> RFC 9457 problem details for Axum — application/problem+json error responses with extensions, plus a layer for bare error statuses.

[![crates.io](https://img.shields.io/crates/v/rune-axum-problem)](https://crates.io/crates/rune-axum-problem)
[![docs.rs](https://img.shields.io/docsrs/rune-axum-problem)](https://docs.rs/rune-axum-problem)
[![license](https://img.shields.io/crates/l/rune-axum-problem)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

[RFC 9457](https://www.rfc-editor.org/rfc/rfc9457) ("Problem Details for HTTP APIs", which obsoletes RFC 7807) defines a JSON object for machine-readable error responses. This crate provides:

- **`Problem`**: builds, serialises and parses problem details (`type`, `title`, `status`, `detail`, `instance` and extension members). It implements `IntoResponse` (default `axum` feature), so handlers can return `Result<T, Problem>`.
- **`IntoProblem`**: a trait for mapping your own error types onto problems.
- **`ProblemLayer`**: a Tower layer that turns bare error statuses (an empty `404` from the router, the `503` of a load shedder, the `504` of a timeout layer) into problem details, keeping the status and headers such as `Retry-After`.

## Installation

```toml
[dependencies]
rune-axum-problem = "0.1"
```

Without Axum (plain `http` + Tower): `default-features = false`.

## Usage

### Returning problems from handlers

```rust
use axum::{extract::Path, http::StatusCode, routing::get, Router};
use rune_axum_problem::Problem;

async fn user(Path(id): Path<u64>) -> Result<String, Problem> {
    Err(Problem::new(StatusCode::NOT_FOUND)
        .with_type("https://example.com/probs/no-such-user")
        .with_detail(format!("user {id} does not exist"))
        .with_extension("user_id", id))
}

let app: Router = Router::new().route("/users/{id}", get(user));
```

### Mapping your errors

```rust
use axum::{http::StatusCode, response::{IntoResponse, Response}};
use rune_axum_problem::{IntoProblem, Problem};

enum AppError { NotFound, Database }

impl IntoProblem for AppError {
    fn into_problem(self) -> Problem {
        match self {
            Self::NotFound => Problem::new(StatusCode::NOT_FOUND),
            // Keep internals out of the response body.
            Self::Database => Problem::new(StatusCode::INTERNAL_SERVER_ERROR),
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        self.into_problem().into_response()
    }
}
```

### Converting bare error statuses

```rust
use axum::{routing::get, Router};
use rune_axum_problem::{ProblemLayer, Problems};

let app: Router = Router::new()
    .route("/", get(handler))
    .layer(ProblemLayer::new(
        Problems::new()
            .instance_from_path(true)
            .map(|p| p.with_type("https://example.com/probs/http")),
    ));
```

## `ProblemLayer` configuration

| Method | Default | Description |
|--------|---------|-------------|
| `.client_errors(bool)` | `true` | Convert bare `4xx` responses. |
| `.server_errors(bool)` | `true` | Convert bare `5xx` responses. |
| `.instance_from_path(bool)` | `false` | Put the request path (never the query) in `instance`. |
| `.map(fn)` | none | Customise every generated `Problem`. |

A response is converted only when its status is an enabled error class, it has no `Content-Type`, and its body is known to be empty. Responses that already carry a body pass through untouched.

## Output

```
HTTP/1.1 403 Forbidden
content-type: application/problem+json
content-length: 212

{"type":"https://example.com/probs/out-of-credit","title":"You do not have enough credit.","status":403,"detail":"Your current balance is 30, but that costs 50.","instance":"/account/12345/msgs/abc","balance":30}
```

Parsing (`Problem::from_json`) follows RFC 9457 §3.1: a standard member with the wrong JSON type is ignored rather than rejected, and every other member is kept as an extension.

## License

MIT
