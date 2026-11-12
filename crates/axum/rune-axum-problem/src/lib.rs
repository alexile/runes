//! Problem details for HTTP APIs — RFC 9457 `application/problem+json`
//! error responses for Axum.
//!
//! [RFC 9457](https://www.rfc-editor.org/rfc/rfc9457) defines a JSON object
//! that carries machine-readable error details in an HTTP response: a
//! problem `type` URI, a `title`, the `status`, a `detail` message, an
//! `instance` URI and any number of extension members.
//!
//! - [`Problem`] builds, serialises and parses such objects. With the
//!   default `axum` feature it implements `IntoResponse`, so handlers can
//!   return `Result<T, Problem>`.
//! - [`IntoProblem`] maps your own error types onto problems.
//! - [`ProblemLayer`] turns bare error statuses (an empty `404`, the `503`
//!   of a load shedder, the `504` of a timeout layer) into problem details.
//!
//! The core is sans-I/O: building and parsing need no runtime.
//!
//! # Quick Start
//!
//! ```rust
//! use http::StatusCode;
//! use rune_axum_problem::{Problem, CONTENT_TYPE_PROBLEM_JSON};
//!
//! let problem = Problem::new(StatusCode::UNPROCESSABLE_ENTITY)
//!     .with_type("https://example.com/probs/validation")
//!     .with_detail("`age` must be a positive integer")
//!     .with_extension("errors", [("pointer", "#/age")]);
//!
//! let response: http::Response<Vec<u8>> = problem.to_response();
//! assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
//! assert_eq!(response.headers()["content-type"], CONTENT_TYPE_PROBLEM_JSON);
//!
//! let parsed = Problem::from_json(response.body())?;
//! assert_eq!(parsed.title(), Some("Unprocessable Entity"));
//! assert_eq!(parsed, problem);
//! # Ok::<(), rune_axum_problem::Error>(())
//! ```
//!
//! # Axum
//!
//! ```rust
//! use axum::{extract::Path, http::StatusCode, routing::get, Router};
//! use rune_axum_problem::{Problem, ProblemLayer};
//!
//! async fn user(Path(id): Path<u64>) -> Result<String, Problem> {
//!     if id == 0 {
//!         return Err(Problem::new(StatusCode::NOT_FOUND)
//!             .with_detail(format!("user {id} does not exist")));
//!     }
//!     Ok(format!("user {id}"))
//! }
//!
//! let app: Router = Router::new()
//!     .route("/users/{id}", get(user))
//!     // Bare error statuses from anywhere inside become problem+json too.
//!     .layer(ProblemLayer::default());
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub use layer::{ProblemLayer, ProblemService, Problems, ResponseFuture};
pub use problem::{ABOUT_BLANK, CONTENT_TYPE_PROBLEM_JSON, Error, IntoProblem, Problem};

mod layer;
mod problem;
