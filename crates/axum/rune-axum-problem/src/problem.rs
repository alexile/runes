//! The [`Problem`] type and its JSON form (RFC 9457 §3).

use std::fmt;

use http::header::{CONTENT_LENGTH, CONTENT_TYPE};
use http::{HeaderValue, Response, StatusCode};
use serde::de::{Deserialize, Deserializer};
use serde::ser::{Serialize, SerializeMap, Serializer};
use serde_json::{Map, Value};

/// Media type of a JSON problem details object (RFC 9457 §6.1).
pub const CONTENT_TYPE_PROBLEM_JSON: &str = "application/problem+json";

/// The default problem type: the problem has no semantics beyond the HTTP
/// status code (RFC 9457 §4.2.1).
pub const ABOUT_BLANK: &str = "about:blank";

/// Member names defined by RFC 9457 §3.1. Extensions cannot use them.
const STANDARD_MEMBERS: [&str; 5] = ["type", "title", "status", "detail", "instance"];

/// The crate's error type.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The input is not valid JSON.
    #[error("invalid JSON: {0}")]
    Json(#[from] serde_json::Error),
    /// The JSON is valid but not an object.
    #[error("a problem details document must be a JSON object")]
    NotAnObject,
}

/// An RFC 9457 problem details object.
///
/// The five standard members are `type` (a URI reference identifying the
/// problem type, default `about:blank`), `title`, `status`, `detail` and
/// `instance`. Any other member is an *extension*; extensions serialise
/// after the standard members, ordered by name.
///
/// A `Problem` serialises to `application/problem+json` with
/// [`to_json`](Self::to_json) or `serde`, becomes an HTTP response with
/// [`to_response`](Self::to_response) (or `IntoResponse` with the `axum`
/// feature), and parses back with [`from_json`](Self::from_json), which
/// follows the RFC's rule that members of the wrong type are ignored.
///
/// # Examples
///
/// ```rust
/// use http::StatusCode;
/// use rune_axum_problem::Problem;
///
/// let problem = Problem::new(StatusCode::FORBIDDEN)
///     .with_type("https://example.com/probs/out-of-credit")
///     .with_title("You do not have enough credit.")
///     .with_detail("Your current balance is 30, but that costs 50.")
///     .with_instance("/account/12345/msgs/abc")
///     .with_extension("balance", 30)
///     .with_extension("accounts", ["/account/12345", "/account/67890"]);
///
/// let json: serde_json::Value = serde_json::from_slice(&problem.to_json()).unwrap();
/// assert_eq!(json["status"], 403);
/// assert_eq!(json["balance"], 30);
/// assert_eq!(Problem::from_json(&problem.to_json()).unwrap(), problem);
/// ```
#[derive(Clone, Debug, PartialEq)]
#[non_exhaustive]
pub struct Problem {
    type_uri: String,
    title: Option<String>,
    status: Option<StatusCode>,
    detail: Option<String>,
    instance: Option<String>,
    extensions: Map<String, Value>,
}

impl Default for Problem {
    /// An `about:blank` problem with no other members.
    fn default() -> Self {
        Self {
            type_uri: ABOUT_BLANK.to_owned(),
            title: None,
            status: None,
            detail: None,
            instance: None,
            extensions: Map::new(),
        }
    }
}

impl Problem {
    /// An `about:blank` problem for `status`, titled with the status's
    /// canonical reason phrase as RFC 9457 §4.2.1 recommends.
    #[must_use]
    pub fn new(status: StatusCode) -> Self {
        Self {
            title: status.canonical_reason().map(str::to_owned),
            status: Some(status),
            ..Self::default()
        }
    }

    /// Sets the problem type URI. Use an absolute URI that, ideally,
    /// dereferences to human-readable documentation (RFC 9457 §3.1.1).
    #[must_use]
    pub fn with_type(mut self, uri: impl Into<String>) -> Self {
        self.type_uri = uri.into();
        self
    }

    /// Sets the short, human-readable summary of the problem type.
    #[must_use]
    pub fn with_title(mut self, title: impl Into<String>) -> Self {
        self.title = Some(title.into());
        self
    }

    /// Sets the HTTP status code of this occurrence. It also becomes the
    /// response status in [`to_response`](Self::to_response).
    #[must_use]
    pub const fn with_status(mut self, status: StatusCode) -> Self {
        self.status = Some(status);
        self
    }

    /// Sets the human-readable explanation of this occurrence. It should
    /// help the client fix the problem, not carry debugging detail.
    #[must_use]
    pub fn with_detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(detail.into());
        self
    }

    /// Sets the URI reference identifying this occurrence.
    #[must_use]
    pub fn with_instance(mut self, instance: impl Into<String>) -> Self {
        self.instance = Some(instance.into());
        self
    }

    /// Adds an extension member. Setting the same name twice keeps the last
    /// value.
    ///
    /// Names of standard members (`type`, `title`, `status`, `detail`,
    /// `instance`) are ignored: use the dedicated setters. A value that
    /// cannot be represented as JSON (for example a map with non-string
    /// keys) is stored as `null`.
    #[must_use]
    pub fn with_extension(mut self, name: impl Into<String>, value: impl Serialize) -> Self {
        let name = name.into();
        if !STANDARD_MEMBERS.contains(&name.as_str()) {
            let value = serde_json::to_value(value).unwrap_or(Value::Null);
            self.extensions.insert(name, value);
        }
        self
    }

    /// The problem type URI (`about:blank` unless set).
    #[must_use]
    pub fn type_uri(&self) -> &str {
        &self.type_uri
    }

    /// The title, if any.
    #[must_use]
    pub fn title(&self) -> Option<&str> {
        self.title.as_deref()
    }

    /// The status member, if any.
    #[must_use]
    pub const fn status(&self) -> Option<StatusCode> {
        self.status
    }

    /// The detail, if any.
    #[must_use]
    pub fn detail(&self) -> Option<&str> {
        self.detail.as_deref()
    }

    /// The instance URI reference, if any.
    #[must_use]
    pub fn instance(&self) -> Option<&str> {
        self.instance.as_deref()
    }

    /// An extension member by name.
    #[must_use]
    pub fn extension(&self, name: &str) -> Option<&Value> {
        self.extensions.get(name)
    }

    /// Every extension member, ordered by name.
    #[must_use]
    pub const fn extensions(&self) -> &Map<String, Value> {
        &self.extensions
    }

    /// The HTTP status a response carrying this problem uses: the `status`
    /// member, or `500 Internal Server Error` when it is unset.
    #[must_use]
    pub fn response_status(&self) -> StatusCode {
        self.status.unwrap_or(StatusCode::INTERNAL_SERVER_ERROR)
    }

    /// Serialises to compact `application/problem+json` bytes.
    #[must_use]
    pub fn to_json(&self) -> Vec<u8> {
        // Every member is a string, a number or a `serde_json::Value`, so
        // serialisation cannot fail; fall back to an empty object regardless.
        serde_json::to_vec(self).unwrap_or_else(|_| b"{}".to_vec())
    }

    /// Parses a problem details document.
    ///
    /// Per RFC 9457 §3.1, a standard member whose value has the wrong type
    /// is ignored rather than rejected: a non-string `type` falls back to
    /// `about:blank`, and a `status` that is not an integer HTTP status code
    /// is dropped. Every non-standard member becomes an extension.
    ///
    /// # Errors
    ///
    /// [`Error::Json`] for malformed JSON and [`Error::NotAnObject`] when
    /// the top-level value is not an object.
    pub fn from_json(input: &[u8]) -> Result<Self, Error> {
        match serde_json::from_slice(input)? {
            Value::Object(map) => Ok(Self::from_map(map)),
            _ => Err(Error::NotAnObject),
        }
    }

    fn from_map(map: Map<String, Value>) -> Self {
        let mut problem = Self::default();
        for (name, value) in map {
            match (name.as_str(), value) {
                ("type", Value::String(s)) => problem.type_uri = s,
                ("title", Value::String(s)) => problem.title = Some(s),
                ("detail", Value::String(s)) => problem.detail = Some(s),
                ("instance", Value::String(s)) => problem.instance = Some(s),
                ("status", Value::Number(n)) => {
                    problem.status = n
                        .as_u64()
                        .and_then(|n| u16::try_from(n).ok())
                        .and_then(|n| StatusCode::from_u16(n).ok());
                }
                (name, _) if STANDARD_MEMBERS.contains(&name) => {}
                (_, value) => {
                    problem.extensions.insert(name, value);
                }
            }
        }
        problem
    }

    /// Builds the HTTP response: status from
    /// [`response_status`](Self::response_status), `Content-Type:
    /// application/problem+json`, `Content-Length` and the JSON body.
    #[must_use]
    pub fn to_response<B: From<Vec<u8>>>(&self) -> Response<B> {
        let body = self.to_json();
        let mut response = Response::new(B::from(Vec::new()));
        *response.status_mut() = self.response_status();
        let headers = response.headers_mut();
        headers.insert(
            CONTENT_TYPE,
            HeaderValue::from_static(CONTENT_TYPE_PROBLEM_JSON),
        );
        headers.insert(CONTENT_LENGTH, HeaderValue::from(body.len()));
        *response.body_mut() = B::from(body);
        response
    }
}

impl From<StatusCode> for Problem {
    fn from(status: StatusCode) -> Self {
        Self::new(status)
    }
}

impl fmt::Display for Problem {
    /// `title: detail`, or whichever of the two is present, or the type URI.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match (&self.title, &self.detail) {
            (Some(t), Some(d)) => write!(f, "{t}: {d}"),
            (Some(s), None) | (None, Some(s)) => f.write_str(s),
            (None, None) => f.write_str(&self.type_uri),
        }
    }
}

impl std::error::Error for Problem {}

impl Serialize for Problem {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(None)?;
        map.serialize_entry("type", &self.type_uri)?;
        if let Some(title) = &self.title {
            map.serialize_entry("title", title)?;
        }
        if let Some(status) = self.status {
            map.serialize_entry("status", &status.as_u16())?;
        }
        if let Some(detail) = &self.detail {
            map.serialize_entry("detail", detail)?;
        }
        if let Some(instance) = &self.instance {
            map.serialize_entry("instance", instance)?;
        }
        for (name, value) in &self.extensions {
            // `from_map` and `with_extension` never store standard names.
            if !STANDARD_MEMBERS.contains(&name.as_str()) {
                map.serialize_entry(name, value)?;
            }
        }
        map.end()
    }
}

impl<'de> Deserialize<'de> for Problem {
    /// Lenient like [`Problem::from_json`]: wrong-typed standard members
    /// are ignored. Fails only when the input is not an object.
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Map::<String, Value>::deserialize(deserializer).map(Self::from_map)
    }
}

/// Conversion of an application error into a [`Problem`].
///
/// Implement it for your error types to choose the problem type, status and
/// the details clients see; [`IntoProblem::into_problem`] is then a one-liner
/// in handlers (`.map_err(IntoProblem::into_problem)?`).
///
/// # Examples
///
/// ```rust
/// use http::StatusCode;
/// use rune_axum_problem::{IntoProblem, Problem};
///
/// enum OrderError { NotFound(u64), OutOfStock }
///
/// impl IntoProblem for OrderError {
///     fn into_problem(self) -> Problem {
///         match self {
///             Self::NotFound(id) => Problem::new(StatusCode::NOT_FOUND)
///                 .with_detail(format!("order {id} does not exist")),
///             Self::OutOfStock => Problem::new(StatusCode::CONFLICT)
///                 .with_type("https://example.com/probs/out-of-stock")
///                 .with_title("Out of stock"),
///         }
///     }
/// }
///
/// assert_eq!(OrderError::NotFound(7).into_problem().status(), Some(StatusCode::NOT_FOUND));
/// ```
pub trait IntoProblem {
    /// Converts `self` into a problem details object.
    fn into_problem(self) -> Problem;
}

impl IntoProblem for Problem {
    fn into_problem(self) -> Problem {
        self
    }
}

impl IntoProblem for StatusCode {
    fn into_problem(self) -> Problem {
        Problem::new(self)
    }
}

#[cfg(feature = "axum")]
impl axum::response::IntoResponse for Problem {
    fn into_response(self) -> axum::response::Response {
        self.to_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn parse(p: &Problem) -> Value {
        serde_json::from_slice(&p.to_json()).unwrap()
    }

    #[test]
    fn rfc_example_shape() {
        // RFC 9457 §3, first example.
        let p = Problem::new(StatusCode::FORBIDDEN)
            .with_type("https://example.com/probs/out-of-credit")
            .with_title("You do not have enough credit.")
            .with_detail("Your current balance is 30, but that costs 50.")
            .with_instance("/account/12345/msgs/abc")
            .with_extension("balance", 30)
            .with_extension("accounts", ["/account/12345", "/account/67890"]);
        assert_eq!(
            parse(&p),
            json!({
                "type": "https://example.com/probs/out-of-credit",
                "title": "You do not have enough credit.",
                "status": 403,
                "detail": "Your current balance is 30, but that costs 50.",
                "instance": "/account/12345/msgs/abc",
                "balance": 30,
                "accounts": ["/account/12345", "/account/67890"]
            })
        );
    }

    #[test]
    fn standard_members_come_first() {
        let p = Problem::new(StatusCode::NOT_FOUND).with_extension("a", 1);
        let text = String::from_utf8(p.to_json()).unwrap();
        assert_eq!(
            text,
            r#"{"type":"about:blank","title":"Not Found","status":404,"a":1}"#
        );
    }

    #[test]
    fn default_is_about_blank() {
        let p = Problem::default();
        assert_eq!(p.type_uri(), ABOUT_BLANK);
        assert_eq!(parse(&p), json!({"type": "about:blank"}));
        assert_eq!(p.response_status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn status_without_reason_has_no_title() {
        let p = Problem::new(StatusCode::from_u16(599).unwrap());
        assert_eq!(p.title(), None);
        assert_eq!(parse(&p), json!({"type": "about:blank", "status": 599}));
    }

    #[test]
    fn reserved_extension_names_are_ignored() {
        let p = Problem::new(StatusCode::BAD_REQUEST)
            .with_extension("status", 200)
            .with_extension("type", "x")
            .with_extension("errors", json!([{"pointer": "#/age"}]));
        assert_eq!(p.extensions().len(), 1);
        assert_eq!(parse(&p)["status"], 400);
        assert_eq!(parse(&p)["type"], "about:blank");
    }

    #[test]
    fn extension_overwrite_keeps_last() {
        let p = Problem::default()
            .with_extension("k", 1)
            .with_extension("k", 2);
        assert_eq!(p.extension("k"), Some(&json!(2)));
    }

    #[test]
    fn unrepresentable_extension_is_null() {
        let mut m = std::collections::BTreeMap::new();
        m.insert((1, 2), "x");
        let p = Problem::default().with_extension("bad", m);
        assert_eq!(p.extension("bad"), Some(&Value::Null));
    }

    #[test]
    fn wrong_typed_members_are_ignored() {
        let p = Problem::from_json(
            br#"{"type": 5, "title": ["x"], "status": "404", "detail": null, "instance": {}, "ext": true}"#,
        )
        .unwrap();
        assert_eq!(p.type_uri(), ABOUT_BLANK);
        assert_eq!(p.title(), None);
        assert_eq!(p.status(), None);
        assert_eq!(p.detail(), None);
        assert_eq!(p.instance(), None);
        assert_eq!(p.extension("ext"), Some(&json!(true)));
    }

    #[test]
    fn out_of_range_status_is_ignored() {
        for s in ["99", "1000", "-1", "404.5", "70000"] {
            let doc = format!(r#"{{"status": {s}}}"#);
            assert_eq!(
                Problem::from_json(doc.as_bytes()).unwrap().status(),
                None,
                "{s}"
            );
        }
        let p = Problem::from_json(br#"{"status": 422}"#).unwrap();
        assert_eq!(p.status(), Some(StatusCode::UNPROCESSABLE_ENTITY));
    }

    #[test]
    fn parse_errors() {
        assert!(matches!(Problem::from_json(b"[]"), Err(Error::NotAnObject)));
        assert!(matches!(Problem::from_json(b"{"), Err(Error::Json(_))));
        assert!(serde_json::from_str::<Problem>("1").is_err());
    }

    #[test]
    fn serde_round_trip() {
        let p = Problem::new(StatusCode::CONFLICT)
            .with_detail("d")
            .with_extension("n", json!({"deep": [1, 2]}));
        let text = serde_json::to_string(&p).unwrap();
        assert_eq!(serde_json::from_str::<Problem>(&text).unwrap(), p);
    }

    #[test]
    fn response_has_media_type_and_status() {
        let p = Problem::new(StatusCode::TOO_MANY_REQUESTS).with_extension("retry", 5);
        let res: Response<Vec<u8>> = p.to_response();
        assert_eq!(res.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(res.headers()[CONTENT_TYPE], CONTENT_TYPE_PROBLEM_JSON);
        assert_eq!(
            res.headers()[CONTENT_LENGTH],
            res.body().len().to_string().as_str()
        );
        assert_eq!(Problem::from_json(res.body()).unwrap(), p);
    }

    #[test]
    fn display_and_conversions() {
        let p = Problem::from(StatusCode::NOT_FOUND);
        assert_eq!(p.to_string(), "Not Found");
        assert_eq!(
            p.clone().with_detail("no such user").to_string(),
            "Not Found: no such user"
        );
        assert_eq!(Problem::default().with_detail("d").to_string(), "d");
        assert_eq!(Problem::default().to_string(), "about:blank");
        assert_eq!(StatusCode::NOT_FOUND.into_problem(), p);
        assert_eq!(p.clone().into_problem(), p);
    }
}
