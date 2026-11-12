//! The HAR 1.2 document model.
//!
//! One struct per object of the [HAR 1.2 specification], with the
//! specification's field names in camelCase on the wire. Every struct keeps
//! the fields it does not know, such as Chrome's `_initiator` or Charles's
//! `_charlesStatus`, in [`Extensions`], so a document survives a read and
//! write without losing them. Deserialization is forgiving (see the crate
//! documentation); serialization writes what the specification asks for.
//!
//! [HAR 1.2 specification]: http://www.softwareishard.com/blog/har-12-spec/

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::lenient;

/// Fields a HAR object carries beyond the specification, by name.
///
/// The specification reserves names starting with `_` for such custom
/// fields; other unknown names are kept as well.
pub type Extensions = Map<String, Value>;

/// A whole HAR document: `{"log": {...}}`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
#[non_exhaustive]
pub struct Har {
    /// The log, the document's only standard field.
    #[serde(deserialize_with = "lenient::or_default")]
    pub log: Log,
    /// Unknown top-level fields.
    #[serde(flatten)]
    pub extra: Extensions,
}

impl Har {
    /// Wraps a log in a document.
    #[must_use]
    pub fn new(log: Log) -> Self {
        Self {
            log,
            extra: Extensions::new(),
        }
    }
}

/// The root of the exported data.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
#[non_exhaustive]
pub struct Log {
    /// Format version, `1.2` for files this crate writes.
    #[serde(deserialize_with = "lenient::string")]
    pub version: String,
    /// The application that wrote the file.
    #[serde(deserialize_with = "lenient::or_default")]
    pub creator: Creator,
    /// The browser the traffic was captured in.
    #[serde(
        deserialize_with = "lenient::opt_struct",
        skip_serializing_if = "Option::is_none"
    )]
    pub browser: Option<Creator>,
    /// Pages the entries belong to.
    #[serde(
        deserialize_with = "lenient::list",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub pages: Vec<Page>,
    /// Requests in the order they were exported.
    #[serde(deserialize_with = "lenient::list")]
    pub entries: Vec<Entry>,
    /// Comment from the user or the application.
    #[serde(
        deserialize_with = "lenient::opt_string",
        skip_serializing_if = "Option::is_none"
    )]
    pub comment: Option<String>,
    /// Unknown fields.
    #[serde(flatten)]
    pub extra: Extensions,
}

impl Default for Log {
    fn default() -> Self {
        Self {
            version: crate::HAR_VERSION.to_owned(),
            creator: Creator::default(),
            browser: None,
            pages: Vec::new(),
            entries: Vec::new(),
            comment: None,
            extra: Extensions::new(),
        }
    }
}

impl Log {
    /// An empty version 1.2 log written by `creator`.
    #[must_use]
    pub fn new(creator: Creator) -> Self {
        Self {
            creator,
            ..Self::default()
        }
    }
}

/// The application (`creator`) or browser (`browser`) behind a log.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
#[non_exhaustive]
pub struct Creator {
    /// Application name.
    #[serde(deserialize_with = "lenient::string")]
    pub name: String,
    /// Application version.
    #[serde(deserialize_with = "lenient::string")]
    pub version: String,
    /// Comment.
    #[serde(
        deserialize_with = "lenient::opt_string",
        skip_serializing_if = "Option::is_none"
    )]
    pub comment: Option<String>,
    /// Unknown fields.
    #[serde(flatten)]
    pub extra: Extensions,
}

impl Creator {
    /// A creator with a name and a version.
    #[must_use]
    pub fn new(name: impl Into<String>, version: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            version: version.into(),
            comment: None,
            extra: Extensions::new(),
        }
    }
}

/// A page whose load issued some of the entries.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
#[non_exhaustive]
pub struct Page {
    /// When the page load started (ISO 8601).
    #[serde(deserialize_with = "lenient::string")]
    pub started_date_time: String,
    /// Page id, referenced by [`Entry::pageref`].
    #[serde(deserialize_with = "lenient::string")]
    pub id: String,
    /// Page title.
    #[serde(deserialize_with = "lenient::string")]
    pub title: String,
    /// Load milestones.
    #[serde(deserialize_with = "lenient::or_default")]
    pub page_timings: PageTimings,
    /// Comment.
    #[serde(
        deserialize_with = "lenient::opt_string",
        skip_serializing_if = "Option::is_none"
    )]
    pub comment: Option<String>,
    /// Unknown fields.
    #[serde(flatten)]
    pub extra: Extensions,
}

/// Page load milestones, in milliseconds since the page load started.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
#[non_exhaustive]
pub struct PageTimings {
    /// When the content finished loading (`DOMContentLoaded`); `-1` or
    /// absent when unknown.
    #[serde(
        deserialize_with = "lenient::opt_number",
        serialize_with = "lenient::write_opt_number",
        skip_serializing_if = "Option::is_none"
    )]
    pub on_content_load: Option<f64>,
    /// When the page finished loading (`load`); `-1` or absent when unknown.
    #[serde(
        deserialize_with = "lenient::opt_number",
        serialize_with = "lenient::write_opt_number",
        skip_serializing_if = "Option::is_none"
    )]
    pub on_load: Option<f64>,
    /// Comment.
    #[serde(
        deserialize_with = "lenient::opt_string",
        skip_serializing_if = "Option::is_none"
    )]
    pub comment: Option<String>,
    /// Unknown fields.
    #[serde(flatten)]
    pub extra: Extensions,
}

/// One request and its response.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
#[non_exhaustive]
pub struct Entry {
    /// Id of the [`Page`] this entry belongs to.
    #[serde(
        deserialize_with = "lenient::opt_string",
        skip_serializing_if = "Option::is_none"
    )]
    pub pageref: Option<String>,
    /// When the request started (ISO 8601).
    #[serde(deserialize_with = "lenient::string")]
    pub started_date_time: String,
    /// Total elapsed time in milliseconds.
    #[serde(
        deserialize_with = "lenient::number_or_zero",
        serialize_with = "lenient::write_number"
    )]
    pub time: f64,
    /// The request.
    #[serde(deserialize_with = "lenient::or_default")]
    pub request: Request,
    /// The response; status `0` when none arrived.
    #[serde(deserialize_with = "lenient::or_default")]
    pub response: Response,
    /// Cache state around the request.
    #[serde(deserialize_with = "lenient::or_default")]
    pub cache: Cache,
    /// Per-phase timings.
    #[serde(deserialize_with = "lenient::or_default")]
    pub timings: Timings,
    /// IP address of the server, verbatim (Chrome brackets IPv6: `[::1]`).
    #[serde(
        rename = "serverIPAddress",
        deserialize_with = "lenient::opt_string",
        skip_serializing_if = "Option::is_none"
    )]
    pub server_ip_address: Option<String>,
    /// Id of the TCP/IP connection.
    #[serde(
        deserialize_with = "lenient::opt_string",
        skip_serializing_if = "Option::is_none"
    )]
    pub connection: Option<String>,
    /// Comment.
    #[serde(
        deserialize_with = "lenient::opt_string",
        skip_serializing_if = "Option::is_none"
    )]
    pub comment: Option<String>,
    /// Unknown fields.
    #[serde(flatten)]
    pub extra: Extensions,
}

/// A recorded request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
#[non_exhaustive]
pub struct Request {
    /// Request method.
    #[serde(deserialize_with = "lenient::string")]
    pub method: String,
    /// Absolute URL, fragments excluded.
    #[serde(deserialize_with = "lenient::string")]
    pub url: String,
    /// Protocol version as written by the exporter (`HTTP/1.1`, `http/2.0`, `h3`).
    #[serde(deserialize_with = "lenient::string")]
    pub http_version: String,
    /// Cookies sent.
    #[serde(deserialize_with = "lenient::list")]
    pub cookies: Vec<Cookie>,
    /// Header fields in order.
    #[serde(deserialize_with = "lenient::list")]
    pub headers: Vec<NameValue>,
    /// Query parameters parsed from the URL.
    #[serde(deserialize_with = "lenient::list")]
    pub query_string: Vec<NameValue>,
    /// Posted data.
    #[serde(
        deserialize_with = "lenient::opt_struct",
        skip_serializing_if = "Option::is_none"
    )]
    pub post_data: Option<PostData>,
    /// Bytes from the start of the request to the body, `-1` if unknown.
    #[serde(deserialize_with = "lenient::int_or_unknown")]
    pub headers_size: i64,
    /// Body bytes, `-1` if unknown.
    #[serde(deserialize_with = "lenient::int_or_unknown")]
    pub body_size: i64,
    /// Comment.
    #[serde(
        deserialize_with = "lenient::opt_string",
        skip_serializing_if = "Option::is_none"
    )]
    pub comment: Option<String>,
    /// Unknown fields.
    #[serde(flatten)]
    pub extra: Extensions,
}

impl Default for Request {
    fn default() -> Self {
        Self {
            method: String::new(),
            url: String::new(),
            http_version: String::new(),
            cookies: Vec::new(),
            headers: Vec::new(),
            query_string: Vec::new(),
            post_data: None,
            headers_size: -1,
            body_size: -1,
            comment: None,
            extra: Extensions::new(),
        }
    }
}

/// A recorded response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
#[non_exhaustive]
pub struct Response {
    /// Status code; `0` when no response arrived.
    #[serde(deserialize_with = "lenient::int_or_zero")]
    pub status: i64,
    /// Reason phrase.
    #[serde(deserialize_with = "lenient::string")]
    pub status_text: String,
    /// Protocol version as written by the exporter.
    #[serde(deserialize_with = "lenient::string")]
    pub http_version: String,
    /// Cookies set.
    #[serde(deserialize_with = "lenient::list")]
    pub cookies: Vec<Cookie>,
    /// Header fields in order.
    #[serde(deserialize_with = "lenient::list")]
    pub headers: Vec<NameValue>,
    /// The response body.
    #[serde(deserialize_with = "lenient::or_default")]
    pub content: Content,
    /// Target of a redirect (`Location`).
    #[serde(rename = "redirectURL", deserialize_with = "lenient::string")]
    pub redirect_url: String,
    /// Bytes from the start of the response to the body, `-1` if unknown.
    #[serde(deserialize_with = "lenient::int_or_unknown")]
    pub headers_size: i64,
    /// Body bytes received (after any transfer coding), `-1` if unknown.
    #[serde(deserialize_with = "lenient::int_or_unknown")]
    pub body_size: i64,
    /// Comment.
    #[serde(
        deserialize_with = "lenient::opt_string",
        skip_serializing_if = "Option::is_none"
    )]
    pub comment: Option<String>,
    /// Unknown fields, e.g. Chrome's `_error` for failed requests.
    #[serde(flatten)]
    pub extra: Extensions,
}

impl Default for Response {
    fn default() -> Self {
        Self {
            status: 0,
            status_text: String::new(),
            http_version: String::new(),
            cookies: Vec::new(),
            headers: Vec::new(),
            content: Content::default(),
            redirect_url: String::new(),
            headers_size: -1,
            body_size: -1,
            comment: None,
            extra: Extensions::new(),
        }
    }
}

/// A cookie sent or set.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
#[non_exhaustive]
pub struct Cookie {
    /// Cookie name.
    #[serde(deserialize_with = "lenient::string")]
    pub name: String,
    /// Cookie value.
    #[serde(deserialize_with = "lenient::string")]
    pub value: String,
    /// `Path` attribute.
    #[serde(
        deserialize_with = "lenient::opt_string",
        skip_serializing_if = "Option::is_none"
    )]
    pub path: Option<String>,
    /// `Domain` attribute.
    #[serde(
        deserialize_with = "lenient::opt_string",
        skip_serializing_if = "Option::is_none"
    )]
    pub domain: Option<String>,
    /// Expiry (ISO 8601 per the specification; exporters vary).
    #[serde(
        deserialize_with = "lenient::opt_string",
        skip_serializing_if = "Option::is_none"
    )]
    pub expires: Option<String>,
    /// `HttpOnly` attribute.
    #[serde(
        deserialize_with = "lenient::opt_bool",
        skip_serializing_if = "Option::is_none"
    )]
    pub http_only: Option<bool>,
    /// `Secure` attribute.
    #[serde(
        deserialize_with = "lenient::opt_bool",
        skip_serializing_if = "Option::is_none"
    )]
    pub secure: Option<bool>,
    /// Comment.
    #[serde(
        deserialize_with = "lenient::opt_string",
        skip_serializing_if = "Option::is_none"
    )]
    pub comment: Option<String>,
    /// Unknown fields, e.g. `sameSite`.
    #[serde(flatten)]
    pub extra: Extensions,
}

/// A header field or query parameter.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
#[non_exhaustive]
pub struct NameValue {
    /// Name.
    #[serde(deserialize_with = "lenient::string")]
    pub name: String,
    /// Value.
    #[serde(deserialize_with = "lenient::string")]
    pub value: String,
    /// Comment.
    #[serde(
        deserialize_with = "lenient::opt_string",
        skip_serializing_if = "Option::is_none"
    )]
    pub comment: Option<String>,
    /// Unknown fields.
    #[serde(flatten)]
    pub extra: Extensions,
}

impl NameValue {
    /// A pair with no comment.
    #[must_use]
    pub fn new(name: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            value: value.into(),
            comment: None,
            extra: Extensions::new(),
        }
    }
}

/// A request body.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
#[non_exhaustive]
pub struct PostData {
    /// MIME type of the body.
    #[serde(deserialize_with = "lenient::string")]
    pub mime_type: String,
    /// Posted parameters, for form bodies.
    #[serde(
        deserialize_with = "lenient::list",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub params: Vec<Param>,
    /// The body as text.
    #[serde(
        deserialize_with = "lenient::opt_string",
        skip_serializing_if = "Option::is_none"
    )]
    pub text: Option<String>,
    /// `base64` when [`text`](Self::text) is base64-encoded. Not in HAR 1.2,
    /// but written by several exporters (some as `_encoding`, which this
    /// crate also reads).
    #[serde(
        deserialize_with = "lenient::opt_string",
        skip_serializing_if = "Option::is_none"
    )]
    pub encoding: Option<String>,
    /// Comment.
    #[serde(
        deserialize_with = "lenient::opt_string",
        skip_serializing_if = "Option::is_none"
    )]
    pub comment: Option<String>,
    /// Unknown fields.
    #[serde(flatten)]
    pub extra: Extensions,
}

/// A posted parameter.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
#[non_exhaustive]
pub struct Param {
    /// Parameter name.
    #[serde(deserialize_with = "lenient::string")]
    pub name: String,
    /// Parameter value, or file content.
    #[serde(
        deserialize_with = "lenient::opt_string",
        skip_serializing_if = "Option::is_none"
    )]
    pub value: Option<String>,
    /// Name of a posted file.
    #[serde(
        deserialize_with = "lenient::opt_string",
        skip_serializing_if = "Option::is_none"
    )]
    pub file_name: Option<String>,
    /// Content type of a posted file.
    #[serde(
        deserialize_with = "lenient::opt_string",
        skip_serializing_if = "Option::is_none"
    )]
    pub content_type: Option<String>,
    /// Comment.
    #[serde(
        deserialize_with = "lenient::opt_string",
        skip_serializing_if = "Option::is_none"
    )]
    pub comment: Option<String>,
    /// Unknown fields.
    #[serde(flatten)]
    pub extra: Extensions,
}

/// A response body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
#[non_exhaustive]
pub struct Content {
    /// Length of the returned content in bytes (decoded, before any
    /// truncation by the exporter).
    #[serde(deserialize_with = "lenient::int_or_zero")]
    pub size: i64,
    /// Bytes saved by compression.
    #[serde(
        deserialize_with = "lenient::opt_int",
        skip_serializing_if = "Option::is_none"
    )]
    pub compression: Option<i64>,
    /// MIME type of the body.
    #[serde(deserialize_with = "lenient::string")]
    pub mime_type: String,
    /// The body, as text or base64 (see [`encoding`](Self::encoding));
    /// absent when it was not captured.
    #[serde(
        deserialize_with = "lenient::opt_string",
        skip_serializing_if = "Option::is_none"
    )]
    pub text: Option<String>,
    /// `base64` when [`text`](Self::text) is base64-encoded.
    #[serde(
        deserialize_with = "lenient::opt_string",
        skip_serializing_if = "Option::is_none"
    )]
    pub encoding: Option<String>,
    /// Comment.
    #[serde(
        deserialize_with = "lenient::opt_string",
        skip_serializing_if = "Option::is_none"
    )]
    pub comment: Option<String>,
    /// Unknown fields.
    #[serde(flatten)]
    pub extra: Extensions,
}

impl Default for Content {
    fn default() -> Self {
        Self {
            size: 0,
            compression: None,
            mime_type: String::new(),
            text: None,
            encoding: None,
            comment: None,
            extra: Extensions::new(),
        }
    }
}

/// Cache state before and after the request.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
#[non_exhaustive]
pub struct Cache {
    /// Cache entry before the request.
    #[serde(
        deserialize_with = "lenient::opt_struct",
        skip_serializing_if = "Option::is_none"
    )]
    pub before_request: Option<CacheEntry>,
    /// Cache entry after the request.
    #[serde(
        deserialize_with = "lenient::opt_struct",
        skip_serializing_if = "Option::is_none"
    )]
    pub after_request: Option<CacheEntry>,
    /// Comment.
    #[serde(
        deserialize_with = "lenient::opt_string",
        skip_serializing_if = "Option::is_none"
    )]
    pub comment: Option<String>,
    /// Unknown fields.
    #[serde(flatten)]
    pub extra: Extensions,
}

/// One cache entry.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
#[non_exhaustive]
pub struct CacheEntry {
    /// Expiry (ISO 8601).
    #[serde(
        deserialize_with = "lenient::opt_string",
        skip_serializing_if = "Option::is_none"
    )]
    pub expires: Option<String>,
    /// Last access (ISO 8601).
    #[serde(deserialize_with = "lenient::string")]
    pub last_access: String,
    /// Entity tag.
    #[serde(deserialize_with = "lenient::string")]
    pub e_tag: String,
    /// Times the entry was opened.
    #[serde(deserialize_with = "lenient::int_or_zero")]
    pub hit_count: i64,
    /// Comment.
    #[serde(
        deserialize_with = "lenient::opt_string",
        skip_serializing_if = "Option::is_none"
    )]
    pub comment: Option<String>,
    /// Unknown fields.
    #[serde(flatten)]
    pub extra: Extensions,
}

/// Per-phase timings in milliseconds; `-1` (or absent) when a phase does
/// not apply.
///
/// The specification requires `send`, `wait` and `receive`; they are
/// optional here so a file that omits them reads without inventing values.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
#[non_exhaustive]
pub struct Timings {
    /// Time queued before the request could be sent.
    #[serde(
        deserialize_with = "lenient::opt_number",
        serialize_with = "lenient::write_opt_number",
        skip_serializing_if = "Option::is_none"
    )]
    pub blocked: Option<f64>,
    /// DNS resolution.
    #[serde(
        deserialize_with = "lenient::opt_number",
        serialize_with = "lenient::write_opt_number",
        skip_serializing_if = "Option::is_none"
    )]
    pub dns: Option<f64>,
    /// TCP connection set-up, including [`ssl`](Self::ssl).
    #[serde(
        deserialize_with = "lenient::opt_number",
        serialize_with = "lenient::write_opt_number",
        skip_serializing_if = "Option::is_none"
    )]
    pub connect: Option<f64>,
    /// Sending the request.
    #[serde(
        deserialize_with = "lenient::opt_number",
        serialize_with = "lenient::write_opt_number",
        skip_serializing_if = "Option::is_none"
    )]
    pub send: Option<f64>,
    /// Waiting for the first response byte.
    #[serde(
        deserialize_with = "lenient::opt_number",
        serialize_with = "lenient::write_opt_number",
        skip_serializing_if = "Option::is_none"
    )]
    pub wait: Option<f64>,
    /// Reading the response.
    #[serde(
        deserialize_with = "lenient::opt_number",
        serialize_with = "lenient::write_opt_number",
        skip_serializing_if = "Option::is_none"
    )]
    pub receive: Option<f64>,
    /// TLS negotiation.
    #[serde(
        deserialize_with = "lenient::opt_number",
        serialize_with = "lenient::write_opt_number",
        skip_serializing_if = "Option::is_none"
    )]
    pub ssl: Option<f64>,
    /// Comment.
    #[serde(
        deserialize_with = "lenient::opt_string",
        skip_serializing_if = "Option::is_none"
    )]
    pub comment: Option<String>,
    /// Unknown fields, e.g. Chrome's `_blocked_queueing`.
    #[serde(flatten)]
    pub extra: Extensions,
}

impl Timings {
    /// The time until the first response byte: the sum of the phases up to
    /// and including `wait`, or `None` when `wait` is unknown.
    ///
    /// `ssl` is not added: the specification counts it inside `connect`.
    #[must_use]
    pub fn time_to_first_byte(&self) -> Option<f64> {
        let wait = self.wait.filter(|wait| *wait >= 0.0)?;
        let before = [self.blocked, self.dns, self.connect, self.send]
            .into_iter()
            .flatten()
            .filter(|phase| *phase >= 0.0)
            .sum::<f64>();
        Some(before + wait)
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn unknown_fields_survive() {
        let value = json!({
            "status": 200, "statusText": "OK", "httpVersion": "h2",
            "cookies": [], "headers": [],
            "content": {"size": 2, "mimeType": "text/plain", "text": "hi", "_x": 1},
            "redirectURL": "", "headersSize": -1, "bodySize": 2,
            "_transferSize": 120, "_error": null
        });
        let response: Response = serde_json::from_value(value.clone()).unwrap();
        assert_eq!(response.extra.get("_transferSize"), Some(&json!(120)));
        assert_eq!(response.content.extra.get("_x"), Some(&json!(1)));
        let again = serde_json::to_value(&response).unwrap();
        assert_eq!(again, value);
    }

    #[test]
    fn missing_and_null_fields_default() {
        let entry: Entry = serde_json::from_value(json!({
            "request": {"method": "GET", "url": "http://h/", "postData": null},
            "response": null,
            "cache": null,
            "timings": {"wait": "12.5", "send": null}
        }))
        .unwrap();
        assert_eq!(entry.request.headers_size, -1);
        assert_eq!(entry.request.post_data, None);
        assert_eq!(entry.response, Response::default());
        assert_eq!(entry.timings.wait, Some(12.5));
        assert_eq!(entry.timings.send, None);
    }

    #[test]
    fn time_to_first_byte_skips_unknown_phases() {
        let timings = Timings {
            blocked: Some(-1.0),
            dns: Some(2.0),
            connect: Some(5.0),
            ssl: Some(3.0),
            send: Some(1.0),
            wait: Some(10.0),
            receive: Some(4.0),
            ..Timings::default()
        };
        assert_eq!(timings.time_to_first_byte(), Some(18.0));
        assert_eq!(Timings::default().time_to_first_byte(), None);
    }
}
