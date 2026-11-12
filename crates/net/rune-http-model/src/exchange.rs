//! Exchanges: one request, its outcome, and how it got there.

use std::fmt;

use crate::{HttpRequest, HttpResponse};

/// How long an exchange took, in whole milliseconds.
///
/// The two fields are a stable shape that callers build with struct
/// literals; finer per-phase timings belong to the formats that carry them.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "serde", serde(default))]
pub struct Timings {
    /// Milliseconds until the response headers arrived, when measured.
    pub time_to_headers_milliseconds: Option<u64>,
    /// Milliseconds for the whole exchange.
    pub total_milliseconds: u64,
}

impl Timings {
    /// Timings with only the total measured.
    #[must_use]
    pub const fn new(total_milliseconds: u64) -> Self {
        Self {
            time_to_headers_milliseconds: None,
            total_milliseconds,
        }
    }

    /// Timings from a measured total duration, saturating at `u64::MAX`
    /// milliseconds.
    #[must_use]
    pub fn from_duration(total: std::time::Duration) -> Self {
        Self::new(duration_milliseconds(total))
    }

    /// Records when the response headers arrived.
    #[must_use]
    pub const fn with_time_to_headers(mut self, milliseconds: u64) -> Self {
        self.time_to_headers_milliseconds = Some(milliseconds);
        self
    }
}

/// Whole milliseconds in `duration`, saturating at `u64::MAX`.
fn duration_milliseconds(duration: std::time::Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

/// Monotonic id of an exchange within one producer.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "serde", serde(transparent))]
pub struct ExchangeId(pub u64);

impl ExchangeId {
    /// The id as a number.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }

    /// The id after this one, or `None` when the ids are exhausted.
    #[must_use]
    pub const fn next(self) -> Option<Self> {
        match self.0.checked_add(1) {
            Some(next) => Some(Self(next)),
            None => None,
        }
    }
}

impl From<u64> for ExchangeId {
    fn from(id: u64) -> Self {
        Self(id)
    }
}

impl From<ExchangeId> for u64 {
    fn from(id: ExchangeId) -> Self {
        id.0
    }
}

impl fmt::Display for ExchangeId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}", self.0)
    }
}

/// One redirect hop that was followed.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
pub struct RedirectHop {
    /// Status code of the redirect response.
    pub status: u16,
    /// `Location` the redirect pointed to, verbatim.
    pub location: String,
}

impl RedirectHop {
    /// Creates a hop.
    #[must_use]
    pub fn new(status: u16, location: impl Into<String>) -> Self {
        Self {
            status,
            location: location.into(),
        }
    }
}

/// One request and its outcome, recorded by any tool.
///
/// An exchange either got a [`response`](Self::response), or carries the
/// transport [`error`](Self::error) or refusal reason that stopped it.
///
/// ```
/// use rune_http_model::{ExchangeId, HttpExchange, HttpRequest, HttpResponse, Timings};
///
/// let exchange = HttpExchange::new(ExchangeId(1), "proxy", HttpRequest::get("http://h/"))
///     .with_response(HttpResponse::new(204))
///     .with_timings(Timings::new(12).with_time_to_headers(9));
/// assert_eq!(exchange.status(), Some(204));
/// assert!(exchange.responded());
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[non_exhaustive]
pub struct HttpExchange {
    /// Id of the exchange within its producer.
    pub id: ExchangeId,
    /// Producing tool, e.g. `workbench`, `proxy` or `scan-engine`.
    pub tool: String,
    /// When the request started, in milliseconds since the Unix epoch.
    pub started_at_unix_milliseconds: u64,
    /// The request as actually sent.
    pub request: HttpRequest,
    /// The final response, if one arrived.
    pub response: Option<HttpResponse>,
    /// Transport error or refusal reason, if the exchange failed.
    #[cfg_attr(feature = "serde", serde(default))]
    pub error: Option<String>,
    /// Redirect hops followed before the final response.
    #[cfg_attr(feature = "serde", serde(default))]
    pub redirect_chain: Vec<RedirectHop>,
    /// How long the exchange took.
    #[cfg_attr(feature = "serde", serde(default))]
    pub timings: Timings,
    /// Remote socket address that served the response, when known.
    #[cfg_attr(feature = "serde", serde(default))]
    pub remote_address: Option<String>,
    /// Free-form label.
    #[cfg_attr(feature = "serde", serde(default))]
    pub label: Option<String>,
    /// Free-form tags.
    #[cfg_attr(feature = "serde", serde(default))]
    pub tags: Vec<String>,
    /// Free-form notes.
    #[cfg_attr(feature = "serde", serde(default))]
    pub notes: Option<String>,
}

impl HttpExchange {
    /// Creates an exchange for `request` with no outcome yet.
    #[must_use]
    pub fn new(id: ExchangeId, tool: impl Into<String>, request: HttpRequest) -> Self {
        Self {
            id,
            tool: tool.into(),
            started_at_unix_milliseconds: 0,
            request,
            response: None,
            error: None,
            redirect_chain: Vec::new(),
            timings: Timings::default(),
            remote_address: None,
            label: None,
            tags: Vec::new(),
            notes: None,
        }
    }

    /// Sets the final response.
    #[must_use]
    pub fn with_response(mut self, response: HttpResponse) -> Self {
        self.response = Some(response);
        self
    }

    /// Sets the transport error or refusal reason.
    #[must_use]
    pub fn with_error(mut self, error: impl Into<String>) -> Self {
        self.error = Some(error.into());
        self
    }

    /// Sets the timings.
    #[must_use]
    pub const fn with_timings(mut self, timings: Timings) -> Self {
        self.timings = timings;
        self
    }

    /// Sets the start time in milliseconds since the Unix epoch.
    #[must_use]
    pub const fn with_started_at(mut self, unix_milliseconds: u64) -> Self {
        self.started_at_unix_milliseconds = unix_milliseconds;
        self
    }

    /// Sets the start time from a [`SystemTime`](std::time::SystemTime).
    ///
    /// Times before the Unix epoch record as `0`.
    #[must_use]
    pub fn with_started_at_time(self, time: std::time::SystemTime) -> Self {
        let milliseconds = time
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, duration_milliseconds);
        self.with_started_at(milliseconds)
    }

    /// Sets the label.
    #[must_use]
    pub fn with_label(mut self, label: impl Into<String>) -> Self {
        self.label = Some(label.into());
        self
    }

    /// Adds a tag.
    #[must_use]
    pub fn with_tag(mut self, tag: impl Into<String>) -> Self {
        self.tags.push(tag.into());
        self
    }

    /// Sets the notes.
    #[must_use]
    pub fn with_notes(mut self, notes: impl Into<String>) -> Self {
        self.notes = Some(notes.into());
        self
    }

    /// Sets the remote socket address.
    #[must_use]
    pub fn with_remote_address(mut self, address: impl Into<String>) -> Self {
        self.remote_address = Some(address.into());
        self
    }

    /// Sets the followed redirect hops.
    #[must_use]
    pub fn with_redirect_chain(mut self, chain: Vec<RedirectHop>) -> Self {
        self.redirect_chain = chain;
        self
    }

    /// Appends a followed redirect hop.
    #[must_use]
    pub fn with_redirect(mut self, hop: RedirectHop) -> Self {
        self.redirect_chain.push(hop);
        self
    }

    /// Status code of the final response, if one arrived.
    #[must_use]
    pub fn status(&self) -> Option<u16> {
        self.response.as_ref().map(|response| response.status)
    }

    /// Whether a response arrived.
    #[must_use]
    pub const fn responded(&self) -> bool {
        self.response.is_some()
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, UNIX_EPOCH};

    use super::*;
    use crate::{HttpBody, HttpVersion};

    fn sample() -> HttpExchange {
        let request = HttpRequest::new("post", "http://example.test/a?b=1")
            .with_header("Content-Type", "application/json")
            .with_body(HttpBody::from_text("{\"k\":1}"))
            .with_version(HttpVersion::Http2)
            .with_raw(HttpBody::new(b"POST /a HTTP/2\r\n\r\n".to_vec()));
        let response = HttpResponse::new(200)
            .with_reason("OK")
            .with_header("content-type", "text/html")
            .with_body(HttpBody::new(vec![0x00, 0xff]));
        HttpExchange::new(ExchangeId(7), "workbench", request)
            .with_response(response)
            .with_started_at(1_700_000_000_000)
            .with_timings(Timings {
                time_to_headers_milliseconds: Some(5),
                total_milliseconds: 9,
            })
            .with_label("login")
            .with_tag("auth")
            .with_notes("n")
            .with_remote_address("127.0.0.1:80")
            .with_redirect_chain(vec![RedirectHop {
                status: 302,
                location: "/a".to_owned(),
            }])
    }

    #[test]
    fn builders_and_accessors() {
        let exchange = sample();
        assert_eq!(exchange.status(), Some(200));
        assert!(exchange.responded());
        assert_eq!(exchange.id.to_string(), "7");
        let failed = HttpExchange::new(ExchangeId(8), "t", HttpRequest::get("http://h/"))
            .with_error("connection refused")
            .with_redirect(RedirectHop::new(301, "/x"));
        assert_eq!(failed.status(), None);
        assert!(!failed.responded());
        assert_eq!(failed.redirect_chain, [RedirectHop::new(301, "/x")]);
    }

    #[test]
    fn started_at_from_system_time() {
        let at = UNIX_EPOCH + Duration::from_millis(1_234);
        let exchange =
            HttpExchange::new(ExchangeId(0), "t", HttpRequest::get("/")).with_started_at_time(at);
        assert_eq!(exchange.started_at_unix_milliseconds, 1_234);
        let before = UNIX_EPOCH
            .checked_sub(Duration::from_secs(1))
            .unwrap_or(UNIX_EPOCH);
        let exchange = exchange.with_started_at_time(before);
        assert_eq!(exchange.started_at_unix_milliseconds, 0);
    }

    #[test]
    fn timings_helpers() {
        assert_eq!(
            Timings::from_duration(Duration::from_micros(2_500)),
            Timings::new(2)
        );
        assert_eq!(
            Timings::from_duration(Duration::MAX).total_milliseconds,
            u64::MAX
        );
        assert_eq!(
            Timings::new(9).with_time_to_headers(5),
            Timings {
                time_to_headers_milliseconds: Some(5),
                total_milliseconds: 9,
            }
        );
    }

    #[test]
    fn exchange_id_helpers() {
        assert_eq!(ExchangeId(1).next(), Some(ExchangeId(2)));
        assert_eq!(ExchangeId(u64::MAX).next(), None);
        assert_eq!(ExchangeId::from(3).get(), 3);
        assert_eq!(u64::from(ExchangeId(4)), 4);
        assert!(ExchangeId(1) < ExchangeId(2));
    }

    #[cfg(feature = "serde")]
    #[test]
    fn json_round_trip_and_shape() {
        let exchange = sample();
        let json = serde_json::to_value(&exchange).unwrap();
        assert_eq!(json["id"], 7);
        assert_eq!(json["request"]["http_version"], "http2");
        assert_eq!(json["response"]["body"]["encoding"], "base64");
        assert_eq!(json["timings"]["total_milliseconds"], 9);
        let back: HttpExchange = serde_json::from_value(json).unwrap();
        assert_eq!(back, exchange);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn minimal_json_uses_defaults() {
        let request: HttpRequest =
            serde_json::from_str(r#"{"method":"GET","url":"http://h/"}"#).unwrap();
        assert_eq!(request, HttpRequest::get("http://h/"));
        let json = serde_json::to_value(&request).unwrap();
        assert!(json.get("raw").is_none());
        let response: HttpResponse = serde_json::from_str(r#"{"status":404}"#).unwrap();
        assert_eq!(response, HttpResponse::new(404));
        let exchange: HttpExchange = serde_json::from_str(
            r#"{"id":1,"tool":"t","started_at_unix_milliseconds":5,
                "request":{"method":"GET","url":"/"},"response":null}"#,
        )
        .unwrap();
        assert_eq!(
            exchange,
            HttpExchange::new(ExchangeId(1), "t", HttpRequest::get("/")).with_started_at(5)
        );
    }

    #[cfg(feature = "schemars")]
    #[test]
    fn schemas_generate() {
        let exchange = schemars::schema_for!(HttpExchange);
        let text = serde_json::to_string(&exchange).unwrap();
        assert!(text.contains("HttpBody"));
        let body = schemars::schema_for!(HttpBody);
        let text = serde_json::to_string(&body).unwrap();
        assert!(text.contains("base64"));
    }
}
