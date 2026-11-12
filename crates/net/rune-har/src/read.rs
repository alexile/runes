//! Reading: bytes to a [`Har`], and a [`Har`] to [`HttpExchange`]s.

use std::fmt;

use rune_http_model::{
    ExchangeId, HeaderEntry, HttpBody, HttpExchange, HttpRequest, HttpResponse, HttpVersion,
    RedirectHop, Timings,
};
use serde_json::{Map, Value};

use crate::model::{Content, Entry, Extensions, Har, Log, NameValue, Page, PostData, Request};
use crate::{HarError, ext, time};

/// Settings for turning entries into exchanges.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ReadOptions {
    /// Tool recorded on exchanges whose entry has no `_tool` field.
    pub tool: String,
    /// Keep HTTP/2 and HTTP/3 pseudo-headers (`:authority`, `:path`, …)
    /// that browsers list among the headers. Off by default: they are not
    /// header fields, and the method, URL and status already carry them.
    pub keep_pseudo_headers: bool,
    /// Read at most this many entries.
    pub max_entries: Option<usize>,
}

impl Default for ReadOptions {
    fn default() -> Self {
        Self {
            tool: "har".to_owned(),
            keep_pseudo_headers: false,
            max_entries: None,
        }
    }
}

impl ReadOptions {
    /// Sets [`ReadOptions::tool`].
    #[must_use]
    pub fn with_tool(mut self, tool: impl Into<String>) -> Self {
        self.tool = tool.into();
        self
    }

    /// Sets [`ReadOptions::keep_pseudo_headers`].
    #[must_use]
    pub const fn with_pseudo_headers(mut self, keep: bool) -> Self {
        self.keep_pseudo_headers = keep;
        self
    }

    /// Sets [`ReadOptions::max_entries`].
    #[must_use]
    pub const fn with_max_entries(mut self, max_entries: usize) -> Self {
        self.max_entries = Some(max_entries);
        self
    }
}

/// Something in the input that was skipped or repaired while reading.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Warning {
    /// Index of the entry in `log.entries`, when the warning is about one.
    pub entry: Option<usize>,
    /// Stable, machine-readable kind, e.g. `invalid_entry`.
    pub code: &'static str,
    /// Human-readable detail.
    pub message: String,
}

impl Warning {
    fn new(entry: Option<usize>, code: &'static str, message: impl Into<String>) -> Self {
        Self {
            entry,
            code,
            message: message.into(),
        }
    }
}

impl fmt::Display for Warning {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.entry {
            Some(index) => write!(formatter, "entries[{index}]: {}", self.message),
            None => formatter.write_str(&self.message),
        }
    }
}

/// A parsed HAR document and what was skipped to get it.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct Parsed {
    /// The document, without the entries and pages that could not be read.
    pub har: Har,
    /// Entries and pages that were skipped, and why.
    pub warnings: Vec<Warning>,
}

/// Exchanges read from a HAR document.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct ReadReport {
    /// One exchange per usable entry, in file order.
    pub exchanges: Vec<HttpExchange>,
    /// What was skipped or repaired.
    pub warnings: Vec<Warning>,
}

/// Takes `log.entries` or `log.pages` out of `log` as a list of raw values.
fn take_list(log: &mut Map<String, Value>, key: &str) -> Result<Vec<Value>, HarError> {
    match log.remove(key) {
        None | Some(Value::Null) => Ok(Vec::new()),
        Some(Value::Array(items)) => Ok(items),
        Some(_) => Err(HarError::NotHar(match key {
            "entries" => "`log.entries` is not an array",
            _ => "`log.pages` is not an array",
        })),
    }
}

/// Parses a HAR document, skipping entries and pages it cannot read.
///
/// The input is UTF-8 JSON (a leading byte-order mark is ignored). The
/// `log` object may also stand alone, without the `{"log": …}` wrapper.
/// Each entry and page is read on its own: one with a field of the wrong
/// shape is skipped with a [`Warning`] instead of failing the whole file.
///
/// # Errors
///
/// [`HarError::Json`] when the input is not JSON, [`HarError::NotHar`]
/// when it has no `log.entries` array.
pub fn parse(input: &[u8]) -> Result<Parsed, HarError> {
    let input = input.strip_prefix(b"\xef\xbb\xbf").unwrap_or(input);
    let document: Value =
        serde_json::from_slice(input).map_err(|error| HarError::Json(error.to_string()))?;
    let Value::Object(mut root) = document else {
        return Err(HarError::NotHar("the document is not a JSON object"));
    };
    let (mut log, root_extra) = match root.remove("log") {
        Some(Value::Object(log)) => (log, root),
        Some(_) => return Err(HarError::NotHar("`log` is not an object")),
        None if root.contains_key("entries") => (root, Extensions::new()),
        None => return Err(HarError::NotHar("no `log.entries` array")),
    };
    if !log.contains_key("entries") {
        return Err(HarError::NotHar("no `log.entries` array"));
    }
    let raw_entries = take_list(&mut log, "entries")?;
    let raw_pages = take_list(&mut log, "pages")?;
    let mut log: Log = serde_json::from_value(Value::Object(log))
        .map_err(|error| HarError::NotHar(log_error(&error)))?;

    let mut warnings = Vec::new();
    for (index, raw) in raw_pages.into_iter().enumerate() {
        match serde_json::from_value::<Page>(raw) {
            Ok(page) => log.pages.push(page),
            Err(error) => warnings.push(Warning::new(
                None,
                "invalid_page",
                format!("pages[{index}] skipped: {error}"),
            )),
        }
    }
    log.entries.reserve(raw_entries.len());
    for (index, raw) in raw_entries.into_iter().enumerate() {
        match serde_json::from_value::<Entry>(raw) {
            Ok(entry) => log.entries.push(entry),
            Err(error) => warnings.push(Warning::new(
                Some(index),
                "invalid_entry",
                format!("skipped: {error}"),
            )),
        }
    }
    let mut har = Har::new(log);
    har.extra = root_extra;
    Ok(Parsed { har, warnings })
}

/// Turns a failure to read the log's own fields into a static reason.
fn log_error(error: &serde_json::Error) -> &'static str {
    if error.to_string().contains("creator") {
        "`log.creator` is malformed"
    } else {
        "`log` has a malformed field"
    }
}

/// Parses a HAR document and reads its entries as exchanges.
///
/// Combines [`parse`] and [`Har::to_exchanges`]; the warnings of both are
/// returned together.
///
/// # Errors
///
/// As [`parse`].
pub fn read(input: &[u8], options: &ReadOptions) -> Result<ReadReport, HarError> {
    let Parsed { har, mut warnings } = parse(input)?;
    // Entry indexes in warnings and default ids refer to the file, so
    // count the entries `parse` skipped.
    let mut skipped: Vec<usize> = warnings
        .iter()
        .filter(|warning| warning.code == "invalid_entry")
        .filter_map(|warning| warning.entry)
        .collect();
    skipped.sort_unstable();
    let original = |mut index: usize| {
        for &gap in &skipped {
            if gap <= index {
                index += 1;
            }
        }
        index
    };
    let mut report = to_exchanges(&har, options, &original);
    warnings.append(&mut report.warnings);
    report.warnings = warnings;
    Ok(report)
}

impl Har {
    /// Reads the entries as exchanges.
    ///
    /// See the crate documentation for how each field maps. Entries
    /// without a method and URL are skipped with a warning; repairable
    /// problems (invalid base64, unknown timestamps) keep the entry and
    /// add a warning.
    #[must_use]
    pub fn to_exchanges(&self, options: &ReadOptions) -> ReadReport {
        to_exchanges(self, options, &|index| index)
    }
}

/// [`Har::to_exchanges`], with `original` mapping a position in
/// `log.entries` to the entry's index in the file.
fn to_exchanges(har: &Har, options: &ReadOptions, original: &dyn Fn(usize) -> usize) -> ReadReport {
    let mut report = ReadReport::default();
    let limit = options.max_entries.unwrap_or(usize::MAX);
    for (position, entry) in har.log.entries.iter().enumerate() {
        if report.exchanges.len() >= limit {
            report.warnings.push(Warning::new(
                None,
                "entry_limit",
                format!("stopped after {limit} entries"),
            ));
            break;
        }
        if let Some(exchange) = exchange(entry, original(position), options, &mut report.warnings) {
            report.exchanges.push(exchange);
        }
    }
    report
}

fn exchange(
    entry: &Entry,
    index: usize,
    options: &ReadOptions,
    warnings: &mut Vec<Warning>,
) -> Option<HttpExchange> {
    let warn = |warnings: &mut Vec<Warning>, code, message: String| {
        warnings.push(Warning::new(Some(index), code, message));
    };
    if entry.request.method.is_empty() && entry.request.url.is_empty() {
        warn(
            warnings,
            "no_request",
            "skipped: no method or URL".to_owned(),
        );
        return None;
    }
    let id = entry
        .extra
        .get(ext::ID)
        .and_then(Value::as_u64)
        .unwrap_or(index as u64);
    let tool = entry
        .extra
        .get(ext::TOOL)
        .and_then(Value::as_str)
        .unwrap_or(&options.tool);
    let request = request(&entry.request, options, &mut |code, message| {
        warn(warnings, code, message);
    });
    let mut exchange = HttpExchange::new(ExchangeId(id), tool, request);

    let error = text_field(&entry.response.extra, ext::ERROR)
        .or_else(|| text_field(&entry.extra, ext::ERROR));
    match u16::try_from(entry.response.status) {
        Ok(0) => {}
        Ok(_) => {
            let response = response(entry, options, &mut |code, message| {
                warn(warnings, code, message);
            });
            exchange = exchange.with_response(response);
        }
        Err(_) => warn(
            warnings,
            "invalid_status",
            format!("status {} is not a status code", entry.response.status),
        ),
    }
    // Without `_error`, a failed entry's response comment is its reason
    // (Charles writes `"comment": "Connect timed out"`).
    exchange.error = error.or_else(|| {
        (exchange.response.is_none())
            .then(|| entry.response.comment.clone())
            .flatten()
            .filter(|comment| !comment.is_empty())
    });

    if !entry.started_date_time.is_empty() {
        match time::parse_unix_millis(&entry.started_date_time) {
            Some(started) => exchange.started_at_unix_milliseconds = started,
            None => warn(
                warnings,
                "invalid_time",
                format!("unreadable startedDateTime `{}`", entry.started_date_time),
            ),
        }
    }
    exchange.timings = timings(entry);
    exchange.remote_address = entry
        .server_ip_address
        .clone()
        .filter(|address| !address.is_empty());
    exchange.notes = entry.comment.clone().filter(|comment| !comment.is_empty());
    exchange.label = text_field(&entry.extra, ext::LABEL);
    if let Some(Value::Array(tags)) = entry.extra.get(ext::TAGS) {
        exchange.tags = tags
            .iter()
            .filter_map(|tag| tag.as_str().map(str::to_owned))
            .collect();
    }
    if let Some(Value::Array(hops)) = entry.extra.get(ext::REDIRECT_CHAIN) {
        exchange.redirect_chain = hops.iter().filter_map(redirect_hop).collect();
    }
    Some(exchange)
}

fn text_field(extra: &Extensions, key: &str) -> Option<String> {
    extra
        .get(key)
        .and_then(Value::as_str)
        .filter(|text| !text.is_empty())
        .map(str::to_owned)
}

fn redirect_hop(hop: &Value) -> Option<RedirectHop> {
    let status = u16::try_from(hop.get("status")?.as_u64()?).ok()?;
    let location = hop.get("location")?.as_str()?;
    Some(RedirectHop::new(status, location))
}

/// Rounds a non-negative, finite millisecond count.
#[expect(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    reason = "checked finite and non-negative; the cast saturates"
)]
fn whole_millis(milliseconds: f64) -> Option<u64> {
    (milliseconds.is_finite() && milliseconds >= 0.0).then(|| milliseconds.round() as u64)
}

fn timings(entry: &Entry) -> Timings {
    let estimated = entry
        .timings
        .extra
        .get(ext::WAIT_ESTIMATED)
        .and_then(Value::as_bool);
    let time_to_headers = if estimated == Some(true) {
        None
    } else {
        entry.timings.time_to_first_byte().and_then(whole_millis)
    };
    let total = whole_millis(entry.time).unwrap_or(0);
    Timings {
        time_to_headers_milliseconds: time_to_headers,
        total_milliseconds: total,
    }
}

fn version(text: &str) -> HttpVersion {
    HttpVersion::parse(text).unwrap_or_default()
}

fn headers(list: &[NameValue], options: &ReadOptions) -> Vec<HeaderEntry> {
    list.iter()
        .filter(|header| options.keep_pseudo_headers || !header.name.starts_with(':'))
        .map(|header| HeaderEntry::new(header.name.as_str(), header.value.as_str()))
        .collect()
}

fn is_base64(encoding: Option<&str>) -> bool {
    encoding.is_some_and(|encoding| encoding.trim().eq_ignore_ascii_case("base64"))
}

/// Decodes base64 text, ignoring the line breaks some exporters insert.
fn decode_base64(text: &str) -> Option<HttpBody> {
    let compact: String = text.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    HttpBody::from_base64(&compact).ok()
}

/// A body from text that may be base64; invalid base64 is kept verbatim.
fn body_from_text(
    text: &str,
    base64: bool,
    report: &mut dyn FnMut(&'static str, String),
) -> HttpBody {
    if base64 {
        if let Some(body) = decode_base64(text) {
            return body;
        }
        report(
            "invalid_base64",
            "body marked base64 does not decode; kept as text".to_owned(),
        );
    }
    HttpBody::from_text(text)
}

/// Applies this crate's capture-metadata extensions to a body.
fn apply_body_extensions(body: &mut HttpBody, extra: &Extensions) {
    if let Some(coding) = text_field(extra, ext::CONTENT_ENCODING) {
        body.content_encoding = Some(coding);
    }
    if extra.get(ext::TRUNCATED).and_then(Value::as_bool) == Some(true) {
        body.truncated = true;
    }
}

fn request(
    har: &Request,
    options: &ReadOptions,
    report: &mut dyn FnMut(&'static str, String),
) -> HttpRequest {
    let mut request = HttpRequest::new(har.method.as_str(), har.url.as_str())
        .with_version(version(&har.http_version))
        .with_headers(headers(&har.headers, options));
    if let Some(post) = &har.post_data {
        request.body = post_body(post, report);
    }
    request
}

fn post_body(post: &PostData, report: &mut dyn FnMut(&'static str, String)) -> HttpBody {
    let encoding = post
        .encoding
        .as_deref()
        .or_else(|| post.extra.get("_encoding").and_then(Value::as_str));
    let mut body = if let Some(text) = &post.text {
        body_from_text(text, is_base64(encoding), report)
    } else if post.params.is_empty() {
        HttpBody::empty()
    } else if post
        .mime_type
        .to_ascii_lowercase()
        .starts_with("multipart/")
    {
        report(
            "params_only",
            "multipart body given only as params; not reconstructed".to_owned(),
        );
        HttpBody::empty()
    } else {
        let pairs = post.params.iter().map(|param| {
            format!(
                "{}={}",
                crate::query::form_encode(&param.name),
                crate::query::form_encode(param.value.as_deref().unwrap_or_default())
            )
        });
        HttpBody::from_text(pairs.collect::<Vec<_>>().join("&"))
    };
    apply_body_extensions(&mut body, &post.extra);
    if let Some(total) = post.extra.get(ext::TOTAL_LEN).and_then(Value::as_u64) {
        body.total_len = Some(total);
    }
    body
}

fn response(
    entry: &Entry,
    options: &ReadOptions,
    report: &mut dyn FnMut(&'static str, String),
) -> HttpResponse {
    let har = &entry.response;
    let status = u16::try_from(har.status).unwrap_or_default();
    let mut response = HttpResponse::new(status)
        .with_version(version(&har.http_version))
        .with_headers(headers(&har.headers, options))
        .with_body(content_body(&har.content, report));
    if !har.status_text.is_empty() {
        response.reason = Some(har.status_text.clone());
    }
    response
}

fn content_body(content: &Content, report: &mut dyn FnMut(&'static str, String)) -> HttpBody {
    let mut body = content
        .text
        .as_deref()
        .map_or_else(HttpBody::empty, |text| {
            body_from_text(text, is_base64(content.encoding.as_deref()), report)
        });
    // A size beyond the captured bytes means the exporter dropped or cut
    // the body (Chrome omits `text` it did not keep).
    if let Ok(size) = u64::try_from(content.size)
        && size > body.len() as u64
    {
        body.truncated = true;
        body.total_len = Some(size);
    }
    apply_body_extensions(&mut body, &content.extra);
    body
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_non_har() {
        assert!(matches!(parse(b"not json"), Err(HarError::Json(_))));
        assert!(matches!(parse(b"[]"), Err(HarError::NotHar(_))));
        assert!(matches!(parse(b"{}"), Err(HarError::NotHar(_))));
        assert!(matches!(parse(br#"{"log": 1}"#), Err(HarError::NotHar(_))));
        assert!(matches!(parse(br#"{"log": {}}"#), Err(HarError::NotHar(_))));
        assert!(matches!(
            parse(br#"{"log": {"entries": {}}}"#),
            Err(HarError::NotHar(_))
        ));
        assert!(matches!(
            parse(br#"{"log": {"entries": [], "creator": 3}}"#),
            Err(HarError::NotHar(_))
        ));
    }

    #[test]
    fn accepts_bare_log_and_bom() {
        let parsed = parse(b"\xef\xbb\xbf{\"entries\": [], \"version\": \"1.1\"}").unwrap();
        assert_eq!(parsed.har.log.version, "1.1");
        assert_eq!(parsed.warnings, []);
    }

    #[test]
    fn skips_malformed_entries_only() {
        let input = br#"{"log": {"entries": [
            {"request": {"method": "GET", "url": "http://a/"}},
            {"request": {"method": {"bad": 1}, "url": "http://b/"}},
            {"request": {"method": "", "url": ""}},
            "nonsense"
        ], "pages": [{"id": []}]}}"#;
        let report = read(input, &ReadOptions::default()).unwrap();
        assert_eq!(report.exchanges.len(), 1);
        let codes: Vec<_> = report.warnings.iter().map(|w| (w.entry, w.code)).collect();
        assert_eq!(
            codes,
            vec![
                (None, "invalid_page"),
                (Some(1), "invalid_entry"),
                (Some(3), "invalid_entry"),
                (Some(2), "no_request"),
            ]
        );
        assert!(
            report.warnings[1]
                .to_string()
                .starts_with("entries[1]: skipped")
        );
    }

    #[test]
    fn entry_limit() {
        let input = br#"{"log": {"entries": [
            {"request": {"method": "GET", "url": "http://a/"}},
            {"request": {"method": "GET", "url": "http://b/"}}
        ]}}"#;
        let report = read(input, &ReadOptions::default().with_max_entries(1)).unwrap();
        assert_eq!(report.exchanges.len(), 1);
        assert_eq!(report.warnings[0].code, "entry_limit");
    }

    #[test]
    fn bodies_and_repairs() {
        let input = br#"{"log": {"entries": [{
            "startedDateTime": "yesterday",
            "time": -5,
            "request": {"method": "POST", "url": "http://a/",
                "postData": {"mimeType": "application/x-www-form-urlencoded",
                    "params": [{"name": "a b", "value": "1&2"}, {"name": "c"}]}},
            "response": {"status": 200, "content": {"size": 10, "text": "!!!", "encoding": "base64"}}
        }, {
            "request": {"method": "POST", "url": "http://a/",
                "postData": {"mimeType": "multipart/form-data; boundary=x",
                    "params": [{"name": "f", "fileName": "a.txt"}]}},
            "response": {"status": 70000}
        }, {
            "request": {"method": "PUT", "url": "http://a/",
                "postData": {"mimeType": "x", "text": "AAEC\r\nAw==", "_encoding": "BASE64"}},
            "response": {"status": 200, "content": {"size": 3, "text": "AA\nEC", "encoding": "base64"}}
        }]}}"#;
        let report = read(input, &ReadOptions::default()).unwrap();
        let [form, multipart, binary] = report.exchanges.as_slice() else {
            panic!("three exchanges");
        };
        assert_eq!(form.request.body.as_utf8(), Some("a+b=1%262&c="));
        assert_eq!(form.started_at_unix_milliseconds, 0);
        assert_eq!(form.timings, Timings::default());
        let body = &form.response.as_ref().unwrap().body;
        assert_eq!(body.as_utf8(), Some("!!!"));
        assert_eq!((body.truncated, body.total_len), (true, Some(10)));
        assert!(multipart.request.body.is_empty());
        assert!(multipart.response.is_none());
        assert_eq!(binary.request.body.as_bytes(), [0, 1, 2, 3]);
        let body = &binary.response.as_ref().unwrap().body;
        assert_eq!(body.as_bytes(), [0, 1, 2]);
        assert!(!body.truncated);
        let codes: Vec<_> = report.warnings.iter().map(|w| (w.entry, w.code)).collect();
        assert_eq!(
            codes,
            vec![
                (Some(0), "invalid_base64"),
                (Some(0), "invalid_time"),
                (Some(1), "params_only"),
                (Some(1), "invalid_status"),
            ]
        );
    }
}
