//! Writing: [`HttpExchange`]s to a [`Har`], and a [`Har`] to JSON.

use std::borrow::Borrow;
use std::io::Write;

use rune_http_model::{HeaderEntry, HttpBody, HttpExchange, HttpRequest, HttpResponse};
use serde::Serialize;
use serde_json::{Value, json};

use crate::model::{
    Cache, Content, Creator, Entry, Extensions, Har, Log, NameValue, PostData, Request, Response,
    Timings,
};
use crate::{HAR_VERSION, HarError, ext, query, time};

/// Settings for writing HAR.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct WriteOptions {
    /// The application recorded as `log.creator`. Defaults to this crate.
    pub creator: Creator,
    /// Indent the JSON for people to read.
    pub pretty: bool,
}

impl Default for WriteOptions {
    fn default() -> Self {
        Self {
            creator: Creator::new(env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION")),
            pretty: false,
        }
    }
}

impl WriteOptions {
    /// Sets [`WriteOptions::creator`].
    #[must_use]
    pub fn with_creator(mut self, name: impl Into<String>, version: impl Into<String>) -> Self {
        self.creator = Creator::new(name, version);
        self
    }

    /// Sets [`WriteOptions::pretty`].
    #[must_use]
    pub const fn with_pretty(mut self, pretty: bool) -> Self {
        self.pretty = pretty;
        self
    }
}

/// Writes `exchanges` as a HAR 1.2 document.
///
/// # Errors
///
/// [`HarError::Write`] if serialization fails, which it does not for the
/// values this crate builds.
pub fn write<I>(exchanges: I, options: &WriteOptions) -> Result<String, HarError>
where
    I: IntoIterator,
    I::Item: Borrow<HttpExchange>,
{
    Har::from_exchanges(exchanges, options).to_json(options.pretty)
}

fn json_error(error: serde_json::Error) -> HarError {
    if error.is_io() {
        HarError::Io(error.into())
    } else {
        HarError::Write(error.to_string())
    }
}

fn to_writer<W: Write, T: Serialize>(writer: W, value: &T, pretty: bool) -> Result<(), HarError> {
    if pretty {
        serde_json::to_writer_pretty(writer, value)
    } else {
        serde_json::to_writer(writer, value)
    }
    .map_err(json_error)
}

impl Har {
    /// A version 1.2 document with one entry per exchange.
    #[must_use]
    pub fn from_exchanges<I>(exchanges: I, options: &WriteOptions) -> Self
    where
        I: IntoIterator,
        I::Item: Borrow<HttpExchange>,
    {
        let mut log = Log::new(options.creator.clone());
        log.entries = exchanges
            .into_iter()
            .map(|exchange| Entry::from_exchange(exchange.borrow()))
            .collect();
        Self::new(log)
    }

    /// The document as JSON text.
    ///
    /// # Errors
    ///
    /// [`HarError::Write`] if serialization fails, which it does not for a
    /// document built by this crate or read by [`parse`](crate::parse).
    pub fn to_json(&self, pretty: bool) -> Result<String, HarError> {
        let mut out = Vec::new();
        self.to_writer(&mut out, pretty)?;
        String::from_utf8(out).map_err(|error| HarError::Write(error.to_string()))
    }

    /// Writes the document as JSON to `writer`.
    ///
    /// # Errors
    ///
    /// [`HarError::Io`] when the writer fails.
    pub fn to_writer<W: Write>(&self, writer: W, pretty: bool) -> Result<(), HarError> {
        to_writer(writer, self, pretty)
    }
}

/// Writes a HAR document one entry at a time, so exporting a large capture
/// needs memory for one exchange only.
///
/// ```
/// use rune_har::{HarWriter, WriteOptions};
/// use rune_http_model::{ExchangeId, HttpExchange, HttpRequest, HttpResponse};
///
/// let mut writer = HarWriter::new(Vec::new(), &WriteOptions::default())?;
/// for id in 0..3 {
///     let exchange = HttpExchange::new(ExchangeId(id), "proxy", HttpRequest::get("http://h/"))
///         .with_response(HttpResponse::new(204));
///     writer.write(&exchange)?;
/// }
/// assert_eq!(writer.count(), 3);
/// let bytes = writer.finish()?;
/// let report = rune_har::read(&bytes, &rune_har::ReadOptions::default())?;
/// assert_eq!(report.exchanges.len(), 3);
/// # Ok::<(), rune_har::HarError>(())
/// ```
#[derive(Debug)]
pub struct HarWriter<W: Write> {
    writer: W,
    count: u64,
}

impl<W: Write> HarWriter<W> {
    /// Starts a document with the creator from `options`.
    ///
    /// # Errors
    ///
    /// [`HarError::Io`] when the writer fails.
    pub fn new(mut writer: W, options: &WriteOptions) -> Result<Self, HarError> {
        writer.write_all(b"{\"log\":{\"version\":")?;
        to_writer(&mut writer, &HAR_VERSION, false)?;
        writer.write_all(b",\"creator\":")?;
        to_writer(&mut writer, &options.creator, false)?;
        writer.write_all(b",\"entries\":[")?;
        Ok(Self { writer, count: 0 })
    }

    /// Appends an exchange.
    ///
    /// # Errors
    ///
    /// [`HarError::Io`] when the writer fails.
    pub fn write(&mut self, exchange: &HttpExchange) -> Result<(), HarError> {
        self.write_entry(&Entry::from_exchange(exchange))
    }

    /// Appends an entry as it is.
    ///
    /// # Errors
    ///
    /// [`HarError::Io`] when the writer fails.
    pub fn write_entry(&mut self, entry: &Entry) -> Result<(), HarError> {
        if self.count > 0 {
            self.writer.write_all(b",")?;
        }
        to_writer(&mut self.writer, entry, false)?;
        self.count += 1;
        Ok(())
    }

    /// Entries written so far.
    #[must_use]
    pub const fn count(&self) -> u64 {
        self.count
    }

    /// Closes the document, flushes and returns the writer.
    ///
    /// # Errors
    ///
    /// [`HarError::Io`] when the writer fails.
    pub fn finish(mut self) -> Result<W, HarError> {
        self.writer.write_all(b"]}}")?;
        self.writer.flush()?;
        Ok(self.writer)
    }
}

fn len_i64(len: usize) -> i64 {
    i64::try_from(len).unwrap_or(i64::MAX)
}

#[expect(
    clippy::cast_precision_loss,
    reason = "millisecond counts beyond 2^53 lose sub-millisecond precision only"
)]
const fn millis_f64(milliseconds: u64) -> f64 {
    milliseconds as f64
}

fn name_values(headers: &[HeaderEntry]) -> Vec<NameValue> {
    headers
        .iter()
        .map(|header| NameValue::new(header.name.as_str(), header.value.as_str()))
        .collect()
}

/// The body as HAR text: UTF-8 text verbatim, anything else (or a body
/// still in a content coding) as base64.
fn body_text(body: &HttpBody) -> (String, Option<String>) {
    match (body.content_encoding.as_deref(), body.as_utf8()) {
        (None, Some(text)) => (text.to_owned(), None),
        _ => (body.to_base64(), Some("base64".to_owned())),
    }
}

/// Records capture metadata HAR has no field for.
fn body_extensions(body: &HttpBody, extra: &mut Extensions) {
    if let Some(coding) = &body.content_encoding {
        extra.insert(ext::CONTENT_ENCODING.to_owned(), coding.as_str().into());
    }
    if body.truncated {
        extra.insert(ext::TRUNCATED.to_owned(), true.into());
    }
}

fn request(request: &HttpRequest) -> Request {
    let post_data = (request.body != HttpBody::empty()).then(|| {
        let (text, encoding) = body_text(&request.body);
        let mut post = PostData {
            mime_type: request.content_type().unwrap_or_default().to_owned(),
            text: Some(text),
            encoding,
            ..PostData::default()
        };
        body_extensions(&request.body, &mut post.extra);
        if let Some(total) = request.body.total_len {
            post.extra.insert(ext::TOTAL_LEN.to_owned(), total.into());
        }
        post
    });
    Request {
        method: request.method.clone(),
        url: request.url.clone(),
        http_version: request.http_version.as_str().to_owned(),
        cookies: query::request_cookies(request.header_values("cookie")),
        headers: name_values(&request.headers),
        query_string: query::query_string(&request.url),
        post_data,
        headers_size: -1,
        body_size: len_i64(request.body.len()),
        comment: None,
        extra: Extensions::new(),
    }
}

fn response(response: &HttpResponse) -> Response {
    let body = &response.body;
    let (text, encoding) = body_text(body);
    let size = body
        .total_len
        .and_then(|total| i64::try_from(total).ok())
        .unwrap_or_else(|| len_i64(body.len()));
    let mut content = Content {
        size,
        mime_type: response.content_type().unwrap_or_default().to_owned(),
        text: Some(text),
        encoding,
        ..Content::default()
    };
    body_extensions(body, &mut content.extra);
    Response {
        status: i64::from(response.status),
        status_text: response.reason.clone().unwrap_or_default(),
        http_version: response.http_version.as_str().to_owned(),
        cookies: response
            .header_values("set-cookie")
            .filter_map(query::response_cookie)
            .collect(),
        headers: name_values(&response.headers),
        content,
        redirect_url: response.location().unwrap_or_default().to_owned(),
        headers_size: -1,
        body_size: if body.truncated {
            -1
        } else {
            len_i64(body.len())
        },
        comment: None,
        extra: Extensions::new(),
    }
}

fn timings(exchange: &HttpExchange) -> Timings {
    let total = exchange.timings.total_milliseconds;
    let measured = exchange.timings.time_to_headers_milliseconds;
    let wait = measured.unwrap_or(total);
    let mut timings = Timings {
        send: Some(0.0),
        wait: Some(millis_f64(wait)),
        receive: Some(millis_f64(total.saturating_sub(wait))),
        ..Timings::default()
    };
    if measured.is_none() {
        timings
            .extra
            .insert(ext::WAIT_ESTIMATED.to_owned(), true.into());
    }
    timings
}

impl Entry {
    /// The HAR entry for an exchange.
    ///
    /// See the crate documentation for how each field maps, and for the
    /// `_`-prefixed fields that carry what HAR has no place for.
    #[must_use]
    pub fn from_exchange(exchange: &HttpExchange) -> Self {
        let mut response = exchange
            .response
            .as_ref()
            .map_or_else(Response::default, response);
        if let Some(error) = &exchange.error {
            response
                .extra
                .insert(ext::ERROR.to_owned(), error.as_str().into());
        }
        let mut extra = Extensions::new();
        extra.insert(ext::ID.to_owned(), exchange.id.get().into());
        extra.insert(ext::TOOL.to_owned(), exchange.tool.as_str().into());
        if let Some(label) = &exchange.label {
            extra.insert(ext::LABEL.to_owned(), label.as_str().into());
        }
        if !exchange.tags.is_empty() {
            extra.insert(ext::TAGS.to_owned(), exchange.tags.clone().into());
        }
        if !exchange.redirect_chain.is_empty() {
            let hops = exchange
                .redirect_chain
                .iter()
                .map(|hop| json!({"status": hop.status, "location": hop.location}))
                .collect::<Vec<Value>>();
            extra.insert(ext::REDIRECT_CHAIN.to_owned(), hops.into());
        }
        Self {
            pageref: None,
            started_date_time: time::format_unix_millis(exchange.started_at_unix_milliseconds),
            time: millis_f64(exchange.timings.total_milliseconds),
            request: request(&exchange.request),
            response,
            cache: Cache::default(),
            timings: timings(exchange),
            server_ip_address: exchange.remote_address.clone(),
            connection: None,
            comment: exchange.notes.clone(),
            extra,
        }
    }
}

#[cfg(test)]
mod tests {
    use rune_http_model::{ExchangeId, RedirectHop};

    use super::*;

    #[test]
    fn entry_shape() {
        let exchange = HttpExchange::new(
            ExchangeId(7),
            "proxy",
            HttpRequest::post("https://h.test/a?x=1%202&y")
                .with_header("Cookie", "a=1; b=2")
                .with_header("Content-Type", "application/octet-stream")
                .with_body(vec![0xff, 0x00]),
        )
        .with_response(
            HttpResponse::new(302)
                .with_reason("Found")
                .with_header("Location", "/b")
                .with_header("Set-Cookie", "s=1; HttpOnly")
                .with_body(HttpBody::from_text("gz").with_content_encoding("gzip")),
        )
        .with_started_at(1_704_164_645_678)
        .with_redirect(RedirectHop::new(301, "/a"))
        .with_tag("t");
        let value = serde_json::to_value(Entry::from_exchange(&exchange)).unwrap();
        assert_eq!(value["startedDateTime"], "2024-01-02T03:04:05.678Z");
        assert_eq!(value["_id"], 7);
        assert_eq!(value["_tool"], "proxy");
        assert_eq!(value["_tags"], json!(["t"]));
        assert_eq!(
            value["_redirectChain"],
            json!([{"status": 301, "location": "/a"}])
        );
        let request = &value["request"];
        assert_eq!(
            request["queryString"],
            json!([{"name": "x", "value": "1 2"}, {"name": "y", "value": ""}])
        );
        assert_eq!(
            request["cookies"],
            json!([{"name": "a", "value": "1"}, {"name": "b", "value": "2"}])
        );
        assert_eq!(
            request["postData"],
            json!({
                "mimeType": "application/octet-stream", "text": "/wA=", "encoding": "base64"
            })
        );
        let response = &value["response"];
        assert_eq!(response["redirectURL"], "/b");
        assert_eq!(
            response["cookies"],
            json!([{"name": "s", "value": "1", "httpOnly": true}])
        );
        assert_eq!(
            response["content"],
            json!({
                "size": 2, "mimeType": "", "text": "Z3o=", "encoding": "base64",
                "_contentEncoding": "gzip"
            })
        );
        assert_eq!(
            value["timings"],
            json!({"send": 0, "wait": 0, "receive": 0, "_waitEstimated": true})
        );
    }

    #[test]
    fn failed_exchange() {
        let exchange = HttpExchange::new(ExchangeId(0), "t", HttpRequest::get("http://h/"))
            .with_error("connection reset");
        let value = serde_json::to_value(Entry::from_exchange(&exchange)).unwrap();
        assert_eq!(value["response"]["status"], 0);
        assert_eq!(value["response"]["_error"], "connection reset");
        assert!(value["request"].get("postData").is_none());
    }

    #[test]
    fn streaming_matches_whole_document() {
        let exchanges = [
            HttpExchange::new(ExchangeId(1), "t", HttpRequest::get("http://h/1")),
            HttpExchange::new(ExchangeId(2), "t", HttpRequest::get("http://h/2")),
        ];
        let options = WriteOptions::default().with_creator("me", "1");
        let mut writer = HarWriter::new(Vec::new(), &options).unwrap();
        for exchange in &exchanges {
            writer.write(exchange).unwrap();
        }
        let streamed: Value = serde_json::from_slice(&writer.finish().unwrap()).unwrap();
        let whole: Value = serde_json::from_str(&write(&exchanges, &options).unwrap()).unwrap();
        assert_eq!(streamed, whole);
        let pretty = write(&exchanges, &options.with_pretty(true)).unwrap();
        assert!(pretty.contains("\n  "));
    }

    #[test]
    fn io_errors_surface() {
        #[derive(Debug)]
        struct Broken;
        impl Write for Broken {
            fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
                Err(std::io::Error::other("disk full"))
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let error = HarWriter::new(Broken, &WriteOptions::default()).unwrap_err();
        assert_eq!(error.code(), "io");
        let error = Har::default().to_writer(Broken, false).unwrap_err();
        assert_eq!(error.code(), "io");
    }
}
