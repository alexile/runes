//! Reading: a Burp export to [`HttpExchange`]s.

use std::borrow::Cow;
use std::fmt;

use rune_http_model::{ExchangeId, HttpBody, HttpExchange};

use crate::message::{self, ParsedRequest};
use crate::xml::{self, Field, Flow};
use crate::{BurpError, time};

/// Settings for reading an export.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ReadOptions {
    /// Tool recorded on every exchange.
    pub tool: String,
    /// Keep the captured bytes as `raw` on requests and responses. On by
    /// default: Burp stores exactly what went over the wire.
    pub keep_raw: bool,
    /// Undo `Transfer-Encoding: chunked` in bodies whose framing is valid.
    /// On by default; the `raw` bytes keep the framing either way.
    pub decode_chunked: bool,
    /// Read at most this many items.
    pub max_items: Option<usize>,
}

impl Default for ReadOptions {
    fn default() -> Self {
        Self {
            tool: "burp".to_owned(),
            keep_raw: true,
            decode_chunked: true,
            max_items: None,
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

    /// Sets [`ReadOptions::keep_raw`].
    #[must_use]
    pub const fn with_raw(mut self, keep: bool) -> Self {
        self.keep_raw = keep;
        self
    }

    /// Sets [`ReadOptions::decode_chunked`].
    #[must_use]
    pub const fn with_decode_chunked(mut self, decode: bool) -> Self {
        self.decode_chunked = decode;
        self
    }

    /// Sets [`ReadOptions::max_items`].
    #[must_use]
    pub const fn with_max_items(mut self, max_items: usize) -> Self {
        self.max_items = Some(max_items);
        self
    }
}

/// Which kind of export was read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum ExportKind {
    /// `<items>`: proxy history, site map or any "Save items" export.
    #[default]
    Items,
    /// `<issues>`: a scanner issues report with request/response evidence.
    Issues,
}

/// Something in the input that was skipped or repaired while reading.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Warning {
    /// Index of the item (counting every element with a `request`), when
    /// the warning is about one.
    pub item: Option<usize>,
    /// Stable, machine-readable kind, e.g. `invalid_request`.
    pub code: &'static str,
    /// Human-readable detail.
    pub message: String,
}

impl Warning {
    fn new(item: Option<usize>, code: &'static str, message: impl Into<String>) -> Self {
        Self {
            item,
            code,
            message: message.into(),
        }
    }
}

impl fmt::Display for Warning {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.item {
            Some(index) => write!(formatter, "item {index}: {}", self.message),
            None => formatter.write_str(&self.message),
        }
    }
}

/// Exchanges read from a Burp export.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct ReadReport {
    /// Items or issues.
    pub kind: ExportKind,
    /// The root's `burpVersion` attribute.
    pub burp_version: Option<String>,
    /// The root's `exportTime` attribute, as written.
    pub export_time: Option<String>,
    /// One exchange per usable item, in file order.
    pub exchanges: Vec<HttpExchange>,
    /// What was skipped or repaired.
    pub warnings: Vec<Warning>,
}

/// Reads a Burp Suite items or issues XML export.
///
/// Items are read one at a time as the document streams by. An item whose
/// request cannot be decoded or parsed is skipped with a [`Warning`]; a
/// response that cannot be is dropped with one. Malformed or truncated XML
/// after the root element ends reading with a warning, keeping the items
/// read so far. Invalid UTF-8 is replaced (with a warning); base64 payloads
/// are unaffected.
///
/// # Errors
///
/// [`BurpError::Xml`] when the document is malformed before its root
/// element, [`BurpError::NotBurp`] when the root is not `items` or
/// `issues`.
pub fn read(input: &[u8], options: &ReadOptions) -> Result<ReadReport, BurpError> {
    let input = input.strip_prefix(b"\xef\xbb\xbf").unwrap_or(input);
    let mut report = ReadReport::default();
    let text = match std::str::from_utf8(input) {
        Ok(text) => Cow::Borrowed(text),
        Err(error) => {
            report.warnings.push(Warning::new(
                None,
                "invalid_utf8",
                format!("input is not valid UTF-8 ({error}); invalid bytes replaced"),
            ));
            String::from_utf8_lossy(input)
        }
    };
    let mut index = 0_usize;
    let mut full = false;
    let outcome = xml::walk(&text, |fields, ancestors| {
        let item = index;
        index += 1;
        match exchange(fields, ancestors, item, options) {
            Ok((exchange, notes)) => {
                report.exchanges.push(exchange);
                report.warnings.extend(
                    notes
                        .into_iter()
                        .map(|(code, message)| Warning::new(Some(item), code, message)),
                );
            }
            Err((code, message)) => {
                report.warnings.push(Warning::new(
                    Some(item),
                    code,
                    format!("skipped: {message}"),
                ));
            }
        }
        if options
            .max_items
            .is_some_and(|max| report.exchanges.len() >= max)
        {
            full = true;
            Flow::Stop
        } else {
            Flow::Continue
        }
    })?;
    report.kind = if outcome.root == "issues" {
        ExportKind::Issues
    } else {
        ExportKind::Items
    };
    let attribute = |name: &str| {
        outcome
            .attributes
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.clone())
            .filter(|value| !value.is_empty())
    };
    report.burp_version = attribute("burpVersion");
    report.export_time = attribute("exportTime");
    if full {
        report.warnings.push(Warning::new(
            None,
            "max_items",
            "item limit reached; rest skipped",
        ));
    } else if let Some(reason) = outcome.stopped {
        report
            .warnings
            .push(Warning::new(None, "truncated", reason));
    }
    Ok(report)
}

type Note = (&'static str, String);

/// A field's payload: base64-decoded when `base64="true"`.
fn payload(field: &Field) -> Option<Vec<u8>> {
    if field.attribute("base64") == Some("true") {
        let compact: String = field
            .text
            .chars()
            .filter(|c| !c.is_ascii_whitespace())
            .collect();
        rune_base64::decode(&compact).ok()
    } else {
        Some(field.text.as_bytes().to_vec())
    }
}

/// A field's trimmed text, when not empty.
fn text(field: Option<&Field>) -> Option<&str> {
    field
        .map(|field| field.text.trim())
        .filter(|text| !text.is_empty())
}

/// The request's absolute URL: Burp's `<url>`, an absolute-form request
/// target, or the target under an origin from `<host>`, `<protocol>` and
/// `<port>` (or the `Host` header).
fn absolute_url(lookup: &Lookup<'_>, parsed: &ParsedRequest) -> Option<String> {
    if let Some(url) = text(lookup.get("url")).filter(|url| url.contains("://")) {
        return Some(url.to_owned());
    }
    let target = parsed.target.as_str();
    let lower = target.get(..8).unwrap_or(target).to_ascii_lowercase();
    if lower.starts_with("http://") || lower.starts_with("https://") {
        return Some(target.to_owned());
    }
    let port = text(lookup.get("port"));
    let default_scheme = if port == Some("443") { "https" } else { "http" };
    let scheme = text(lookup.get("protocol"))
        .map_or_else(|| default_scheme.to_owned(), str::to_ascii_lowercase);
    let origin = match text(lookup.get("host")) {
        Some(host) if host.contains("://") => host.trim_end_matches('/').to_owned(),
        Some(host) => {
            let default = if scheme == "https" { "443" } else { "80" };
            match port {
                Some(port) if port != default => format!("{scheme}://{host}:{port}"),
                _ => format!("{scheme}://{host}"),
            }
        }
        None => {
            let host = parsed.request.header("Host").map(str::trim)?;
            if host.is_empty() {
                return None;
            }
            format!("{scheme}://{host}")
        }
    };
    Some(if target.starts_with('/') {
        format!("{origin}{target}")
    } else if parsed.request.method.eq_ignore_ascii_case("CONNECT") {
        origin
    } else {
        format!("{origin}/{target}")
    })
}

/// An item's fields, falling back to its ancestors' (an issue's `host`).
struct Lookup<'a> {
    fields: &'a [Field],
    ancestors: &'a [&'a [Field]],
}

impl<'a> Lookup<'a> {
    fn get(&self, name: &str) -> Option<&'a Field> {
        xml::field(self.fields, name).or_else(|| {
            self.ancestors
                .iter()
                .find_map(|ancestor| xml::field(ancestor, name))
        })
    }
}

/// Turns one item's fields into an exchange, with warnings about it.
fn exchange(
    fields: &[Field],
    ancestors: &[&[Field]],
    index: usize,
    options: &ReadOptions,
) -> Result<(HttpExchange, Vec<Note>), Note> {
    let lookup = Lookup { fields, ancestors };
    let own = |name: &str| xml::field(fields, name);
    let mut notes = Vec::new();

    let raw = own("request")
        .and_then(payload)
        .ok_or_else(|| ("invalid_base64", "request is not valid base64".to_owned()))?;
    if raw.iter().all(u8::is_ascii_whitespace) {
        return Err(("empty_request", "request is empty".to_owned()));
    }
    let parsed = message::parse_request(&raw, options.decode_chunked).ok_or_else(|| {
        (
            "invalid_request",
            "request is not an HTTP message".to_owned(),
        )
    })?;
    let url = absolute_url(&lookup, &parsed).ok_or_else(|| {
        (
            "no_host",
            "no URL, host or Host header to make the request absolute".to_owned(),
        )
    })?;
    let mut request = parsed.request;
    request.url = url;
    if options.keep_raw {
        request.raw = Some(HttpBody::new(raw));
    }

    let id = ExchangeId(u64::try_from(index).unwrap_or(u64::MAX));
    let mut exchange = HttpExchange::new(id, options.tool.clone(), request);
    if let Some(when) = text(own("time")) {
        match time::parse(when) {
            Some(parsed) => {
                exchange.started_at_unix_milliseconds = parsed.unix_milliseconds;
                if parsed.zone_assumed {
                    notes.push((
                        "time_zone_assumed_utc",
                        format!("time zone in `{when}` not recognised; read as UTC"),
                    ));
                }
            }
            None => notes.push(("invalid_time", format!("time `{when}` not understood"))),
        }
    }

    if let Some(field) = own("response") {
        match payload(field) {
            None => notes.push((
                "invalid_response",
                "response is not valid base64; dropped".to_owned(),
            )),
            Some(raw) if raw.iter().all(u8::is_ascii_whitespace) => {}
            Some(raw) => match message::parse_response(&raw, options.decode_chunked) {
                None => notes.push((
                    "invalid_response",
                    "response is not an HTTP message; dropped".to_owned(),
                )),
                Some(mut response) => {
                    // A stated length beyond the captured bytes: the
                    // capture was cut.
                    if let Some(stated) =
                        text(own("responselength")).and_then(|length| length.parse::<u64>().ok())
                        && let Ok(captured) = u64::try_from(raw.len())
                        && stated > captured
                        && let Ok(body_len) = u64::try_from(response.body.len())
                    {
                        response.body.truncated = true;
                        response.body.total_len = Some(body_len + (stated - captured));
                    }
                    if options.keep_raw {
                        response.raw = Some(HttpBody::new(raw));
                    }
                    exchange.response = Some(response);
                }
            },
        }
    }

    exchange.remote_address = lookup
        .get("host")
        .and_then(|host| host.attribute("ip"))
        .map(str::trim)
        .filter(|ip| !ip.is_empty())
        .map(str::to_owned);
    exchange.notes = own("comment")
        .filter(|comment| !comment.text.trim().is_empty())
        .map(|comment| comment.text.clone());
    // Issue evidence carries the issue's name.
    exchange.label = ancestors
        .iter()
        .find_map(|ancestor| text(xml::field(ancestor, "name")))
        .map(str::to_owned);
    Ok((exchange, notes))
}
