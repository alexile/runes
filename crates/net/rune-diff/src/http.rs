//! Structural diff of HTTP messages built on `rune-http-model`.

use std::collections::BTreeMap;
use std::fmt;

use rune_http_model::{HeaderEntry, HttpBody, HttpExchange, HttpRequest, HttpResponse};
use serde_json::Value;

use crate::json::{JsonDiffer, leaf_count, parse_pointer};
use crate::{
    DiffOptions, EditScript, Error, Granularity, JsonChange, MaskOptions, Masker, TextDiff,
};

/// Response headers that change on every request and are skipped by default.
///
/// `content-length` is included because the body diff already covers it.
pub const VOLATILE_HEADERS: &[&str] = &[
    "age",
    "cf-ray",
    "content-length",
    "date",
    "etag",
    "expires",
    "last-modified",
    "nel",
    "report-to",
    "server-timing",
    "x-amz-cf-id",
    "x-amz-request-id",
    "x-amzn-requestid",
    "x-amzn-trace-id",
    "x-cache",
    "x-cache-hits",
    "x-correlation-id",
    "x-request-id",
    "x-response-time",
    "x-runtime",
    "x-served-by",
    "x-timer",
    "traceparent",
    "via",
];

/// Settings for [`HttpDiffer`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct HttpDiffOptions {
    /// Volatile content masked in header values, URLs, text bodies and JSON
    /// strings before comparing.
    pub mask: MaskOptions,
    /// Header names (any case) left out of the comparison. Default
    /// [`VOLATILE_HEADERS`].
    pub ignore_headers: Vec<String>,
    /// JSON pointers left out of body comparison; a `*` segment matches any
    /// key or index, and a pointer covers everything below it.
    pub ignore_json_pointers: Vec<String>,
    /// Compare JSON bodies structurally. Default `true`.
    pub json: bool,
    /// Granularity of text body diffs. Default [`Granularity::Line`].
    pub granularity: Granularity,
    /// Text bodies longer than this many bytes are only compared for
    /// equality. Default 2 MiB.
    pub max_text_len: usize,
    /// Myers settings for text and JSON array diffs.
    pub diff: DiffOptions,
}

impl Default for HttpDiffOptions {
    fn default() -> Self {
        Self {
            mask: MaskOptions::default(),
            ignore_headers: VOLATILE_HEADERS.iter().map(|&h| h.to_owned()).collect(),
            ignore_json_pointers: Vec::new(),
            json: true,
            granularity: Granularity::Line,
            max_text_len: 2 * 1024 * 1024,
            diff: DiffOptions::default(),
        }
    }
}

impl HttpDiffOptions {
    /// Compares everything exactly: no masking, no ignored headers.
    #[must_use]
    pub fn strict() -> Self {
        Self {
            mask: MaskOptions::none(),
            ignore_headers: Vec::new(),
            ..Self::default()
        }
    }

    /// Sets [`mask`](Self::mask).
    #[must_use]
    pub fn with_mask(mut self, mask: MaskOptions) -> Self {
        self.mask = mask;
        self
    }

    /// Ignores one more header.
    #[must_use]
    pub fn with_ignored_header(mut self, name: impl Into<String>) -> Self {
        self.ignore_headers.push(name.into());
        self
    }

    /// Ignores a JSON pointer such as `/meta/requestId` or `/items/*/etag`.
    #[must_use]
    pub fn with_ignored_json_pointer(mut self, pointer: impl Into<String>) -> Self {
        self.ignore_json_pointers.push(pointer.into());
        self
    }

    /// Sets [`json`](Self::json).
    #[must_use]
    pub const fn with_json(mut self, on: bool) -> Self {
        self.json = on;
        self
    }

    /// Sets [`granularity`](Self::granularity).
    #[must_use]
    pub const fn with_granularity(mut self, granularity: Granularity) -> Self {
        self.granularity = granularity;
        self
    }

    /// Sets [`max_text_len`](Self::max_text_len).
    #[must_use]
    pub const fn with_max_text_len(mut self, max: usize) -> Self {
        self.max_text_len = max;
        self
    }

    /// Sets [`diff`](Self::diff).
    #[must_use]
    pub const fn with_diff(mut self, diff: DiffOptions) -> Self {
        self.diff = diff;
        self
    }
}

/// An old and a new value.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct FieldChange<T> {
    /// Before.
    pub old: T,
    /// After.
    pub new: T,
}

/// How a header differs. Values are in wire order, unmasked.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(tag = "kind", rename_all = "snake_case"))]
#[non_exhaustive]
pub enum HeaderChangeKind {
    /// Only in the new message.
    Added {
        /// Its values.
        values: Vec<String>,
    },
    /// Only in the old message.
    Removed {
        /// Its values.
        values: Vec<String>,
    },
    /// In both, with different (masked) values.
    Changed {
        /// Old values.
        old: Vec<String>,
        /// New values.
        new: Vec<String>,
    },
}

/// One header difference.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub struct HeaderChange {
    /// Lower-cased header name.
    pub name: String,
    /// What changed.
    pub kind: HeaderChangeKind,
}

/// A text body diff that owns its (masked) texts.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct TextBodyDiff {
    /// The old body after masking.
    pub old: String,
    /// The new body after masking.
    pub new: String,
    /// How the texts were tokenized.
    pub granularity: Granularity,
    /// The edit script over the tokens.
    pub script: EditScript,
}

impl TextBodyDiff {
    /// A borrowed [`TextDiff`] view, for changes and unified output.
    #[must_use]
    pub fn view(&self) -> TextDiff<'_> {
        TextDiff::from_parts(
            self.granularity.tokenize(&self.old),
            self.granularity.tokenize(&self.new),
            self.script.clone(),
        )
    }

    /// Unified diff with `context` lines.
    #[must_use]
    pub fn unified(&self, context: usize) -> String {
        self.view().unified(context).to_string()
    }

    /// Token similarity in `[0, 1]`.
    #[must_use]
    pub fn ratio(&self) -> f64 {
        let v = self.view();
        v.ratio()
    }
}

/// How two bodies differ.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(tag = "kind", rename_all = "snake_case"))]
#[non_exhaustive]
pub enum BodyDiff {
    /// Equal after masking.
    Same,
    /// Both bodies are JSON; the structural differences.
    Json {
        /// The changes, in document order.
        changes: Vec<JsonChange>,
        /// Leaves in the larger document, for [`similarity`](BodyDiff::similarity).
        leaves: usize,
    },
    /// Text bodies that differ.
    Text(TextBodyDiff),
    /// Bodies that are not text (not UTF-8, still content-encoded, or
    /// over [`HttpDiffOptions::max_text_len`]) and differ.
    Binary {
        /// Old length in bytes.
        old_len: usize,
        /// New length in bytes.
        new_len: usize,
    },
}

impl BodyDiff {
    /// Whether the bodies are equivalent.
    #[must_use]
    pub const fn is_same(&self) -> bool {
        matches!(self, Self::Same)
    }

    /// Similarity in `[0, 1]`: 1 for equivalent bodies, the share of
    /// unchanged leaves for JSON, the token ratio for text, 0 for differing
    /// binary bodies.
    #[must_use]
    #[allow(clippy::cast_precision_loss, reason = "counts are far below 2^52")]
    pub fn similarity(&self) -> f64 {
        match self {
            Self::Same => 1.0,
            Self::Json { changes, leaves } => {
                1.0 - (changes.len() as f64 / (*leaves).max(1) as f64).min(1.0)
            }
            Self::Text(t) => t.ratio(),
            Self::Binary { .. } => 0.0,
        }
    }
}

/// Structural diff of two responses.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub struct ResponseDiff {
    /// Status code change.
    pub status: Option<FieldChange<u16>>,
    /// Reason phrase change.
    pub reason: Option<FieldChange<Option<String>>>,
    /// Protocol version change.
    pub version: Option<FieldChange<String>>,
    /// Header changes, sorted by name.
    pub headers: Vec<HeaderChange>,
    /// Body difference.
    pub body: BodyDiff,
}

impl ResponseDiff {
    /// Whether the responses are equivalent: same status, version and
    /// reason, no header changes and the same body, after masking.
    #[must_use]
    pub const fn is_equivalent(&self) -> bool {
        self.status.is_none()
            && self.reason.is_none()
            && self.version.is_none()
            && self.headers.is_empty()
            && self.body.is_same()
    }

    /// Overall similarity in `[0, 1]`: 0 if the status differs, otherwise
    /// the body similarity.
    #[must_use]
    pub fn similarity(&self) -> f64 {
        if self.status.is_some() {
            0.0
        } else {
            self.body.similarity()
        }
    }
}

/// Structural diff of two requests.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub struct RequestDiff {
    /// Method change.
    pub method: Option<FieldChange<String>>,
    /// URL change (compared after masking).
    pub url: Option<FieldChange<String>>,
    /// Protocol version change.
    pub version: Option<FieldChange<String>>,
    /// Header changes, sorted by name.
    pub headers: Vec<HeaderChange>,
    /// Body difference.
    pub body: BodyDiff,
}

impl RequestDiff {
    /// Whether the requests are equivalent after masking.
    #[must_use]
    pub const fn is_equivalent(&self) -> bool {
        self.method.is_none()
            && self.url.is_none()
            && self.version.is_none()
            && self.headers.is_empty()
            && self.body.is_same()
    }
}

/// Structural diff of two exchanges.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub struct ExchangeDiff {
    /// The requests' diff.
    pub request: RequestDiff,
    /// The responses' diff, when both exchanges have a response.
    pub response: Option<ResponseDiff>,
    /// Whether exactly one side has a response.
    pub response_presence: Option<FieldChange<bool>>,
}

/// Compiled settings that diff HTTP messages.
///
/// ```
/// use rune_diff::{HttpDiffer, HttpDiffOptions};
/// use rune_http_model::HttpResponse;
///
/// let differ = HttpDiffer::new(&HttpDiffOptions::default())?;
/// let a = HttpResponse::new(200)
///     .with_header("Date", "Tue, 10 Nov 2026 08:12:31 GMT")
///     .with_header("Content-Type", "application/json")
///     .with_body(r#"{"user":"ann","admin":false,"ts":"2026-11-10T08:12:31Z"}"#);
/// let b = HttpResponse::new(200)
///     .with_header("Date", "Tue, 10 Nov 2026 08:12:39 GMT")
///     .with_header("Content-Type", "application/json")
///     .with_body(r#"{"user":"ann","admin":true,"ts":"2026-11-10T08:12:39Z"}"#);
///
/// let diff = differ.diff_responses(&a, &b);
/// assert!(diff.status.is_none() && diff.headers.is_empty());
/// assert_eq!(diff.to_string(), "body /admin: false -> true\n");
/// # Ok::<(), rune_diff::Error>(())
/// ```
#[derive(Debug, Clone)]
pub struct HttpDiffer {
    masker: Masker,
    ignore_headers: Vec<String>,
    ignore_pointers: Vec<Vec<String>>,
    options: HttpDiffOptions,
}

impl HttpDiffer {
    /// Compiles `options`.
    pub fn new(options: &HttpDiffOptions) -> Result<Self, Error> {
        let ignore_pointers = options
            .ignore_json_pointers
            .iter()
            .map(|p| parse_pointer(p).ok_or_else(|| Error::JsonPointer(p.clone())))
            .collect::<Result<_, _>>()?;
        Ok(Self {
            masker: Masker::new(&options.mask)?,
            ignore_headers: options
                .ignore_headers
                .iter()
                .map(|h| h.to_ascii_lowercase())
                .collect(),
            ignore_pointers,
            options: options.clone(),
        })
    }

    /// The masker built from the options.
    #[must_use]
    pub const fn masker(&self) -> &Masker {
        &self.masker
    }

    /// Diffs two responses.
    #[must_use]
    pub fn diff_responses(&self, old: &HttpResponse, new: &HttpResponse) -> ResponseDiff {
        ResponseDiff {
            status: change(old.status, new.status),
            reason: change(old.reason.clone(), new.reason.clone()),
            version: change(old.http_version.to_string(), new.http_version.to_string()),
            headers: self.diff_headers(&old.headers, &new.headers),
            body: self.diff_bodies(&old.body, old.content_type(), &new.body, new.content_type()),
        }
    }

    /// Diffs two requests.
    #[must_use]
    pub fn diff_requests(&self, old: &HttpRequest, new: &HttpRequest) -> RequestDiff {
        let url = (old.url != new.url && self.masker.mask(&old.url) != self.masker.mask(&new.url))
            .then(|| FieldChange {
                old: old.url.clone(),
                new: new.url.clone(),
            });
        RequestDiff {
            method: change(old.method.clone(), new.method.clone()),
            url,
            version: change(old.http_version.to_string(), new.http_version.to_string()),
            headers: self.diff_headers(&old.headers, &new.headers),
            body: self.diff_bodies(&old.body, old.content_type(), &new.body, new.content_type()),
        }
    }

    /// Diffs two exchanges: requests, and responses when both have one.
    #[must_use]
    pub fn diff_exchanges(&self, old: &HttpExchange, new: &HttpExchange) -> ExchangeDiff {
        let response = match (&old.response, &new.response) {
            (Some(a), Some(b)) => Some(self.diff_responses(a, b)),
            _ => None,
        };
        ExchangeDiff {
            request: self.diff_requests(&old.request, &new.request),
            response,
            response_presence: change(old.response.is_some(), new.response.is_some()),
        }
    }

    /// Diffs header lists: names case-insensitively, values per name in
    /// wire order after masking. Ignored headers are skipped.
    #[must_use]
    pub fn diff_headers(&self, old: &[HeaderEntry], new: &[HeaderEntry]) -> Vec<HeaderChange> {
        let group = |headers: &[HeaderEntry]| {
            let mut map: BTreeMap<String, Vec<String>> = BTreeMap::new();
            for h in headers {
                let name = h.name.to_ascii_lowercase();
                if !self.ignore_headers.contains(&name) {
                    map.entry(name).or_default().push(h.value.clone());
                }
            }
            map
        };
        let (a, b) = (group(old), group(new));
        let mut out = Vec::new();
        for (name, va) in &a {
            match b.get(name) {
                None => out.push(HeaderChange {
                    name: name.clone(),
                    kind: HeaderChangeKind::Removed { values: va.clone() },
                }),
                Some(vb) => {
                    let same = va.len() == vb.len()
                        && va
                            .iter()
                            .zip(vb)
                            .all(|(x, y)| x == y || self.masker.mask(x) == self.masker.mask(y));
                    if !same {
                        out.push(HeaderChange {
                            name: name.clone(),
                            kind: HeaderChangeKind::Changed {
                                old: va.clone(),
                                new: vb.clone(),
                            },
                        });
                    }
                }
            }
        }
        for (name, vb) in &b {
            if !a.contains_key(name) {
                out.push(HeaderChange {
                    name: name.clone(),
                    kind: HeaderChangeKind::Added { values: vb.clone() },
                });
            }
        }
        out.sort_by(|x, y| x.name.cmp(&y.name));
        out
    }

    /// Diffs two bodies: structurally when both are JSON, as masked text
    /// when both are UTF-8, by bytes otherwise.
    #[must_use]
    pub fn diff_bodies(
        &self,
        old: &HttpBody,
        old_type: Option<&str>,
        new: &HttpBody,
        new_type: Option<&str>,
    ) -> BodyDiff {
        if old.as_bytes() == new.as_bytes() && old.content_encoding == new.content_encoding {
            return BodyDiff::Same;
        }
        let binary = || BodyDiff::Binary {
            old_len: old.as_bytes().len(),
            new_len: new.as_bytes().len(),
        };
        let max = self.options.max_text_len;
        let (Some(a), Some(b)) = (text_of(old, max), text_of(new, max)) else {
            return binary();
        };
        if self.options.json
            && let Some((va, vb)) = json_pair(a, old_type, b, new_type)
        {
            let changes = JsonDiffer {
                masker: &self.masker,
                ignore: &self.ignore_pointers,
                options: &self.options.diff,
            }
            .diff(&va, &vb);
            return if changes.is_empty() {
                BodyDiff::Same
            } else {
                BodyDiff::Json {
                    changes,
                    leaves: leaf_count(&va).max(leaf_count(&vb)),
                }
            };
        }
        let (ma, mb) = (self.masker.mask(a), self.masker.mask(b));
        if ma == mb {
            return BodyDiff::Same;
        }
        let g = self.options.granularity;
        let script = {
            let d = TextDiff::with_options(&ma, &mb, g, &self.options.diff);
            d.script().clone()
        };
        BodyDiff::Text(TextBodyDiff {
            old: ma.into_owned(),
            new: mb.into_owned(),
            granularity: g,
            script,
        })
    }
}

/// Diffs two responses with default options (volatile headers ignored,
/// default masking, JSON structural diff).
///
/// ```
/// use rune_http_model::HttpResponse;
///
/// let a = HttpResponse::new(200).with_body("hello\n");
/// let b = HttpResponse::new(404).with_body("not found\n");
/// let diff = rune_diff::diff_responses(&a, &b);
/// assert_eq!(diff.status.as_ref().map(|s| (s.old, s.new)), Some((200, 404)));
/// assert!(!diff.is_equivalent());
/// ```
#[must_use]
pub fn diff_responses(old: &HttpResponse, new: &HttpResponse) -> ResponseDiff {
    HttpDiffer::new(&HttpDiffOptions::default()).map_or_else(
        // The default options hold no custom patterns, so this cannot fail;
        // fall back to an exact comparison rather than panicking.
        |_| {
            HttpDiffer {
                masker: Masker::noop(),
                ignore_headers: Vec::new(),
                ignore_pointers: Vec::new(),
                options: HttpDiffOptions::strict(),
            }
            .diff_responses(old, new)
        },
        |d| d.diff_responses(old, new),
    )
}

fn change<T: PartialEq>(old: T, new: T) -> Option<FieldChange<T>> {
    (old != new).then_some(FieldChange { old, new })
}

fn text_of(body: &HttpBody, max: usize) -> Option<&str> {
    if body.content_encoding.is_some() || body.as_bytes().len() > max {
        return None;
    }
    body.as_utf8()
}

fn is_json_type(content_type: Option<&str>) -> bool {
    content_type.is_some_and(|t| {
        let mime = t
            .split(';')
            .next()
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase();
        mime == "application/json" || mime.ends_with("+json") || mime == "text/json"
    })
}

/// Both bodies parsed as JSON, if either is labelled JSON or both look like
/// JSON documents.
fn json_pair(a: &str, at: Option<&str>, b: &str, bt: Option<&str>) -> Option<(Value, Value)> {
    let looks = |s: &str| matches!(s.trim_start().as_bytes().first(), Some(b'{' | b'['));
    if !(is_json_type(at) || is_json_type(bt) || (looks(a) && looks(b))) {
        return None;
    }
    let parse = |s: &str| {
        if s.trim().is_empty() {
            None
        } else {
            serde_json::from_str::<Value>(s).ok()
        }
    };
    Some((parse(a)?, parse(b)?))
}

fn write_values(f: &mut fmt::Formatter<'_>, values: &[String]) -> fmt::Result {
    for (i, v) in values.iter().enumerate() {
        if i > 0 {
            f.write_str(", ")?;
        }
        write!(f, "{v:?}")?;
    }
    Ok(())
}

fn write_headers(f: &mut fmt::Formatter<'_>, headers: &[HeaderChange]) -> fmt::Result {
    for h in headers {
        write!(f, "header {}: ", h.name)?;
        match &h.kind {
            HeaderChangeKind::Added { values } => {
                f.write_str("added ")?;
                write_values(f, values)?;
            }
            HeaderChangeKind::Removed { values } => {
                f.write_str("removed ")?;
                write_values(f, values)?;
            }
            HeaderChangeKind::Changed { old, new } => {
                write_values(f, old)?;
                f.write_str(" -> ")?;
                write_values(f, new)?;
            }
        }
        writeln!(f)?;
    }
    Ok(())
}

impl fmt::Display for BodyDiff {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Same => Ok(()),
            Self::Json { changes, .. } => {
                for c in changes {
                    let p = if c.pointer.is_empty() {
                        "/"
                    } else {
                        &c.pointer
                    };
                    match &c.kind {
                        crate::JsonChangeKind::Added { value } => {
                            writeln!(f, "body {p}: added {value}")?;
                        }
                        crate::JsonChangeKind::Removed { value } => {
                            writeln!(f, "body {p}: removed {value}")?;
                        }
                        crate::JsonChangeKind::Changed { old, new } => {
                            writeln!(f, "body {p}: {old} -> {new}")?;
                        }
                    }
                }
                Ok(())
            }
            Self::Text(t) => {
                writeln!(f, "body (text, similarity {:.3}):", t.ratio())?;
                f.write_str(&t.unified(3))
            }
            Self::Binary { old_len, new_len } => {
                writeln!(f, "body (binary): {old_len} bytes -> {new_len} bytes")
            }
        }
    }
}

impl fmt::Display for ResponseDiff {
    /// One line per difference; empty when equivalent.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(s) = &self.status {
            writeln!(f, "status: {} -> {}", s.old, s.new)?;
        }
        if let Some(v) = &self.version {
            writeln!(f, "version: {} -> {}", v.old, v.new)?;
        }
        if let Some(r) = &self.reason {
            writeln!(f, "reason: {:?} -> {:?}", r.old, r.new)?;
        }
        write_headers(f, &self.headers)?;
        self.body.fmt(f)
    }
}

impl fmt::Display for RequestDiff {
    /// One line per difference; empty when equivalent.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(m) = &self.method {
            writeln!(f, "method: {} -> {}", m.old, m.new)?;
        }
        if let Some(u) = &self.url {
            writeln!(f, "url: {} -> {}", u.old, u.new)?;
        }
        if let Some(v) = &self.version {
            writeln!(f, "version: {} -> {}", v.old, v.new)?;
        }
        write_headers(f, &self.headers)?;
        self.body.fmt(f)
    }
}
