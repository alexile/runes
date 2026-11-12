//! Nuclei-style response matching and extraction over
//! [`rune_http_model::HttpExchange`]s.
//!
//! A [`Matcher`] tests one selected [`ResponsePart`] of an exchange (word,
//! regex, status, size, binary, time, header and JSON-pointer kinds, with
//! nuclei-style `condition`, `negative` and `case_insensitive` flags). A
//! [`MatcherSet`] combines several matchers with `and`/`or`. An [`Extractor`]
//! pulls values out of a part (regex groups, header/cookie `kval`, JSON
//! pointer or jq-lite paths, a small `XPath` subset, plain headers, cookies).
//!
//! The rule format follows the
//! [nuclei matcher](https://docs.projectdiscovery.io/templates/reference/matchers)
//! and [extractor](https://docs.projectdiscovery.io/templates/reference/extractors)
//! reference; JSON pointers follow [RFC 6901](https://www.rfc-editor.org/rfc/rfc6901).
//! The crate is sans-I/O: it only reads exchanges you already hold.
//!
//! # Example
//!
//! ```
//! use rune_http_model::{ExchangeId, HttpExchange, HttpRequest, HttpResponse};
//! use rune_matchers::{Extractor, ExtractorKind, MatchCondition, Matcher, MatcherSet};
//!
//! let exchange = HttpExchange::new(ExchangeId(1), "docs", HttpRequest::get("http://host.test/"))
//!     .with_response(
//!         HttpResponse::new(200)
//!             .with_header("Server", "nginx/1.25")
//!             .with_body("<title>Admin Login</title> build=4242"),
//!     );
//!
//! // Compile once, evaluate many times.
//! let set = MatcherSet::new(
//!     vec![Matcher::status([200]), Matcher::word(["admin login"]).ignoring_case()],
//!     MatchCondition::And,
//! )
//! .compile()?;
//! assert!(set.matches(&exchange));
//!
//! let build = Extractor::new(ExtractorKind::Regex {
//!     regex: vec![r"build=(\d+)".into()],
//!     group: 1,
//! })
//! .compile()?;
//! assert_eq!(build.extract(&exchange), vec!["4242"]);
//! # Ok::<(), rune_matchers::MatchError>(())
//! ```
//!
//! # Compile once
//!
//! [`Matcher::matches`] and [`Extractor::extract`] compile on every call and
//! are meant for one-off checks. Hot loops should compile once with
//! [`Matcher::compile`], [`MatcherSet::compile`] or [`Extractor::compile`] and
//! evaluate the resulting [`CompiledMatcher`], [`CompiledMatcherSet`] or
//! [`CompiledExtractor`], which never recompile and never fail at evaluation.
//!
//! # Untrusted patterns
//!
//! Templates and plugins are untrusted, so every regex is built with
//! [`regex::bytes::RegexBuilder`] under [`REGEX_SIZE_LIMIT`],
//! [`REGEX_DFA_SIZE_LIMIT`] and a nesting limit, and user patterns longer than
//! [`MAX_PATTERN_LEN`] bytes are rejected with [`MatchError::Regex`]. The
//! `regex` crate guarantees linear-time matching, so catastrophic
//! backtracking is impossible; in exchange **backreferences and lookaround
//! (`\1`, `(?=…)`, `(?!…)`, `(?<=…)`) are unsupported** and fail to compile.
//! Regexes run over the raw bytes of a part (Unicode-aware for UTF-8 text).
//!
//! # Missing responses
//!
//! A matcher whose part needs the response (everything except the request
//! parts and [`MatcherKind::Time`]) evaluates to `false` when the exchange has
//! no response, regardless of `negative`. Extractors yield no values.
//!
//! # Features
//!
//! - `serde`: serialize and deserialize rules (nuclei-like JSON shape, with a
//!   `type` tag such as `{"type": "word", "words": ["admin"]}`).
//! - `schemars`: derive `schemars::JsonSchema` for rules. Implies `serde`.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod compiled;
mod part;
mod path;

#[cfg(test)]
mod tests;

use rune_http_model::HttpExchange;

pub use compiled::{CompiledExtractor, CompiledMatcher, CompiledMatcherSet};

/// Maximum length in bytes of a user-supplied regex pattern.
pub const MAX_PATTERN_LEN: usize = 4096;
/// Compiled-program size limit for every regex (bytes).
pub const REGEX_SIZE_LIMIT: usize = 1024 * 1024;
/// Lazy-DFA cache size limit for every regex (bytes).
pub const REGEX_DFA_SIZE_LIMIT: usize = 1024 * 1024;
/// Maximum number of values a single extractor returns.
pub const MAX_EXTRACTED_VALUES: usize = 1000;

/// Which part of an exchange a matcher or extractor inspects.
///
/// Rendered text parts use `\n` line endings: headers become
/// `Name: Value\n` lines in their original order.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[non_exhaustive]
pub enum ResponsePart {
    /// The exact response body bytes (the default).
    #[default]
    Body,
    /// All response headers as `Name: Value\n` lines.
    Headers,
    /// The values of one response header (case-insensitive name), one per line.
    Header(String),
    /// The response status code as decimal text.
    Status,
    /// Response headers, a blank line, then the body.
    All,
    /// The captured wire bytes of the response when available, otherwise a
    /// rendering of status line, headers, blank line and body.
    Raw,
    /// The exact request body bytes.
    RequestBody,
    /// All request headers as `Name: Value\n` lines.
    RequestHeaders,
    /// The request URL.
    Url,
    /// Total exchange time in milliseconds as decimal text.
    Time,
}

/// How several boolean results are combined.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[non_exhaustive]
pub enum MatchCondition {
    /// Every result must be true.
    And,
    /// At least one result must be true (the default).
    #[default]
    Or,
}

impl MatchCondition {
    /// Combines results (short-circuiting); an empty input is always `false`.
    pub fn combine(self, mut results: impl Iterator<Item = bool>) -> bool {
        let Some(first) = results.next() else {
            return false;
        };
        match self {
            Self::And => first && results.all(|hit| hit),
            Self::Or => first || results.any(|hit| hit),
        }
    }
}

/// A numeric comparison operator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[non_exhaustive]
pub enum Comparison {
    /// Strictly less than.
    Lt,
    /// Less than or equal.
    Le,
    /// Strictly greater than.
    Gt,
    /// Greater than or equal.
    Ge,
    /// Equal.
    Eq,
    /// Not equal.
    Ne,
}

impl Comparison {
    /// Whether `left <op> right` holds.
    #[must_use]
    pub const fn holds(self, left: u64, right: u64) -> bool {
        match self {
            Self::Lt => left < right,
            Self::Le => left <= right,
            Self::Gt => left > right,
            Self::Ge => left >= right,
            Self::Eq => left == right,
            Self::Ne => left != right,
        }
    }
}

/// One comparison against the exchange's total time in milliseconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
pub struct TimeComparison {
    /// The operator, applied as `total_milliseconds <op> milliseconds`.
    pub op: Comparison,
    /// The threshold in milliseconds.
    pub milliseconds: u64,
}

impl TimeComparison {
    /// `total_milliseconds <op> milliseconds`.
    #[must_use]
    pub const fn new(op: Comparison, milliseconds: u64) -> Self {
        Self { op, milliseconds }
    }
}

/// The concrete matching rule. With the `serde` feature it is serialized
/// with a `type` tag next to the shared [`Matcher`] fields, e.g.
/// `{"type": "word", "words": ["admin"]}`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(tag = "type", rename_all = "snake_case"))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[non_exhaustive]
pub enum MatcherKind {
    /// The part contains each/any of the literal words.
    Word {
        /// Literal substrings to look for.
        words: Vec<String>,
    },
    /// The part matches each/any of the regular expressions.
    Regex {
        /// Patterns (Rust `regex` syntax; no backreferences or lookaround).
        regex: Vec<String>,
    },
    /// The response status is in the list (`condition` and `part` ignored).
    Status {
        /// Accepted status codes.
        status: Vec<u16>,
    },
    /// The part's byte length is in the list.
    Size {
        /// Accepted lengths in bytes.
        size: Vec<usize>,
    },
    /// The part's raw bytes contain each/any hex-encoded byte sequence.
    /// `case_insensitive` is ignored.
    Binary {
        /// Hex byte sequences, e.g. `"504b0304"`; whitespace is ignored.
        binary: Vec<String>,
    },
    /// The total exchange time satisfies each/any comparison (`part` ignored).
    Time {
        /// Comparisons against the total time in milliseconds.
        time: Vec<TimeComparison>,
    },
    /// A response header is present, optionally with a value matching a regex
    /// (`part` ignored; any of several same-named headers may match).
    Header {
        /// Header name, compared case-insensitively.
        name: String,
        /// Regex the value must match; absent means "header exists".
        #[cfg_attr(
            feature = "serde",
            serde(default, skip_serializing_if = "Option::is_none")
        )]
        value: Option<String>,
    },
    /// The part parses as JSON and the path resolves, optionally to an exact
    /// value. Unparseable JSON never matches.
    JsonPointer {
        /// RFC 6901 pointer (`/a/0/b`, or empty for the root) or jq-lite
        /// path (`.a[0].b`, `a.b`).
        pointer: String,
        /// Value the target must equal (strict JSON equality); absent means
        /// "path exists".
        #[cfg_attr(
            feature = "serde",
            serde(default, skip_serializing_if = "Option::is_none")
        )]
        value: Option<serde_json::Value>,
    },
}

/// One matcher: a rule tested against a selected part of an exchange.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[non_exhaustive]
pub struct Matcher {
    /// The rule and its parameters.
    #[cfg_attr(feature = "serde", serde(flatten))]
    pub kind: MatcherKind,
    /// The part inspected (defaults to the response body).
    #[cfg_attr(feature = "serde", serde(default))]
    pub part: ResponsePart,
    /// How the entries of the rule's list combine (defaults to `or`).
    #[cfg_attr(feature = "serde", serde(default))]
    pub condition: MatchCondition,
    /// Invert the result (only when the part is available).
    #[cfg_attr(feature = "serde", serde(default))]
    pub negative: bool,
    /// Match words, regexes and header values ignoring case (Unicode-aware).
    #[cfg_attr(feature = "serde", serde(default))]
    pub case_insensitive: bool,
}

impl Matcher {
    /// A matcher of `kind` on the response body with default flags.
    #[must_use]
    pub const fn new(kind: MatcherKind) -> Self {
        Self {
            kind,
            part: ResponsePart::Body,
            condition: MatchCondition::Or,
            negative: false,
            case_insensitive: false,
        }
    }

    /// A word matcher on the body.
    #[must_use]
    pub fn word<I: IntoIterator<Item = S>, S: Into<String>>(words: I) -> Self {
        Self::new(MatcherKind::Word {
            words: words.into_iter().map(Into::into).collect(),
        })
    }

    /// A regex matcher on the body.
    #[must_use]
    pub fn regex<I: IntoIterator<Item = S>, S: Into<String>>(patterns: I) -> Self {
        Self::new(MatcherKind::Regex {
            regex: patterns.into_iter().map(Into::into).collect(),
        })
    }

    /// A status matcher.
    #[must_use]
    pub fn status(codes: impl Into<Vec<u16>>) -> Self {
        Self::new(MatcherKind::Status {
            status: codes.into(),
        })
    }

    /// Sets the inspected part.
    #[must_use]
    pub fn with_part(mut self, part: ResponsePart) -> Self {
        self.part = part;
        self
    }

    /// Sets the list condition.
    #[must_use]
    pub const fn with_condition(mut self, condition: MatchCondition) -> Self {
        self.condition = condition;
        self
    }

    /// Inverts the matcher.
    #[must_use]
    pub const fn negated(mut self) -> Self {
        self.negative = true;
        self
    }

    /// Makes word/regex/header-value matching case-insensitive.
    #[must_use]
    pub const fn ignoring_case(mut self) -> Self {
        self.case_insensitive = true;
        self
    }

    /// Compiles the matcher once for repeated evaluation.
    pub fn compile(&self) -> Result<CompiledMatcher, MatchError> {
        CompiledMatcher::new(self)
    }

    /// Compiles and evaluates the matcher against one exchange.
    pub fn matches(&self, exchange: &HttpExchange) -> Result<bool, MatchError> {
        Ok(self.compile()?.matches(exchange))
    }
}

/// Several matchers combined with `and`/`or`. An empty set never matches.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[non_exhaustive]
pub struct MatcherSet {
    /// The matchers.
    #[cfg_attr(feature = "serde", serde(default))]
    pub matchers: Vec<Matcher>,
    /// How matcher results combine (defaults to `or`).
    #[cfg_attr(feature = "serde", serde(default))]
    pub condition: MatchCondition,
}

impl MatcherSet {
    /// A set of `matchers` combined with `condition`.
    #[must_use]
    pub const fn new(matchers: Vec<Matcher>, condition: MatchCondition) -> Self {
        Self {
            matchers,
            condition,
        }
    }

    /// Compiles every matcher once for repeated evaluation.
    pub fn compile(&self) -> Result<CompiledMatcherSet, MatchError> {
        CompiledMatcherSet::new(self)
    }

    /// Compiles and evaluates the set against one exchange.
    pub fn matches(&self, exchange: &HttpExchange) -> Result<bool, MatchError> {
        Ok(self.compile()?.matches(exchange))
    }
}

/// The concrete extraction rule. With the `serde` feature it is serialized
/// with a `type` tag next to the shared [`Extractor`] fields, e.g.
/// `{"type": "regex", "regex": ["id=(\\d+)"], "group": 1}`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(tag = "type", rename_all = "snake_case"))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[non_exhaustive]
pub enum ExtractorKind {
    /// Every match of every pattern, in pattern order, taking one capture group.
    Regex {
        /// Patterns (Rust `regex` syntax; no backreferences or lookaround).
        regex: Vec<String>,
        /// Capture group index (`0` = whole match); must exist in every pattern.
        #[cfg_attr(feature = "serde", serde(default))]
        group: usize,
    },
    /// nuclei `kval`: response header values by key (case-insensitive, `_`
    /// treated as `-`), falling back to a `Set-Cookie` cookie of that name.
    /// `part` is ignored.
    Kval {
        /// Keys to look up, in order.
        kval: Vec<String>,
    },
    /// Values at JSON paths of the part parsed as JSON. Strings are returned
    /// unquoted, other values as compact JSON.
    Json {
        /// RFC 6901 pointers (`/a/0`) or jq-lite paths (`.a[0].b`, `a.b`).
        json: Vec<String>,
    },
    /// Values selected by a minimal `XPath` subset over the part parsed as XML.
    ///
    /// Supported: absolute (`/a/b`) or descendant (`//b`, `//a/b`) element
    /// paths, `*` steps, and a final `text()` or `@attr` step. Not supported:
    /// predicates (`[1]`, `[@x='y']`), axes, functions, unions and `//` after
    /// the first step. Element names compare by local name. Text values are
    /// the trimmed concatenated descendant text. Input should be well-formed
    /// XML; HTML is best-effort (void elements like `<br>` confuse nesting).
    Xpath {
        /// Paths to evaluate, in order.
        xpath: Vec<String>,
        /// Attribute to take from matched elements instead of their text.
        #[cfg_attr(
            feature = "serde",
            serde(default, skip_serializing_if = "Option::is_none")
        )]
        attribute: Option<String>,
    },
    /// All values of response headers by exact (case-insensitive) name.
    /// `part` is ignored.
    Header {
        /// Header names, in order.
        header: Vec<String>,
    },
    /// Cookie values from response `Set-Cookie` headers by (case-insensitive)
    /// name. `part` is ignored.
    Cookie {
        /// Cookie names, in order.
        cookie: Vec<String>,
    },
}

/// One extractor: pulls values out of a selected part of an exchange.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[non_exhaustive]
pub struct Extractor {
    /// The rule and its parameters.
    #[cfg_attr(feature = "serde", serde(flatten))]
    pub kind: ExtractorKind,
    /// The part read (defaults to the response body).
    #[cfg_attr(feature = "serde", serde(default))]
    pub part: ResponsePart,
}

impl Extractor {
    /// An extractor of `kind` reading the response body.
    #[must_use]
    pub const fn new(kind: ExtractorKind) -> Self {
        Self {
            kind,
            part: ResponsePart::Body,
        }
    }

    /// Sets the part read.
    #[must_use]
    pub fn with_part(mut self, part: ResponsePart) -> Self {
        self.part = part;
        self
    }

    /// Compiles the extractor once for repeated evaluation.
    pub fn compile(&self) -> Result<CompiledExtractor, MatchError> {
        CompiledExtractor::new(self)
    }

    /// Compiles and runs the extractor against one exchange. Returns every
    /// value found (at most [`MAX_EXTRACTED_VALUES`]), in rule order.
    pub fn extract(&self, exchange: &HttpExchange) -> Result<Vec<String>, MatchError> {
        Ok(self.compile()?.extract(exchange))
    }
}

/// What went wrong while compiling a matcher or extractor.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum MatchError {
    /// A regex failed to compile, was too long, or exceeded a size limit.
    #[error("invalid regex {pattern:?}: {message}")]
    Regex {
        /// The pattern (truncated to 200 characters).
        pattern: String,
        /// Why it was rejected.
        message: String,
    },
    /// A regex extractor asked for a capture group the pattern lacks.
    #[error("regex {pattern:?} has no capture group {group}")]
    InvalidGroup {
        /// The pattern (truncated to 200 characters).
        pattern: String,
        /// The requested group index.
        group: usize,
    },
    /// A binary matcher entry is not valid hex.
    #[error("invalid hex {value:?}: {message}")]
    InvalidHex {
        /// The entry (truncated to 200 characters).
        value: String,
        /// Why it was rejected.
        message: String,
    },
    /// A JSON path or `XPath` expression is malformed or unsupported.
    #[error("invalid path {path:?}: {message}")]
    InvalidPath {
        /// The path (truncated to 200 characters).
        path: String,
        /// Why it was rejected.
        message: String,
    },
}

impl MatchError {
    /// A stable, machine-readable kind an agent can branch on.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Regex { .. } => "invalid_regex",
            Self::InvalidGroup { .. } => "invalid_regex_group",
            Self::InvalidHex { .. } => "invalid_hex",
            Self::InvalidPath { .. } => "invalid_path",
        }
    }
}

/// Truncates user input echoed in errors.
pub(crate) fn clip(text: &str) -> String {
    text.chars().take(200).collect()
}
