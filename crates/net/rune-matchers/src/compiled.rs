//! Compiled matchers and extractors: regexes and paths are built once.

use regex::bytes::{Regex, RegexBuilder};

use rune_http_model::{HeaderEntry, HttpExchange};

use crate::part::{needs_response, part_bytes};
use crate::path::{JsonPath, XPath, json_scalar};
use crate::{
    Extractor, ExtractorKind, MAX_EXTRACTED_VALUES, MAX_PATTERN_LEN, MatchCondition, MatchError,
    Matcher, MatcherKind, MatcherSet, REGEX_DFA_SIZE_LIMIT, REGEX_SIZE_LIMIT, TimeComparison, clip,
};

/// Builds a size-limited regex. `source` is the user text the length cap
/// applies to (the pattern itself, or a word/hex string it was derived from).
fn build_regex(pattern: &str, source: &str, case_insensitive: bool) -> Result<Regex, MatchError> {
    if source.len() > MAX_PATTERN_LEN {
        return Err(MatchError::Regex {
            pattern: clip(source),
            message: format!(
                "pattern is {} bytes; the limit is {MAX_PATTERN_LEN}",
                source.len()
            ),
        });
    }
    RegexBuilder::new(pattern)
        .case_insensitive(case_insensitive)
        .size_limit(REGEX_SIZE_LIMIT)
        .dfa_size_limit(REGEX_DFA_SIZE_LIMIT)
        .nest_limit(100)
        .build()
        .map_err(|error| MatchError::Regex {
            pattern: clip(source),
            message: error.to_string(),
        })
}

fn build_regexes(patterns: &[String], case_insensitive: bool) -> Result<Vec<Regex>, MatchError> {
    patterns
        .iter()
        .map(|pattern| build_regex(pattern, pattern, case_insensitive))
        .collect()
}

/// Turns a hex string (whitespace ignored) into a byte-literal regex.
fn binary_regex(hex: &str) -> Result<Regex, MatchError> {
    let invalid = |message: &str| MatchError::InvalidHex {
        value: clip(hex),
        message: message.to_owned(),
    };
    let digits: Vec<u8> = hex.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    if digits.is_empty() {
        return Err(invalid("empty byte sequence"));
    }
    if !digits.len().is_multiple_of(2) {
        return Err(invalid("odd number of hex digits"));
    }
    if !digits.iter().all(u8::is_ascii_hexdigit) {
        return Err(invalid("non-hex character"));
    }
    let mut pattern = String::from("(?-u:");
    for pair in digits.chunks(2) {
        pattern.push_str("\\x");
        pattern.push(char::from(pair[0]));
        pattern.push(char::from(pair[1]));
    }
    pattern.push(')');
    build_regex(&pattern, hex, false)
}

#[derive(Debug, Clone)]
enum CompiledKind {
    /// Word, regex and binary matchers: one regex per list entry.
    Patterns(Vec<Regex>),
    Status(Vec<u16>),
    Size(Vec<usize>),
    Time(Vec<TimeComparison>),
    Header {
        name: String,
        value: Option<Regex>,
    },
    JsonPointer {
        path: JsonPath,
        value: Option<serde_json::Value>,
    },
}

/// A [`Matcher`] with its regexes and paths built once.
#[derive(Debug, Clone)]
pub struct CompiledMatcher {
    source: Matcher,
    kind: CompiledKind,
}

impl CompiledMatcher {
    pub(super) fn new(matcher: &Matcher) -> Result<Self, MatchError> {
        let ci = matcher.case_insensitive;
        let kind = match &matcher.kind {
            MatcherKind::Word { words } => CompiledKind::Patterns(
                words
                    .iter()
                    .map(|word| build_regex(&regex::escape(word), word, ci))
                    .collect::<Result<_, _>>()?,
            ),
            MatcherKind::Regex { regex } => CompiledKind::Patterns(build_regexes(regex, ci)?),
            MatcherKind::Binary { binary } => CompiledKind::Patterns(
                binary
                    .iter()
                    .map(|hex| binary_regex(hex))
                    .collect::<Result<_, _>>()?,
            ),
            MatcherKind::Status { status } => CompiledKind::Status(status.clone()),
            MatcherKind::Size { size } => CompiledKind::Size(size.clone()),
            MatcherKind::Time { time } => CompiledKind::Time(time.clone()),
            MatcherKind::Header { name, value } => CompiledKind::Header {
                name: name.clone(),
                value: value
                    .as_ref()
                    .map(|pattern| build_regex(pattern, pattern, ci))
                    .transpose()?,
            },
            MatcherKind::JsonPointer { pointer, value } => CompiledKind::JsonPointer {
                path: JsonPath::parse(pointer)?,
                value: value.clone(),
            },
        };
        Ok(Self {
            source: matcher.clone(),
            kind,
        })
    }

    /// The matcher this was compiled from.
    #[must_use]
    pub const fn source(&self) -> &Matcher {
        &self.source
    }

    /// Evaluates against one exchange. `false` when the inspected part needs
    /// a response the exchange lacks (regardless of `negative`).
    #[must_use]
    pub fn matches(&self, exchange: &HttpExchange) -> bool {
        self.evaluate(exchange)
            .is_some_and(|hit| hit != self.source.negative)
    }

    /// The un-negated result, or `None` when the part is unavailable.
    fn evaluate(&self, exchange: &HttpExchange) -> Option<bool> {
        let condition = self.source.condition;
        match &self.kind {
            CompiledKind::Status(codes) => exchange.status().map(|code| codes.contains(&code)),
            CompiledKind::Time(comparisons) => {
                let total = exchange.timings.total_milliseconds;
                Some(
                    condition.combine(
                        comparisons
                            .iter()
                            .map(|comparison| comparison.op.holds(total, comparison.milliseconds)),
                    ),
                )
            }
            CompiledKind::Header { name, value } => {
                let response = exchange.response.as_ref()?;
                Some(response.headers.iter().any(|header| {
                    header.name.eq_ignore_ascii_case(name)
                        && value
                            .as_ref()
                            .is_none_or(|regex| regex.is_match(header.value.as_bytes()))
                }))
            }
            CompiledKind::Patterns(regexes) => {
                let bytes = part_bytes(&self.source.part, exchange)?;
                Some(condition.combine(regexes.iter().map(|regex| regex.is_match(&bytes))))
            }
            CompiledKind::Size(sizes) => {
                let bytes = part_bytes(&self.source.part, exchange)?;
                Some(sizes.contains(&bytes.len()))
            }
            CompiledKind::JsonPointer { path, value } => {
                let bytes = part_bytes(&self.source.part, exchange)?;
                let document: Option<serde_json::Value> = serde_json::from_slice(&bytes).ok();
                Some(
                    document
                        .as_ref()
                        .and_then(|document| path.resolve(document))
                        .is_some_and(|found| value.as_ref().is_none_or(|wanted| wanted == found)),
                )
            }
        }
    }
}

/// A [`MatcherSet`] with every matcher compiled once.
#[derive(Debug, Clone)]
pub struct CompiledMatcherSet {
    matchers: Vec<CompiledMatcher>,
    condition: MatchCondition,
}

impl CompiledMatcherSet {
    pub(super) fn new(set: &MatcherSet) -> Result<Self, MatchError> {
        Ok(Self {
            matchers: set
                .matchers
                .iter()
                .map(CompiledMatcher::new)
                .collect::<Result<_, _>>()?,
            condition: set.condition,
        })
    }

    /// The compiled matchers, in order.
    #[must_use]
    pub fn matchers(&self) -> &[CompiledMatcher] {
        &self.matchers
    }

    /// Whether the set is satisfied (short-circuits). An empty set is `false`.
    #[must_use]
    pub fn matches(&self, exchange: &HttpExchange) -> bool {
        self.condition.combine(
            self.matchers
                .iter()
                .map(|matcher| matcher.matches(exchange)),
        )
    }

    /// Evaluates every matcher; returns the indices of those that matched
    /// when the set is satisfied, otherwise `None`.
    #[must_use]
    pub fn fired(&self, exchange: &HttpExchange) -> Option<Vec<usize>> {
        let results: Vec<bool> = self
            .matchers
            .iter()
            .map(|matcher| matcher.matches(exchange))
            .collect();
        self.condition.combine(results.iter().copied()).then(|| {
            results
                .iter()
                .enumerate()
                .filter_map(|(index, hit)| hit.then_some(index))
                .collect()
        })
    }
}

#[derive(Debug, Clone)]
enum CompiledExtract {
    Regex { regexes: Vec<Regex>, group: usize },
    Kval(Vec<String>),
    Json(Vec<JsonPath>),
    Xpath(Vec<XPath>),
    Header(Vec<String>),
    Cookie(Vec<String>),
}

/// An [`Extractor`] with its regexes and paths built once.
#[derive(Debug, Clone)]
pub struct CompiledExtractor {
    source: Extractor,
    kind: CompiledExtract,
}

impl CompiledExtractor {
    pub(super) fn new(extractor: &Extractor) -> Result<Self, MatchError> {
        let kind = match &extractor.kind {
            ExtractorKind::Regex { regex, group } => {
                let regexes = build_regexes(regex, false)?;
                if let Some((pattern, _)) = regex
                    .iter()
                    .zip(&regexes)
                    .find(|(_, compiled)| compiled.captures_len() <= *group)
                {
                    return Err(MatchError::InvalidGroup {
                        pattern: clip(pattern),
                        group: *group,
                    });
                }
                CompiledExtract::Regex {
                    regexes,
                    group: *group,
                }
            }
            ExtractorKind::Kval { kval } => CompiledExtract::Kval(kval.clone()),
            ExtractorKind::Json { json } => CompiledExtract::Json(
                json.iter()
                    .map(|path| JsonPath::parse(path))
                    .collect::<Result<_, _>>()?,
            ),
            ExtractorKind::Xpath { xpath, attribute } => CompiledExtract::Xpath(
                xpath
                    .iter()
                    .map(|path| XPath::parse(path, attribute.as_deref()))
                    .collect::<Result<_, _>>()?,
            ),
            ExtractorKind::Header { header } => CompiledExtract::Header(header.clone()),
            ExtractorKind::Cookie { cookie } => CompiledExtract::Cookie(cookie.clone()),
        };
        Ok(Self {
            source: extractor.clone(),
            kind,
        })
    }

    /// The extractor this was compiled from.
    #[must_use]
    pub const fn source(&self) -> &Extractor {
        &self.source
    }

    /// Every value found, in rule order, capped at [`MAX_EXTRACTED_VALUES`].
    /// Empty when the needed response is missing.
    #[must_use]
    pub fn extract(&self, exchange: &HttpExchange) -> Vec<String> {
        let mut out = Vec::new();
        match &self.kind {
            CompiledExtract::Kval(keys) => kval(exchange, keys, &mut out),
            CompiledExtract::Header(names) => {
                for name in names {
                    out.extend(response_headers(exchange, |header| {
                        header.name.eq_ignore_ascii_case(name.trim())
                    }));
                }
            }
            CompiledExtract::Cookie(names) => {
                for name in names {
                    out.extend(cookies(exchange, name));
                }
            }
            CompiledExtract::Regex { .. }
            | CompiledExtract::Json(_)
            | CompiledExtract::Xpath(_) => self.extract_from_part(exchange, &mut out),
        }
        out.truncate(MAX_EXTRACTED_VALUES);
        out
    }

    fn extract_from_part(&self, exchange: &HttpExchange, out: &mut Vec<String>) {
        if needs_response(&self.source.part) && exchange.response.is_none() {
            return;
        }
        let Some(bytes) = part_bytes(&self.source.part, exchange) else {
            return;
        };
        match &self.kind {
            CompiledExtract::Regex { regexes, group } => {
                for regex in regexes {
                    for captures in regex.captures_iter(&bytes) {
                        if out.len() >= MAX_EXTRACTED_VALUES {
                            return;
                        }
                        if let Some(found) = captures.get(*group) {
                            out.push(String::from_utf8_lossy(found.as_bytes()).into_owned());
                        }
                    }
                }
            }
            CompiledExtract::Json(paths) => {
                if let Ok(document) = serde_json::from_slice::<serde_json::Value>(&bytes) {
                    out.extend(
                        paths
                            .iter()
                            .filter_map(|path| path.resolve(&document))
                            .map(json_scalar),
                    );
                }
            }
            CompiledExtract::Xpath(paths) => {
                let text = String::from_utf8_lossy(&bytes);
                for path in paths {
                    path.evaluate(&text, out);
                }
            }
            CompiledExtract::Kval(_) | CompiledExtract::Header(_) | CompiledExtract::Cookie(_) => {}
        }
    }
}

fn response_headers<'a>(
    exchange: &'a HttpExchange,
    keep: impl Fn(&HeaderEntry) -> bool + 'a,
) -> impl Iterator<Item = String> + 'a {
    exchange
        .response
        .iter()
        .flat_map(|response| response.headers.iter())
        .filter(move |header| keep(header))
        .map(|header| header.value.clone())
}

/// Values of cookie `name` across all `Set-Cookie` response headers.
fn cookies<'a>(exchange: &'a HttpExchange, name: &'a str) -> impl Iterator<Item = String> + 'a {
    response_headers(exchange, |header| {
        header.name.eq_ignore_ascii_case("set-cookie")
    })
    .filter_map(move |set_cookie| {
        let first = set_cookie.split(';').next()?;
        let (cookie, value) = first.split_once('=')?;
        cookie
            .trim()
            .eq_ignore_ascii_case(name.trim())
            .then(|| value.trim().to_owned())
    })
}

fn normalize_key(key: &str) -> String {
    key.trim().to_ascii_lowercase().replace('_', "-")
}

/// nuclei `kval`: headers by normalized key, else a cookie of that name.
fn kval(exchange: &HttpExchange, keys: &[String], out: &mut Vec<String>) {
    for key in keys {
        let wanted = normalize_key(key);
        let before = out.len();
        out.extend(response_headers(exchange, |header| {
            normalize_key(&header.name) == wanted
        }));
        if out.len() == before {
            out.extend(cookies(exchange, key));
        }
    }
}
