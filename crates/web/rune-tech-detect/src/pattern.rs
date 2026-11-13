//! Wappalyzer-style patterns: a regex plus `\;version:` and `\;confidence:` tags.

use std::cmp::Ordering;

use regex::{Regex, RegexBuilder};
use rune_matchers::{MAX_PATTERN_LEN, MatchError, REGEX_DFA_SIZE_LIMIT, REGEX_SIZE_LIMIT};

/// One pattern of a rule.
///
/// Written as in Wappalyzer rule files: a regular expression optionally
/// followed by `\;`-separated tags, e.g.
/// `jquery[.-]([\d.]+)\.js\;version:\1\;confidence:50`.
///
/// - `version:` is a template: `\1`…`\9` are capture groups, and
///   `\1?yes:no` picks `yes` when group 1 matched and `no` otherwise.
/// - `confidence:` is 0 to 100 (default 100).
///
/// An empty regex matches anything: for headers, cookies and meta tags it
/// means "present".
///
/// ```
/// use rune_tech_detect::Pattern;
///
/// let pattern = Pattern::parse(r"jquery-([\d.]+)\.min\.js\;version:\1\;confidence:80");
/// assert_eq!(pattern.regex, r"jquery-([\d.]+)\.min\.js");
/// assert_eq!(pattern.version.as_deref(), Some(r"\1"));
/// assert_eq!(pattern.confidence, 80);
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub struct Pattern {
    /// The regular expression (Rust `regex` syntax; matched ignoring case).
    pub regex: String,
    /// The version template, when the pattern yields a version.
    pub version: Option<String>,
    /// Confidence points (0 to 100) the pattern adds when it matches.
    pub confidence: u8,
}

impl Pattern {
    /// A pattern with full confidence and no version.
    #[must_use]
    pub fn new(regex: impl Into<String>) -> Self {
        Self {
            regex: regex.into(),
            version: None,
            confidence: 100,
        }
    }

    /// Sets the version template.
    #[must_use]
    pub fn with_version(mut self, template: impl Into<String>) -> Self {
        self.version = Some(template.into());
        self
    }

    /// Sets the confidence (capped at 100).
    #[must_use]
    pub fn with_confidence(mut self, confidence: u8) -> Self {
        self.confidence = confidence.min(100);
        self
    }

    /// Parses the Wappalyzer string form. Unknown tags are ignored, and an
    /// unparseable confidence keeps the default, as Wappalyzer does.
    #[must_use]
    pub fn parse(text: &str) -> Self {
        let mut parts = text.split("\\;");
        let mut pattern = Self::new(parts.next().unwrap_or_default());
        for tag in parts {
            if let Some(version) = tag.strip_prefix("version:") {
                pattern.version = Some(version.to_owned());
            } else if let Some(confidence) = tag.strip_prefix("confidence:")
                && let Ok(confidence) = confidence.trim().parse::<u8>()
            {
                pattern.confidence = confidence.min(100);
            }
        }
        pattern
    }
}

/// A pattern with its regex built.
#[derive(Debug, Clone)]
pub struct CompiledPattern {
    pub(crate) regex: Option<Regex>,
    pub(crate) version: Option<String>,
    pub(crate) confidence: u8,
}

/// The result of one pattern matching some text.
pub struct PatternMatch {
    pub(crate) confidence: u8,
    pub(crate) version: Option<String>,
}

impl CompiledPattern {
    /// Builds the regex, case-insensitive and size-limited like
    /// [`rune_matchers`] regexes.
    pub(crate) fn new(pattern: &Pattern) -> Result<Self, MatchError> {
        let regex = if pattern.regex.is_empty() {
            None
        } else {
            if pattern.regex.len() > MAX_PATTERN_LEN {
                return Err(MatchError::Regex {
                    pattern: crate::error::clip(&pattern.regex),
                    message: format!(
                        "pattern is {} bytes; the limit is {MAX_PATTERN_LEN}",
                        pattern.regex.len()
                    ),
                });
            }
            Some(
                RegexBuilder::new(&pattern.regex)
                    .case_insensitive(true)
                    .size_limit(REGEX_SIZE_LIMIT)
                    .dfa_size_limit(REGEX_DFA_SIZE_LIMIT)
                    .nest_limit(100)
                    .build()
                    .map_err(|error| MatchError::Regex {
                        pattern: crate::error::clip(&pattern.regex),
                        message: error.to_string(),
                    })?,
            )
        };
        Ok(Self {
            regex,
            version: pattern.version.clone(),
            confidence: pattern.confidence.min(100),
        })
    }

    /// Matches `text`; with a version template, every match is tried and
    /// the highest resolved version wins.
    pub(crate) fn matches(&self, text: &str) -> Option<PatternMatch> {
        let Some(regex) = &self.regex else {
            return Some(PatternMatch {
                confidence: self.confidence,
                version: None,
            });
        };
        let Some(template) = &self.version else {
            return regex.is_match(text).then_some(PatternMatch {
                confidence: self.confidence,
                version: None,
            });
        };
        let mut found = false;
        let mut best: Option<String> = None;
        // Bounded: a body can hold many script tags, but not this many
        // version strings worth comparing.
        for captures in regex.captures_iter(text).take(100) {
            found = true;
            let groups: Vec<Option<&str>> = captures
                .iter()
                .map(|group| group.map(|m| m.as_str()))
                .collect();
            let version = resolve_version(template, &groups);
            if !version.is_empty()
                && best
                    .as_deref()
                    .is_none_or(|best| compare_versions(&version, best) == Ordering::Greater)
            {
                best = Some(version);
            }
        }
        found.then_some(PatternMatch {
            confidence: self.confidence,
            version: best,
        })
    }
}

/// Expands a version template with capture groups.
///
/// `groups[0]` is the whole match. `\N` is group N (empty when it did not match);
/// `\N?a:b` is `a` when group N matched non-empty, else `b`, with `\N`
/// expanded in the chosen branch (a ternary is not nested, as in
/// Wappalyzer). The result is trimmed and at most 64 characters.
#[must_use]
pub fn resolve_version(template: &str, groups: &[Option<&str>]) -> String {
    let group = |index: usize| {
        groups
            .get(index)
            .copied()
            .flatten()
            .filter(|text| !text.is_empty())
    };
    let bytes = template.as_bytes();
    // Ternary form: the whole template is `\N?a:b`.
    let template =
        if bytes.len() >= 3 && bytes[0] == b'\\' && bytes[1].is_ascii_digit() && bytes[2] == b'?' {
            let index = usize::from(bytes[1] - b'0');
            let rest = &template[3..];
            let (yes, no) = rest.split_once(':').unwrap_or((rest, ""));
            if group(index).is_some() { yes } else { no }
        } else {
            template
        };
    let mut out = String::new();
    let mut chars = template.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\\'
            && let Some(digit) = chars.peek().and_then(|d| d.to_digit(10))
        {
            chars.next();
            // A digit is at most 9, so the cast is lossless.
            out.push_str(group(digit as usize).unwrap_or_default());
            continue;
        }
        out.push(c);
    }
    out.trim().chars().take(64).collect()
}

/// Compares dotted versions numerically segment by segment (`1.10` >
/// `1.9`), falling back to text for non-numeric segments; a longer version
/// with an equal prefix is greater.
#[must_use]
pub fn compare_versions(a: &str, b: &str) -> Ordering {
    let mut left = a.split(['.', '-', '_']);
    let mut right = b.split(['.', '-', '_']);
    loop {
        match (left.next(), right.next()) {
            (None, None) => return Ordering::Equal,
            (Some(_), None) => return Ordering::Greater,
            (None, Some(_)) => return Ordering::Less,
            (Some(x), Some(y)) => {
                let order = match (x.parse::<u64>(), y.parse::<u64>()) {
                    (Ok(x), Ok(y)) => x.cmp(&y),
                    _ => x.cmp(y),
                };
                if order != Ordering::Equal {
                    return order;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_tags() {
        let pattern = Pattern::parse(r"^nginx(?:/([\d.]+))?\;version:\1");
        assert_eq!(pattern.regex, r"^nginx(?:/([\d.]+))?");
        assert_eq!(pattern.version.as_deref(), Some(r"\1"));
        assert_eq!(pattern.confidence, 100);
        let pattern = Pattern::parse(r"x\;confidence:250\;bogus:1");
        assert_eq!(pattern.confidence, 100);
        assert_eq!(Pattern::parse(r"x\;confidence:nan").confidence, 100);
        assert_eq!(Pattern::parse("").regex, "");
        assert_eq!(Pattern::new("a").with_confidence(150).confidence, 100);
    }

    #[test]
    fn version_templates() {
        let groups = [Some("jquery-3.7.1"), Some("3.7.1"), None];
        assert_eq!(resolve_version(r"\1", &groups), "3.7.1");
        assert_eq!(resolve_version(r"v\1-\2!", &groups), "v3.7.1-!");
        assert_eq!(resolve_version(r"\1?yes:no", &groups), "yes");
        assert_eq!(resolve_version(r"\2?yes:no", &groups), "no");
        assert_eq!(resolve_version(r"\1?\1:", &groups), "3.7.1");
        assert_eq!(resolve_version(r"\9", &groups), "");
        assert_eq!(resolve_version("\\", &groups), "\\");
        assert_eq!(resolve_version("é\\1", &groups), "é3.7.1");
    }

    // Regression: a ternary branch was resolved as a template again, so a
    // rule file could nest `\1?` deep enough to overflow the stack.
    #[test]
    fn ternary_branches_are_expanded_once() {
        let groups = [Some("x"), Some("1.0"), Some("2.0")];
        let nested = r"\1?".repeat(200_000);
        assert_eq!(resolve_version(&nested, &groups), "1.0?".repeat(16));
        assert_eq!(resolve_version(r"\1?\2?a:b", &groups), "2.0?a");
    }

    #[test]
    fn version_ordering() {
        assert_eq!(compare_versions("1.10", "1.9"), Ordering::Greater);
        assert_eq!(compare_versions("1.2", "1.2.0"), Ordering::Less);
        assert_eq!(compare_versions("2.0-beta", "2.0-alpha"), Ordering::Greater);
        assert_eq!(compare_versions("3", "3"), Ordering::Equal);
    }

    #[test]
    fn highest_version_wins_and_empty_matches_all() {
        let compiled =
            CompiledPattern::new(&Pattern::new(r"lib-([\d.]+)\.js").with_version(r"\1")).unwrap();
        let hit = compiled
            .matches("lib-1.9.js lib-1.10.js LIB-1.2.js")
            .unwrap();
        assert_eq!(hit.version.as_deref(), Some("1.10"));
        assert!(compiled.matches("nothing").is_none());
        let any = CompiledPattern::new(&Pattern::new("")).unwrap();
        assert_eq!(any.matches("").map(|m| m.confidence), Some(100));
        assert!(CompiledPattern::new(&Pattern::new("(?=x)")).is_err());
        assert!(CompiledPattern::new(&Pattern::new("a".repeat(MAX_PATTERN_LEN + 1))).is_err());
    }
}
