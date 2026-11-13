//! Directives and policies (CSP3 §2.2 and §2.3).

use std::collections::HashSet;
use std::fmt;
use std::str::FromStr;

use crate::Error;
use crate::source::Source;

/// Directives whose value is a source list (CSP3 §6.1, §6.3, §6.4).
const SOURCE_LIST_DIRECTIVES: &[&str] = &[
    "default-src",
    "child-src",
    "connect-src",
    "font-src",
    "frame-src",
    "img-src",
    "manifest-src",
    "media-src",
    "object-src",
    "prefetch-src",
    "script-src",
    "script-src-elem",
    "script-src-attr",
    "style-src",
    "style-src-elem",
    "style-src-attr",
    "worker-src",
    "base-uri",
    "form-action",
    "frame-ancestors",
    "navigate-to",
    "fenced-frame-src",
];

/// Other directives defined by CSP3 and its companion specifications.
const OTHER_KNOWN_DIRECTIVES: &[&str] = &[
    "sandbox",
    "report-uri",
    "report-to",
    "upgrade-insecure-requests",
    "block-all-mixed-content",
    "require-trusted-types-for",
    "trusted-types",
    "require-sri-for",
    "plugin-types",
    "referrer",
    "reflected-xss",
    "disown-opener",
];

/// Directives that browsers have removed or deprecated.
const DEPRECATED_DIRECTIVES: &[&str] = &[
    "block-all-mixed-content",
    "plugin-types",
    "prefetch-src",
    "referrer",
    "reflected-xss",
    "require-sri-for",
    "disown-opener",
    "navigate-to",
];

/// Directives whose source lists accept nonces and hashes.
const NONCE_DIRECTIVES: &[&str] = &[
    "default-src",
    "script-src",
    "script-src-elem",
    "script-src-attr",
    "style-src",
    "style-src-elem",
    "style-src-attr",
];

/// One directive: a lowercase name and its whitespace-separated value.
///
/// ```
/// use rune_csp::{Directive, Keyword, Source};
///
/// let d = Directive::new("Script-Src", ["'SELF'", "https://cdn.example"]);
/// assert_eq!(d.name(), "script-src");
/// assert_eq!(d.sources()[0], Source::Keyword(Keyword::SelfOrigin));
/// assert_eq!(d.to_string(), "script-src 'self' https://cdn.example");
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Directive {
    name: String,
    tokens: Vec<String>,
}

impl Directive {
    /// Builds a directive. The name is lowercased; tokens are kept as given
    /// (callers pass whitespace-free tokens).
    pub fn new<I, S>(name: &str, tokens: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            name: name.to_ascii_lowercase(),
            tokens: tokens.into_iter().map(Into::into).collect(),
        }
    }

    /// The lowercase directive name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The raw value tokens, as written.
    #[must_use]
    pub fn tokens(&self) -> &[String] {
        &self.tokens
    }

    /// `true` when the value is a source list (`script-src`, `img-src`,
    /// `base-uri`, `frame-ancestors`, ...).
    #[must_use]
    pub fn is_source_list(&self) -> bool {
        SOURCE_LIST_DIRECTIVES.contains(&self.name.as_str())
    }

    /// `true` when the name is a directive some specification defines.
    #[must_use]
    pub fn is_known(&self) -> bool {
        self.is_source_list() || OTHER_KNOWN_DIRECTIVES.contains(&self.name.as_str())
    }

    /// `true` when browsers have removed or deprecated the directive.
    #[must_use]
    pub fn is_deprecated(&self) -> bool {
        DEPRECATED_DIRECTIVES.contains(&self.name.as_str())
    }

    /// `true` when the directive's source list honours nonces and hashes.
    #[must_use]
    pub fn accepts_nonces(&self) -> bool {
        NONCE_DIRECTIVES.contains(&self.name.as_str())
    }

    /// The parsed source list. Empty for directives that do not take one.
    #[must_use]
    pub fn sources(&self) -> Vec<Source> {
        if self.is_source_list() {
            self.tokens.iter().map(|t| Source::parse(t)).collect()
        } else {
            Vec::new()
        }
    }

    /// The canonical value: source lists re-serialized in canonical form,
    /// other values as written, separated by single spaces.
    #[must_use]
    pub fn canonical_value(&self) -> String {
        if self.is_source_list() {
            self.sources()
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(" ")
        } else {
            self.tokens.join(" ")
        }
    }
}

impl fmt::Display for Directive {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.name)?;
        let value = self.canonical_value();
        if !value.is_empty() {
            write!(f, " {value}")?;
        }
        Ok(())
    }
}

/// A problem found while parsing, for a directive the browser skips.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ParseIssue {
    /// A directive repeats an earlier one; browsers ignore the repeat.
    DuplicateDirective {
        /// Lowercase name of the repeated directive.
        name: String,
    },
    /// The directive name is not `1*( ALPHA / DIGIT / "-" )`; browsers
    /// ignore the directive.
    InvalidDirectiveName {
        /// The name as written.
        name: String,
    },
}

/// A parsed Content-Security-Policy: an ordered set of directives.
///
/// [`Policy::parse`] follows the CSP3 parsing algorithm and never fails;
/// skipped directives are recorded as [`ParseIssue`]s. [`str::parse`]
/// (via [`FromStr`]) is the strict variant and rejects any issue, any
/// invalid source expression, an empty policy and a comma.
///
/// [`Display`](fmt::Display) writes the canonical form: lowercase names and
/// keywords, single spaces, `"; "` between directives, duplicates dropped.
///
/// ```
/// use rune_csp::Policy;
///
/// let policy = Policy::parse("  DEFAULT-SRC 'SELF' ;; img-src * data: ; default-src 'none'");
/// assert_eq!(policy.to_string(), "default-src 'self'; img-src * data:");
/// assert_eq!(policy.issues().len(), 1); // the repeated default-src
/// assert!("default-src 'self'".parse::<Policy>().is_ok());
/// assert!("default-src self'".parse::<Policy>().is_err());
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub struct Policy {
    directives: Vec<Directive>,
    issues: Vec<ParseIssue>,
}

impl Policy {
    /// An empty policy.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Parses one serialized policy (CSP3 §2.2.1). Commas are not policy
    /// separators here; use [`parse_header`] for a header value.
    #[must_use]
    pub fn parse(serialized: &str) -> Self {
        let mut policy = Self::new();
        // Names seen so far, so hostile headers with many directives stay
        // linear instead of rescanning the list for each one.
        let mut seen = HashSet::new();
        for token in serialized.split(';') {
            let token = token.trim_matches(|c: char| c.is_ascii_whitespace());
            if token.is_empty() {
                continue;
            }
            let name_end = token
                .find(|c: char| c.is_ascii_whitespace())
                .unwrap_or(token.len());
            let (name, value) = token.split_at(name_end);
            if !is_directive_name(name) {
                policy.issues.push(ParseIssue::InvalidDirectiveName {
                    name: name.to_owned(),
                });
                continue;
            }
            let directive = Directive::new(name, value.split_ascii_whitespace());
            if !seen.insert(directive.name.clone()) {
                policy.issues.push(ParseIssue::DuplicateDirective {
                    name: directive.name,
                });
                continue;
            }
            policy.directives.push(directive);
        }
        policy
    }

    /// Appends a directive. Returns `false`, leaving the policy unchanged,
    /// when a directive with the same name is already present.
    pub fn insert(&mut self, directive: Directive) -> bool {
        if self.directive(directive.name()).is_some() {
            return false;
        }
        self.directives.push(directive);
        true
    }

    /// Builder form of [`Policy::insert`].
    #[must_use]
    pub fn with_directive(mut self, directive: Directive) -> Self {
        self.insert(directive);
        self
    }

    /// The directives, in order.
    #[must_use]
    pub fn directives(&self) -> &[Directive] {
        &self.directives
    }

    /// Problems found by [`Policy::parse`].
    #[must_use]
    pub fn issues(&self) -> &[ParseIssue] {
        &self.issues
    }

    /// `true` when the policy has no directives.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.directives.is_empty()
    }

    /// The directive called `name` (ASCII case-insensitive).
    #[must_use]
    pub fn directive(&self, name: &str) -> Option<&Directive> {
        self.directives
            .iter()
            .find(|d| d.name.eq_ignore_ascii_case(name))
    }

    /// The directive that governs `name` after the CSP3 fallback chain
    /// (§6.8.3): for example `script-src-elem` falls back to `script-src`,
    /// then `default-src`. `None` when nothing in the chain is present.
    ///
    /// ```
    /// use rune_csp::Policy;
    ///
    /// let p = Policy::parse("default-src 'self'; child-src 'none'");
    /// assert_eq!(p.effective_directive("img-src").map(|d| d.name()), Some("default-src"));
    /// assert_eq!(p.effective_directive("worker-src").map(|d| d.name()), Some("child-src"));
    /// assert!(p.effective_directive("base-uri").is_none());
    /// ```
    #[must_use]
    pub fn effective_directive(&self, name: &str) -> Option<&Directive> {
        fallback_chain(name)
            .iter()
            .find_map(|candidate| self.directive(candidate))
    }
}

impl fmt::Display for Policy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, directive) in self.directives.iter().enumerate() {
            if i > 0 {
                f.write_str("; ")?;
            }
            directive.fmt(f)?;
        }
        Ok(())
    }
}

impl FromStr for Policy {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Error> {
        if s.contains(',') {
            return Err(Error::MultiplePolicies);
        }
        let policy = Self::parse(s);
        if let Some(issue) = policy.issues.first() {
            return Err(match issue {
                ParseIssue::DuplicateDirective { name } => {
                    Error::DuplicateDirective { name: name.clone() }
                }
                ParseIssue::InvalidDirectiveName { name } => {
                    Error::InvalidDirectiveName { name: name.clone() }
                }
            });
        }
        if policy.is_empty() {
            return Err(Error::Empty);
        }
        for directive in &policy.directives {
            if let Some(Source::Invalid(token)) = directive
                .sources()
                .into_iter()
                .find(|s| matches!(s, Source::Invalid(_)))
            {
                return Err(Error::InvalidSource {
                    directive: directive.name.clone(),
                    token,
                });
            }
        }
        Ok(policy)
    }
}

/// Parses a `Content-Security-Policy` header value, which may hold several
/// comma-separated policies (CSP3 §2.2.2). Empty policies are dropped.
///
/// ```
/// let policies = rune_csp::parse_header("script-src 'self', object-src 'none' ,");
/// assert_eq!(policies.len(), 2);
/// assert_eq!(rune_csp::serialize_header(&policies), "script-src 'self', object-src 'none'");
/// ```
#[must_use]
pub fn parse_header(value: &str) -> Vec<Policy> {
    value
        .split(',')
        .map(Policy::parse)
        .filter(|p| !p.is_empty() || !p.issues.is_empty())
        .collect()
}

/// Serializes policies in canonical form, separated by `", "`. Policies
/// without directives are skipped.
#[must_use]
pub fn serialize_header(policies: &[Policy]) -> String {
    policies
        .iter()
        .filter(|p| !p.is_empty())
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

/// `directive-name = 1*( ALPHA / DIGIT / "-" )`
fn is_directive_name(name: &str) -> bool {
    !name.is_empty() && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

/// The CSP3 §6.8.3 fallback list for a directive name, most specific first.
fn fallback_chain(name: &str) -> Vec<String> {
    let lower = name.to_ascii_lowercase();
    let rest: &[&str] = match lower.as_str() {
        "script-src-elem" | "script-src-attr" => &["script-src", "default-src"],
        "style-src-elem" | "style-src-attr" => &["style-src", "default-src"],
        "worker-src" => &["child-src", "script-src", "default-src"],
        "frame-src" | "fenced-frame-src" => &["child-src", "default-src"],
        "script-src" | "style-src" | "child-src" | "connect-src" | "font-src" | "img-src"
        | "manifest-src" | "media-src" | "object-src" | "prefetch-src" => &["default-src"],
        _ => &[],
    };
    std::iter::once(lower)
        .chain(rest.iter().map(|s| (*s).to_owned()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_canonicalizes() {
        let p = Policy::parse("\tScript-Src  'SELF'\n https://A.example ;object-src 'none';");
        assert_eq!(p.directives().len(), 2);
        assert_eq!(
            p.to_string(),
            "script-src 'self' https://a.example; object-src 'none'"
        );
        assert_eq!(p.issues(), []);
    }

    #[test]
    fn first_duplicate_wins() {
        let p = Policy::parse("script-src 'none'; SCRIPT-SRC *");
        assert_eq!(p.to_string(), "script-src 'none'");
        assert_eq!(
            p.issues(),
            [ParseIssue::DuplicateDirective {
                name: "script-src".into()
            }]
        );
    }

    #[test]
    fn invalid_names_are_skipped() {
        let p = Policy::parse("scr\u{ef}pt-src *; img_src *; img-src 'self'");
        assert_eq!(p.to_string(), "img-src 'self'");
        assert_eq!(p.issues().len(), 2);
    }

    #[test]
    fn non_source_values_kept_verbatim() {
        let p =
            Policy::parse("sandbox Allow-Scripts; report-uri /csp?a=B; upgrade-insecure-requests");
        assert_eq!(
            p.to_string(),
            "sandbox Allow-Scripts; report-uri /csp?a=B; upgrade-insecure-requests"
        );
        assert!(
            p.directive("sandbox")
                .is_some_and(|d| d.sources().is_empty())
        );
    }

    #[test]
    fn strict_parsing() {
        assert_eq!("".parse::<Policy>(), Err(Error::Empty));
        assert_eq!(" ; ".parse::<Policy>(), Err(Error::Empty));
        assert_eq!("a 'b', c".parse::<Policy>(), Err(Error::MultiplePolicies));
        assert_eq!(
            "img-src *; img-src 'self'".parse::<Policy>(),
            Err(Error::DuplicateDirective {
                name: "img-src".into()
            })
        );
        assert_eq!(
            "img@src *".parse::<Policy>(),
            Err(Error::InvalidDirectiveName {
                name: "img@src".into()
            })
        );
        assert_eq!(
            "img-src 'bogus'".parse::<Policy>(),
            Err(Error::InvalidSource {
                directive: "img-src".into(),
                token: "'bogus'".into()
            })
        );
    }

    #[test]
    fn header_with_several_policies() {
        let policies = parse_header("default-src 'self', , script-src 'none'");
        assert_eq!(policies.len(), 2);
        assert_eq!(
            serialize_header(&policies),
            "default-src 'self', script-src 'none'"
        );
        assert_eq!(parse_header(""), []);
        assert_eq!(parse_header(" ;, ;"), []);
    }

    #[test]
    fn fallback_chain_order() {
        let p = Policy::parse("default-src 'self'; script-src 'none'");
        assert_eq!(
            p.effective_directive("script-src-elem")
                .map(Directive::name),
            Some("script-src")
        );
        assert_eq!(
            p.effective_directive("worker-src").map(Directive::name),
            Some("script-src")
        );
        assert_eq!(
            p.effective_directive("frame-src").map(Directive::name),
            Some("default-src")
        );
        assert!(p.effective_directive("form-action").is_none());
    }

    #[test]
    fn insert_rejects_duplicates() {
        let mut p = Policy::new().with_directive(Directive::new("img-src", ["*"]));
        assert!(!p.insert(Directive::new("IMG-SRC", ["'self'"])));
        assert!(p.insert(Directive::new(
            "upgrade-insecure-requests",
            Vec::<String>::new()
        )));
        assert_eq!(p.to_string(), "img-src *; upgrade-insecure-requests");
    }
}
