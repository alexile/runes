//! The ruleset engine: [`Ruleset`] compiles [`SecretRule`]s once and scans
//! text into borrowed [`SecretMatch`]es, which convert to
//! [`rune_finding::Finding`]s.

use crate::detect::{
    data_uri_payloads, for_each_keylike_token, in_url_path, is_path_like, is_sri_digest, is_uuid,
    overlaps, redact, within,
};
use crate::error::Error;
use crate::rule::{
    CWE_HARDCODED_CREDENTIALS, HIGH_ENTROPY_RULE_ID, SecretRule, cwe_ref, default_rules,
};
use regex::{Regex, RegexBuilder};
use rune_entropy::entropy;
use rune_finding::{Confidence, Evidence, Finding, Location, Remediation, Severity};

/// Default entropy threshold (bits per byte) of the entropy detector.
pub const DEFAULT_ENTROPY_THRESHOLD: f64 = 4.3;

/// Upper bound on a compiled rule's regex program, so a hostile rule file
/// cannot exhaust memory.
const REGEX_SIZE_LIMIT: usize = 1 << 20;

const REMEDIATION: &str = "Remove the secret from source control, rotate the credential, and \
                           load it from a secrets manager or environment variable instead.";

struct CompiledRule {
    rule: SecretRule,
    regex: Regex,
    /// Lower-cased keywords.
    keywords: Vec<String>,
}

/// A compiled, immutable set of [`SecretRule`]s plus an optional entropy
/// detector. Compile once and share it: scanning takes `&self`.
///
/// # Examples
///
/// ```rust
/// use rune_leak::Ruleset;
///
/// let rules = Ruleset::builtin();
/// let matches = rules.scan_str("aws_access_key_id = AKIAIOSFODNN7EXAMPLE");
/// assert_eq!(matches[0].rule.id, "aws_access_key");
/// assert_eq!(matches[0].value, "AKIAIOSFODNN7EXAMPLE");
///
/// let finding = matches[0].to_finding::<()>("config.env");
/// assert_eq!(finding.check_id, "secret.aws_access_key");
/// assert_eq!(finding.taxonomy[0].id, "CWE-798");
/// ```
pub struct Ruleset {
    rules: Vec<CompiledRule>,
    entropy: Option<SecretRule>,
    entropy_threshold: f64,
}

impl std::fmt::Debug for Ruleset {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Ruleset")
            .field(
                "rules",
                &self.rules.iter().map(|r| &r.rule.id).collect::<Vec<_>>(),
            )
            .field(
                "entropy_threshold",
                &self.entropy.as_ref().map(|_| self.entropy_threshold),
            )
            .finish()
    }
}

impl Default for Ruleset {
    fn default() -> Self {
        Self::builtin()
    }
}

impl Ruleset {
    /// Compiles `rules`, with entropy detection off.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidRule`] for an empty or malformed id, an empty pattern
    /// or a non-finite entropy threshold, and [`Error::InvalidRegex`] for a
    /// pattern that does not compile.
    pub fn new(rules: impl IntoIterator<Item = SecretRule>) -> Result<Self, Error> {
        let mut ruleset = Self {
            rules: Vec::new(),
            entropy: None,
            entropy_threshold: DEFAULT_ENTROPY_THRESHOLD,
        };
        ruleset.extend(rules)?;
        Ok(ruleset)
    }

    /// [`default_rules`] plus entropy detection at
    /// [`DEFAULT_ENTROPY_THRESHOLD`].
    #[must_use]
    pub fn builtin() -> Self {
        let mut ruleset = Self {
            rules: Vec::new(),
            entropy: None,
            entropy_threshold: DEFAULT_ENTROPY_THRESHOLD,
        };
        // The built-in rules are literals tested to compile (`builtin_rules_compile`);
        // a failing one would only be left out, never panic.
        for rule in default_rules() {
            let _ = ruleset.push(rule);
        }
        ruleset.with_entropy(DEFAULT_ENTROPY_THRESHOLD)
    }

    /// Compiles more rules and appends them after the existing ones.
    ///
    /// # Errors
    ///
    /// As [`Ruleset::new`]. Rules before the failing one stay added.
    pub fn extend(&mut self, rules: impl IntoIterator<Item = SecretRule>) -> Result<(), Error> {
        rules.into_iter().try_for_each(|rule| self.push(rule))
    }

    fn push(&mut self, rule: SecretRule) -> Result<(), Error> {
        validate(&rule)?;
        let regex = RegexBuilder::new(&rule.pattern)
            .size_limit(REGEX_SIZE_LIMIT)
            .build()
            .map_err(|source| Error::InvalidRegex {
                id: rule.id.clone(),
                source,
            })?;
        let keywords = rule
            .keywords
            .iter()
            .filter(|k| !k.is_empty())
            .map(|k| k.to_ascii_lowercase())
            .collect();
        self.rules.push(CompiledRule {
            rule,
            regex,
            keywords,
        });
        Ok(())
    }

    /// Turns on entropy detection: key-like tokens (20+ base64/hex bytes
    /// mixing letters and digits) at or above `threshold` bits per byte are
    /// reported as `secret.high_entropy_string` (Low, tentative). UUIDs,
    /// data-URI payloads, subresource-integrity digests and tokens a rule
    /// already matched are skipped.
    #[must_use]
    pub fn with_entropy(mut self, threshold: f64) -> Self {
        self.entropy_threshold = threshold;
        self.entropy = Some(
            SecretRule::new(
                HIGH_ENTROPY_RULE_ID,
                "High-entropy string resembling a secret",
                "",
                Severity::Low,
            )
            .with_entropy_threshold(threshold),
        );
        self
    }

    /// Turns off entropy detection.
    #[must_use]
    pub fn without_entropy(mut self) -> Self {
        self.entropy = None;
        self
    }

    /// The rules, in matching order (the entropy detector is not included).
    pub fn rules(&self) -> impl Iterator<Item = &SecretRule> {
        self.rules.iter().map(|r| &r.rule)
    }

    /// Scans `text` and returns every match.
    #[must_use]
    pub fn scan_str<'a>(&'a self, text: &'a str) -> Vec<SecretMatch<'a>> {
        let mut out = Vec::new();
        self.for_each_match(text, |m| out.push(m));
        out
    }

    /// Scans `text` into findings located in `path`.
    #[must_use]
    pub fn findings(&self, text: &str, path: &str) -> Vec<Finding> {
        let mut out = Vec::new();
        self.for_each_match(text, |m| out.push(m.to_finding(path)));
        out
    }

    /// Scans `text` and calls `f` for every match, in line order. The
    /// allocation-light path for large trees: the only allocations are a few
    /// scratch buffers reused across lines.
    pub fn for_each_match<'a>(&'a self, text: &'a str, mut f: impl FnMut(SecretMatch<'a>)) {
        let mut lower = String::new();
        let mut payloads: Vec<(usize, usize)> = Vec::new();
        let mut taken: Vec<(usize, usize)> = Vec::new();
        let mut line_start = 0usize;

        for (idx, raw) in text.split_inclusive('\n').enumerate() {
            let line = raw.trim_end_matches(['\n', '\r']);
            let line_number = idx + 1;
            lower.clear();
            lower.extend(line.chars().map(|c| c.to_ascii_lowercase()));
            data_uri_payloads(line, &mut payloads);
            taken.clear();

            let mut emit = |rule: &'a SecretRule,
                            start: usize,
                            value: &'a str,
                            value_entropy: f64,
                            confidence: Confidence| {
                f(SecretMatch {
                    rule,
                    value,
                    line_number,
                    column: start + 1,
                    offset: line_start + start,
                    entropy: value_entropy,
                    confidence,
                });
            };

            for compiled in &self.rules {
                if !compiled.keywords.is_empty()
                    && !compiled.keywords.iter().any(|k| lower.contains(k.as_str()))
                {
                    continue;
                }
                for caps in compiled.regex.captures_iter(line) {
                    let Some(m) = caps.get(1).or_else(|| caps.get(0)) else {
                        continue;
                    };
                    let (start, end) = (m.start(), m.end());
                    if start == end || within(&payloads, start, end) || overlaps(&taken, start, end)
                    {
                        continue;
                    }
                    let value_entropy = entropy(m.as_str().as_bytes());
                    if let Some(min) = compiled.rule.entropy_threshold
                        && value_entropy < min
                    {
                        continue;
                    }
                    taken.push((start, end));
                    emit(
                        &compiled.rule,
                        start,
                        m.as_str(),
                        value_entropy,
                        Confidence::Firm,
                    );
                }
            }

            if let Some(rule) = &self.entropy {
                for_each_keylike_token(line, |start, token| {
                    let end = start + token.len();
                    if is_uuid(token)
                        || is_sri_digest(token)
                        || is_path_like(token)
                        || in_url_path(line, start)
                        || within(&payloads, start, end)
                        || overlaps(&taken, start, end)
                    {
                        return;
                    }
                    let value_entropy = entropy(token.as_bytes());
                    if value_entropy >= self.entropy_threshold {
                        emit(rule, start, token, value_entropy, Confidence::Tentative);
                    }
                });
            }
            line_start += raw.len();
        }
    }
}

fn validate(rule: &SecretRule) -> Result<(), Error> {
    let invalid = |reason: &'static str| Error::InvalidRule {
        id: rule.id.clone(),
        reason,
    };
    if rule.id.is_empty()
        || !rule.id.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'_' | b'-' | b'.')
        })
    {
        return Err(invalid("id must be non-empty [a-z0-9_.-]"));
    }
    if rule.pattern.is_empty() {
        return Err(invalid("pattern is empty"));
    }
    if rule.entropy_threshold.is_some_and(|t| !t.is_finite()) {
        return Err(invalid("entropy_threshold is not finite"));
    }
    Ok(())
}

/// One secret found by a [`Ruleset`], borrowing the rule and the scanned text.
#[derive(Debug, Clone, Copy, PartialEq)]
#[non_exhaustive]
pub struct SecretMatch<'a> {
    /// The rule that matched (for entropy hits, a synthetic
    /// `high_entropy_string` rule).
    pub rule: &'a SecretRule,
    /// The secret: capture group 1 of the rule's pattern, or the whole match.
    pub value: &'a str,
    /// 1-based line number.
    pub line_number: usize,
    /// 1-based byte column of the secret's start on its line.
    pub column: usize,
    /// 0-based byte offset of the secret in the scanned text.
    pub offset: usize,
    /// Shannon entropy of the secret, bits per byte.
    pub entropy: f64,
    /// Firm for a rule match, tentative for an entropy hit.
    pub confidence: Confidence,
}

impl SecretMatch<'_> {
    /// The finding check id, `secret.<rule id>`.
    #[must_use]
    pub fn check_id(&self) -> String {
        self.rule.check_id()
    }

    /// The secret, redacted to a 4-character prefix and its length.
    #[must_use]
    pub fn redacted(&self) -> String {
        redact(self.value)
    }

    /// Converts the match into a finding at `path`: [`Location::File`] with
    /// line, columns (end exclusive) and byte range, a CWE taxonomy
    /// reference, redacted `secret` evidence and a remediation. The secret
    /// itself is never copied into the finding.
    #[must_use]
    pub fn to_finding<X: Default>(&self, path: &str) -> Finding<X> {
        let to_u32 = |n: usize| u32::try_from(n).unwrap_or(u32::MAX);
        let line = to_u32(self.line_number);
        let location = Location::file(path)
            .with_lines(line, line)
            .with_columns(to_u32(self.column), to_u32(self.column + self.value.len()))
            .with_bytes(self.offset as u64, (self.offset + self.value.len()) as u64);
        let cwe = if self.rule.cwe == 0 {
            CWE_HARDCODED_CREDENTIALS
        } else {
            self.rule.cwe
        };
        Finding::<X>::new(
            self.check_id(),
            self.rule.name.clone(),
            self.rule.severity,
            self.confidence,
            location,
        )
        .push_taxonomy(cwe_ref(cwe))
        .push_evidence(Evidence::new(
            "secret",
            format!("rule={} {}", self.rule.id, self.redacted()),
        ))
        .push_evidence(Evidence::new("entropy", format!("{:.2}", self.entropy)))
        .with_remediation(Remediation::new(REMEDIATION))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtin_rules_compile() {
        let n = default_rules().len();
        assert_eq!(Ruleset::new(default_rules()).unwrap().rules().count(), n);
        assert_eq!(Ruleset::builtin().rules().count(), n);
    }

    #[test]
    fn rule_ids_are_unique() {
        let mut ids: Vec<_> = default_rules().into_iter().map(|r| r.id).collect();
        ids.sort();
        let before = ids.len();
        ids.dedup();
        assert_eq!(before, ids.len());
    }

    #[test]
    fn invalid_rules_are_rejected() {
        let bad_id = SecretRule::new("Bad Id", "x", "x", Severity::Low);
        assert_eq!(Ruleset::new([bad_id]).unwrap_err().code(), "invalid_rule");
        let bad_re = SecretRule::new("x", "x", "(", Severity::Low);
        assert_eq!(Ruleset::new([bad_re]).unwrap_err().code(), "invalid_regex");
        let nan = SecretRule::new("x", "x", "x", Severity::Low).with_entropy_threshold(f64::NAN);
        assert!(Ruleset::new([nan]).is_err());
    }

    #[test]
    fn keywords_prefilter_and_capture_group() {
        let rule = SecretRule::new("acme", "ACME", r"acme_([0-9a-f]{8})", Severity::High)
            .with_keywords(["ACME_"]);
        let rs = Ruleset::new([rule]).unwrap();
        let m = rs.scan_str("x\nt = acme_deadbeef\n");
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].value, "deadbeef");
        assert_eq!((m[0].line_number, m[0].column, m[0].offset), (2, 10, 11));
    }

    #[test]
    fn later_rules_do_not_repeat_earlier_matches() {
        let rs = Ruleset::builtin();
        let m = rs.scan_str("token = \"ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789\"");
        let ids: Vec<_> = m.iter().map(|m| m.rule.id.as_str()).collect();
        assert_eq!(ids, ["github_token"]);
    }

    #[test]
    fn finding_never_contains_the_secret() {
        let rs = Ruleset::builtin();
        let f: Finding = rs.findings("k = AKIAIOSFODNN7EXAMPLE", "a.env").remove(0);
        assert!(
            f.evidence
                .iter()
                .all(|e| !e.snippet.contains("AKIAIOSFODNN7EXAMPLE"))
        );
        assert!(matches!(
            f.location,
            Location::File {
                start_column: Some(5),
                end_column: Some(25),
                start_byte: Some(4),
                ..
            }
        ));
    }
}
