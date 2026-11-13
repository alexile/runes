//! The compiled detection and replacement engine.

use std::sync::{Arc, OnceLock};

use regex::Regex;
use rune_entropy::entropy;
use rune_leak::Ruleset;

use crate::category::Category;
use crate::error::Error;
use crate::hmac::{hex, hmac_sha256};
use crate::policy::{Policy, Replacement};
use crate::stream::StreamRedactor;
use crate::vault::TokenVault;

/// One sensitive value found in a text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct Detection {
    /// What was found.
    pub category: Category,
    /// Byte offset of the first byte.
    pub start: usize,
    /// Byte offset one past the last byte.
    pub end: usize,
}

impl Detection {
    /// The detected text, sliced out of the `text` it was found in.
    #[must_use]
    pub fn value<'t>(&self, text: &'t str) -> Option<&'t str> {
        text.get(self.start..self.end)
    }
}

struct Inner {
    policy: Policy,
    ruleset: Option<Ruleset>,
    vault: TokenVault,
}

/// A compiled [`Policy`]: detects sensitive values and rewrites them.
///
/// Compile once and share: cloning is cheap (an `Arc`), and clones share the
/// [`TokenVault`], so tokenized values stay consistent across threads, writers
/// and the [`tracing`](crate#tracing) integration.
///
/// # Example
///
/// ```rust
/// use rune_redact::{Category, Policy, Redactor};
///
/// let redactor = Redactor::new(Policy::default().without_category(Category::Ipv4))?;
/// let out = redactor.redact("user=bob@example.com ip=10.0.0.1 key=AKIAIOSFODNN7EXAMPLE");
/// assert_eq!(out, "user=[EMAIL] ip=10.0.0.1 key=[CREDENTIAL]");
/// # Ok::<(), rune_redact::Error>(())
/// ```
#[derive(Clone)]
pub struct Redactor {
    inner: Arc<Inner>,
}

impl std::fmt::Debug for Redactor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Redactor")
            .field("policy", &self.inner.policy)
            .field("vault", &self.inner.vault)
            .finish_non_exhaustive()
    }
}

impl Default for Redactor {
    /// [`Policy::default()`]: every category, `[LABEL]` placeholders.
    fn default() -> Self {
        Self::build(
            Policy::default(),
            Some(Ruleset::builtin().without_entropy()),
        )
    }
}

impl Redactor {
    /// Compiles `policy`.
    ///
    /// # Errors
    ///
    /// [`Error::Rules`] if an [extra rule](Policy::with_rules) is invalid,
    /// [`Error::MissingHashKey`] if [`Replacement::Hash`] is used without a
    /// [hash key](Policy::with_hash_key), and
    /// [`Error::InvalidEntropyThreshold`] for a NaN, infinite or negative
    /// threshold while [`Category::HighEntropy`] is enabled.
    pub fn new(policy: Policy) -> Result<Self, Error> {
        if policy.contains(Category::HighEntropy)
            && (!policy.entropy_threshold.is_finite() || policy.entropy_threshold < 0.0)
        {
            return Err(Error::InvalidEntropyThreshold);
        }
        if policy.hash_key().is_empty() && policy.uses(&Replacement::Hash) {
            return Err(Error::MissingHashKey);
        }
        let ruleset = if policy.contains(Category::Credential) {
            let mut ruleset = Ruleset::builtin().without_entropy();
            ruleset.extend(policy.extra_rules.iter().cloned())?;
            Some(ruleset)
        } else {
            // Still validate the rules, so a bad rule never hides until the
            // category is switched on.
            Ruleset::new(policy.extra_rules.iter().cloned())?;
            None
        };
        Ok(Self::build(policy, ruleset))
    }

    fn build(policy: Policy, ruleset: Option<Ruleset>) -> Self {
        let vault = TokenVault::new(policy.vault_capacity);
        Self {
            inner: Arc::new(Inner {
                policy,
                ruleset,
                vault,
            }),
        }
    }

    /// The compiled policy.
    #[must_use]
    pub fn policy(&self) -> &Policy {
        &self.inner.policy
    }

    /// The token map used by [`Replacement::Tokenize`].
    #[must_use]
    pub fn vault(&self) -> &TokenVault {
        &self.inner.vault
    }

    /// Finds the sensitive values in `text`: non-overlapping, sorted by
    /// offset. Where detections overlap, the category with the higher
    /// priority (earlier in [`Category::ALL`]) wins.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_redact::{Category, Redactor};
    ///
    /// let text = "mail bob@example.com";
    /// let found = Redactor::default().detect(text);
    /// assert_eq!(found.len(), 1);
    /// assert_eq!(found[0].category, Category::Email);
    /// assert_eq!(found[0].value(text), Some("bob@example.com"));
    /// ```
    #[must_use]
    pub fn detect(&self, text: &str) -> Vec<Detection> {
        let policy = &self.inner.policy;
        let mut accepted: Vec<Detection> = Vec::new();
        for &category in &policy.categories {
            let mut accept = |start: usize, end: usize| {
                if start < end && end <= text.len() {
                    insert_disjoint(
                        &mut accepted,
                        Detection {
                            category,
                            start,
                            end,
                        },
                    );
                }
            };
            match category {
                Category::BearerToken => regex_spans(bearer_re(), text, &mut accept),
                Category::PrivateKey => private_key_spans(text, &mut accept),
                Category::Jwt => slice_spans(text, rune_regex_sec::match_jwt(text), &mut accept),
                Category::Credential => {
                    if let Some(ruleset) = &self.inner.ruleset {
                        ruleset.for_each_match(text, |m| {
                            accept(m.offset, m.offset + m.value.len());
                        });
                    }
                }
                Category::CreditCard => regex_spans(credit_card_re(), text, &mut accept),
                Category::Ssn => regex_spans(ssn_re(), text, &mut accept),
                Category::Email => {
                    slice_spans(text, rune_regex_sec::match_email(text), &mut accept);
                }
                Category::Ipv4 => slice_spans(text, rune_regex_sec::match_ipv4(text), &mut accept),
                Category::Ipv6 => {
                    slice_spans(text, rune_regex_sec::match_ipv6(text), &mut |s, e| {
                        if let Some(s) = ipv6_start(text, s, e) {
                            accept(s, e);
                        }
                    });
                }
                Category::Phone => regex_spans(phone_re(), text, &mut accept),
                // Runs last, over what the other detectors left.
                Category::HighEntropy => {}
            }
        }
        if policy.contains(Category::HighEntropy) {
            self.detect_high_entropy(text, &mut accepted);
        }
        accepted
    }

    /// Flags high-entropy pieces of each whitespace-delimited token. Parts
    /// of a token already claimed by another detector split it, and each
    /// remaining piece is judged on its own, so a key glued to an email
    /// address is still caught.
    fn detect_high_entropy(&self, text: &str, accepted: &mut Vec<Detection>) {
        let policy = &self.inner.policy;
        let Some(re) = token_re() else {
            return;
        };
        let mut pieces = Vec::new();
        for m in re.find_iter(text) {
            let mut from = m.start();
            let first = accepted.partition_point(|d| d.end <= m.start());
            for d in accepted
                .iter()
                .skip(first)
                .take_while(|d| d.start < m.end())
            {
                pieces.push((from, d.start.max(from)));
                from = d.end;
            }
            pieces.push((from, m.end()));
        }
        for (start, end) in pieces {
            let Some(piece) = text.get(start..end) else {
                continue;
            };
            if piece.len() >= policy.min_entropy_len
                && entropy(piece.as_bytes()) >= policy.entropy_threshold
            {
                insert_disjoint(
                    accepted,
                    Detection {
                        category: Category::HighEntropy,
                        start,
                        end,
                    },
                );
            }
        }
    }

    /// Redacts `text` according to the policy.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_redact::Redactor;
    ///
    /// let out = Redactor::default().redact("SSN 123-45-6789, card 4111-1111-1111-1111");
    /// assert_eq!(out, "SSN [SSN], card [CC]");
    /// ```
    #[must_use]
    pub fn redact(&self, text: &str) -> String {
        let mut out = String::with_capacity(text.len());
        self.redact_into(text, &mut out);
        out
    }

    /// Redacts `text`, appending the result to `out`.
    pub fn redact_into(&self, text: &str, out: &mut String) {
        let detections = self.detect(text);
        self.render(text, &detections, out);
    }

    /// Writes `text` to `out` with every detection replaced. `detections`
    /// must be sorted and disjoint, as [`detect`](Self::detect) returns them.
    pub(crate) fn render(&self, text: &str, detections: &[Detection], out: &mut String) {
        let mut last = 0;
        for d in detections {
            let (Some(before), Some(value)) = (text.get(last..d.start), d.value(text)) else {
                continue;
            };
            out.push_str(before);
            self.replace(d.category, value, out);
            last = d.end;
        }
        out.push_str(text.get(last..).unwrap_or_default());
    }

    fn replace(&self, category: Category, value: &str, out: &mut String) {
        let label = category.label();
        match self.inner.policy.replacement_for(category) {
            Replacement::Mask { fill, keep_last } => {
                let n = value.chars().count();
                let keep = (*keep_last).min(n / 2);
                out.extend(std::iter::repeat_n(*fill, n - keep));
                out.extend(value.chars().skip(n - keep));
            }
            Replacement::Hash => {
                let mac = hmac_sha256(
                    self.inner.policy.hash_key(),
                    &[category.name().as_bytes(), &[0], value.as_bytes()],
                );
                out.push('[');
                out.push_str(label);
                out.push(':');
                out.push_str(&hex(&mac[..8]));
                out.push(']');
            }
            Replacement::Tokenize => match self.inner.vault.token_for(category, value) {
                Some(token) => out.push_str(&token),
                None => push_label(label, out),
            },
            Replacement::Label => push_label(label, out),
        }
    }

    /// Maps the tokens issued by [`Replacement::Tokenize`] in `text` back to
    /// the original values: redact a prompt, send it, restore the reply.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_redact::{Policy, Redactor, Replacement};
    ///
    /// let redactor = Redactor::new(Policy::default().with_replacement(Replacement::Tokenize))?;
    /// let prompt = redactor.redact("Draft a reply to amy@example.com");
    /// assert_eq!(prompt, "Draft a reply to [EMAIL_1]");
    /// let reply = "Hi [EMAIL_1], thanks!"; // what the model sent back
    /// assert_eq!(redactor.restore(reply), "Hi amy@example.com, thanks!");
    /// # Ok::<(), rune_redact::Error>(())
    /// ```
    #[must_use]
    pub fn restore(&self, text: &str) -> String {
        self.inner.vault.restore(text)
    }

    /// A [`StreamRedactor`] for text that arrives in chunks, sharing this
    /// redactor's policy and vault.
    #[must_use]
    pub fn stream(&self) -> StreamRedactor {
        StreamRedactor::new(self.clone())
    }
}

fn push_label(label: &str, out: &mut String) {
    out.push('[');
    out.push_str(label);
    out.push(']');
}

/// Inserts `d` into the sorted, disjoint `accepted` unless it overlaps an
/// existing detection.
fn insert_disjoint(accepted: &mut Vec<Detection>, d: Detection) {
    let idx = accepted.partition_point(|a| a.start < d.start);
    let overlaps_prev = idx > 0 && accepted.get(idx - 1).is_some_and(|p| p.end > d.start);
    let overlaps_next = accepted.get(idx).is_some_and(|n| n.start < d.end);
    if !overlaps_prev && !overlaps_next {
        accepted.insert(idx, d);
    }
}

fn regex_spans(re: Option<&Regex>, text: &str, accept: &mut impl FnMut(usize, usize)) {
    if let Some(re) = re {
        for m in re.find_iter(text) {
            accept(m.start(), m.end());
        }
    }
}

/// Finds PEM private keys: each `-----BEGIN … PRIVATE KEY-----` line through
/// its `-----END …-----` line. A block with no END line (truncated, or not
/// fully arrived yet) runs over the base64 and `Name: value` header lines
/// that follow it, so the key body is never left behind. Line breaks may be
/// real or JSON-escaped (`\\n`).
fn private_key_spans(text: &str, accept: &mut impl FnMut(usize, usize)) {
    let (Some(begin_re), Some(end_re)) = (pem_begin_re(), pem_end_re()) else {
        return;
    };
    let begins: Vec<_> = begin_re.find_iter(text).collect();
    for (i, begin) in begins.iter().enumerate() {
        let limit = begins.get(i + 1).map_or(text.len(), regex::Match::start);
        let rest = text.get(begin.end()..limit).unwrap_or_default();
        let end = end_re.find(rest).map_or_else(
            || pem_body_end(text, begin.end(), limit),
            |m| begin.end() + m.end(),
        );
        accept(begin.start(), end);
    }
}

/// The end of the run of PEM body lines (`Name: value` headers, then
/// base64, with blank lines anywhere) that starts right after `from`, not
/// past `limit`.
fn pem_body_end(text: &str, from: usize, limit: usize) -> usize {
    let text = text.get(..limit).unwrap_or(text);
    let mut end = from;
    let mut pos = from;
    let mut in_body = false;
    loop {
        let rest = text.get(pos..).unwrap_or_default();
        let Some(sep) = ["\r\n", "\n", "\\r\\n", "\\n"]
            .into_iter()
            .find(|sep| rest.starts_with(sep))
        else {
            return end;
        };
        let line = rest.get(sep.len()..).unwrap_or_default();
        let line = line
            .get(..line.find(['\r', '\n', '\\']).unwrap_or(line.len()))
            .unwrap_or_default();
        let trimmed = line.trim_matches([' ', '\t']);
        let base64 = trimmed
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'='));
        let header = !in_body
            && trimmed.split_once(": ").is_some_and(|(name, _)| {
                !name.is_empty() && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
            });
        if !base64 && !header {
            return end;
        }
        in_body |= base64 && !trimmed.is_empty();
        pos += sep.len() + line.len();
        if !trimmed.is_empty() {
            end = pos;
        }
    }
}

fn pem_begin_re() -> Option<&'static Regex> {
    static RE: OnceLock<Option<Regex>> = OnceLock::new();
    cached(
        &RE,
        r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----",
    )
}

fn pem_end_re() -> Option<&'static Regex> {
    static RE: OnceLock<Option<Regex>> = OnceLock::new();
    cached(&RE, r"-----END (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----")
}

/// Converts sub-slices of `text` (as `rune-regex-sec` returns them) to spans.
fn slice_spans(text: &str, parts: Vec<&str>, accept: &mut impl FnMut(usize, usize)) {
    let base = text.as_ptr().addr();
    for part in parts {
        if let Some(start) = part.as_ptr().addr().checked_sub(base) {
            accept(start, start + part.len());
        }
    }
}

/// Validates an IPv6 candidate from `rune-regex-sec` and returns its real
/// start. The compressed form (`::1`) is also what Rust paths look like
/// (`std::fmt`), so a `::` match must not be followed by an identifier
/// character, and hex digits right before it (`fe80::1`) are taken into the
/// address while any other identifier before it (`crate::db`) rejects it.
fn ipv6_start(text: &str, start: usize, end: usize) -> Option<usize> {
    let bytes = text.as_bytes();
    let ident = |b: u8| b.is_ascii_alphanumeric() || b == b'_';
    if bytes.get(end).copied().is_some_and(ident) {
        return None;
    }
    if !text.get(start..)?.starts_with("::") {
        return Some(start);
    }
    let head = bytes.get(..start)?;
    let run = head
        .iter()
        .rev()
        .take_while(|&&b| ident(b) || b == b':')
        .count();
    let prefix = head.get(start - run..)?;
    prefix
        .iter()
        .all(|&b| b.is_ascii_hexdigit() || b == b':')
        .then_some(start - run)
}

/// Compile `pattern` once into `cell`.
///
/// Every pattern passed here is a literal in this file and the
/// `all_patterns_compile` test proves it valid, so `None` is unreachable in
/// practice. Returning it instead of panicking keeps the library panic-free.
fn cached(cell: &'static OnceLock<Option<Regex>>, pattern: &str) -> Option<&'static Regex> {
    cell.get_or_init(|| Regex::new(pattern).ok()).as_ref()
}

fn token_re() -> Option<&'static Regex> {
    static RE: OnceLock<Option<Regex>> = OnceLock::new();
    cached(&RE, r"\S+")
}

fn credit_card_re() -> Option<&'static Regex> {
    static RE: OnceLock<Option<Regex>> = OnceLock::new();
    cached(
        &RE,
        r"\b(?:4\d{3}|5[1-5]\d{2}|6011|3[47]\d{2})[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b",
    )
}

fn phone_re() -> Option<&'static Regex> {
    static RE: OnceLock<Option<Regex>> = OnceLock::new();
    cached(
        &RE,
        r"(?:\+1[ \t.\-]?)?(?:\(\d{3}\)|\d{3})[ \t.\-]?\d{3}[ \t.\-]?\d{4}",
    )
}

fn ssn_re() -> Option<&'static Regex> {
    static RE: OnceLock<Option<Regex>> = OnceLock::new();
    cached(&RE, r"\b\d{3}-\d{2}-\d{4}\b")
}

fn bearer_re() -> Option<&'static Regex> {
    static RE: OnceLock<Option<Regex>> = OnceLock::new();
    cached(&RE, r"(?i)Bearer[ \t]+[A-Za-z0-9\-._~+/]+=*")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn only(category: Category) -> Redactor {
        Redactor::new(Policy::none().with_category(category)).unwrap()
    }

    #[test]
    fn all_patterns_compile() {
        for re in [
            token_re(),
            credit_card_re(),
            phone_re(),
            ssn_re(),
            bearer_re(),
            pem_begin_re(),
            pem_end_re(),
        ] {
            assert!(re.is_some());
        }
    }

    #[test]
    fn each_category_is_detected() {
        let cases = [
            (
                Category::BearerToken,
                "auth: Bearer abc.def-ghi",
                "auth: [BEARER]",
            ),
            (
                Category::PrivateKey,
                "-----BEGIN RSA PRIVATE KEY-----",
                "[PRIVATE_KEY]",
            ),
            (
                Category::Jwt,
                "t=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2ln end",
                "t=[JWT] end",
            ),
            (
                Category::Credential,
                "key AKIAIOSFODNN7EXAMPLE",
                "key [CREDENTIAL]",
            ),
            (Category::CreditCard, "cc 5500 0000 0000 0004", "cc [CC]"),
            (Category::Ssn, "ssn 123-45-6789.", "ssn [SSN]."),
            (Category::Email, "to a.b@c.io!", "to [EMAIL]!"),
            (Category::Ipv4, "from 10.1.2.3:80", "from [IP]:80"),
            (
                Category::Ipv6,
                "from 2001:db8:0:0:0:0:0:1 ok",
                "from [IP] ok",
            ),
            (
                Category::Ipv6,
                "bind [::1]:80 or fe80::1",
                "bind [[IP]]:80 or [IP]",
            ),
            (
                Category::Ipv6,
                "in std::fmt and crate::db",
                "in std::fmt and crate::db",
            ),
            (Category::Phone, "call (555) 123-4567", "call [PHONE]"),
            (
                Category::HighEntropy,
                "k sK3xPq9mNbYrVwZuAtJhCf7DgLeW2oI5qR8eMvXn",
                "k [SECRET]",
            ),
        ];
        for (category, input, want) in cases {
            assert_eq!(only(category).redact(input), want, "{category}");
        }
    }

    #[test]
    fn higher_priority_wins_overlaps() {
        let text = "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2ln";
        let found = Redactor::default().detect(text);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].category, Category::BearerToken);
    }

    #[test]
    fn detections_are_sorted_and_disjoint() {
        let text = "a@b.io 10.0.0.1 555-123-4567 123-45-6789 a@b.io";
        let found = Redactor::default().detect(text);
        assert_eq!(found.len(), 5);
        assert!(found.windows(2).all(|w| w[0].end <= w[1].start));
    }

    #[test]
    fn entropy_checks_pieces_around_other_detections() {
        let key = "sK3xPq9mNbYrVwZuAtJhCf7DgLeW2oI5qR8eMvXn";
        let out = Redactor::default().redact(&format!("{key}/bob@example.com"));
        assert_eq!(out, "[SECRET][EMAIL]");
    }

    #[test]
    fn mask_keeps_at_most_half() {
        let r = Redactor::new(
            Policy::none()
                .with_category(Category::Ssn)
                .with_replacement(Replacement::Mask {
                    fill: '#',
                    keep_last: 100,
                }),
        )
        .unwrap();
        assert_eq!(r.redact("123-45-6789"), "######-6789");
    }

    #[test]
    fn hash_is_keyed_and_stable() {
        let policy = Policy::none()
            .with_category(Category::Email)
            .with_replacement(Replacement::Hash);
        assert!(matches!(
            Redactor::new(policy.clone()),
            Err(Error::MissingHashKey)
        ));
        let a = Redactor::new(policy.clone().with_hash_key("k1")).unwrap();
        let b = Redactor::new(policy.with_hash_key("k2")).unwrap();
        let x = a.redact("a@b.io");
        assert!(x.starts_with("[EMAIL:") && x.len() == "[EMAIL:]".len() + 16);
        assert_eq!(x, a.redact("a@b.io"));
        assert_ne!(x, a.redact("c@b.io"));
        assert_ne!(x, b.redact("a@b.io"));
    }

    #[test]
    fn tokenize_is_consistent_across_clones() {
        let r = Redactor::new(
            Policy::none()
                .with_category(Category::Email)
                .with_replacement(Replacement::Tokenize),
        )
        .unwrap();
        let clone = r.clone();
        assert_eq!(r.redact("x@y.io a@b.io"), "[EMAIL_1] [EMAIL_2]");
        assert_eq!(clone.redact("a@b.io"), "[EMAIL_2]");
        assert_eq!(r.restore("[EMAIL_2]"), "a@b.io");
    }

    #[test]
    fn tokenize_falls_back_to_label_when_full() {
        let r = Redactor::new(
            Policy::none()
                .with_category(Category::Email)
                .with_replacement(Replacement::Tokenize)
                .with_vault_capacity(1),
        )
        .unwrap();
        assert_eq!(r.redact("x@y.io a@b.io"), "[EMAIL_1] [EMAIL]");
    }

    #[test]
    fn extra_rules_and_validation() {
        use rune_leak::SecretRule;
        let rule = SecretRule::new(
            "acme",
            "ACME token",
            r"acme_[0-9a-f]{8}",
            rune_finding_severity(),
        );
        let r = Redactor::new(
            Policy::none()
                .with_category(Category::Credential)
                .with_rules([rule]),
        )
        .unwrap();
        assert_eq!(r.redact("t=acme_deadbeef"), "t=[CREDENTIAL]");

        let bad = SecretRule::new("acme", "x", "(", rune_finding_severity());
        assert!(matches!(
            Redactor::new(Policy::none().with_rules([bad])),
            Err(Error::Rules(_))
        ));
        assert!(matches!(
            Redactor::new(Policy::default().with_entropy_threshold(f64::NAN)),
            Err(Error::InvalidEntropyThreshold)
        ));
    }

    const fn rune_finding_severity() -> rune_finding::Severity {
        rune_finding::Severity::High
    }

    const PEM_KEY: &str = "-----BEGIN PRIVATE KEY-----\n\
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgf+/P7VnzoQyH+/F6\n\
n3sVp0RGmSdIKYeaFxns1vjuXfmhRANCAAQV7oIVVRc7OI2lrPc6WNmi7ZmQywRK\n\
g8mi6bswL0UwjsNB4JWJNvAlVqinM2nbksSeEKFga2saLK8v92voHvOh\n\
-----END PRIVATE KEY-----";

    // Regression: only the `-----BEGIN ... PRIVATE KEY-----` line was
    // matched, so the base64 body (the key itself) was left in the output.
    #[test]
    fn private_key_body_is_redacted() {
        for header in ["PRIVATE KEY", "RSA PRIVATE KEY", "ENCRYPTED PRIVATE KEY"] {
            let pem = PEM_KEY.replace("PRIVATE KEY", header);
            let text = format!("key:\n{pem}\nafter");
            let out = only(Category::PrivateKey).redact(&text);
            assert_eq!(out, "key:\n[PRIVATE_KEY]\nafter", "{header}");
        }
    }

    #[test]
    fn private_key_without_end_or_with_escaped_newlines() {
        let r = only(Category::PrivateKey);
        let truncated = PEM_KEY.replace("-----END PRIVATE KEY-----", "");
        assert_eq!(
            r.redact(&format!("{truncated}\nnext: a b\n")),
            "[PRIVATE_KEY]\n\nnext: a b\n"
        );
        let json = format!(r#"{{"key":"{}"}}"#, PEM_KEY.replace('\n', "\\n"));
        assert_eq!(r.redact(&json), r#"{"key":"[PRIVATE_KEY]"}"#);
        let json = format!(r#"{{"key":"{}"}}"#, truncated.replace('\n', "\\n"));
        assert_eq!(r.redact(&json), r#"{"key":"[PRIVATE_KEY]\n"}"#);
        let pgp = "-----BEGIN PGP PRIVATE KEY BLOCK-----\nVersion: x 1\n\nlQOYBF\n=a1b2\n\
                   -----END PGP PRIVATE KEY BLOCK-----";
        assert_eq!(r.redact(pgp), "[PRIVATE_KEY]");
        // Two blocks stay two detections.
        let two = format!("{PEM_KEY}\n{PEM_KEY}");
        assert_eq!(r.redact(&two), "[PRIVATE_KEY]\n[PRIVATE_KEY]");
    }

    #[test]
    fn debug_does_not_leak_vault_values() {
        let r = Redactor::new(Policy::default().with_replacement(Replacement::Tokenize)).unwrap();
        let _ = r.redact("bob@example.com");
        assert!(!format!("{r:?}").contains("bob@"));
    }
}
