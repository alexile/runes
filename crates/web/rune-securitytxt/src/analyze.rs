//! Validation against RFC 9116 and the mapping to `rune_finding`.

use std::fmt;

use rune_finding::{Confidence, Evidence, Finding, Location, Remediation, Severity, TaxonomyRef};

use crate::{Error, Field, FieldKind, Malformed, SecurityTxt, Timestamp};

/// RFC 9116.
const RFC_URL: &str = "https://www.rfc-editor.org/rfc/rfc9116";
/// Project site with a generator.
const SITE_URL: &str = "https://securitytxt.org/";

/// 365 days, in seconds: RFC 9116 §2.5.5 recommends `Expires` be less than
/// a year away.
pub const MAX_VALIDITY_SECONDS: i64 = 365 * 86_400;

/// The class of a [`Weakness`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[non_exhaustive]
pub enum WeaknessKind {
    /// No security.txt was found.
    MissingFile,
    /// The PGP cleartext framing is broken, or text sits outside it.
    InvalidSignature,
    /// No `Contact` field (§2.5.3: one or more required).
    MissingContact,
    /// No `Expires` field (§2.5.5: required).
    MissingExpires,
    /// More than one `Expires` field (§2.5.5: must not repeat).
    DuplicateExpires,
    /// `Expires` is not an RFC 3339 date-time.
    InvalidExpires,
    /// `Expires` is in the past: the file is stale (§2.5.5).
    Expired,
    /// `Expires` is more than a year away (§2.5.5 recommends less).
    LongExpiry,
    /// More than one `Preferred-Languages` field (§2.5.8).
    DuplicatePreferredLanguages,
    /// A `Preferred-Languages` entry is not an RFC 5646 language tag.
    InvalidLanguageTag,
    /// A URI field holds something that is not a URI (e.g. a bare email
    /// address or an inline key).
    InvalidUri,
    /// A web URI uses `http://`; RFC 9116 requires `https://`.
    InsecureUri,
    /// The file was retrieved from a URI its `Canonical` fields do not list
    /// (§2.5.2), so it is not authoritative there.
    CanonicalMismatch,
    /// The file is signed but has no `Canonical` field (§2.3 recommends one,
    /// so the signature cannot be replayed on another site).
    SignedWithoutCanonical,
    /// The file is not signed (§2.3 recommends a signature).
    Unsigned,
    /// A line breaks the grammar.
    MalformedLine,
    /// A field not in the IANA registry; clients ignore it.
    UnknownField,
}

impl WeaknessKind {
    /// The `snake_case` name, used in [`WeaknessKind::check_id`].
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MissingFile => "missing_file",
            Self::InvalidSignature => "invalid_signature",
            Self::MissingContact => "missing_contact",
            Self::MissingExpires => "missing_expires",
            Self::DuplicateExpires => "duplicate_expires",
            Self::InvalidExpires => "invalid_expires",
            Self::Expired => "expired",
            Self::LongExpiry => "long_expiry",
            Self::DuplicatePreferredLanguages => "duplicate_preferred_languages",
            Self::InvalidLanguageTag => "invalid_language_tag",
            Self::InvalidUri => "invalid_uri",
            Self::InsecureUri => "insecure_uri",
            Self::CanonicalMismatch => "canonical_mismatch",
            Self::SignedWithoutCanonical => "signed_without_canonical",
            Self::Unsigned => "unsigned",
            Self::MalformedLine => "malformed_line",
            Self::UnknownField => "unknown_field",
        }
    }

    /// The stable `rune_finding` check id, `securitytxt.<kind>`.
    #[must_use]
    pub fn check_id(self) -> String {
        format!("securitytxt.{}", self.as_str())
    }

    /// Whether the weakness makes the file invalid or not authoritative:
    /// it breaks an RFC 9116 "MUST", or the file is stale.
    #[must_use]
    pub const fn invalidates(self) -> bool {
        matches!(
            self,
            Self::MissingFile
                | Self::InvalidSignature
                | Self::MissingContact
                | Self::MissingExpires
                | Self::DuplicateExpires
                | Self::InvalidExpires
                | Self::Expired
                | Self::DuplicatePreferredLanguages
                | Self::InvalidUri
                | Self::InsecureUri
                | Self::CanonicalMismatch
        )
    }

    /// What to do about it.
    #[must_use]
    pub const fn remediation(self) -> &'static str {
        match self {
            Self::MissingFile => {
                "Publish /.well-known/security.txt over HTTPS with Contact and Expires fields."
            }
            Self::InvalidSignature => {
                "Re-sign the whole file with an OpenPGP cleartext signature and put nothing \
                 outside it."
            }
            Self::MissingContact => {
                "Add a Contact field with a mailto:, tel: or https:// URI for reports."
            }
            Self::MissingExpires | Self::InvalidExpires | Self::Expired | Self::LongExpiry => {
                "Set one Expires field to an RFC 3339 date-time less than a year ahead, and \
                 renew it before it passes."
            }
            Self::DuplicateExpires => "Keep a single Expires field.",
            Self::DuplicatePreferredLanguages => {
                "Merge the language tags into one Preferred-Languages field."
            }
            Self::InvalidLanguageTag => {
                "List RFC 5646 language tags separated by commas, e.g. en, fr."
            }
            Self::InvalidUri => {
                "Write a full URI: mailto:security@example.com, tel:+1-201-555-0123 or \
                 https://example.com/…; link to keys instead of inlining them."
            }
            Self::InsecureUri => "Use https:// for every web URI.",
            Self::CanonicalMismatch => {
                "List every URI the file is served from in a Canonical field."
            }
            Self::SignedWithoutCanonical => {
                "Add Canonical fields so the signed file cannot be reused on other sites."
            }
            Self::Unsigned => "Sign the file with an OpenPGP cleartext signature.",
            Self::MalformedLine => "Write each field as `Name: value`, or comment the line out.",
            Self::UnknownField => "Check the field name against the IANA registry.",
        }
    }

    const fn cwe(self) -> Option<u32> {
        match self {
            // Cleartext transmission of reports or keys.
            Self::InsecureUri => Some(319),
            // Integrity of the contact data.
            Self::InvalidSignature | Self::CanonicalMismatch => Some(345),
            _ => None,
        }
    }
}

impl fmt::Display for WeaknessKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One problem found in a security.txt file.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct Weakness {
    /// The class of weakness.
    pub kind: WeaknessKind,
    /// How much it matters, in context.
    pub severity: Severity,
    /// The field concerned, by its registered name or as written.
    pub field: Option<String>,
    /// The 1-based line concerned, when there is one.
    pub line: Option<usize>,
    /// A human-readable explanation.
    pub message: String,
}

impl Weakness {
    fn new(kind: WeaknessKind, severity: Severity, message: impl Into<String>) -> Self {
        Self {
            kind,
            severity,
            field: None,
            line: None,
            message: message.into(),
        }
    }

    fn at(mut self, field: &Field) -> Self {
        self.field = Some(field.canonical_name().to_owned());
        self.line = (field.line > 0).then_some(field.line);
        self
    }

    const fn on_line(mut self, line: usize) -> Self {
        self.line = Some(line);
        self
    }

    /// Converts the weakness into a [`rune_finding::Finding`] with check id
    /// `securitytxt.<kind>`. The field, when there is one, becomes the
    /// location parameter; field and line go into the evidence.
    #[must_use]
    pub fn to_finding<X: Default>(&self, location: &Location) -> Finding<X> {
        let location = self.field.as_ref().map_or_else(
            || location.clone(),
            |f| location.clone().with_parameter(f.clone()),
        );
        let mut finding = Finding::<X>::new(
            self.kind.check_id(),
            self.message.clone(),
            self.severity,
            Confidence::Certain,
            location,
        )
        .with_remediation(
            Remediation::new(self.kind.remediation())
                .push_reference(RFC_URL)
                .push_reference(SITE_URL),
        );
        if let Some(cwe) = self.kind.cwe() {
            finding = finding.push_taxonomy(TaxonomyRef::cwe(cwe));
        }
        if let Some(f) = &self.field {
            finding = finding.push_evidence(Evidence::new("field", f.clone()));
        }
        if let Some(l) = self.line {
            finding = finding.push_evidence(Evidence::new("line", l.to_string()));
        }
        finding
    }
}

/// Settings for [`run`] and [`analyze`].
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct Options {
    /// The current time. Without it, `Expires` is not compared with the
    /// clock: the crate never reads one itself.
    pub now: Option<Timestamp>,
    /// `Expires` further than this many seconds after [`Options::now`] is a
    /// [`WeaknessKind::LongExpiry`]. `None` means [`MAX_VALIDITY_SECONDS`].
    pub max_validity: Option<i64>,
    /// The URI the file was retrieved from, checked against `Canonical`.
    pub retrieved_from: Option<String>,
    /// Report a missing signature as [`Severity::Low`] instead of
    /// [`Severity::Informational`]. A file with intact cleartext signature
    /// framing counts as signed even though the signature is not verified
    /// (see [`SecurityTxt::is_signed`]).
    pub require_signature: bool,
}

impl Options {
    /// Sets [`Options::now`].
    #[must_use]
    pub const fn with_now(mut self, now: Timestamp) -> Self {
        self.now = Some(now);
        self
    }

    /// Sets [`Options::max_validity`], in seconds.
    #[must_use]
    pub const fn with_max_validity(mut self, seconds: i64) -> Self {
        self.max_validity = Some(seconds);
        self
    }

    /// Sets [`Options::retrieved_from`].
    #[must_use]
    pub fn with_retrieved_from(mut self, uri: impl Into<String>) -> Self {
        self.retrieved_from = Some(uri.into());
        self
    }

    /// Sets [`Options::require_signature`].
    #[must_use]
    pub const fn with_require_signature(mut self, require: bool) -> Self {
        self.require_signature = require;
        self
    }
}

/// The result of [`run`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Report {
    /// The parsed file, when the signature framing (if any) is intact.
    pub security_txt: Option<SecurityTxt>,
    /// Why the file did not parse, if it did not.
    pub error: Option<Error>,
    /// Weaknesses, most severe first.
    pub weaknesses: Vec<Weakness>,
}

impl Report {
    /// The report for a site that serves no security.txt.
    #[must_use]
    pub fn missing() -> Self {
        Self {
            security_txt: None,
            error: None,
            weaknesses: vec![Weakness::new(
                WeaknessKind::MissingFile,
                Severity::Low,
                "No security.txt file: researchers have no published way to report \
                 vulnerabilities",
            )],
        }
    }

    /// Whether the file parsed and no weakness [invalidates](WeaknessKind::invalidates) it.
    #[must_use]
    pub fn is_valid(&self) -> bool {
        self.security_txt.is_some() && !self.weaknesses.iter().any(|w| w.kind.invalidates())
    }

    /// The most severe weakness level, if any.
    #[must_use]
    pub fn max_severity(&self) -> Option<Severity> {
        self.weaknesses.iter().map(|w| w.severity).max()
    }

    /// One [`Finding`] per weakness, at `location` (typically the URL the
    /// file was fetched from).
    #[must_use]
    pub fn to_findings<X: Default>(&self, location: &Location) -> Vec<Finding<X>> {
        self.weaknesses
            .iter()
            .map(|w| w.to_finding(location))
            .collect()
    }
}

/// Parses and validates a security.txt file.
///
/// ```
/// use rune_securitytxt::{Options, Timestamp, WeaknessKind, run};
///
/// let now = Timestamp::parse("2026-01-01T00:00:00Z")?;
/// let report = run(
///     "Contact: mailto:security@example.com\nExpires: 2025-06-30T00:00:00Z\n",
///     &Options::default().with_now(now),
/// );
/// assert!(!report.is_valid());
/// assert!(report.weaknesses.iter().any(|w| w.kind == WeaknessKind::Expired));
/// # Ok::<(), rune_securitytxt::Error>(())
/// ```
#[must_use]
pub fn run(text: &str, options: &Options) -> Report {
    match SecurityTxt::parse(text) {
        Ok(doc) => {
            let weaknesses = analyze(&doc, options);
            Report {
                security_txt: Some(doc),
                error: None,
                weaknesses,
            }
        }
        Err(error) => {
            let mut w = Weakness::new(
                WeaknessKind::InvalidSignature,
                Severity::Medium,
                format!("The file cannot be trusted: {error}"),
            );
            if let Error::InvalidSignature { line, .. } = &error {
                w = w.on_line(*line);
            }
            Report {
                security_txt: None,
                error: Some(error),
                weaknesses: vec![w],
            }
        }
    }
}

/// Validates a parsed file against RFC 9116. Weaknesses come most severe
/// first, then in file order.
#[must_use]
pub fn analyze(doc: &SecurityTxt, options: &Options) -> Vec<Weakness> {
    let mut out = Vec::new();
    for m in &doc.malformed {
        let what = match m.reason {
            Malformed::NoSeparator => "is not a `Name: value` field or a comment",
            Malformed::InvalidName => "has an invalid field name",
            Malformed::MissingSpace => "has no space after the colon",
            Malformed::EmptyValue => "has an empty value",
            Malformed::ControlCharacter => "has control characters",
        };
        out.push(
            Weakness::new(
                WeaknessKind::MalformedLine,
                Severity::Low,
                format!("Line {} {what}", m.line),
            )
            .on_line(m.line),
        );
    }
    if doc.fields_of(FieldKind::Contact).next().is_none() {
        out.push(Weakness::new(
            WeaknessKind::MissingContact,
            Severity::Medium,
            "No Contact field: the file does not say where to report vulnerabilities",
        ));
    }
    check_expires(doc, options, &mut out);
    check_languages(doc, &mut out);
    for field in &doc.fields {
        if field.kind.is_uri() {
            check_uri(field, &mut out);
        } else if field.kind == FieldKind::Extension {
            out.push(
                Weakness::new(
                    WeaknessKind::UnknownField,
                    Severity::Informational,
                    format!(
                        "Field {} is not in the IANA registry and is ignored",
                        field.name
                    ),
                )
                .at(field),
            );
        }
    }
    check_canonical(doc, options, &mut out);
    if doc.is_signed() {
        if doc.fields_of(FieldKind::Canonical).next().is_none() {
            out.push(Weakness::new(
                WeaknessKind::SignedWithoutCanonical,
                Severity::Low,
                "The file is signed but has no Canonical field, so the signed file can be \
                 replayed on another site",
            ));
        }
    } else {
        out.push(Weakness::new(
            WeaknessKind::Unsigned,
            if options.require_signature {
                Severity::Low
            } else {
                Severity::Informational
            },
            "The file has no OpenPGP signature, so its contacts cannot be authenticated",
        ));
    }
    // Stable: equal severities keep file order.
    out.sort_by_key(|w| std::cmp::Reverse(w.severity));
    out
}

fn check_expires(doc: &SecurityTxt, options: &Options, out: &mut Vec<Weakness>) {
    let mut expires = doc.fields_of(FieldKind::Expires);
    let Some(first) = expires.next() else {
        out.push(Weakness::new(
            WeaknessKind::MissingExpires,
            Severity::Medium,
            "No Expires field: clients cannot tell whether the file is current",
        ));
        return;
    };
    for dup in expires {
        out.push(
            Weakness::new(
                WeaknessKind::DuplicateExpires,
                Severity::Medium,
                "Expires appears more than once",
            )
            .at(dup),
        );
    }
    let Ok(at) = Timestamp::parse(&first.value) else {
        out.push(
            Weakness::new(
                WeaknessKind::InvalidExpires,
                Severity::Medium,
                format!(
                    "Expires value {:?} is not an RFC 3339 date-time",
                    first.value
                ),
            )
            .at(first),
        );
        return;
    };
    let Some(now) = options.now else { return };
    if at <= now {
        out.push(
            Weakness::new(
                WeaknessKind::Expired,
                Severity::Medium,
                format!("The file expired at {at} and is stale"),
            )
            .at(first),
        );
    } else {
        let max = options.max_validity.unwrap_or(MAX_VALIDITY_SECONDS);
        if at.unix_seconds().saturating_sub(now.unix_seconds()) > max {
            out.push(
                Weakness::new(
                    WeaknessKind::LongExpiry,
                    Severity::Low,
                    format!(
                        "Expires ({at}) is more than {} days away; stale contacts may go \
                         unnoticed",
                        max / 86_400
                    ),
                )
                .at(first),
            );
        }
    }
}

fn check_languages(doc: &SecurityTxt, out: &mut Vec<Weakness>) {
    let mut fields = doc.fields_of(FieldKind::PreferredLanguages);
    let Some(first) = fields.next() else { return };
    for dup in fields {
        out.push(
            Weakness::new(
                WeaknessKind::DuplicatePreferredLanguages,
                Severity::Low,
                "Preferred-Languages appears more than once",
            )
            .at(dup),
        );
    }
    for tag in first.value.split(',').map(|t| t.trim_matches([' ', '\t'])) {
        if !is_language_tag(tag) {
            out.push(
                Weakness::new(
                    WeaknessKind::InvalidLanguageTag,
                    Severity::Low,
                    format!("{tag:?} is not a language tag"),
                )
                .at(first),
            );
        }
    }
}

/// RFC 5646 well-formedness, loosely: alphanumeric subtags of 1–8
/// characters separated by `-`, the first alphabetic (or `x`/`i`).
fn is_language_tag(tag: &str) -> bool {
    let mut subtags = tag.split('-');
    let first_ok = subtags
        .next()
        .is_some_and(|s| (1..=8).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_alphabetic()));
    first_ok
        && subtags
            .all(|s| (1..=8).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_alphanumeric()))
}

/// The URI scheme (RFC 3986 §3.1), if `value` starts with one.
fn scheme(value: &str) -> Option<&str> {
    let (scheme, _) = value.split_once(':')?;
    let mut bytes = scheme.bytes();
    (bytes.next().is_some_and(|b| b.is_ascii_alphabetic())
        && bytes.all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'-' | b'.')))
    .then_some(scheme)
}

fn check_uri(field: &Field, out: &mut Vec<Weakness>) {
    let name = field.canonical_name();
    let value = field.value.as_str();
    let invalid = |why: String| {
        Weakness::new(
            WeaknessKind::InvalidUri,
            if field.kind == FieldKind::Contact {
                Severity::Medium
            } else {
                Severity::Low
            },
            why,
        )
        .at(field)
    };
    if value
        .chars()
        .any(|c| c.is_whitespace() || c.is_control() || matches!(c, '<' | '>' | '"'))
    {
        out.push(invalid(format!("{name} value {value:?} is not a URI")));
        return;
    }
    let Some(scheme) = scheme(value) else {
        let hint = if value.contains('@') {
            " (an email address needs the mailto: scheme)"
        } else {
            ""
        };
        out.push(invalid(format!(
            "{name} value {value:?} is not a URI{hint}"
        )));
        return;
    };
    let rest = &value[scheme.len() + 1..];
    let web = scheme.eq_ignore_ascii_case("https") || scheme.eq_ignore_ascii_case("http");
    if web && (!rest.starts_with("//") || rest.len() == 2 || rest[2..].starts_with('/')) {
        out.push(invalid(format!("{name} URI {value:?} has no host")));
    } else if scheme.eq_ignore_ascii_case("http") {
        out.push(
            Weakness::new(
                WeaknessKind::InsecureUri,
                if field.kind == FieldKind::Contact || field.kind == FieldKind::Encryption {
                    Severity::Medium
                } else {
                    Severity::Low
                },
                format!("{name} URI {value:?} uses http:// instead of https://"),
            )
            .at(field),
        );
    } else if field.kind != FieldKind::Contact && field.kind != FieldKind::Encryption && !web {
        out.push(invalid(format!(
            "{name} must be an https:// URI, not {scheme}:"
        )));
    }
}

/// Lowercases the scheme and authority of a URI; the rest is compared as is.
fn normalize(uri: &str) -> String {
    let Some((scheme, rest)) = uri.split_once("://") else {
        return uri.to_owned();
    };
    let split = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let (authority, path) = rest.split_at(split);
    let authority = authority.to_ascii_lowercase();
    let authority = authority
        .strip_suffix(":443")
        .filter(|_| scheme.eq_ignore_ascii_case("https"))
        .unwrap_or(&authority);
    format!("{}://{authority}{path}", scheme.to_ascii_lowercase())
}

fn check_canonical(doc: &SecurityTxt, options: &Options, out: &mut Vec<Weakness>) {
    let Some(from) = &options.retrieved_from else {
        return;
    };
    let mut canonical = doc.fields_of(FieldKind::Canonical).peekable();
    let Some(first) = canonical.peek().copied() else {
        return;
    };
    let from_n = normalize(from);
    if !canonical.any(|f| normalize(&f.value) == from_n) {
        out.push(
            Weakness::new(
                WeaknessKind::CanonicalMismatch,
                Severity::Medium,
                format!("The file was retrieved from {from}, which no Canonical field lists"),
            )
            .at(first),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GOOD: &str = "Contact: mailto:security@example.com\n\
                        Expires: 2026-06-01T00:00:00Z\n\
                        Canonical: https://example.com/.well-known/security.txt\n";

    fn now() -> Timestamp {
        Timestamp::parse("2026-01-01T00:00:00Z").unwrap()
    }

    fn kinds(text: &str, options: &Options) -> Vec<WeaknessKind> {
        run(text, options)
            .weaknesses
            .iter()
            .map(|w| w.kind)
            .collect()
    }

    #[test]
    fn good_file_is_valid() {
        let opts = Options::default()
            .with_now(now())
            .with_retrieved_from("HTTPS://Example.com:443/.well-known/security.txt");
        let r = run(GOOD, &opts);
        assert!(r.is_valid());
        assert_eq!(r.max_severity(), Some(Severity::Informational));
        assert_eq!(kinds(GOOD, &opts), [WeaknessKind::Unsigned]);
    }

    #[test]
    fn required_fields() {
        let k = kinds("Policy: https://example.com/p\n", &Options::default());
        assert!(k.contains(&WeaknessKind::MissingContact));
        assert!(k.contains(&WeaknessKind::MissingExpires));
        assert!(!run("", &Options::default()).is_valid());
    }

    #[test]
    fn expiry() {
        let opts = Options::default().with_now(now());
        let expired = GOOD.replace("2026-06-01", "2025-12-31");
        assert!(kinds(&expired, &opts).contains(&WeaknessKind::Expired));
        assert!(!run(&expired, &opts).is_valid());
        // Without a clock, no verdict on staleness.
        assert!(run(&expired, &Options::default()).is_valid());
        let long = GOOD.replace("2026-06-01", "2027-06-01");
        let r = run(&long, &opts);
        assert!(r.is_valid());
        assert!(
            r.weaknesses
                .iter()
                .any(|w| w.kind == WeaknessKind::LongExpiry)
        );
        let dup = format!("{GOOD}Expires: 2026-05-01T00:00:00Z\n");
        assert!(kinds(&dup, &opts).contains(&WeaknessKind::DuplicateExpires));
        let bad = GOOD.replace("2026-06-01T00:00:00Z", "Mon, 01 Jun 2026 00:00:00 GMT");
        assert!(kinds(&bad, &opts).contains(&WeaknessKind::InvalidExpires));
    }

    #[test]
    fn uris() {
        let text = format!(
            "{GOOD}Contact: security@example.com\nContact: http://example.com/report\n\
             Encryption: openpgp4fpr:5f2de5521c63a801ab59ccb603d49de44b29100f\n\
             Encryption: -----BEGIN PGP PUBLIC KEY BLOCK-----\nPolicy: ftp://example.com/p\n\
             Hiring: https:///jobs\n"
        );
        let r = run(&text, &Options::default());
        let got: Vec<_> = r
            .weaknesses
            .iter()
            .filter(|w| matches!(w.kind, WeaknessKind::InvalidUri | WeaknessKind::InsecureUri))
            .map(|w| (w.kind, w.line))
            .collect();
        assert_eq!(
            got,
            [
                (WeaknessKind::InvalidUri, Some(4)),
                (WeaknessKind::InsecureUri, Some(5)),
                (WeaknessKind::InvalidUri, Some(7)),
                (WeaknessKind::InvalidUri, Some(8)),
                (WeaknessKind::InvalidUri, Some(9)),
            ]
        );
        assert!(r.weaknesses[0].message.contains("mailto:"));
    }

    #[test]
    fn canonical_mismatch() {
        let opts =
            Options::default().with_retrieved_from("https://evil.example/.well-known/security.txt");
        assert!(kinds(GOOD, &opts).contains(&WeaknessKind::CanonicalMismatch));
        // No Canonical field: nothing to compare against.
        let no_canonical = "Contact: mailto:a@example.com\nExpires: 2026-06-01T00:00:00Z\n";
        assert!(!kinds(no_canonical, &opts).contains(&WeaknessKind::CanonicalMismatch));
    }

    #[test]
    fn languages_and_extensions() {
        let text = format!(
            "{GOOD}Preferred-Languages: en, zh-Hant-TW, english!\nPreferred-Languages: fr\nX-Foo: 1\n"
        );
        let k = kinds(&text, &Options::default());
        assert!(k.contains(&WeaknessKind::InvalidLanguageTag));
        assert!(k.contains(&WeaknessKind::DuplicatePreferredLanguages));
        assert!(k.contains(&WeaknessKind::UnknownField));
        assert_eq!(
            k.iter()
                .filter(|k| **k == WeaknessKind::InvalidLanguageTag)
                .count(),
            1
        );
    }

    #[test]
    fn signature_problems() {
        let signed = "-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA512\n\n\
             Contact: mailto:a@example.com\nExpires: 2026-06-01T00:00:00Z\n\
             -----BEGIN PGP SIGNATURE-----\nAA==\n-----END PGP SIGNATURE-----\n";
        let k = kinds(signed, &Options::default());
        assert_eq!(k, [WeaknessKind::SignedWithoutCanonical]);
        // "AA==" is no signature at all: the framing is all that is checked.
        let k = kinds(signed, &Options::default().with_require_signature(true));
        assert!(!k.contains(&WeaknessKind::Unsigned));
        let tampered = format!("{signed}Contact: mailto:attacker@evil.example\n");
        let r = run(&tampered, &Options::default());
        assert!(r.error.is_some());
        assert_eq!(r.weaknesses[0].kind, WeaknessKind::InvalidSignature);
        assert_eq!(r.weaknesses[0].line, Some(9));
        assert!(!r.is_valid());
    }

    #[test]
    fn findings() {
        let r = run("Contact: http://example.com/\n", &Options::default());
        let f: Vec<rune_finding::Finding> = r.to_findings(&Location::url(
            "https://example.com/.well-known/security.txt",
        ));
        assert_eq!(f.len(), r.weaknesses.len());
        assert!(f.iter().any(|f| f.check_id == "securitytxt.insecure_uri"));
        assert!(
            f.iter()
                .any(|f| f.check_id == "securitytxt.missing_expires")
        );
        let missing = Report::missing();
        assert!(!missing.is_valid());
        assert_eq!(
            missing.weaknesses[0].kind.check_id(),
            "securitytxt.missing_file"
        );
    }
}
