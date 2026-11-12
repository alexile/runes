//! The security.txt document model and its parser (RFC 9116 §4 grammar,
//! RFC 4880 §7 cleartext signature framework).

use std::fmt;

use crate::{Error, Timestamp};

const SIGNED_HEADER: &str = "-----BEGIN PGP SIGNED MESSAGE-----";
const SIGNATURE_BEGIN: &str = "-----BEGIN PGP SIGNATURE-----";
const SIGNATURE_END: &str = "-----END PGP SIGNATURE-----";

/// The kind of a [`Field`]: one of the fields in the IANA "security.txt
/// Fields" registry, or an extension.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[non_exhaustive]
pub enum FieldKind {
    /// `Acknowledgments` (RFC 9116 §2.5.1): a page recognizing reporters.
    Acknowledgments,
    /// `Canonical` (§2.5.2): a URI where this file is published.
    Canonical,
    /// `Contact` (§2.5.3, required): where to report vulnerabilities. The
    /// order of `Contact` fields is the order of preference.
    Contact,
    /// `CSAF` (CSAF 2.0 §7.1.8): a CSAF provider metadata URL.
    Csaf,
    /// `Encryption` (§2.5.4): where to find a key for encrypted reports.
    Encryption,
    /// `Expires` (§2.5.5, required once): when the file becomes stale.
    Expires,
    /// `Hiring` (§2.5.6): security-related job openings.
    Hiring,
    /// `Policy` (§2.5.7): the vulnerability disclosure policy.
    Policy,
    /// `Preferred-Languages` (§2.5.8, at most once): language tags.
    PreferredLanguages,
    /// Any other field; parsers must ignore it (§2.4).
    Extension,
}

impl FieldKind {
    /// Every registered kind, in registry order.
    pub const REGISTERED: [Self; 9] = [
        Self::Acknowledgments,
        Self::Canonical,
        Self::Contact,
        Self::Csaf,
        Self::Encryption,
        Self::Expires,
        Self::Hiring,
        Self::Policy,
        Self::PreferredLanguages,
    ];

    /// The kind for a field name, compared case-insensitively (§2.4).
    #[must_use]
    pub fn from_name(name: &str) -> Self {
        Self::REGISTERED
            .into_iter()
            .find(|k| k.name().is_some_and(|n| n.eq_ignore_ascii_case(name)))
            .unwrap_or(Self::Extension)
    }

    /// The registered field name, or `None` for [`FieldKind::Extension`].
    #[must_use]
    pub const fn name(self) -> Option<&'static str> {
        Some(match self {
            Self::Acknowledgments => "Acknowledgments",
            Self::Canonical => "Canonical",
            Self::Contact => "Contact",
            Self::Csaf => "CSAF",
            Self::Encryption => "Encryption",
            Self::Expires => "Expires",
            Self::Hiring => "Hiring",
            Self::Policy => "Policy",
            Self::PreferredLanguages => "Preferred-Languages",
            Self::Extension => return None,
        })
    }

    /// Whether the value is a URI (every registered field except `Expires`
    /// and `Preferred-Languages`).
    #[must_use]
    pub const fn is_uri(self) -> bool {
        !matches!(
            self,
            Self::Expires | Self::PreferredLanguages | Self::Extension
        )
    }
}

/// One `Name: value` line.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct Field {
    /// What the field is.
    pub kind: FieldKind,
    /// The name as written.
    pub name: String,
    /// The value, without surrounding whitespace.
    pub value: String,
    /// 1-based line number in the input (0 for fields built in code).
    pub line: usize,
}

impl Field {
    /// A field built in code; the kind follows from `name`.
    #[must_use]
    pub fn new(name: impl Into<String>, value: impl Into<String>) -> Self {
        let name = name.into();
        Self {
            kind: FieldKind::from_name(&name),
            name,
            value: value.into(),
            line: 0,
        }
    }

    /// The registered name for a registered kind, the name as written
    /// otherwise.
    #[must_use]
    pub fn canonical_name(&self) -> &str {
        self.kind.name().unwrap_or(&self.name)
    }
}

/// Why a line is not a well-formed field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Malformed {
    /// The line is neither blank, a `#` comment nor `name: value`.
    NoSeparator,
    /// The field name is empty or has characters RFC 5322 does not allow.
    InvalidName,
    /// The `:` is not followed by a space. The field is still parsed.
    MissingSpace,
    /// The field has no value; it is ignored.
    EmptyValue,
    /// The line has control characters; it is ignored.
    ControlCharacter,
}

/// A line that breaks the RFC 9116 grammar.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct MalformedLine {
    /// 1-based line number.
    pub line: usize,
    /// The line, without its line ending.
    pub text: String,
    /// What is wrong with it.
    pub reason: Malformed,
}

/// A PGP cleartext signature around the file (RFC 4880 §7).
///
/// The crate does not verify signatures. Hand
/// [`Signature::canonical_text`] and [`Signature::armored`] to a PGP
/// implementation, with the organization's key, to do that.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct Signature {
    /// Hash algorithms named in `Hash:` armor headers (e.g. `SHA512`).
    pub hash_algorithms: Vec<String>,
    /// The signed text, dash-unescaped, lines joined with `\n` and without
    /// the final line ending.
    pub signed_text: String,
    /// The ASCII-armored signature, from `-----BEGIN PGP SIGNATURE-----`
    /// to `-----END PGP SIGNATURE-----` inclusive, lines joined with `\n`.
    pub armored: String,
}

impl Signature {
    /// The text the signature is computed over: trailing spaces and tabs
    /// removed from each line, lines joined with `\r\n` (RFC 4880 §7.1).
    #[must_use]
    pub fn canonical_text(&self) -> String {
        self.signed_text
            .split('\n')
            .map(|l| l.trim_end_matches([' ', '\t']))
            .collect::<Vec<_>>()
            .join("\r\n")
    }
}

/// A parsed security.txt file.
///
/// [`SecurityTxt::parse`] follows the RFC 9116 grammar loosely, the way
/// clients should: field names are case-insensitive, unknown fields are
/// kept as [`FieldKind::Extension`], and lines that break the grammar are
/// listed in [`SecurityTxt::malformed`] instead of failing the parse. Only
/// a broken PGP cleartext framing is an [`Error`], since then it is
/// unclear which fields are covered by the signature.
///
/// [`Display`](fmt::Display) writes the fields, one per line, with their
/// registered names (unsigned; comments are dropped).
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct SecurityTxt {
    /// Every field, in file order.
    pub fields: Vec<Field>,
    /// Lines that break the grammar.
    pub malformed: Vec<MalformedLine>,
    /// The cleartext signature, when the file is signed.
    pub signature: Option<Signature>,
}

impl SecurityTxt {
    /// An empty document.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a field.
    #[must_use]
    pub fn with_field(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.fields.push(Field::new(name, value));
        self
    }

    /// Parses the body of a security.txt file. A leading byte-order mark is
    /// skipped; lines end with `\n` or `\r\n`.
    pub fn parse(text: &str) -> Result<Self, Error> {
        let text = text.strip_prefix('\u{feff}').unwrap_or(text);
        let lines: Vec<&str> = text
            .split('\n')
            .map(|l| l.strip_suffix('\r').unwrap_or(l))
            .collect();
        let mut doc = Self::new();
        if lines
            .first()
            .is_some_and(|l| l.trim_end_matches([' ', '\t']) == SIGNED_HEADER)
        {
            let (signature, body_start, body) = parse_signed(&lines)?;
            for (i, line) in body.iter().enumerate() {
                doc.parse_line(body_start + i + 1, line);
            }
            doc.signature = Some(signature);
        } else {
            for (i, line) in lines.iter().enumerate() {
                doc.parse_line(i + 1, line);
            }
        }
        Ok(doc)
    }

    fn parse_line(&mut self, number: usize, raw: &str) {
        let line = raw.trim_end_matches([' ', '\t']);
        if line.is_empty() || line.starts_with('#') {
            return;
        }
        let malformed = |reason| MalformedLine {
            line: number,
            text: raw.to_owned(),
            reason,
        };
        if line.chars().any(|c| c.is_control() && c != '\t') {
            self.malformed.push(malformed(Malformed::ControlCharacter));
            return;
        }
        let Some((name, rest)) = line.split_once(':') else {
            self.malformed.push(malformed(Malformed::NoSeparator));
            return;
        };
        // RFC 5322 field-name: printable US-ASCII except ":".
        if name.is_empty() || !name.bytes().all(|b| (33..=126).contains(&b)) {
            self.malformed.push(malformed(Malformed::InvalidName));
            return;
        }
        let value = rest.trim_matches([' ', '\t']);
        if value.is_empty() {
            self.malformed.push(malformed(Malformed::EmptyValue));
            return;
        }
        if !rest.starts_with(' ') {
            self.malformed.push(malformed(Malformed::MissingSpace));
        }
        self.fields.push(Field {
            kind: FieldKind::from_name(name),
            name: name.to_owned(),
            value: value.to_owned(),
            line: number,
        });
    }

    /// The fields of one kind, in file order.
    pub fn fields_of(&self, kind: FieldKind) -> impl Iterator<Item = &Field> {
        self.fields.iter().filter(move |f| f.kind == kind)
    }

    /// The values of one kind, in file order.
    pub fn values(&self, kind: FieldKind) -> impl Iterator<Item = &str> {
        self.fields_of(kind).map(|f| f.value.as_str())
    }

    /// `Contact` URIs, most preferred first.
    #[must_use]
    pub fn contacts(&self) -> Vec<&str> {
        self.values(FieldKind::Contact).collect()
    }

    /// `Encryption` URIs.
    #[must_use]
    pub fn encryption(&self) -> Vec<&str> {
        self.values(FieldKind::Encryption).collect()
    }

    /// `Acknowledgments` URIs.
    #[must_use]
    pub fn acknowledgments(&self) -> Vec<&str> {
        self.values(FieldKind::Acknowledgments).collect()
    }

    /// `Canonical` URIs.
    #[must_use]
    pub fn canonical(&self) -> Vec<&str> {
        self.values(FieldKind::Canonical).collect()
    }

    /// `Policy` URIs.
    #[must_use]
    pub fn policy(&self) -> Vec<&str> {
        self.values(FieldKind::Policy).collect()
    }

    /// `Hiring` URIs.
    #[must_use]
    pub fn hiring(&self) -> Vec<&str> {
        self.values(FieldKind::Hiring).collect()
    }

    /// `CSAF` provider metadata URLs.
    #[must_use]
    pub fn csaf(&self) -> Vec<&str> {
        self.values(FieldKind::Csaf).collect()
    }

    /// The first `Expires` value, if present and a valid timestamp.
    #[must_use]
    pub fn expires(&self) -> Option<Timestamp> {
        self.values(FieldKind::Expires)
            .next()
            .and_then(|v| Timestamp::parse(v).ok())
    }

    /// The language tags of the first `Preferred-Languages` field, in
    /// order (empty when there is none).
    #[must_use]
    pub fn preferred_languages(&self) -> Vec<&str> {
        self.values(FieldKind::PreferredLanguages)
            .next()
            .map(|v| {
                v.split(',')
                    .map(|t| t.trim_matches([' ', '\t']))
                    .filter(|t| !t.is_empty())
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Fields that are not in the registry.
    pub fn extensions(&self) -> impl Iterator<Item = &Field> {
        self.fields_of(FieldKind::Extension)
    }

    /// Whether the file has a PGP cleartext signature.
    #[must_use]
    pub const fn is_signed(&self) -> bool {
        self.signature.is_some()
    }
}

impl fmt::Display for SecurityTxt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for field in &self.fields {
            writeln!(f, "{}: {}", field.canonical_name(), field.value)?;
        }
        Ok(())
    }
}

/// Splits a cleartext-signed message into its signature, the 0-based index
/// of the first body line, and the dash-unescaped body lines.
fn parse_signed<'a>(lines: &[&'a str]) -> Result<(Signature, usize, Vec<&'a str>), Error> {
    let err = |line: usize, message: &str| Error::InvalidSignature {
        line,
        message: message.to_owned(),
    };
    // Armor headers, up to an empty line.
    let mut hash_algorithms = Vec::new();
    let mut i = 1;
    loop {
        let Some(line) = lines.get(i) else {
            return Err(err(
                lines.len(),
                "armor headers are not followed by an empty line",
            ));
        };
        let line = line.trim_end_matches([' ', '\t']);
        if line.is_empty() {
            break;
        }
        let Some((key, value)) = line.split_once(": ") else {
            return Err(err(i + 1, "malformed armor header"));
        };
        if key == "Hash" {
            hash_algorithms.extend(
                value
                    .split(',')
                    .map(str::trim)
                    .filter(|h| !h.is_empty())
                    .map(str::to_owned),
            );
        }
        i += 1;
    }
    let body_start = i + 1;
    let mut body = Vec::new();
    let mut i = body_start;
    loop {
        let Some(&line) = lines.get(i) else {
            return Err(err(lines.len(), "no -----BEGIN PGP SIGNATURE----- line"));
        };
        if line.trim_end_matches([' ', '\t']) == SIGNATURE_BEGIN {
            break;
        }
        if let Some(rest) = line.strip_prefix("- ") {
            body.push(rest);
        } else if line.starts_with('-') {
            return Err(err(i + 1, "line starting with '-' is not dash-escaped"));
        } else {
            body.push(line);
        }
        i += 1;
    }
    let sig_start = i;
    loop {
        i += 1;
        let Some(line) = lines.get(i) else {
            return Err(err(lines.len(), "no -----END PGP SIGNATURE----- line"));
        };
        if line.trim_end_matches([' ', '\t']) == SIGNATURE_END {
            break;
        }
    }
    let armored = lines[sig_start..=i]
        .iter()
        .map(|l| l.trim_end_matches([' ', '\t']))
        .collect::<Vec<_>>()
        .join("\n");
    if let Some(extra) = lines[i + 1..].iter().position(|l| !l.trim().is_empty()) {
        return Err(err(
            i + extra + 2,
            "content after the signature is not covered by it",
        ));
    }
    let signature = Signature {
        hash_algorithms,
        signed_text: body.join("\n"),
        armored,
    };
    Ok((signature, body_start, body))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_fields_comments_and_case() {
        let doc = SecurityTxt::parse(
            "# comment\r\ncontact: mailto:a@example.com\r\n\r\nCONTACT: tel:+1-201-555-0123  \r\n\
             Expires: 2030-01-01T00:00:00Z\nX-Thing: whatever\n",
        )
        .unwrap();
        assert_eq!(
            doc.contacts(),
            ["mailto:a@example.com", "tel:+1-201-555-0123"]
        );
        assert_eq!(doc.fields[0].line, 2);
        assert_eq!(doc.fields[1].line, 4);
        assert_eq!(
            doc.expires().map(Timestamp::unix_seconds),
            Some(1_893_456_000)
        );
        assert_eq!(doc.extensions().count(), 1);
        assert_eq!(doc.malformed, []);
        assert!(!doc.is_signed());
        assert_eq!(
            doc.to_string(),
            "Contact: mailto:a@example.com\nContact: tel:+1-201-555-0123\n\
             Expires: 2030-01-01T00:00:00Z\nX-Thing: whatever\n"
        );
    }

    #[test]
    fn malformed_lines() {
        let doc = SecurityTxt::parse(
            "just text\nContact:mailto:a@example.com\nBad Name: x\nPolicy:\n: x\nHiring: a\u{7}b\n",
        )
        .unwrap();
        let reasons: Vec<_> = doc.malformed.iter().map(|m| (m.line, m.reason)).collect();
        assert_eq!(
            reasons,
            [
                (1, Malformed::NoSeparator),
                (2, Malformed::MissingSpace),
                (3, Malformed::InvalidName),
                (4, Malformed::EmptyValue),
                (5, Malformed::InvalidName),
                (6, Malformed::ControlCharacter),
            ]
        );
        // A missing space is reported, but the field is kept.
        assert_eq!(doc.contacts(), ["mailto:a@example.com"]);
    }

    #[test]
    fn preferred_languages() {
        let doc = SecurityTxt::parse("Preferred-Languages: en, es ,fr\n").unwrap();
        assert_eq!(doc.preferred_languages(), ["en", "es", "fr"]);
    }

    #[test]
    fn signed_framing() {
        let text = "-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\n\
                    Contact: mailto:a@example.com  \n- -dash line\n\
                    -----BEGIN PGP SIGNATURE-----\n\nAAAA\n-----END PGP SIGNATURE-----\n\n";
        let doc = SecurityTxt::parse(text).unwrap();
        let sig = doc.signature.as_ref().unwrap();
        assert_eq!(sig.hash_algorithms, ["SHA256"]);
        assert_eq!(
            sig.signed_text,
            "Contact: mailto:a@example.com  \n-dash line"
        );
        assert_eq!(
            sig.canonical_text(),
            "Contact: mailto:a@example.com\r\n-dash line"
        );
        assert!(sig.armored.starts_with(SIGNATURE_BEGIN));
        assert!(sig.armored.ends_with(SIGNATURE_END));
        assert_eq!(doc.fields[0].line, 4);
        assert_eq!(doc.malformed[0].line, 5);
    }

    #[test]
    fn broken_signed_framing() {
        let head = "-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n";
        for (text, line) in [
            (head.to_owned(), 3),
            (format!("{head}\nContact: x\n"), 5),
            (format!("{head}\n-bad\n{SIGNATURE_BEGIN}\n"), 4),
            (format!("{head}\nContact: x\n{SIGNATURE_BEGIN}\nAA\n"), 7),
            (
                format!("{head}\nContact: x\n{SIGNATURE_BEGIN}\n{SIGNATURE_END}\n\nContact: y\n"),
                8,
            ),
            (
                "-----BEGIN PGP SIGNED MESSAGE-----\nHash SHA256\n".to_owned(),
                2,
            ),
        ] {
            match SecurityTxt::parse(&text) {
                Err(Error::InvalidSignature { line: l, .. }) => {
                    assert_eq!(l, line, "{text:?} -> {l}");
                }
                other => panic!("{text:?}: {other:?}"),
            }
        }
    }

    #[test]
    fn field_kind_names() {
        for k in FieldKind::REGISTERED {
            let name = k.name().unwrap();
            assert_eq!(FieldKind::from_name(name), k);
            assert_eq!(FieldKind::from_name(&name.to_lowercase()), k);
        }
        assert_eq!(FieldKind::from_name("Contacts"), FieldKind::Extension);
    }
}
