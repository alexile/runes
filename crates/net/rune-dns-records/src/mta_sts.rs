//! MTA-STS ([RFC 8461](https://www.rfc-editor.org/rfc/rfc8461)): the
//! `_mta-sts` `TXT` record and the HTTPS policy file.

use core::fmt;
use core::str::FromStr;

use crate::error::{Error, RecordKind};
use crate::issue::{Issue, IssueKind, sorted};

/// Largest policy file a sender should accept (RFC 8461 §3.3: 64 KiB).
pub const MAX_POLICY_LEN: usize = 64 * 1024;

/// Largest `max_age` allowed, about one year (RFC 8461 §3.2).
pub const MAX_MAX_AGE: u32 = 31_557_600;

/// One day: a `max_age` below this defeats MTA-STS caching.
const SHORT_MAX_AGE: u32 = 86_400;

/// Splits `v=...; name=value; ...` (RFC 8461 §3.1, RFC 8460 §3), checking
/// that the first field is `version` exactly and that extension names are
/// 1–32 of `ALPHA / DIGIT / "_" / "-" / "."`. Returns the other fields.
pub(crate) fn version_fields<'a>(
    text: &'a str,
    record: RecordKind,
    version: &'static str,
) -> Result<Vec<(&'a str, &'a str)>, Error> {
    let wsp = |c: char| c == ' ' || c == '\t';
    let mut parts = text.split(';').map(|p| p.trim_matches(wsp));
    if parts.next() != Some(version) {
        return Err(Error::NotThisRecord {
            record,
            reason: "missing or wrong version field",
        });
    }
    let mut fields: Vec<(&str, &str)> = Vec::new();
    let mut parts = parts.peekable();
    while let Some(part) = parts.next() {
        if part.is_empty() {
            // Only a final separator may be followed by nothing.
            if parts.peek().is_some() {
                return Err(Error::syntax(record, text, "empty field"));
            }
            continue;
        }
        let Some((name, value)) = part.split_once('=') else {
            return Err(Error::syntax(record, part, "field without `=`"));
        };
        let name_ok = (1..=32).contains(&name.len())
            && name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'));
        if !name_ok {
            return Err(Error::syntax(record, part, "invalid field name"));
        }
        // RFC 8461 forbids `=` in extension values, but RFC 8460 URIs may
        // contain it; `;` cannot occur after the split.
        if !value
            .bytes()
            .all(|b| matches!(b, 0x21..=0x7e | b' ' | b'\t'))
        {
            return Err(Error::syntax(
                record,
                part,
                "invalid character in field value",
            ));
        }
        if fields.iter().any(|(n, _)| *n == name) {
            return Err(Error::DuplicateTag {
                record,
                tag: crate::error::truncate(name),
            });
        }
        fields.push((name, value));
    }
    Ok(fields)
}

/// The `_mta-sts.<domain>` `TXT` record (RFC 8461 §3.1).
///
/// ```
/// use rune_dns_records::mta_sts::MtaStsRecord;
///
/// let record: MtaStsRecord = "v=STSv1; id=20160831085700Z;".parse()?;
/// assert_eq!(record.id, "20160831085700Z");
/// # Ok::<(), rune_dns_records::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct MtaStsRecord {
    /// Policy version id: 1 to 32 letters and digits. A change tells
    /// senders to fetch the policy again.
    pub id: String,
    /// Extension fields, in order.
    pub extensions: Vec<(String, String)>,
}

impl MtaStsRecord {
    /// Parses the record.
    ///
    /// # Errors
    ///
    /// [`Error::NotThisRecord`] unless it starts with `v=STSv1`,
    /// [`Error::MissingTag`] without `id=`, [`Error::InvalidTag`] for a bad
    /// id, [`Error::Syntax`] or [`Error::DuplicateTag`] otherwise.
    pub fn parse(text: &str) -> Result<Self, Error> {
        const R: RecordKind = RecordKind::MtaSts;
        let mut id = None;
        let mut extensions = Vec::new();
        for (name, value) in version_fields(text, R, "v=STSv1")? {
            if name == "id" {
                let ok = (1..=32).contains(&value.len())
                    && value.bytes().all(|b| b.is_ascii_alphanumeric());
                if !ok {
                    return Err(Error::invalid_tag(
                        R,
                        "id",
                        "expected 1 to 32 letters and digits",
                    ));
                }
                id = Some(value.to_owned());
            } else {
                extensions.push((name.to_owned(), value.to_owned()));
            }
        }
        let id = id.ok_or(Error::MissingTag {
            record: R,
            tag: "id",
        })?;
        Ok(Self { id, extensions })
    }

    /// Selects and parses the record among the `TXT` records at
    /// `_mta-sts.<domain>`: those starting with `v=STSv1;` (RFC 8461 §3.1).
    ///
    /// # Errors
    ///
    /// [`Error::MultipleRecords`] if there are several, otherwise any
    /// error of [`MtaStsRecord::parse`].
    pub fn find<I, S>(txts: I) -> Result<Option<Self>, Error>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        find_one(txts, "v=STSv1;", RecordKind::MtaSts, Self::parse)
    }
}

/// Picks the single `TXT` record starting with `prefix`.
pub(crate) fn find_one<I, S, T>(
    txts: I,
    prefix: &str,
    record: RecordKind,
    parse: impl Fn(&str) -> Result<T, Error>,
) -> Result<Option<T>, Error>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut found = None;
    let mut count = 0;
    for txt in txts {
        let matches =
            txt.as_ref().starts_with(prefix) || txt.as_ref() == prefix.trim_end_matches(';');
        if matches {
            count += 1;
            found.get_or_insert(txt);
        }
    }
    match (found, count) {
        (None, _) => Ok(None),
        (Some(txt), 1) => parse(txt.as_ref()).map(Some),
        (Some(_), count) => Err(Error::MultipleRecords { record, count }),
    }
}

impl FromStr for MtaStsRecord {
    type Err = Error;

    fn from_str(text: &str) -> Result<Self, Error> {
        Self::parse(text)
    }
}

impl fmt::Display for MtaStsRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "v=STSv1; id={}", self.id)?;
        for (name, value) in &self.extensions {
            write!(f, "; {name}={value}")?;
        }
        Ok(())
    }
}

/// The policy mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Mode {
    /// Senders must not deliver unless TLS to a listed MX succeeds.
    Enforce,
    /// Senders deliver anyway and report failures (TLS-RPT).
    Testing,
    /// The policy is withdrawn.
    None,
}

impl Mode {
    /// The field value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Enforce => "enforce",
            Self::Testing => "testing",
            Self::None => "none",
        }
    }
}

/// The policy file at `https://mta-sts.<domain>/.well-known/mta-sts.txt`
/// (RFC 8461 §3.2).
///
/// ```
/// use rune_dns_records::mta_sts::{Mode, MtaStsPolicy};
///
/// let policy: MtaStsPolicy =
///     "version: STSv1\r\nmode: enforce\r\nmx: mail.example.com\r\nmx: *.example.net\r\nmax_age: 604800\r\n"
///         .parse()?;
/// assert_eq!(policy.mode, Mode::Enforce);
/// assert!(policy.matches_mx("mx1.example.net"));
/// assert!(!policy.matches_mx("a.b.example.net"));
/// # Ok::<(), rune_dns_records::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct MtaStsPolicy {
    /// The mode.
    pub mode: Mode,
    /// How long senders may cache the policy, in seconds.
    pub max_age: u32,
    /// MX host patterns: a host name, or `*.` and a domain matching one
    /// extra label.
    pub mx: Vec<String>,
    /// Other fields, in order.
    pub extensions: Vec<(String, String)>,
}

impl MtaStsPolicy {
    /// Parses a policy file. Lines end in CRLF or LF.
    ///
    /// # Errors
    ///
    /// [`Error::TooLong`] above [`MAX_POLICY_LEN`],
    /// [`Error::NotThisRecord`] without `version: STSv1`,
    /// [`Error::MissingTag`] without `mode`, `max_age`, or (unless the mode
    /// is `none`) any `mx`, [`Error::InvalidTag`] for bad values,
    /// [`Error::Syntax`] and [`Error::DuplicateTag`] for malformed lines.
    pub fn parse(text: &str) -> Result<Self, Error> {
        const R: RecordKind = RecordKind::MtaStsPolicy;
        if text.len() > MAX_POLICY_LEN {
            return Err(Error::TooLong {
                record: R,
                len: text.len(),
                max: MAX_POLICY_LEN,
            });
        }
        let mut version = false;
        let mut mode = None;
        let mut max_age = None;
        let mut mx = Vec::new();
        let mut extensions = Vec::new();
        for line in text.split('\n') {
            let line = line.strip_suffix('\r').unwrap_or(line);
            if line.trim().is_empty() {
                continue;
            }
            let Some((key, value)) = line.split_once(':') else {
                return Err(Error::syntax(R, line, "line without `:`"));
            };
            let value = value.trim_matches([' ', '\t']);
            let key_ok = (1..=32).contains(&key.len())
                && key
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'));
            if !key_ok {
                return Err(Error::syntax(R, line, "invalid field name"));
            }
            if !value
                .bytes()
                .all(|b| (0x20..=0x7e).contains(&b) || b == b'\t')
            {
                return Err(Error::syntax(R, line, "invalid character in field value"));
            }
            let duplicate = || Error::DuplicateTag {
                record: R,
                tag: key.to_owned(),
            };
            match key {
                "version" => {
                    if version {
                        return Err(duplicate());
                    }
                    if value != "STSv1" {
                        return Err(Error::NotThisRecord {
                            record: R,
                            reason: "version is not STSv1",
                        });
                    }
                    version = true;
                }
                "mode" => {
                    let parsed = match value {
                        "enforce" => Mode::Enforce,
                        "testing" => Mode::Testing,
                        "none" => Mode::None,
                        _ => {
                            return Err(Error::invalid_tag(
                                R,
                                "mode",
                                "expected enforce, testing or none",
                            ));
                        }
                    };
                    if mode.replace(parsed).is_some() {
                        return Err(duplicate());
                    }
                }
                "max_age" => {
                    let parsed = (value.len() <= 10 && value.bytes().all(|b| b.is_ascii_digit()))
                        .then(|| value.parse::<u32>().ok())
                        .flatten()
                        .filter(|age| *age <= MAX_MAX_AGE)
                        .ok_or_else(|| {
                            Error::invalid_tag(R, "max_age", "expected 0 to 31557600 seconds")
                        })?;
                    if max_age.replace(parsed).is_some() {
                        return Err(duplicate());
                    }
                }
                "mx" => {
                    if !is_mx_pattern(value) {
                        return Err(Error::invalid_tag(
                            R,
                            "mx",
                            "expected a host name or *.domain",
                        ));
                    }
                    mx.push(value.to_owned());
                }
                _ => extensions.push((key.to_owned(), value.to_owned())),
            }
        }
        if !version {
            return Err(Error::NotThisRecord {
                record: R,
                reason: "missing version: STSv1",
            });
        }
        let mode = mode.ok_or(Error::MissingTag {
            record: R,
            tag: "mode",
        })?;
        let max_age = max_age.ok_or(Error::MissingTag {
            record: R,
            tag: "max_age",
        })?;
        if mx.is_empty() && mode != Mode::None {
            return Err(Error::MissingTag {
                record: R,
                tag: "mx",
            });
        }
        Ok(Self {
            mode,
            max_age,
            mx,
            extensions,
        })
    }

    /// Whether `host` (an MX host name) matches one of the `mx` patterns
    /// (RFC 8461 §4.1): exactly, or a `*.` pattern with exactly one more
    /// label. Case and a trailing dot are ignored.
    #[must_use]
    pub fn matches_mx(&self, host: &str) -> bool {
        let host = host.trim_end_matches('.').to_ascii_lowercase();
        self.mx.iter().any(|pattern| {
            let pattern = pattern.trim_end_matches('.').to_ascii_lowercase();
            pattern.strip_prefix("*.").map_or_else(
                || host == pattern,
                |domain| {
                    host.split_once('.')
                        .is_some_and(|(label, rest)| !label.is_empty() && rest == domain)
                },
            )
        })
    }

    /// Checks the mode and cache lifetime. Most severe first.
    #[must_use]
    pub fn issues(&self) -> Vec<Issue> {
        let mut issues = Vec::new();
        match self.mode {
            Mode::Enforce => {}
            Mode::Testing => issues.push(Issue::new(
                IssueKind::MtaStsTestingMode,
                "MTA-STS policy is in testing mode; TLS failures are not enforced",
            )),
            Mode::None => issues.push(Issue::new(
                IssueKind::MtaStsModeNone,
                "MTA-STS policy mode is none",
            )),
        }
        if self.mode != Mode::None && self.max_age < SHORT_MAX_AGE {
            issues.push(Issue::new(
                IssueKind::MtaStsShortMaxAge,
                format!(
                    "MTA-STS max_age of {} seconds is shorter than a day",
                    self.max_age
                ),
            ));
        }
        sorted(issues)
    }
}

/// `mx` pattern: an optional `*.`, then a host name of letters, digits and
/// hyphens with at least two labels.
fn is_mx_pattern(value: &str) -> bool {
    let host = value.strip_prefix("*.").unwrap_or(value);
    let host = host.strip_suffix('.').unwrap_or(host);
    host.contains('.')
        && host.split('.').all(|label| {
            (1..=63).contains(&label.len())
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
                && !label.starts_with('-')
                && !label.ends_with('-')
        })
}

impl FromStr for MtaStsPolicy {
    type Err = Error;

    fn from_str(text: &str) -> Result<Self, Error> {
        Self::parse(text)
    }
}

impl fmt::Display for MtaStsPolicy {
    /// The policy file, CRLF line endings.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "version: STSv1\r\nmode: {}\r\n", self.mode.as_str())?;
        for mx in &self.mx {
            write!(f, "mx: {mx}\r\n")?;
        }
        write!(f, "max_age: {}\r\n", self.max_age)?;
        for (key, value) in &self.extensions {
            write!(f, "{key}: {value}\r\n")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc_8461_record_and_policy() {
        // RFC 8461 §3.1 and §3.2 examples.
        let record = MtaStsRecord::parse("v=STSv1; id=20160831085700Z;").unwrap();
        assert_eq!(record.id, "20160831085700Z");
        assert_eq!(MtaStsRecord::parse(&record.to_string()).unwrap(), record);

        let policy = MtaStsPolicy::parse(
            "version: STSv1\nmode: enforce\nmx: mail.example.com\nmx: *.example.net\nmx: backupmx.example.com\nmax_age: 604800\n",
        )
        .unwrap();
        assert_eq!(policy.mx.len(), 3);
        assert_eq!(policy.max_age, 604_800);
        assert_eq!(policy.issues().len(), 0);
        assert!(policy.matches_mx("Mail.Example.com."));
        assert!(policy.matches_mx("foo.example.net"));
        assert!(!policy.matches_mx("example.net"));
        assert!(!policy.matches_mx("a.foo.example.net"));
        assert_eq!(MtaStsPolicy::parse(&policy.to_string()).unwrap(), policy);
    }

    #[test]
    fn record_errors_and_find() {
        assert!(matches!(
            MtaStsRecord::parse("v=STSv1;"),
            Err(Error::MissingTag { .. })
        ));
        assert!(matches!(
            MtaStsRecord::parse("v=STSv2; id=1"),
            Err(Error::NotThisRecord { .. })
        ));
        assert!(matches!(
            MtaStsRecord::parse("v=STSv1; id=has-dash"),
            Err(Error::InvalidTag { .. })
        ));
        assert!(matches!(
            MtaStsRecord::parse("v=STSv1; id=1; id=2"),
            Err(Error::DuplicateTag { .. })
        ));
        assert!(matches!(
            MtaStsRecord::parse("v=STSv1;; id=1"),
            Err(Error::Syntax { .. })
        ));
        let ext = MtaStsRecord::parse("v=STSv1; id=1; x-ext.v=ok").unwrap();
        assert_eq!(ext.extensions, [("x-ext.v".to_owned(), "ok".to_owned())]);
        assert!(MtaStsRecord::find(["v=spf1 -all"]).unwrap().is_none());
        assert!(matches!(
            MtaStsRecord::find(["v=STSv1; id=1", "v=STSv1; id=2"]),
            Err(Error::MultipleRecords { count: 2, .. })
        ));
    }

    #[test]
    fn policy_weaknesses() {
        let testing = MtaStsPolicy::parse(
            "version: STSv1\r\nmode: testing\r\nmx: mx.example.com\r\nmax_age: 3600",
        )
        .unwrap();
        let kinds: Vec<_> = testing.issues().iter().map(|i| i.kind).collect();
        assert_eq!(
            kinds,
            [IssueKind::MtaStsTestingMode, IssueKind::MtaStsShortMaxAge]
        );
        let none = MtaStsPolicy::parse("version: STSv1\nmode: none\nmax_age: 0").unwrap();
        let kinds: Vec<_> = none.issues().iter().map(|i| i.kind).collect();
        assert_eq!(kinds, [IssueKind::MtaStsModeNone]);
    }

    #[test]
    fn policy_errors() {
        for (policy, tag) in [
            ("mode: enforce\nmx: a.example\nmax_age: 1", "version"),
            ("version: STSv1\nmx: a.example\nmax_age: 1", "mode"),
            ("version: STSv1\nmode: enforce\nmx: a.example", "max_age"),
            ("version: STSv1\nmode: enforce\nmax_age: 1", "mx"),
            (
                "version: STSv1\nmode: strict\nmx: a.example\nmax_age: 1",
                "mode",
            ),
            (
                "version: STSv1\nmode: enforce\nmx: a.example\nmax_age: 31557601",
                "max_age",
            ),
            ("version: STSv1\nmode: enforce\nmx: *\nmax_age: 1", "mx"),
            (
                "version: STSv1\nmode: enforce\nmode: none\nmx: a.example\nmax_age: 1",
                "mode",
            ),
            ("version: STSv1\nmode enforce", "`:`"),
        ] {
            let error = MtaStsPolicy::parse(policy).unwrap_err();
            assert!(error.to_string().contains(tag), "{policy}: {error}");
        }
        let huge = "a".repeat(MAX_POLICY_LEN + 1);
        assert!(matches!(
            MtaStsPolicy::parse(&huge),
            Err(Error::TooLong { .. })
        ));
    }
}
