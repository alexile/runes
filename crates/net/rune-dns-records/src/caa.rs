//! Certification Authority Authorization ([RFC 8659](https://www.rfc-editor.org/rfc/rfc8659)).
//!
//! Wire-level `CAA` data comes from [`rune_dns_wire::Caa`]; this module
//! gives the property values their meaning, parses and writes the zone-file
//! presentation format, decides whether a CA may issue, and flags weak
//! policies.

use core::fmt;
use core::str::FromStr;

use rune_dns_wire::{Caa, Name};

use crate::error::{Error, RecordKind};
use crate::issue::{Issue, IssueKind, sorted};

const R: RecordKind = RecordKind::Caa;

/// The issuer critical flag (RFC 8659 §4.1).
pub const CRITICAL: u8 = 0x80;

/// The value of an `issue`, `issuewild`, `issuemail` or `issuevmc`
/// property (RFC 8659 §4.2).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct IssuerValue {
    /// The CA's issuer domain name; `None` (a bare `;`) forbids issuance.
    pub issuer: Option<String>,
    /// `tag=value` parameters, in order.
    pub parameters: Vec<(String, String)>,
}

impl IssuerValue {
    /// Parses the value of an issuer property.
    ///
    /// # Errors
    ///
    /// [`Error::Syntax`] for a malformed issuer domain or parameter.
    pub fn parse(value: &[u8]) -> Result<Self, Error> {
        let text = ascii(value)?;
        let wsp = [' ', '\t'];
        let (domain, params) = match text.split_once(';') {
            Some((domain, params)) => (domain.trim_matches(wsp), Some(params)),
            None => (text.trim_matches(wsp), None),
        };
        let issuer = if domain.is_empty() {
            None
        } else if domain.split('.').all(is_label) {
            Some(domain.to_owned())
        } else {
            return Err(Error::syntax(R, text, "invalid issuer domain name"));
        };
        let mut parameters = Vec::new();
        for param in params.into_iter().flat_map(|p| p.split(';')) {
            let param = param.trim_matches(wsp);
            if param.is_empty() {
                continue;
            }
            let Some((tag, value)) = param.split_once('=') else {
                return Err(Error::syntax(R, param, "parameter without `=`"));
            };
            let (tag, value) = (tag.trim_matches(wsp), value.trim_matches(wsp));
            if !is_label(tag) || !value.bytes().all(|b| (0x21..=0x7e).contains(&b)) {
                return Err(Error::syntax(R, param, "invalid parameter"));
            }
            parameters.push((tag.to_owned(), value.to_owned()));
        }
        Ok(Self { issuer, parameters })
    }

    /// The value of parameter `tag` (case-insensitive), if present.
    #[must_use]
    pub fn parameter(&self, tag: &str) -> Option<&str> {
        self.parameters
            .iter()
            .find(|(t, _)| t.eq_ignore_ascii_case(tag))
            .map(|(_, v)| v.as_str())
    }
}

impl fmt::Display for IssuerValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(issuer) = &self.issuer {
            f.write_str(issuer)?;
        }
        if self.parameters.is_empty() {
            if self.issuer.is_none() {
                f.write_str(";")?;
            }
            return Ok(());
        }
        for (tag, value) in &self.parameters {
            write!(f, "; {tag}={value}")?;
        }
        Ok(())
    }
}

/// `(ALPHA / DIGIT) *( *("-") (ALPHA / DIGIT))`.
fn is_label(label: &str) -> bool {
    let bytes = label.as_bytes();
    bytes.first().is_some_and(u8::is_ascii_alphanumeric)
        && bytes.last().is_some_and(u8::is_ascii_alphanumeric)
        && bytes
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || *b == b'-')
}

fn ascii(value: &[u8]) -> Result<&str, Error> {
    core::str::from_utf8(value)
        .ok()
        .filter(|s| s.is_ascii())
        .ok_or_else(|| Error::syntax(R, &String::from_utf8_lossy(value), "non-ASCII value"))
}

/// A CAA property with its value interpreted.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Property {
    /// `issue`: who may issue certificates.
    Issue(IssuerValue),
    /// `issuewild`: who may issue wildcard certificates.
    IssueWild(IssuerValue),
    /// `issuemail`: who may issue S/MIME certificates (RFC 9495).
    IssueMail(IssuerValue),
    /// `issuevmc`: who may issue BIMI mark certificates.
    IssueVmc(IssuerValue),
    /// `iodef`: where to report refused requests (a `mailto:` or `http(s):`
    /// URL).
    Iodef(String),
    /// `contactemail`: a contact address for domain validation.
    ContactEmail(String),
    /// `contactphone`: a contact phone number for domain validation.
    ContactPhone(String),
    /// Any other tag, uninterpreted.
    Other {
        /// The tag, as written.
        tag: String,
        /// The raw value.
        value: Vec<u8>,
    },
}

impl Property {
    /// Interprets `value` for `tag` (matched case-insensitively).
    ///
    /// # Errors
    ///
    /// [`Error::Syntax`] for a tag that is not 1–15 ASCII letters and
    /// digits, or a value that does not fit the tag's grammar.
    pub fn parse(tag: &str, value: &[u8]) -> Result<Self, Error> {
        if !(1..=15).contains(&tag.len()) || !tag.bytes().all(|b| b.is_ascii_alphanumeric()) {
            return Err(Error::syntax(R, tag, "invalid property tag"));
        }
        let text = || ascii(value).map(str::to_owned);
        Ok(match tag.to_ascii_lowercase().as_str() {
            "issue" => Self::Issue(IssuerValue::parse(value)?),
            "issuewild" => Self::IssueWild(IssuerValue::parse(value)?),
            "issuemail" => Self::IssueMail(IssuerValue::parse(value)?),
            "issuevmc" => Self::IssueVmc(IssuerValue::parse(value)?),
            "iodef" => {
                let url = text()?;
                let lower = url.to_ascii_lowercase();
                let ok = ["mailto:", "http://", "https://"]
                    .iter()
                    .any(|s| lower.starts_with(s) && lower.len() > s.len());
                if !ok || url.contains(char::is_whitespace) {
                    return Err(Error::syntax(
                        R,
                        &url,
                        "iodef is not a mailto:, http: or https: URL",
                    ));
                }
                Self::Iodef(url)
            }
            "contactemail" => Self::ContactEmail(text()?),
            "contactphone" => Self::ContactPhone(text()?),
            _ => Self::Other {
                tag: tag.to_owned(),
                value: value.to_vec(),
            },
        })
    }

    /// The tag, lowercase for the known ones.
    #[must_use]
    pub fn tag(&self) -> &str {
        match self {
            Self::Issue(_) => "issue",
            Self::IssueWild(_) => "issuewild",
            Self::IssueMail(_) => "issuemail",
            Self::IssueVmc(_) => "issuevmc",
            Self::Iodef(_) => "iodef",
            Self::ContactEmail(_) => "contactemail",
            Self::ContactPhone(_) => "contactphone",
            Self::Other { tag, .. } => tag,
        }
    }

    /// The value in wire form.
    #[must_use]
    pub fn value(&self) -> Vec<u8> {
        match self {
            Self::Issue(v) | Self::IssueWild(v) | Self::IssueMail(v) | Self::IssueVmc(v) => {
                v.to_string().into_bytes()
            }
            Self::Iodef(s) | Self::ContactEmail(s) | Self::ContactPhone(s) => {
                s.clone().into_bytes()
            }
            Self::Other { value, .. } => value.clone(),
        }
    }
}

/// A CAA record: flags and an interpreted property.
///
/// `FromStr` and `Display` use the zone-file presentation format,
/// `<flags> <tag> "<value>"`.
///
/// ```
/// use rune_dns_records::caa::{CaaRecord, Property};
///
/// let record: CaaRecord = r#"0 issue "letsencrypt.org; validationmethods=dns-01""#.parse()?;
/// let Property::Issue(value) = &record.property else { unreachable!() };
/// assert_eq!(value.issuer.as_deref(), Some("letsencrypt.org"));
/// assert_eq!(value.parameter("validationmethods"), Some("dns-01"));
/// # Ok::<(), rune_dns_records::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CaaRecord {
    /// Flags; bit 7 ([`CRITICAL`]) is "issuer critical".
    pub flags: u8,
    /// The property.
    pub property: Property,
}

impl CaaRecord {
    /// Interprets wire-level CAA data.
    ///
    /// # Errors
    ///
    /// Any error of [`Property::parse`].
    pub fn from_rdata(caa: &Caa) -> Result<Self, Error> {
        Ok(Self {
            flags: caa.flags,
            property: Property::parse(&caa.tag, &caa.value)?,
        })
    }

    /// The wire-level CAA data.
    #[must_use]
    pub fn to_rdata(&self) -> Caa {
        Caa {
            flags: self.flags,
            tag: self.property.tag().to_owned(),
            value: self.property.value(),
        }
    }

    /// Whether the issuer critical flag is set.
    #[must_use]
    pub const fn is_critical(&self) -> bool {
        self.flags & CRITICAL != 0
    }
}

impl FromStr for CaaRecord {
    type Err = Error;

    /// Parses `<flags> <tag> <value>`, the value quoted or a single
    /// unquoted word, with `\X` and `\DDD` escapes.
    fn from_str(text: &str) -> Result<Self, Error> {
        let text = text.trim();
        let mut parts = text.splitn(3, [' ', '\t']);
        let flags = parts
            .next()
            .and_then(|f| f.parse::<u8>().ok())
            .ok_or_else(|| Error::syntax(R, text, "invalid flags"))?;
        let tag = parts
            .next()
            .filter(|t| !t.is_empty())
            .ok_or_else(|| Error::syntax(R, text, "missing tag"))?;
        let value = parts.next().unwrap_or_default().trim_start();
        let value = unquote(value).ok_or_else(|| Error::syntax(R, text, "invalid value string"))?;
        Ok(Self {
            flags,
            property: Property::parse(tag, &value)?,
        })
    }
}

/// Decodes a presentation-format `<character-string>`.
fn unquote(value: &str) -> Option<Vec<u8>> {
    let (body, quoted) = value
        .strip_prefix('"')
        .map_or((value, false), |rest| (rest, true));
    let mut out = Vec::new();
    let mut bytes = body.bytes();
    while let Some(b) = bytes.next() {
        match b {
            b'"' if quoted => return bytes.next().is_none().then_some(out),
            b'\\' => {
                let first = bytes.next()?;
                if first.is_ascii_digit() {
                    let d2 = bytes.next().filter(u8::is_ascii_digit)?;
                    let d3 = bytes.next().filter(u8::is_ascii_digit)?;
                    let n = u16::from(first - b'0') * 100
                        + u16::from(d2 - b'0') * 10
                        + u16::from(d3 - b'0');
                    out.push(u8::try_from(n).ok()?);
                } else {
                    out.push(first);
                }
            }
            b' ' | b'\t' | b'"' if !quoted => return None,
            _ => out.push(b),
        }
    }
    (!quoted).then_some(out)
}

impl fmt::Display for CaaRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {} \"", self.flags, self.property.tag())?;
        for b in self.property.value() {
            match b {
                b'"' | b'\\' => write!(f, "\\{}", char::from(b))?,
                0x20..=0x7e => write!(f, "{}", char::from(b))?,
                _ => write!(f, "\\{b:03}")?,
            }
        }
        f.write_str("\"")
    }
}

/// Whether the CAA `RRset` `rrset` lets the CA identified by `issuer` (its
/// issuer domain name, e.g. `letsencrypt.org`) issue a certificate, a
/// wildcard one if `wildcard` (RFC 8659 §4.2, §4.3).
///
/// An empty `RRset` permits every CA. A critical property with an unknown
/// tag forbids all issuance. For a wildcard, `issuewild` properties apply
/// if there are any, else `issue`. Malformed issuer values match nothing.
///
/// ```
/// use rune_dns_records::caa::{CaaRecord, permits};
///
/// let rrset: Vec<_> = [r#"0 issue "letsencrypt.org""#, r#"0 issuewild ";""#]
///     .iter()
///     .map(|r| r.parse::<CaaRecord>().map(|r| r.to_rdata()))
///     .collect::<Result<_, _>>()?;
/// assert!(permits(&rrset, "letsencrypt.org", false));
/// assert!(!permits(&rrset, "letsencrypt.org", true));
/// assert!(!permits(&rrset, "digicert.com", false));
/// # Ok::<(), rune_dns_records::Error>(())
/// ```
#[must_use]
pub fn permits(rrset: &[Caa], issuer: &str, wildcard: bool) -> bool {
    let parsed: Vec<_> = rrset
        .iter()
        .map(|caa| (caa, CaaRecord::from_rdata(caa)))
        .collect();
    let unknown_critical = parsed.iter().any(|(caa, record)| {
        caa.flags & CRITICAL != 0
            && record.as_ref().map_or(true, |record| {
                matches!(record.property, Property::Other { .. })
            })
    });
    if unknown_critical {
        return false;
    }
    let tag_is = |caa: &Caa, tag: &str| caa.tag.eq_ignore_ascii_case(tag);
    let has_wild = rrset.iter().any(|caa| tag_is(caa, "issuewild"));
    let relevant_tag = if wildcard && has_wild {
        "issuewild"
    } else {
        "issue"
    };
    let mut relevant = parsed
        .iter()
        .filter(|(caa, _)| tag_is(caa, relevant_tag))
        .peekable();
    if relevant.peek().is_none() {
        return true;
    }
    let issuer = issuer.trim_end_matches('.');
    relevant.any(|(_, record)| match record {
        Ok(CaaRecord {
            property: Property::Issue(v) | Property::IssueWild(v),
            ..
        }) => v
            .issuer
            .as_deref()
            .is_some_and(|i| i.eq_ignore_ascii_case(issuer)),
        _ => false,
    })
}

/// The names whose CAA `RRsets` are consulted for `name`, in order: `name`
/// and each ancestor, excluding the root (RFC 8659 §3). The relevant `RRset`
/// is the first non-empty one.
#[must_use]
pub fn search_names(name: &Name) -> Vec<Name> {
    let mut names = Vec::new();
    let mut current = Some(name.clone());
    while let Some(n) = current {
        if n.is_root() {
            break;
        }
        current = n.parent();
        names.push(n);
    }
    names
}

/// Finds the relevant CAA `RRset` for `name` (RFC 8659 §3).
///
/// It climbs from `name` towards the root. `fetch` returns the CAA records at a name (empty for
/// none), which keeps this sans-I/O. Returns the owner and records, or
/// `None` if no ancestor has any.
pub fn relevant_rrset<F>(name: &Name, mut fetch: F) -> Option<(Name, Vec<Caa>)>
where
    F: FnMut(&Name) -> Vec<Caa>,
{
    search_names(name).into_iter().find_map(|n| {
        let rrset = fetch(&n);
        (!rrset.is_empty()).then_some((n, rrset))
    })
}

/// Checks a domain's relevant CAA `RRset`: missing, malformed or blocking
/// records, and the absence of `iodef`. Most severe first.
#[must_use]
pub fn issues(rrset: &[Caa]) -> Vec<Issue> {
    let mut issues = Vec::new();
    if rrset.is_empty() {
        issues.extend(Issue::missing(R));
        return issues;
    }
    let mut iodef = false;
    for caa in rrset {
        let critical = caa.flags & CRITICAL != 0;
        match CaaRecord::from_rdata(caa) {
            Err(error) => {
                let issue = Issue::new(IssueKind::CaaInvalid, error.to_string())
                    .with_evidence(format!("{} {}", caa.flags, caa.tag));
                issues.push(issue);
                if critical {
                    issues.push(
                        Issue::new(
                            IssueKind::CaaUnknownCritical,
                            format!(
                                "malformed critical CAA property {} blocks all issuance",
                                caa.tag
                            ),
                        )
                        .with_evidence(caa.tag.clone()),
                    );
                }
            }
            Ok(record) => {
                iodef |= matches!(record.property, Property::Iodef(_));
                if critical && matches!(record.property, Property::Other { .. }) {
                    issues.push(
                        Issue::new(
                            IssueKind::CaaUnknownCritical,
                            format!(
                                "unknown critical CAA property {} blocks all issuance",
                                caa.tag
                            ),
                        )
                        .with_evidence(record.to_string()),
                    );
                }
            }
        }
    }
    if !iodef {
        issues.push(Issue::new(
            IssueKind::CaaNoIodef,
            "CAA records have no iodef property",
        ));
    }
    sorted(issues)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rrset(records: &[&str]) -> Vec<Caa> {
        records
            .iter()
            .map(|r| r.parse::<CaaRecord>().unwrap().to_rdata())
            .collect()
    }

    #[test]
    fn rfc_8659_examples() {
        // RFC 8659 §4.2 to §4.4.
        let set = rrset(&[
            r#"0 issue "ca1.example.net""#,
            r#"0 issue "ca2.example.org""#,
        ]);
        assert!(permits(&set, "ca1.example.net", false));
        assert!(permits(&set, "CA2.example.org.", true));
        assert!(!permits(&set, "ca3.example.com", false));

        let set = rrset(&[r#"0 issue ";""#]);
        assert!(!permits(&set, "ca1.example.net", false));

        let set = rrset(&[r#"0 issue "ca1.example.net""#, r#"0 issuewild ";""#]);
        assert!(permits(&set, "ca1.example.net", false));
        assert!(!permits(&set, "ca1.example.net", true));

        let set = rrset(&[r#"0 issuewild "ca1.example.net""#]);
        assert!(permits(&set, "any.example", false));
        assert!(permits(&set, "ca1.example.net", true));
        assert!(!permits(&set, "any.example", true));

        let record: CaaRecord = r#"0 issue "ca1.example.net; account=230123""#.parse().unwrap();
        let Property::Issue(value) = &record.property else {
            panic!()
        };
        assert_eq!(value.parameter("account"), Some("230123"));

        let set = rrset(&[
            r#"0 iodef "mailto:security@example.com""#,
            r#"128 tbs "Unknown""#,
        ]);
        assert!(!permits(&set, "ca1.example.net", false));
        let kinds: Vec<_> = issues(&set).iter().map(|i| i.kind).collect();
        assert_eq!(kinds, [IssueKind::CaaUnknownCritical]);

        assert!(permits(&[], "anyone.example", true));
    }

    #[test]
    fn presentation_round_trip() {
        for text in [
            r#"0 issue "letsencrypt.org""#,
            r#"0 issue ";""#,
            r#"0 issue "; policy=ev""#,
            r#"128 issuewild "digicert.com; cansignhttpexchanges=yes""#,
            r#"0 iodef "https://iodef.example.com/""#,
            r#"0 contactemail "domains@example.com""#,
            r#"0 future "with \"quotes\" and \\ and \255""#,
        ] {
            let record: CaaRecord = text.parse().unwrap();
            assert_eq!(record.to_string(), text);
            assert_eq!(CaaRecord::from_rdata(&record.to_rdata()).unwrap(), record);
        }
        let unquoted: CaaRecord = "0 issue letsencrypt.org".parse().unwrap();
        assert_eq!(unquoted.to_string(), r#"0 issue "letsencrypt.org""#);
        let upper: CaaRecord = r#"0 ISSUE "letsencrypt.org""#.parse().unwrap();
        assert!(matches!(upper.property, Property::Issue(_)));
    }

    #[test]
    fn rejects_malformed_values() {
        for text in [
            "x issue \"a.example\"",
            "0",
            "0 issue \"-bad.example\"",
            "0 issue \"a.example; =v\"",
            "0 iodef \"ftp://example.com\"",
            "0 iss_ue \"x\"",
            "0 issue \"unterminated",
            "0 issue \"x\" trailing",
            "0 issue \"\\25\"",
            "0 sixteencharstags \"x\"",
        ] {
            assert!(text.parse::<CaaRecord>().is_err(), "{text}");
        }
    }

    #[test]
    fn weak_policies() {
        let kinds = |set: &[Caa]| issues(set).iter().map(|i| i.kind).collect::<Vec<_>>();
        assert_eq!(kinds(&[]), [IssueKind::CaaMissing]);
        assert_eq!(
            kinds(&rrset(&[r#"0 issue "letsencrypt.org""#])),
            [IssueKind::CaaNoIodef]
        );
        let bad = Caa {
            flags: 0,
            tag: "issue".into(),
            value: b"not a domain!".to_vec(),
        };
        let iodef = rrset(&[r#"0 iodef "mailto:a@example.com""#]);
        let set = [bad, iodef[0].clone()];
        assert_eq!(kinds(&set), [IssueKind::CaaInvalid]);
        assert!(!permits(&set, "letsencrypt.org", false));
    }

    #[test]
    fn climbs_to_the_relevant_rrset() {
        let name: Name = "www.shop.example.com".parse().unwrap();
        let names: Vec<String> = search_names(&name)
            .iter()
            .map(ToString::to_string)
            .collect();
        assert_eq!(
            names,
            [
                "www.shop.example.com",
                "shop.example.com",
                "example.com",
                "com"
            ]
        );
        let found = relevant_rrset(&name, |n| {
            if n.to_string() == "example.com" {
                rrset(&[r#"0 issue "letsencrypt.org""#])
            } else {
                Vec::new()
            }
        });
        assert_eq!(
            found.map(|(n, _)| n.to_string()),
            Some("example.com".to_owned())
        );
        assert!(relevant_rrset(&name, |_| Vec::new()).is_none());
    }
}
