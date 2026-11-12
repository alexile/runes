//! BIMI assertion records
//! ([draft-brand-indicators-for-message-identification](https://datatracker.ietf.org/doc/draft-brand-indicators-for-message-identification/)),
//! published at `<selector>._bimi.<domain>` (usually `default._bimi`).

use core::fmt;
use core::str::FromStr;

use crate::error::{Error, RecordKind};
use crate::issue::{Issue, IssueKind, sorted};
use crate::tags;

const R: RecordKind = RecordKind::Bimi;

/// A parsed BIMI assertion record.
///
/// ```
/// use rune_dns_records::bimi::Bimi;
///
/// let bimi: Bimi = "v=BIMI1; l=https://example.com/logo.svg; a=https://example.com/vmc.pem".parse()?;
/// assert_eq!(bimi.location.as_deref(), Some("https://example.com/logo.svg"));
/// assert!(bimi.issues().is_empty());
/// # Ok::<(), rune_dns_records::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct Bimi {
    /// The SVG logo URI (`l=`); `None` when empty or absent.
    pub location: Option<String>,
    /// The evidence document (VMC/CMC certificate) URI (`a=`); `None` when
    /// empty or absent.
    pub authority: Option<String>,
    /// Other tags, in order.
    pub extensions: Vec<(String, String)>,
}

impl Bimi {
    /// Parses a BIMI record.
    ///
    /// # Errors
    ///
    /// [`Error::NotThisRecord`] unless `v=BIMI1` comes first,
    /// [`Error::InvalidTag`] for an `l=` or `a=` that is not a URI,
    /// [`Error::Syntax`] or [`Error::DuplicateTag`] for a malformed tag
    /// list.
    pub fn parse(text: &str) -> Result<Self, Error> {
        let tags = tags::parse(text, R, true)?;
        let version_ok = tags.first().is_some_and(|t| {
            t.name.eq_ignore_ascii_case("v") && t.value.eq_ignore_ascii_case("BIMI1")
        });
        if !version_ok {
            return Err(Error::NotThisRecord {
                record: R,
                reason: "does not start with v=BIMI1",
            });
        }
        let mut bimi = Self {
            location: None,
            authority: None,
            extensions: Vec::new(),
        };
        for tag in tags.iter().skip(1) {
            match tag.name.to_ascii_lowercase().as_str() {
                "l" => bimi.location = uri("l", tag.value)?,
                "a" => bimi.authority = uri("a", tag.value)?,
                _ => bimi
                    .extensions
                    .push((tag.name.to_owned(), tag.value.to_owned())),
            }
        }
        Ok(bimi)
    }

    /// Selects and parses the BIMI record among `TXT` records.
    ///
    /// # Errors
    ///
    /// [`Error::MultipleRecords`] if several start with `v=BIMI1`,
    /// otherwise any error of [`Bimi::parse`].
    pub fn find<I, S>(txts: I) -> Result<Option<Self>, Error>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let is_bimi = |t: &str| {
            t.split(';')
                .next()
                .and_then(|v| v.split_once('='))
                .is_some_and(|(n, v)| {
                    n.trim_matches(tags::is_fws).eq_ignore_ascii_case("v")
                        && v.trim_matches(tags::is_fws).eq_ignore_ascii_case("BIMI1")
                })
        };
        let matching: Vec<S> = txts.into_iter().filter(|t| is_bimi(t.as_ref())).collect();
        match matching.as_slice() {
            [] => Ok(None),
            [one] => Self::parse(one.as_ref()).map(Some),
            more => Err(Error::MultipleRecords {
                record: R,
                count: more.len(),
            }),
        }
    }

    /// Whether this is a declination record: the domain opts out of BIMI
    /// (`l=` and `a=` both empty).
    #[must_use]
    pub const fn is_declination(&self) -> bool {
        self.location.is_none() && self.authority.is_none()
    }

    /// Checks transport security and evidence. Most severe first.
    #[must_use]
    pub fn issues(&self) -> Vec<Issue> {
        let mut issues = Vec::new();
        if self.is_declination() {
            return issues;
        }
        for uri in [&self.location, &self.authority].into_iter().flatten() {
            if !is_https(uri) {
                issues.push(
                    Issue::new(
                        IssueKind::BimiInsecureUri,
                        format!("BIMI URI {uri} is not https"),
                    )
                    .with_evidence(uri.clone()),
                );
            }
        }
        if self.authority.is_none() {
            issues.push(Issue::new(
                IssueKind::BimiNoAuthority,
                "BIMI record has no a= evidence document (VMC or CMC)",
            ));
        }
        sorted(issues)
    }
}

fn is_https(uri: &str) -> bool {
    uri.get(..8)
        .is_some_and(|s| s.eq_ignore_ascii_case("https://"))
        && uri.len() > 8
}

/// An optional URI tag value: empty means absent.
fn uri(tag: &str, value: &str) -> Result<Option<String>, Error> {
    if value.is_empty() {
        return Ok(None);
    }
    let ok = value.split_once(':').is_some_and(|(scheme, rest)| {
        !rest.is_empty()
            && scheme
                .as_bytes()
                .first()
                .is_some_and(u8::is_ascii_alphabetic)
            && scheme
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'-' | b'.'))
    }) && !value.contains(char::is_whitespace);
    if ok {
        Ok(Some(value.to_owned()))
    } else {
        Err(Error::invalid_tag(R, tag, "not a URI"))
    }
}

impl FromStr for Bimi {
    type Err = Error;

    fn from_str(text: &str) -> Result<Self, Error> {
        Self::parse(text)
    }
}

impl fmt::Display for Bimi {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "v=BIMI1; l={}; a={}",
            self.location.as_deref().unwrap_or_default(),
            self.authority.as_deref().unwrap_or_default()
        )?;
        for (name, value) in &self.extensions {
            write!(f, "; {name}={value}")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_records() {
        let bimi = Bimi::parse("v=BIMI1; l=https://example.com/logo.svg;").unwrap();
        assert_eq!(bimi.authority, None);
        let kinds: Vec<_> = bimi.issues().iter().map(|i| i.kind).collect();
        assert_eq!(kinds, [IssueKind::BimiNoAuthority]);
        assert_eq!(Bimi::parse(&bimi.to_string()).unwrap(), bimi);

        let declined = Bimi::parse("v=BIMI1; l=; a=;").unwrap();
        assert!(declined.is_declination());
        assert_eq!(declined.issues().len(), 0);

        let insecure =
            Bimi::parse("v=BIMI1; l=http://example.com/logo.svg; a=https://example.com/a.pem")
                .unwrap();
        let kinds: Vec<_> = insecure.issues().iter().map(|i| i.kind).collect();
        assert_eq!(kinds, [IssueKind::BimiInsecureUri]);
    }

    #[test]
    fn errors_and_find() {
        assert!(matches!(
            Bimi::parse("l=https://x.example/"),
            Err(Error::NotThisRecord { .. })
        ));
        assert!(matches!(
            Bimi::parse("v=BIMI2"),
            Err(Error::NotThisRecord { .. })
        ));
        assert!(matches!(
            Bimi::parse("v=BIMI1; l=logo.svg"),
            Err(Error::InvalidTag { .. })
        ));
        assert!(Bimi::find(["v=spf1 -all"]).unwrap().is_none());
        assert!(Bimi::find(["v=BIMI1; l=;", "v=spf1"]).unwrap().is_some());
        assert!(matches!(
            Bimi::find(["v=BIMI1;", "v=BIMI1; l="]),
            Err(Error::MultipleRecords { count: 2, .. })
        ));
    }
}
