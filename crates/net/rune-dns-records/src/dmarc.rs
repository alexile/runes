//! DMARC policy records ([RFC 7489 §6.3](https://www.rfc-editor.org/rfc/rfc7489#section-6.3)),
//! including `np=` from [RFC 9091](https://www.rfc-editor.org/rfc/rfc9091).

use core::fmt;
use core::str::FromStr;

use crate::error::{Error, RecordKind};
use crate::issue::{Issue, IssueKind, sorted};
use crate::tags;

const R: RecordKind = RecordKind::Dmarc;

/// What a receiver does with failing mail (`p=`, `sp=`, `np=`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Policy {
    /// Deliver as normal; only report.
    None,
    /// Treat as suspicious (spam folder).
    Quarantine,
    /// Reject during the SMTP transaction.
    Reject,
}

impl Policy {
    /// The tag value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Quarantine => "quarantine",
            Self::Reject => "reject",
        }
    }

    fn parse(tag: &str, value: &str) -> Result<Self, Error> {
        match value.to_ascii_lowercase().as_str() {
            "none" => Ok(Self::None),
            "quarantine" => Ok(Self::Quarantine),
            "reject" => Ok(Self::Reject),
            _ => Err(Error::invalid_tag(
                R,
                tag,
                "expected none, quarantine or reject",
            )),
        }
    }
}

/// Identifier alignment mode (`adkim=`, `aspf=`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub enum Alignment {
    /// `r`: organizational domains must match. The default.
    #[default]
    Relaxed,
    /// `s`: domains must be identical.
    Strict,
}

impl Alignment {
    /// The tag value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Relaxed => "r",
            Self::Strict => "s",
        }
    }

    fn parse(tag: &str, value: &str) -> Result<Self, Error> {
        match value {
            "r" | "R" => Ok(Self::Relaxed),
            "s" | "S" => Ok(Self::Strict),
            _ => Err(Error::invalid_tag(R, tag, "expected r or s")),
        }
    }
}

/// One `rua=`/`ruf=` destination: a URI with an optional size limit.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ReportUri {
    /// The URI, e.g. `mailto:dmarc@example.com`.
    pub uri: String,
    /// The `!<size>[k|m|g|t]` limit, as written after `!`.
    pub max_size: Option<String>,
}

impl ReportUri {
    fn parse(tag: &str, item: &str) -> Result<Self, Error> {
        let (uri, max_size) = match item.rsplit_once('!') {
            Some((uri, size)) => {
                let digits = size.trim_end_matches(['k', 'm', 'g', 't', 'K', 'M', 'G', 'T']);
                let suffix = size.len() - digits.len();
                if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) || suffix > 1 {
                    return Err(Error::invalid_tag(R, tag, "invalid size limit"));
                }
                (uri, Some(size.to_owned()))
            }
            None => (item, None),
        };
        let scheme_ok = uri.split_once(':').is_some_and(|(scheme, rest)| {
            !rest.is_empty()
                && scheme
                    .as_bytes()
                    .first()
                    .is_some_and(u8::is_ascii_alphabetic)
                && scheme
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'-' | b'.'))
        });
        if !scheme_ok || uri.contains([' ', '\t', ',']) {
            return Err(Error::invalid_tag(R, tag, "not a URI"));
        }
        Ok(Self {
            uri: uri.to_owned(),
            max_size,
        })
    }

    /// The `mailto:` address, if this is a `mailto:` URI.
    #[must_use]
    pub fn mailto(&self) -> Option<&str> {
        let (scheme, rest) = self.uri.split_once(':')?;
        scheme.eq_ignore_ascii_case("mailto").then_some(rest)
    }
}

impl fmt::Display for ReportUri {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.uri)?;
        self.max_size.as_ref().map_or(Ok(()), |s| write!(f, "!{s}"))
    }
}

/// A parsed DMARC record, published at `_dmarc.<domain>`.
///
/// ```
/// use rune_dns_records::dmarc::{Dmarc, Policy};
///
/// let dmarc: Dmarc = "v=DMARC1; p=none; rua=mailto:dmarc@example.com".parse()?;
/// assert_eq!(dmarc.policy, Policy::None);
/// assert_eq!(dmarc.subdomain_policy(), Policy::None);
/// assert_eq!(dmarc.issues()[0].kind.as_str(), "dmarc_policy_none");
/// # Ok::<(), rune_dns_records::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct Dmarc {
    /// Policy for the domain (`p=`).
    pub policy: Policy,
    /// Policy for subdomains (`sp=`); defaults to `p=`.
    pub sp: Option<Policy>,
    /// Policy for non-existent subdomains (`np=`, RFC 9091); defaults to
    /// `sp=`.
    pub np: Option<Policy>,
    /// DKIM alignment (`adkim=`).
    pub adkim: Option<Alignment>,
    /// SPF alignment (`aspf=`).
    pub aspf: Option<Alignment>,
    /// Percentage of failing mail the policy applies to (`pct=`, 0–100).
    pub pct: Option<u8>,
    /// Aggregate report destinations (`rua=`).
    pub rua: Vec<ReportUri>,
    /// Failure report destinations (`ruf=`).
    pub ruf: Vec<ReportUri>,
    /// Failure reporting options (`fo=`), e.g. `["0"]` or `["1", "d"]`.
    pub fo: Option<Vec<String>>,
    /// Failure report formats (`rf=`).
    pub rf: Option<Vec<String>>,
    /// Aggregate report interval in seconds (`ri=`).
    pub ri: Option<u32>,
    /// Other tags, in order, which receivers ignore.
    pub extensions: Vec<(String, String)>,
}

/// Whether `text` is a DMARC record: it starts with `v=DMARC1` (any case,
/// whitespace allowed around `=`), followed by `;`, whitespace or the end.
#[must_use]
pub fn is_dmarc(text: &str) -> bool {
    let first = text.split(';').next().unwrap_or_default();
    first.split_once('=').is_some_and(|(v, value)| {
        v.trim_matches(tags::is_fws).eq_ignore_ascii_case("v")
            && value
                .trim_matches(tags::is_fws)
                .eq_ignore_ascii_case("DMARC1")
    })
}

impl Dmarc {
    /// Parses a DMARC record.
    ///
    /// # Errors
    ///
    /// [`Error::NotThisRecord`] unless `v=DMARC1` comes first,
    /// [`Error::MissingTag`] without `p=`, [`Error::InvalidTag`] for a
    /// known tag with a bad value, [`Error::Syntax`] or
    /// [`Error::DuplicateTag`] for a malformed tag list.
    pub fn parse(text: &str) -> Result<Self, Error> {
        if !is_dmarc(text) {
            return Err(Error::NotThisRecord {
                record: R,
                reason: "does not start with v=DMARC1",
            });
        }
        let tags = tags::parse(text, R, true)?;
        let mut policy = None;
        let mut record = Self {
            policy: Policy::None,
            sp: None,
            np: None,
            adkim: None,
            aspf: None,
            pct: None,
            rua: Vec::new(),
            ruf: Vec::new(),
            fo: None,
            rf: None,
            ri: None,
            extensions: Vec::new(),
        };
        for tag in tags.iter().skip(1) {
            let value = tag.value;
            match tag.name.to_ascii_lowercase().as_str() {
                "p" => policy = Some(Policy::parse("p", value)?),
                "sp" => record.sp = Some(Policy::parse("sp", value)?),
                "np" => record.np = Some(Policy::parse("np", value)?),
                "adkim" => record.adkim = Some(Alignment::parse("adkim", value)?),
                "aspf" => record.aspf = Some(Alignment::parse("aspf", value)?),
                "pct" => {
                    record.pct = Some(
                        value
                            .parse::<u8>()
                            .ok()
                            .filter(|p| *p <= 100)
                            .ok_or_else(|| Error::invalid_tag(R, "pct", "expected 0 to 100"))?,
                    );
                }
                "rua" => record.rua = uri_list("rua", value)?,
                "ruf" => record.ruf = uri_list("ruf", value)?,
                "fo" => {
                    let fo = colon_list(value);
                    if fo.is_empty()
                        || !fo
                            .iter()
                            .all(|o| matches!(o.as_str(), "0" | "1" | "d" | "s"))
                    {
                        return Err(Error::invalid_tag(R, "fo", "expected 0, 1, d or s"));
                    }
                    record.fo = Some(fo);
                }
                "rf" => {
                    let rf = colon_list(value);
                    if rf.is_empty() {
                        return Err(Error::invalid_tag(R, "rf", "empty format list"));
                    }
                    record.rf = Some(rf);
                }
                "ri" => {
                    record.ri = Some(
                        value
                            .parse()
                            .map_err(|_| Error::invalid_tag(R, "ri", "expected seconds"))?,
                    );
                }
                _ => record
                    .extensions
                    .push((tag.name.to_owned(), value.to_owned())),
            }
        }
        record.policy = policy.ok_or(Error::MissingTag {
            record: R,
            tag: "p",
        })?;
        Ok(record)
    }

    /// Selects and parses the DMARC record among the `TXT` records at
    /// `_dmarc.<domain>`. `Ok(None)` when none starts with `v=DMARC1`.
    ///
    /// # Errors
    ///
    /// [`Error::MultipleRecords`] if more than one does (RFC 7489 §6.6.3),
    /// otherwise any error of [`Dmarc::parse`].
    pub fn find<I, S>(txts: I) -> Result<Option<Self>, Error>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut found = None;
        let mut count = 0;
        for txt in txts {
            if is_dmarc(txt.as_ref()) {
                count += 1;
                found.get_or_insert(txt);
            }
        }
        match (found, count) {
            (None, _) => Ok(None),
            (Some(txt), 1) => Self::parse(txt.as_ref()).map(Some),
            (Some(_), count) => Err(Error::MultipleRecords { record: R, count }),
        }
    }

    /// The effective subdomain policy: `sp=`, else `p=`.
    #[must_use]
    pub fn subdomain_policy(&self) -> Policy {
        self.sp.unwrap_or(self.policy)
    }

    /// The effective policy for non-existent subdomains: `np=`, else the
    /// subdomain policy.
    #[must_use]
    pub fn non_existent_policy(&self) -> Policy {
        self.np.unwrap_or_else(|| self.subdomain_policy())
    }

    /// The effective percentage: `pct=`, else 100.
    #[must_use]
    pub fn percentage(&self) -> u8 {
        self.pct.unwrap_or(100)
    }

    /// Checks the policy strength, coverage and reporting. Most severe
    /// first.
    #[must_use]
    pub fn issues(&self) -> Vec<Issue> {
        let mut issues = Vec::new();
        let record = self.to_string();
        let ev = |issue: Issue| issue.with_evidence(record.clone());
        if self.policy == Policy::None {
            issues.push(ev(Issue::new(
                IssueKind::DmarcPolicyNone,
                "DMARC policy is p=none",
            )));
        } else {
            let weak = [("sp", self.sp), ("np", self.np)]
                .into_iter()
                .filter(|(_, p)| *p == Some(Policy::None))
                .map(|(t, _)| format!("{t}=none"))
                .collect::<Vec<_>>();
            if !weak.is_empty() {
                issues.push(ev(Issue::new(
                    IssueKind::DmarcSubdomainPolicyNone,
                    format!(
                        "DMARC {} exempts subdomains from p={}",
                        weak.join(" and "),
                        self.policy.as_str()
                    ),
                )));
            }
            if self.percentage() < 100 {
                issues.push(ev(Issue::new(
                    IssueKind::DmarcPartialPct,
                    format!(
                        "DMARC policy applies to only {}% of failing mail",
                        self.percentage()
                    ),
                )));
            }
        }
        if self.rua.is_empty() {
            issues.push(ev(Issue::new(
                IssueKind::DmarcNoReporting,
                "DMARC record has no rua= aggregate report destination",
            )));
        }
        sorted(issues)
    }
}

fn uri_list(tag: &str, value: &str) -> Result<Vec<ReportUri>, Error> {
    tags::list(value, ',')
        .map(|item| ReportUri::parse(tag, item))
        .collect()
}

fn colon_list(value: &str) -> Vec<String> {
    tags::list(value, ':')
        .filter(|item| !item.is_empty())
        .map(str::to_owned)
        .collect()
}

impl FromStr for Dmarc {
    type Err = Error;

    fn from_str(text: &str) -> Result<Self, Error> {
        Self::parse(text)
    }
}

impl fmt::Display for Dmarc {
    /// The record with `v` and `p` first, then the other set tags in RFC
    /// order, then extensions.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "v=DMARC1; p={}", self.policy.as_str())?;
        for (tag, policy) in [("sp", self.sp), ("np", self.np)] {
            if let Some(policy) = policy {
                write!(f, "; {tag}={}", policy.as_str())?;
            }
        }
        for (tag, alignment) in [("adkim", self.adkim), ("aspf", self.aspf)] {
            if let Some(alignment) = alignment {
                write!(f, "; {tag}={}", alignment.as_str())?;
            }
        }
        if let Some(pct) = self.pct {
            write!(f, "; pct={pct}")?;
        }
        for (tag, uris) in [("rua", &self.rua), ("ruf", &self.ruf)] {
            if !uris.is_empty() {
                let list: Vec<String> = uris.iter().map(ToString::to_string).collect();
                write!(f, "; {tag}={}", list.join(","))?;
            }
        }
        if let Some(fo) = &self.fo {
            write!(f, "; fo={}", fo.join(":"))?;
        }
        if let Some(rf) = &self.rf {
            write!(f, "; rf={}", rf.join(":"))?;
        }
        if let Some(ri) = self.ri {
            write!(f, "; ri={ri}")?;
        }
        for (tag, value) in &self.extensions {
            write!(f, "; {tag}={value}")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kinds(dmarc: &str) -> Vec<IssueKind> {
        Dmarc::parse(dmarc)
            .unwrap()
            .issues()
            .iter()
            .map(|i| i.kind)
            .collect()
    }

    #[test]
    fn rfc_7489_examples() {
        // RFC 7489 §B.2.1 to §B.2.4.
        let d = Dmarc::parse("v=DMARC1; p=none; rua=mailto:dmarc-feedback@example.com").unwrap();
        assert_eq!(d.rua[0].mailto(), Some("dmarc-feedback@example.com"));
        let d = Dmarc::parse(
            "v=DMARC1; p=none; rua=mailto:dmarc-feedback@example.com; ruf=mailto:auth-reports@thirdparty.example.net",
        )
        .unwrap();
        assert_eq!(d.ruf[0].uri, "mailto:auth-reports@thirdparty.example.net");
        let d = Dmarc::parse(
            "v=DMARC1; p=quarantine; rua=mailto:dmarc-feedback@example.com,mailto:tld-test@thirdparty.example.net!10m; pct=25",
        )
        .unwrap();
        assert_eq!(d.rua[1].max_size.as_deref(), Some("10m"));
        assert_eq!(d.percentage(), 25);
        assert_eq!(Dmarc::parse(&d.to_string()).unwrap(), d);
        let d = Dmarc::parse("v=DMARC1; p=reject; aspf=r; rua=mailto:dmarc-feedback@example.com")
            .unwrap();
        assert_eq!(d.aspf, Some(Alignment::Relaxed));
    }

    #[test]
    fn real_world_records() {
        let d = Dmarc::parse(
            "v=DMARC1; p=reject; sp=reject; adkim=s; aspf=s; fo=1:d; rf=afrf; ri=3600; \
             rua=mailto:a@example.com; ruf=mailto:f@example.com; psd=n",
        )
        .unwrap();
        assert_eq!(d.adkim, Some(Alignment::Strict));
        assert_eq!(d.fo.as_deref(), Some(&["1".to_owned(), "d".to_owned()][..]));
        assert_eq!(d.ri, Some(3600));
        assert_eq!(d.extensions, [("psd".to_owned(), "n".to_owned())]);
        assert_eq!(d.issues().len(), 0);
        assert_eq!(Dmarc::parse(&d.to_string()).unwrap(), d);
        // Upper case and stray separators are common.
        let d = Dmarc::parse("V=DMARC1;P=Reject;;").unwrap();
        assert_eq!(d.policy, Policy::Reject);
    }

    #[test]
    fn weaknesses() {
        assert_eq!(
            kinds("v=DMARC1; p=none"),
            [IssueKind::DmarcPolicyNone, IssueKind::DmarcNoReporting]
        );
        assert_eq!(
            kinds("v=DMARC1; p=reject; sp=none; np=none; pct=50; rua=mailto:a@example.com"),
            [
                IssueKind::DmarcSubdomainPolicyNone,
                IssueKind::DmarcPartialPct
            ]
        );
        assert_eq!(
            kinds("v=DMARC1; p=quarantine; rua=mailto:a@example.com").len(),
            0
        );
    }

    #[test]
    fn effective_policies() {
        let d = Dmarc::parse("v=DMARC1; p=reject; sp=quarantine").unwrap();
        assert_eq!(d.subdomain_policy(), Policy::Quarantine);
        assert_eq!(d.non_existent_policy(), Policy::Quarantine);
        let d = Dmarc::parse("v=DMARC1; p=reject; np=none").unwrap();
        assert_eq!(d.subdomain_policy(), Policy::Reject);
        assert_eq!(d.non_existent_policy(), Policy::None);
    }

    #[test]
    fn rejects_malformed_records() {
        for record in [
            "v=spf1 -all",
            "p=reject; v=DMARC1",
            "v=DMARC1",
            "v=DMARC1; p=block",
            "v=DMARC1; p=none; pct=101",
            "v=DMARC1; p=none; adkim=x",
            "v=DMARC1; p=none; rua=dmarc@example.com",
            "v=DMARC1; p=none; rua=mailto:a@example.com!10x",
            "v=DMARC1; p=none; fo=2",
            "v=DMARC1; p=none; ri=-1",
            "v=DMARC1; p=none; P=reject",
        ] {
            let error = Dmarc::parse(record).unwrap_err();
            assert_eq!(error.record(), RecordKind::Dmarc, "{record}");
        }
    }

    #[test]
    fn find_selects_one_record() {
        assert_eq!(Dmarc::find(["unrelated"]).unwrap(), None);
        assert!(
            Dmarc::find(["v=DMARC1; p=none", "v=spf1 -all"])
                .unwrap()
                .is_some()
        );
        assert!(matches!(
            Dmarc::find(["v=DMARC1; p=none", "v=DMARC1; p=reject"]),
            Err(Error::MultipleRecords { count: 2, .. })
        ));
    }
}
