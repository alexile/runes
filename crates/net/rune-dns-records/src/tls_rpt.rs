//! SMTP TLS Reporting records ([RFC 8460 §3](https://www.rfc-editor.org/rfc/rfc8460#section-3)),
//! published at `_smtp._tls.<domain>`.

use core::fmt;
use core::str::FromStr;

use crate::error::{Error, RecordKind};
use crate::mta_sts::{find_one, version_fields};

const R: RecordKind = RecordKind::TlsRpt;

/// A parsed TLS-RPT record.
///
/// ```
/// use rune_dns_records::tls_rpt::TlsRpt;
///
/// let record: TlsRpt = "v=TLSRPTv1; rua=mailto:reports@example.com".parse()?;
/// assert_eq!(record.rua, ["mailto:reports@example.com"]);
/// # Ok::<(), rune_dns_records::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct TlsRpt {
    /// Report destinations: `mailto:` or `https:` URIs.
    pub rua: Vec<String>,
    /// Extension fields, in order.
    pub extensions: Vec<(String, String)>,
}

impl TlsRpt {
    /// Parses the record.
    ///
    /// # Errors
    ///
    /// [`Error::NotThisRecord`] unless it starts with `v=TLSRPTv1`,
    /// [`Error::MissingTag`] without `rua=`, [`Error::InvalidTag`] for a
    /// destination that is not a `mailto:` or `https:` URI,
    /// [`Error::Syntax`] or [`Error::DuplicateTag`] otherwise.
    pub fn parse(text: &str) -> Result<Self, Error> {
        let mut rua = None;
        let mut extensions = Vec::new();
        for (name, value) in version_fields(text, R, "v=TLSRPTv1")? {
            if name == "rua" {
                let uris = value
                    .split(',')
                    .map(|uri| uri.trim_matches([' ', '\t']))
                    .map(|uri| {
                        let ok = ["mailto:", "https://"].iter().any(|scheme| {
                            uri.get(..scheme.len())
                                .is_some_and(|s| s.eq_ignore_ascii_case(scheme))
                                && uri.len() > scheme.len()
                        }) && !uri.contains([' ', '\t']);
                        if ok {
                            Ok(uri.to_owned())
                        } else {
                            Err(Error::invalid_tag(
                                R,
                                "rua",
                                "expected mailto: or https: URIs",
                            ))
                        }
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                rua = Some(uris);
            } else {
                extensions.push((name.to_owned(), value.to_owned()));
            }
        }
        let rua = rua.ok_or(Error::MissingTag {
            record: R,
            tag: "rua",
        })?;
        Ok(Self { rua, extensions })
    }

    /// Selects and parses the record among the `TXT` records at
    /// `_smtp._tls.<domain>`: those starting with `v=TLSRPTv1;`.
    ///
    /// # Errors
    ///
    /// [`Error::MultipleRecords`] if there are several, otherwise any
    /// error of [`TlsRpt::parse`].
    pub fn find<I, S>(txts: I) -> Result<Option<Self>, Error>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        find_one(txts, "v=TLSRPTv1;", R, Self::parse)
    }
}

impl FromStr for TlsRpt {
    type Err = Error;

    fn from_str(text: &str) -> Result<Self, Error> {
        Self::parse(text)
    }
}

impl fmt::Display for TlsRpt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "v=TLSRPTv1; rua={}", self.rua.join(","))?;
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
    fn rfc_8460_examples() {
        // RFC 8460 §3.1.
        let mail = TlsRpt::parse("v=TLSRPTv1;rua=mailto:reports@example.com").unwrap();
        assert_eq!(mail.rua, ["mailto:reports@example.com"]);
        let https =
            TlsRpt::parse("v=TLSRPTv1; rua=https://reporting.example.com/v1/tlsrpt").unwrap();
        assert_eq!(https.rua, ["https://reporting.example.com/v1/tlsrpt"]);
        let both =
            TlsRpt::parse("v=TLSRPTv1; rua=mailto:a@example.com, https://r.example/?k=v;").unwrap();
        assert_eq!(both.rua.len(), 2);
        assert_eq!(TlsRpt::parse(&both.to_string()).unwrap(), both);
    }

    #[test]
    fn errors() {
        assert!(matches!(
            TlsRpt::parse("v=TLSRPTv1"),
            Err(Error::MissingTag { .. })
        ));
        assert!(matches!(
            TlsRpt::parse("v=TLSRPTv2; rua=mailto:a@b"),
            Err(Error::NotThisRecord { .. })
        ));
        assert!(matches!(
            TlsRpt::parse("v=TLSRPTv1; rua=http://insecure.example/"),
            Err(Error::InvalidTag { .. })
        ));
        assert!(matches!(
            TlsRpt::parse("v=TLSRPTv1; rua=mailto:"),
            Err(Error::InvalidTag { .. })
        ));
        assert!(TlsRpt::find(["v=spf1 -all"]).unwrap().is_none());
        assert!(
            TlsRpt::find(["v=TLSRPTv1; rua=mailto:a@example.com"])
                .unwrap()
                .is_some()
        );
    }
}
