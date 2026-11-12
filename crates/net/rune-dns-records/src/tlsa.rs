//! DANE `TLSA` records ([RFC 6698](https://www.rfc-editor.org/rfc/rfc6698),
//! usage guidance in [RFC 7671](https://www.rfc-editor.org/rfc/rfc7671)).

use core::fmt;
use core::str::FromStr;

use rune_dns_wire::{Name, Tlsa};
use sha2::{Digest, Sha256, Sha512};

use crate::error::{Error, RecordKind};
use crate::issue::{Issue, IssueKind, sorted};

const R: RecordKind = RecordKind::Tlsa;

macro_rules! tlsa_field {
    ($(#[$meta:meta])* $name:ident { $($(#[$vmeta:meta])* $variant:ident = $value:literal => $mnemonic:literal,)* }) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub enum $name {
            $($(#[$vmeta])* $variant,)*
            /// An unassigned value.
            Other(u8),
        }

        impl $name {
            /// The wire value.
            #[must_use]
            pub const fn value(self) -> u8 {
                match self {
                    $(Self::$variant => $value,)*
                    Self::Other(v) => v,
                }
            }

            /// The IANA mnemonic, e.g. `DANE-EE`, if assigned.
            #[must_use]
            pub const fn mnemonic(self) -> Option<&'static str> {
                match self {
                    $(Self::$variant => Some($mnemonic),)*
                    Self::Other(_) => None,
                }
            }
        }

        impl From<u8> for $name {
            fn from(value: u8) -> Self {
                match value {
                    $($value => Self::$variant,)*
                    other => Self::Other(other),
                }
            }
        }
    };
}

tlsa_field! {
    /// Certificate usage (RFC 6698 §2.1.1, RFC 7218 mnemonics).
    CertUsage {
        /// 0: a CA that must also pass PKIX validation.
        PkixTa = 0 => "PKIX-TA",
        /// 1: the end-entity certificate, which must also pass PKIX
        /// validation.
        PkixEe = 1 => "PKIX-EE",
        /// 2: a trust anchor, no PKIX validation.
        DaneTa = 2 => "DANE-TA",
        /// 3: the end-entity certificate or key, no PKIX validation.
        DaneEe = 3 => "DANE-EE",
    }
}

tlsa_field! {
    /// Which part of the certificate is matched (RFC 6698 §2.1.2).
    Selector {
        /// 0: the whole DER certificate.
        Cert = 0 => "Cert",
        /// 1: the DER `SubjectPublicKeyInfo`.
        Spki = 1 => "SPKI",
    }
}

tlsa_field! {
    /// How the selected data is matched (RFC 6698 §2.1.3).
    MatchingType {
        /// 0: exact match.
        Full = 0 => "Full",
        /// 1: SHA-256 digest.
        Sha256 = 1 => "SHA2-256",
        /// 2: SHA-512 digest.
        Sha512 = 2 => "SHA2-512",
    }
}

impl MatchingType {
    /// The digest length the association data must have, if fixed.
    #[must_use]
    pub const fn digest_len(self) -> Option<usize> {
        match self {
            Self::Sha256 => Some(32),
            Self::Sha512 => Some(64),
            Self::Full | Self::Other(_) => None,
        }
    }
}

/// A TLSA record with its parameters interpreted.
///
/// `FromStr` and `Display` use the presentation format,
/// `<usage> <selector> <matching type> <hex>`.
///
/// ```
/// use rune_dns_records::tlsa::{CertUsage, TlsaRecord};
///
/// let record: TlsaRecord =
///     "3 1 1 0B9FA5A59EED715C26C1020C711B4F6EC42D58B0015E14337A39DAD301C5AFC3".parse()?;
/// assert_eq!(record.usage, CertUsage::DaneEe);
/// assert!(record.issues().is_empty());
/// # Ok::<(), rune_dns_records::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TlsaRecord {
    /// Certificate usage.
    pub usage: CertUsage,
    /// Selector.
    pub selector: Selector,
    /// Matching type.
    pub matching_type: MatchingType,
    /// Certificate association data.
    pub data: Vec<u8>,
}

impl TlsaRecord {
    /// Interprets wire-level TLSA data.
    ///
    /// # Errors
    ///
    /// [`Error::Syntax`] if the data is empty, or its length does not match
    /// a SHA-256 or SHA-512 matching type.
    pub fn from_rdata(tlsa: &Tlsa) -> Result<Self, Error> {
        let record = Self {
            usage: tlsa.usage.into(),
            selector: tlsa.selector.into(),
            matching_type: tlsa.matching_type.into(),
            data: tlsa.data.clone(),
        };
        record.validate()?;
        Ok(record)
    }

    fn validate(&self) -> Result<(), Error> {
        if self.data.is_empty() {
            return Err(Error::syntax(R, &self.header(), "empty association data"));
        }
        match self.matching_type.digest_len() {
            Some(len) if len != self.data.len() => Err(Error::syntax(
                R,
                &self.header(),
                "association data length does not match the digest",
            )),
            _ => Ok(()),
        }
    }

    fn header(&self) -> String {
        format!(
            "{} {} {}",
            self.usage.value(),
            self.selector.value(),
            self.matching_type.value()
        )
    }

    /// The wire-level TLSA data.
    #[must_use]
    pub fn to_rdata(&self) -> Tlsa {
        Tlsa {
            usage: self.usage.value(),
            selector: self.selector.value(),
            matching_type: self.matching_type.value(),
            data: self.data.clone(),
        }
    }

    /// Whether `selected` matches the association data. `selected` is what
    /// [`TlsaRecord::selector`] picks from the presented certificate: the
    /// whole DER certificate, or its DER `SubjectPublicKeyInfo`. Unknown
    /// matching types never match.
    #[must_use]
    pub fn matches(&self, selected: &[u8]) -> bool {
        match self.matching_type {
            MatchingType::Full => self.data == selected,
            MatchingType::Sha256 => self.data[..] == Sha256::digest(selected)[..],
            MatchingType::Sha512 => self.data[..] == Sha512::digest(selected)[..],
            MatchingType::Other(_) => false,
        }
    }

    /// Checks for parameters no client can use. Most severe first.
    #[must_use]
    pub fn issues(&self) -> Vec<Issue> {
        let unknown = [
            ("usage", self.usage.mnemonic().is_none()),
            ("selector", self.selector.mnemonic().is_none()),
            ("matching type", self.matching_type.mnemonic().is_none()),
        ];
        let issues = unknown
            .into_iter()
            .filter(|(_, unknown)| *unknown)
            .map(|(field, _)| {
                Issue::new(
                    IssueKind::TlsaUnusable,
                    format!("TLSA record has an unassigned {field}"),
                )
                .with_evidence(self.header())
            })
            .collect();
        sorted(issues)
    }
}

impl FromStr for TlsaRecord {
    type Err = Error;

    /// Parses `<usage> <selector> <matching type> <hex>`; the hex may be
    /// split by whitespace.
    fn from_str(text: &str) -> Result<Self, Error> {
        let mut parts = text.split_ascii_whitespace();
        let mut field = || {
            parts
                .next()
                .and_then(|p| p.parse::<u8>().ok())
                .ok_or_else(|| Error::syntax(R, text, "expected three numeric fields"))
        };
        let (usage, selector, matching_type) = (field()?, field()?, field()?);
        let hex: String = parts.collect();
        let data =
            rune_hex::decode(&hex).map_err(|_| Error::syntax(R, text, "invalid hex data"))?;
        let record = Self {
            usage: usage.into(),
            selector: selector.into(),
            matching_type: matching_type.into(),
            data,
        };
        record.validate()?;
        Ok(record)
    }
}

impl fmt::Display for TlsaRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {}",
            self.header(),
            rune_hex::encode_upper(&self.data)
        )
    }
}

/// The owner name of TLSA records for a service: `_<port>._<protocol>.<host>`
/// (RFC 6698 §3), e.g. `_25._tcp.mx.example.com`.
///
/// # Errors
///
/// [`Error::Syntax`] if `protocol` is not a valid label or the name would
/// be too long.
pub fn owner_name(port: u16, protocol: &str, host: &Name) -> Result<Name, Error> {
    let valid = !protocol.is_empty()
        && protocol
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-');
    if !valid {
        return Err(Error::syntax(R, protocol, "invalid protocol label"));
    }
    let port_label = format!("_{port}");
    let proto_label = format!("_{protocol}");
    let labels = [port_label.as_bytes(), proto_label.as_bytes()]
        .into_iter()
        .chain(host.labels());
    Name::from_labels(labels).map_err(|_| Error::syntax(R, protocol, "invalid owner name"))
}

/// Checks a TLSA `RRset`: records that do not parse, and parameters no
/// client can use. Most severe first.
#[must_use]
pub fn issues(rrset: &[Tlsa]) -> Vec<Issue> {
    let mut issues = Vec::new();
    for tlsa in rrset {
        match TlsaRecord::from_rdata(tlsa) {
            Ok(record) => issues.extend(record.issues()),
            Err(error) => issues.push(Issue::invalid(&error)),
        }
    }
    sorted(issues)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc_6698_examples() {
        // RFC 6698 §2.3.
        let examples = [
            "0 0 1 d2abde240d7cd3ee6b4b28c54df034b97983a1d16e8a410e4561cb106618e971",
            "1 1 2 92003ba34942dc74152e2f2c408d29eca5a520e7f2e06bb944f4dca346baf63c1b177615d466f6c4b71c216a50292bd58c9ebdd2f74e38fe51ffd48c43326cbc",
            "3 0 0 30820307308201efa003020102020900b1",
        ];
        for text in examples {
            let record: TlsaRecord = text.parse().unwrap();
            assert!(record.issues().is_empty(), "{text}");
            assert_eq!(record.to_string().to_lowercase(), text);
            assert_eq!(TlsaRecord::from_rdata(&record.to_rdata()).unwrap(), record);
        }
        let record: TlsaRecord = examples[0].parse().unwrap();
        assert_eq!(record.usage.mnemonic(), Some("PKIX-TA"));
        assert_eq!(record.matching_type, MatchingType::Sha256);
    }

    #[test]
    fn matches_selected_data() {
        let spki = b"not really a SubjectPublicKeyInfo";
        let sha256 = rune_hex::encode(&Sha256::digest(spki));
        let sha512 = rune_hex::encode(&Sha512::digest(spki));
        let full = rune_hex::encode(spki);
        for (mtype, hex) in [(1, sha256), (2, sha512), (0, full)] {
            let record: TlsaRecord = format!("3 1 {mtype} {hex}").parse().unwrap();
            assert!(record.matches(spki));
            assert!(!record.matches(b"other"));
        }
        let other: TlsaRecord = "3 1 9 00".parse().unwrap();
        assert!(!other.matches(b""));
    }

    #[test]
    fn rejects_mismatched_lengths() {
        assert!("3 1 1 00".parse::<TlsaRecord>().is_err());
        assert!("3 1 2 00".parse::<TlsaRecord>().is_err());
        assert!("3 1 0".parse::<TlsaRecord>().is_err());
        assert!("3 1 x 00".parse::<TlsaRecord>().is_err());
        assert!("3 1 0 0g".parse::<TlsaRecord>().is_err());
        assert!("256 1 0 00".parse::<TlsaRecord>().is_err());
        let bad = Tlsa {
            usage: 3,
            selector: 1,
            matching_type: 1,
            data: vec![0; 31],
        };
        let kinds: Vec<_> = issues(&[bad]).iter().map(|i| i.kind).collect();
        assert_eq!(kinds, [IssueKind::TlsaInvalid]);
    }

    #[test]
    fn unusable_parameters() {
        let record: TlsaRecord = "4 2 0 00".parse().unwrap();
        let issues = record.issues();
        assert_eq!(issues.len(), 2);
        assert!(issues.iter().all(|i| i.kind == IssueKind::TlsaUnusable));
        assert_eq!(CertUsage::from(4), CertUsage::Other(4));
        assert_eq!(CertUsage::Other(4).value(), 4);
    }

    #[test]
    fn owner_names() {
        let host: Name = "mx.example.com".parse().unwrap();
        assert_eq!(
            owner_name(25, "tcp", &host).unwrap().to_string(),
            "_25._tcp.mx.example.com"
        );
        assert!(owner_name(25, "", &host).is_err());
    }
}
