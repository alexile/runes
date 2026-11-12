//! DKIM public key records ([RFC 6376 §3.6.1](https://www.rfc-editor.org/rfc/rfc6376#section-3.6.1)),
//! with [RFC 8301](https://www.rfc-editor.org/rfc/rfc8301) key-size and
//! hash rules and [RFC 8463](https://www.rfc-editor.org/rfc/rfc8463)
//! Ed25519 keys.

use core::fmt;
use core::str::FromStr;

use rune_finding::Severity;

use crate::error::{Error, RecordKind};
use crate::issue::{Issue, IssueKind, sorted};
use crate::tags;

const R: RecordKind = RecordKind::Dkim;

/// The key type, from `k=`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum KeyType {
    /// `rsa`, the default.
    Rsa,
    /// `ed25519` (RFC 8463).
    Ed25519,
    /// Any other value, which verifiers ignore.
    Other(String),
}

impl KeyType {
    /// The `k=` value.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::Rsa => "rsa",
            Self::Ed25519 => "ed25519",
            Self::Other(other) => other,
        }
    }
}

/// A parsed DKIM key record, published at
/// `<selector>._domainkey.<domain>`.
///
/// ```
/// use rune_dns_records::dkim::{DkimKey, KeyType};
///
/// let key: DkimKey = "v=DKIM1; k=ed25519; p=11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=".parse()?;
/// assert_eq!(key.key_type, KeyType::Ed25519);
/// assert!(!key.is_revoked());
/// assert!(key.issues().is_empty());
/// # Ok::<(), rune_dns_records::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct DkimKey {
    /// Acceptable hash algorithms (`h=`); `None` means all.
    pub hash_algorithms: Option<Vec<String>>,
    /// Key type (`k=`), `rsa` by default.
    pub key_type: KeyType,
    /// Notes for humans (`n=`), as written.
    pub notes: Option<String>,
    /// The public key (`p=`), base64-decoded. Empty when revoked.
    pub public_key: Vec<u8>,
    /// Service types (`s=`); `None` means `*`.
    pub service_types: Option<Vec<String>>,
    /// Flags (`t=`): `y` (testing), `s` (strict identity), others.
    pub flags: Vec<String>,
}

impl DkimKey {
    /// Parses a key record.
    ///
    /// # Errors
    ///
    /// [`Error::Syntax`] or [`Error::DuplicateTag`] for a malformed tag
    /// list, [`Error::NotThisRecord`] for a `v=` other than `DKIM1` or not
    /// first, [`Error::MissingTag`] without `p=`, [`Error::InvalidTag`] for
    /// bad base64 in `p=`.
    pub fn parse(text: &str) -> Result<Self, Error> {
        let tags = tags::parse(text, R, false)?;
        let mut key = Self {
            hash_algorithms: None,
            key_type: KeyType::Rsa,
            notes: None,
            public_key: Vec::new(),
            service_types: None,
            flags: Vec::new(),
        };
        let mut has_p = false;
        for (index, tag) in tags.iter().enumerate() {
            match tag.name {
                "v" => {
                    if index != 0 || tag.value != "DKIM1" {
                        return Err(Error::NotThisRecord {
                            record: R,
                            reason: "v= must come first and be DKIM1",
                        });
                    }
                }
                "h" => key.hash_algorithms = Some(colon_list(tag.value)),
                "k" => {
                    key.key_type = match tag.value {
                        "rsa" => KeyType::Rsa,
                        "ed25519" => KeyType::Ed25519,
                        other => KeyType::Other(other.to_owned()),
                    };
                }
                "n" => key.notes = Some(tag.value.to_owned()),
                "p" => {
                    has_p = true;
                    key.public_key = rune_base64::decode(&tags::strip_fws(tag.value))
                        .map_err(|_| Error::invalid_tag(R, "p", "invalid base64"))?;
                }
                "s" => key.service_types = Some(colon_list(tag.value)),
                "t" => key.flags = colon_list(tag.value),
                _ => {}
            }
        }
        if !has_p {
            return Err(Error::MissingTag {
                record: R,
                tag: "p",
            });
        }
        Ok(key)
    }

    /// Whether the key is revoked (`p=` empty).
    #[must_use]
    pub const fn is_revoked(&self) -> bool {
        self.public_key.is_empty()
    }

    /// Whether the domain is testing DKIM (`t=y`).
    #[must_use]
    pub fn is_testing(&self) -> bool {
        self.flags.iter().any(|f| f == "y")
    }

    /// Whether signatures must use the exact domain (`t=s`).
    #[must_use]
    pub fn is_strict(&self) -> bool {
        self.flags.iter().any(|f| f == "s")
    }

    /// Whether `sha256` signatures are accepted.
    #[must_use]
    pub fn allows_sha256(&self) -> bool {
        self.hash_algorithms
            .as_ref()
            .is_none_or(|h| h.iter().any(|a| a == "sha256"))
    }

    /// Length of the RSA modulus in bits, for an RSA key whose `p=` holds a
    /// DER `SubjectPublicKeyInfo` or `RSAPublicKey`. `None` for other key
    /// types, revoked keys and undecodable key data.
    #[must_use]
    pub fn rsa_key_bits(&self) -> Option<usize> {
        if self.key_type != KeyType::Rsa {
            return None;
        }
        rsa_modulus_bits(&self.public_key)
    }

    /// Checks the key: revocation, test mode, key type, key size and hash
    /// algorithms. Most severe first.
    #[must_use]
    pub fn issues(&self) -> Vec<Issue> {
        let mut issues = Vec::new();
        if self.is_revoked() {
            issues.push(Issue::new(
                IssueKind::DkimRevoked,
                "DKIM key is revoked (empty p=)",
            ));
            return issues;
        }
        if self.is_testing() {
            issues.push(Issue::new(
                IssueKind::DkimTestMode,
                "DKIM key is in test mode (t=y); receivers may ignore failures",
            ));
        }
        if !self.allows_sha256() {
            issues.push(Issue::new(
                IssueKind::DkimSha1Only,
                "DKIM key accepts only SHA-1 signatures (RFC 8301 forbids rsa-sha1)",
            ));
        }
        match &self.key_type {
            KeyType::Rsa => match self.rsa_key_bits() {
                None => issues.push(Issue::new(
                    IssueKind::DkimInvalid,
                    "p= is not a DER-encoded RSA public key",
                )),
                Some(bits) if bits < 1024 => issues.push(
                    Issue::new(
                        IssueKind::DkimWeakKey,
                        format!("{bits}-bit RSA key; RFC 8301 requires at least 1024 bits"),
                    )
                    .with_severity(Severity::High),
                ),
                Some(bits) if bits < 2048 => issues.push(Issue::new(
                    IssueKind::DkimWeakKey,
                    format!("{bits}-bit RSA key; 2048 bits are recommended"),
                )),
                Some(_) => {}
            },
            KeyType::Ed25519 => {
                if self.public_key.len() != 32 {
                    issues.push(Issue::new(
                        IssueKind::DkimInvalid,
                        format!(
                            "Ed25519 key of {} bytes; it must be 32",
                            self.public_key.len()
                        ),
                    ));
                }
            }
            KeyType::Other(other) => issues.push(
                Issue::new(
                    IssueKind::DkimUnknownKeyType,
                    format!("unknown DKIM key type k={other}"),
                )
                .with_evidence(other.clone()),
            ),
        }
        sorted(issues)
    }
}

fn colon_list(value: &str) -> Vec<String> {
    tags::list(value, ':')
        .filter(|item| !item.is_empty())
        .map(str::to_owned)
        .collect()
}

impl FromStr for DkimKey {
    type Err = Error;

    fn from_str(text: &str) -> Result<Self, Error> {
        Self::parse(text)
    }
}

impl fmt::Display for DkimKey {
    /// The record in canonical tag order: `v`, `h`, `k`, `n`, `s`, `t`, `p`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("v=DKIM1")?;
        if let Some(h) = &self.hash_algorithms {
            write!(f, "; h={}", h.join(":"))?;
        }
        write!(f, "; k={}", self.key_type.as_str())?;
        if let Some(n) = &self.notes {
            write!(f, "; n={n}")?;
        }
        if let Some(s) = &self.service_types {
            write!(f, "; s={}", s.join(":"))?;
        }
        if !self.flags.is_empty() {
            write!(f, "; t={}", self.flags.join(":"))?;
        }
        write!(f, "; p={}", rune_base64::encode(&self.public_key))
    }
}

/// Reads one DER TLV, returning its tag, contents and the bytes after it.
fn der(input: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&tag, rest) = input.split_first()?;
    let (&first, rest) = rest.split_first()?;
    let (len, rest) = if first < 0x80 {
        (usize::from(first), rest)
    } else {
        let n = usize::from(first & 0x7f);
        if n == 0 || n > 4 || rest.len() < n {
            return None;
        }
        let (bytes, rest) = rest.split_at(n);
        let len = bytes
            .iter()
            .fold(0usize, |acc, &b| (acc << 8) | usize::from(b));
        (len, rest)
    };
    if rest.len() < len {
        return None;
    }
    let (body, rest) = rest.split_at(len);
    Some((tag, body, rest))
}

const SEQUENCE: u8 = 0x30;
const INTEGER: u8 = 0x02;
const BIT_STRING: u8 = 0x03;

/// Modulus bits of a DER `SubjectPublicKeyInfo` holding an RSA key, or of a
/// bare PKCS #1 `RSAPublicKey`.
fn rsa_modulus_bits(key: &[u8]) -> Option<usize> {
    let (tag, body, _) = der(key)?;
    if tag != SEQUENCE {
        return None;
    }
    let (inner_tag, inner, rest) = der(body)?;
    match inner_tag {
        // RSAPublicKey: the first element is the modulus.
        INTEGER => integer_bits(inner),
        // SubjectPublicKeyInfo: AlgorithmIdentifier, then a BIT STRING.
        SEQUENCE => {
            let (bits_tag, bits, _) = der(rest)?;
            let (&unused, pkcs1) = bits.split_first()?;
            if bits_tag != BIT_STRING || unused != 0 {
                return None;
            }
            let (tag, body, _) = der(pkcs1)?;
            let (int_tag, modulus, _) = der(body)?;
            (tag == SEQUENCE && int_tag == INTEGER).then_some(())?;
            integer_bits(modulus)
        }
        _ => None,
    }
}

/// Bits in a big-endian unsigned integer, ignoring leading zeros.
pub(crate) fn integer_bits(bytes: &[u8]) -> Option<usize> {
    let start = bytes.iter().position(|&b| b != 0)?;
    let first = bytes[start];
    Some((bytes.len() - start - 1) * 8 + (8 - first.leading_zeros() as usize))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A 1024-bit RSA key from RFC 6376 Appendix C (`brisbane._domainkey`).
    const RFC6376_KEY: &str = "v=DKIM1; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDwIRP/UC3SBsEmGqZ9ZJW3/DkMoGeLnQg1fWn7/zYtIxN2SnFCjxOCKG9v3b4jYfcTNh5ijSsq631uBItLa7od+v/RtdC2UzJ1lWT947qR+Rcac2gbto/NMqJ0fzfVjH4OuKhitdY9tf6mcwGjaNBcWToIMmPSPDdQPNUYckcQ2QIDAQAB";

    /// Ed25519 key from RFC 8463 Appendix A.2.
    const RFC8463_KEY: &str = "v=DKIM1; k=ed25519; p=11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=";

    #[test]
    fn rfc_6376_appendix_c_key() {
        let key: DkimKey = RFC6376_KEY.parse().unwrap();
        assert_eq!(key.key_type, KeyType::Rsa);
        assert_eq!(key.rsa_key_bits(), Some(1024));
        let issues = key.issues();
        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].kind, IssueKind::DkimWeakKey);
        assert_eq!(issues[0].severity, Severity::Low);
        assert_eq!(DkimKey::parse(&key.to_string()).unwrap(), key);
    }

    #[test]
    fn rfc_8463_ed25519_key() {
        let key: DkimKey = RFC8463_KEY.parse().unwrap();
        assert_eq!(key.public_key.len(), 32);
        assert_eq!(key.rsa_key_bits(), None);
        assert_eq!(key.issues().len(), 0);
    }

    #[test]
    fn pkcs1_key_and_folded_base64() {
        // RSAPublicKey { n = 0x01c1 (9 bits), e = 3 }.
        let der = [0x30, 0x07, 0x02, 0x02, 0x01, 0xc1, 0x02, 0x01, 0x03];
        let p = rune_base64::encode(&der);
        let folded = format!("p={} {}", &p[..4], &p[4..]);
        let key = DkimKey::parse(&folded).unwrap();
        assert_eq!(key.rsa_key_bits(), Some(9));
        assert_eq!(key.issues()[0].severity, Severity::High);
    }

    #[test]
    fn tags_and_flags() {
        let key = DkimKey::parse("v=DKIM1; h=sha1; k=rsa; n=hi there; s=email; t=y:s; p=").unwrap();
        assert!(key.is_revoked());
        assert!(key.is_testing());
        assert!(key.is_strict());
        assert!(!key.allows_sha256());
        assert_eq!(
            key.service_types.as_deref(),
            Some(&["email".to_owned()][..])
        );
        assert_eq!(
            key.issues().iter().map(|i| i.kind).collect::<Vec<_>>(),
            [IssueKind::DkimRevoked]
        );
        let testing = DkimKey::parse(&RFC6376_KEY.replace("p=", "h=sha1; t=y; p=")).unwrap();
        let kinds: Vec<_> = testing.issues().iter().map(|i| i.kind).collect();
        assert_eq!(
            kinds,
            [
                IssueKind::DkimSha1Only,
                IssueKind::DkimTestMode,
                IssueKind::DkimWeakKey
            ]
        );
    }

    #[test]
    fn rejects_bad_records() {
        assert!(matches!(
            DkimKey::parse("k=rsa"),
            Err(Error::MissingTag { tag: "p", .. })
        ));
        assert!(matches!(
            DkimKey::parse("p=; v=DKIM1"),
            Err(Error::NotThisRecord { .. })
        ));
        assert!(matches!(
            DkimKey::parse("v=DKIM2; p="),
            Err(Error::NotThisRecord { .. })
        ));
        assert!(matches!(
            DkimKey::parse("p=!!!"),
            Err(Error::InvalidTag { .. })
        ));
        assert!(matches!(
            DkimKey::parse("p=; p="),
            Err(Error::DuplicateTag { .. })
        ));
    }

    #[test]
    fn undecodable_and_unknown_keys_are_issues() {
        let junk = DkimKey::parse("p=AAAA").unwrap();
        assert_eq!(junk.issues()[0].kind, IssueKind::DkimInvalid);
        let other = DkimKey::parse("k=dsa; p=AAAA").unwrap();
        assert_eq!(other.issues()[0].kind, IssueKind::DkimUnknownKeyType);
        let short = DkimKey::parse("k=ed25519; p=AAAA").unwrap();
        assert_eq!(short.issues()[0].kind, IssueKind::DkimInvalid);
    }

    #[test]
    fn der_rejects_truncation() {
        assert_eq!(rsa_modulus_bits(&[0x30, 0x05, 0x02]), None);
        assert_eq!(
            rsa_modulus_bits(&[0x30, 0x84, 0xff, 0xff, 0xff, 0xff]),
            None
        );
        assert_eq!(rsa_modulus_bits(&[]), None);
        assert_eq!(integer_bits(&[0, 0, 0x80]), Some(8));
        assert_eq!(integer_bits(&[0]), None);
    }
}
