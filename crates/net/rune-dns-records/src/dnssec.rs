//! DNSSEC basics for `DS`, `DNSKEY` and `RRSIG` records
//! ([RFC 4034](https://www.rfc-editor.org/rfc/rfc4034)): algorithm
//! recommendations ([RFC 8624](https://www.rfc-editor.org/rfc/rfc8624)),
//! key tags, DS digests, RSA key sizes
//! ([RFC 3110](https://www.rfc-editor.org/rfc/rfc3110)) and signature
//! validity windows.
//!
//! This is not a validator: it does not verify signatures. It checks what a
//! configuration audit can check from the records alone.

use std::collections::BTreeSet;

use rune_dns_wire::{Dnskey, Ds, Name, Rrsig};
use rune_finding::Severity;
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha384};

use crate::dkim::integer_bits;
use crate::issue::{Issue, IssueKind, sorted};

/// `DNSKEY` flag: zone key (RFC 4034 §2.1.1).
pub const FLAG_ZONE: u16 = 0x0100;
/// `DNSKEY` flag: revoked (RFC 5011 §3).
pub const FLAG_REVOKE: u16 = 0x0080;
/// `DNSKEY` flag: secure entry point, i.e. a key-signing key.
pub const FLAG_SEP: u16 = 0x0001;

/// How strongly RFC 8624 recommends an algorithm for signing or for
/// creating DS records.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum Status {
    /// MUST NOT be used.
    MustNot,
    /// NOT RECOMMENDED.
    NotRecommended,
    /// MAY be used.
    May,
    /// RECOMMENDED.
    Recommended,
    /// MUST be implemented.
    Must,
    /// Not listed.
    Unknown,
}

/// A DNSSEC signing algorithm number (IANA "DNS Security Algorithm
/// Numbers").
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Algorithm(pub u8);

impl Algorithm {
    /// 1, `RSAMD5`.
    pub const RSAMD5: Self = Self(1);
    /// 3, `DSA`.
    pub const DSA: Self = Self(3);
    /// 5, `RSASHA1`.
    pub const RSASHA1: Self = Self(5);
    /// 6, `DSA-NSEC3-SHA1`.
    pub const DSA_NSEC3_SHA1: Self = Self(6);
    /// 7, `RSASHA1-NSEC3-SHA1`.
    pub const RSASHA1_NSEC3_SHA1: Self = Self(7);
    /// 8, `RSASHA256`.
    pub const RSASHA256: Self = Self(8);
    /// 10, `RSASHA512`.
    pub const RSASHA512: Self = Self(10);
    /// 12, `ECC-GOST`.
    pub const ECC_GOST: Self = Self(12);
    /// 13, `ECDSAP256SHA256`.
    pub const ECDSAP256SHA256: Self = Self(13);
    /// 14, `ECDSAP384SHA384`.
    pub const ECDSAP384SHA384: Self = Self(14);
    /// 15, `ED25519`.
    pub const ED25519: Self = Self(15);
    /// 16, `ED448`.
    pub const ED448: Self = Self(16);

    /// The IANA mnemonic, if assigned.
    #[must_use]
    pub const fn mnemonic(self) -> Option<&'static str> {
        Some(match self.0 {
            1 => "RSAMD5",
            3 => "DSA",
            5 => "RSASHA1",
            6 => "DSA-NSEC3-SHA1",
            7 => "RSASHA1-NSEC3-SHA1",
            8 => "RSASHA256",
            10 => "RSASHA512",
            12 => "ECC-GOST",
            13 => "ECDSAP256SHA256",
            14 => "ECDSAP384SHA384",
            15 => "ED25519",
            16 => "ED448",
            _ => return None,
        })
    }

    /// The RFC 8624 §3.1 recommendation for signing.
    #[must_use]
    pub const fn signing_status(self) -> Status {
        match self.0 {
            1 | 3 | 6 | 12 => Status::MustNot,
            5 | 7 | 10 => Status::NotRecommended,
            8 | 13 => Status::Must,
            15 => Status::Recommended,
            14 | 16 => Status::May,
            _ => Status::Unknown,
        }
    }

    /// Whether the algorithm signs with a SHA-1 or MD5 digest.
    #[must_use]
    pub const fn uses_weak_hash(self) -> bool {
        matches!(self.0, 1 | 3 | 5 | 6 | 7)
    }

    /// Whether keys of this algorithm are RSA keys in RFC 3110 format.
    #[must_use]
    pub const fn is_rsa(self) -> bool {
        matches!(self.0, 1 | 5 | 7 | 8 | 10)
    }

    /// A display name: the mnemonic, or the number.
    fn label(self) -> String {
        self.mnemonic().map_or_else(
            || format!("algorithm {}", self.0),
            |m| format!("{m} ({})", self.0),
        )
    }
}

/// A DS digest type number.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DigestType(pub u8);

impl DigestType {
    /// 1, SHA-1.
    pub const SHA1: Self = Self(1);
    /// 2, SHA-256.
    pub const SHA256: Self = Self(2);
    /// 3, GOST R 34.11-94.
    pub const GOST: Self = Self(3);
    /// 4, SHA-384.
    pub const SHA384: Self = Self(4);

    /// The RFC 8624 §3.3 recommendation for creating DS records.
    #[must_use]
    pub const fn status(self) -> Status {
        match self.0 {
            1 | 3 => Status::MustNot,
            2 => Status::Must,
            4 => Status::May,
            _ => Status::Unknown,
        }
    }
}

/// The RDATA of `key` in wire form: flags, protocol, algorithm, key.
#[must_use]
pub fn dnskey_rdata(key: &Dnskey) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + key.public_key.len());
    out.extend_from_slice(&key.flags.to_be_bytes());
    out.push(key.protocol);
    out.push(key.algorithm);
    out.extend_from_slice(&key.public_key);
    out
}

/// The key tag of `key` (RFC 4034 Appendix B), which DS and RRSIG records
/// use to refer to it.
#[must_use]
pub fn key_tag(key: &Dnskey) -> u16 {
    if key.algorithm == Algorithm::RSAMD5.0 {
        // Appendix B.1: bits 8..24 of the modulus, counting from the end.
        let k = &key.public_key;
        return match k.len() {
            0..=2 => 0,
            n => u16::from_be_bytes([k[n - 3], k[n - 2]]),
        };
    }
    let mut acc: u32 = 0;
    for (i, &b) in dnskey_rdata(key).iter().enumerate() {
        acc = acc.wrapping_add(if i & 1 == 0 {
            u32::from(b) << 8
        } else {
            u32::from(b)
        });
    }
    acc = acc.wrapping_add((acc >> 16) & 0xffff);
    let [_, _, high, low] = acc.to_be_bytes();
    u16::from_be_bytes([high, low])
}

/// The DS digest of `key` owned by `owner` (RFC 4034 §5.1.4): the digest of
/// the canonical (lowercase) owner name and the DNSKEY RDATA. `None` for a
/// digest type this crate does not compute (GOST, unassigned).
#[must_use]
pub fn ds_digest(owner: &Name, key: &Dnskey, digest_type: DigestType) -> Option<Vec<u8>> {
    let mut input = owner.to_ascii_lowercase().as_wire().to_vec();
    input.extend_from_slice(&dnskey_rdata(key));
    Some(match digest_type {
        DigestType::SHA1 => Sha1::digest(&input).to_vec(),
        DigestType::SHA256 => Sha256::digest(&input).to_vec(),
        DigestType::SHA384 => Sha384::digest(&input).to_vec(),
        _ => return None,
    })
}

/// Whether `ds` refers to `key` owned by `owner`: same key tag and
/// algorithm, and the digest matches. `None` when the digest type cannot be
/// computed.
#[must_use]
pub fn ds_matches(ds: &Ds, owner: &Name, key: &Dnskey) -> Option<bool> {
    let digest = ds_digest(owner, key, DigestType(ds.digest_type))?;
    Some(ds.key_tag == key_tag(key) && ds.algorithm == key.algorithm && ds.digest == digest)
}

/// The modulus length in bits of an RSA `DNSKEY` (RFC 3110 §2), or `None`
/// for other algorithms and malformed keys.
#[must_use]
pub fn rsa_key_bits(key: &Dnskey) -> Option<usize> {
    if !Algorithm(key.algorithm).is_rsa() {
        return None;
    }
    let k = &key.public_key;
    let (&first, rest) = k.split_first()?;
    let (exp_len, rest) = if first == 0 {
        let (len, rest) = rest.split_at_checked(2)?;
        (usize::from(u16::from_be_bytes([len[0], len[1]])), rest)
    } else {
        (usize::from(first), rest)
    };
    let modulus = rest.get(exp_len..)?;
    integer_bits(modulus)
}

/// Where the current time falls in an `RRSIG` validity window.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Validity {
    /// The inception lies in the future.
    NotYetValid {
        /// Seconds until the inception.
        starts_in: u32,
    },
    /// Currently valid.
    Valid {
        /// Seconds until the expiration.
        expires_in: u32,
    },
    /// The expiration has passed.
    Expired {
        /// Seconds since the expiration.
        expired_for: u32,
    },
}

/// Where `now_unix` (seconds since the epoch) falls in the signature's
/// validity window, using RFC 1982 serial number arithmetic as RFC 4034
/// §3.1.5 requires.
#[must_use]
pub const fn signature_validity(rrsig: &Rrsig, now_unix: u64) -> Validity {
    #[allow(
        clippy::cast_possible_truncation,
        reason = "the timestamps are defined modulo 2^32"
    )]
    let now = now_unix as u32;
    let to_inception = rrsig.inception.wrapping_sub(now);
    let to_expiration = rrsig.expiration.wrapping_sub(now);
    if to_inception.cast_signed() > 0 {
        Validity::NotYetValid {
            starts_in: to_inception,
        }
    } else if to_expiration.cast_signed() < 0 {
        Validity::Expired {
            expired_for: now.wrapping_sub(rrsig.expiration),
        }
    } else {
        Validity::Valid {
            expires_in: to_expiration,
        }
    }
}

/// Settings for [`issues`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Options {
    /// Report signatures expiring within this many seconds. Three days by
    /// default.
    pub expiry_warning: u32,
    /// Report RSA keys shorter than this. 2048 by default.
    pub min_rsa_bits: usize,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            expiry_warning: 3 * 86_400,
            min_rsa_bits: 2048,
        }
    }
}

impl Options {
    /// Sets [`Options::expiry_warning`].
    #[must_use]
    pub const fn with_expiry_warning(mut self, seconds: u32) -> Self {
        self.expiry_warning = seconds;
        self
    }

    /// Sets [`Options::min_rsa_bits`].
    #[must_use]
    pub const fn with_min_rsa_bits(mut self, bits: usize) -> Self {
        self.min_rsa_bits = bits;
        self
    }
}

/// Checks a zone's DNSSEC records: `ds` from the parent, the zone's apex
/// `dnskeys` and any `rrsigs` collected from it, at time `now_unix`.
///
/// Reports an unsigned zone, deprecated algorithms and digests, weak or
/// malformed keys, a DS set that matches no key, and expired, not yet
/// valid or soon expiring signatures. Most severe first.
///
/// ```
/// use rune_dns_records::dnssec::{self, Options};
/// use rune_dns_records::IssueKind;
///
/// let zone = "example.com".parse()?;
/// let issues = dnssec::issues(&zone, &[], &[], &[], 0, &Options::default());
/// assert_eq!(issues[0].kind, IssueKind::DnssecMissing);
/// # Ok::<(), rune_dns_wire::Error>(())
/// ```
#[must_use]
pub fn issues(
    zone: &Name,
    ds: &[Ds],
    dnskeys: &[Dnskey],
    rrsigs: &[Rrsig],
    now_unix: u64,
    options: &Options,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    if ds.is_empty() {
        let message = if dnskeys.is_empty() {
            "zone is not DNSSEC-signed".to_owned()
        } else {
            "zone publishes DNSKEYs but the parent has no DS record".to_owned()
        };
        issues.push(Issue::new(IssueKind::DnssecMissing, message).with_evidence(zone.to_string()));
        if dnskeys.is_empty() {
            return issues;
        }
    }

    let algorithms: BTreeSet<Algorithm> = ds
        .iter()
        .map(|d| d.algorithm)
        .chain(dnskeys.iter().map(|k| k.algorithm))
        .chain(rrsigs.iter().map(|s| s.algorithm))
        .map(Algorithm)
        .collect();
    for algorithm in algorithms {
        let status = algorithm.signing_status();
        let issue = |severity| {
            Issue::new(
                IssueKind::DnssecDeprecatedAlgorithm,
                format!(
                    "zone uses {}, which RFC 8624 says {}",
                    algorithm.label(),
                    match status {
                        Status::MustNot => "must not be used",
                        _ => "is not recommended",
                    }
                ),
            )
            .with_severity(severity)
            .with_evidence(algorithm.label())
        };
        match status {
            Status::MustNot => issues.push(issue(Severity::Medium)),
            Status::NotRecommended if algorithm.uses_weak_hash() => {
                issues.push(issue(Severity::Medium));
            }
            Status::NotRecommended => issues.push(issue(Severity::Low)),
            _ => {}
        }
    }

    for d in ds {
        let digest = DigestType(d.digest_type);
        if digest.status() == Status::MustNot {
            issues.push(
                Issue::new(
                    IssueKind::DnssecWeakDigest,
                    format!(
                        "DS {} uses digest type {}, which RFC 8624 says must not be used",
                        d.key_tag, d.digest_type
                    ),
                )
                .with_evidence(format!("{} {} {}", d.key_tag, d.algorithm, d.digest_type)),
            );
        }
    }

    for key in dnskeys {
        let tag = key_tag(key);
        if key.protocol != 3 || key.flags & FLAG_ZONE == 0 {
            issues.push(
                Issue::new(
                    IssueKind::DnssecInvalidKey,
                    format!("DNSKEY {tag} is not a zone key with protocol 3"),
                )
                .with_evidence(format!("{} {} {}", key.flags, key.protocol, key.algorithm)),
            );
            continue;
        }
        if Algorithm(key.algorithm).is_rsa() {
            match rsa_key_bits(key) {
                None => issues.push(Issue::new(
                    IssueKind::DnssecInvalidKey,
                    format!("DNSKEY {tag} has malformed RSA key data"),
                )),
                Some(bits) if bits < 1024 => issues.push(
                    Issue::new(
                        IssueKind::DnssecWeakRsaKey,
                        format!("DNSKEY {tag} is a {bits}-bit RSA key"),
                    )
                    .with_severity(Severity::High),
                ),
                Some(bits) if bits < options.min_rsa_bits => issues.push(Issue::new(
                    IssueKind::DnssecWeakRsaKey,
                    format!("DNSKEY {tag} is a {bits}-bit RSA key"),
                )),
                Some(_) => {}
            }
        }
    }

    if !ds.is_empty() {
        let mut results = ds
            .iter()
            .flat_map(|d| dnskeys.iter().map(move |k| ds_matches(d, zone, k)));
        let checkable = ds
            .iter()
            .any(|d| DigestType(d.digest_type).status() != Status::Unknown)
            && !ds.iter().all(|d| d.digest_type == DigestType::GOST.0);
        if checkable && !results.any(|r| r == Some(true)) {
            let message = if dnskeys.is_empty() {
                "the parent publishes DS records but the zone serves no DNSKEY"
            } else {
                "no DS record at the parent matches a DNSKEY of the zone"
            };
            issues.push(
                Issue::new(IssueKind::DnssecDsMismatch, message).with_evidence(zone.to_string()),
            );
        }
    }

    for sig in rrsigs {
        let what = format!("RRSIG {} by key {}", sig.type_covered, sig.key_tag);
        match signature_validity(sig, now_unix) {
            Validity::Expired { expired_for } => issues.push(Issue::new(
                IssueKind::DnssecSignatureExpired,
                format!("{what} expired {expired_for} seconds ago"),
            )),
            Validity::NotYetValid { starts_in } => issues.push(Issue::new(
                IssueKind::DnssecSignatureNotYetValid,
                format!("{what} becomes valid in {starts_in} seconds"),
            )),
            Validity::Valid { expires_in } if expires_in < options.expiry_warning => {
                issues.push(Issue::new(
                    IssueKind::DnssecSignatureExpiring,
                    format!("{what} expires in {expires_in} seconds"),
                ));
            }
            Validity::Valid { .. } => {}
        }
    }
    sorted(issues)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rune_dns_wire::RecordType;

    /// `dskey.example.com` from RFC 4034 §5.4 and RFC 4509 §2.3.
    fn rfc_key() -> (Name, Dnskey) {
        let key = rune_base64::decode(
            "AQOeiiR0GOMYkDshWoSKz9XzfwJr1AYtsmx3TGkJaNXVbfi/2pHm822aJ5iI9BMzNXxeYCmZDRD99WYwYqUSdjMmmAphXdvxegXd/M5+X7OrzKBaMbCVdFLUUh6DhweJBjEVv5f2wwjM9XzcnOf+EPbtG9DMBmADjFDc2w/rljwvFw==",
        )
        .unwrap();
        let dnskey = Dnskey {
            flags: 256,
            protocol: 3,
            algorithm: 5,
            public_key: key,
        };
        ("dskey.example.com".parse().unwrap(), dnskey)
    }

    #[test]
    fn rfc_4034_key_tag_and_ds_digests() {
        let (owner, key) = rfc_key();
        assert_eq!(key_tag(&key), 60485);
        let sha1 = ds_digest(&owner, &key, DigestType::SHA1).unwrap();
        assert_eq!(
            rune_hex::encode_upper(&sha1),
            "2BB183AF5F22588179A53B0A98631FAD1A292118"
        );
        let sha256 = ds_digest(&owner, &key, DigestType::SHA256).unwrap();
        assert_eq!(
            rune_hex::encode_upper(&sha256),
            "D4B7D520E7BB5F0F67674A0CCEB1E3E0614B93C4F9E99B8383F6A1E4469DA50A"
        );
        // Owner case does not matter.
        let upper: Name = "DSKEY.Example.COM".parse().unwrap();
        let ds = Ds {
            key_tag: 60485,
            algorithm: 5,
            digest_type: 2,
            digest: sha256,
        };
        assert_eq!(ds_matches(&ds, &upper, &key), Some(true));
        let gost = Ds {
            digest_type: 3,
            ..ds
        };
        assert_eq!(ds_matches(&gost, &owner, &key), None);
        assert_eq!(rsa_key_bits(&key), Some(1024));
    }

    #[test]
    fn rsa_key_parsing() {
        // Long exponent-length form: 0, then a 2-byte length.
        let key = Dnskey {
            flags: 257,
            protocol: 3,
            algorithm: 8,
            public_key: [&[0u8, 0, 1, 3][..], &[0xff; 256]].concat(),
        };
        assert_eq!(rsa_key_bits(&key), Some(2048));
        let truncated = Dnskey {
            public_key: vec![5, 1, 0, 1],
            ..key
        };
        assert_eq!(rsa_key_bits(&truncated), None);
        let ecdsa = Dnskey {
            algorithm: 13,
            public_key: vec![1, 3, 0xff],
            ..truncated
        };
        assert_eq!(rsa_key_bits(&ecdsa), None);
    }

    #[test]
    fn algorithm_tables() {
        assert_eq!(Algorithm::ECDSAP256SHA256.signing_status(), Status::Must);
        assert_eq!(Algorithm::RSAMD5.signing_status(), Status::MustNot);
        assert_eq!(Algorithm(200).signing_status(), Status::Unknown);
        assert_eq!(Algorithm::ED25519.mnemonic(), Some("ED25519"));
        assert_eq!(DigestType::SHA1.status(), Status::MustNot);
        assert_eq!(DigestType::SHA256.status(), Status::Must);
    }

    fn rrsig(inception: u32, expiration: u32) -> Rrsig {
        Rrsig {
            type_covered: RecordType::SOA,
            algorithm: 13,
            labels: 2,
            original_ttl: 3600,
            expiration,
            inception,
            key_tag: 1,
            signer_name: "example.com".parse().unwrap(),
            signature: vec![0; 64],
        }
    }

    #[test]
    fn validity_uses_serial_arithmetic() {
        let sig = rrsig(1_000, 2_000);
        assert_eq!(
            signature_validity(&sig, 500),
            Validity::NotYetValid { starts_in: 500 }
        );
        assert_eq!(
            signature_validity(&sig, 1_500),
            Validity::Valid { expires_in: 500 }
        );
        assert_eq!(
            signature_validity(&sig, 2_500),
            Validity::Expired { expired_for: 500 }
        );
        // Across the 2^32 wrap: the window still holds.
        let wrapped = rrsig(u32::MAX - 10, 10);
        assert_eq!(
            signature_validity(&wrapped, (1 << 32) + 5),
            Validity::Valid { expires_in: 5 }
        );
    }

    fn kinds(issues: &[Issue]) -> Vec<IssueKind> {
        issues.iter().map(|i| i.kind).collect()
    }

    #[test]
    fn audit_of_a_weak_zone() {
        let (owner, key) = rfc_key();
        let sha1 = ds_digest(&owner, &key, DigestType::SHA1).unwrap();
        let ds = Ds {
            key_tag: 60485,
            algorithm: 5,
            digest_type: 1,
            digest: sha1,
        };
        let issues = issues(
            &owner,
            &[ds],
            &[key],
            &[rrsig(0, 1_000), rrsig(5_000, 10_000)],
            2_000,
            &Options::default(),
        );
        assert_eq!(
            kinds(&issues),
            [
                IssueKind::DnssecSignatureExpired,
                IssueKind::DnssecSignatureNotYetValid,
                IssueKind::DnssecDeprecatedAlgorithm,
                IssueKind::DnssecWeakDigest,
                IssueKind::DnssecWeakRsaKey,
            ]
        );
    }

    #[test]
    fn audit_of_broken_and_missing_chains() {
        let (owner, key) = rfc_key();
        let wrong = Ds {
            key_tag: 1,
            algorithm: 5,
            digest_type: 2,
            digest: vec![0; 32],
        };
        let opts = Options::default().with_min_rsa_bits(512);
        let found = kinds(&issues(
            &owner,
            core::slice::from_ref(&wrong),
            core::slice::from_ref(&key),
            &[],
            0,
            &opts,
        ));
        assert!(found.contains(&IssueKind::DnssecDsMismatch), "{found:?}");
        let found = kinds(&issues(&owner, &[wrong], &[], &[], 0, &opts));
        assert!(found.contains(&IssueKind::DnssecDsMismatch), "{found:?}");
        let found = kinds(&issues(&owner, &[], &[key], &[], 0, &opts));
        assert!(found.contains(&IssueKind::DnssecMissing), "{found:?}");
        assert_eq!(
            kinds(&issues(&owner, &[], &[], &[], 0, &opts)),
            [IssueKind::DnssecMissing]
        );
    }

    #[test]
    fn audit_of_a_healthy_zone() {
        let owner: Name = "example.com".parse().unwrap();
        let key = Dnskey {
            flags: 257,
            protocol: 3,
            algorithm: 13,
            public_key: vec![7; 64],
        };
        let ds = Ds {
            key_tag: key_tag(&key),
            algorithm: 13,
            digest_type: 2,
            digest: ds_digest(&owner, &key, DigestType::SHA256).unwrap(),
        };
        let sig = rrsig(0, 30 * 86_400);
        let (ds, key) = ([ds], [key]);
        let healthy = issues(
            &owner,
            &ds,
            &key,
            core::slice::from_ref(&sig),
            86_400,
            &Options::default(),
        );
        assert_eq!(healthy.len(), 0, "{healthy:?}");
        let soon = Options::default().with_expiry_warning(30 * 86_400);
        assert_eq!(
            kinds(&issues(&owner, &ds, &key, &[sig], 86_400, &soon)),
            [IssueKind::DnssecSignatureExpiring]
        );
    }
}
