//! Record data (RDATA) for the record types this crate understands.

use core::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};

use crate::Error;
use crate::name::Name;
use crate::types::RecordType;
use crate::wire::{Reader, Writer};

/// `MX` data (RFC 1035 §3.3.9).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Mx {
    /// Lower is preferred.
    pub preference: u16,
    /// The mail exchanger.
    pub exchange: Name,
}

/// `SOA` data (RFC 1035 §3.3.13).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Soa {
    /// Primary name server.
    pub mname: Name,
    /// Mailbox of the person responsible, as a name.
    pub rname: Name,
    /// Zone serial number.
    pub serial: u32,
    /// Seconds between secondary refreshes.
    pub refresh: u32,
    /// Seconds between retries of a failed refresh.
    pub retry: u32,
    /// Seconds after which a secondary stops answering.
    pub expire: u32,
    /// Negative caching TTL (RFC 2308).
    pub minimum: u32,
}

/// `SRV` data (RFC 2782).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Srv {
    /// Lower is preferred.
    pub priority: u16,
    /// Relative weight among records of equal priority.
    pub weight: u16,
    /// Port of the service.
    pub port: u16,
    /// Host providing the service; `.` means "not available".
    pub target: Name,
}

/// `CAA` data (RFC 8659).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Caa {
    /// Flags; bit 7 (`128`) is "issuer critical".
    pub flags: u8,
    /// Property tag, 1 to 15 ASCII letters and digits (`issue`,
    /// `issuewild`, `iodef`, ...).
    pub tag: String,
    /// Property value.
    pub value: Vec<u8>,
}

/// `TLSA` data (RFC 6698).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Tlsa {
    /// Certificate usage.
    pub usage: u8,
    /// Selector: full certificate or public key.
    pub selector: u8,
    /// Matching type: exact, SHA-256 or SHA-512.
    pub matching_type: u8,
    /// Certificate association data.
    pub data: Vec<u8>,
}

/// `DS` data (RFC 4034 §5).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Ds {
    /// Key tag of the referenced `DNSKEY`.
    pub key_tag: u16,
    /// Algorithm of the referenced `DNSKEY`.
    pub algorithm: u8,
    /// Digest algorithm.
    pub digest_type: u8,
    /// Digest of the referenced `DNSKEY`.
    pub digest: Vec<u8>,
}

/// `DNSKEY` data (RFC 4034 §2).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Dnskey {
    /// Flags; `256` is a zone key, `257` a zone key with SEP set.
    pub flags: u16,
    /// Always 3.
    pub protocol: u8,
    /// Public key algorithm.
    pub algorithm: u8,
    /// Public key material.
    pub public_key: Vec<u8>,
}

/// `RRSIG` data (RFC 4034 §3).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Rrsig {
    /// Type of the `RRset` this signature covers.
    pub type_covered: RecordType,
    /// Signature algorithm.
    pub algorithm: u8,
    /// Number of labels in the original owner name.
    pub labels: u8,
    /// TTL of the covered `RRset` as signed.
    pub original_ttl: u32,
    /// Expiration, seconds since the epoch modulo 2³² (RFC 1982).
    pub expiration: u32,
    /// Inception, seconds since the epoch modulo 2³².
    pub inception: u32,
    /// Key tag of the signing `DNSKEY`.
    pub key_tag: u16,
    /// Owner of the signing `DNSKEY` (never compressed).
    pub signer_name: Name,
    /// The signature.
    pub signature: Vec<u8>,
}

/// The data of a resource record.
///
/// Types this crate does not model are kept as [`RData::Unknown`]. Use that
/// variant only for such types: a known type written as `Unknown` encodes,
/// but decodes back as its typed variant (or fails if the bytes do not fit
/// the type's layout).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum RData {
    /// IPv4 address.
    A(Ipv4Addr),
    /// IPv6 address.
    Aaaa(Ipv6Addr),
    /// Authoritative name server.
    Ns(Name),
    /// Canonical name.
    Cname(Name),
    /// Domain name pointer.
    Ptr(Name),
    /// Mail exchange.
    Mx(Mx),
    /// Text: one or more `<character-string>`s of up to 255 octets each.
    Txt(Vec<Vec<u8>>),
    /// Start of authority.
    Soa(Soa),
    /// Service locator.
    Srv(Srv),
    /// Certification authority authorization.
    Caa(Caa),
    /// TLS certificate association.
    Tlsa(Tlsa),
    /// Delegation signer.
    Ds(Ds),
    /// DNSSEC public key.
    Dnskey(Dnskey),
    /// DNSSEC signature.
    Rrsig(Rrsig),
    /// Any other type, as opaque bytes (RFC 3597).
    Unknown {
        /// The record type.
        rtype: RecordType,
        /// The RDATA.
        data: Vec<u8>,
    },
}

impl RData {
    /// `TXT` data holding `text`, split into 255-octet strings. Empty text
    /// gives one empty string.
    #[must_use]
    pub fn txt(text: impl AsRef<[u8]>) -> Self {
        let text = text.as_ref();
        if text.is_empty() {
            return Self::Txt(vec![Vec::new()]);
        }
        Self::Txt(text.chunks(255).map(<[u8]>::to_vec).collect())
    }

    /// The record type of this data.
    #[must_use]
    pub const fn rtype(&self) -> RecordType {
        match self {
            Self::A(_) => RecordType::A,
            Self::Aaaa(_) => RecordType::AAAA,
            Self::Ns(_) => RecordType::NS,
            Self::Cname(_) => RecordType::CNAME,
            Self::Ptr(_) => RecordType::PTR,
            Self::Mx(_) => RecordType::MX,
            Self::Txt(_) => RecordType::TXT,
            Self::Soa(_) => RecordType::SOA,
            Self::Srv(_) => RecordType::SRV,
            Self::Caa(_) => RecordType::CAA,
            Self::Tlsa(_) => RecordType::TLSA,
            Self::Ds(_) => RecordType::DS,
            Self::Dnskey(_) => RecordType::DNSKEY,
            Self::Rrsig(_) => RecordType::RRSIG,
            Self::Unknown { rtype, .. } => *rtype,
        }
    }

    /// Decodes the RDATA of type `rtype` from `reader`, which spans exactly
    /// the RDATA.
    pub fn decode(rtype: RecordType, reader: &mut Reader<'_>) -> Result<Self, Error> {
        let data = match rtype {
            RecordType::A => Self::A(Ipv4Addr::from(reader.array::<4>()?)),
            RecordType::AAAA => Self::Aaaa(Ipv6Addr::from(reader.array::<16>()?)),
            RecordType::NS => Self::Ns(reader.name()?),
            RecordType::CNAME => Self::Cname(reader.name()?),
            RecordType::PTR => Self::Ptr(reader.name()?),
            RecordType::MX => Self::Mx(Mx {
                preference: reader.u16()?,
                exchange: reader.name()?,
            }),
            RecordType::TXT => {
                let mut strings = Vec::new();
                while reader.remaining() > 0 {
                    strings.push(reader.character_string()?.to_vec());
                }
                Self::Txt(strings)
            }
            RecordType::SOA => Self::Soa(Soa {
                mname: reader.name()?,
                rname: reader.name()?,
                serial: reader.u32()?,
                refresh: reader.u32()?,
                retry: reader.u32()?,
                expire: reader.u32()?,
                minimum: reader.u32()?,
            }),
            RecordType::SRV => Self::Srv(Srv {
                priority: reader.u16()?,
                weight: reader.u16()?,
                port: reader.u16()?,
                target: reader.name()?,
            }),
            RecordType::CAA => {
                let flags = reader.u8()?;
                let tag = reader.character_string()?;
                let tag = caa_tag(tag)?.to_owned();
                Self::Caa(Caa {
                    flags,
                    tag,
                    value: reader.rest()?.to_vec(),
                })
            }
            RecordType::TLSA => Self::Tlsa(Tlsa {
                usage: reader.u8()?,
                selector: reader.u8()?,
                matching_type: reader.u8()?,
                data: reader.rest()?.to_vec(),
            }),
            RecordType::DS => Self::Ds(Ds {
                key_tag: reader.u16()?,
                algorithm: reader.u8()?,
                digest_type: reader.u8()?,
                digest: reader.rest()?.to_vec(),
            }),
            RecordType::DNSKEY => Self::Dnskey(Dnskey {
                flags: reader.u16()?,
                protocol: reader.u8()?,
                algorithm: reader.u8()?,
                public_key: reader.rest()?.to_vec(),
            }),
            RecordType::RRSIG => Self::Rrsig(Rrsig {
                type_covered: RecordType(reader.u16()?),
                algorithm: reader.u8()?,
                labels: reader.u8()?,
                original_ttl: reader.u32()?,
                expiration: reader.u32()?,
                inception: reader.u32()?,
                key_tag: reader.u16()?,
                signer_name: reader.name()?,
                signature: reader.rest()?.to_vec(),
            }),
            RecordType::OPT => {
                return Err(Error::InvalidOpt {
                    reason: "OPT outside the additional section",
                });
            }
            _ => Self::Unknown {
                rtype,
                data: reader.rest()?.to_vec(),
            },
        };
        if reader.remaining() > 0 {
            return Err(Error::InvalidRdata {
                rtype,
                reason: "longer than its fields",
            });
        }
        Ok(data)
    }

    /// Writes the RDATA (without its length prefix). Names are compressed
    /// only in the RFC 1035 types, as RFC 3597 §4 requires.
    pub fn encode(&self, writer: &mut Writer) -> Result<(), Error> {
        match self {
            Self::A(addr) => writer.bytes(&addr.octets()),
            Self::Aaaa(addr) => writer.bytes(&addr.octets()),
            Self::Ns(name) | Self::Cname(name) | Self::Ptr(name) => writer.name(name, true),
            Self::Mx(mx) => {
                writer.u16(mx.preference);
                writer.name(&mx.exchange, true);
            }
            Self::Txt(strings) => {
                for string in strings {
                    writer.character_string(string)?;
                }
            }
            Self::Soa(soa) => {
                writer.name(&soa.mname, true);
                writer.name(&soa.rname, true);
                for value in [soa.serial, soa.refresh, soa.retry, soa.expire, soa.minimum] {
                    writer.u32(value);
                }
            }
            Self::Srv(srv) => {
                writer.u16(srv.priority);
                writer.u16(srv.weight);
                writer.u16(srv.port);
                writer.name(&srv.target, false);
            }
            Self::Caa(caa) => {
                writer.u8(caa.flags);
                writer.character_string(caa_tag(caa.tag.as_bytes())?.as_bytes())?;
                writer.bytes(&caa.value);
            }
            Self::Tlsa(tlsa) => {
                writer.u8(tlsa.usage);
                writer.u8(tlsa.selector);
                writer.u8(tlsa.matching_type);
                writer.bytes(&tlsa.data);
            }
            Self::Ds(ds) => {
                writer.u16(ds.key_tag);
                writer.u8(ds.algorithm);
                writer.u8(ds.digest_type);
                writer.bytes(&ds.digest);
            }
            Self::Dnskey(key) => {
                writer.u16(key.flags);
                writer.u8(key.protocol);
                writer.u8(key.algorithm);
                writer.bytes(&key.public_key);
            }
            Self::Rrsig(sig) => {
                writer.u16(sig.type_covered.0);
                writer.u8(sig.algorithm);
                writer.u8(sig.labels);
                writer.u32(sig.original_ttl);
                writer.u32(sig.expiration);
                writer.u32(sig.inception);
                writer.u16(sig.key_tag);
                writer.name(&sig.signer_name, false);
                writer.bytes(&sig.signature);
            }
            Self::Unknown { rtype, data } => {
                if *rtype == RecordType::OPT {
                    return Err(Error::InvalidOpt {
                        reason: "set Message::edns instead of writing an OPT record",
                    });
                }
                writer.bytes(data);
            }
        }
        Ok(())
    }
}

/// Checks a CAA tag: 1 to 15 ASCII letters and digits (RFC 8659 §4.1).
fn caa_tag(tag: &[u8]) -> Result<&str, Error> {
    let valid = (1..=15).contains(&tag.len()) && tag.iter().all(u8::is_ascii_alphanumeric);
    core::str::from_utf8(tag)
        .ok()
        .filter(|_| valid)
        .ok_or(Error::InvalidRdata {
            rtype: RecordType::CAA,
            reason: "tag is not 1 to 15 ASCII letters and digits",
        })
}

/// Writes `bytes` as a quoted `<character-string>` (RFC 1035 §5.1).
fn quoted(f: &mut fmt::Formatter<'_>, bytes: &[u8]) -> fmt::Result {
    f.write_str("\"")?;
    for &byte in bytes {
        match byte {
            b'"' | b'\\' => write!(f, "\\{}", char::from(byte))?,
            0x20..=0x7e => write!(f, "{}", char::from(byte))?,
            _ => write!(f, "\\{byte:03}")?,
        }
    }
    f.write_str("\"")
}

/// Upper-case hex, or `-` when empty (RFC 6698 uses hex; empty is unusual).
fn hex(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return "-".to_owned();
    }
    rune_hex::encode_upper(bytes)
}

/// Presentation format (RFC 1035 §5.1 and each type's RFC). Unknown types
/// use the RFC 3597 `\# <length> <hex>` form. Names are printed without the
/// trailing dot, like [`Name`]'s `Display`.
impl fmt::Display for RData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::A(addr) => write!(f, "{addr}"),
            Self::Aaaa(addr) => write!(f, "{addr}"),
            Self::Ns(name) | Self::Cname(name) | Self::Ptr(name) => write!(f, "{name}"),
            Self::Mx(mx) => write!(f, "{} {}", mx.preference, mx.exchange),
            Self::Txt(strings) => {
                for (index, string) in strings.iter().enumerate() {
                    if index > 0 {
                        f.write_str(" ")?;
                    }
                    quoted(f, string)?;
                }
                Ok(())
            }
            Self::Soa(soa) => write!(
                f,
                "{} {} {} {} {} {} {}",
                soa.mname, soa.rname, soa.serial, soa.refresh, soa.retry, soa.expire, soa.minimum
            ),
            Self::Srv(srv) => write!(
                f,
                "{} {} {} {}",
                srv.priority, srv.weight, srv.port, srv.target
            ),
            Self::Caa(caa) => {
                write!(f, "{} {} ", caa.flags, caa.tag)?;
                quoted(f, &caa.value)
            }
            Self::Tlsa(tlsa) => write!(
                f,
                "{} {} {} {}",
                tlsa.usage,
                tlsa.selector,
                tlsa.matching_type,
                hex(&tlsa.data)
            ),
            Self::Ds(ds) => write!(
                f,
                "{} {} {} {}",
                ds.key_tag,
                ds.algorithm,
                ds.digest_type,
                hex(&ds.digest)
            ),
            Self::Dnskey(key) => write!(
                f,
                "{} {} {} {}",
                key.flags,
                key.protocol,
                key.algorithm,
                rune_base64::encode(&key.public_key)
            ),
            Self::Rrsig(sig) => write!(
                f,
                "{} {} {} {} {} {} {} {} {}",
                sig.type_covered,
                sig.algorithm,
                sig.labels,
                sig.original_ttl,
                sig.expiration,
                sig.inception,
                sig.key_tag,
                sig.signer_name,
                rune_base64::encode(&sig.signature)
            ),
            Self::Unknown { data, .. } if data.is_empty() => f.write_str("\\# 0"),
            Self::Unknown { data, .. } => {
                write!(f, "\\# {} {}", data.len(), rune_hex::encode_upper(data))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn txt_splits_long_text() {
        let RData::Txt(strings) = RData::txt("x".repeat(600)) else {
            unreachable!()
        };
        assert_eq!(
            strings.iter().map(Vec::len).collect::<Vec<_>>(),
            [255, 255, 90]
        );
        assert_eq!(RData::txt(""), RData::Txt(vec![Vec::new()]));
    }

    #[test]
    fn presentation_format() {
        let name = |text: &str| Name::from_ascii(text).unwrap();
        let cases = [
            (RData::A(Ipv4Addr::new(192, 0, 2, 1)), "192.0.2.1"),
            (
                RData::Mx(Mx {
                    preference: 10,
                    exchange: name("mail.example"),
                }),
                "10 mail.example",
            ),
            (
                RData::Txt(vec![b"v=spf1 -all".to_vec(), b"a\"b\\\x01".to_vec()]),
                "\"v=spf1 -all\" \"a\\\"b\\\\\\001\"",
            ),
            (
                RData::Caa(Caa {
                    flags: 0,
                    tag: "issue".into(),
                    value: b"letsencrypt.org".to_vec(),
                }),
                "0 issue \"letsencrypt.org\"",
            ),
            (
                RData::Ds(Ds {
                    key_tag: 370,
                    algorithm: 13,
                    digest_type: 2,
                    digest: vec![0xab, 0x01],
                }),
                "370 13 2 AB01",
            ),
            (
                RData::Unknown {
                    rtype: RecordType(65_280),
                    data: vec![0x0a, 0xff],
                },
                "\\# 2 0AFF",
            ),
            (
                RData::Unknown {
                    rtype: RecordType(65_280),
                    data: vec![],
                },
                "\\# 0",
            ),
        ];
        for (data, text) in cases {
            assert_eq!(data.to_string(), text);
        }
    }

    #[test]
    fn caa_tag_rules() {
        assert!(caa_tag(b"issue").is_ok());
        assert!(caa_tag(b"").is_err());
        assert!(caa_tag(b"issue-wild").is_err());
        assert!(caa_tag(&[b'a'; 16]).is_err());
    }
}
