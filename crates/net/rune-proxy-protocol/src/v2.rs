//! PROXY protocol version 2: a binary block with TLV extensions.
//!
//! A 12-byte signature, a version/command byte, a family/transport byte, a
//! big-endian `u16` length, then the address block and TLVs.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};

use crate::header::UNIX_ADDR_LEN;
use crate::tlv::{self, PP2_TYPE_CRC32C};
use crate::{Addresses, Command, Error, Header, Transport};

/// The 12-byte v2 signature.
pub const SIGNATURE: &[u8; 12] = b"\r\n\r\n\0\r\nQUIT\n";
/// Length of the fixed part (signature, two bytes, length).
pub const FIXED_LEN: usize = 16;

const FAMILY_UNSPEC: u8 = 0x0;
const FAMILY_INET: u8 = 0x1;
const FAMILY_INET6: u8 = 0x2;
const FAMILY_UNIX: u8 = 0x3;

/// Decodes a v2 header at the start of `buf` (which starts with
/// [`SIGNATURE`]). `Ok(None)` means more bytes are needed.
pub(crate) fn decode(buf: &[u8]) -> Result<Option<(Header, usize)>, Error> {
    let Some(&[ver_cmd, fam, hi, lo]) = buf.get(12..FIXED_LEN) else {
        return Ok(None);
    };
    let version = ver_cmd >> 4;
    if version != 2 {
        return Err(Error::UnsupportedVersion(version));
    }
    let command = match ver_cmd & 0x0F {
        0 => Command::Local,
        1 => Command::Proxy,
        other => return Err(Error::UnsupportedCommand(other)),
    };
    let total = FIXED_LEN + usize::from(u16::from_be_bytes([hi, lo]));
    let Some(header_bytes) = buf.get(..total) else {
        return Ok(None);
    };
    let block = &header_bytes[FIXED_LEN..];
    let header = match parse_block(command, fam, block) {
        Ok(header) => header,
        // LOCAL: the receiver must discard the block and use the real
        // endpoints, so a block it cannot parse is not an error.
        Err(_) if command == Command::Local => Header::local(),
        Err(err) => return Err(err),
    };
    verify_crc(&header, header_bytes, block)?;
    Ok(Some((header, total)))
}

fn parse_block(command: Command, fam: u8, block: &[u8]) -> Result<Header, Error> {
    let transport = match fam & 0x0F {
        0 => Transport::Unspecified,
        1 => Transport::Stream,
        2 => Transport::Datagram,
        other => return Err(Error::UnsupportedTransport(other)),
    };
    let family = fam >> 4;
    let needed = match family {
        FAMILY_UNSPEC => 0,
        FAMILY_INET => 12,
        FAMILY_INET6 => 36,
        FAMILY_UNIX => 2 * UNIX_ADDR_LEN,
        other => return Err(Error::UnsupportedFamily(other)),
    };
    let (addr, tlvs) = block
        .split_at_checked(needed)
        .ok_or(Error::AddressBlockTooShort {
            len: block.len(),
            needed,
        })?;
    let addresses = match family {
        FAMILY_INET => {
            let ip = |i: usize| Ipv4Addr::new(addr[i], addr[i + 1], addr[i + 2], addr[i + 3]);
            Addresses::Ipv4 {
                source: SocketAddrV4::new(ip(0), port(addr, 8)),
                destination: SocketAddrV4::new(ip(4), port(addr, 10)),
            }
        }
        FAMILY_INET6 => Addresses::Ipv6 {
            source: SocketAddrV6::new(ipv6(addr, 0), port(addr, 32), 0, 0),
            destination: SocketAddrV6::new(ipv6(addr, 16), port(addr, 34), 0, 0),
        },
        FAMILY_UNIX => {
            let (src, dst) = addr.split_at(UNIX_ADDR_LEN);
            Addresses::Unix {
                source: trim_nul(src).to_vec(),
                destination: trim_nul(dst).to_vec(),
            }
        }
        _ => Addresses::Unspecified,
    };
    Ok(Header {
        command,
        transport,
        addresses,
        tlvs: tlv::decode_all(tlvs)?,
    })
}

const fn port(addr: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([addr[at], addr[at + 1]])
}

fn ipv6(addr: &[u8], at: usize) -> Ipv6Addr {
    let mut octets = [0; 16];
    octets.copy_from_slice(&addr[at..at + 16]);
    Ipv6Addr::from(octets)
}

fn trim_nul(path: &[u8]) -> &[u8] {
    let end = path.iter().rposition(|&b| b != 0).map_or(0, |i| i + 1);
    &path[..end]
}

/// Checks the first `PP2_TYPE_CRC32C` TLV, if any, against the header.
fn verify_crc(header: &Header, header_bytes: &[u8], block: &[u8]) -> Result<(), Error> {
    let Some(crc_tlv) = header.tlv(PP2_TYPE_CRC32C) else {
        return Ok(());
    };
    let Ok(expected) = <[u8; 4]>::try_from(crc_tlv.value.as_slice()) else {
        return Err(Error::TruncatedTlv);
    };
    let Some(offset) = crc_value_offset(header, block.len()) else {
        return Ok(());
    };
    let mut zeroed = header_bytes.to_vec();
    zeroed[FIXED_LEN + offset..FIXED_LEN + offset + 4].fill(0);
    let actual = tlv::crc32c(&zeroed);
    let expected = u32::from_be_bytes(expected);
    if actual == expected {
        Ok(())
    } else {
        Err(Error::ChecksumMismatch { expected, actual })
    }
}

/// Offset, inside the block, of the first CRC32C TLV's value.
fn crc_value_offset(header: &Header, block_len: usize) -> Option<usize> {
    let mut offset = address_len(&header.addresses);
    for tlv in &header.tlvs {
        if tlv.kind == PP2_TYPE_CRC32C {
            let at = offset + 3;
            return (at + 4 <= block_len).then_some(at);
        }
        offset += 3 + tlv.value.len();
    }
    None
}

const fn address_len(addresses: &Addresses) -> usize {
    match addresses {
        Addresses::Unspecified => 0,
        Addresses::Ipv4 { .. } => 12,
        Addresses::Ipv6 { .. } => 36,
        Addresses::Unix { .. } => 2 * UNIX_ADDR_LEN,
    }
}

pub(crate) fn encode(header: &Header) -> Result<Vec<u8>, Error> {
    let mut out = Vec::with_capacity(FIXED_LEN + 64);
    out.extend_from_slice(SIGNATURE);
    out.push(match header.command {
        Command::Local => 0x20,
        Command::Proxy => 0x21,
    });
    let family = match header.addresses {
        Addresses::Unspecified => FAMILY_UNSPEC,
        Addresses::Ipv4 { .. } => FAMILY_INET,
        Addresses::Ipv6 { .. } => FAMILY_INET6,
        Addresses::Unix { .. } => FAMILY_UNIX,
    };
    let transport = match header.transport {
        Transport::Unspecified => 0,
        Transport::Stream => 1,
        Transport::Datagram => 2,
    };
    out.push((family << 4) | transport);
    out.extend_from_slice(&[0, 0]);
    match &header.addresses {
        Addresses::Unspecified => {}
        Addresses::Ipv4 {
            source,
            destination,
        } => {
            out.extend_from_slice(&source.ip().octets());
            out.extend_from_slice(&destination.ip().octets());
            out.extend_from_slice(&source.port().to_be_bytes());
            out.extend_from_slice(&destination.port().to_be_bytes());
        }
        Addresses::Ipv6 {
            source,
            destination,
        } => {
            out.extend_from_slice(&source.ip().octets());
            out.extend_from_slice(&destination.ip().octets());
            out.extend_from_slice(&source.port().to_be_bytes());
            out.extend_from_slice(&destination.port().to_be_bytes());
        }
        Addresses::Unix {
            source,
            destination,
        } => {
            for path in [source, destination] {
                if path.len() > UNIX_ADDR_LEN {
                    return Err(Error::TooLong("UNIX socket path"));
                }
                let start = out.len();
                out.extend_from_slice(path);
                out.resize(start + UNIX_ADDR_LEN, 0);
            }
        }
    }
    tlv::encode_all(&header.tlvs, &mut out)?;
    let len = u16::try_from(out.len() - FIXED_LEN).map_err(|_| Error::TooLong("v2 header"))?;
    out[14..FIXED_LEN].copy_from_slice(&len.to_be_bytes());
    if let Some(offset) = header
        .tlv(PP2_TYPE_CRC32C)
        .filter(|t| t.value.len() == 4)
        .and_then(|_| crc_value_offset(header, out.len() - FIXED_LEN))
    {
        let at = FIXED_LEN + offset;
        out[at..at + 4].fill(0);
        let crc = tlv::crc32c(&out);
        out[at..at + 4].copy_from_slice(&crc.to_be_bytes());
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tlv::{PP2_TYPE_ALPN, PP2_TYPE_AUTHORITY, Tlv};

    fn hex(s: &str) -> Vec<u8> {
        let s: String = s.split_whitespace().collect();
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn decodes_ipv4_known_answer() {
        // PROXY TCP4 127.0.0.1:12345 -> 127.0.0.2:443, then payload.
        let bytes = hex("0d0a0d0a000d0a515549540a 21 11 000c
                         7f000001 7f000002 3039 01bb 474554");
        let (h, n) = decode(&bytes).unwrap().unwrap();
        assert_eq!(n, 28);
        assert_eq!(h.command, Command::Proxy);
        assert_eq!(h.transport, Transport::Stream);
        assert_eq!(h.source(), Some("127.0.0.1:12345".parse().unwrap()));
        assert_eq!(h.destination(), Some("127.0.0.2:443".parse().unwrap()));
        assert_eq!(encode(&h).unwrap(), bytes[..28]);
    }

    #[test]
    fn decodes_local_health_check() {
        let bytes = hex("0d0a0d0a000d0a515549540a 20 00 0000");
        let (h, n) = decode(&bytes).unwrap().unwrap();
        assert_eq!(n, 16);
        assert_eq!(h, Header::local());
        assert_eq!(encode(&h).unwrap(), bytes);
    }

    #[test]
    fn local_with_garbage_block_is_accepted() {
        let bytes = hex("0d0a0d0a000d0a515549540a 20 f0 0003 010203");
        let (h, n) = decode(&bytes).unwrap().unwrap();
        assert_eq!(n, 19);
        assert_eq!(h, Header::local());
    }

    #[test]
    fn decodes_ipv6_udp_with_tlvs() {
        let bytes = hex("0d0a0d0a000d0a515549540a 21 22 0032
                         20010db8000000000000000000000001
                         00000000000000000000000000000001
                         0035 1f90
                         01 0002 6832
                         02 0006 6578616d706c");
        let (h, n) = decode(&bytes).unwrap().unwrap();
        assert_eq!(n, bytes.len());
        assert_eq!(h.transport, Transport::Datagram);
        assert_eq!(h.source(), Some("[2001:db8::1]:53".parse().unwrap()));
        assert_eq!(h.destination(), Some("[::1]:8080".parse().unwrap()));
        assert_eq!(h.alpn(), Some(&b"h2"[..]));
        assert_eq!(h.authority(), Some("exampl"));
        assert_eq!(encode(&h).unwrap(), bytes);
    }

    #[test]
    fn unix_paths_are_padded_and_trimmed() {
        let h = Header::new(
            Command::Proxy,
            Transport::Stream,
            Addresses::Unix {
                source: b"/run/a.sock".to_vec(),
                destination: b"\0abstract".to_vec(),
            },
        );
        let bytes = encode(&h).unwrap();
        assert_eq!(bytes.len(), FIXED_LEN + 216);
        assert_eq!(bytes[13], 0x31);
        assert_eq!(decode(&bytes).unwrap().unwrap().0, h);
        let long = Header::new(
            Command::Proxy,
            Transport::Stream,
            Addresses::Unix {
                source: vec![b'a'; 109],
                destination: Vec::new(),
            },
        );
        assert!(matches!(encode(&long), Err(Error::TooLong(_))));
    }

    #[test]
    fn crc32c_is_written_and_verified() {
        let h = Header::tcp(
            "10.0.0.1:1000".parse().unwrap(),
            "10.0.0.2:80".parse().unwrap(),
        )
        .unwrap()
        .with_tlv(Tlv::new(PP2_TYPE_AUTHORITY, b"example.com".to_vec()))
        .with_crc32c();
        let mut bytes = encode(&h).unwrap();
        let (back, _) = decode(&bytes).unwrap().unwrap();
        assert_ne!(back.tlv(PP2_TYPE_CRC32C).unwrap().value, [0; 4]);
        // Re-encoding reproduces the same bytes.
        assert_eq!(encode(&back).unwrap(), bytes);
        // Flip one address bit: the checksum no longer matches.
        bytes[16] ^= 1;
        assert!(matches!(
            decode(&bytes),
            Err(Error::ChecksumMismatch { .. })
        ));
    }

    #[test]
    fn crc32c_with_wrong_length_is_rejected() {
        let h = Header::local().with_tlv(Tlv::new(PP2_TYPE_CRC32C, vec![0; 3]));
        let bytes = encode(&h).unwrap();
        // LOCAL falls back to discarding the block, so use PROXY.
        let mut bytes_proxy = bytes;
        bytes_proxy[12] = 0x21;
        assert!(matches!(decode(&bytes_proxy), Err(Error::TruncatedTlv)));
    }

    #[test]
    fn incomplete_input_needs_more() {
        let h = Header::tcp("1.2.3.4:5".parse().unwrap(), "6.7.8.9:10".parse().unwrap())
            .unwrap()
            .with_tlv(Tlv::new(PP2_TYPE_ALPN, b"http/1.1".to_vec()));
        let bytes = encode(&h).unwrap();
        for cut in 12..bytes.len() {
            assert!(decode(&bytes[..cut]).unwrap().is_none(), "cut at {cut}");
        }
    }

    #[test]
    fn rejects_bad_fields() {
        let base = hex("0d0a0d0a000d0a515549540a 21 11 000c 7f000001 7f000002 3039 01bb");
        let mut b = base.clone();
        b[12] = 0x11;
        assert!(matches!(decode(&b), Err(Error::UnsupportedVersion(1))));
        b = base.clone();
        b[12] = 0x22;
        assert!(matches!(decode(&b), Err(Error::UnsupportedCommand(2))));
        b = base.clone();
        b[13] = 0x41;
        assert!(matches!(decode(&b), Err(Error::UnsupportedFamily(4))));
        b = base.clone();
        b[13] = 0x13;
        assert!(matches!(decode(&b), Err(Error::UnsupportedTransport(3))));
        b = base.clone();
        b[13] = 0x21;
        assert!(matches!(
            decode(&b),
            Err(Error::AddressBlockTooShort {
                len: 12,
                needed: 36
            })
        ));
        b = base;
        b[15] = 0x0e;
        b.extend_from_slice(&[0x01, 0x00]);
        assert!(matches!(decode(&b), Err(Error::TruncatedTlv)));
    }

    #[test]
    fn oversized_header_is_rejected() {
        let h = Header::local()
            .with_tlv(Tlv::new(4, vec![0; 65_535]))
            .with_tlv(Tlv::new(4, Vec::new()));
        assert!(matches!(encode(&h), Err(Error::TooLong(_))));
    }
}
