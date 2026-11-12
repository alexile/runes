//! PROXY protocol version 1: a single text line.
//!
//! `PROXY TCP4 <src> <dst> <sport> <dport>\r\n`, `PROXY TCP6 …` or
//! `PROXY UNKNOWN…\r\n`, at most 107 bytes including the CRLF.

use std::fmt::Write as _;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};
use std::str::FromStr;

use crate::{Addresses, Command, Error, Header, Transport};

/// The v1 signature, `PROXY` (the space after it is checked when parsing).
pub const SIGNATURE: &[u8; 5] = b"PROXY";
/// Longest v1 header, CRLF included.
pub const MAX_LEN: usize = 107;

/// Decodes a v1 header at the start of `buf`.
///
/// `Ok(None)` means `buf` is a valid prefix and more bytes are needed.
pub(crate) fn decode(buf: &[u8]) -> Result<Option<(Header, usize)>, Error> {
    let window = &buf[..buf.len().min(MAX_LEN)];
    let Some(lf) = window.iter().position(|&b| b == b'\n') else {
        return if buf.len() >= MAX_LEN {
            Err(Error::V1TooLong)
        } else {
            Ok(None)
        };
    };
    let line = window[..lf]
        .strip_suffix(b"\r")
        .ok_or(Error::InvalidV1("line does not end in CRLF"))?;
    let rest = line
        .strip_prefix(b"PROXY ")
        .ok_or(Error::InvalidV1("missing \"PROXY \" prefix"))?;
    let header = parse_body(rest)?;
    Ok(Some((header, lf + 1)))
}

fn parse_body(rest: &[u8]) -> Result<Header, Error> {
    // UNKNOWN may be followed by anything (the receiver must ignore it).
    if let Some(tail) = rest.strip_prefix(b"UNKNOWN")
        && (tail.is_empty() || tail.starts_with(b" "))
    {
        return Ok(Header::new(
            Command::Proxy,
            Transport::Unspecified,
            Addresses::Unspecified,
        ));
    }
    let text = std::str::from_utf8(rest).map_err(|_| Error::InvalidV1("non-ASCII field"))?;
    let fields: Vec<&str> = text.split(' ').collect();
    let [proto, src, dst, sport, dport] = fields.as_slice() else {
        return Err(Error::InvalidV1(
            "expected protocol, two addresses and two ports",
        ));
    };
    let sport = parse_port(sport)?;
    let dport = parse_port(dport)?;
    let addresses = match *proto {
        "TCP4" => Addresses::Ipv4 {
            source: SocketAddrV4::new(parse_addr::<Ipv4Addr>(src)?, sport),
            destination: SocketAddrV4::new(parse_addr::<Ipv4Addr>(dst)?, dport),
        },
        "TCP6" => Addresses::Ipv6 {
            source: SocketAddrV6::new(parse_addr::<Ipv6Addr>(src)?, sport, 0, 0),
            destination: SocketAddrV6::new(parse_addr::<Ipv6Addr>(dst)?, dport, 0, 0),
        },
        _ => return Err(Error::InvalidV1("unknown protocol")),
    };
    Ok(Header::new(Command::Proxy, Transport::Stream, addresses))
}

fn parse_addr<A: FromStr>(text: &str) -> Result<A, Error> {
    text.parse()
        .map_err(|_| Error::InvalidV1("invalid address"))
}

fn parse_port(text: &str) -> Result<u16, Error> {
    let digits_ok = !text.is_empty()
        && text.len() <= 5
        && text.bytes().all(|b| b.is_ascii_digit())
        && (text == "0" || !text.starts_with('0'));
    if !digits_ok {
        return Err(Error::InvalidV1("invalid port"));
    }
    text.parse().map_err(|_| Error::InvalidV1("invalid port"))
}

pub(crate) fn encode(header: &Header) -> Result<String, Error> {
    if !header.tlvs.is_empty() {
        return Err(Error::NotRepresentableInV1("TLVs"));
    }
    let mut out = String::with_capacity(MAX_LEN);
    match (&header.addresses, header.command, header.transport) {
        (Addresses::Unspecified, _, _) => out.push_str("PROXY UNKNOWN"),
        (_, Command::Local, _) => {
            return Err(Error::NotRepresentableInV1("LOCAL with addresses"));
        }
        (Addresses::Unix { .. }, _, _) => {
            return Err(Error::NotRepresentableInV1("UNIX addresses"));
        }
        (_, _, transport) if transport != Transport::Stream => {
            return Err(Error::NotRepresentableInV1("non-TCP transport"));
        }
        (
            Addresses::Ipv4 {
                source,
                destination,
            },
            ..,
        ) => {
            let _ = write!(
                out,
                "PROXY TCP4 {} {} {} {}",
                source.ip(),
                destination.ip(),
                source.port(),
                destination.port()
            );
        }
        (
            Addresses::Ipv6 {
                source,
                destination,
            },
            ..,
        ) => {
            let _ = write!(
                out,
                "PROXY TCP6 {} {} {} {}",
                source.ip(),
                destination.ip(),
                source.port(),
                destination.port()
            );
        }
    }
    out.push_str("\r\n");
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;

    fn ok(input: &[u8]) -> (Header, usize) {
        decode(input).unwrap().unwrap()
    }

    #[test]
    fn decodes_spec_examples() {
        let (h, n) = ok(b"PROXY TCP4 255.255.255.255 255.255.255.255 65535 65535\r\nGET /");
        assert_eq!(n, 56);
        assert_eq!(
            h.source(),
            Some(SocketAddr::from(([255, 255, 255, 255], 65535)))
        );
        let (h, n) = ok(b"PROXY TCP6 ffff:f::1 ::1 1 443\r\n");
        assert_eq!(n, 32);
        assert_eq!(h.destination(), Some("[::1]:443".parse().unwrap()));
        assert_eq!(h.transport, Transport::Stream);
        let (h, n) = ok(b"PROXY UNKNOWN\r\n");
        assert_eq!(n, 15);
        assert_eq!(h.addresses, Addresses::Unspecified);
        let (h, _) = ok(b"PROXY UNKNOWN ffff:: ::1 1 2\r\n");
        assert_eq!(h.transport, Transport::Unspecified);
    }

    #[test]
    fn longest_header_fits() {
        let line = "PROXY TCP6 ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff \
                    ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff 65535 65535\r\n";
        assert!(line.len() <= MAX_LEN);
        assert_eq!(ok(line.as_bytes()).1, line.len());
    }

    #[test]
    fn incomplete_and_oversized() {
        assert!(decode(b"PROXY TCP4 1.2.3.4").unwrap().is_none());
        assert!(matches!(decode(&[b'P'; 200]), Err(Error::V1TooLong)));
        let mut long = b"PROXY UNKNOWN ".to_vec();
        long.resize(120, b'x');
        long.extend_from_slice(b"\r\n");
        assert!(matches!(decode(&long), Err(Error::V1TooLong)));
    }

    #[test]
    fn rejects_malformed_lines() {
        for bad in [
            &b"PROXY TCP4 1.2.3.4 5.6.7.8 1 2\n"[..],
            b"PROXY TCP4 1.2.3.4 5.6.7.8 1\r\n",
            b"PROXY TCP4 1.2.3.4  5.6.7.8 1 2\r\n",
            b"PROXY TCP4 ::1 ::1 1 2\r\n",
            b"PROXY TCP6 1.2.3.4 5.6.7.8 1 2\r\n",
            b"PROXY TCP4 1.2.3.4 5.6.7.8 01 2\r\n",
            b"PROXY TCP4 1.2.3.4 5.6.7.8 +1 2\r\n",
            b"PROXY TCP4 1.2.3.4 5.6.7.8 65536 2\r\n",
            b"PROXY TCP4 1.2.3.04 5.6.7.8 1 2\r\n",
            b"PROXY UDP4 1.2.3.4 5.6.7.8 1 2\r\n",
            b"PROXY UNKNOWNX\r\n",
            b"PROXY\r\n",
        ] {
            assert!(
                matches!(decode(bad), Err(Error::InvalidV1(_))),
                "{:?}",
                String::from_utf8_lossy(bad)
            );
        }
    }

    #[test]
    fn encodes_lines() {
        let h = Header::tcp(
            "192.0.2.1:56324".parse().unwrap(),
            "198.51.100.2:443".parse().unwrap(),
        )
        .unwrap();
        assert_eq!(
            encode(&h).unwrap(),
            "PROXY TCP4 192.0.2.1 198.51.100.2 56324 443\r\n"
        );
        let h = Header::tcp(
            "[2001:db8::1]:1".parse().unwrap(),
            "[::1]:2".parse().unwrap(),
        )
        .unwrap();
        assert_eq!(encode(&h).unwrap(), "PROXY TCP6 2001:db8::1 ::1 1 2\r\n");
        assert_eq!(encode(&Header::local()).unwrap(), "PROXY UNKNOWN\r\n");
    }

    #[test]
    fn refuses_what_v1_cannot_say() {
        let udp = Header::udp("1.1.1.1:1".parse().unwrap(), "2.2.2.2:2".parse().unwrap()).unwrap();
        assert!(matches!(encode(&udp), Err(Error::NotRepresentableInV1(_))));
        let unix = Header::new(
            Command::Proxy,
            Transport::Stream,
            Addresses::Unix {
                source: b"/a".to_vec(),
                destination: b"/b".to_vec(),
            },
        );
        assert!(matches!(encode(&unix), Err(Error::NotRepresentableInV1(_))));
        let tlv = Header::local().with_crc32c();
        assert!(matches!(encode(&tlv), Err(Error::NotRepresentableInV1(_))));
    }
}
