//! Destination addresses and the incremental decoding result.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use crate::Error;

/// The result of decoding a message from the front of a buffer.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[must_use]
pub enum Decoded<T> {
    /// A whole message, and how many bytes of the buffer it took.
    Complete(T, usize),
    /// The buffer is a valid prefix; at least this many more bytes are
    /// needed. Reading exactly this many never reads past the message.
    Incomplete(usize),
}

impl<T> Decoded<T> {
    /// The message and its length, if complete.
    pub fn complete(self) -> Option<(T, usize)> {
        match self {
            Self::Complete(value, len) => Some((value, len)),
            Self::Incomplete(_) => None,
        }
    }

    /// Adds `prefix` bytes to a complete message's length (for a message
    /// decoded after a fixed header).
    pub(crate) fn shift(self, prefix: usize) -> Self {
        match self {
            Self::Complete(value, len) => Self::Complete(value, prefix + len),
            Self::Incomplete(n) => Self::Incomplete(n),
        }
    }

    pub(crate) fn map<U>(self, f: impl FnOnce(T) -> U) -> Decoded<U> {
        match self {
            Self::Complete(value, len) => Decoded::Complete(f(value), len),
            Self::Incomplete(n) => Decoded::Incomplete(n),
        }
    }
}

/// Returns `Incomplete` from the enclosing function unless `buf` holds at
/// least `len` bytes.
macro_rules! need {
    ($buf:expr, $len:expr) => {
        if $buf.len() < $len {
            return Ok($crate::Decoded::Incomplete($len - $buf.len()));
        }
    };
}
pub(crate) use need;

/// Where a client wants to go: an IP socket address or a host name and port.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum TargetAddr {
    /// An IP address and port.
    Ip(SocketAddr),
    /// A host name (1 to 255 bytes) and port, resolved by the proxy.
    Domain(String, u16),
}

impl TargetAddr {
    /// A host name target.
    #[must_use]
    pub fn domain(host: impl Into<String>, port: u16) -> Self {
        Self::Domain(host.into(), port)
    }

    /// The port.
    #[must_use]
    pub const fn port(&self) -> u16 {
        match self {
            Self::Ip(addr) => addr.port(),
            Self::Domain(_, port) => *port,
        }
    }

    /// The IP socket address, for IP targets.
    #[must_use]
    pub const fn ip(&self) -> Option<SocketAddr> {
        match self {
            Self::Ip(addr) => Some(*addr),
            Self::Domain(..) => None,
        }
    }

    /// The unspecified IPv4 address with port 0, as used in replies that
    /// carry no meaningful address.
    #[must_use]
    pub const fn unspecified() -> Self {
        Self::Ip(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0))
    }

    /// Length of the SOCKS5 encoding (address type, address, port).
    #[must_use]
    pub const fn encoded_len(&self) -> usize {
        match self {
            Self::Ip(SocketAddr::V4(_)) => 7,
            Self::Ip(SocketAddr::V6(_)) => 19,
            Self::Domain(host, _) => 4 + host.len(),
        }
    }

    /// Appends the SOCKS5 encoding (`ATYP`, address, port) to `out`.
    ///
    /// # Errors
    ///
    /// [`Error::Invalid`] for an empty host name, [`Error::TooLong`] for one
    /// over 255 bytes.
    pub fn encode_to(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        match self {
            Self::Ip(SocketAddr::V4(a)) => {
                out.push(ATYP_IPV4);
                out.extend_from_slice(&a.ip().octets());
            }
            Self::Ip(SocketAddr::V6(a)) => {
                out.push(ATYP_IPV6);
                out.extend_from_slice(&a.ip().octets());
            }
            Self::Domain(host, _) => {
                let len = check_domain(host)?;
                out.push(ATYP_DOMAIN);
                out.push(len);
                out.extend_from_slice(host.as_bytes());
            }
        }
        out.extend_from_slice(&self.port().to_be_bytes());
        Ok(())
    }

    /// Decodes a SOCKS5 address (`ATYP`, address, port) at the start of
    /// `buf`.
    ///
    /// # Errors
    ///
    /// [`Error::AddressType`] for an unknown type, [`Error::Invalid`] for an
    /// empty or non-UTF-8 host name.
    pub fn decode(buf: &[u8]) -> Result<Decoded<Self>, Error> {
        need!(buf, 1);
        let (len, addr) = match buf[0] {
            ATYP_IPV4 => {
                need!(buf, 7);
                let ip = Ipv4Addr::new(buf[1], buf[2], buf[3], buf[4]);
                (7, Self::Ip(SocketAddr::new(ip.into(), port_at(buf, 5))))
            }
            ATYP_IPV6 => {
                need!(buf, 19);
                let mut octets = [0; 16];
                octets.copy_from_slice(&buf[1..17]);
                let ip = Ipv6Addr::from(octets);
                (19, Self::Ip(SocketAddr::new(ip.into(), port_at(buf, 17))))
            }
            ATYP_DOMAIN => {
                need!(buf, 2);
                let n = usize::from(buf[1]);
                if n == 0 {
                    return Err(Error::Invalid("empty host name"));
                }
                need!(buf, 4 + n);
                let host = std::str::from_utf8(&buf[2..2 + n])
                    .map_err(|_| Error::Invalid("host name is not UTF-8"))?;
                (4 + n, Self::Domain(host.to_owned(), port_at(buf, 2 + n)))
            }
            other => return Err(Error::AddressType(other)),
        };
        Ok(Decoded::Complete(addr, len))
    }
}

impl From<SocketAddr> for TargetAddr {
    fn from(addr: SocketAddr) -> Self {
        Self::Ip(addr)
    }
}

impl fmt::Display for TargetAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ip(addr) => addr.fmt(f),
            Self::Domain(host, port) => write!(f, "{host}:{port}"),
        }
    }
}

const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;

pub const fn port_at(buf: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([buf[at], buf[at + 1]])
}

/// Validates a host name for the wire and returns its length byte.
pub fn check_domain(host: &str) -> Result<u8, Error> {
    if host.is_empty() {
        return Err(Error::Invalid("empty host name"));
    }
    u8::try_from(host.len()).map_err(|_| Error::TooLong("host name"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_answers() {
        let v4 = TargetAddr::Ip("192.0.2.1:80".parse().unwrap());
        let mut out = Vec::new();
        v4.encode_to(&mut out).unwrap();
        assert_eq!(out, [1, 192, 0, 2, 1, 0, 80]);
        assert_eq!(TargetAddr::decode(&out).unwrap(), Decoded::Complete(v4, 7));

        let d = TargetAddr::domain("example.com", 443);
        out.clear();
        d.encode_to(&mut out).unwrap();
        assert_eq!(out, b"\x03\x0bexample.com\x01\xbb");
        assert_eq!(d.encoded_len(), out.len());
        assert_eq!(TargetAddr::decode(&out).unwrap(), Decoded::Complete(d, 15));

        let v6 = TargetAddr::Ip("[2001:db8::1]:8080".parse().unwrap());
        out.clear();
        v6.encode_to(&mut out).unwrap();
        assert_eq!(out.len(), 19);
        assert_eq!(out[0], 4);
        assert_eq!(TargetAddr::decode(&out).unwrap(), Decoded::Complete(v6, 19));
    }

    #[test]
    fn incomplete_reports_exact_need() {
        assert_eq!(TargetAddr::decode(&[]).unwrap(), Decoded::Incomplete(1));
        assert_eq!(TargetAddr::decode(&[1, 0]).unwrap(), Decoded::Incomplete(5));
        assert_eq!(TargetAddr::decode(&[3]).unwrap(), Decoded::Incomplete(1));
        assert_eq!(
            TargetAddr::decode(&[3, 5, b'a']).unwrap(),
            Decoded::Incomplete(6)
        );
    }

    #[test]
    fn rejects_bad_addresses() {
        assert!(matches!(
            TargetAddr::decode(&[2]),
            Err(Error::AddressType(2))
        ));
        assert!(matches!(
            TargetAddr::decode(&[3, 0]),
            Err(Error::Invalid(_))
        ));
        assert!(matches!(
            TargetAddr::decode(&[3, 1, 0xff, 0, 0]),
            Err(Error::Invalid(_))
        ));
        let long = TargetAddr::domain("a".repeat(256), 1);
        assert!(matches!(
            long.encode_to(&mut Vec::new()),
            Err(Error::TooLong(_))
        ));
        let empty = TargetAddr::domain("", 1);
        assert!(matches!(
            empty.encode_to(&mut Vec::new()),
            Err(Error::Invalid(_))
        ));
    }

    #[test]
    fn display() {
        assert_eq!(TargetAddr::domain("h", 1).to_string(), "h:1");
        assert_eq!(TargetAddr::unspecified().to_string(), "0.0.0.0:0");
    }
}
