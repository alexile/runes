//! SOCKS4 and SOCKS 4a messages.
//!
//! Request: `VN=4 CD DSTPORT(2) DSTIP(4) USERID NUL`, and for SOCKS 4a (a
//! `DSTIP` of `0.0.0.x`, `x != 0`) a trailing `HOSTNAME NUL`. Reply:
//! `VN=0 CD DSTPORT(2) DSTIP(4)`.
//!
//! See the [SOCKS4](https://www.openssh.com/txt/socks4.protocol) and
//! [SOCKS 4a](https://www.openssh.com/txt/socks4a.protocol) specifications.

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

use crate::addr::{need, port_at};
use crate::{Decoded, Error, TargetAddr};

/// The SOCKS4 version byte.
pub const VERSION: u8 = 4;
/// Longest user id or host name accepted, in bytes (without the NUL).
pub const MAX_FIELD_LEN: usize = 255;

/// A SOCKS4 command.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Socks4Command {
    /// `CONNECT` (1).
    Connect,
    /// `BIND` (2).
    Bind,
}

/// A SOCKS4 or SOCKS 4a request.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct Socks4Request {
    /// The command.
    pub command: Socks4Command,
    /// The destination: an IPv4 address (SOCKS4) or a host name (SOCKS 4a).
    pub target: TargetAddr,
    /// The user id (no NUL bytes, at most 255 bytes).
    pub user_id: Vec<u8>,
}

impl Socks4Request {
    /// A `CONNECT` request with an empty user id.
    #[must_use]
    pub const fn connect(target: TargetAddr) -> Self {
        Self {
            command: Socks4Command::Connect,
            target,
            user_id: Vec::new(),
        }
    }

    /// Sets the command.
    #[must_use]
    pub const fn with_command(mut self, command: Socks4Command) -> Self {
        self.command = command;
        self
    }

    /// Sets the user id.
    #[must_use]
    pub fn with_user_id(mut self, user_id: impl Into<Vec<u8>>) -> Self {
        self.user_id = user_id.into();
        self
    }

    /// Encodes the request. Host name targets use SOCKS 4a.
    ///
    /// # Errors
    ///
    /// [`Error::NotRepresentable`] for an IPv6 target or an IPv4 target in
    /// `0.0.0.1`–`0.0.0.255` (reserved for SOCKS 4a); [`Error::Invalid`] for
    /// a NUL in the user id or host name; [`Error::TooLong`] for fields over
    /// 255 bytes.
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        check_field(&self.user_id, "user id")?;
        let mut out = vec![
            VERSION,
            match self.command {
                Socks4Command::Connect => 1,
                Socks4Command::Bind => 2,
            },
        ];
        out.extend_from_slice(&self.target.port().to_be_bytes());
        match &self.target {
            TargetAddr::Ip(SocketAddr::V4(addr)) => {
                if is_socks4a_marker(*addr.ip()) {
                    return Err(Error::NotRepresentable(
                        "IPv4 0.0.0.x is reserved for SOCKS4a",
                    ));
                }
                out.extend_from_slice(&addr.ip().octets());
                out.extend_from_slice(&self.user_id);
                out.push(0);
            }
            TargetAddr::Ip(SocketAddr::V6(_)) => {
                return Err(Error::NotRepresentable("IPv6 address in SOCKS4"));
            }
            TargetAddr::Domain(host, _) => {
                if host.is_empty() {
                    return Err(Error::Invalid("empty host name"));
                }
                check_field(host.as_bytes(), "host name")?;
                out.extend_from_slice(&[0, 0, 0, 1]);
                out.extend_from_slice(&self.user_id);
                out.push(0);
                out.extend_from_slice(host.as_bytes());
                out.push(0);
            }
        }
        Ok(out)
    }

    /// Decodes a request at the start of `buf`.
    ///
    /// # Errors
    ///
    /// [`Error::Version`], [`Error::Command`], [`Error::TooLong`] when no NUL
    /// ends a field within 255 bytes, [`Error::Invalid`] for an empty or
    /// non-UTF-8 SOCKS 4a host name.
    pub fn decode(buf: &[u8]) -> Result<Decoded<Self>, Error> {
        need!(buf, 1);
        if buf[0] != VERSION {
            return Err(Error::Version(buf[0]));
        }
        need!(buf, 2);
        let command = match buf[1] {
            1 => Socks4Command::Connect,
            2 => Socks4Command::Bind,
            other => return Err(Error::Command(other)),
        };
        need!(buf, 8);
        let port = port_at(buf, 2);
        let ip = Ipv4Addr::new(buf[4], buf[5], buf[6], buf[7]);
        let Some((user_id, user_end)) = nul_field(&buf[8..], "user id")? else {
            return Ok(Decoded::Incomplete(1));
        };
        let user_end = 8 + user_end;
        let (target, len) = if is_socks4a_marker(ip) {
            let Some((host, host_end)) = nul_field(&buf[user_end..], "host name")? else {
                return Ok(Decoded::Incomplete(1));
            };
            if host.is_empty() {
                return Err(Error::Invalid("empty host name"));
            }
            let host =
                std::str::from_utf8(host).map_err(|_| Error::Invalid("host name is not UTF-8"))?;
            (TargetAddr::domain(host, port), user_end + host_end)
        } else {
            (TargetAddr::Ip(SocketAddrV4::new(ip, port).into()), user_end)
        };
        Ok(Decoded::Complete(
            Self {
                command,
                target,
                user_id: user_id.to_vec(),
            },
            len,
        ))
    }
}

/// A SOCKS4 reply code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Socks4Status {
    /// 90: request granted.
    Granted,
    /// 91: request rejected or failed.
    Rejected,
    /// 92: rejected because the server cannot reach the client's identd.
    IdentdUnreachable,
    /// 93: rejected because identd reported a different user id.
    IdentdMismatch,
    /// Any other code.
    Other(u8),
}

impl From<u8> for Socks4Status {
    fn from(code: u8) -> Self {
        match code {
            90 => Self::Granted,
            91 => Self::Rejected,
            92 => Self::IdentdUnreachable,
            93 => Self::IdentdMismatch,
            other => Self::Other(other),
        }
    }
}

impl From<Socks4Status> for u8 {
    fn from(status: Socks4Status) -> Self {
        match status {
            Socks4Status::Granted => 90,
            Socks4Status::Rejected => 91,
            Socks4Status::IdentdUnreachable => 92,
            Socks4Status::IdentdMismatch => 93,
            Socks4Status::Other(other) => other,
        }
    }
}

/// A SOCKS4 reply (8 bytes).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct Socks4Reply {
    /// The result.
    pub status: Socks4Status,
    /// The bound address (meaningful for `BIND`; often zero for `CONNECT`).
    pub address: SocketAddrV4,
}

impl Socks4Reply {
    /// Length of an encoded reply.
    pub const LEN: usize = 8;

    /// A reply from its parts.
    #[must_use]
    pub const fn new(status: Socks4Status, address: SocketAddrV4) -> Self {
        Self { status, address }
    }

    /// Encodes the reply (version byte 0).
    #[must_use]
    pub fn encode(&self) -> [u8; 8] {
        let [p0, p1] = self.address.port().to_be_bytes();
        let [a, b, c, d] = self.address.ip().octets();
        [0, self.status.into(), p0, p1, a, b, c, d]
    }

    /// Decodes a reply. The version byte may be 0 (as specified) or 4 (as
    /// some servers send).
    ///
    /// # Errors
    ///
    /// [`Error::Version`] for any other version byte.
    pub fn decode(buf: &[u8]) -> Result<Decoded<Self>, Error> {
        need!(buf, 1);
        if buf[0] != 0 && buf[0] != VERSION {
            return Err(Error::Version(buf[0]));
        }
        need!(buf, Self::LEN);
        let ip = Ipv4Addr::new(buf[4], buf[5], buf[6], buf[7]);
        Ok(Decoded::Complete(
            Self::new(buf[1].into(), SocketAddrV4::new(ip, port_at(buf, 2))),
            Self::LEN,
        ))
    }
}

const fn is_socks4a_marker(ip: Ipv4Addr) -> bool {
    let [a, b, c, d] = ip.octets();
    a == 0 && b == 0 && c == 0 && d != 0
}

fn check_field(field: &[u8], what: &'static str) -> Result<(), Error> {
    if field.contains(&0) {
        return Err(Error::Invalid("NUL byte in a SOCKS4 field"));
    }
    if field.len() > MAX_FIELD_LEN {
        return Err(Error::TooLong(what));
    }
    Ok(())
}

/// Finds a NUL-terminated field: `Some((field, len_with_nul))`, or `None`
/// if more bytes are needed.
fn nul_field<'a>(buf: &'a [u8], what: &'static str) -> Result<Option<(&'a [u8], usize)>, Error> {
    match buf.iter().position(|&b| b == 0) {
        Some(end) if end > MAX_FIELD_LEN => Err(Error::TooLong(what)),
        Some(end) => Ok(Some((&buf[..end], end + 1))),
        None if buf.len() > MAX_FIELD_LEN => Err(Error::TooLong(what)),
        None => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn socks4_connect_known_answer() {
        // CONNECT 66.102.7.99:80 as user "Fred" (the classic example).
        let wire = b"\x04\x01\x00\x50\x42\x66\x07\x63Fred\x00";
        let req = Socks4Request::connect(TargetAddr::Ip("66.102.7.99:80".parse().unwrap()))
            .with_user_id("Fred");
        assert_eq!(req.encode().unwrap(), wire);
        assert_eq!(
            Socks4Request::decode(wire).unwrap(),
            Decoded::Complete(req, wire.len())
        );
    }

    #[test]
    fn socks4a_known_answer() {
        let wire = b"\x04\x01\x01\xbb\x00\x00\x00\x01\x00example.com\x00";
        let req = Socks4Request::connect(TargetAddr::domain("example.com", 443));
        assert_eq!(req.encode().unwrap(), wire);
        assert_eq!(
            Socks4Request::decode(wire).unwrap(),
            Decoded::Complete(req, wire.len())
        );
    }

    #[test]
    fn incremental_decoding() {
        let wire = Socks4Request::connect(TargetAddr::domain("h.example", 1))
            .with_command(Socks4Command::Bind)
            .with_user_id("u")
            .encode()
            .unwrap();
        for cut in 0..wire.len() {
            assert!(
                matches!(
                    Socks4Request::decode(&wire[..cut]).unwrap(),
                    Decoded::Incomplete(_)
                ),
                "cut at {cut}"
            );
        }
    }

    #[test]
    fn rejects_bad_requests() {
        assert!(matches!(
            Socks4Request::decode(b"\x05"),
            Err(Error::Version(5))
        ));
        assert!(matches!(
            Socks4Request::decode(b"\x04\x03"),
            Err(Error::Command(3))
        ));
        let mut long = b"\x04\x01\x00\x50\x01\x02\x03\x04".to_vec();
        long.extend_from_slice(&[b'a'; 256]);
        assert!(matches!(
            Socks4Request::decode(&long),
            Err(Error::TooLong(_))
        ));
        assert!(matches!(
            Socks4Request::decode(b"\x04\x01\x00\x50\x00\x00\x00\x01\x00\x00"),
            Err(Error::Invalid(_))
        ));
    }

    #[test]
    fn refuses_unrepresentable_requests() {
        let v6 = Socks4Request::connect(TargetAddr::Ip("[::1]:1".parse().unwrap()));
        assert!(matches!(v6.encode(), Err(Error::NotRepresentable(_))));
        let marker = Socks4Request::connect(TargetAddr::Ip("0.0.0.7:1".parse().unwrap()));
        assert!(matches!(marker.encode(), Err(Error::NotRepresentable(_))));
        let nul = Socks4Request::connect(TargetAddr::Ip("1.2.3.4:1".parse().unwrap()))
            .with_user_id(b"a\0b".to_vec());
        assert!(matches!(nul.encode(), Err(Error::Invalid(_))));
    }

    #[test]
    fn reply_round_trip() {
        let reply = Socks4Reply::new(Socks4Status::Granted, "10.0.0.1:1080".parse().unwrap());
        let wire = reply.encode();
        assert_eq!(wire, [0, 90, 0x04, 0x38, 10, 0, 0, 1]);
        assert_eq!(
            Socks4Reply::decode(&wire).unwrap(),
            Decoded::Complete(reply, 8)
        );
        let mut v4 = wire;
        v4[0] = 4;
        assert!(Socks4Reply::decode(&v4).unwrap().complete().is_some());
        assert!(matches!(Socks4Reply::decode(&[5]), Err(Error::Version(5))));
        assert_eq!(
            Socks4Reply::decode(&wire[..3]).unwrap(),
            Decoded::Incomplete(5)
        );
        for code in 0..=255_u8 {
            assert_eq!(u8::from(Socks4Status::from(code)), code);
        }
    }
}
