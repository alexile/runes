//! SOCKS5 messages ([RFC 1928]), username/password authentication
//! ([RFC 1929]) and GSSAPI message framing ([RFC 1961]).
//!
//! [RFC 1928]: https://www.rfc-editor.org/rfc/rfc1928
//! [RFC 1929]: https://www.rfc-editor.org/rfc/rfc1929
//! [RFC 1961]: https://www.rfc-editor.org/rfc/rfc1961

use std::fmt;

use crate::addr::need;
use crate::{Decoded, Error, TargetAddr};

/// The SOCKS5 version byte.
pub const VERSION: u8 = 5;
/// The version byte of RFC 1929 and RFC 1961 sub-negotiation messages.
pub const SUBNEGOTIATION_VERSION: u8 = 1;

/// An authentication method.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum AuthMethod {
    /// `0x00`: no authentication.
    NoAuth,
    /// `0x01`: GSSAPI (RFC 1961). Only the message framing is implemented.
    Gssapi,
    /// `0x02`: username/password (RFC 1929).
    UsernamePassword,
    /// `0xFF`: in a method selection, none of the offered methods is
    /// acceptable.
    NoAcceptable,
    /// Any other method code.
    Other(u8),
}

impl From<u8> for AuthMethod {
    fn from(code: u8) -> Self {
        match code {
            0x00 => Self::NoAuth,
            0x01 => Self::Gssapi,
            0x02 => Self::UsernamePassword,
            0xFF => Self::NoAcceptable,
            other => Self::Other(other),
        }
    }
}

impl From<AuthMethod> for u8 {
    fn from(method: AuthMethod) -> Self {
        match method {
            AuthMethod::NoAuth => 0x00,
            AuthMethod::Gssapi => 0x01,
            AuthMethod::UsernamePassword => 0x02,
            AuthMethod::NoAcceptable => 0xFF,
            AuthMethod::Other(other) => other,
        }
    }
}

/// The client's opening message: the methods it supports.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct Greeting {
    /// Offered methods, 1 to 255 of them.
    pub methods: Vec<AuthMethod>,
}

impl Greeting {
    /// A greeting offering `methods`.
    #[must_use]
    pub fn new(methods: impl Into<Vec<AuthMethod>>) -> Self {
        Self {
            methods: methods.into(),
        }
    }

    /// Encodes the greeting.
    ///
    /// # Errors
    ///
    /// [`Error::Invalid`] with no methods, [`Error::TooLong`] with over 255.
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        if self.methods.is_empty() {
            return Err(Error::Invalid("greeting offers no methods"));
        }
        let n = u8::try_from(self.methods.len()).map_err(|_| Error::TooLong("method list"))?;
        let mut out = vec![VERSION, n];
        out.extend(self.methods.iter().map(|&m| u8::from(m)));
        Ok(out)
    }

    /// Decodes a greeting.
    ///
    /// # Errors
    ///
    /// [`Error::Version`] or [`Error::Invalid`] for an empty method list.
    pub fn decode(buf: &[u8]) -> Result<Decoded<Self>, Error> {
        need!(buf, 1);
        if buf[0] != VERSION {
            return Err(Error::Version(buf[0]));
        }
        need!(buf, 2);
        let n = usize::from(buf[1]);
        if n == 0 {
            return Err(Error::Invalid("greeting offers no methods"));
        }
        need!(buf, 2 + n);
        let methods = buf[2..2 + n].iter().map(|&b| AuthMethod::from(b)).collect();
        Ok(Decoded::Complete(Self { methods }, 2 + n))
    }

    /// Picks a method the server supports, in the server's order of
    /// preference: the first of `supported` that the client offered, or
    /// [`AuthMethod::NoAcceptable`].
    #[must_use]
    pub fn select(&self, supported: &[AuthMethod]) -> AuthMethod {
        supported
            .iter()
            .copied()
            .find(|m| self.methods.contains(m))
            .unwrap_or(AuthMethod::NoAcceptable)
    }
}

/// The server's choice of method (`VER METHOD`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct MethodSelection {
    /// The selected method, or [`AuthMethod::NoAcceptable`].
    pub method: AuthMethod,
}

impl MethodSelection {
    /// Length of an encoded selection.
    pub const LEN: usize = 2;

    /// A selection of `method`.
    #[must_use]
    pub const fn new(method: AuthMethod) -> Self {
        Self { method }
    }

    /// Encodes the selection.
    #[must_use]
    pub fn encode(&self) -> [u8; 2] {
        [VERSION, self.method.into()]
    }

    /// Decodes a selection.
    ///
    /// # Errors
    ///
    /// [`Error::Version`].
    pub fn decode(buf: &[u8]) -> Result<Decoded<Self>, Error> {
        need!(buf, 1);
        if buf[0] != VERSION {
            return Err(Error::Version(buf[0]));
        }
        need!(buf, 2);
        Ok(Decoded::Complete(Self::new(buf[1].into()), 2))
    }
}

/// Username and password (RFC 1929). Each is at most 255 bytes. `Debug`
/// output hides the password.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Credentials {
    /// The user name.
    pub username: Vec<u8>,
    /// The password.
    pub password: Vec<u8>,
}

impl fmt::Debug for Credentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Credentials")
            .field("username", &String::from_utf8_lossy(&self.username))
            .field("password", &"<redacted>")
            .finish()
    }
}

impl Credentials {
    /// Credentials from a user name and password.
    #[must_use]
    pub fn new(username: impl Into<Vec<u8>>, password: impl Into<Vec<u8>>) -> Self {
        Self {
            username: username.into(),
            password: password.into(),
        }
    }

    /// Encodes the RFC 1929 request (`VER ULEN UNAME PLEN PASSWD`).
    ///
    /// # Errors
    ///
    /// [`Error::TooLong`] for a field over 255 bytes.
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        let ulen = u8::try_from(self.username.len()).map_err(|_| Error::TooLong("username"))?;
        let plen = u8::try_from(self.password.len()).map_err(|_| Error::TooLong("password"))?;
        let mut out = Vec::with_capacity(3 + self.username.len() + self.password.len());
        out.extend_from_slice(&[SUBNEGOTIATION_VERSION, ulen]);
        out.extend_from_slice(&self.username);
        out.push(plen);
        out.extend_from_slice(&self.password);
        Ok(out)
    }

    /// Decodes an RFC 1929 request. Empty fields are accepted.
    ///
    /// # Errors
    ///
    /// [`Error::Version`] for a version byte other than 1.
    pub fn decode(buf: &[u8]) -> Result<Decoded<Self>, Error> {
        need!(buf, 1);
        if buf[0] != SUBNEGOTIATION_VERSION {
            return Err(Error::Version(buf[0]));
        }
        need!(buf, 2);
        let ulen = usize::from(buf[1]);
        need!(buf, 3 + ulen);
        let plen = usize::from(buf[2 + ulen]);
        let len = 3 + ulen + plen;
        need!(buf, len);
        Ok(Decoded::Complete(
            Self::new(&buf[2..2 + ulen], &buf[3 + ulen..len]),
            len,
        ))
    }
}

/// The RFC 1929 reply: whether authentication succeeded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct AuthReply {
    /// The status byte; zero means success.
    pub status: u8,
}

impl AuthReply {
    /// A success (`true`) or failure reply.
    #[must_use]
    pub const fn new(success: bool) -> Self {
        Self {
            status: if success { 0 } else { 1 },
        }
    }

    /// Whether the status means success.
    #[must_use]
    pub const fn is_success(&self) -> bool {
        self.status == 0
    }

    /// Encodes the reply.
    #[must_use]
    pub const fn encode(&self) -> [u8; 2] {
        [SUBNEGOTIATION_VERSION, self.status]
    }

    /// Decodes a reply. The version byte may be 1 (as specified) or 5 (as
    /// some servers send).
    ///
    /// # Errors
    ///
    /// [`Error::Version`] for any other version byte.
    pub const fn decode(buf: &[u8]) -> Result<Decoded<Self>, Error> {
        need!(buf, 1);
        if buf[0] != SUBNEGOTIATION_VERSION && buf[0] != VERSION {
            return Err(Error::Version(buf[0]));
        }
        need!(buf, 2);
        Ok(Decoded::Complete(Self { status: buf[1] }, 2))
    }
}

/// A SOCKS5 command.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Command {
    /// `CONNECT` (1): open a TCP connection to the target.
    Connect,
    /// `BIND` (2): accept one inbound TCP connection.
    Bind,
    /// `UDP ASSOCIATE` (3): relay UDP datagrams.
    UdpAssociate,
}

/// A SOCKS5 request (`VER CMD RSV ATYP DST.ADDR DST.PORT`).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct Request {
    /// The command.
    pub command: Command,
    /// The destination. For `UDP ASSOCIATE`, the address the client will
    /// send datagrams from (or all zeros if unknown).
    pub target: TargetAddr,
}

impl Request {
    /// A request from its parts.
    #[must_use]
    pub const fn new(command: Command, target: TargetAddr) -> Self {
        Self { command, target }
    }

    /// Encodes the request.
    ///
    /// # Errors
    ///
    /// As [`TargetAddr::encode_to`].
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        let cmd = match self.command {
            Command::Connect => 1,
            Command::Bind => 2,
            Command::UdpAssociate => 3,
        };
        let mut out = Vec::with_capacity(3 + self.target.encoded_len());
        out.extend_from_slice(&[VERSION, cmd, 0]);
        self.target.encode_to(&mut out)?;
        Ok(out)
    }

    /// Decodes a request. The reserved byte is ignored.
    ///
    /// # Errors
    ///
    /// [`Error::Version`], [`Error::Command`], or as [`TargetAddr::decode`].
    pub fn decode(buf: &[u8]) -> Result<Decoded<Self>, Error> {
        need!(buf, 1);
        if buf[0] != VERSION {
            return Err(Error::Version(buf[0]));
        }
        need!(buf, 2);
        let command = match buf[1] {
            1 => Command::Connect,
            2 => Command::Bind,
            3 => Command::UdpAssociate,
            other => return Err(Error::Command(other)),
        };
        need!(buf, 3);
        Ok(TargetAddr::decode(&buf[3..])?
            .map(|target| Self { command, target })
            .shift(3))
    }
}

/// A SOCKS5 reply code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ReplyCode {
    /// `0x00`: succeeded.
    Succeeded,
    /// `0x01`: general SOCKS server failure.
    GeneralFailure,
    /// `0x02`: connection not allowed by ruleset.
    NotAllowed,
    /// `0x03`: network unreachable.
    NetworkUnreachable,
    /// `0x04`: host unreachable.
    HostUnreachable,
    /// `0x05`: connection refused.
    ConnectionRefused,
    /// `0x06`: TTL expired.
    TtlExpired,
    /// `0x07`: command not supported.
    CommandNotSupported,
    /// `0x08`: address type not supported.
    AddressTypeNotSupported,
    /// Any other code.
    Other(u8),
}

impl From<u8> for ReplyCode {
    fn from(code: u8) -> Self {
        match code {
            0 => Self::Succeeded,
            1 => Self::GeneralFailure,
            2 => Self::NotAllowed,
            3 => Self::NetworkUnreachable,
            4 => Self::HostUnreachable,
            5 => Self::ConnectionRefused,
            6 => Self::TtlExpired,
            7 => Self::CommandNotSupported,
            8 => Self::AddressTypeNotSupported,
            other => Self::Other(other),
        }
    }
}

impl From<ReplyCode> for u8 {
    fn from(code: ReplyCode) -> Self {
        match code {
            ReplyCode::Succeeded => 0,
            ReplyCode::GeneralFailure => 1,
            ReplyCode::NotAllowed => 2,
            ReplyCode::NetworkUnreachable => 3,
            ReplyCode::HostUnreachable => 4,
            ReplyCode::ConnectionRefused => 5,
            ReplyCode::TtlExpired => 6,
            ReplyCode::CommandNotSupported => 7,
            ReplyCode::AddressTypeNotSupported => 8,
            ReplyCode::Other(other) => other,
        }
    }
}

impl ReplyCode {
    /// The reply code for an I/O error from connecting to a target.
    #[must_use]
    pub fn from_io_error(err: &std::io::Error) -> Self {
        use std::io::ErrorKind;
        match err.kind() {
            ErrorKind::ConnectionRefused => Self::ConnectionRefused,
            ErrorKind::PermissionDenied => Self::NotAllowed,
            ErrorKind::NetworkUnreachable => Self::NetworkUnreachable,
            ErrorKind::HostUnreachable | ErrorKind::NotFound => Self::HostUnreachable,
            ErrorKind::TimedOut => Self::TtlExpired,
            ErrorKind::Unsupported => Self::AddressTypeNotSupported,
            _ => Self::GeneralFailure,
        }
    }
}

/// A SOCKS5 reply (`VER REP RSV ATYP BND.ADDR BND.PORT`).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct Reply {
    /// The result.
    pub code: ReplyCode,
    /// The bound address: the proxy's outgoing address for `CONNECT`, or the
    /// relay address for `UDP ASSOCIATE`.
    pub bound: TargetAddr,
}

impl Reply {
    /// A reply from its parts.
    #[must_use]
    pub const fn new(code: ReplyCode, bound: TargetAddr) -> Self {
        Self { code, bound }
    }

    /// A failure reply with an all-zero bound address.
    #[must_use]
    pub const fn failure(code: ReplyCode) -> Self {
        Self::new(code, TargetAddr::unspecified())
    }

    /// Encodes the reply.
    ///
    /// # Errors
    ///
    /// As [`TargetAddr::encode_to`].
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        let mut out = Vec::with_capacity(3 + self.bound.encoded_len());
        out.extend_from_slice(&[VERSION, self.code.into(), 0]);
        self.bound.encode_to(&mut out)?;
        Ok(out)
    }

    /// Decodes a reply. The reserved byte is ignored.
    ///
    /// # Errors
    ///
    /// [`Error::Version`], or as [`TargetAddr::decode`].
    pub fn decode(buf: &[u8]) -> Result<Decoded<Self>, Error> {
        need!(buf, 1);
        if buf[0] != VERSION {
            return Err(Error::Version(buf[0]));
        }
        need!(buf, 3);
        let code = ReplyCode::from(buf[1]);
        Ok(TargetAddr::decode(&buf[3..])?
            .map(|bound| Self { code, bound })
            .shift(3))
    }
}

/// The header of a UDP datagram relayed through `UDP ASSOCIATE`
/// (`RSV(2) FRAG ATYP DST.ADDR DST.PORT`), followed by the payload.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct UdpHeader {
    /// Fragment number; 0 for a standalone datagram. Most implementations
    /// drop fragments.
    pub frag: u8,
    /// The destination (client to relay) or source (relay to client).
    pub target: TargetAddr,
}

impl UdpHeader {
    /// An unfragmented header for `target`.
    #[must_use]
    pub const fn new(target: TargetAddr) -> Self {
        Self { frag: 0, target }
    }

    /// Encodes the header followed by `payload` as one datagram.
    ///
    /// # Errors
    ///
    /// As [`TargetAddr::encode_to`].
    pub fn encode_datagram(&self, payload: &[u8]) -> Result<Vec<u8>, Error> {
        let mut out = Vec::with_capacity(3 + self.target.encoded_len() + payload.len());
        out.extend_from_slice(&[0, 0, self.frag]);
        self.target.encode_to(&mut out)?;
        out.extend_from_slice(payload);
        Ok(out)
    }

    /// Splits a datagram into its header and payload. A datagram is always
    /// complete, so a truncated header is an error.
    ///
    /// # Errors
    ///
    /// [`Error::Invalid`] for a truncated header, or as
    /// [`TargetAddr::decode`]. The reserved bytes are ignored.
    pub fn decode_datagram(datagram: &[u8]) -> Result<(Self, &[u8]), Error> {
        let Some((&[_, _, frag], rest)) = datagram.split_first_chunk::<3>() else {
            return Err(Error::Invalid("truncated UDP header"));
        };
        match TargetAddr::decode(rest)? {
            Decoded::Complete(target, len) => Ok((Self { frag, target }, &rest[len..])),
            Decoded::Incomplete(_) => Err(Error::Invalid("truncated UDP header")),
        }
    }
}

/// An RFC 1961 GSSAPI message type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum GssapiMessageType {
    /// `0x01`: a context establishment token.
    Authentication,
    /// `0x02`: protection-level negotiation.
    Protection,
    /// `0x03`: an encapsulated data message.
    Encapsulation,
    /// `0xFF`: abort.
    Abort,
    /// Any other type.
    Other(u8),
}

impl From<u8> for GssapiMessageType {
    fn from(code: u8) -> Self {
        match code {
            0x01 => Self::Authentication,
            0x02 => Self::Protection,
            0x03 => Self::Encapsulation,
            0xFF => Self::Abort,
            other => Self::Other(other),
        }
    }
}

impl From<GssapiMessageType> for u8 {
    fn from(kind: GssapiMessageType) -> Self {
        match kind {
            GssapiMessageType::Authentication => 0x01,
            GssapiMessageType::Protection => 0x02,
            GssapiMessageType::Encapsulation => 0x03,
            GssapiMessageType::Abort => 0xFF,
            GssapiMessageType::Other(other) => other,
        }
    }
}

/// An RFC 1961 GSSAPI sub-negotiation message (`VER MTYP LEN(2) TOKEN`).
///
/// This crate frames the messages so a caller can plug in a GSSAPI
/// implementation; the tokio client and server do not negotiate GSSAPI.
/// An abort message is `VER 0xFF` with no length or token.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct GssapiMessage {
    /// The message type.
    pub kind: GssapiMessageType,
    /// The opaque token (empty for an abort).
    pub token: Vec<u8>,
}

impl GssapiMessage {
    /// A message from its parts.
    #[must_use]
    pub fn new(kind: GssapiMessageType, token: impl Into<Vec<u8>>) -> Self {
        Self {
            kind,
            token: token.into(),
        }
    }

    /// Encodes the message.
    ///
    /// # Errors
    ///
    /// [`Error::TooLong`] for a token over 65 535 bytes, [`Error::Invalid`]
    /// for an abort with a token.
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        if self.kind == GssapiMessageType::Abort {
            if !self.token.is_empty() {
                return Err(Error::Invalid("GSSAPI abort carries no token"));
            }
            return Ok(vec![SUBNEGOTIATION_VERSION, 0xFF]);
        }
        let len = u16::try_from(self.token.len()).map_err(|_| Error::TooLong("GSSAPI token"))?;
        let mut out = vec![SUBNEGOTIATION_VERSION, self.kind.into()];
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(&self.token);
        Ok(out)
    }

    /// Decodes a message.
    ///
    /// # Errors
    ///
    /// [`Error::Version`] for a version byte other than 1.
    pub fn decode(buf: &[u8]) -> Result<Decoded<Self>, Error> {
        need!(buf, 1);
        if buf[0] != SUBNEGOTIATION_VERSION {
            return Err(Error::Version(buf[0]));
        }
        need!(buf, 2);
        let kind = GssapiMessageType::from(buf[1]);
        if kind == GssapiMessageType::Abort {
            return Ok(Decoded::Complete(Self::new(kind, Vec::new()), 2));
        }
        need!(buf, 4);
        let len = 4 + usize::from(u16::from_be_bytes([buf[2], buf[3]]));
        need!(buf, len);
        Ok(Decoded::Complete(Self::new(kind, &buf[4..len]), len))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn greeting_and_selection() {
        let g = Greeting::new([AuthMethod::NoAuth, AuthMethod::UsernamePassword]);
        let wire = g.encode().unwrap();
        assert_eq!(wire, [5, 2, 0, 2]);
        assert_eq!(
            Greeting::decode(&wire).unwrap(),
            Decoded::Complete(g.clone(), 4)
        );
        assert_eq!(
            Greeting::decode(&wire[..2]).unwrap(),
            Decoded::Incomplete(2)
        );
        assert_eq!(
            g.select(&[AuthMethod::UsernamePassword, AuthMethod::NoAuth]),
            AuthMethod::UsernamePassword
        );
        assert_eq!(g.select(&[AuthMethod::Gssapi]), AuthMethod::NoAcceptable);
        assert!(matches!(Greeting::decode(&[5, 0]), Err(Error::Invalid(_))));
        assert!(matches!(Greeting::decode(&[4]), Err(Error::Version(4))));
        assert!(Greeting::new([]).encode().is_err());

        let sel = MethodSelection::new(AuthMethod::NoAcceptable);
        assert_eq!(sel.encode(), [5, 0xFF]);
        assert_eq!(
            MethodSelection::decode(&[5, 0xFF]).unwrap(),
            Decoded::Complete(sel, 2)
        );
        for code in 0..=255_u8 {
            assert_eq!(u8::from(AuthMethod::from(code)), code);
            assert_eq!(u8::from(ReplyCode::from(code)), code);
            assert_eq!(u8::from(GssapiMessageType::from(code)), code);
        }
    }

    #[test]
    fn username_password() {
        let c = Credentials::new("alice", "s3cret");
        let wire = c.encode().unwrap();
        assert_eq!(wire, b"\x01\x05alice\x06s3cret");
        assert_eq!(
            Credentials::decode(&wire).unwrap(),
            Decoded::Complete(c.clone(), wire.len())
        );
        assert_eq!(
            Credentials::decode(&wire[..7]).unwrap(),
            Decoded::Incomplete(1)
        );
        assert!(!format!("{c:?}").contains("s3cret"));
        assert!(matches!(
            Credentials::new(vec![b'a'; 256], "").encode(),
            Err(Error::TooLong(_))
        ));
        assert!(
            AuthReply::decode(&[1, 0])
                .unwrap()
                .complete()
                .unwrap()
                .0
                .is_success()
        );
        assert!(
            !AuthReply::decode(&[5, 1])
                .unwrap()
                .complete()
                .unwrap()
                .0
                .is_success()
        );
        assert_eq!(AuthReply::new(false).encode(), [1, 1]);
        assert!(matches!(AuthReply::decode(&[2]), Err(Error::Version(2))));
    }

    #[test]
    fn request_known_answers() {
        // CONNECT example.com:80 by name.
        let wire = b"\x05\x01\x00\x03\x0bexample.com\x00\x50";
        let req = Request::new(Command::Connect, TargetAddr::domain("example.com", 80));
        assert_eq!(req.encode().unwrap(), wire);
        assert_eq!(
            Request::decode(wire).unwrap(),
            Decoded::Complete(req, wire.len())
        );
        for cut in 0..wire.len() {
            assert!(matches!(
                Request::decode(&wire[..cut]).unwrap(),
                Decoded::Incomplete(_)
            ));
        }
        assert!(matches!(
            Request::decode(b"\x05\x09"),
            Err(Error::Command(9))
        ));
        let udp = Request::new(Command::UdpAssociate, TargetAddr::unspecified());
        assert_eq!(udp.encode().unwrap(), [5, 3, 0, 1, 0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn reply_known_answers() {
        let reply = Reply::new(
            ReplyCode::Succeeded,
            TargetAddr::Ip("10.1.2.3:4321".parse().unwrap()),
        );
        let wire = reply.encode().unwrap();
        assert_eq!(wire, [5, 0, 0, 1, 10, 1, 2, 3, 0x10, 0xe1]);
        assert_eq!(Reply::decode(&wire).unwrap(), Decoded::Complete(reply, 10));
        let fail = Reply::failure(ReplyCode::ConnectionRefused)
            .encode()
            .unwrap();
        assert_eq!(fail[1], 5);
        let refused = std::io::Error::from(std::io::ErrorKind::ConnectionRefused);
        assert_eq!(
            ReplyCode::from_io_error(&refused),
            ReplyCode::ConnectionRefused
        );
        let denied = std::io::Error::from(std::io::ErrorKind::PermissionDenied);
        assert_eq!(ReplyCode::from_io_error(&denied), ReplyCode::NotAllowed);
    }

    #[test]
    fn udp_datagrams() {
        let h = UdpHeader::new(TargetAddr::Ip("192.0.2.5:53".parse().unwrap()));
        let d = h.encode_datagram(b"query").unwrap();
        assert_eq!(&d[..10], [0, 0, 0, 1, 192, 0, 2, 5, 0, 53]);
        let (back, payload) = UdpHeader::decode_datagram(&d).unwrap();
        assert_eq!(back, h);
        assert_eq!(payload, b"query");
        assert!(UdpHeader::decode_datagram(&d[..6]).is_err());
        assert!(UdpHeader::decode_datagram(&[0, 0]).is_err());
    }

    #[test]
    fn gssapi_framing() {
        let m = GssapiMessage::new(GssapiMessageType::Authentication, b"tok".to_vec());
        let wire = m.encode().unwrap();
        assert_eq!(wire, b"\x01\x01\x00\x03tok");
        assert_eq!(
            GssapiMessage::decode(&wire).unwrap(),
            Decoded::Complete(m, 7)
        );
        let abort = GssapiMessage::new(GssapiMessageType::Abort, Vec::new());
        assert_eq!(abort.encode().unwrap(), [1, 0xFF]);
        assert_eq!(
            GssapiMessage::decode(&[1, 0xFF]).unwrap(),
            Decoded::Complete(abort, 2)
        );
        assert!(
            GssapiMessage::new(GssapiMessageType::Abort, b"x".to_vec())
                .encode()
                .is_err()
        );
        assert_eq!(
            GssapiMessage::decode(&[1, 2, 0, 9]).unwrap(),
            Decoded::Incomplete(9)
        );
    }
}
