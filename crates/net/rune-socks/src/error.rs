//! The crate's error type.

use crate::v4::Socks4Status;
use crate::v5::{AuthMethod, ReplyCode};

/// Errors returned by the codecs and the tokio client and server.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// A message carries an unexpected protocol version byte.
    #[error("unexpected SOCKS version byte {0:#04x}")]
    Version(u8),
    /// A request carries an unknown command.
    #[error("unknown SOCKS command {0:#04x}")]
    Command(u8),
    /// A SOCKS5 address has an unknown address type.
    #[error("unknown SOCKS5 address type {0:#04x}")]
    AddressType(u8),
    /// A message is structurally invalid.
    #[error("invalid SOCKS message: {0}")]
    Invalid(&'static str),
    /// A field is longer than the protocol allows (255 bytes for names,
    /// user ids and credentials, 65 535 for GSSAPI tokens).
    #[error("{0} is too long")]
    TooLong(&'static str),
    /// A value cannot be expressed in the chosen protocol version (an IPv6
    /// address in SOCKS4, for example).
    #[error("cannot encode: {0}")]
    NotRepresentable(&'static str),
    /// The SOCKS5 server accepted none of the offered methods.
    #[error("the SOCKS5 server accepted none of the offered authentication methods")]
    NoAcceptableMethod,
    /// The SOCKS5 server selected a method this client does not implement
    /// (GSSAPI) or did not offer.
    #[error("the SOCKS5 server selected unsupported method {0:?}")]
    UnsupportedMethod(AuthMethod),
    /// The SOCKS5 server rejected the username and password.
    #[error("SOCKS5 username/password authentication failed")]
    AuthFailed,
    /// The SOCKS5 server refused the request.
    #[error("SOCKS5 request failed: {0:?}")]
    Rejected(ReplyCode),
    /// The SOCKS4 server refused the request.
    #[error("SOCKS4 request failed: {0:?}")]
    Socks4Rejected(Socks4Status),
    /// An I/O error from the tokio adapters.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}
