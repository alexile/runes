//! SOCKS4, SOCKS 4a and SOCKS5 ([RFC 1928]) for clients and servers.
//!
//! The core is sans-I/O: every message has an `encode` method and a
//! `decode` function that works on the front of a byte buffer and returns
//! [`Decoded::Incomplete`] with the exact number of bytes still needed, so
//! a caller never reads past a message. Covered:
//!
//! - SOCKS4/4a ([`v4`]): `CONNECT` and `BIND` requests, user ids, host
//!   names (4a) and replies.
//! - SOCKS5 ([`v5`]): method negotiation, `CONNECT`, `BIND` and
//!   `UDP ASSOCIATE` requests and replies, IPv4/IPv6/host name addresses,
//!   the UDP datagram header, username/password authentication
//!   ([RFC 1929]) and GSSAPI message framing ([RFC 1961]; the GSSAPI
//!   exchange itself is left to the caller).
//!
//! The `tokio` feature adds a [`Client`](crate::tokio::Client) that dials
//! through a proxy and a [`Server`](crate::tokio::Server) that forwards
//! through a pluggable [`Connector`](crate::tokio::Connector), with a
//! `UDP ASSOCIATE` relay.
//!
//! [RFC 1928]: https://www.rfc-editor.org/rfc/rfc1928
//! [RFC 1929]: https://www.rfc-editor.org/rfc/rfc1929
//! [RFC 1961]: https://www.rfc-editor.org/rfc/rfc1961
//!
//! # Example
//!
//! ```
//! use rune_socks::v5::{AuthMethod, Command, Greeting, MethodSelection, Reply, ReplyCode, Request};
//! use rune_socks::{Decoded, TargetAddr};
//!
//! // Client side: offer "no authentication", then ask for a CONNECT.
//! let greeting = Greeting::new([AuthMethod::NoAuth]).encode()?;
//! assert_eq!(greeting, [5, 1, 0]);
//! let request = Request::new(Command::Connect, TargetAddr::domain("example.com", 443)).encode()?;
//!
//! // Server side: decode incrementally, choose a method, reply.
//! let Decoded::Complete(offer, _) = Greeting::decode(&greeting)? else { unreachable!() };
//! let method = offer.select(&[AuthMethod::NoAuth]);
//! assert_eq!(MethodSelection::new(method).encode(), [5, 0]);
//! assert_eq!(Request::decode(&request[..4])?, Decoded::Incomplete(1));
//! let (req, len) = Request::decode(&request)?.complete().expect("whole request");
//! assert_eq!(len, request.len());
//! assert_eq!(req.target.to_string(), "example.com:443");
//! let reply = Reply::new(ReplyCode::Succeeded, "10.0.0.1:50000".parse::<std::net::SocketAddr>()?.into());
//! assert_eq!(reply.encode()?.len(), 10);
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod addr;
mod error;
#[cfg(feature = "tokio")]
pub mod tokio;
pub mod v4;
pub mod v5;

pub use addr::{Decoded, TargetAddr};
pub use error::Error;
