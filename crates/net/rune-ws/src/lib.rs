//! Sans-I/O WebSocket: [RFC 6455] framing, the opening handshake and a
//! connection state machine, with [RFC 7692] permessage-deflate behind the
//! `deflate` feature and an async adapter behind `tokio`.
//!
//! The crate is layered so that each piece is usable on its own:
//!
//! - **Frames** — [`Frame`], [`OpCode`], [`apply_mask`], [`decode_frame`]
//!   and the incremental [`FrameDecoder`]. Decoded frames keep their
//!   masking key and re-encode byte-for-byte, so a proxy can inspect or
//!   rewrite traffic without terminating the connection.
//! - **Handshake** — [`parse_request`] / [`parse_response`] for the
//!   HTTP/1.1 upgrade heads, [`accept_key`], [`ClientHandshake`] and
//!   [`ServerHandshake`] for validation and subprotocol / extension
//!   negotiation.
//! - **Connection** — [`Connection`] reassembles fragmented messages,
//!   validates UTF-8 (failing fast on a bad fragment), answers pings,
//!   runs the close handshake, enforces masking direction and size limits,
//!   and fails the connection with the right close code on any violation.
//! - **Async** — `WebSocket` (feature `tokio`) drives a [`Connection`]
//!   over any `AsyncRead + AsyncWrite` stream.
//!
//! No layer does I/O except the `tokio` adapter.
//!
//! [RFC 6455]: https://www.rfc-editor.org/rfc/rfc6455
//! [RFC 7692]: https://www.rfc-editor.org/rfc/rfc7692
//!
//! # Example
//!
//! A full client/server exchange, entirely in memory:
//!
//! ```
//! use rune_ws::{
//!     ClientHandshake, CloseCode, CloseFrame, Connection, Message, Options, ServerHandshake,
//!     parse_request, parse_response,
//! };
//!
//! // Opening handshake.
//! let client_hs = ClientHandshake::new("example.com", "/ws", [42; 16]);
//! let (request, _) = parse_request(&client_hs.request_bytes(), 16 * 1024)?.unwrap();
//! let (reply, server_agreed) = ServerHandshake::default().accept(&request)?;
//! let (response, _) = parse_response(&reply, 16 * 1024)?.unwrap();
//! let client_agreed = client_hs.verify(&response)?;
//!
//! let mut server = Connection::server(Options::default()).with_negotiated(&server_agreed);
//! let mut client =
//!     Connection::client(Options::default(), || [0x37, 0xfa, 0x21, 0x3d])
//!         .with_negotiated(&client_agreed);
//!
//! // Messages.
//! client.send(Message::Text("Hello".into()))?;
//! assert_eq!(
//!     client.outgoing(),
//!     [0x81, 0x85, 0x37, 0xfa, 0x21, 0x3d, 0x7f, 0x9f, 0x4d, 0x51, 0x58], // RFC 6455 §5.7
//! );
//! server.receive(&client.take_outgoing());
//! assert_eq!(server.next_message().unwrap()?, Message::Text("Hello".into()));
//!
//! // Closing handshake.
//! server.close(Some(CloseFrame::new(CloseCode::GOING_AWAY, "restart")))?;
//! client.receive(&server.take_outgoing());
//! assert!(matches!(client.next_message().unwrap()?, Message::Close(Some(_))));
//! server.receive(&client.take_outgoing()); // the echoed close
//! assert!(matches!(server.next_message().unwrap()?, Message::Close(_)));
//! assert!(client.is_closed() && server.is_closed());
//! # Ok::<(), rune_ws::Error>(())
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![cfg_attr(docsrs, feature(doc_cfg))]

mod close;
mod connection;
#[cfg(feature = "deflate")]
mod deflate;
mod error;
mod frame;
mod handshake;
#[cfg(feature = "tokio")]
mod tokio_io;

pub use close::{CloseCode, CloseFrame};
pub use connection::{Connection, Message, Options, Role, State};
#[cfg(feature = "deflate")]
pub use deflate::{DeflateConfig, DeflateParams, Extension, parse_extensions};
pub use error::{Error, Result};
pub use frame::{
    DecoderOptions, Frame, FrameDecoder, MAX_CONTROL_PAYLOAD, MaskPolicy, OpCode, RSV1, RSV2, RSV3,
    apply_mask, decode_frame,
};
pub use handshake::{
    ClientHandshake, DEFAULT_MAX_HEAD, GUID, Headers, Negotiated, Request, Response,
    ServerHandshake, accept_key, key_from_nonce, parse_request, parse_response, reject_bad_request,
    reject_version,
};
#[cfg(feature = "tokio")]
pub use tokio_io::{WebSocket, random_nonce};
