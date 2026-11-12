//! The crate's error type.

use crate::close::CloseCode;

/// Everything that can go wrong while framing, handshaking or running a
/// WebSocket connection.
///
/// Protocol violations map to the close code the endpoint should send with
/// [`Error::close_code`].
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// A frame used an opcode that RFC 6455 reserves (`0x3`–`0x7`, `0xB`–`0xF`).
    #[error("reserved opcode {0:#x}")]
    ReservedOpcode(u8),
    /// A frame set an RSV bit that no negotiated extension defines.
    #[error("reserved bits set without a negotiated extension (rsv = {0:#05b})")]
    ReservedBits(u8),
    /// A control frame was fragmented (FIN clear).
    #[error("fragmented control frame")]
    FragmentedControl,
    /// A control frame carried more than 125 bytes of payload.
    #[error("control frame payload of {0} bytes exceeds 125")]
    ControlTooLong(u64),
    /// The payload length did not use the minimal encoding, or used the
    /// most significant bit of the 64-bit form.
    #[error("invalid payload length encoding")]
    InvalidLength,
    /// A frame's payload is larger than the configured limit.
    #[error("frame payload of {len} bytes exceeds the limit of {max}")]
    FrameTooLarge {
        /// The declared payload length.
        len: u64,
        /// The configured limit.
        max: u64,
    },
    /// A reassembled (and possibly decompressed) message exceeds the limit.
    #[error("message exceeds the limit of {max} bytes")]
    MessageTooLarge {
        /// The configured limit.
        max: usize,
    },
    /// A client sent an unmasked frame to a server.
    #[error("frame from client is not masked")]
    UnmaskedFrame,
    /// A server sent a masked frame to a client.
    #[error("frame from server is masked")]
    MaskedFrame,
    /// A continuation frame arrived with no fragmented message in progress.
    #[error("continuation frame without a message in progress")]
    UnexpectedContinuation,
    /// A new data frame arrived while a fragmented message was in progress.
    #[error("data frame while a fragmented message is in progress")]
    ExpectedContinuation,
    /// A text message or close reason was not valid UTF-8.
    #[error("invalid UTF-8 in text payload")]
    InvalidUtf8,
    /// A close frame payload was one byte long.
    #[error("malformed close frame payload")]
    InvalidClosePayload,
    /// A close frame carried a code that must not appear on the wire.
    #[error("invalid close code {0}")]
    InvalidCloseCode(u16),
    /// A message could not be sent: the connection is closing or closed.
    #[error("connection is closed")]
    Closed,
    /// An HTTP upgrade head exceeded the size limit before it was complete.
    #[error("handshake head exceeds {0} bytes")]
    HeadTooLarge(usize),
    /// An HTTP upgrade head could not be parsed.
    #[error("malformed HTTP head: {0}")]
    MalformedHead(&'static str),
    /// The upgrade request or response is missing a required header or has
    /// a wrong value in one.
    #[error("invalid handshake: {0}")]
    Handshake(&'static str),
    /// The client asked for a protocol version other than 13.
    #[error("unsupported WebSocket version {0:?}")]
    UnsupportedVersion(String),
    /// The server answered the upgrade with a status other than 101.
    #[error("server rejected the upgrade with status {0}")]
    Rejected(u16),
    /// The server's `Sec-WebSocket-Accept` does not match the key sent.
    #[error("Sec-WebSocket-Accept does not match the key")]
    AcceptMismatch,
    /// An extension negotiation or permessage-deflate payload was invalid.
    #[error("extension error: {0}")]
    Extension(String),
    /// The transport ended before the close handshake completed.
    #[error("connection closed without a close handshake")]
    UnexpectedEof,
    /// An I/O error from the transport (async adapter only).
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

impl Error {
    /// The close code an endpoint should send when it fails the connection
    /// because of this error (RFC 6455 §7.4.1).
    #[must_use]
    pub const fn close_code(&self) -> CloseCode {
        match self {
            Self::InvalidUtf8 => CloseCode::INVALID_PAYLOAD,
            Self::FrameTooLarge { .. } | Self::MessageTooLarge { .. } => CloseCode::TOO_BIG,
            Self::Io(_) | Self::UnexpectedEof | Self::Closed => CloseCode::ABNORMAL,
            _ => CloseCode::PROTOCOL_ERROR,
        }
    }
}

/// Shorthand for `Result<T, rune_ws::Error>`.
pub type Result<T, E = Error> = std::result::Result<T, E>;
