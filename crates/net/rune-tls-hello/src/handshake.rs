//! Handshake messages ([RFC 8446 §4](https://www.rfc-editor.org/rfc/rfc8446#section-4))
//! and a sans-I/O reader that reassembles them from records.

use crate::codec::{Reader, put_vec24};
use crate::record::RECORD_HEADER_LEN;
use crate::{
    Alert, ClientHello, ContentType, Error, HandshakeType, ProtocolVersion, Record, ServerHello,
};

/// Length of a handshake message header: type and 24-bit length.
pub const HANDSHAKE_HEADER_LEN: usize = 4;

/// Default limit on a handshake message body: 64 KiB, enough for hellos
/// and typical certificate chains.
pub const DEFAULT_MAX_HANDSHAKE_LEN: usize = 1 << 16;

/// A handshake message. Hellos are decoded; any other message keeps its
/// body as bytes.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum HandshakeMessage {
    /// A `ClientHello`.
    ClientHello(ClientHello),
    /// A `ServerHello` or `HelloRetryRequest`.
    ServerHello(ServerHello),
    /// Any other message.
    Other {
        /// The message type.
        msg_type: HandshakeType,
        /// The body, without the four-byte header.
        body: Vec<u8>,
    },
}

impl HandshakeMessage {
    /// Decodes a message from its type and body.
    ///
    /// # Errors
    ///
    /// The errors of [`ClientHello::parse`] or [`ServerHello::parse`] for
    /// a malformed hello.
    pub fn from_body(msg_type: HandshakeType, body: &[u8]) -> Result<Self, Error> {
        Ok(match msg_type {
            HandshakeType::CLIENT_HELLO => Self::ClientHello(ClientHello::parse(body)?),
            HandshakeType::SERVER_HELLO => Self::ServerHello(ServerHello::parse(body)?),
            _ => Self::Other {
                msg_type,
                body: body.to_vec(),
            },
        })
    }

    /// Parses the message at the start of `buf`, header included, and
    /// returns it with the number of bytes it took.
    ///
    /// # Errors
    ///
    /// [`Error::Incomplete`] if `buf` ends before the message does, and
    /// the errors of [`HandshakeMessage::from_body`].
    pub fn parse(buf: &[u8]) -> Result<(Self, usize), Error> {
        let (msg_type, len) = header(buf).ok_or_else(|| Error::Incomplete {
            needed: HANDSHAKE_HEADER_LEN.saturating_sub(buf.len()),
        })?;
        let total = HANDSHAKE_HEADER_LEN + len;
        let body = buf
            .get(HANDSHAKE_HEADER_LEN..total)
            .ok_or_else(|| Error::Incomplete {
                needed: total.saturating_sub(buf.len()),
            })?;
        Ok((Self::from_body(msg_type, body)?, total))
    }

    /// The message type.
    #[must_use]
    pub const fn msg_type(&self) -> HandshakeType {
        match self {
            Self::ClientHello(_) => HandshakeType::CLIENT_HELLO,
            Self::ServerHello(_) => HandshakeType::SERVER_HELLO,
            Self::Other { msg_type, .. } => *msg_type,
        }
    }

    /// The encoded message, header included.
    ///
    /// # Errors
    ///
    /// [`Error::TooLong`] if a field does not fit its length prefix.
    pub fn to_bytes(&self) -> Result<Vec<u8>, Error> {
        match self {
            Self::ClientHello(hello) => hello.to_message(),
            Self::ServerHello(hello) => hello.to_message(),
            Self::Other { msg_type, body } => encode_message(*msg_type, body),
        }
    }
}

/// The type and body length from a handshake header, if `buf` holds one.
fn header(buf: &[u8]) -> Option<(HandshakeType, usize)> {
    let mut r = Reader::new(buf);
    let msg_type = HandshakeType(r.u8("handshake header").ok()?);
    let len = r.u24("handshake header").ok()?;
    Some((msg_type, len))
}

/// Encodes a handshake message.
pub fn encode_message(msg_type: HandshakeType, body: &[u8]) -> Result<Vec<u8>, Error> {
    let mut out = Vec::with_capacity(HANDSHAKE_HEADER_LEN + body.len());
    out.push(msg_type.0);
    put_vec24(&mut out, body, "handshake message")?;
    Ok(out)
}

/// Checks the header of a complete message and returns its body.
pub fn parse_message_header(message: &[u8], expected: HandshakeType) -> Result<&[u8], Error> {
    let (msg_type, len) = header(message).ok_or_else(|| Error::Incomplete {
        needed: HANDSHAKE_HEADER_LEN.saturating_sub(message.len()),
    })?;
    if msg_type != expected {
        return Err(Error::UnexpectedHandshakeType {
            expected,
            found: msg_type,
        });
    }
    let rest = message.get(HANDSHAKE_HEADER_LEN..).unwrap_or_default();
    match rest.len().cmp(&len) {
        std::cmp::Ordering::Less => Err(Error::Incomplete {
            needed: len - rest.len(),
        }),
        std::cmp::Ordering::Greater => Err(Error::TrailingBytes {
            what: "handshake message",
            count: rest.len() - len,
        }),
        std::cmp::Ordering::Equal => Ok(rest),
    }
}

/// Reassembles the first handshake message of a record stream, which must
/// be of type `expected`, and returns its body.
pub fn first_message(stream: &[u8], expected: HandshakeType) -> Result<Vec<u8>, Error> {
    let mut assembled = Vec::new();
    let mut rest = stream;
    loop {
        if let Some((msg_type, len)) = header(&assembled) {
            if msg_type != expected {
                return Err(Error::UnexpectedHandshakeType {
                    expected,
                    found: msg_type,
                });
            }
            check_len(len, DEFAULT_MAX_HANDSHAKE_LEN)?;
            let total = HANDSHAKE_HEADER_LEN + len;
            if let Some(body) = assembled.get(HANDSHAKE_HEADER_LEN..total) {
                return Ok(body.to_vec());
            }
        }
        if rest.is_empty() {
            let want = header(&assembled)
                .map_or(HANDSHAKE_HEADER_LEN, |(_, len)| HANDSHAKE_HEADER_LEN + len);
            return Err(Error::Incomplete {
                needed: want.saturating_sub(assembled.len()) + RECORD_HEADER_LEN,
            });
        }
        let (record, used) = Record::parse(rest)?;
        rest = rest.get(used..).unwrap_or_default();
        if record.content_type != ContentType::HANDSHAKE {
            return Err(Error::UnexpectedContentType {
                expected: ContentType::HANDSHAKE,
                found: record.content_type,
            });
        }
        if record.fragment.is_empty() {
            return Err(empty_handshake_record());
        }
        assembled.extend_from_slice(record.fragment);
    }
}

const fn check_len(len: usize, max: usize) -> Result<(), Error> {
    if len > max {
        Err(Error::TooLong {
            what: "handshake message",
            len,
            max,
        })
    } else {
        Ok(())
    }
}

const fn empty_handshake_record() -> Error {
    Error::Malformed {
        what: "handshake record",
        reason: "empty fragment",
    }
}

/// One message read from a TLS stream by [`MessageReader`].
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Message {
    /// A complete handshake message, reassembled across records.
    Handshake(HandshakeMessage),
    /// An alert.
    Alert(Alert),
    /// A `change_cipher_spec` record's body (normally `[1]`).
    ChangeCipherSpec(Vec<u8>),
    /// A handshake record after `change_cipher_spec`: encrypted, so its
    /// bytes are returned as they are (a TLS 1.2 Finished, for instance).
    EncryptedHandshake(Vec<u8>),
    /// An `application_data` record's body; ciphertext, and in TLS 1.3
    /// also the encrypted handshake.
    ApplicationData(Vec<u8>),
    /// A `heartbeat` record's body.
    Heartbeat(Vec<u8>),
}

/// A sans-I/O reader of one direction of a TLS stream: feed it bytes as
/// they arrive and take whole messages out.
///
/// Handshake messages are reassembled across records, and several messages
/// in one record come out one by one. After a `change_cipher_spec`, handshake
/// records are encrypted and come out as [`Message::EncryptedHandshake`].
/// After an error the stream is not valid TLS; stop reading it.
///
/// ```
/// use rune_tls_hello::{ClientHello, HandshakeMessage, Message, MessageReader, ProtocolVersion};
///
/// let hello = ClientHello::new().with_random([1; 32]);
/// let bytes = hello.to_records(ProtocolVersion::TLS_1_0, 16)?;
///
/// let mut reader = MessageReader::new();
/// let (first, second) = bytes.split_at(20);
/// reader.feed(first);
/// assert_eq!(reader.next_message()?, None); // needs more bytes
/// reader.feed(second);
/// assert_eq!(
///     reader.next_message()?,
///     Some(Message::Handshake(HandshakeMessage::ClientHello(hello)))
/// );
/// # Ok::<(), rune_tls_hello::Error>(())
/// ```
#[derive(Debug, Clone)]
pub struct MessageReader {
    input: Vec<u8>,
    /// Bytes at the front of `input` already parsed. They are dropped in
    /// bulk, so reading many small records stays linear.
    consumed: usize,
    handshake: Vec<u8>,
    max_handshake_len: usize,
    record_version: Option<ProtocolVersion>,
    encrypted: bool,
}

impl Default for MessageReader {
    fn default() -> Self {
        Self {
            input: Vec::new(),
            consumed: 0,
            handshake: Vec::new(),
            max_handshake_len: DEFAULT_MAX_HANDSHAKE_LEN,
            record_version: None,
            encrypted: false,
        }
    }
}

impl MessageReader {
    /// A reader with the [`DEFAULT_MAX_HANDSHAKE_LEN`] limit.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the largest handshake message body to accept.
    #[must_use]
    pub const fn with_max_handshake_len(mut self, max: usize) -> Self {
        self.max_handshake_len = max;
        self
    }

    /// Appends bytes received from the peer.
    pub fn feed(&mut self, bytes: &[u8]) {
        self.input.extend_from_slice(bytes);
    }

    /// Bytes fed but not yet returned as messages.
    #[must_use]
    pub const fn buffered_len(&self) -> usize {
        self.input.len() - self.consumed + self.handshake.len()
    }

    /// The version of the last record read, if any.
    #[must_use]
    pub const fn record_version(&self) -> Option<ProtocolVersion> {
        self.record_version
    }

    /// The next complete message, or `None` until more bytes are fed.
    ///
    /// # Errors
    ///
    /// The errors of [`Record::parse`] (except [`Error::Incomplete`]);
    /// [`Error::TooLong`] for a handshake message over the limit;
    /// [`Error::Malformed`] for an empty handshake record, a handshake
    /// message interrupted by another content type, or an alert record
    /// that is not two bytes; and the errors of [`ClientHello::parse`] and
    /// [`ServerHello::parse`] for malformed hellos.
    pub fn next_message(&mut self) -> Result<Option<Message>, Error> {
        loop {
            if let Some((msg_type, len)) = header(&self.handshake) {
                check_len(len, self.max_handshake_len)?;
                let total = HANDSHAKE_HEADER_LEN + len;
                if let Some(body) = self.handshake.get(HANDSHAKE_HEADER_LEN..total) {
                    let message = HandshakeMessage::from_body(msg_type, body);
                    self.handshake.drain(..total);
                    return message.map(|m| Some(Message::Handshake(m)));
                }
            }
            let unread = self.input.get(self.consumed..).unwrap_or_default();
            let (record, used) = match Record::parse(unread) {
                Ok(parsed) => parsed,
                Err(Error::Incomplete { .. }) => {
                    self.compact();
                    return Ok(None);
                }
                Err(err) => return Err(err),
            };
            self.record_version = Some(record.version);
            let content_type = record.content_type;
            let fragment = record.fragment.to_vec();
            self.consumed += used;
            if self.consumed * 2 >= self.input.len() {
                self.compact();
            }

            if content_type == ContentType::HANDSHAKE && !self.encrypted {
                if fragment.is_empty() {
                    return Err(empty_handshake_record());
                }
                self.handshake.extend_from_slice(&fragment);
                continue;
            }
            if !self.handshake.is_empty() {
                return Err(Error::Malformed {
                    what: "record stream",
                    reason: "handshake message interrupted by another content type",
                });
            }
            let message = match content_type {
                ContentType::HANDSHAKE => Message::EncryptedHandshake(fragment),
                ContentType::ALERT => Message::Alert(Alert::parse(&fragment)?),
                ContentType::CHANGE_CIPHER_SPEC => {
                    self.encrypted = true;
                    Message::ChangeCipherSpec(fragment)
                }
                ContentType::HEARTBEAT => Message::Heartbeat(fragment),
                _ => Message::ApplicationData(fragment),
            };
            return Ok(Some(message));
        }
    }

    /// Drops the parsed bytes from the front of the input buffer.
    fn compact(&mut self) {
        self.input.drain(..self.consumed);
        self.consumed = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AlertDescription, AlertLevel, encode_records};

    #[test]
    fn reads_several_messages_from_one_record() {
        let hello = ServerHello::new().with_random([2; 32]);
        let mut flight = hello.to_message().unwrap();
        flight.extend(encode_message(HandshakeType::SERVER_HELLO_DONE, &[]).unwrap());
        let mut bytes = encode_records(
            ContentType::HANDSHAKE,
            ProtocolVersion::TLS_1_2,
            &flight,
            1000,
        )
        .unwrap();
        bytes.extend([20, 3, 3, 0, 1, 1]);
        bytes.extend([22, 3, 3, 0, 3, 9, 9, 9]);
        bytes.extend([21, 3, 3, 0, 2, 2, 40]);

        let mut reader = MessageReader::new();
        reader.feed(&bytes);
        assert_eq!(
            reader.next_message().unwrap(),
            Some(Message::Handshake(HandshakeMessage::ServerHello(hello)))
        );
        assert_eq!(
            reader.next_message().unwrap(),
            Some(Message::Handshake(HandshakeMessage::Other {
                msg_type: HandshakeType::SERVER_HELLO_DONE,
                body: Vec::new()
            }))
        );
        assert_eq!(
            reader.next_message().unwrap(),
            Some(Message::ChangeCipherSpec(vec![1]))
        );
        assert_eq!(
            reader.next_message().unwrap(),
            Some(Message::EncryptedHandshake(vec![9, 9, 9]))
        );
        assert_eq!(
            reader.next_message().unwrap(),
            Some(Message::Alert(Alert::new(
                AlertLevel::FATAL,
                AlertDescription::HANDSHAKE_FAILURE
            )))
        );
        assert_eq!(reader.next_message().unwrap(), None);
        assert_eq!(reader.buffered_len(), 0);
        assert_eq!(reader.record_version(), Some(ProtocolVersion::TLS_1_2));
    }

    #[test]
    fn many_small_records_take_linear_time() {
        // 1 MiB of empty application data records, fed at once.
        let records = (4 << 20) / RECORD_HEADER_LEN;
        let mut reader = MessageReader::new();
        reader.feed(&[23, 3, 3, 0, 0].repeat(records));
        let started = std::time::Instant::now();
        let mut count = 0;
        while let Some(message) = reader.next_message().unwrap() {
            assert_eq!(message, Message::ApplicationData(Vec::new()));
            count += 1;
        }
        let elapsed = started.elapsed();
        assert_eq!(count, records);
        assert_eq!(reader.buffered_len(), 0);
        assert!(
            elapsed < std::time::Duration::from_secs(2),
            "{records} records took {elapsed:?}"
        );
    }

    #[test]
    fn rejects_interleaving_and_oversize() {
        let mut reader = MessageReader::new();
        reader.feed(&[22, 3, 3, 0, 2, 1, 0]);
        reader.feed(&[21, 3, 3, 0, 2, 2, 40]);
        assert!(matches!(
            reader.next_message(),
            Err(Error::Malformed { .. })
        ));

        let mut reader = MessageReader::new().with_max_handshake_len(10);
        reader.feed(&[22, 3, 3, 0, 4, 11, 0, 0, 11]);
        assert!(matches!(reader.next_message(), Err(Error::TooLong { .. })));

        let mut reader = MessageReader::new();
        reader.feed(&[22, 3, 3, 0, 0]);
        assert!(reader.next_message().is_err());
    }

    #[test]
    fn first_message_reports_what_is_missing() {
        let hello = ClientHello::new()
            .to_records(ProtocolVersion::TLS_1_0, 20)
            .unwrap();
        for len in 0..hello.len() {
            assert!(
                matches!(
                    ClientHello::parse_records(&hello[..len]),
                    Err(Error::Incomplete { needed }) if needed > 0
                ),
                "prefix {len}"
            );
        }
        assert!(ClientHello::parse_records(&hello).is_ok());
        assert_eq!(
            ClientHello::parse_records(&[21, 3, 3, 0, 2, 2, 40]),
            Err(Error::UnexpectedContentType {
                expected: ContentType::HANDSHAKE,
                found: ContentType::ALERT
            })
        );
        assert!(matches!(
            ClientHello::parse_records(&[22, 3, 1, 0, 4, 1, 0xff, 0, 0]),
            Err(Error::TooLong { .. })
        ));
    }

    #[test]
    fn parses_other_messages() {
        let bytes = [11, 0, 0, 2, 0xab, 0xcd, 0xff];
        let (message, used) = HandshakeMessage::parse(&bytes).unwrap();
        assert_eq!(used, 6);
        assert_eq!(message.msg_type(), HandshakeType::CERTIFICATE);
        assert_eq!(message.to_bytes().unwrap(), bytes[..6]);
        assert_eq!(
            HandshakeMessage::parse(&bytes[..3]),
            Err(Error::Incomplete { needed: 1 })
        );
        assert_eq!(
            HandshakeMessage::parse(&bytes[..5]),
            Err(Error::Incomplete { needed: 1 })
        );
    }
}
