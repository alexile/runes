//! The sans-I/O connection state machine that runs after the handshake:
//! message reassembly, control frames, the close handshake and, when
//! negotiated, permessage-deflate.

use std::fmt;

use crate::close::{CloseCode, CloseFrame};
use crate::error::{Error, Result};
use crate::frame::{
    DecoderOptions, Frame, FrameDecoder, MAX_CONTROL_PAYLOAD, MaskPolicy, OpCode, RSV1,
};
use crate::handshake::Negotiated;

/// Which end of the connection this endpoint is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Role {
    /// Masks every frame it sends; rejects masked frames.
    Client,
    /// Sends unmasked frames; rejects unmasked frames.
    Server,
}

/// Where the connection is in its lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum State {
    /// Messages flow both ways.
    Open,
    /// We sent a close frame and are waiting for the peer's.
    Closing,
    /// Both close frames were exchanged, or the connection failed. The
    /// transport should be closed once [`Connection::outgoing`] is flushed.
    Closed,
}

/// A complete message or control frame.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Message {
    /// A UTF-8 text message.
    Text(String),
    /// A binary message.
    Binary(Vec<u8>),
    /// A ping with its application data.
    Ping(Vec<u8>),
    /// A pong with its application data.
    Pong(Vec<u8>),
    /// A close frame; `None` when it carried no status code.
    Close(Option<CloseFrame>),
}

/// Connection limits and behaviour.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Options {
    /// Largest single frame accepted. Default: 16 MiB.
    pub max_frame_size: u64,
    /// Largest reassembled (and decompressed) message accepted.
    /// Default: 64 MiB.
    pub max_message_size: usize,
    /// Answer pings with pongs automatically. Default: `true`.
    pub auto_pong: bool,
    /// Split outgoing data messages into frames of at most this many
    /// payload bytes. Default: `None` (one frame per message).
    pub send_fragment_size: Option<usize>,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            max_frame_size: 16 << 20,
            max_message_size: 64 << 20,
            auto_pong: true,
            send_fragment_size: None,
        }
    }
}

impl Options {
    /// Sets [`max_frame_size`](Self::max_frame_size).
    #[must_use]
    pub const fn with_max_frame_size(mut self, max: u64) -> Self {
        self.max_frame_size = max;
        self
    }

    /// Sets [`max_message_size`](Self::max_message_size).
    #[must_use]
    pub const fn with_max_message_size(mut self, max: usize) -> Self {
        self.max_message_size = max;
        self
    }

    /// Sets [`auto_pong`](Self::auto_pong).
    #[must_use]
    pub const fn with_auto_pong(mut self, on: bool) -> Self {
        self.auto_pong = on;
        self
    }

    /// Sets [`send_fragment_size`](Self::send_fragment_size); `Some(0)` is
    /// treated as `None`.
    #[must_use]
    pub const fn with_send_fragment_size(mut self, size: Option<usize>) -> Self {
        self.send_fragment_size = match size {
            Some(0) => None,
            other => other,
        };
        self
    }
}

/// A fragmented message being reassembled.
#[derive(Debug)]
struct Partial {
    text: bool,
    compressed: bool,
    data: Vec<u8>,
    /// Prefix of `data` already validated as UTF-8 (uncompressed text).
    utf8_checked: usize,
}

#[cfg(feature = "deflate")]
#[derive(Debug)]
struct Deflate {
    compressor: crate::deflate::Compressor,
    decompressor: crate::deflate::Decompressor,
    threshold: usize,
}

type MaskSource = Box<dyn FnMut() -> [u8; 4] + Send>;

/// A WebSocket endpoint after a successful handshake.
///
/// It does no I/O: feed it received bytes with [`receive`](Self::receive), pull messages
/// with [`next_message`](Self::next_message), queue messages with
/// [`send`](Self::send), and write [`outgoing`](Self::outgoing) bytes to
/// the transport.
///
/// Pings are answered and close frames are echoed automatically; those
/// replies appear in the outgoing buffer. A protocol violation fails the
/// connection: a close frame with the matching code is queued, the state
/// becomes [`State::Closed`], and the error is returned once.
///
/// ```
/// use rune_ws::{Connection, Message, Options};
///
/// let mut server = Connection::server(Options::default());
/// let mut client = Connection::client(Options::default(), || [1, 2, 3, 4]);
///
/// client.send(Message::Text("hi".into()))?;
/// server.receive(&client.take_outgoing());
/// assert_eq!(server.next_message().unwrap()?, Message::Text("hi".into()));
///
/// server.send(Message::Ping(b"?".to_vec()))?;
/// client.receive(&server.take_outgoing());
/// assert_eq!(client.next_message().unwrap()?, Message::Ping(b"?".to_vec()));
/// server.receive(&client.take_outgoing()); // the automatic pong
/// assert_eq!(server.next_message().unwrap()?, Message::Pong(b"?".to_vec()));
/// # Ok::<(), rune_ws::Error>(())
/// ```
pub struct Connection {
    role: Role,
    options: Options,
    decoder: FrameDecoder,
    out: Vec<u8>,
    state: State,
    partial: Option<Partial>,
    masks: Option<MaskSource>,
    #[cfg(feature = "deflate")]
    deflate: Option<Deflate>,
}

impl fmt::Debug for Connection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Connection")
            .field("role", &self.role)
            .field("state", &self.state)
            .field("options", &self.options)
            .field("outgoing", &self.out.len())
            .finish_non_exhaustive()
    }
}

impl Connection {
    fn new(role: Role, options: Options, masks: Option<MaskSource>) -> Self {
        let policy = match role {
            Role::Client => MaskPolicy::Forbidden,
            Role::Server => MaskPolicy::Required,
        };
        let decoder = FrameDecoder::new(
            DecoderOptions::default()
                .with_max_payload(options.max_frame_size)
                .with_mask(policy),
        );
        Self {
            role,
            options,
            decoder,
            out: Vec::new(),
            state: State::Open,
            partial: None,
            masks,
            #[cfg(feature = "deflate")]
            deflate: None,
        }
    }

    /// A server endpoint.
    #[must_use]
    pub fn server(options: Options) -> Self {
        Self::new(Role::Server, options, None)
    }

    /// A client endpoint. `masks` supplies a masking key for every frame;
    /// RFC 6455 §5.3 requires keys to be unpredictable, so use a
    /// cryptographically strong source in production (the async adapter
    /// uses the OS-seeded RNG).
    pub fn client(options: Options, masks: impl FnMut() -> [u8; 4] + Send + 'static) -> Self {
        Self::new(Role::Client, options, Some(Box::new(masks)))
    }

    /// Applies what the handshake negotiated (permessage-deflate, when the
    /// `deflate` feature is on).
    #[must_use]
    #[cfg_attr(
        not(feature = "deflate"),
        allow(unused_variables, unused_mut, clippy::missing_const_for_fn)
    )]
    pub fn with_negotiated(mut self, negotiated: &Negotiated) -> Self {
        #[cfg(feature = "deflate")]
        if let Some(params) = negotiated.deflate {
            self = self.with_deflate(params);
        }
        self
    }

    /// Enables permessage-deflate with negotiated parameters.
    #[cfg(feature = "deflate")]
    #[must_use]
    pub fn with_deflate(mut self, params: crate::deflate::DeflateParams) -> Self {
        let (ours, theirs) = match self.role {
            Role::Server => (
                params.server_no_context_takeover,
                params.client_no_context_takeover,
            ),
            Role::Client => (
                params.client_no_context_takeover,
                params.server_no_context_takeover,
            ),
        };
        self.deflate = Some(Deflate {
            compressor: crate::deflate::Compressor::new(params.level, ours),
            decompressor: crate::deflate::Decompressor::new(theirs),
            threshold: params.threshold,
        });
        let options = self.decoder.options().clone().with_allowed_rsv(RSV1);
        self.decoder.set_options(options);
        self
    }

    /// This endpoint's role.
    #[must_use]
    pub const fn role(&self) -> Role {
        self.role
    }

    /// The current state.
    #[must_use]
    pub const fn state(&self) -> State {
        self.state
    }

    /// Whether the connection is closed and the transport can be shut down
    /// once the outgoing buffer is flushed.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.state == State::Closed
    }

    /// Feeds bytes received from the transport. Ignored once closed.
    pub fn receive(&mut self, data: &[u8]) {
        if self.state != State::Closed {
            self.decoder.push(data);
        }
    }

    /// The next complete message, or `None` until more bytes arrive (and
    /// always `None` once closed).
    pub fn next_message(&mut self) -> Option<Result<Message>> {
        while self.state != State::Closed {
            let frame = match self.decoder.next_frame()? {
                Ok(frame) => frame,
                Err(err) => return Some(Err(self.fail(err))),
            };
            match self.handle_frame(frame) {
                Ok(Some(message)) => return Some(Ok(message)),
                Ok(None) => {}
                Err(err) => return Some(Err(self.fail(err))),
            }
        }
        None
    }

    /// Bytes waiting to be written to the transport.
    #[must_use]
    pub fn outgoing(&self) -> &[u8] {
        &self.out
    }

    /// Marks the first `n` outgoing bytes as written.
    pub fn consume_outgoing(&mut self, n: usize) {
        self.out.drain(..n.min(self.out.len()));
    }

    /// Takes every outgoing byte.
    pub fn take_outgoing(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.out)
    }

    /// Queues a message. [`Message::Close`] starts the close handshake.
    ///
    /// # Errors
    ///
    /// [`Error::Closed`] after the close handshake has started,
    /// [`Error::ControlTooLong`] for a ping, pong or close payload over 125
    /// bytes, and [`Error::InvalidCloseCode`] for a close code that may
    /// not be sent.
    pub fn send(&mut self, message: Message) -> Result<()> {
        if self.state != State::Open {
            return Err(Error::Closed);
        }
        match message {
            Message::Text(text) => self.send_data(OpCode::Text, text.into_bytes()),
            Message::Binary(data) => self.send_data(OpCode::Binary, data),
            Message::Ping(data) => self.send_control(OpCode::Ping, data),
            Message::Pong(data) => self.send_control(OpCode::Pong, data),
            Message::Close(close) => self.close(close),
        }
    }

    /// Starts the close handshake.
    ///
    /// # Errors
    ///
    /// As for [`send`](Self::send).
    #[allow(
        clippy::needless_pass_by_value,
        reason = "owned argument keeps call sites simple"
    )]
    pub fn close(&mut self, close: Option<CloseFrame>) -> Result<()> {
        if self.state != State::Open {
            return Err(Error::Closed);
        }
        if let Some(frame) = &close
            && !frame.code.is_valid_on_wire()
        {
            return Err(Error::InvalidCloseCode(frame.code.0));
        }
        self.send_control(OpCode::Close, Frame::close(close.as_ref()).payload)?;
        self.state = State::Closing;
        Ok(())
    }

    fn write(&mut self, frame: Frame) {
        let mask = self.masks.as_mut().map(|next| next());
        frame.with_mask(mask).encode(&mut self.out);
    }

    fn send_control(&mut self, opcode: OpCode, payload: Vec<u8>) -> Result<()> {
        if payload.len() > MAX_CONTROL_PAYLOAD {
            return Err(Error::ControlTooLong(payload.len() as u64));
        }
        self.write(Frame::new(opcode, payload));
        Ok(())
    }

    #[cfg_attr(not(feature = "deflate"), allow(clippy::unnecessary_wraps))]
    fn send_data(&mut self, opcode: OpCode, payload: Vec<u8>) -> Result<()> {
        #[cfg(feature = "deflate")]
        let (payload, rsv) = match &mut self.deflate {
            Some(deflate) if payload.len() >= deflate.threshold => {
                (deflate.compressor.compress(&payload)?, RSV1)
            }
            _ => (payload, 0),
        };
        #[cfg(not(feature = "deflate"))]
        let rsv = 0;
        let size = self.options.send_fragment_size.unwrap_or(usize::MAX);
        if payload.len() <= size {
            self.write(Frame::new(opcode, payload).with_rsv(rsv));
            return Ok(());
        }
        let count = payload.len().div_ceil(size);
        for (index, chunk) in payload.chunks(size).enumerate() {
            let (opcode, rsv) = if index == 0 {
                (opcode, rsv)
            } else {
                (OpCode::Continuation, 0)
            };
            self.write(
                Frame::new(opcode, chunk)
                    .with_rsv(rsv)
                    .with_fin(index + 1 == count),
            );
        }
        Ok(())
    }

    /// Fails the connection: queues a close frame with the error's code if
    /// none was sent yet.
    fn fail(&mut self, err: Error) -> Error {
        if self.state == State::Open {
            let code = err.close_code();
            let close = (code != CloseCode::ABNORMAL).then(|| CloseFrame::new(code, ""));
            self.write(Frame::close(close.as_ref()));
        }
        self.state = State::Closed;
        self.partial = None;
        err
    }

    fn handle_frame(&mut self, frame: Frame) -> Result<Option<Message>> {
        if frame.opcode.is_control() && frame.rsv != 0 {
            return Err(Error::ReservedBits(frame.rsv));
        }
        match frame.opcode {
            OpCode::Ping => {
                if self.options.auto_pong && self.state == State::Open {
                    self.write(Frame::pong(frame.payload.clone()));
                }
                Ok(Some(Message::Ping(frame.payload)))
            }
            OpCode::Pong => Ok(Some(Message::Pong(frame.payload))),
            OpCode::Close => self.handle_close(&frame.payload).map(Some),
            OpCode::Text | OpCode::Binary => {
                if self.partial.is_some() {
                    return Err(Error::ExpectedContinuation);
                }
                self.partial = Some(Partial {
                    text: frame.opcode == OpCode::Text,
                    compressed: frame.rsv & RSV1 != 0,
                    data: Vec::new(),
                    utf8_checked: 0,
                });
                self.append(&frame)
            }
            OpCode::Continuation => {
                if self.partial.is_none() {
                    return Err(Error::UnexpectedContinuation);
                }
                if frame.rsv != 0 {
                    return Err(Error::ReservedBits(frame.rsv));
                }
                self.append(&frame)
            }
        }
    }

    fn handle_close(&mut self, payload: &[u8]) -> Result<Message> {
        let close = CloseFrame::parse(payload)?;
        if self.state == State::Open {
            // Echo the status code (RFC 6455 §5.5.1).
            let echo = close.as_ref().map(|c| CloseFrame::new(c.code, ""));
            self.write(Frame::close(echo.as_ref()));
        }
        self.state = State::Closed;
        self.partial = None;
        Ok(Message::Close(close))
    }

    fn append(&mut self, frame: &Frame) -> Result<Option<Message>> {
        let max = self.options.max_message_size;
        let Some(partial) = self.partial.as_mut() else {
            return Err(Error::UnexpectedContinuation);
        };
        if partial.data.len().saturating_add(frame.payload.len()) > max {
            return Err(Error::MessageTooLarge { max });
        }
        partial.data.extend_from_slice(&frame.payload);
        if partial.text && !partial.compressed {
            check_utf8_prefix(partial, frame.fin)?;
        }
        if !frame.fin {
            return Ok(None);
        }
        let Some(partial) = self.partial.take() else {
            return Err(Error::UnexpectedContinuation);
        };
        self.finish(partial).map(Some)
    }

    #[cfg_attr(
        not(feature = "deflate"),
        allow(
            clippy::needless_pass_by_ref_mut,
            reason = "mutated by the deflate path"
        )
    )]
    fn finish(&mut self, partial: Partial) -> Result<Message> {
        let data = if partial.compressed {
            self.inflate(&partial.data)?
        } else {
            partial.data
        };
        if partial.text {
            String::from_utf8(data)
                .map(Message::Text)
                .map_err(|_| Error::InvalidUtf8)
        } else {
            Ok(Message::Binary(data))
        }
    }

    #[cfg(feature = "deflate")]
    fn inflate(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        let max = self.options.max_message_size;
        match &mut self.deflate {
            Some(deflate) => deflate.decompressor.decompress(data, max),
            None => Err(Error::ReservedBits(RSV1)),
        }
    }

    #[cfg(not(feature = "deflate"))]
    #[allow(clippy::unused_self, reason = "mirrors the deflate-enabled signature")]
    const fn inflate(&self, _data: &[u8]) -> Result<Vec<u8>> {
        Err(Error::ReservedBits(RSV1))
    }
}

/// Validates the newly appended part of a text message so that invalid
/// UTF-8 fails fast, before the message is complete. An incomplete
/// sequence at the end is allowed until the final fragment.
fn check_utf8_prefix(partial: &mut Partial, fin: bool) -> Result<()> {
    match std::str::from_utf8(&partial.data[partial.utf8_checked..]) {
        Ok(_) => partial.utf8_checked = partial.data.len(),
        Err(err) if err.error_len().is_none() && !fin => partial.utf8_checked += err.valid_up_to(),
        Err(_) => return Err(Error::InvalidUtf8),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pair() -> (Connection, Connection) {
        let mut n = 0u8;
        let client = Connection::client(Options::default(), move || {
            n = n.wrapping_add(1);
            [n, 0x5a, 0xa5, n]
        });
        (client, Connection::server(Options::default()))
    }

    #[test]
    fn text_and_binary_both_ways() {
        let (mut client, mut server) = pair();
        client.send(Message::Binary(vec![0, 1, 2])).unwrap();
        server.receive(&client.take_outgoing());
        assert_eq!(
            server.next_message().unwrap().unwrap(),
            Message::Binary(vec![0, 1, 2])
        );
        server.send(Message::Text("ok".into())).unwrap();
        client.receive(&server.take_outgoing());
        assert_eq!(
            client.next_message().unwrap().unwrap(),
            Message::Text("ok".into())
        );
        assert!(client.next_message().is_none());
    }

    #[test]
    fn fragmented_send_reassembles() {
        let mut client =
            Connection::client(Options::default().with_send_fragment_size(Some(3)), || {
                [9, 8, 7, 6]
            });
        let mut server = Connection::server(Options::default());
        client.send(Message::Text("héllo wörld".into())).unwrap();
        let bytes = client.take_outgoing();
        for byte in &bytes {
            server.receive(std::slice::from_ref(byte));
        }
        assert_eq!(
            server.next_message().unwrap().unwrap(),
            Message::Text("héllo wörld".into())
        );
    }

    #[test]
    fn close_handshake_initiated_by_client() {
        let (mut client, mut server) = pair();
        client
            .close(Some(CloseFrame::new(CloseCode::NORMAL, "done")))
            .unwrap();
        assert_eq!(client.state(), State::Closing);
        assert!(matches!(
            client.send(Message::Text("x".into())),
            Err(Error::Closed)
        ));
        server.receive(&client.take_outgoing());
        assert_eq!(
            server.next_message().unwrap().unwrap(),
            Message::Close(Some(CloseFrame::new(CloseCode::NORMAL, "done")))
        );
        assert!(server.is_closed());
        client.receive(&server.take_outgoing());
        assert_eq!(
            client.next_message().unwrap().unwrap(),
            Message::Close(Some(CloseFrame::new(CloseCode::NORMAL, "")))
        );
        assert!(client.is_closed());
        assert_eq!(client.outgoing(), []);
    }

    #[test]
    fn violations_fail_with_matching_code() {
        let cases: [(&[u8], u16); 3] = [
            (&[0x81, 0x01, 0xff], 1002),             // unmasked frame to server
            (&[0x81, 0x81, 0, 0, 0, 0, 0xff], 1007), // invalid UTF-8
            (&[0x80, 0x80, 0, 0, 0, 0], 1002),       // stray continuation
        ];
        for (bytes, code) in cases {
            let mut server = Connection::server(Options::default());
            server.receive(bytes);
            assert!(server.next_message().unwrap().is_err());
            assert!(server.next_message().is_none());
            assert!(server.is_closed());
            let mut client = Connection::client(Options::default(), || [0; 4]);
            client.receive(server.outgoing());
            assert_eq!(
                client.next_message().unwrap().unwrap(),
                Message::Close(Some(CloseFrame::new(code, "")))
            );
        }
    }

    #[test]
    fn message_size_limit() {
        let mut server = Connection::server(Options::default().with_max_message_size(4));
        let mut client =
            Connection::client(Options::default().with_send_fragment_size(Some(2)), || {
                [0; 4]
            });
        client.send(Message::Binary(vec![0; 6])).unwrap();
        server.receive(&client.take_outgoing());
        assert!(matches!(
            server.next_message(),
            Some(Err(Error::MessageTooLarge { max: 4 }))
        ));
    }

    #[test]
    fn send_validation() {
        let (mut client, _) = pair();
        assert!(matches!(
            client.send(Message::Ping(vec![0; 126])),
            Err(Error::ControlTooLong(126))
        ));
        assert!(matches!(
            client.close(Some(CloseFrame::new(CloseCode::ABNORMAL, ""))),
            Err(Error::InvalidCloseCode(1006))
        ));
    }

    #[test]
    fn utf8_fails_fast_but_allows_split_sequences() {
        let mut partial = Partial {
            text: true,
            compressed: false,
            data: vec![0xce],
            utf8_checked: 0,
        };
        check_utf8_prefix(&mut partial, false).unwrap();
        partial.data.push(0xba);
        check_utf8_prefix(&mut partial, true).unwrap();
        partial.data.extend([0xce]);
        assert!(check_utf8_prefix(&mut partial, true).is_err());
        let mut bad = Partial {
            text: true,
            compressed: false,
            data: vec![b'a', 0xff],
            utf8_checked: 0,
        };
        assert!(check_utf8_prefix(&mut bad, false).is_err());
    }
}
