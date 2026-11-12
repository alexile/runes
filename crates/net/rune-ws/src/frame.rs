//! RFC 6455 §5 base framing: opcodes, masking, length encodings, and an
//! incremental frame decoder.

use crate::error::{Error, Result};

/// RSV1 bit in [`Frame::rsv`] (used by permessage-deflate).
pub const RSV1: u8 = 0b100;
/// RSV2 bit in [`Frame::rsv`].
pub const RSV2: u8 = 0b010;
/// RSV3 bit in [`Frame::rsv`].
pub const RSV3: u8 = 0b001;

/// Largest payload a control frame may carry.
pub const MAX_CONTROL_PAYLOAD: usize = 125;

/// A frame opcode (RFC 6455 §5.2). Reserved opcodes are rejected by the
/// decoder and are not representable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum OpCode {
    /// `0x0`: continues a fragmented message.
    Continuation,
    /// `0x1`: first frame of a UTF-8 text message.
    Text,
    /// `0x2`: first frame of a binary message.
    Binary,
    /// `0x8`: connection close.
    Close,
    /// `0x9`: ping.
    Ping,
    /// `0xA`: pong.
    Pong,
}

impl OpCode {
    /// Decodes the low four bits of the first header byte.
    ///
    /// # Errors
    ///
    /// [`Error::ReservedOpcode`] for `0x3`–`0x7` and `0xB`–`0xF`.
    pub const fn from_u8(value: u8) -> Result<Self> {
        Ok(match value {
            0x0 => Self::Continuation,
            0x1 => Self::Text,
            0x2 => Self::Binary,
            0x8 => Self::Close,
            0x9 => Self::Ping,
            0xA => Self::Pong,
            other => return Err(Error::ReservedOpcode(other)),
        })
    }

    /// The four-bit wire value.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        match self {
            Self::Continuation => 0x0,
            Self::Text => 0x1,
            Self::Binary => 0x2,
            Self::Close => 0x8,
            Self::Ping => 0x9,
            Self::Pong => 0xA,
        }
    }

    /// Whether this is a control opcode (close, ping or pong).
    #[must_use]
    pub const fn is_control(self) -> bool {
        matches!(self, Self::Close | Self::Ping | Self::Pong)
    }
}

/// One WebSocket frame.
///
/// The decoder stores the payload **unmasked** and keeps the masking key in
/// [`mask`](Self::mask), so `encode(decode(bytes)) == bytes` for any frame
/// that uses the minimal length encoding. A proxy can therefore inspect and
/// rewrite payloads and re-emit frames faithfully.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Frame {
    /// FIN: this is the final fragment of a message.
    pub fin: bool,
    /// RSV1–RSV3 as the three low bits ([`RSV1`], [`RSV2`], [`RSV3`]).
    pub rsv: u8,
    /// The opcode.
    pub opcode: OpCode,
    /// The masking key; `Some` for frames sent by a client.
    pub mask: Option<[u8; 4]>,
    /// The unmasked application payload.
    pub payload: Vec<u8>,
}

impl Frame {
    /// A final, unmasked frame with no RSV bits.
    pub fn new(opcode: OpCode, payload: impl Into<Vec<u8>>) -> Self {
        Self {
            fin: true,
            rsv: 0,
            opcode,
            mask: None,
            payload: payload.into(),
        }
    }

    /// A single-frame text message.
    pub fn text(text: impl Into<String>) -> Self {
        Self::new(OpCode::Text, text.into().into_bytes())
    }

    /// A single-frame binary message.
    pub fn binary(data: impl Into<Vec<u8>>) -> Self {
        Self::new(OpCode::Binary, data)
    }

    /// A ping frame.
    pub fn ping(data: impl Into<Vec<u8>>) -> Self {
        Self::new(OpCode::Ping, data)
    }

    /// A pong frame.
    pub fn pong(data: impl Into<Vec<u8>>) -> Self {
        Self::new(OpCode::Pong, data)
    }

    /// A close frame; `None` sends an empty close payload.
    #[must_use]
    pub fn close(close: Option<&crate::CloseFrame>) -> Self {
        Self::new(
            OpCode::Close,
            close.map(crate::CloseFrame::to_payload).unwrap_or_default(),
        )
    }

    /// Sets FIN.
    #[must_use]
    pub const fn with_fin(mut self, fin: bool) -> Self {
        self.fin = fin;
        self
    }

    /// Sets the RSV bits (only the three low bits are used).
    #[must_use]
    pub const fn with_rsv(mut self, rsv: u8) -> Self {
        self.rsv = rsv & 0b111;
        self
    }

    /// Sets the masking key.
    #[must_use]
    pub const fn with_mask(mut self, mask: Option<[u8; 4]>) -> Self {
        self.mask = mask;
        self
    }

    /// The number of bytes [`encode`](Self::encode) produces.
    #[must_use]
    pub const fn encoded_len(&self) -> usize {
        let len = self.payload.len();
        let ext = if len < 126 {
            0
        } else if len <= 0xFFFF {
            2
        } else {
            8
        };
        let mask = if self.mask.is_some() { 4 } else { 0 };
        2 + ext + mask + len
    }

    /// Appends the wire form of the frame to `out`, masking the payload if
    /// a key is set. Uses the minimal length encoding.
    ///
    /// Encoding is infallible and writes exactly what the frame says, even
    /// if it breaks a protocol rule (an oversized control frame, say); the
    /// [`Connection`](crate::Connection) validates what it sends.
    pub fn encode(&self, out: &mut Vec<u8>) {
        out.reserve(self.encoded_len());
        let fin = if self.fin { 0x80 } else { 0 };
        out.push(fin | ((self.rsv & 0b111) << 4) | self.opcode.as_u8());
        let mask_bit = if self.mask.is_some() { 0x80 } else { 0 };
        let len = self.payload.len();
        if let Ok(short) = u8::try_from(len)
            && short < 126
        {
            out.push(mask_bit | short);
        } else if let Ok(medium) = u16::try_from(len) {
            out.push(mask_bit | 0x7e);
            out.extend_from_slice(&medium.to_be_bytes());
        } else {
            out.push(mask_bit | 0x7f);
            out.extend_from_slice(&(len as u64).to_be_bytes());
        }
        let start = out.len();
        out.extend_from_slice(&self.payload);
        if let Some(mask) = self.mask {
            out.extend_from_slice(&mask);
            // The key precedes the payload on the wire: rotate it in place.
            out[start..].rotate_right(4);
            apply_mask(&mut out[start + 4..], mask);
        }
    }

    /// The wire form of the frame.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.encode(&mut out);
        out
    }
}

/// XORs `data` with the four-byte masking key (RFC 6455 §5.3). Masking is
/// its own inverse.
pub fn apply_mask(data: &mut [u8], mask: [u8; 4]) {
    let word = u32::from_ne_bytes(mask);
    let (chunks, remainder) = data.as_chunks_mut::<4>();
    for chunk in chunks {
        *chunk = (u32::from_ne_bytes(*chunk) ^ word).to_ne_bytes();
    }
    for (byte, key) in remainder.iter_mut().zip(mask) {
        *byte ^= key;
    }
}

/// Which masking a decoder demands of incoming frames.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum MaskPolicy {
    /// Accept masked and unmasked frames (passive inspection).
    #[default]
    Any,
    /// Every frame must be masked: a server reading a client.
    Required,
    /// No frame may be masked: a client reading a server.
    Forbidden,
}

/// Limits and rules for [`FrameDecoder`] and [`decode_frame`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct DecoderOptions {
    /// Largest payload accepted in a single frame. Default: 16 MiB.
    pub max_payload: u64,
    /// RSV bits a negotiated extension allows; any other set bit is an
    /// error. Default: none.
    pub allowed_rsv: u8,
    /// Masking requirement. Default: [`MaskPolicy::Any`].
    pub mask: MaskPolicy,
}

impl Default for DecoderOptions {
    fn default() -> Self {
        Self {
            max_payload: 16 << 20,
            allowed_rsv: 0,
            mask: MaskPolicy::Any,
        }
    }
}

impl DecoderOptions {
    /// Sets [`max_payload`](Self::max_payload).
    #[must_use]
    pub const fn with_max_payload(mut self, max: u64) -> Self {
        self.max_payload = max;
        self
    }

    /// Sets [`allowed_rsv`](Self::allowed_rsv).
    #[must_use]
    pub const fn with_allowed_rsv(mut self, rsv: u8) -> Self {
        self.allowed_rsv = rsv & 0b111;
        self
    }

    /// Sets [`mask`](Self::mask).
    #[must_use]
    pub const fn with_mask(mut self, mask: MaskPolicy) -> Self {
        self.mask = mask;
        self
    }
}

struct Header {
    fin: bool,
    rsv: u8,
    opcode: OpCode,
    mask: Option<[u8; 4]>,
    len: usize,
    header_len: usize,
}

fn read_length(b1: u8, rest: &[u8]) -> Result<Option<(u64, usize)>> {
    match b1 & 0x7F {
        126 => {
            let Some(bytes) = rest.get(..2) else {
                return Ok(None);
            };
            let len = u16::from_be_bytes([bytes[0], bytes[1]]);
            if len < 126 {
                return Err(Error::InvalidLength);
            }
            Ok(Some((u64::from(len), 2)))
        }
        127 => {
            let Some(bytes) = rest.get(..8) else {
                return Ok(None);
            };
            let mut raw = [0; 8];
            raw.copy_from_slice(bytes);
            let len = u64::from_be_bytes(raw);
            if len >> 63 != 0 || len <= 0xFFFF {
                return Err(Error::InvalidLength);
            }
            Ok(Some((len, 8)))
        }
        short => Ok(Some((u64::from(short), 0))),
    }
}

fn parse_header(buf: &[u8], options: &DecoderOptions) -> Result<Option<Header>> {
    let [b0, b1, rest @ ..] = buf else {
        return Ok(None);
    };
    let fin = b0 & 0x80 != 0;
    let rsv = (b0 >> 4) & 0b111;
    let opcode = OpCode::from_u8(b0 & 0x0F)?;
    if rsv & !options.allowed_rsv != 0 {
        return Err(Error::ReservedBits(rsv));
    }
    let masked = b1 & 0x80 != 0;
    match (options.mask, masked) {
        (MaskPolicy::Required, false) => return Err(Error::UnmaskedFrame),
        (MaskPolicy::Forbidden, true) => return Err(Error::MaskedFrame),
        _ => {}
    }
    let Some((len, ext)) = read_length(*b1, rest)? else {
        return Ok(None);
    };
    if opcode.is_control() {
        if !fin {
            return Err(Error::FragmentedControl);
        }
        if len > MAX_CONTROL_PAYLOAD as u64 {
            return Err(Error::ControlTooLong(len));
        }
    }
    let too_large = Error::FrameTooLarge {
        len,
        max: options.max_payload,
    };
    if len > options.max_payload {
        return Err(too_large);
    }
    let len = usize::try_from(len).map_err(|_| too_large)?;
    let mask = if masked {
        let Some(key) = rest.get(ext..ext + 4) else {
            return Ok(None);
        };
        Some([key[0], key[1], key[2], key[3]])
    } else {
        None
    };
    Ok(Some(Header {
        fin,
        rsv,
        opcode,
        mask,
        len,
        header_len: 2 + ext + if masked { 4 } else { 0 },
    }))
}

/// Decodes one frame from the front of `buf`.
///
/// Returns `Ok(None)` when `buf` does not yet hold a complete frame, and
/// otherwise the frame and the number of bytes it occupied. Header rules
/// (reserved opcodes and bits, control frame limits, length encoding, mask
/// policy, `max_payload`) are checked as soon as the header bytes are
/// present, before the payload arrives.
///
/// # Errors
///
/// Any framing violation listed on [`Error`].
pub fn decode_frame(buf: &[u8], options: &DecoderOptions) -> Result<Option<(Frame, usize)>> {
    let Some(header) = parse_header(buf, options)? else {
        return Ok(None);
    };
    let total = header.header_len + header.len;
    let Some(raw) = buf.get(header.header_len..total) else {
        return Ok(None);
    };
    let mut payload = raw.to_vec();
    if let Some(mask) = header.mask {
        apply_mask(&mut payload, mask);
    }
    let frame = Frame {
        fin: header.fin,
        rsv: header.rsv,
        opcode: header.opcode,
        mask: header.mask,
        payload,
    };
    Ok(Some((frame, total)))
}

/// An incremental frame decoder: push bytes as they arrive, pull frames.
///
/// After the first error the decoder stops: a WebSocket stream cannot be
/// resynchronised once framing is lost.
///
/// ```
/// use rune_ws::{FrameDecoder, OpCode};
///
/// let mut decoder = FrameDecoder::default();
/// decoder.push(&[0x81, 0x05, b'H', b'e']);
/// assert!(decoder.next_frame().is_none());
/// decoder.push(b"llo");
/// let frame = decoder.next_frame().unwrap()?;
/// assert_eq!((frame.opcode, frame.payload.as_slice()), (OpCode::Text, &b"Hello"[..]));
/// # Ok::<(), rune_ws::Error>(())
/// ```
#[derive(Debug, Clone, Default)]
pub struct FrameDecoder {
    buf: Vec<u8>,
    start: usize,
    options: DecoderOptions,
    failed: bool,
}

impl FrameDecoder {
    /// A decoder with the given options.
    #[must_use]
    pub const fn new(options: DecoderOptions) -> Self {
        Self {
            buf: Vec::new(),
            start: 0,
            options,
            failed: false,
        }
    }

    /// The decoder's options.
    #[must_use]
    pub const fn options(&self) -> &DecoderOptions {
        &self.options
    }

    /// Replaces the options; takes effect from the next frame.
    pub const fn set_options(&mut self, options: DecoderOptions) {
        self.options = options;
    }

    /// Appends received bytes.
    pub fn push(&mut self, data: &[u8]) {
        if self.start == self.buf.len() {
            self.buf.clear();
            self.start = 0;
        } else if self.start >= 4096 && self.start * 2 >= self.buf.len() {
            self.buf.drain(..self.start);
            self.start = 0;
        }
        self.buf.extend_from_slice(data);
    }

    /// The next complete frame, `None` if more bytes are needed (or after
    /// an error has been returned).
    pub fn next_frame(&mut self) -> Option<Result<Frame>> {
        if self.failed {
            return None;
        }
        match decode_frame(&self.buf[self.start..], &self.options) {
            Ok(Some((frame, used))) => {
                self.start += used;
                Some(Ok(frame))
            }
            Ok(None) => None,
            Err(err) => {
                self.failed = true;
                Some(Err(err))
            }
        }
    }

    /// Bytes received but not yet returned as frames.
    #[must_use]
    pub fn buffered(&self) -> &[u8] {
        &self.buf[self.start..]
    }

    /// Whether the decoder has stopped after an error.
    #[must_use]
    pub const fn is_failed(&self) -> bool {
        self.failed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode_all(bytes: &[u8]) -> Frame {
        let (frame, used) = decode_frame(bytes, &DecoderOptions::default())
            .unwrap()
            .unwrap();
        assert_eq!(used, bytes.len());
        assert_eq!(
            frame.to_bytes(),
            bytes,
            "re-encoding must be byte-identical"
        );
        frame
    }

    // RFC 6455 §5.7 examples.
    #[test]
    fn rfc_single_frame_unmasked_text() {
        let frame = decode_all(&[0x81, 0x05, 0x48, 0x65, 0x6c, 0x6c, 0x6f]);
        assert!(frame.fin);
        assert_eq!(frame.opcode, OpCode::Text);
        assert_eq!(frame.payload, b"Hello");
        assert_eq!(frame.mask, None);
    }

    #[test]
    fn rfc_single_frame_masked_text() {
        let frame = decode_all(&[
            0x81, 0x85, 0x37, 0xfa, 0x21, 0x3d, 0x7f, 0x9f, 0x4d, 0x51, 0x58,
        ]);
        assert_eq!(frame.payload, b"Hello");
        assert_eq!(frame.mask, Some([0x37, 0xfa, 0x21, 0x3d]));
    }

    #[test]
    fn rfc_fragmented_unmasked_text() {
        let first = decode_all(&[0x01, 0x03, 0x48, 0x65, 0x6c]);
        assert!(!first.fin);
        assert_eq!(first.opcode, OpCode::Text);
        let second = decode_all(&[0x80, 0x02, 0x6c, 0x6f]);
        assert!(second.fin);
        assert_eq!(second.opcode, OpCode::Continuation);
    }

    #[test]
    fn rfc_ping_and_masked_pong() {
        let request = decode_all(&[0x89, 0x05, 0x48, 0x65, 0x6c, 0x6c, 0x6f]);
        assert_eq!(
            (request.opcode, request.payload.as_slice()),
            (OpCode::Ping, &b"Hello"[..])
        );
        let reply = decode_all(&[
            0x8a, 0x85, 0x37, 0xfa, 0x21, 0x3d, 0x7f, 0x9f, 0x4d, 0x51, 0x58,
        ]);
        assert_eq!(
            (reply.opcode, reply.payload.as_slice()),
            (OpCode::Pong, &b"Hello"[..])
        );
    }

    #[test]
    fn rfc_extended_lengths() {
        let mut medium = vec![0x82, 0x7E, 0x01, 0x00];
        medium.extend(std::iter::repeat_n(7, 256));
        assert_eq!(decode_all(&medium).payload.len(), 256);

        let mut large = vec![0x82, 0x7F, 0, 0, 0, 0, 0, 0x01, 0x00, 0x00];
        large.extend(std::iter::repeat_n(9, 65536));
        assert_eq!(decode_all(&large).payload.len(), 65536);
    }

    #[test]
    fn incomplete_input_needs_more() {
        let bytes = Frame::binary(vec![1; 300])
            .with_mask(Some([1, 2, 3, 4]))
            .to_bytes();
        for cut in 0..bytes.len() {
            assert!(
                decode_frame(&bytes[..cut], &DecoderOptions::default())
                    .unwrap()
                    .is_none()
            );
        }
    }

    #[test]
    fn header_violations() {
        let opts = DecoderOptions::default();
        let err = |bytes: &[u8]| decode_frame(bytes, &opts).unwrap_err();
        assert!(matches!(err(&[0x83, 0x00]), Error::ReservedOpcode(3)));
        assert!(matches!(err(&[0x8B, 0x00]), Error::ReservedOpcode(0xB)));
        assert!(matches!(err(&[0xC1, 0x00]), Error::ReservedBits(0b100)));
        assert!(matches!(err(&[0x09, 0x00]), Error::FragmentedControl));
        assert!(matches!(
            err(&[0x89, 0x7E, 0x00, 0x7E]),
            Error::ControlTooLong(126)
        ));
        assert!(matches!(
            err(&[0x82, 0x7E, 0x00, 0x05]),
            Error::InvalidLength
        ));
        assert!(matches!(
            err(&[0x82, 0x7F, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF]),
            Error::InvalidLength
        ));
        assert!(matches!(
            err(&[0x82, 0x7F, 0x80, 0, 0, 0, 0, 0, 0, 0]),
            Error::InvalidLength
        ));
        let small = DecoderOptions::default().with_max_payload(4);
        assert!(matches!(
            decode_frame(&[0x82, 0x05], &small),
            Err(Error::FrameTooLarge { len: 5, max: 4 })
        ));
        let allow = DecoderOptions::default().with_allowed_rsv(RSV1);
        assert!(decode_frame(&[0xC1, 0x00], &allow).unwrap().is_some());
    }

    #[test]
    fn mask_policy() {
        let masked = Frame::text("x").with_mask(Some([9, 9, 9, 9])).to_bytes();
        let plain = Frame::text("x").to_bytes();
        let req = DecoderOptions::default().with_mask(MaskPolicy::Required);
        let forb = DecoderOptions::default().with_mask(MaskPolicy::Forbidden);
        assert!(matches!(
            decode_frame(&plain, &req),
            Err(Error::UnmaskedFrame)
        ));
        assert!(matches!(
            decode_frame(&masked, &forb),
            Err(Error::MaskedFrame)
        ));
        assert!(decode_frame(&masked, &req).unwrap().is_some());
        assert!(decode_frame(&plain, &forb).unwrap().is_some());
    }

    #[test]
    fn decoder_streams_and_stops_after_error() {
        let mut bytes = Frame::text("a").to_bytes();
        bytes.extend(Frame::ping(*b"p").to_bytes());
        bytes.extend([0x83, 0x00]);
        bytes.extend(Frame::text("never").to_bytes());
        let mut decoder = FrameDecoder::default();
        for byte in &bytes {
            decoder.push(std::slice::from_ref(byte));
        }
        assert_eq!(decoder.next_frame().unwrap().unwrap().payload, b"a");
        assert_eq!(decoder.next_frame().unwrap().unwrap().opcode, OpCode::Ping);
        assert!(decoder.next_frame().unwrap().is_err());
        assert!(decoder.next_frame().is_none());
        assert!(decoder.is_failed());
    }

    #[test]
    fn mask_is_an_involution_for_all_lengths() {
        for len in 0..12 {
            let original: Vec<u8> = (0..len).map(|i| i * 17).collect();
            let mut data = original.clone();
            apply_mask(&mut data, [0xde, 0xad, 0xbe, 0xef]);
            if len > 0 {
                assert_ne!(data, original);
            }
            apply_mask(&mut data, [0xde, 0xad, 0xbe, 0xef]);
            assert_eq!(data, original);
        }
    }
}
