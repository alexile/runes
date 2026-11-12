//! Bounded byte reader and compressing writer.

use std::collections::HashMap;

use crate::name::{MAX_NAME_LEN, Name};
use crate::{Error, MAX_MESSAGE_LEN};

/// Size of the fixed message header.
pub const HEADER_LEN: usize = 12;

/// Most compression pointers one name may follow. A valid name has at most
/// 127 labels, so it never needs more pointers than that.
const MAX_POINTERS: usize = 128;

/// Reads big-endian fields from a message, never past `end`.
pub struct Reader<'a> {
    /// The whole message, for following compression pointers.
    msg: &'a [u8],
    pos: usize,
    /// Reads stop here (the end of the RDATA being parsed, or the message).
    end: usize,
}

impl<'a> Reader<'a> {
    pub const fn new(msg: &'a [u8]) -> Self {
        Self {
            msg,
            pos: 0,
            end: msg.len(),
        }
    }

    pub const fn pos(&self) -> usize {
        self.pos
    }

    pub const fn remaining(&self) -> usize {
        self.end.saturating_sub(self.pos)
    }

    /// A reader over the next `len` bytes, sharing the message for pointer
    /// targets. Advances `self` past them.
    pub fn sub(&mut self, len: usize) -> Result<Self, Error> {
        let end = self
            .pos
            .checked_add(len)
            .filter(|&end| end <= self.end)
            .ok_or(Error::Truncated { offset: self.end })?;
        let sub = Self {
            msg: self.msg,
            pos: self.pos,
            end,
        };
        self.pos = end;
        Ok(sub)
    }

    pub fn bytes(&mut self, len: usize) -> Result<&'a [u8], Error> {
        let end = self
            .pos
            .checked_add(len)
            .filter(|&end| end <= self.end)
            .ok_or(Error::Truncated { offset: self.end })?;
        let bytes = self
            .msg
            .get(self.pos..end)
            .ok_or(Error::Truncated { offset: self.pos })?;
        self.pos = end;
        Ok(bytes)
    }

    /// The rest of this reader's bytes.
    pub fn rest(&mut self) -> Result<&'a [u8], Error> {
        self.bytes(self.remaining())
    }

    pub fn u8(&mut self) -> Result<u8, Error> {
        let [byte] = self.array()?;
        Ok(byte)
    }

    pub fn u16(&mut self) -> Result<u16, Error> {
        self.array().map(u16::from_be_bytes)
    }

    pub fn u32(&mut self) -> Result<u32, Error> {
        self.array().map(u32::from_be_bytes)
    }

    pub fn array<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        let bytes = self.bytes(N)?;
        <[u8; N]>::try_from(bytes).map_err(|_| Error::Truncated { offset: self.pos })
    }

    /// Reads a `<character-string>`: a length octet and that many octets.
    pub fn character_string(&mut self) -> Result<&'a [u8], Error> {
        let len = self.u8()?;
        self.bytes(usize::from(len))
    }

    /// Reads a possibly compressed name (RFC 1035 §4.1.4).
    ///
    /// The labels before the first pointer must lie inside this reader;
    /// pointers may target anything earlier in the message, but only
    /// strictly before the start of the run of labels that contains them,
    /// so every jump goes backwards and the walk terminates.
    pub fn name(&mut self) -> Result<Name, Error> {
        let start = self.pos;
        let mut wire = Vec::with_capacity(32);
        let mut pos = self.pos;
        let mut limit = self.end;
        let mut run_start = self.pos;
        let mut resume = None;
        let mut pointers = 0;
        loop {
            let byte = *self
                .msg
                .get(..limit)
                .and_then(|msg| msg.get(pos))
                .ok_or(Error::Truncated { offset: pos })?;
            match byte & 0xC0 {
                0x00 => {
                    let len = usize::from(byte);
                    let label_end = pos + 1 + len;
                    if len == 0 {
                        wire.push(0);
                        pos += 1;
                        break;
                    }
                    let label = self
                        .msg
                        .get(..limit)
                        .and_then(|msg| msg.get(pos + 1..label_end))
                        .ok_or(Error::Truncated { offset: limit })?;
                    // Room for this label and the terminating root octet.
                    if wire.len() + 1 + len + 1 > MAX_NAME_LEN {
                        return Err(Error::NameTooLong);
                    }
                    wire.push(byte);
                    wire.extend_from_slice(label);
                    pos = label_end;
                }
                0xC0 => {
                    let low = *self
                        .msg
                        .get(..limit)
                        .and_then(|msg| msg.get(pos + 1))
                        .ok_or(Error::Truncated { offset: pos + 1 })?;
                    let target = usize::from(byte & 0x3F) << 8 | usize::from(low);
                    if target >= run_start || target < HEADER_LEN {
                        return Err(Error::BadPointer {
                            offset: pos,
                            target,
                        });
                    }
                    pointers += 1;
                    if pointers > MAX_POINTERS {
                        return Err(Error::TooManyPointers { offset: start });
                    }
                    resume.get_or_insert(pos + 2);
                    run_start = target;
                    pos = target;
                    limit = self.msg.len();
                }
                _ => return Err(Error::BadLabelType { offset: pos, byte }),
            }
        }
        self.pos = resume.unwrap_or(pos);
        Ok(Name::from_wire_unchecked(wire))
    }
}

/// Writes a message, compressing names against earlier ones.
pub struct Writer {
    buf: Vec<u8>,
    /// Offsets of name suffixes already written, keyed by their exact
    /// uncompressed wire form.
    names: HashMap<Vec<u8>, u16>,
}

impl Writer {
    pub fn new() -> Self {
        Self {
            buf: Vec::with_capacity(512),
            names: HashMap::new(),
        }
    }

    pub const fn len(&self) -> usize {
        self.buf.len()
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.buf
    }

    /// Drops everything from `len` on, and the compression targets in it.
    pub fn truncate(&mut self, len: usize) {
        self.buf.truncate(len);
        self.names.retain(|_, offset| usize::from(*offset) < len);
    }

    pub fn u8(&mut self, value: u8) {
        self.buf.push(value);
    }

    pub fn u16(&mut self, value: u16) {
        self.buf.extend_from_slice(&value.to_be_bytes());
    }

    pub fn u32(&mut self, value: u32) {
        self.buf.extend_from_slice(&value.to_be_bytes());
    }

    pub fn bytes(&mut self, bytes: &[u8]) {
        self.buf.extend_from_slice(bytes);
    }

    /// Overwrites the big-endian `u16` at `offset`.
    pub fn set_u16(&mut self, offset: usize, value: u16) {
        if let Some(slot) = self.buf.get_mut(offset..offset + 2) {
            slot.copy_from_slice(&value.to_be_bytes());
        }
    }

    pub fn character_string(&mut self, bytes: &[u8]) -> Result<(), Error> {
        let len = u8::try_from(bytes.len())
            .map_err(|_| Error::CharacterStringTooLong { len: bytes.len() })?;
        self.u8(len);
        self.bytes(bytes);
        Ok(())
    }

    /// Writes `name`. With `compress`, its longest suffix already in the
    /// message becomes a pointer, and its own suffixes become targets for
    /// later names.
    pub fn name(&mut self, name: &Name, compress: bool) {
        if !compress {
            self.bytes(name.as_wire());
            return;
        }
        let wire = name.as_wire();
        let mut rest = wire;
        while rest.len() > 1 {
            if let Some(&offset) = self.names.get(rest) {
                self.u16(0xC000 | offset);
                return;
            }
            let here = self.buf.len();
            // Pointers carry 14 bits of offset.
            if let Some(offset) = u16::try_from(here).ok().filter(|&offset| offset < 0x4000) {
                self.names.entry(rest.to_vec()).or_insert(offset);
            }
            let len = rest.first().map_or(0, |&len| usize::from(len));
            let (label, tail) = rest.split_at_checked(1 + len).unwrap_or((rest, &[]));
            self.bytes(label);
            rest = tail;
        }
        self.u8(0);
    }

    /// Fails if the message has grown past `max`.
    pub const fn check_len(&self, max: usize) -> Result<(), Error> {
        if self.buf.len() > max || self.buf.len() > MAX_MESSAGE_LEN {
            return Err(Error::MessageTooLong {
                len: self.buf.len(),
                max,
            });
        }
        Ok(())
    }
}
