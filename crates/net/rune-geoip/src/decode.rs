//! Data-section decoder (`MaxMind` DB spec, "Output Data Section").
//!
//! Every read is bounds-checked. Nesting is capped at [`MAX_DEPTH`] and the
//! number of values one call may produce at [`MAX_VALUES`], so a hostile
//! file cannot exhaust the stack, or blow up through shared pointers.

use std::collections::BTreeMap;

use crate::Error;
use crate::value::Value;

/// Deepest nesting of maps, arrays and pointers in one decoded value.
pub const MAX_DEPTH: usize = 64;
/// Most values (scalars, maps, arrays) one decode call may produce.
pub const MAX_VALUES: usize = 1 << 20;

pub const TYPE_EXTENDED: u8 = 0;
pub const TYPE_POINTER: u8 = 1;
pub const TYPE_STRING: u8 = 2;
pub const TYPE_DOUBLE: u8 = 3;
pub const TYPE_BYTES: u8 = 4;
pub const TYPE_UINT16: u8 = 5;
pub const TYPE_UINT32: u8 = 6;
pub const TYPE_MAP: u8 = 7;
pub const TYPE_INT32: u8 = 8;
pub const TYPE_UINT64: u8 = 9;
pub const TYPE_UINT128: u8 = 10;
pub const TYPE_ARRAY: u8 = 11;
pub const TYPE_CONTAINER: u8 = 12;
pub const TYPE_END_MARKER: u8 = 13;
pub const TYPE_BOOL: u8 = 14;
pub const TYPE_FLOAT: u8 = 15;

/// A decoder over one section; pointers are offsets from its start.
pub struct Decoder<'a> {
    buf: &'a [u8],
}

/// A control byte (and its extended-type and size bytes), decoded.
enum Control {
    Pointer(usize),
    Value { ty: u8, size: usize },
}

const fn err(offset: usize, reason: &'static str) -> Error {
    Error::InvalidData { offset, reason }
}

impl<'a> Decoder<'a> {
    pub const fn new(buf: &'a [u8]) -> Self {
        Self { buf }
    }

    /// Decodes the value at `offset`.
    pub fn decode(&self, offset: usize) -> Result<Value, Error> {
        let mut budget = MAX_VALUES;
        self.value(offset, 0, &mut budget).map(|(value, _)| value)
    }

    fn bytes(&self, offset: usize, len: usize) -> Result<&'a [u8], Error> {
        offset
            .checked_add(len)
            .and_then(|end| self.buf.get(offset..end))
            .ok_or_else(|| err(offset, "value runs past the end of the section"))
    }

    fn be(&self, offset: usize, len: usize) -> Result<u128, Error> {
        Ok(self
            .bytes(offset, len)?
            .iter()
            .fold(0u128, |acc, &b| (acc << 8) | u128::from(b)))
    }

    #[allow(
        clippy::cast_possible_truncation,
        reason = "be() of at most 4 bytes fits in usize on every supported target"
    )]
    fn be_usize(&self, offset: usize, len: usize) -> Result<usize, Error> {
        self.be(offset, len).map(|n| n as usize)
    }

    /// Reads the control byte at `offset`; returns it and the offset of the
    /// payload.
    fn control(&self, offset: usize) -> Result<(Control, usize), Error> {
        let ctrl = *self
            .buf
            .get(offset)
            .ok_or_else(|| err(offset, "value runs past the end of the section"))?;
        let mut pos = offset + 1;
        let mut ty = ctrl >> 5;
        if ty == TYPE_POINTER {
            let size = usize::from((ctrl >> 3) & 0x3);
            let vvv = usize::from(ctrl & 0x7);
            let target = match size {
                0 => (vvv << 8) | self.be_usize(pos, 1)?,
                1 => ((vvv << 16) | self.be_usize(pos, 2)?) + 2048,
                2 => ((vvv << 24) | self.be_usize(pos, 3)?) + 526_336,
                _ => self.be_usize(pos, 4)?,
            };
            return Ok((Control::Pointer(target), pos + size + 1));
        }
        if ty == TYPE_EXTENDED {
            let ext = *self
                .buf
                .get(pos)
                .ok_or_else(|| err(pos, "missing extended type byte"))?;
            ty = ext
                .checked_add(7)
                .filter(|&t| t >= TYPE_INT32)
                .ok_or_else(|| err(pos, "invalid extended type"))?;
            pos += 1;
        }
        let size = match ctrl & 0x1f {
            29 => {
                let n = 29 + self.be_usize(pos, 1)?;
                pos += 1;
                n
            }
            30 => {
                let n = 285 + self.be_usize(pos, 2)?;
                pos += 2;
                n
            }
            31 => {
                let n = 65_821 + self.be_usize(pos, 3)?;
                pos += 3;
                n
            }
            n => usize::from(n),
        };
        Ok((Control::Value { ty, size }, pos))
    }

    /// Decodes the value at `offset`; returns it and the offset just past
    /// it (past the pointer itself, when the value was a pointer).
    fn value(
        &self,
        offset: usize,
        depth: usize,
        budget: &mut usize,
    ) -> Result<(Value, usize), Error> {
        if depth > MAX_DEPTH {
            return Err(err(offset, "values nested too deeply"));
        }
        *budget = budget
            .checked_sub(1)
            .ok_or_else(|| err(offset, "value expands to too many items"))?;
        let (control, pos) = self.control(offset)?;
        let (ty, size) = match control {
            Control::Pointer(target) => {
                if let (Control::Pointer(_), _) = self.control(target)? {
                    return Err(err(offset, "pointer to a pointer"));
                }
                let (value, _) = self.value(target, depth + 1, budget)?;
                return Ok((value, pos));
            }
            Control::Value { ty, size } => (ty, size),
        };
        let fixed = |want: usize| {
            if size == want {
                Ok(())
            } else {
                Err(err(offset, "wrong size for a fixed-size type"))
            }
        };
        let max = |limit: usize| {
            if size <= limit {
                Ok(())
            } else {
                Err(err(offset, "integer wider than its type"))
            }
        };
        let value = match ty {
            TYPE_STRING => {
                let bytes = self.bytes(pos, size)?;
                let s = std::str::from_utf8(bytes).map_err(|_| err(pos, "invalid UTF-8"))?;
                Value::String(s.to_owned())
            }
            TYPE_DOUBLE => {
                fixed(8)?;
                let mut b = [0u8; 8];
                b.copy_from_slice(self.bytes(pos, 8)?);
                Value::Double(f64::from_be_bytes(b))
            }
            TYPE_FLOAT => {
                fixed(4)?;
                let mut b = [0u8; 4];
                b.copy_from_slice(self.bytes(pos, 4)?);
                Value::Float(f32::from_be_bytes(b))
            }
            TYPE_BYTES => Value::Bytes(self.bytes(pos, size)?.to_vec()),
            TYPE_UINT16 => {
                max(2)?;
                Value::Uint16(u16::try_from(self.be(pos, size)?).unwrap_or(u16::MAX))
            }
            TYPE_UINT32 => {
                max(4)?;
                Value::Uint32(u32::try_from(self.be(pos, size)?).unwrap_or(u32::MAX))
            }
            TYPE_INT32 => {
                max(4)?;
                // Shorter encodings are zero-padded, as in the reference
                // readers: only a 4-byte encoding can be negative.
                let raw = u32::try_from(self.be(pos, size)?).unwrap_or(u32::MAX);
                Value::Int32(i32::from_be_bytes(raw.to_be_bytes()))
            }
            TYPE_UINT64 => {
                max(8)?;
                Value::Uint64(u64::try_from(self.be(pos, size)?).unwrap_or(u64::MAX))
            }
            TYPE_UINT128 => {
                max(16)?;
                Value::Uint128(self.be(pos, size)?)
            }
            TYPE_BOOL => match size {
                0 => return Ok((Value::Bool(false), pos)),
                1 => return Ok((Value::Bool(true), pos)),
                _ => return Err(err(offset, "boolean size is not 0 or 1")),
            },
            TYPE_MAP => return self.map(pos, size, depth, budget),
            TYPE_ARRAY => {
                let mut items = Vec::new();
                let mut pos = pos;
                for _ in 0..size {
                    let (item, next) = self.value(pos, depth + 1, budget)?;
                    items.push(item);
                    pos = next;
                }
                return Ok((Value::Array(items), pos));
            }
            TYPE_CONTAINER => return Err(err(offset, "data cache container is not a value")),
            TYPE_END_MARKER => return Err(err(offset, "end marker is not a value")),
            _ => return Err(err(offset, "unknown data type")),
        };
        Ok((value, pos + size))
    }

    fn map(
        &self,
        mut pos: usize,
        size: usize,
        depth: usize,
        budget: &mut usize,
    ) -> Result<(Value, usize), Error> {
        let mut map = BTreeMap::new();
        for _ in 0..size {
            let key_at = pos;
            let (key, next) = self.value(pos, depth + 1, budget)?;
            let Value::String(key) = key else {
                return Err(err(key_at, "map key is not a string"));
            };
            let (value, next) = self.value(next, depth + 1, budget)?;
            map.insert(key, value);
            pos = next;
        }
        Ok((Value::Map(map), pos))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode(bytes: &[u8]) -> Result<Value, Error> {
        Decoder::new(bytes).decode(0)
    }

    // Known answers worked out by hand from the specification.
    #[test]
    fn scalars() {
        assert_eq!(decode(b"\x43foo"), Ok(Value::from("foo")));
        assert_eq!(decode(b"\x40"), Ok(Value::from("")));
        assert_eq!(decode(b"\xa0"), Ok(Value::Uint16(0)));
        assert_eq!(decode(b"\xa2\x01\xf4"), Ok(Value::Uint16(500)));
        assert_eq!(decode(b"\xc4\xff\xff\xff\xff"), Ok(Value::Uint32(u32::MAX)));
        assert_eq!(decode(b"\x04\x01\xff\xff\xff\xff"), Ok(Value::Int32(-1)));
        assert_eq!(decode(b"\x01\x01\xff"), Ok(Value::Int32(255)));
        assert_eq!(decode(b"\x02\x02\x01\x00"), Ok(Value::Uint64(256)));
        assert_eq!(
            decode(b"\x10\x03\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"),
            Ok(Value::Uint128(1 << 120))
        );
        assert_eq!(decode(b"\x00\x07"), Ok(Value::Bool(false)));
        assert_eq!(decode(b"\x01\x07"), Ok(Value::Bool(true)));
        assert_eq!(
            decode(b"\x68\x3f\xf0\x00\x00\x00\x00\x00\x00"),
            Ok(Value::Double(1.0))
        );
        assert_eq!(decode(b"\x04\x08\x3f\x80\x00\x00"), Ok(Value::Float(1.0)));
        assert_eq!(decode(b"\x82\x01\x02"), Ok(Value::Bytes(vec![1, 2])));
    }

    #[test]
    fn long_sizes() {
        // 29 + 1 = 30, 285 + 0x0102 = 543, 65 821 + 0x000001 = 65 822.
        let mut bytes = vec![0x5d, 1];
        bytes.extend(std::iter::repeat_n(b'a', 30));
        assert_eq!(decode(&bytes), Ok(Value::String("a".repeat(30))));
        let mut bytes = vec![0x9e, 1, 2];
        bytes.extend(std::iter::repeat_n(7, 543));
        assert_eq!(decode(&bytes), Ok(Value::Bytes(vec![7; 543])));
        let mut bytes = vec![0x9f, 0, 0, 1];
        bytes.extend(std::iter::repeat_n(7, 65_822));
        assert_eq!(decode(&bytes), Ok(Value::Bytes(vec![7; 65_822])));
    }

    #[test]
    fn maps_arrays_and_pointers() {
        // {"en": "Germany", "de": <pointer to offset 0x11>} with "Deutschland"
        // at offset 0x11, then an array [ptr(0x11), 1u16].
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"\xe2\x42en\x47Germany\x42de\x20\x11");
        assert_eq!(bytes.len(), 0x11);
        bytes.extend_from_slice(b"\x4bDeutschland");
        let array_at = bytes.len();
        bytes.extend_from_slice(b"\x02\x04\x20\x11\xa1\x01");
        let map = decode(&bytes).unwrap();
        assert_eq!(map.get("de").and_then(Value::as_str), Some("Deutschland"));
        assert_eq!(map.get("en").and_then(Value::as_str), Some("Germany"));
        assert_eq!(
            Decoder::new(&bytes).decode(array_at),
            Ok(Value::Array(vec![
                Value::from("Deutschland"),
                Value::Uint16(1)
            ]))
        );
    }

    #[test]
    fn pointer_sizes() {
        let decoder = Decoder::new(&[]);
        let cases: [(&[u8], usize); 4] = [
            (b"\x27\xff", 0x7ff),
            (b"\x2f\xff\xff", 0x7_ffff + 2048),
            (b"\x37\xff\xff\xff", 0x7ff_ffff + 526_336),
            (b"\x38\x12\x34\x56\x78", 0x1234_5678),
        ];
        for (bytes, want) in cases {
            let decoder = Decoder::new(bytes);
            match decoder.control(0) {
                Ok((Control::Pointer(target), next)) => {
                    assert_eq!(target, want);
                    assert_eq!(next, bytes.len());
                }
                _ => panic!("not a pointer: {bytes:?}"),
            }
        }
        assert!(decoder.decode(0).is_err());
    }

    #[test]
    fn rejects_malformed() {
        for bytes in [
            &b""[..],
            b"\x45ab",               // string past the end
            b"\x42\xff\xfe",         // invalid UTF-8
            b"\xa3\x00\x00\x01",     // uint16 of 3 bytes
            b"\x67\x00",             // double of 7 bytes
            b"\x02\x07",             // bool of size 2
            b"\x00\x05",             // extended type 12: container
            b"\x00\x06",             // extended type 13: end marker
            b"\x00\x09",             // extended type 16: unknown
            b"\x00\x00",             // extended type 7 is not extended
            b"\x00",                 // missing extended byte
            b"\xe1\xa1\x01\xa1\x01", // map key not a string
            b"\x20\x00",             // pointer to itself (a pointer)
            b"\x20\x10",             // pointer past the end
            b"\x5d",                 // missing size byte
        ] {
            assert!(decode(bytes).is_err(), "{bytes:?}");
        }
    }

    #[test]
    fn caps_depth_and_fan_out() {
        // 100 nested one-element arrays.
        let mut bytes = vec![0x01, 0x04];
        for _ in 0..7 {
            bytes.extend_from_slice(&bytes.clone());
        }
        assert_eq!(decode(&bytes), Err(err(130, "values nested too deeply")));

        // A chain of arrays [p, p] where both pointers target the next
        // array: 2^30 values from 180 bytes, within the depth cap.
        let mut bytes = Vec::new();
        for i in 0..30u8 {
            let next = 6 * (i + 1);
            bytes.extend_from_slice(&[0x02, 0x04, 0x20, next, 0x20, next]);
        }
        bytes.extend_from_slice(b"\xa0");
        assert!(matches!(
            decode(&bytes),
            Err(Error::InvalidData {
                reason: "value expands to too many items",
                ..
            })
        ));
    }
}
