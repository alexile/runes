//! Data-section encoder: the inverse of [`crate::decode`], without pointers.

use crate::Error;
use crate::decode::{
    TYPE_ARRAY, TYPE_BOOL, TYPE_BYTES, TYPE_DOUBLE, TYPE_FLOAT, TYPE_INT32, TYPE_MAP, TYPE_STRING,
    TYPE_UINT16, TYPE_UINT32, TYPE_UINT64, TYPE_UINT128,
};
use crate::value::Value;

/// Largest size the 3-byte size form can express.
const MAX_SIZE: usize = 65_821 + 0xff_ffff;

fn control(ty: u8, size: usize, out: &mut Vec<u8>) -> Result<(), Error> {
    let (low, extra): (u8, &[u8]) = match size {
        0..29 => (u8::try_from(size).unwrap_or(0), &[]),
        29..285 => (
            29,
            &(size - 29).to_be_bytes()[std::mem::size_of::<usize>() - 1..],
        ),
        285..65_821 => (
            30,
            &(size - 285).to_be_bytes()[std::mem::size_of::<usize>() - 2..],
        ),
        65_821..=MAX_SIZE => (
            31,
            &(size - 65_821).to_be_bytes()[std::mem::size_of::<usize>() - 3..],
        ),
        _ => return Err(Error::Build("value is longer than the format allows")),
    };
    if ty <= TYPE_MAP {
        out.push((ty << 5) | low);
    } else {
        out.push(low);
        out.push(ty - 7);
    }
    out.extend_from_slice(extra);
    Ok(())
}

/// Appends the big-endian bytes of `n` without leading zeros.
fn uint(ty: u8, n: u128, width: usize, out: &mut Vec<u8>) -> Result<(), Error> {
    let bytes = n.to_be_bytes();
    let skip = bytes.iter().take_while(|&&b| b == 0).count();
    let significant = &bytes[skip.max(16 - width)..];
    control(ty, significant.len(), out)?;
    out.extend_from_slice(significant);
    Ok(())
}

pub fn encode(value: &Value, out: &mut Vec<u8>) -> Result<(), Error> {
    match value {
        Value::String(s) => {
            control(TYPE_STRING, s.len(), out)?;
            out.extend_from_slice(s.as_bytes());
        }
        Value::Bytes(bytes) => {
            control(TYPE_BYTES, bytes.len(), out)?;
            out.extend_from_slice(bytes);
        }
        Value::Double(n) => {
            control(TYPE_DOUBLE, 8, out)?;
            out.extend_from_slice(&n.to_be_bytes());
        }
        Value::Float(n) => {
            control(TYPE_FLOAT, 4, out)?;
            out.extend_from_slice(&n.to_be_bytes());
        }
        Value::Uint16(n) => uint(TYPE_UINT16, (*n).into(), 2, out)?,
        Value::Uint32(n) => uint(TYPE_UINT32, (*n).into(), 4, out)?,
        Value::Uint64(n) => uint(TYPE_UINT64, (*n).into(), 8, out)?,
        Value::Uint128(n) => uint(TYPE_UINT128, *n, 16, out)?,
        Value::Int32(n) => {
            // Zero-padded decoding means negatives need all four bytes.
            let raw = u32::from_be_bytes(n.to_be_bytes());
            uint(TYPE_INT32, raw.into(), 4, out)?;
        }
        Value::Bool(b) => control(TYPE_BOOL, usize::from(*b), out)?,
        Value::Map(map) => {
            control(TYPE_MAP, map.len(), out)?;
            for (key, value) in map {
                control(TYPE_STRING, key.len(), out)?;
                out.extend_from_slice(key.as_bytes());
                encode(value, out)?;
            }
        }
        Value::Array(items) => {
            control(TYPE_ARRAY, items.len(), out)?;
            for item in items {
                encode(item, out)?;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn enc(value: &Value) -> Vec<u8> {
        value.encode().unwrap()
    }

    #[test]
    fn known_encodings() {
        assert_eq!(enc(&Value::from("foo")), b"\x43foo");
        assert_eq!(enc(&Value::Uint16(0)), b"\xa0");
        assert_eq!(enc(&Value::Uint16(500)), b"\xa2\x01\xf4");
        assert_eq!(enc(&Value::Int32(-1)), b"\x04\x01\xff\xff\xff\xff");
        assert_eq!(enc(&Value::Int32(255)), b"\x01\x01\xff");
        assert_eq!(enc(&Value::Bool(true)), b"\x01\x07");
        assert_eq!(enc(&Value::Uint128(1)), b"\x01\x03\x01");
        assert_eq!(enc(&Value::Array(vec![])), b"\x00\x04");
        assert_eq!(enc(&Value::from("a".repeat(30)))[..2], [0x5d, 1]);
        assert_eq!(enc(&Value::Bytes(vec![0; 543]))[..3], [0x9e, 1, 2]);
        assert_eq!(enc(&Value::Bytes(vec![0; 65_822]))[..4], [0x9f, 0, 0, 1]);
    }

    #[test]
    fn size_boundaries_round_trip() {
        for len in [0, 28, 29, 284, 285, 65_820, 65_821, 65_822] {
            let value = Value::Bytes(vec![0xab; len]);
            assert_eq!(Value::decode(&enc(&value)), Ok(value), "{len}");
        }
    }
}
