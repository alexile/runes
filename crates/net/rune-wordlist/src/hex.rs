//! Strict lowercase hex for fixed-size fields.

use crate::Error;

const DIGITS: &[u8; 16] = b"0123456789abcdef";

/// Lowercase hex of `bytes`.
pub fn encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(char::from(DIGITS[usize::from(b >> 4)]));
        out.push(char::from(DIGITS[usize::from(b & 0x0f)]));
    }
    out
}

/// Decodes exactly `N` bytes from `2 * N` lowercase hex digits.
pub fn decode<const N: usize>(text: &str, what: &'static str) -> Result<[u8; N], Error> {
    let err = || Error::InvalidHex { what, len: N * 2 };
    let digits = text.as_bytes();
    if digits.len() != N * 2 {
        return Err(err());
    }
    let nibble = |c: u8| match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        _ => Err(err()),
    };
    let mut out = [0u8; N];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = (nibble(digits[2 * i])? << 4) | nibble(digits[2 * i + 1])?;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips() {
        let bytes = [0x00, 0x7f, 0x80, 0xff, 0x1a];
        assert_eq!(encode(&bytes), "007f80ff1a");
        assert_eq!(decode::<5>("007f80ff1a", "x").unwrap(), bytes);
    }

    #[test]
    fn strict() {
        assert!(decode::<2>("ABCD", "x").is_err());
        assert!(decode::<2>("abc", "x").is_err());
        assert!(decode::<2>("abcdef", "x").is_err());
        assert!(decode::<2>("0xab", "x").is_err());
    }
}
