//! Encoding without lookup tables or data-dependent branches.
//!
//! Each nibble `n` becomes `n + '0'`, plus a fixed offset when `n >= 10`.
//! The `n >= 10` test is done with an add that sets bit 7, so the same code
//! runs for every input value. Eight bytes are processed at a time as one
//! `u64`.

use core::fmt::{self, Write as _};

/// Distance from `'0' + 10` to `'a'`.
pub const LOWER: u8 = b'a' - b'0' - 10;
/// Distance from `'0' + 10` to `'A'`.
pub const UPPER: u8 = b'A' - b'0' - 10;

const LANES: u64 = 0x0101_0101_0101_0101;
const NIBBLES: u64 = LANES * 0x0f;

/// Hex digit for a nibble in `0..16`.
#[inline]
const fn digit(n: u8, case: u8) -> u8 {
    // n + 0x76 reaches 0x80 exactly when n >= 10.
    let letter = (n + 0x76) >> 7;
    n + b'0' + letter * case
}

/// Turns eight nibbles (one per byte lane) into eight hex digits.
#[inline]
const fn digits(n: u64, case: u8) -> u64 {
    // No lane exceeds 0x85 here, so nothing carries into its neighbour.
    let letter = ((n + LANES * 0x76) >> 7) & LANES;
    n + LANES * b'0' as u64 + letter * case as u64
}

/// Moves byte `i` of `x` to byte `2 * i` of the result.
#[inline]
const fn spread(x: u64) -> u128 {
    let mut x = x as u128;
    x = (x | (x << 32)) & 0x0000_0000_ffff_ffff_0000_0000_ffff_ffff;
    x = (x | (x << 16)) & 0x0000_ffff_0000_ffff_0000_ffff_0000_ffff;
    (x | (x << 8)) & 0x00ff_00ff_00ff_00ff_00ff_00ff_00ff_00ff
}

#[inline]
const fn encode_block(src: [u8; 8], case: u8) -> [u8; 16] {
    let x = u64::from_be_bytes(src);
    let hi = digits((x >> 4) & NIBBLES, case);
    let lo = digits(x & NIBBLES, case);
    ((spread(hi) << 8) | spread(lo)).to_be_bytes()
}

#[inline]
const fn encode_byte(b: u8, case: u8) -> [u8; 2] {
    [digit(b >> 4, case), digit(b & 0x0f, case)]
}

/// Writes the hex form of `src` into `out`, which must be exactly twice as
/// long.
pub fn encode_into(src: &[u8], out: &mut [u8], case: u8) {
    debug_assert_eq!(out.len(), src.len() * 2);
    let (blocks, tail) = src.as_chunks::<8>();
    let (out_blocks, out_tail) = out.as_chunks_mut::<16>();
    for (s, o) in blocks.iter().zip(out_blocks) {
        *o = encode_block(*s, case);
    }
    for (&b, o) in tail.iter().zip(out_tail.as_chunks_mut::<2>().0) {
        *o = encode_byte(b, case);
    }
}

/// Formats a byte slice as hex. Created by [`display`](crate::display).
///
/// `{}` and `{:x}` print lowercase digits, `{:X}` uppercase. Width, fill and
/// alignment apply to the whole hex string.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Display<'a> {
    bytes: &'a [u8],
}

impl<'a> Display<'a> {
    pub(crate) const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes }
    }

    fn write(&self, f: &mut fmt::Formatter<'_>, case: u8) -> fmt::Result {
        let len = self.bytes.len() * 2;
        let pad = f.width().map_or(0, |w| w.saturating_sub(len));
        let (before, after) = match f.align() {
            _ if pad == 0 => (0, 0),
            Some(fmt::Alignment::Right) => (pad, 0),
            Some(fmt::Alignment::Center) => (pad / 2, pad - pad / 2),
            Some(fmt::Alignment::Left) | None => (0, pad),
        };
        let fill = f.fill();
        for _ in 0..before {
            f.write_char(fill)?;
        }
        self.write_digits(f, case)?;
        for _ in 0..after {
            f.write_char(fill)?;
        }
        Ok(())
    }

    fn write_digits(&self, f: &mut fmt::Formatter<'_>, case: u8) -> fmt::Result {
        let mut buf = [0u8; 512];
        for chunk in self.bytes.chunks(buf.len() / 2) {
            let out = &mut buf[..chunk.len() * 2];
            encode_into(chunk, out, case);
            f.write_str(core::str::from_utf8(out).map_err(|_| fmt::Error)?)?;
        }
        Ok(())
    }
}

impl fmt::Display for Display<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.write(f, LOWER)
    }
}

impl fmt::LowerHex for Display<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.write(f, LOWER)
    }
}

impl fmt::UpperHex for Display<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.write(f, UPPER)
    }
}

impl fmt::Debug for Display<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Display(\"")?;
        self.write_digits(f, LOWER)?;
        f.write_str("\")")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn naive(bytes: &[u8], upper: bool) -> String {
        bytes
            .iter()
            .map(|b| {
                if upper {
                    format!("{b:02X}")
                } else {
                    format!("{b:02x}")
                }
            })
            .collect()
    }

    #[test]
    fn digits_cover_every_nibble() {
        for n in 0..16u8 {
            let lower = char::from(digit(n, LOWER));
            let upper = char::from(digit(n, UPPER));
            assert_eq!(lower, char::from_digit(n.into(), 16).unwrap_or('?'));
            assert_eq!(upper, lower.to_ascii_uppercase());
        }
    }

    #[test]
    fn blocks_match_naive_for_all_lengths() {
        let data: Vec<u8> = (0..=255u8).rev().chain(0..=255).collect();
        for len in 0..=40 {
            for start in [0usize, 3, 250] {
                let src = &data[start..start + len];
                let mut out = vec![0u8; len * 2];
                encode_into(src, &mut out, LOWER);
                assert_eq!(out, naive(src, false).as_bytes());
                encode_into(src, &mut out, UPPER);
                assert_eq!(out, naive(src, true).as_bytes());
            }
        }
    }

    #[test]
    fn display_formats() {
        let bytes: Vec<u8> = (0..=255u8).collect();
        let d = Display::new(&bytes);
        assert_eq!(d.to_string(), naive(&bytes, false));
        assert_eq!(format!("{d:X}"), naive(&bytes, true));
        assert_eq!(format!("{:x}", Display::new(&[1, 2])), "0102");
        assert_eq!(format!("{:-<6}", Display::new(&[1, 2])), "0102--");
        assert_eq!(format!("{:?}", Display::new(&[0xab])), "Display(\"ab\")");
        let long = vec![0x5a; 1000];
        assert_eq!(format!("{:>2001}", Display::new(&long)).len(), 2001);
        assert_eq!(format!("{:*^8}", Display::new(&[1, 2])), "**0102**");
    }
}
