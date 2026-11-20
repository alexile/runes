//! Bit packing for the sub-byte element types.
//!
//! * FP4: two codes per byte, the first in the low nibble.
//! * FP6: four codes per three bytes, little-endian: the 24-bit word
//!   `c0 | c1 << 6 | c2 << 12 | c3 << 18` is stored low byte first.
//!
//! A trailing partial group is padded with zero codes.

use crate::error::{LowpError, Result};

/// Bytes needed for `n` codes of `bits` bits each (4, 6 or 8).
#[must_use]
pub const fn packed_len(bits: u32, n: usize) -> usize {
    match bits {
        4 => n.div_ceil(2),
        6 => n.div_ceil(4) * 3,
        _ => n,
    }
}

pub(crate) fn pack_fp4_into(codes: &[u8], out: &mut [u8]) {
    for (o, pair) in out.iter_mut().zip(codes.chunks(2)) {
        let lo = pair[0] & 0x0F;
        let hi = pair.get(1).map_or(0, |&c| c & 0x0F);
        *o = lo | (hi << 4);
    }
}

pub(crate) fn unpack_fp4_into(packed: &[u8], out: &mut [u8]) {
    for (pair, &b) in out.chunks_mut(2).zip(packed) {
        pair[0] = b & 0x0F;
        if let Some(h) = pair.get_mut(1) {
            *h = b >> 4;
        }
    }
}

pub(crate) fn pack_fp6_into(codes: &[u8], out: &mut [u8]) {
    for (o, quad) in out.chunks_mut(3).zip(codes.chunks(4)) {
        let mut w = 0u32;
        for (i, &c) in quad.iter().enumerate() {
            w |= u32::from(c & 0x3F) << (6 * i);
        }
        o.copy_from_slice(&w.to_le_bytes()[..3]);
    }
}

pub(crate) fn unpack_fp6_into(packed: &[u8], out: &mut [u8]) {
    for (quad, bytes) in out.chunks_mut(4).zip(packed.chunks(3)) {
        let w = bytes
            .iter()
            .enumerate()
            .fold(0u32, |acc, (i, &b)| acc | (u32::from(b) << (8 * i)));
        for (i, c) in quad.iter_mut().enumerate() {
            *c = ((w >> (6 * i)) & 0x3F) as u8;
        }
    }
}

pub(crate) fn pack_into(bits: u32, codes: &[u8], out: &mut [u8]) {
    match bits {
        4 => pack_fp4_into(codes, out),
        6 => pack_fp6_into(codes, out),
        _ => out.copy_from_slice(codes),
    }
}

pub(crate) fn unpack_into(bits: u32, packed: &[u8], out: &mut [u8]) {
    match bits {
        4 => unpack_fp4_into(packed, out),
        6 => unpack_fp6_into(packed, out),
        _ => out.copy_from_slice(packed),
    }
}

/// Packs 4-bit codes (upper bits ignored), two per byte.
///
/// ```
/// assert_eq!(rune_lowp::pack::pack_fp4(&[0x1, 0x2, 0xF]), [0x21, 0x0F]);
/// ```
#[must_use]
pub fn pack_fp4(codes: &[u8]) -> Vec<u8> {
    let mut out = vec![0; packed_len(4, codes.len())];
    pack_fp4_into(codes, &mut out);
    out
}

/// Unpacks `n` 4-bit codes.
///
/// # Errors
///
/// [`LowpError::LengthMismatch`] if `packed` is not exactly
/// `packed_len(4, n)` bytes.
pub fn unpack_fp4(packed: &[u8], n: usize) -> Result<Vec<u8>> {
    check(packed.len(), packed_len(4, n))?;
    let mut out = vec![0; n];
    unpack_fp4_into(packed, &mut out);
    Ok(out)
}

/// Packs 6-bit codes (upper bits ignored), four per three bytes.
///
/// ```
/// // 0b000001, 0b000010, 0b000011, 0b111111
/// assert_eq!(rune_lowp::pack::pack_fp6(&[1, 2, 3, 63]), [0x81, 0x30, 0xFC]);
/// ```
#[must_use]
pub fn pack_fp6(codes: &[u8]) -> Vec<u8> {
    let mut out = vec![0; packed_len(6, codes.len())];
    pack_fp6_into(codes, &mut out);
    out
}

/// Unpacks `n` 6-bit codes.
///
/// # Errors
///
/// [`LowpError::LengthMismatch`] if `packed` is not exactly
/// `packed_len(6, n)` bytes.
pub fn unpack_fp6(packed: &[u8], n: usize) -> Result<Vec<u8>> {
    check(packed.len(), packed_len(6, n))?;
    let mut out = vec![0; n];
    unpack_fp6_into(packed, &mut out);
    Ok(out)
}

const fn check(found: usize, expected: usize) -> Result<()> {
    if found == expected {
        Ok(())
    } else {
        Err(LowpError::LengthMismatch { expected, found })
    }
}
