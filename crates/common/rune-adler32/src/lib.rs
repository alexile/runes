//! Adler-32 checksum computation for byte slices and files (RFC 1950).
//!
//! Adler-32 is a fast checksum algorithm used in zlib, PNG, and other
//! compression formats. It computes two running sums (`s1` and `s2`) modulo
//! 65521 (the largest prime less than 2¹⁶), combining them into a single
//! 32-bit value: `(s2 << 16) | s1`.
//!
//! > [!NOTE]
//! > Adler-32 is faster but weaker than CRC-32. It does not reliably detect
//! > single-bit errors in all positions. Use CRC-32 when error-detection
//! > quality matters.
//!
//! # Features
//!
//! - [`checksum`] — Adler-32 of an in-memory byte slice, returned as a `u32`.
//! - [`checksum_hex`] — same, formatted as an 8-character lowercase hex string.
//! - [`checksum_file`] — reads a file from disk and returns its Adler-32.
//!
//! # Quick Start
//!
//! ```rust
//! use rune_adler32::checksum;
//!
//! let crc = checksum(b"Wikipedia");
//! assert_eq!(crc, 0x11E60398);
//! ```
//!
//! # CLI
//!
//! ```bash
//! rune-adler32 myfile.bin
//! cat data.bin | rune-adler32 -
//! ```

#![cfg_attr(not(any(feature = "std", test)), no_std)]

extern crate alloc;

use alloc::format;
use alloc::string::String;

const MOD_ADLER: u32 = 65521;

/// Computes the Adler-32 checksum of a byte slice.
///
/// # Examples
///
/// ```rust
/// use rune_adler32::checksum;
///
/// assert_eq!(checksum(b""), 1);
/// assert_eq!(checksum(b"Wikipedia"), 0x11E60398);
/// ```
#[must_use]
pub fn checksum(data: &[u8]) -> u32 {
    let mut s1: u32 = 1;
    let mut s2: u32 = 0;
    for &byte in data {
        s1 = (s1 + u32::from(byte)) % MOD_ADLER;
        s2 = (s2 + s1) % MOD_ADLER;
    }
    (s2 << 16) | s1
}

/// Computes the Adler-32 checksum of a byte slice and returns it as an
/// 8-character lowercase hex string.
///
/// # Examples
///
/// ```rust
/// use rune_adler32::checksum_hex;
///
/// assert_eq!(checksum_hex(b"Wikipedia"), "11e60398");
/// ```
#[must_use]
pub fn checksum_hex(data: &[u8]) -> String {
    format!("{:08x}", checksum(data))
}

/// Computes the Adler-32 checksum of the file at the given path.
///
/// Available with the `std` feature (on by default).
///
/// # Errors
///
/// Returns an [`std::io::Error`] if the file cannot be read.
///
/// # Examples
///
/// ```rust,no_run
/// use rune_adler32::checksum_file;
///
/// let adler = checksum_file("data.bin").unwrap();
/// println!("{adler:08x}");
/// ```
#[cfg(feature = "std")]
pub fn checksum_file(path: impl AsRef<std::path::Path>) -> std::io::Result<u32> {
    let data = std::fs::read(path)?;
    Ok(checksum(&data))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_slice_is_one() {
        assert_eq!(checksum(b""), 1);
    }

    #[test]
    fn wikipedia_reference_value() {
        assert_eq!(checksum(b"Wikipedia"), 0x11E6_0398);
    }

    #[test]
    fn single_a() {
        assert_eq!(checksum(b"a"), 0x0062_0062);
    }

    #[test]
    fn abc() {
        assert_eq!(checksum(b"abc"), 0x024D_0127);
    }

    #[test]
    fn message_digest() {
        assert_eq!(checksum(b"message digest"), 0x2975_0586);
    }

    #[test]
    fn hex_format() {
        assert_eq!(checksum_hex(b"Wikipedia"), "11e60398");
    }

    #[test]
    fn hex_padding() {
        assert_eq!(checksum_hex(b""), "00000001");
    }
}
