//! CRC-32 checksum computation for byte slices and files.
//!
//! Implements the IEEE 802.3 polynomial (0xEDB88320, reflected form) used in
//! Ethernet, ZIP, PNG, gzip, and most common CRC-32 contexts. The lookup table
//! is computed once at startup and reused for all subsequent calls.
//!
//! # Features
//!
//! - [`checksum`] — CRC-32 of an in-memory byte slice, returned as a `u32`.
//! - [`checksum_hex`] — same, formatted as an 8-character lowercase hex string.
//! - [`checksum_file`] — reads a file from disk and returns its CRC-32.
//!
//! # Quick Start
//!
//! ```rust
//! use rune_crc32::checksum;
//!
//! let crc = checksum(b"hello world");
//! assert_eq!(crc, 0x0D4A1185);
//! ```
//!
//! # CLI
//!
//! ```bash
//! rune-crc32 myfile.bin
//! cat data.bin | rune-crc32 -
//! ```

#![cfg_attr(not(any(feature = "std", test)), no_std)]

extern crate alloc;

use alloc::format;
use alloc::string::String;

/// The reflected IEEE 802.3 lookup table, computed at compile time.
static TABLE: [u32; 256] = make_table();

const fn make_table() -> [u32; 256] {
    let mut t = [0u32; 256];
    let mut byte = 0u32;
    while byte < 256 {
        let mut crc = byte;
        let mut bit = 0;
        while bit < 8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ 0xEDB8_8320;
            } else {
                crc >>= 1;
            }
            bit += 1;
        }
        t[byte as usize] = crc;
        byte += 1;
    }
    t
}

fn table() -> &'static [u32; 256] {
    &TABLE
}

/// Computes the CRC-32 checksum of a byte slice.
///
/// Uses the IEEE 802.3 polynomial (0xEDB88320) — the same variant used by
/// Ethernet, ZIP, PNG, and gzip.
///
/// # Examples
///
/// ```rust
/// use rune_crc32::checksum;
///
/// assert_eq!(checksum(b""), 0x00000000);
/// assert_eq!(checksum(b"hello world"), 0x0D4A1185);
/// assert_eq!(checksum(b"123456789"), 0xCBF43926);
/// ```
#[must_use]
pub fn checksum(data: &[u8]) -> u32 {
    let table = table();
    let mut crc: u32 = 0xFFFF_FFFF;
    for &byte in data {
        let index = ((crc ^ u32::from(byte)) & 0xFF) as usize;
        crc = (crc >> 8) ^ table[index];
    }
    crc ^ 0xFFFF_FFFF
}

/// Computes the CRC-32 checksum of a byte slice and returns it as an 8-character
/// lowercase hex string.
///
/// # Examples
///
/// ```rust
/// use rune_crc32::checksum_hex;
///
/// assert_eq!(checksum_hex(b"123456789"), "cbf43926");
/// assert_eq!(checksum_hex(b"hello world"), "0d4a1185");
/// ```
#[must_use]
pub fn checksum_hex(data: &[u8]) -> String {
    format!("{:08x}", checksum(data))
}

/// Computes the CRC-32 checksum of the file at the given path.
///
/// Reads the entire file into memory before computing the checksum.
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
/// use rune_crc32::checksum_file;
///
/// let crc = checksum_file("data.bin").unwrap();
/// println!("{crc:08x}");
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
    fn empty_slice() {
        assert_eq!(checksum(b""), 0x0000_0000);
    }

    #[test]
    fn check_value_standard() {
        assert_eq!(checksum(b"123456789"), 0xCBF4_3926);
    }

    #[test]
    fn hello_world() {
        assert_eq!(checksum(b"hello world"), 0x0D4A_1185);
    }

    #[test]
    fn hex_format_padded() {
        assert_eq!(checksum_hex(b""), "00000000");
        assert_eq!(checksum_hex(b"123456789"), "cbf43926");
    }

    #[test]
    fn single_zero_byte() {
        assert_eq!(checksum(b"\x00"), 0xD202_EF8D);
    }

    #[test]
    fn all_ones_byte() {
        assert_eq!(checksum(b"\xFF"), 0xFF00_0000);
    }

    #[test]
    fn incremental_consistency() {
        let full = checksum(b"helloworld");
        assert_ne!(full, checksum(b"hello"));
        assert_ne!(full, checksum(b"world"));
    }
}
