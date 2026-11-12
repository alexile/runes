//! MD5 checksums for byte slices and files.
//!
//! Wraps the `md5` crate and returns digests as lowercase hex strings.
//!
//! > [!WARNING]
//! > MD5 is cryptographically broken and collision-prone. Do not use for
//! > security purposes (signatures, password hashing). Suitable for
//! > non-security checksums, legacy interoperability, and CTF challenges.
//!
//! # Features
//!
//! - [`hash_bytes`] — MD5 of an in-memory byte slice, returned as a
//!   32-character lowercase hex string.
//! - [`hash_file`] — reads a file from disk and returns its MD5 digest.
//!
//! # Quick Start
//!
//! ```rust
//! use rune_md5::hash_bytes;
//!
//! let digest = hash_bytes(b"hello world");
//! assert_eq!(digest, "5eb63bbbe01eeed093cb22bb8f5acdc3");
//! ```
//!
//! # CLI
//!
//! ```bash
//! rune-md5 myfile.bin
//! cat data.bin | rune-md5 -
//! ```

use std::fs;
use std::io;
use std::path::Path;

/// Compute the MD5 digest of a byte slice.
///
/// Returns a 32-character lowercase hex string.
///
/// > [!WARNING]
/// > MD5 is cryptographically broken. Do not use for security-sensitive purposes.
///
/// # Example
///
/// ```rust
/// use rune_md5::hash_bytes;
///
/// assert_eq!(hash_bytes(b""), "d41d8cd98f00b204e9800998ecf8427e");
/// assert_eq!(hash_bytes(b"hello world"), "5eb63bbbe01eeed093cb22bb8f5acdc3");
/// ```
#[must_use]
pub fn hash_bytes(data: &[u8]) -> String {
    format!("{:x}", md5::compute(data))
}

/// Compute the raw MD5 digest of a byte slice, returning the 16-byte array.
///
/// Use this when you need the bytes directly — for HMAC construction, binary
/// comparison, or further processing — rather than a hex string.
///
/// # Example
///
/// ```rust
/// use rune_md5::hash_raw;
///
/// let digest = hash_raw(b"");
/// assert_eq!(digest, [0xd4, 0x1d, 0x8c, 0xd9, 0x8f, 0x00, 0xb2, 0x04,
///                      0xe9, 0x80, 0x09, 0x98, 0xec, 0xf8, 0x42, 0x7e]);
/// ```
#[must_use]
pub fn hash_raw(data: &[u8]) -> [u8; 16] {
    md5::compute(data).0
}

/// Read a file and return its MD5 digest as a lowercase hex string.
///
/// # Errors
///
/// Returns an [`io::Error`] if the file cannot be read.
///
/// # Example
///
/// ```rust,no_run
/// use rune_md5::hash_file;
///
/// let digest = hash_file("/etc/hostname").unwrap();
/// println!("{digest}  /etc/hostname");
/// ```
pub fn hash_file(path: impl AsRef<Path>) -> io::Result<String> {
    Ok(hash_bytes(&fs::read(path)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_slice() {
        assert_eq!(hash_bytes(b""), "d41d8cd98f00b204e9800998ecf8427e");
    }

    #[test]
    fn known_digest() {
        assert_eq!(
            hash_bytes(b"hello world"),
            "5eb63bbbe01eeed093cb22bb8f5acdc3"
        );
    }

    #[test]
    fn digest_length() {
        assert_eq!(hash_bytes(b"any input").len(), 32);
    }

    #[test]
    fn deterministic() {
        assert_eq!(hash_bytes(b"rune"), hash_bytes(b"rune"));
    }

    #[test]
    fn hash_file_roundtrip() {
        let path = std::env::temp_dir().join("rune_md5_test.bin");
        std::fs::write(&path, b"hello world").unwrap();
        assert_eq!(
            hash_file(&path).unwrap(),
            "5eb63bbbe01eeed093cb22bb8f5acdc3"
        );
    }
}
