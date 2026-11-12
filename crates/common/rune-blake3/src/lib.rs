//! BLAKE3 hashing for byte slices and files.
//!
//! Wraps the `blake3` crate and returns digests as lowercase hex strings.
//! BLAKE3 is cryptographically secure, significantly faster than SHA-256,
//! and supports arbitrary-length output (this crate uses the standard
//! 256-bit / 32-byte output).
//!
//! # Features
//!
//! - [`hash_bytes`] — BLAKE3 of an in-memory byte slice, returned as a
//!   64-character lowercase hex string.
//! - [`hash_file`] — reads a file from disk and returns its BLAKE3 digest.
//!
//! # Quick Start
//!
//! ```rust
//! use rune_blake3::hash_bytes;
//!
//! let digest = hash_bytes(b"hello world");
//! assert_eq!(digest.len(), 64);
//! ```
//!
//! # CLI
//!
//! ```bash
//! rune-blake3 myfile.bin
//! cat data.bin | rune-blake3 -
//! ```

use std::fs;
use std::io;
use std::path::Path;

/// Compute the BLAKE3 digest of a byte slice.
///
/// Returns a 64-character lowercase hex string (256-bit output).
///
/// # Example
///
/// ```rust
/// use rune_blake3::hash_bytes;
///
/// let digest = hash_bytes(b"hello world");
/// assert_eq!(digest, "d74981efa70a0c880b8d8c1985d075dbcbf679b99a5f9914e5aaf96b831a9e24");
/// assert_eq!(hash_bytes(b"rune").len(), 64);
/// ```
#[must_use]
pub fn hash_bytes(data: &[u8]) -> String {
    blake3::hash(data).to_hex().to_string()
}

/// Computes the raw BLAKE3 digest of a byte slice, returning the 32-byte array.
///
/// Use this when you need the bytes directly — for key derivation, binary
/// comparison, or further processing — rather than a hex string.
///
/// # Example
///
/// ```rust
/// use rune_blake3::hash_raw;
///
/// let raw = hash_raw(b"hello world");
/// assert_eq!(raw.len(), 32);
/// assert_eq!(raw[0], 0xd7);
/// ```
#[must_use]
pub fn hash_raw(data: &[u8]) -> [u8; 32] {
    *blake3::hash(data).as_bytes()
}

/// Read a file and return its BLAKE3 digest as a lowercase hex string.
///
/// # Errors
///
/// Returns an [`io::Error`] if the file cannot be read.
///
/// # Example
///
/// ```rust,no_run
/// use rune_blake3::hash_file;
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
    fn known_digest() {
        assert_eq!(
            hash_bytes(b"hello world"),
            "d74981efa70a0c880b8d8c1985d075dbcbf679b99a5f9914e5aaf96b831a9e24"
        );
    }

    #[test]
    fn digest_length() {
        assert_eq!(hash_bytes(b"any input").len(), 64);
    }

    #[test]
    fn deterministic() {
        assert_eq!(hash_bytes(b"rune"), hash_bytes(b"rune"));
    }

    #[test]
    fn different_inputs_differ() {
        assert_ne!(hash_bytes(b"a"), hash_bytes(b"b"));
    }

    #[test]
    fn hash_file_roundtrip() {
        let path = std::env::temp_dir().join("rune_blake3_test.bin");
        std::fs::write(&path, b"hello world").unwrap();
        assert_eq!(
            hash_file(&path).unwrap(),
            "d74981efa70a0c880b8d8c1985d075dbcbf679b99a5f9914e5aaf96b831a9e24"
        );
    }
}
