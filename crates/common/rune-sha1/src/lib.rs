//! SHA-1 hashing for byte slices and files.
//!
//! Wraps the `RustCrypto` `sha1` crate and returns digests as lowercase hex
//! strings.
//!
//! > [!WARNING]
//! > SHA-1 is cryptographically broken and must not be used for security
//! > purposes (signatures, certificates, password hashing). It is included
//! > here for interoperability with legacy systems and CTF challenges where
//! > SHA-1 checksums are required.
//!
//! # Features
//!
//! - [`hash_bytes`] — SHA-1 of an in-memory byte slice, returned as a
//!   40-character lowercase hex string.
//! - [`hash_file`] — reads a file from disk and returns its SHA-1 digest.
//!
//! # Quick Start
//!
//! ```rust
//! use rune_sha1::hash_bytes;
//!
//! let digest = hash_bytes(b"hello world");
//! assert_eq!(digest, "2aae6c35c94fcfb415dbe95f408b9ce91ee846ed");
//! ```
//!
//! # CLI
//!
//! ```bash
//! rune-sha1 myfile.bin
//! cat data.bin | rune-sha1 -
//! ```

use std::fs;
use std::io;
use std::path::Path;

use rune_hex::encode;
use sha1::{Digest, Sha1};

/// Compute the SHA-1 digest of a byte slice.
///
/// Returns a 40-character lowercase hex string.
///
/// > [!WARNING]
/// > SHA-1 is cryptographically broken. Do not use for security-sensitive purposes.
///
/// # Example
///
/// ```rust
/// use rune_sha1::hash_bytes;
///
/// assert_eq!(hash_bytes(b""), "da39a3ee5e6b4b0d3255bfef95601890afd80709");
/// assert_eq!(hash_bytes(b"hello world"), "2aae6c35c94fcfb415dbe95f408b9ce91ee846ed");
/// ```
#[must_use]
pub fn hash_bytes(data: &[u8]) -> String {
    encode(Sha1::digest(data).as_slice())
}

/// Compute the raw SHA-1 digest of a byte slice, returning the 20-byte array.
///
/// Use this when you need the bytes directly — for HMAC construction, binary
/// comparison, or further processing — rather than a hex string.
///
/// > [!WARNING]
/// > SHA-1 is cryptographically broken. Do not use for security-sensitive purposes.
///
/// # Example
///
/// ```rust
/// use rune_sha1::hash_raw;
///
/// let raw = hash_raw(b"hello world");
/// assert_eq!(raw.len(), 20);
/// assert_eq!(raw[0], 0x2a);
/// ```
#[must_use]
pub fn hash_raw(data: &[u8]) -> [u8; 20] {
    let digest = Sha1::digest(data);
    let mut out = [0u8; 20];
    out.copy_from_slice(&digest);
    out
}

/// Read a file and return its SHA-1 digest as a lowercase hex string.
///
/// # Errors
///
/// Returns an [`io::Error`] if the file cannot be read.
///
/// # Example
///
/// ```rust,no_run
/// use rune_sha1::hash_file;
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
        assert_eq!(hash_bytes(b""), "da39a3ee5e6b4b0d3255bfef95601890afd80709");
    }

    #[test]
    fn known_digest() {
        assert_eq!(
            hash_bytes(b"hello world"),
            "2aae6c35c94fcfb415dbe95f408b9ce91ee846ed"
        );
    }

    #[test]
    fn digest_length() {
        assert_eq!(hash_bytes(b"any input").len(), 40);
    }

    #[test]
    fn deterministic() {
        assert_eq!(hash_bytes(b"rune"), hash_bytes(b"rune"));
    }

    #[test]
    fn hash_file_roundtrip() {
        let path = std::env::temp_dir().join("rune_sha1_test.bin");
        std::fs::write(&path, b"hello world").unwrap();
        assert_eq!(
            hash_file(&path).unwrap(),
            "2aae6c35c94fcfb415dbe95f408b9ce91ee846ed"
        );
    }
}
