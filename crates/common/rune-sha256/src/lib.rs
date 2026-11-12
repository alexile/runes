//! SHA-256 hashing for byte slices and files.
//!
//! Wraps the `RustCrypto` `sha2` crate and returns digests as lowercase hex
//! strings. Designed to be the shared hashing primitive consumed by
//! `rune-axum-csrf`, `rune-axum-signature`, and `rune-chain-tools`.
//!
//! # Features
//!
//! - [`hash_bytes`] — SHA-256 of an in-memory byte slice, returned as a 64-character lowercase hex string.
//! - [`hash_file`] — reads a file from disk and returns its SHA-256 digest.
//!
//! # Quick Start
//!
//! ```rust
//! use rune_sha256::hash_bytes;
//!
//! let digest = hash_bytes(b"hello world");
//! assert_eq!(digest, "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9");
//! ```
//!
//! # CLI
//!
//! ```bash
//! rune-sha256 myfile.bin
//! cat data.bin | rune-sha256 -
//! ```

use rune_hex::encode;
use sha2::{Digest, Sha256};
use std::fs;
use std::io;
use std::path::Path;

/// Computes the SHA-256 digest of a byte slice.
///
/// Returns a 64-character lowercase hex string.
///
/// # Examples
///
/// ```rust
/// use rune_sha256::hash_bytes;
///
/// let digest = hash_bytes(b"");
/// assert_eq!(digest, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
///
/// let digest = hash_bytes(b"hello world");
/// assert_eq!(digest, "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9");
/// ```
#[must_use]
pub fn hash_bytes(data: &[u8]) -> String {
    let digest = Sha256::digest(data);
    encode(digest.as_slice())
}

/// Computes the raw SHA-256 digest of a byte slice, returning the 32-byte array.
///
/// Use this when you need the bytes directly — for HMAC construction, binary
/// comparison, or further processing — rather than a hex string.
///
/// # Examples
///
/// ```rust
/// use rune_sha256::hash_raw;
///
/// let raw = hash_raw(b"hello world");
/// assert_eq!(raw.len(), 32);
/// // Reconstruct hex and compare
/// assert_eq!(raw[0], 0xb9);
/// ```
#[must_use]
pub fn hash_raw(data: &[u8]) -> [u8; 32] {
    let digest = Sha256::digest(data);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

/// Reads a file and returns its SHA-256 digest as a lowercase hex string.
///
/// # Errors
///
/// Returns an [`io::Error`] if the file cannot be read.
///
/// # Examples
///
/// ```rust,no_run
/// use rune_sha256::hash_file;
///
/// let digest = hash_file("/etc/hostname").unwrap();
/// println!("{digest}  /etc/hostname");
/// ```
pub fn hash_file(path: impl AsRef<Path>) -> io::Result<String> {
    let data = fs::read(path)?;
    Ok(hash_bytes(&data))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_slice() {
        assert_eq!(
            hash_bytes(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn known_digest() {
        assert_eq!(
            hash_bytes(b"hello world"),
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
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
        let path = std::env::temp_dir().join("rune_sha256_test.bin");
        std::fs::write(&path, b"hello world").unwrap();
        let digest = hash_file(&path).unwrap();
        assert_eq!(
            digest,
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
    }
}
