//! SHA-512 hashing for byte slices and files.
//!
//! Wraps the `RustCrypto` `sha2` crate and returns digests as lowercase hex
//! strings.
//!
//! # Features
//!
//! - [`hash_bytes`] — SHA-512 of an in-memory byte slice, returned as a
//!   128-character lowercase hex string.
//! - [`hash_file`] — reads a file from disk and returns its SHA-512 digest.
//!
//! # Quick Start
//!
//! ```rust
//! use rune_sha512::hash_bytes;
//!
//! let digest = hash_bytes(b"hello world");
//! assert_eq!(digest.len(), 128);
//! ```
//!
//! # CLI
//!
//! ```bash
//! rune-sha512 myfile.bin
//! cat data.bin | rune-sha512 -
//! ```

use std::fs;
use std::io;
use std::path::Path;

use rune_hex::encode;
use sha2::{Digest, Sha512};

/// Compute the SHA-512 digest of a byte slice.
///
/// Returns a 128-character lowercase hex string.
///
/// # Example
///
/// ```rust
/// use rune_sha512::hash_bytes;
///
/// let digest = hash_bytes(b"");
/// assert_eq!(digest, "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e");
///
/// assert_eq!(hash_bytes(b"rune").len(), 128);
/// ```
#[must_use]
pub fn hash_bytes(data: &[u8]) -> String {
    encode(Sha512::digest(data).as_slice())
}

/// Computes the raw SHA-512 digest of a byte slice, returning the 64-byte array.
///
/// Use this when you need the bytes directly — for HMAC construction, binary
/// comparison, or further processing — rather than a hex string.
///
/// # Example
///
/// ```rust
/// use rune_sha512::hash_raw;
///
/// let raw = hash_raw(b"hello world");
/// assert_eq!(raw.len(), 64);
/// ```
#[must_use]
pub fn hash_raw(data: &[u8]) -> [u8; 64] {
    let digest = Sha512::digest(data);
    let mut out = [0u8; 64];
    out.copy_from_slice(&digest);
    out
}

/// Read a file and return its SHA-512 digest as a lowercase hex string.
///
/// # Errors
///
/// Returns an [`io::Error`] if the file cannot be read.
///
/// # Example
///
/// ```rust,no_run
/// use rune_sha512::hash_file;
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
        assert_eq!(
            hash_bytes(b""),
            "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
        );
    }

    #[test]
    fn digest_length() {
        assert_eq!(hash_bytes(b"any input").len(), 128);
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
        let path = std::env::temp_dir().join("rune_sha512_test.bin");
        std::fs::write(&path, b"hello").unwrap();
        assert_eq!(hash_file(&path).unwrap().len(), 128);
    }
}
