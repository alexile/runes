//! Shannon entropy calculator for files and byte streams.
//!
//! Entropy measures the randomness of data on a scale from `0.0` (fully
//! uniform, e.g. a file of all-zero bytes) to `8.0` (maximum randomness,
//! e.g. encrypted or truly random data). It is a fast, dependency-free way
//! to triage files during malware analysis, CTF challenges, or forensics work.
//!
//! # Features
//!
//! - Calculate entropy of any `&[u8]` byte slice
//! - Calculate entropy directly from a file path
//! - Split data into fixed-size blocks and compute per-block entropy
//! - Classify a score into a human-readable label
//!
//! # Quick Start
//!
//! ```rust
//! use rune_entropy::{entropy, classify};
//!
//! let score = entropy(b"hello world");
//! println!("{score:.4} — {}", classify(score));
//! ```
//!
//! ## Per-block analysis
//!
//! Useful for identifying partially-encrypted or packed regions within a file.
//!
//! ```rust
//! use rune_entropy::{block_entropy, classify};
//!
//! let data: Vec<u8> = (0u8..=255).cycle().take(512).collect();
//! for (i, score) in block_entropy(&data, 256).iter().enumerate() {
//!     println!("block {i:>4}  {score:.4}  {}", classify(*score));
//! }
//! ```
//!
//! # CLI
//!
//! ```bash
//! rune-entropy suspicious.bin
//! rune-entropy --block-size 512 firmware.bin
//! cat data.bin | rune-entropy -
//! ```

use std::fmt;
use std::fs;
use std::io;
use std::path::Path;

/// Classification of a Shannon entropy score into a human-readable category.
///
/// # Examples
///
/// ```rust
/// use rune_entropy::{entropy, classify, EntropyClass};
///
/// let class = classify(entropy(b"hello world"));
/// match class {
///     EntropyClass::Plaintext         => println!("likely plain text"),
///     EntropyClass::Structured        => println!("structured data"),
///     EntropyClass::CompressedOrCode  => println!("compressed or compiled"),
///     EntropyClass::EncryptedOrRandom => println!("encrypted or random"),
/// }
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntropyClass {
    /// Entropy 0.0 – 2.9: plain text, simple markup, repetitive data.
    Plaintext,
    /// Entropy 3.0 – 4.9: structured formats like JSON, XML, binary headers.
    Structured,
    /// Entropy 5.0 – 6.9: compiled code, compressed archives.
    CompressedOrCode,
    /// Entropy 7.0 – 8.0: encrypted payloads, truly random data.
    EncryptedOrRandom,
}

impl fmt::Display for EntropyClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Plaintext => f.write_str("plaintext"),
            Self::Structured => f.write_str("structured"),
            Self::CompressedOrCode => f.write_str("compressed/code"),
            Self::EncryptedOrRandom => f.write_str("encrypted/random"),
        }
    }
}

/// Calculates the Shannon entropy of a byte slice.
///
/// Returns a value in `[0.0, 8.0]` where `8.0` is maximum entropy.
///
/// # Examples
///
/// ```rust
/// use rune_entropy::entropy;
///
/// assert_eq!(entropy(&[]), 0.0);
/// assert_eq!(entropy(&[0u8; 1024]), 0.0);
///
/// // Uniform distribution across all 256 byte values → entropy ≈ 8.0
/// let uniform: Vec<u8> = (0..=255u8).cycle().take(4096).collect();
/// assert!((entropy(&uniform) - 8.0).abs() < 0.01);
/// ```
#[allow(
    clippy::cast_precision_loss,
    reason = "counts and indices stay far below 2^52, so the f64 conversion is exact"
)]
#[must_use]
pub fn entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    let mut byte_counts = [0u64; 256];
    for &byte in data {
        byte_counts[usize::from(byte)] += 1;
    }

    let total_bytes = data.len() as f64;
    byte_counts
        .iter()
        .filter(|&&count| count > 0)
        .map(|&count| {
            let probability = count as f64 / total_bytes;
            -probability * probability.log2()
        })
        .sum()
}

/// Classifies an entropy score into an [`EntropyClass`] variant.
///
/// | Range     | Variant                          |
/// |-----------|----------------------------------|
/// | 0.0 – 2.9 | [`EntropyClass::Plaintext`]        |
/// | 3.0 – 4.9 | [`EntropyClass::Structured`]       |
/// | 5.0 – 6.9 | [`EntropyClass::CompressedOrCode`] |
/// | 7.0 – 8.0 | [`EntropyClass::EncryptedOrRandom`]|
///
/// # Examples
///
/// ```rust
/// use rune_entropy::{classify, EntropyClass};
///
/// assert_eq!(classify(1.5), EntropyClass::Plaintext);
/// assert_eq!(classify(3.8), EntropyClass::Structured);
/// assert_eq!(classify(5.5), EntropyClass::CompressedOrCode);
/// assert_eq!(classify(7.9), EntropyClass::EncryptedOrRandom);
/// ```
#[must_use]
pub fn classify(score: f64) -> EntropyClass {
    match score {
        s if s < 3.0 => EntropyClass::Plaintext,
        s if s < 5.0 => EntropyClass::Structured,
        s if s < 7.0 => EntropyClass::CompressedOrCode,
        _ => EntropyClass::EncryptedOrRandom,
    }
}

/// Reads a file and returns its Shannon entropy.
///
/// # Errors
///
/// Returns an error if the file cannot be opened or read.
///
/// # Examples
///
/// ```rust,no_run
/// use rune_entropy::file_entropy;
/// use std::path::Path;
///
/// let score = file_entropy(Path::new("data.bin")).unwrap();
/// println!("{score:.4}");
/// ```
pub fn file_entropy(path: &Path) -> io::Result<f64> {
    let bytes = fs::read(path)?;
    Ok(entropy(&bytes))
}

/// Computes Shannon entropy of each fixed-size block in `data`.
///
/// Each element in the returned `Vec` is the entropy of block `i`, covering
/// bytes `i * block_size .. (i + 1) * block_size`. The final block may be
/// shorter than `block_size` if `data.len()` is not a multiple of `block_size`.
///
/// Returns an empty `Vec` if `data` is empty.
///
/// This is useful for identifying partially-encrypted or packed regions within
/// a file: blocks with entropy above `7.0` strongly suggest ciphertext or
/// compressed data, while adjacent low-entropy blocks indicate plaintext.
///
/// # Panics
///
/// Panics if `block_size` is zero.
///
/// # Examples
///
/// ```rust
/// use rune_entropy::{block_entropy, classify, EntropyClass};
///
/// let data: Vec<u8> = (0u8..=255).cycle().take(512).collect();
/// let scores = block_entropy(&data, 256);
/// assert_eq!(scores.len(), 2);
/// assert!((scores[0] - 8.0).abs() < 0.01);
/// ```
pub fn block_entropy(data: &[u8], block_size: usize) -> Vec<f64> {
    assert!(block_size > 0, "block_size must be greater than zero");
    data.chunks(block_size).map(entropy).collect()
}

/// Reads a file and returns per-block Shannon entropy scores.
///
/// Each element corresponds to a `block_size`-byte region starting at byte
/// offset `i * block_size`. See [`block_entropy`] for full semantics.
///
/// # Errors
///
/// Returns an error if the file cannot be opened or read.
///
/// # Examples
///
/// ```rust,no_run
/// use rune_entropy::{file_block_entropy, classify};
/// use std::path::Path;
///
/// let scores = file_block_entropy(Path::new("firmware.bin"), 512)?;
/// for (i, score) in scores.iter().enumerate() {
///     println!("block {i:>4} @ +{:#08x}  {score:.4}  {}", i * 512, classify(*score));
/// }
/// # Ok::<(), std::io::Error>(())
/// ```
pub fn file_block_entropy(path: &Path, block_size: usize) -> io::Result<Vec<f64>> {
    let bytes = fs::read(path)?;
    Ok(block_entropy(&bytes, block_size))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_slice_is_zero() {
        assert_eq!(entropy(&[]), 0.0);
    }

    #[test]
    fn uniform_distribution_is_max_entropy() {
        let data: Vec<u8> = (0..=255u8).cycle().take(4096).collect();
        let score = entropy(&data);
        assert!((score - 8.0).abs() < 0.01, "expected ~8.0, got {score}");
    }

    #[test]
    fn single_repeated_byte_is_zero_entropy() {
        let data = vec![0u8; 1024];
        assert_eq!(entropy(&data), 0.0);
    }

    #[test]
    fn classify_covers_all_ranges() {
        assert_eq!(classify(1.0), EntropyClass::Plaintext);
        assert_eq!(classify(3.5), EntropyClass::Structured);
        assert_eq!(classify(5.5), EntropyClass::CompressedOrCode);
        assert_eq!(classify(7.9), EntropyClass::EncryptedOrRandom);
    }

    #[test]
    fn block_entropy_splits_correctly() {
        let data: Vec<u8> = (0u8..=255).cycle().take(512).collect();
        let scores = block_entropy(&data, 256);
        assert_eq!(scores.len(), 2);
        for score in &scores {
            assert!((score - 8.0).abs() < 0.01, "expected ~8.0, got {score}");
        }
    }

    #[test]
    fn block_entropy_empty_returns_empty() {
        assert_eq!(block_entropy(&[], 64), [] as [f64; 0]);
    }

    #[test]
    fn block_entropy_partial_final_block() {
        let data = vec![0u8; 100];
        let scores = block_entropy(&data, 64);
        assert_eq!(scores.len(), 2);
        assert_eq!(scores[0], 0.0);
        assert_eq!(scores[1], 0.0);
    }

    #[test]
    #[should_panic(expected = "block_size must be greater than zero")]
    fn block_entropy_zero_block_size_panics() {
        block_entropy(b"hello", 0);
    }
}
