//! FNV-1 and FNV-1a hash functions for byte slices and strings.
//!
//! Fowler–Noll–Vo (FNV) is a fast, non-cryptographic hash function used in
//! hash tables, bloom filters, and data deduplication. This crate provides
//! both 32-bit and 64-bit variants of FNV-1 and FNV-1a.
//!
//! > [!WARNING]
//! > FNV is not a cryptographic hash. Do not use it for security-sensitive
//! > purposes such as password hashing or message authentication.
//!
//! # Variants
//!
//! | Function | Width | Algorithm |
//! |----------|-------|-----------|
//! | [`fnv1_32`] | 32-bit | FNV-1 |
//! | [`fnv1a_32`] | 32-bit | FNV-1a (recommended) |
//! | [`fnv1_64`] | 64-bit | FNV-1 |
//! | [`fnv1a_64`] | 64-bit | FNV-1a (recommended) |
//!
//! FNV-1a is generally preferred over FNV-1 because it produces better
//! avalanche behaviour (small input changes affect more output bits).
//!
//! # Quick Start
//!
//! ```rust
//! use rune_fnv::fnv1a_64;
//!
//! let hash = fnv1a_64(b"hello");
//! println!("{hash:016x}");
//! ```
//!
//! # CLI
//!
//! ```bash
//! rune-fnv hello.txt
//! cat data.bin | rune-fnv -
//! ```

#![cfg_attr(not(any(feature = "std", test)), no_std)]

const FNV_PRIME_32: u32 = 16_777_619;
const FNV_OFFSET_32: u32 = 2_166_136_261;

const FNV_PRIME_64: u64 = 1_099_511_628_211;
const FNV_OFFSET_64: u64 = 14_695_981_039_346_656_037;

/// Computes the 32-bit FNV-1 hash of a byte slice.
///
/// # Examples
///
/// ```rust
/// use rune_fnv::fnv1_32;
///
/// assert_eq!(fnv1_32(b""), 2166136261);
/// assert_eq!(fnv1_32(b"a"), 84696446);
/// ```
#[must_use]
pub fn fnv1_32(data: &[u8]) -> u32 {
    let mut hash = FNV_OFFSET_32;
    for &byte in data {
        hash = hash.wrapping_mul(FNV_PRIME_32);
        hash ^= u32::from(byte);
    }
    hash
}

/// Computes the 32-bit FNV-1a hash of a byte slice.
///
/// FNV-1a XORs before multiplying, producing better avalanche than FNV-1.
///
/// # Examples
///
/// ```rust
/// use rune_fnv::fnv1a_32;
///
/// assert_eq!(fnv1a_32(b""), 2166136261);
/// assert_eq!(fnv1a_32(b"a"), 3826002220);
/// ```
#[must_use]
pub fn fnv1a_32(data: &[u8]) -> u32 {
    let mut hash = FNV_OFFSET_32;
    for &byte in data {
        hash ^= u32::from(byte);
        hash = hash.wrapping_mul(FNV_PRIME_32);
    }
    hash
}

/// Computes the 64-bit FNV-1 hash of a byte slice.
///
/// # Examples
///
/// ```rust
/// use rune_fnv::fnv1_64;
///
/// assert_eq!(fnv1_64(b""), 14695981039346656037);
/// ```
#[must_use]
pub fn fnv1_64(data: &[u8]) -> u64 {
    let mut hash = FNV_OFFSET_64;
    for &byte in data {
        hash = hash.wrapping_mul(FNV_PRIME_64);
        hash ^= u64::from(byte);
    }
    hash
}

/// Computes the 64-bit FNV-1a hash of a byte slice.
///
/// FNV-1a XORs before multiplying, producing better avalanche than FNV-1.
///
/// # Examples
///
/// ```rust
/// use rune_fnv::fnv1a_64;
///
/// assert_eq!(fnv1a_64(b""), 14695981039346656037);
/// assert_eq!(fnv1a_64(b"hello"), 11831194018420276491);
/// ```
#[must_use]
pub fn fnv1a_64(data: &[u8]) -> u64 {
    let mut hash = FNV_OFFSET_64;
    for &byte in data {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(FNV_PRIME_64);
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fnv1_32_empty() {
        assert_eq!(fnv1_32(b""), FNV_OFFSET_32);
    }

    #[test]
    fn fnv1a_32_empty() {
        assert_eq!(fnv1a_32(b""), FNV_OFFSET_32);
    }

    #[test]
    fn fnv1_64_empty() {
        assert_eq!(fnv1_64(b""), FNV_OFFSET_64);
    }

    #[test]
    fn fnv1a_64_empty() {
        assert_eq!(fnv1a_64(b""), FNV_OFFSET_64);
    }

    #[test]
    fn fnv1a_32_hello() {
        assert_eq!(fnv1a_32(b"hello"), 1_335_831_723);
    }

    #[test]
    fn fnv1a_64_hello() {
        assert_eq!(fnv1a_64(b"hello"), 11_831_194_018_420_276_491);
    }

    #[test]
    fn fnv1_and_fnv1a_differ() {
        let data = b"test data";
        assert_ne!(fnv1_32(data), fnv1a_32(data));
        assert_ne!(fnv1_64(data), fnv1a_64(data));
    }

    #[test]
    fn different_inputs_differ() {
        assert_ne!(fnv1a_64(b"hello"), fnv1a_64(b"world"));
        assert_ne!(fnv1a_32(b"hello"), fnv1a_32(b"world"));
    }

    #[test]
    fn fnv1a_32_known_value_a() {
        assert_eq!(fnv1a_32(b"a"), 3_826_002_220);
    }
}
