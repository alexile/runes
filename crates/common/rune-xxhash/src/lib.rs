//! xxHash — extremely fast non-cryptographic hash.
//!
//! Pure-Rust implementation of xxHash by Yann Collet, covering the two most
//! widely deployed variants:
//!
//! | Function | Output | Throughput (approx) |
//! |---|---|---|
//! | [`xxh32`] | `u32` | ~5 GB/s on 32-bit; faster than MD5 on 64-bit |
//! | [`xxh64`] | `u64` | ~9 GB/s on 64-bit |
//!
//! xxHash is the hash function behind LZ4, `RocksDB` bloom filters, and `ClickHouse`
//! checksums.
//!
//! > [!NOTE]
//! > xxHash is **not** a cryptographic hash. Do not use it for password hashing,
//! > MACs, or any security-sensitive purpose.
//!
//! # Features
//!
//! - [`xxh32`] — 32-bit hash, good on both 32-bit and 64-bit platforms
//! - [`xxh64`] — 64-bit hash, fastest on 64-bit hardware
//! - Both functions are seed-parameterised for independent hash families
//! - Zero dependencies, pure safe Rust
//!
//! # Quick Start
//!
//! ```rust
//! use rune_xxhash::{xxh32, xxh64};
//!
//! let h32 = xxh32(b"hello", 0);
//! println!("xxh32: {h32:#010x}");
//!
//! let h64 = xxh64(b"hello", 0);
//! println!("xxh64: {h64:#018x}");
//! ```
//!
//! # CLI
//!
//! ```bash
//! rune-xxhash file.bin           # xxh64 by default
//! rune-xxhash --x32 file.bin     # xxh32
//! echo -n "hello" | rune-xxhash -
//! ```

#![cfg_attr(not(any(feature = "std", test)), no_std)]

const PRIME32_1: u32 = 0x9E37_79B1;
const PRIME32_2: u32 = 0x85EB_CA77;
const PRIME32_3: u32 = 0xC2B2_AE3D;
const PRIME32_4: u32 = 0x27D4_EB2F;
const PRIME32_5: u32 = 0x1656_67B1;

const PRIME64_1: u64 = 0x9E37_79B1_85EB_CA87;
const PRIME64_2: u64 = 0xC2B2_AE3D_27D4_EB4F;
const PRIME64_3: u64 = 0x1656_67B1_9E37_79F9;
const PRIME64_4: u64 = 0x85EB_CA77_C2B2_AE63;
const PRIME64_5: u64 = 0x27D4_EB2F_1656_67C5;

/// Computes the xxHash 32-bit hash of `data` with the given `seed`.
///
/// # Examples
///
/// ```rust
/// use rune_xxhash::xxh32;
///
/// assert_eq!(xxh32(b"", 0), 0x02cc5d05);
/// assert_eq!(xxh32(b"hello", 0), 4211111929);
/// assert_eq!(xxh32(b"hello", 42), 1292028262);
/// ```
#[allow(
    clippy::cast_possible_truncation,
    reason = "values are masked or range-limited first; truncation is the intended encoding"
)]
#[must_use]
pub fn xxh32(data: &[u8], seed: u32) -> u32 {
    let total_len = data.len();
    let mut pos = 0;

    let mut acc: u32 = if total_len >= 16 {
        let mut v1 = seed.wrapping_add(PRIME32_1).wrapping_add(PRIME32_2);
        let mut v2 = seed.wrapping_add(PRIME32_2);
        let mut v3 = seed;
        let mut v4 = seed.wrapping_sub(PRIME32_1);

        while pos + 16 <= total_len {
            v1 = round32(v1, read_u32_le(data, pos));
            v2 = round32(v2, read_u32_le(data, pos + 4));
            v3 = round32(v3, read_u32_le(data, pos + 8));
            v4 = round32(v4, read_u32_le(data, pos + 12));
            pos += 16;
        }

        v1.rotate_left(1)
            .wrapping_add(v2.rotate_left(7))
            .wrapping_add(v3.rotate_left(12))
            .wrapping_add(v4.rotate_left(18))
    } else {
        seed.wrapping_add(PRIME32_5)
    };

    acc = acc.wrapping_add(total_len as u32);

    while pos + 4 <= total_len {
        let lane = read_u32_le(data, pos);
        acc = acc.wrapping_add(lane.wrapping_mul(PRIME32_3));
        acc = acc.rotate_left(17).wrapping_mul(PRIME32_4);
        pos += 4;
    }

    while pos < total_len {
        acc = acc.wrapping_add(u32::from(data[pos]).wrapping_mul(PRIME32_5));
        acc = acc.rotate_left(11).wrapping_mul(PRIME32_1);
        pos += 1;
    }

    avalanche32(acc)
}

/// Computes the xxHash 64-bit hash of `data` with the given `seed`.
///
/// # Examples
///
/// ```rust
/// use rune_xxhash::xxh64;
///
/// assert_eq!(xxh64(b"", 0), 0xef46db3751d8e999);
/// let h = xxh64(b"hello", 0);
/// assert!(h != 0);
/// assert_eq!(xxh64(b"hello", 42), 14078989533569169714);
/// ```
#[must_use]
pub fn xxh64(data: &[u8], seed: u64) -> u64 {
    let total_len = data.len();
    let mut pos = 0;

    let mut acc: u64 = if total_len >= 32 {
        let mut v1 = seed.wrapping_add(PRIME64_1).wrapping_add(PRIME64_2);
        let mut v2 = seed.wrapping_add(PRIME64_2);
        let mut v3 = seed;
        let mut v4 = seed.wrapping_sub(PRIME64_1);

        while pos + 32 <= total_len {
            v1 = round64(v1, read_u64_le(data, pos));
            v2 = round64(v2, read_u64_le(data, pos + 8));
            v3 = round64(v3, read_u64_le(data, pos + 16));
            v4 = round64(v4, read_u64_le(data, pos + 24));
            pos += 32;
        }

        let mut h = v1
            .rotate_left(1)
            .wrapping_add(v2.rotate_left(7))
            .wrapping_add(v3.rotate_left(12))
            .wrapping_add(v4.rotate_left(18));
        h = merge_round64(h, v1);
        h = merge_round64(h, v2);
        h = merge_round64(h, v3);
        h = merge_round64(h, v4);
        h
    } else {
        seed.wrapping_add(PRIME64_5)
    };

    acc = acc.wrapping_add(total_len as u64);

    while pos + 8 <= total_len {
        let lane = read_u64_le(data, pos);
        acc ^= round64(0, lane);
        acc = acc
            .rotate_left(27)
            .wrapping_mul(PRIME64_1)
            .wrapping_add(PRIME64_4);
        pos += 8;
    }

    if pos + 4 <= total_len {
        let lane = read_u32_le(data, pos);
        acc ^= u64::from(lane).wrapping_mul(PRIME64_1);
        acc = acc
            .rotate_left(23)
            .wrapping_mul(PRIME64_2)
            .wrapping_add(PRIME64_3);
        pos += 4;
    }

    while pos < total_len {
        acc ^= u64::from(data[pos]).wrapping_mul(PRIME64_5);
        acc = acc.rotate_left(11).wrapping_mul(PRIME64_1);
        pos += 1;
    }

    avalanche64(acc)
}

const fn round32(acc: u32, lane: u32) -> u32 {
    acc.wrapping_add(lane.wrapping_mul(PRIME32_2))
        .rotate_left(13)
        .wrapping_mul(PRIME32_1)
}

const fn avalanche32(mut h: u32) -> u32 {
    h ^= h >> 15;
    h = h.wrapping_mul(PRIME32_2);
    h ^= h >> 13;
    h = h.wrapping_mul(PRIME32_3);
    h ^= h >> 16;
    h
}

const fn round64(acc: u64, lane: u64) -> u64 {
    acc.wrapping_add(lane.wrapping_mul(PRIME64_2))
        .rotate_left(31)
        .wrapping_mul(PRIME64_1)
}

fn merge_round64(acc: u64, val: u64) -> u64 {
    let val = round64(0, val);
    acc.bitxor(val)
        .wrapping_mul(PRIME64_1)
        .wrapping_add(PRIME64_4)
}

const fn avalanche64(mut h: u64) -> u64 {
    h ^= h >> 33;
    h = h.wrapping_mul(PRIME64_2);
    h ^= h >> 29;
    h = h.wrapping_mul(PRIME64_3);
    h ^= h >> 32;
    h
}

trait BitXor: Sized + core::ops::BitXor<Output = Self> {
    fn bitxor(self, rhs: Self) -> Self {
        self ^ rhs
    }
}

impl BitXor for u64 {}

/// Little-endian `u32` at `pos`. Callers guarantee `pos + 4 <= data.len()`.
const fn read_u32_le(data: &[u8], pos: usize) -> u32 {
    u32::from_le_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]])
}

/// Little-endian `u64` at `pos`. Callers guarantee `pos + 8 <= data.len()`.
const fn read_u64_le(data: &[u8], pos: usize) -> u64 {
    u64::from_le_bytes([
        data[pos],
        data[pos + 1],
        data[pos + 2],
        data[pos + 3],
        data[pos + 4],
        data[pos + 5],
        data[pos + 6],
        data[pos + 7],
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xxh32_empty() {
        assert_eq!(xxh32(b"", 0), 0x02cc_5d05);
    }

    #[test]
    fn xxh32_hello() {
        assert_eq!(xxh32(b"hello", 0), 4_211_111_929);
    }

    #[test]
    fn xxh32_seeded() {
        assert_eq!(xxh32(b"hello", 42), 1_292_028_262);
    }

    #[test]
    fn xxh32_deterministic() {
        let a = xxh32(b"xxHash is fast", 0);
        let b = xxh32(b"xxHash is fast", 0);
        assert_eq!(a, b);
    }

    #[test]
    fn xxh64_empty() {
        assert_eq!(xxh64(b"", 0), 0xef46_db37_51d8_e999);
    }

    #[test]
    fn xxh64_hello() {
        assert_eq!(xxh64(b"hello", 0), 0x26c7_827d_889f_6da3);
    }

    #[test]
    fn xxh64_seeded() {
        assert_eq!(xxh64(b"hello", 42), 14_078_989_533_569_169_714);
    }

    #[test]
    fn xxh64_deterministic() {
        let a = xxh64(b"xxHash is fast", 0);
        let b = xxh64(b"xxHash is fast", 0);
        assert_eq!(a, b);
    }

    #[test]
    fn different_inputs_different_hashes() {
        assert_ne!(xxh32(b"foo", 0), xxh32(b"bar", 0));
        assert_ne!(xxh64(b"foo", 0), xxh64(b"bar", 0));
    }
}
