//! `MurmurHash3` — fast, non-cryptographic hash for hash tables and checksums.
//!
//! Pure-Rust implementation of the `MurmurHash3` algorithm by Austin Appleby,
//! covering the two variants most widely used in practice:
//!
//! | Function | Output | Platform | Use case |
//! |---|---|---|---|
//! | [`murmurhash3_x86_32`] | `u32` | 32 and 64-bit | Hash tables, checksums, small data |
//! | [`murmurhash3_x64_128`] | `u128` | 64-bit optimised | Large data, databases, Cassandra, Elasticsearch |
//!
//! > [!NOTE]
//! > MurmurHash3 is **not** a cryptographic hash. Do not use it for password
//! > hashing, MACs, or any security-sensitive purpose.
//!
//! # Features
//!
//! - [`murmurhash3_x86_32`] — 32-bit hash, works on any platform
//! - [`murmurhash3_x64_128`] — 128-bit hash, optimised for 64-bit hardware
//! - Both functions are seed-parameterised for independent hash families
//! - Zero dependencies, `#[no_std]`-compatible (no allocation)
//!
//! # Quick Start
//!
//! ```rust
//! use rune_murmur::{murmurhash3_x86_32, murmurhash3_x64_128};
//!
//! let h32 = murmurhash3_x86_32(b"hello", 0);
//! println!("32-bit: {h32:#010x}");
//!
//! let h128 = murmurhash3_x64_128(b"hello", 0);
//! println!("128-bit: {h128:#034x}");
//! ```
//!
//! # CLI
//!
//! ```bash
//! rune-murmur hello.txt           # 32-bit hash of a file
//! rune-murmur --x128 hello.txt    # 128-bit hash
//! echo -n "hello" | rune-murmur - # hash stdin
//! ```

#![cfg_attr(not(any(feature = "std", test)), no_std)]

/// Computes the `MurmurHash3` 32-bit hash of `data` with the given `seed`.
///
/// This is the `MurmurHash3_x86_32` variant — suitable for 32-bit and 64-bit
/// platforms. Output is a single `u32`.
///
/// # Examples
///
/// ```rust
/// use rune_murmur::murmurhash3_x86_32;
///
/// assert_eq!(murmurhash3_x86_32(b"", 0), 0);
/// assert_eq!(murmurhash3_x86_32(b"hello", 0), 0x248bfa47);
/// assert_eq!(murmurhash3_x86_32(b"hello", 42), 0xe2dbd2e1);
/// ```
#[allow(
    clippy::cast_possible_truncation,
    reason = "values are masked or range-limited first; truncation is the intended encoding"
)]
#[must_use]
pub fn murmurhash3_x86_32(data: &[u8], seed: u32) -> u32 {
    const C1: u32 = 0xcc9e_2d51;
    const C2: u32 = 0x1b87_3593;

    let total_bytes = data.len();
    let num_blocks = total_bytes / 4;
    let mut h1 = seed;

    for block_idx in 0..num_blocks {
        let offset = block_idx * 4;
        let mut k1 = u32::from_le_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ]);
        k1 = k1.wrapping_mul(C1);
        k1 = k1.rotate_left(15);
        k1 = k1.wrapping_mul(C2);
        h1 ^= k1;
        h1 = h1.rotate_left(13);
        h1 = h1.wrapping_mul(5).wrapping_add(0xe654_6b64);
    }

    let tail_offset = num_blocks * 4;
    let tail = &data[tail_offset..];
    let mut k1: u32 = 0;

    match tail.len() {
        3 => {
            k1 ^= u32::from(tail[2]) << 16;
            k1 ^= u32::from(tail[1]) << 8;
            k1 ^= u32::from(tail[0]);
            k1 = k1.wrapping_mul(C1);
            k1 = k1.rotate_left(15);
            k1 = k1.wrapping_mul(C2);
            h1 ^= k1;
        }
        2 => {
            k1 ^= u32::from(tail[1]) << 8;
            k1 ^= u32::from(tail[0]);
            k1 = k1.wrapping_mul(C1);
            k1 = k1.rotate_left(15);
            k1 = k1.wrapping_mul(C2);
            h1 ^= k1;
        }
        1 => {
            k1 ^= u32::from(tail[0]);
            k1 = k1.wrapping_mul(C1);
            k1 = k1.rotate_left(15);
            k1 = k1.wrapping_mul(C2);
            h1 ^= k1;
        }
        _ => {}
    }

    h1 ^= total_bytes as u32;
    fmix32(h1)
}

/// Computes the `MurmurHash3` 128-bit hash of `data` with the given `seed`.
///
/// This is the `MurmurHash3_x64_128` variant, optimised for 64-bit platforms.
/// The `u128` value packs the two 64-bit halves: low 64 bits = h1, high 64 bits = h2.
///
/// This is the variant used by Cassandra, Elasticsearch, and Guava's
/// `Hashing.murmur3_128()`.
///
/// # Examples
///
/// ```rust
/// use rune_murmur::murmurhash3_x64_128;
///
/// assert_eq!(murmurhash3_x64_128(b"", 0), 0);
/// let h = murmurhash3_x64_128(b"hello", 0);
/// assert!(h != 0);
/// ```
#[allow(
    clippy::too_many_lines,
    reason = "the reference algorithm, kept in one piece for auditability"
)]
#[must_use]
pub fn murmurhash3_x64_128(data: &[u8], seed: u32) -> u128 {
    const C1: u64 = 0x87c3_7b91_1142_53d5;
    const C2: u64 = 0x4cf5_ad43_2745_937f;

    let total_bytes = data.len();
    let num_blocks = total_bytes / 16;
    let mut h1 = u64::from(seed);
    let mut h2 = u64::from(seed);

    for block_idx in 0..num_blocks {
        let offset = block_idx * 16;
        let mut k1 = read_u64_le(data, offset);
        let mut k2 = read_u64_le(data, offset + 8);

        k1 = k1.wrapping_mul(C1);
        k1 = k1.rotate_left(31);
        k1 = k1.wrapping_mul(C2);
        h1 ^= k1;
        h1 = h1.rotate_left(27);
        h1 = h1.wrapping_add(h2);
        h1 = h1.wrapping_mul(5).wrapping_add(0x52dc_e729);

        k2 = k2.wrapping_mul(C2);
        k2 = k2.rotate_left(33);
        k2 = k2.wrapping_mul(C1);
        h2 ^= k2;
        h2 = h2.rotate_left(31);
        h2 = h2.wrapping_add(h1);
        h2 = h2.wrapping_mul(5).wrapping_add(0x3849_5ab5);
    }

    let tail_offset = num_blocks * 16;
    let tail = &data[tail_offset..];
    let mut k1: u64 = 0;
    let mut k2: u64 = 0;

    match tail.len() {
        15 => {
            k2 ^= u64::from(tail[14]) << 48;
            k2 ^= u64::from(tail[13]) << 40;
            k2 ^= u64::from(tail[12]) << 32;
            k2 ^= u64::from(tail[11]) << 24;
            k2 ^= u64::from(tail[10]) << 16;
            k2 ^= u64::from(tail[9]) << 8;
            k2 ^= u64::from(tail[8]);
            k2 = k2.wrapping_mul(C2);
            k2 = k2.rotate_left(33);
            k2 = k2.wrapping_mul(C1);
            h2 ^= k2;
            k1 ^= u64::from(tail[7]) << 56;
            k1 ^= u64::from(tail[6]) << 48;
            k1 ^= u64::from(tail[5]) << 40;
            k1 ^= u64::from(tail[4]) << 32;
            k1 ^= u64::from(tail[3]) << 24;
            k1 ^= u64::from(tail[2]) << 16;
            k1 ^= u64::from(tail[1]) << 8;
            k1 ^= u64::from(tail[0]);
            k1 = k1.wrapping_mul(C1);
            k1 = k1.rotate_left(31);
            k1 = k1.wrapping_mul(C2);
            h1 ^= k1;
        }
        14 => {
            k2 ^= u64::from(tail[13]) << 40;
            k2 ^= u64::from(tail[12]) << 32;
            k2 ^= u64::from(tail[11]) << 24;
            k2 ^= u64::from(tail[10]) << 16;
            k2 ^= u64::from(tail[9]) << 8;
            k2 ^= u64::from(tail[8]);
            k2 = k2.wrapping_mul(C2);
            k2 = k2.rotate_left(33);
            k2 = k2.wrapping_mul(C1);
            h2 ^= k2;
            k1 ^= u64::from(tail[7]) << 56;
            k1 ^= u64::from(tail[6]) << 48;
            k1 ^= u64::from(tail[5]) << 40;
            k1 ^= u64::from(tail[4]) << 32;
            k1 ^= u64::from(tail[3]) << 24;
            k1 ^= u64::from(tail[2]) << 16;
            k1 ^= u64::from(tail[1]) << 8;
            k1 ^= u64::from(tail[0]);
            k1 = k1.wrapping_mul(C1);
            k1 = k1.rotate_left(31);
            k1 = k1.wrapping_mul(C2);
            h1 ^= k1;
        }
        13 => {
            k2 ^= u64::from(tail[12]) << 32;
            k2 ^= u64::from(tail[11]) << 24;
            k2 ^= u64::from(tail[10]) << 16;
            k2 ^= u64::from(tail[9]) << 8;
            k2 ^= u64::from(tail[8]);
            k2 = k2.wrapping_mul(C2);
            k2 = k2.rotate_left(33);
            k2 = k2.wrapping_mul(C1);
            h2 ^= k2;
            k1 ^= u64::from(tail[7]) << 56;
            k1 ^= u64::from(tail[6]) << 48;
            k1 ^= u64::from(tail[5]) << 40;
            k1 ^= u64::from(tail[4]) << 32;
            k1 ^= u64::from(tail[3]) << 24;
            k1 ^= u64::from(tail[2]) << 16;
            k1 ^= u64::from(tail[1]) << 8;
            k1 ^= u64::from(tail[0]);
            k1 = k1.wrapping_mul(C1);
            k1 = k1.rotate_left(31);
            k1 = k1.wrapping_mul(C2);
            h1 ^= k1;
        }
        12 => {
            k2 ^= u64::from(tail[11]) << 24;
            k2 ^= u64::from(tail[10]) << 16;
            k2 ^= u64::from(tail[9]) << 8;
            k2 ^= u64::from(tail[8]);
            k2 = k2.wrapping_mul(C2);
            k2 = k2.rotate_left(33);
            k2 = k2.wrapping_mul(C1);
            h2 ^= k2;
            k1 ^= u64::from(tail[7]) << 56;
            k1 ^= u64::from(tail[6]) << 48;
            k1 ^= u64::from(tail[5]) << 40;
            k1 ^= u64::from(tail[4]) << 32;
            k1 ^= u64::from(tail[3]) << 24;
            k1 ^= u64::from(tail[2]) << 16;
            k1 ^= u64::from(tail[1]) << 8;
            k1 ^= u64::from(tail[0]);
            k1 = k1.wrapping_mul(C1);
            k1 = k1.rotate_left(31);
            k1 = k1.wrapping_mul(C2);
            h1 ^= k1;
        }
        11 => {
            k2 ^= u64::from(tail[10]) << 16;
            k2 ^= u64::from(tail[9]) << 8;
            k2 ^= u64::from(tail[8]);
            k2 = k2.wrapping_mul(C2);
            k2 = k2.rotate_left(33);
            k2 = k2.wrapping_mul(C1);
            h2 ^= k2;
            k1 ^= u64::from(tail[7]) << 56;
            k1 ^= u64::from(tail[6]) << 48;
            k1 ^= u64::from(tail[5]) << 40;
            k1 ^= u64::from(tail[4]) << 32;
            k1 ^= u64::from(tail[3]) << 24;
            k1 ^= u64::from(tail[2]) << 16;
            k1 ^= u64::from(tail[1]) << 8;
            k1 ^= u64::from(tail[0]);
            k1 = k1.wrapping_mul(C1);
            k1 = k1.rotate_left(31);
            k1 = k1.wrapping_mul(C2);
            h1 ^= k1;
        }
        10 => {
            k2 ^= u64::from(tail[9]) << 8;
            k2 ^= u64::from(tail[8]);
            k2 = k2.wrapping_mul(C2);
            k2 = k2.rotate_left(33);
            k2 = k2.wrapping_mul(C1);
            h2 ^= k2;
            k1 ^= u64::from(tail[7]) << 56;
            k1 ^= u64::from(tail[6]) << 48;
            k1 ^= u64::from(tail[5]) << 40;
            k1 ^= u64::from(tail[4]) << 32;
            k1 ^= u64::from(tail[3]) << 24;
            k1 ^= u64::from(tail[2]) << 16;
            k1 ^= u64::from(tail[1]) << 8;
            k1 ^= u64::from(tail[0]);
            k1 = k1.wrapping_mul(C1);
            k1 = k1.rotate_left(31);
            k1 = k1.wrapping_mul(C2);
            h1 ^= k1;
        }
        9 => {
            k2 ^= u64::from(tail[8]);
            k2 = k2.wrapping_mul(C2);
            k2 = k2.rotate_left(33);
            k2 = k2.wrapping_mul(C1);
            h2 ^= k2;
            k1 ^= u64::from(tail[7]) << 56;
            k1 ^= u64::from(tail[6]) << 48;
            k1 ^= u64::from(tail[5]) << 40;
            k1 ^= u64::from(tail[4]) << 32;
            k1 ^= u64::from(tail[3]) << 24;
            k1 ^= u64::from(tail[2]) << 16;
            k1 ^= u64::from(tail[1]) << 8;
            k1 ^= u64::from(tail[0]);
            k1 = k1.wrapping_mul(C1);
            k1 = k1.rotate_left(31);
            k1 = k1.wrapping_mul(C2);
            h1 ^= k1;
        }
        8 => {
            k1 ^= u64::from(tail[7]) << 56;
            k1 ^= u64::from(tail[6]) << 48;
            k1 ^= u64::from(tail[5]) << 40;
            k1 ^= u64::from(tail[4]) << 32;
            k1 ^= u64::from(tail[3]) << 24;
            k1 ^= u64::from(tail[2]) << 16;
            k1 ^= u64::from(tail[1]) << 8;
            k1 ^= u64::from(tail[0]);
            k1 = k1.wrapping_mul(C1);
            k1 = k1.rotate_left(31);
            k1 = k1.wrapping_mul(C2);
            h1 ^= k1;
        }
        7 => {
            k1 ^= u64::from(tail[6]) << 48;
            k1 ^= u64::from(tail[5]) << 40;
            k1 ^= u64::from(tail[4]) << 32;
            k1 ^= u64::from(tail[3]) << 24;
            k1 ^= u64::from(tail[2]) << 16;
            k1 ^= u64::from(tail[1]) << 8;
            k1 ^= u64::from(tail[0]);
            k1 = k1.wrapping_mul(C1);
            k1 = k1.rotate_left(31);
            k1 = k1.wrapping_mul(C2);
            h1 ^= k1;
        }
        6 => {
            k1 ^= u64::from(tail[5]) << 40;
            k1 ^= u64::from(tail[4]) << 32;
            k1 ^= u64::from(tail[3]) << 24;
            k1 ^= u64::from(tail[2]) << 16;
            k1 ^= u64::from(tail[1]) << 8;
            k1 ^= u64::from(tail[0]);
            k1 = k1.wrapping_mul(C1);
            k1 = k1.rotate_left(31);
            k1 = k1.wrapping_mul(C2);
            h1 ^= k1;
        }
        5 => {
            k1 ^= u64::from(tail[4]) << 32;
            k1 ^= u64::from(tail[3]) << 24;
            k1 ^= u64::from(tail[2]) << 16;
            k1 ^= u64::from(tail[1]) << 8;
            k1 ^= u64::from(tail[0]);
            k1 = k1.wrapping_mul(C1);
            k1 = k1.rotate_left(31);
            k1 = k1.wrapping_mul(C2);
            h1 ^= k1;
        }
        4 => {
            k1 ^= u64::from(tail[3]) << 24;
            k1 ^= u64::from(tail[2]) << 16;
            k1 ^= u64::from(tail[1]) << 8;
            k1 ^= u64::from(tail[0]);
            k1 = k1.wrapping_mul(C1);
            k1 = k1.rotate_left(31);
            k1 = k1.wrapping_mul(C2);
            h1 ^= k1;
        }
        3 => {
            k1 ^= u64::from(tail[2]) << 16;
            k1 ^= u64::from(tail[1]) << 8;
            k1 ^= u64::from(tail[0]);
            k1 = k1.wrapping_mul(C1);
            k1 = k1.rotate_left(31);
            k1 = k1.wrapping_mul(C2);
            h1 ^= k1;
        }
        2 => {
            k1 ^= u64::from(tail[1]) << 8;
            k1 ^= u64::from(tail[0]);
            k1 = k1.wrapping_mul(C1);
            k1 = k1.rotate_left(31);
            k1 = k1.wrapping_mul(C2);
            h1 ^= k1;
        }
        1 => {
            k1 ^= u64::from(tail[0]);
            k1 = k1.wrapping_mul(C1);
            k1 = k1.rotate_left(31);
            k1 = k1.wrapping_mul(C2);
            h1 ^= k1;
        }
        _ => {}
    }

    let len64 = total_bytes as u64;
    h1 ^= len64;
    h2 ^= len64;
    h1 = h1.wrapping_add(h2);
    h2 = h2.wrapping_add(h1);
    h1 = fmix64(h1);
    h2 = fmix64(h2);
    h1 = h1.wrapping_add(h2);
    h2 = h2.wrapping_add(h1);

    u128::from(h1) | (u128::from(h2) << 64)
}

const fn fmix32(mut h: u32) -> u32 {
    h ^= h >> 16;
    h = h.wrapping_mul(0x85eb_ca6b);
    h ^= h >> 13;
    h = h.wrapping_mul(0xc2b2_ae35);
    h ^= h >> 16;
    h
}

const fn fmix64(mut k: u64) -> u64 {
    k ^= k >> 33;
    k = k.wrapping_mul(0xff51_afd7_ed55_8ccd);
    k ^= k >> 33;
    k = k.wrapping_mul(0xc4ce_b9fe_1a85_ec53);
    k ^= k >> 33;
    k
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
    fn x86_32_empty() {
        assert_eq!(murmurhash3_x86_32(b"", 0), 0);
    }

    #[test]
    fn x86_32_hello() {
        assert_eq!(murmurhash3_x86_32(b"hello", 0), 0x248b_fa47);
    }

    #[test]
    fn x86_32_seed() {
        assert_eq!(murmurhash3_x86_32(b"hello", 42), 0xe2db_d2e1);
    }

    #[test]
    fn x86_32_deterministic() {
        let a = murmurhash3_x86_32(b"MurmurHash3 is great", 0);
        let b = murmurhash3_x86_32(b"MurmurHash3 is great", 0);
        assert_eq!(a, b);
    }

    #[test]
    fn x64_128_empty() {
        assert_eq!(murmurhash3_x64_128(b"", 0), 0);
    }

    #[test]
    fn x64_128_hello() {
        assert_eq!(
            murmurhash3_x64_128(b"hello", 0),
            121_118_445_609_844_952_839_898_260_755_277_781_762
        );
    }

    #[test]
    fn x64_128_deterministic() {
        let a = murmurhash3_x64_128(b"MurmurHash3 is great", 0);
        let b = murmurhash3_x64_128(b"MurmurHash3 is great", 0);
        assert_eq!(a, b);
    }

    #[test]
    fn different_inputs_different_hashes() {
        let a = murmurhash3_x86_32(b"foo", 0);
        let b = murmurhash3_x86_32(b"bar", 0);
        assert_ne!(a, b);
    }
}
