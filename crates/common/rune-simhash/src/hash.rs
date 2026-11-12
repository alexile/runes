//! Stable, seedless 64-bit feature hashing.
//!
//! Signatures must be comparable across processes, machines and releases,
//! so the crate uses its own fixed hash rather than `std`'s randomly
//! seeded `DefaultHasher`: FNV-1a over the bytes, followed by the
//! `SplitMix64` finalizer so that every output bit depends on every input
//! bit (plain FNV-1a has weak high-bit avalanche, which skews SimHash).

const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

/// The `SplitMix64` output function: a bijective 64-bit mixer.
#[must_use]
pub const fn mix64(mut z: u64) -> u64 {
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^ (z >> 31)
}

/// Incremental FNV-1a state.
#[derive(Debug, Clone, Copy)]
pub struct Fnv(u64);

impl Fnv {
    pub const fn new() -> Self {
        Self(FNV_OFFSET)
    }

    pub fn write(&mut self, bytes: &[u8]) {
        for &b in bytes {
            self.0 ^= u64::from(b);
            self.0 = self.0.wrapping_mul(FNV_PRIME);
        }
    }

    pub const fn finish(self) -> u64 {
        mix64(self.0)
    }
}

/// Hashes arbitrary bytes to a stable, well-mixed 64-bit feature.
///
/// Use this to feed your own features (header names, DOM paths, status
/// lines…) into [`SimHasher`](crate::SimHasher) or
/// [`MinHasher`](crate::MinHasher). The value is fixed across platforms
/// and releases.
///
/// ```
/// let a = rune_simhash::hash_feature(b"content-type");
/// assert_eq!(a, rune_simhash::hash_feature(b"content-type"));
/// assert_ne!(a, rune_simhash::hash_feature(b"content-length"));
/// ```
#[must_use]
pub fn hash_feature(bytes: &[u8]) -> u64 {
    let mut h = Fnv::new();
    h.write(bytes);
    h.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fnv_known_answers() {
        // Raw FNV-1a 64 vectors (before the finalizer).
        let mut h = Fnv::new();
        h.write(b"");
        assert_eq!(h.0, 0xcbf2_9ce4_8422_2325);
        let mut h = Fnv::new();
        h.write(b"a");
        assert_eq!(h.0, 0xaf63_dc4c_8601_ec8c);
        let mut h = Fnv::new();
        h.write(b"foobar");
        assert_eq!(h.0, 0x8594_4171_f739_67e8);
    }

    #[test]
    fn splitmix_known_answer() {
        // First output of SplitMix64 seeded with 0 is mix64(0x9e3779b97f4a7c15).
        assert_eq!(mix64(0x9e37_79b9_7f4a_7c15), 0xe220_a839_7b1d_cdaf);
    }
}
