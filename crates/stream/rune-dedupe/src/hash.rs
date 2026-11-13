//! Keyed SipHash-2-4 so attacker-chosen keys can't be steered into collisions.

use std::collections::hash_map::RandomState;
use std::fmt;
use std::hash::{BuildHasher, Hasher};

/// A secret 128-bit key for the SipHash-2-4 hash used on every dedupe key.
///
/// Both the exact hash tables and the approximate Bloom filters hash keys with
/// this key. When keys come from untrusted input, an attacker who could predict
/// the hash could pile keys into one bucket (`HashDoS`) or pick keys that look
/// like duplicates to a Bloom filter. With a secret random key they can't.
///
/// [`HashKey::random`] (also the [`Default`]) draws a fresh key per call from
/// the standard library's randomly seeded hasher, which the OS seeds once per
/// process. Use [`HashKey::new`] only when you need reproducible hashing, such
/// as in tests; a fixed, public key gives up the `HashDoS` protection.
///
/// A [`Snapshot`](crate::Snapshot) stores the key so a restored approximate
/// filter answers exactly as before. Treat persisted snapshots as secret if the
/// key matters to you. `Debug` never prints the key.
///
/// # Example
///
/// ```rust
/// use rune_dedupe::HashKey;
/// use std::hash::BuildHasher;
///
/// let fixed = HashKey::new(1, 2);
/// assert_eq!(fixed.hash_one("a"), HashKey::new(1, 2).hash_one("a"));
/// assert_ne!(fixed.hash_one("a"), HashKey::new(3, 4).hash_one("a"));
/// assert_eq!(format!("{fixed:?}"), "HashKey(..)");
/// ```
#[derive(Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct HashKey {
    k0: u64,
    k1: u64,
}

impl HashKey {
    /// A key made of two fixed 64-bit halves. Reproducible, so only use it where
    /// the keys being deduplicated are trusted.
    #[must_use]
    pub const fn new(k0: u64, k1: u64) -> Self {
        Self { k0, k1 }
    }

    /// A fresh unpredictable key.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_dedupe::HashKey;
    ///
    /// assert_ne!(HashKey::random(), HashKey::random());
    /// ```
    #[must_use]
    pub fn random() -> Self {
        // Each RandomState carries its own secret SipHash key; hashing two fixed
        // inputs under it yields 128 bits nobody outside the process can predict.
        let state = RandomState::new();
        Self {
            k0: state.hash_one(0x6b30_u64),
            k1: state.hash_one(0x6b31_u64),
        }
    }
}

impl Default for HashKey {
    fn default() -> Self {
        Self::random()
    }
}

impl fmt::Debug for HashKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("HashKey(..)")
    }
}

impl BuildHasher for HashKey {
    type Hasher = SipHasher24;

    fn build_hasher(&self) -> SipHasher24 {
        SipHasher24::new(*self)
    }
}

/// Streaming SipHash-2-4, the hasher [`HashKey`] builds.
///
/// # Example
///
/// ```rust
/// use rune_dedupe::{HashKey, SipHasher24};
/// use std::hash::Hasher;
///
/// // Reference vector from the SipHash paper: key 00..0f, empty message.
/// let key = HashKey::new(0x0706_0504_0302_0100, 0x0f0e_0d0c_0b0a_0908);
/// let hasher = SipHasher24::new(key);
/// assert_eq!(hasher.finish(), 0x726f_db47_dd0e_0e31);
/// ```
#[derive(Clone)]
pub struct SipHasher24 {
    v0: u64,
    v1: u64,
    v2: u64,
    v3: u64,
    tail: u64,
    ntail: usize,
    length: usize,
}

impl SipHasher24 {
    /// A hasher keyed with `key`.
    #[must_use]
    pub const fn new(key: HashKey) -> Self {
        Self {
            v0: key.k0 ^ 0x736f_6d65_7073_6575,
            v1: key.k1 ^ 0x646f_7261_6e64_6f6d,
            v2: key.k0 ^ 0x6c79_6765_6e65_7261,
            v3: key.k1 ^ 0x7465_6462_7974_6573,
            tail: 0,
            ntail: 0,
            length: 0,
        }
    }

    const fn round(v: &mut [u64; 4]) {
        v[0] = v[0].wrapping_add(v[1]);
        v[1] = v[1].rotate_left(13);
        v[1] ^= v[0];
        v[0] = v[0].rotate_left(32);
        v[2] = v[2].wrapping_add(v[3]);
        v[3] = v[3].rotate_left(16);
        v[3] ^= v[2];
        v[0] = v[0].wrapping_add(v[3]);
        v[3] = v[3].rotate_left(21);
        v[3] ^= v[0];
        v[2] = v[2].wrapping_add(v[1]);
        v[1] = v[1].rotate_left(17);
        v[1] ^= v[2];
        v[2] = v[2].rotate_left(32);
    }

    const fn compress(&mut self, m: u64) {
        let mut v = [self.v0, self.v1, self.v2, self.v3];
        v[3] ^= m;
        Self::round(&mut v);
        Self::round(&mut v);
        v[0] ^= m;
        [self.v0, self.v1, self.v2, self.v3] = v;
    }

    fn push_byte(&mut self, byte: u8) {
        self.tail |= u64::from(byte) << (8 * self.ntail);
        self.ntail += 1;
        if self.ntail == 8 {
            let m = self.tail;
            self.compress(m);
            self.tail = 0;
            self.ntail = 0;
        }
    }
}

impl Hasher for SipHasher24 {
    fn write(&mut self, bytes: &[u8]) {
        self.length = self.length.wrapping_add(bytes.len());
        let mut rest = bytes;
        while self.ntail != 0 {
            let Some((&first, tail)) = rest.split_first() else {
                return;
            };
            self.push_byte(first);
            rest = tail;
        }
        let (chunks, remainder) = rest.as_chunks::<8>();
        for chunk in chunks {
            self.compress(u64::from_le_bytes(*chunk));
        }
        for &byte in remainder {
            self.push_byte(byte);
        }
    }

    fn finish(&self) -> u64 {
        // Only the low byte of the length goes into the final block.
        let b = ((self.length as u64) << 56) | self.tail;
        let mut v = [self.v0, self.v1, self.v2, self.v3];
        v[3] ^= b;
        Self::round(&mut v);
        Self::round(&mut v);
        v[0] ^= b;
        v[2] ^= 0xff;
        for _ in 0..4 {
            Self::round(&mut v);
        }
        v[0] ^ v[1] ^ v[2] ^ v[3]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PAPER_KEY: HashKey = HashKey::new(0x0706_0504_0302_0100, 0x0f0e_0d0c_0b0a_0908);

    fn sip(key: HashKey, msg: &[u8]) -> u64 {
        let mut h = SipHasher24::new(key);
        h.write(msg);
        h.finish()
    }

    #[test]
    fn paper_vectors() {
        let msg: Vec<u8> = (0..15).collect();
        assert_eq!(sip(PAPER_KEY, &[]), 0x726f_db47_dd0e_0e31);
        assert_eq!(sip(PAPER_KEY, &msg), 0xa129_ca61_49be_45e5);
    }

    #[test]
    #[allow(deprecated)]
    fn matches_std_siphash_2_4() {
        // std's deprecated SipHasher is SipHash-2-4; use it as an oracle.
        let msg: Vec<u8> = (0..=255).collect();
        for len in 0..msg.len() {
            let mut oracle = std::hash::SipHasher::new_with_keys(7, 11);
            oracle.write(&msg[..len]);
            assert_eq!(sip(HashKey::new(7, 11), &msg[..len]), oracle.finish());
        }
    }

    #[test]
    fn split_writes_match_one_write() {
        let msg: Vec<u8> = (0..40).collect();
        for cut in 0..msg.len() {
            let mut h = SipHasher24::new(PAPER_KEY);
            h.write(&msg[..cut]);
            h.write(&msg[cut..]);
            assert_eq!(h.finish(), sip(PAPER_KEY, &msg), "cut at {cut}");
        }
    }

    #[test]
    fn random_keys_differ() {
        assert_ne!(HashKey::random(), HashKey::random());
        assert_ne!(
            HashKey::default().hash_one("x"),
            HashKey::default().hash_one("x")
        );
    }
}
