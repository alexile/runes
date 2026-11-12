//! 64-bit SimHash (Charikar 2002).
//!
//! Each feature hash votes `+w` on the bit positions where it has a 1 and
//! `-w` where it has a 0. The fingerprint keeps a 1 wherever the tally is
//! positive. Similar feature multisets give fingerprints with a small
//! Hamming distance. See M. Charikar, *Similarity estimation techniques
//! from rounding algorithms*, STOC 2002, and Manku, Jain & Das Sarma,
//! *Detecting near-duplicates for web crawling*, WWW 2007.

use std::fmt;

use crate::Error;
use crate::shingle::{ShingleOptions, shingles};

/// A 64-bit SimHash fingerprint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SimHash(pub u64);

impl SimHash {
    /// The fingerprint of a feature set, each feature weighted 1.
    ///
    /// Duplicate features count once per occurrence.
    #[must_use]
    pub fn from_features<I: IntoIterator<Item = u64>>(features: I) -> Self {
        let mut hasher = SimHasher::new();
        for f in features {
            hasher.add(f);
        }
        hasher.finish()
    }

    /// Shingles `text` and fingerprints the shingles.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidParameter`] if the shingle options are invalid.
    pub fn from_text(text: &str, options: &ShingleOptions) -> Result<Self, Error> {
        Ok(Self::from_features(shingles(text, options)?))
    }

    /// Number of differing bits, `0..=64`.
    #[must_use]
    pub const fn hamming(self, other: Self) -> u32 {
        (self.0 ^ other.0).count_ones()
    }

    /// `1 - hamming / 64`, in `[0, 1]`. Unrelated inputs land near 0.5,
    /// because half the bits of two random fingerprints agree.
    #[must_use]
    pub fn similarity(self, other: Self) -> f64 {
        1.0 - f64::from(self.hamming(other)) / 64.0
    }
}

impl fmt::Display for SimHash {
    /// Formats as 16 lowercase hex digits.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:016x}", self.0)
    }
}

impl From<u64> for SimHash {
    fn from(v: u64) -> Self {
        Self(v)
    }
}

impl From<SimHash> for u64 {
    fn from(v: SimHash) -> Self {
        v.0
    }
}

/// Incremental SimHash builder with per-feature weights.
///
/// ```
/// use rune_simhash::{SimHasher, hash_feature};
///
/// let mut h = SimHasher::new();
/// h.add_weighted(hash_feature(b"title:not found"), 5);
/// h.add(hash_feature(b"status:200"));
/// let fp = h.finish();
/// assert_eq!(fp, h.finish()); // `finish` does not consume the state
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SimHasher {
    tally: [i64; 64],
}

impl Default for SimHasher {
    fn default() -> Self {
        Self::new()
    }
}

impl SimHasher {
    /// An empty builder. Finishing it gives `SimHash(0)`.
    #[must_use]
    pub const fn new() -> Self {
        Self { tally: [0; 64] }
    }

    /// Adds a feature with weight 1.
    pub fn add(&mut self, feature: u64) {
        self.add_weighted(feature, 1);
    }

    /// Adds a feature with weight `weight`. Negative weights subtract a
    /// feature; tallies saturate rather than overflow.
    pub fn add_weighted(&mut self, feature: u64, weight: i64) {
        for (bit, t) in self.tally.iter_mut().enumerate() {
            if feature >> bit & 1 == 1 {
                *t = t.saturating_add(weight);
            } else {
                *t = t.saturating_sub(weight);
            }
        }
    }

    /// The fingerprint of everything added so far.
    #[must_use]
    pub fn finish(&self) -> SimHash {
        SimHash(
            self.tally
                .iter()
                .enumerate()
                .filter(|(_, t)| **t > 0)
                .fold(0, |acc, (bit, _)| acc | 1 << bit),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn majority_vote_per_bit() {
        // bit 0 set in 2 of 3, bit 1 in 1 of 3, bit 63 in 3 of 3.
        let fp = SimHash::from_features([0b01 | 1 << 63, 0b11 | 1 << 63, 1 << 63]);
        assert_eq!(fp, SimHash(0b01 | 1 << 63));
    }

    #[test]
    fn ties_and_empty_give_zero_bits() {
        assert_eq!(SimHash::from_features([]), SimHash(0));
        assert_eq!(SimHash::from_features([u64::MAX, 0]), SimHash(0));
    }

    #[test]
    fn weights_dominate() {
        let mut h = SimHasher::new();
        h.add_weighted(0xF0, 3);
        h.add(0x0F);
        h.add(0x0F);
        assert_eq!(h.finish(), SimHash(0xF0));
        h.add_weighted(0xF0, -3);
        assert_eq!(h.finish(), SimHash(0x0F));
        h.add_weighted(1, i64::MAX);
        h.add_weighted(1, i64::MAX);
        assert_eq!(h.finish().0 & 1, 1);
    }

    #[test]
    fn hamming_and_similarity() {
        assert_eq!(SimHash(0).hamming(SimHash(u64::MAX)), 64);
        assert!((SimHash(0).similarity(SimHash(u64::MAX))).abs() < f64::EPSILON);
        assert!((SimHash(7).similarity(SimHash(7)) - 1.0).abs() < f64::EPSILON);
        assert_eq!(SimHash(0b1010).hamming(SimHash(0b0110)), 2);
    }

    #[test]
    fn display_is_fixed_width_hex() {
        assert_eq!(SimHash(0xab).to_string(), "00000000000000ab");
    }

    #[test]
    fn stable_fingerprint() {
        // Locks the feature hash and shingling: a change here breaks
        // stored fingerprints and must be a deliberate, versioned change.
        let fp = SimHash::from_text(
            "The quick brown fox jumps over the lazy dog",
            &ShingleOptions::default(),
        )
        .unwrap();
        assert_eq!(fp.to_string(), STABLE);
    }

    const STABLE: &str = "ebdc3e49fbeeda1c";
}
