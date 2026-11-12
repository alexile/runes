//! MinHash signatures (Broder 1997).
//!
//! Each of `n` independent hash functions maps every feature to a value;
//! the signature keeps the minimum per function. The fraction of
//! positions where two signatures agree is an unbiased estimate of the
//! Jaccard similarity of the two feature *sets*, with standard error
//! `sqrt(J(1-J)/n)`. See A. Broder, *On the resemblance and containment of
//! documents*, 1997.
//!
//! The hash family is `h_i(x) = (a_i·x + b_i) mod (2^61 − 1)`, with `a_i`,
//! `b_i` drawn from `SplitMix64` seeded by [`MinHasher::seed`]. Only
//! signatures made with the same `n` and seed are comparable.

use std::collections::HashSet;

use crate::Error;
use crate::hash::mix64;
use crate::shingle::{ShingleOptions, shingles};

const MERSENNE_61: u64 = (1 << 61) - 1;
const GOLDEN: u64 = 0x9e37_79b9_7f4a_7c15;

/// `x mod (2^61 − 1)` for `x < 2^122`.
const fn mod_m61(x: u128) -> u64 {
    // Truncations are intentional: each half is below 2^61 + 2^61.
    #[allow(clippy::cast_possible_truncation, reason = "masked to 61 bits")]
    let lo = (x as u64) & MERSENNE_61;
    #[allow(
        clippy::cast_possible_truncation,
        reason = "x < 2^122, so x >> 61 < 2^61"
    )]
    let hi = (x >> 61) as u64;
    let s = lo + hi;
    if s >= MERSENNE_61 { s - MERSENNE_61 } else { s }
}

/// A family of `n` hash functions that turns feature sets into
/// [`MinHashSignature`]s.
///
/// ```
/// use rune_simhash::{MinHasher, ShingleOptions};
///
/// let hasher = MinHasher::new(128, 42)?;
/// let o = ShingleOptions::default();
/// let a = hasher.signature_text("the cat sat on the mat today", &o)?;
/// let b = hasher.signature_text("the cat sat on the mat yesterday", &o)?;
/// let j = a.jaccard(&b)?;
/// assert!(j > 0.5 && j < 1.0); // exact Jaccard is 4/6
/// # Ok::<(), rune_simhash::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MinHasher {
    seed: u64,
    /// `(a, b)` per function, `a` in `[1, p)`, `b` in `[0, p)`.
    coeffs: Vec<(u64, u64)>,
}

impl MinHasher {
    /// A hasher with `num_hashes` functions derived from `seed`.
    ///
    /// 128 functions give a standard error of about 0.044 at `J = 0.5`.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidParameter`] if `num_hashes` is 0.
    pub fn new(num_hashes: usize, seed: u64) -> Result<Self, Error> {
        if num_hashes == 0 {
            return Err(Error::InvalidParameter {
                name: "num_hashes",
                reason: "must be at least 1",
            });
        }
        let mut state = seed;
        let mut next = || {
            state = state.wrapping_add(GOLDEN);
            mix64(state)
        };
        let coeffs = (0..num_hashes)
            .map(|_| {
                let a = next() % (MERSENNE_61 - 1) + 1;
                let b = next() % MERSENNE_61;
                (a, b)
            })
            .collect();
        Ok(Self { seed, coeffs })
    }

    /// The seed the functions were derived from.
    #[must_use]
    pub const fn seed(&self) -> u64 {
        self.seed
    }

    /// Number of hash functions, which is the signature length.
    #[must_use]
    pub const fn num_hashes(&self) -> usize {
        self.coeffs.len()
    }

    /// The signature of a feature set. Duplicates do not matter. The
    /// empty set gives a signature of all `u64::MAX`.
    #[must_use]
    pub fn signature<I: IntoIterator<Item = u64>>(&self, features: I) -> MinHashSignature {
        let mut mins = vec![u64::MAX; self.coeffs.len()];
        for f in features {
            let x = u128::from(f % MERSENNE_61);
            for (m, &(a, b)) in mins.iter_mut().zip(&self.coeffs) {
                let h = mod_m61(u128::from(a) * x + u128::from(b));
                if h < *m {
                    *m = h;
                }
            }
        }
        MinHashSignature(mins)
    }

    /// Shingles `text` and signs the shingle set.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidParameter`] if the shingle options are invalid.
    pub fn signature_text(
        &self,
        text: &str,
        options: &ShingleOptions,
    ) -> Result<MinHashSignature, Error> {
        Ok(self.signature(shingles(text, options)?))
    }
}

/// A MinHash signature: one minimum per hash function.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct MinHashSignature(pub Vec<u64>);

impl MinHashSignature {
    /// The per-function minima.
    #[must_use]
    pub fn values(&self) -> &[u64] {
        &self.0
    }

    /// Number of hash functions.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the signature has no hash functions.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Estimated Jaccard similarity: the fraction of agreeing positions.
    ///
    /// # Errors
    ///
    /// [`Error::LengthMismatch`] if the signatures have different lengths,
    /// which means they came from different [`MinHasher`]s.
    pub fn jaccard(&self, other: &Self) -> Result<f64, Error> {
        if self.len() != other.len() {
            return Err(Error::LengthMismatch {
                left: self.len(),
                right: other.len(),
            });
        }
        if self.is_empty() {
            return Ok(1.0);
        }
        let agree = self.0.iter().zip(&other.0).filter(|(a, b)| a == b).count();
        #[allow(clippy::cast_precision_loss, reason = "signature lengths are small")]
        Ok(agree as f64 / self.len() as f64)
    }
}

/// Exact Jaccard similarity `|A ∩ B| / |A ∪ B|` of two feature sets.
///
/// Two empty sets have similarity 1. Use it to check MinHash estimates or
/// when sets are small enough to keep.
#[must_use]
pub fn jaccard<A, B>(a: A, b: B) -> f64
where
    A: IntoIterator<Item = u64>,
    B: IntoIterator<Item = u64>,
{
    let a: HashSet<u64> = a.into_iter().collect();
    let b: HashSet<u64> = b.into_iter().collect();
    let union = a.union(&b).count();
    if union == 0 {
        return 1.0;
    }
    #[allow(clippy::cast_precision_loss, reason = "set sizes far below 2^52")]
    let j = a.intersection(&b).count() as f64 / union as f64;
    j
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_zero_hashes() {
        assert!(MinHasher::new(0, 1).is_err());
    }

    #[test]
    fn mod_m61_matches_naive() {
        for x in [
            0u128,
            1,
            u128::from(MERSENNE_61),
            u128::from(MERSENNE_61) * 2 + 5,
            (1 << 121) + 12_345,
        ] {
            let expected = u64::try_from(x % u128::from(MERSENNE_61)).unwrap();
            assert_eq!(mod_m61(x), expected, "x = {x}");
        }
        let max =
            u128::from(MERSENNE_61 - 1) * u128::from(MERSENNE_61 - 1) + u128::from(MERSENNE_61 - 1);
        assert_eq!(u128::from(mod_m61(max)), max % u128::from(MERSENNE_61));
    }

    #[test]
    fn identical_and_disjoint_sets() {
        let h = MinHasher::new(64, 7).unwrap();
        let a = h.signature(0..100);
        assert!((a.jaccard(&h.signature((0..100).rev())).unwrap() - 1.0).abs() < f64::EPSILON);
        assert!(a.jaccard(&h.signature(1000..1100)).unwrap() < 0.1);
    }

    #[test]
    fn empty_set_signature() {
        let h = MinHasher::new(4, 0).unwrap();
        assert_eq!(h.signature([]).values(), [u64::MAX; 4]);
    }

    #[test]
    fn length_mismatch_is_an_error() {
        let a = MinHasher::new(4, 0).unwrap().signature([1]);
        let b = MinHasher::new(8, 0).unwrap().signature([1]);
        assert_eq!(
            a.jaccard(&b),
            Err(Error::LengthMismatch { left: 4, right: 8 })
        );
    }

    #[test]
    fn estimate_tracks_exact_jaccard() {
        // |A ∩ B| = 500, |A ∪ B| = 1500 → J = 1/3.
        let h = MinHasher::new(512, 99).unwrap();
        let a: Vec<u64> = (0..1000).map(mix64).collect();
        let b: Vec<u64> = (500..1500).map(mix64).collect();
        let exact = jaccard(a.iter().copied(), b.iter().copied());
        assert!((exact - 1.0 / 3.0).abs() < 1e-12);
        let est = h.signature(a).jaccard(&h.signature(b)).unwrap();
        // 4 standard errors: sqrt(J(1-J)/512) ≈ 0.021.
        assert!(
            (est - exact).abs() < 0.084,
            "estimate {est} vs exact {exact}"
        );
    }

    #[test]
    fn same_seed_same_functions() {
        assert_eq!(
            MinHasher::new(16, 3).unwrap(),
            MinHasher::new(16, 3).unwrap()
        );
        assert_ne!(
            MinHasher::new(16, 3).unwrap(),
            MinHasher::new(16, 4).unwrap()
        );
    }

    #[test]
    fn exact_jaccard_edge_cases() {
        assert!((jaccard([], []) - 1.0).abs() < f64::EPSILON);
        assert!(jaccard([1], []).abs() < f64::EPSILON);
        assert!((jaccard([1, 1, 2], [2, 1]) - 1.0).abs() < f64::EPSILON);
    }
}
