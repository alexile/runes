//! TLSH, the Trend Micro locality-sensitive hash.
//!
//! Implements the standard TLSH digest — 128 buckets, 1-byte checksum,
//! printed as `T1` plus 70 hex digits — bit for bit as the reference
//! implementation (<https://github.com/trendmicro/tlsh>, v4) produces it,
//! together with its distance score. See J. Oliver, C. Cheng, Y. Chen,
//! *TLSH — A Locality Sensitive Hash*, 4th Cybercrime and Trustworthy
//! Computing Workshop, 2013.
//!
//! In short: a 5-byte sliding window feeds six byte-triplets per position
//! through a Pearson hash into 256 counters. The first 128 counters are
//! quantised against their quartiles into 2 bits each. The digest adds a
//! rolling checksum, a log-scaled length and two quartile ratios.

mod tables;

use std::fmt;
use std::str::FromStr;

use crate::Error;
use tables::{PEARSON, TOPVAL};

/// Inputs shorter than this cannot be hashed.
pub const MIN_LEN: usize = 50;
/// Shortest input [`TlshBuilder::finish_conservative`] accepts. TLSH's
/// authors recommend it when false positives are expensive.
pub const MIN_CONSERVATIVE_LEN: usize = 256;
/// Longest input TLSH's length encoding can represent (3.9 GiB).
pub const MAX_LEN: u64 = TOPVAL[TOPVAL.len() - 1] as u64;

/// Distances at or below this are strong evidence of a common origin.
///
/// Trend Micro's evaluation of TLSH puts the false-positive rate at this
/// cut-off well under 0.01 % while still catching most variants.
pub const STRICT_MAX_DISTANCE: u32 = 30;
/// Recommended cut-off for grouping files as "similar": distances at or
/// below this usually mean versions or variants of the same content.
///
/// It catches more variants than [`STRICT_MAX_DISTANCE`] at a higher, but
/// still low, false-positive rate. Above roughly 100 inputs are rarely
/// related. Tune against your own data when the cost of a wrong grouping
/// is high.
pub const RECOMMENDED_MAX_DISTANCE: u32 = 50;

const BUCKETS: usize = 256;
const EFF_BUCKETS: usize = 128;
const CODE_SIZE: usize = EFF_BUCKETS / 4;
/// Hex digits after the `T1` prefix: checksum, length, ratios, code.
const HEX_LEN: usize = 2 * (3 + CODE_SIZE);

/// Pearson hash of a salt and three bytes.
#[inline]
fn pearson(salt: u8, a: u8, b: u8, c: u8) -> u8 {
    let h = PEARSON[usize::from(salt)];
    let h = PEARSON[usize::from(h ^ a)];
    let h = PEARSON[usize::from(h ^ b)];
    PEARSON[usize::from(h ^ c)]
}

/// Incremental TLSH computation, for input that arrives in pieces.
///
/// ```
/// use rune_fuzzyhash::tlsh::{Tlsh, TlshBuilder};
///
/// let data: Vec<u8> = (0..2048u32).map(|i| (i * 7 % 251) as u8 ^ (i >> 5) as u8).collect();
/// let mut b = TlshBuilder::new();
/// for chunk in data.chunks(100) {
///     b.update(chunk);
/// }
/// assert_eq!(b.finish()?, Tlsh::hash(&data)?);
/// # Ok::<(), rune_fuzzyhash::Error>(())
/// ```
#[derive(Debug, Clone)]
pub struct TlshBuilder {
    buckets: [u32; BUCKETS],
    /// The last four bytes, most recent first.
    window: [u8; 4],
    len: u64,
    checksum: u8,
}

impl Default for TlshBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl TlshBuilder {
    /// An empty builder.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            buckets: [0; BUCKETS],
            window: [0; 4],
            len: 0,
            checksum: 0,
        }
    }

    /// Feeds more input.
    pub fn update(&mut self, data: &[u8]) {
        for &b0 in data {
            if self.len >= 4 {
                let [b1, b2, b3, b4] = self.window;
                self.checksum = pearson(0, b0, b1, self.checksum);
                for (salt, x, y) in [
                    (2, b1, b2),
                    (3, b1, b3),
                    (5, b2, b3),
                    (7, b2, b4),
                    (11, b1, b4),
                    (13, b3, b4),
                ] {
                    let bucket = &mut self.buckets[usize::from(pearson(salt, b0, x, y))];
                    *bucket = bucket.saturating_add(1);
                }
            }
            self.window = [b0, self.window[0], self.window[1], self.window[2]];
            self.len = self.len.saturating_add(1);
        }
    }

    /// Number of bytes fed so far.
    #[must_use]
    pub const fn len(&self) -> u64 {
        self.len
    }

    /// Whether nothing has been fed yet.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// The digest, as the reference `Tlsh::final()` computes it.
    ///
    /// # Errors
    ///
    /// - [`Error::TooShort`] below [`MIN_LEN`] bytes.
    /// - [`Error::TooLong`] above [`MAX_LEN`] bytes.
    /// - [`Error::LowVariation`] if the input is too uniform (half or more
    ///   of the buckets are empty), for example a run of one byte.
    pub fn finish(&self) -> Result<Tlsh, Error> {
        self.finish_min(MIN_LEN)
    }

    /// Like [`finish`](Self::finish), but requires
    /// [`MIN_CONSERVATIVE_LEN`] bytes (the reference "conservative" mode).
    ///
    /// # Errors
    ///
    /// As for [`finish`](Self::finish).
    pub fn finish_conservative(&self) -> Result<Tlsh, Error> {
        self.finish_min(MIN_CONSERVATIVE_LEN)
    }

    fn finish_min(&self, min: usize) -> Result<Tlsh, Error> {
        if self.len < min as u64 {
            return Err(Error::TooShort {
                algorithm: "TLSH",
                len: self.len,
                min,
            });
        }
        if self.len > MAX_LEN {
            return Err(Error::TooLong {
                algorithm: "TLSH",
                len: self.len,
                max: MAX_LEN,
            });
        }
        let eff = &self.buckets[..EFF_BUCKETS];
        let mut sorted = [0u32; EFF_BUCKETS];
        sorted.copy_from_slice(eff);
        sorted.sort_unstable();
        let (q1, q2, q3) = (
            sorted[EFF_BUCKETS / 4 - 1],
            sorted[EFF_BUCKETS / 2 - 1],
            sorted[EFF_BUCKETS - EFF_BUCKETS / 4 - 1],
        );
        let nonzero = eff.iter().filter(|&&c| c > 0).count();
        if q3 == 0 || nonzero <= EFF_BUCKETS / 2 {
            return Err(Error::LowVariation);
        }
        let mut code = [0u8; CODE_SIZE];
        for (byte, quad) in code.iter_mut().zip(eff.as_chunks::<4>().0) {
            for (j, &count) in quad.iter().enumerate() {
                let level = if count > q3 {
                    3
                } else if count > q2 {
                    2
                } else {
                    u8::from(count > q1)
                };
                *byte |= level << (2 * j);
            }
        }
        let ratio = |q: u32| {
            // q ≤ q3, so the ratio is at most 100 before the modulus.
            u8::try_from(u64::from(q) * 100 / u64::from(q3) % 16).unwrap_or(0)
        };
        Ok(Tlsh {
            checksum: self.checksum,
            lvalue: l_capturing(self.len),
            q1_ratio: ratio(q1),
            q2_ratio: ratio(q2),
            code,
        })
    }
}

/// The log-scaled length byte: the first `i` with `len ≤ TOPVAL[i]`.
fn l_capturing(len: u64) -> u8 {
    let idx = TOPVAL.partition_point(|&top| u64::from(top) < len);
    u8::try_from(idx).unwrap_or(u8::MAX)
}

/// A TLSH digest (128 buckets, 1-byte checksum).
///
/// Displays as the reference `T1…` string (72 characters, uppercase hex)
/// and parses from it, with or without the `T1` prefix.
///
/// ```
/// use rune_fuzzyhash::tlsh::Tlsh;
///
/// let a: Tlsh = "T109F05A198CC69A5A4F0F9380A9EE93F2B927CF42089EA74276DC5F0BB2D34E68114448".parse()?;
/// let b: Tlsh = "T1301124198C869A5A4F0F9380A9AE92F2B9278F42089EA34272885F0FB2D34E6911444C".parse()?;
/// assert_eq!(a.distance(&b), 121);
/// assert_eq!(a.distance_ignoring_len(&b), 97);
/// assert_eq!(a.to_string().parse::<Tlsh>()?, a);
/// # Ok::<(), rune_fuzzyhash::Error>(())
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Tlsh {
    checksum: u8,
    lvalue: u8,
    q1_ratio: u8,
    q2_ratio: u8,
    /// Two bits per bucket, bucket `4i + j` in bits `2j..2j+2` of byte `i`.
    code: [u8; CODE_SIZE],
}

impl Tlsh {
    /// Hashes `data` in one go.
    ///
    /// # Errors
    ///
    /// As for [`TlshBuilder::finish`].
    pub fn hash(data: &[u8]) -> Result<Self, Error> {
        let mut b = TlshBuilder::new();
        b.update(data);
        b.finish()
    }

    /// The TLSH distance, length difference included: 0 for identical
    /// digests, growing without a fixed bound (scores above 300 are
    /// common for unrelated inputs). See [`RECOMMENDED_MAX_DISTANCE`].
    #[must_use]
    pub fn distance(&self, other: &Self) -> u32 {
        let ldiff = mod_diff(self.lvalue, other.lvalue, 256);
        let len = match ldiff {
            0 | 1 => ldiff,
            d => d * 12,
        };
        len + self.distance_ignoring_len(other)
    }

    /// The TLSH distance without the length term, for comparing a
    /// fragment with a whole or inputs whose size is known to vary.
    #[must_use]
    pub fn distance_ignoring_len(&self, other: &Self) -> u32 {
        let ratio = |a: u8, b: u8| match mod_diff(a, b, 16) {
            d @ (0 | 1) => d,
            d => (d - 1) * 12,
        };
        let mut diff = ratio(self.q1_ratio, other.q1_ratio) + ratio(self.q2_ratio, other.q2_ratio);
        diff += u32::from(self.checksum != other.checksum);
        for (&a, &b) in self.code.iter().zip(&other.code) {
            for shift in [0, 2, 4, 6] {
                diff += match ((a >> shift) & 3).abs_diff((b >> shift) & 3) {
                    3 => 6,
                    d => u32::from(d),
                };
            }
        }
        diff
    }

    /// Whether `distance(other) ≤ RECOMMENDED_MAX_DISTANCE`.
    #[must_use]
    pub fn is_similar(&self, other: &Self) -> bool {
        self.distance(other) <= RECOMMENDED_MAX_DISTANCE
    }

    /// The 1-byte checksum of the input.
    #[must_use]
    pub const fn checksum(&self) -> u8 {
        self.checksum
    }

    /// The log-scaled input length (`L` value).
    #[must_use]
    pub const fn lvalue(&self) -> u8 {
        self.lvalue
    }

    /// `(q1 · 100 / q3) mod 16` and `(q2 · 100 / q3) mod 16`.
    #[must_use]
    pub const fn q_ratios(&self) -> (u8, u8) {
        (self.q1_ratio, self.q2_ratio)
    }

    /// The 2-bit quartile level (0–3) of bucket `index` (`0..128`), or
    /// `None` out of range.
    #[must_use]
    pub fn bucket(&self, index: usize) -> Option<u8> {
        (index < EFF_BUCKETS).then(|| (self.code[index / 4] >> (2 * (index % 4))) & 3)
    }
}

/// Circular distance between `a` and `b` modulo `range`.
fn mod_diff(a: u8, b: u8, range: u32) -> u32 {
    let d = u32::from(a.abs_diff(b));
    d.min(range - d)
}

const fn swap_nibbles(b: u8) -> u8 {
    b.rotate_left(4)
}

impl fmt::Display for Tlsh {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "T1{:02X}{:02X}{:02X}",
            swap_nibbles(self.checksum),
            swap_nibbles(self.lvalue),
            self.q1_ratio << 4 | self.q2_ratio
        )?;
        self.code
            .iter()
            .rev()
            .try_for_each(|b| write!(f, "{b:02X}"))
    }
}

impl FromStr for Tlsh {
    type Err = Error;

    /// Parses `T1` + 70 hex digits, or the 70 digits alone (the pre-v4
    /// form). Hex is case-insensitive.
    fn from_str(s: &str) -> Result<Self, Error> {
        let invalid = |reason| Error::InvalidDigest {
            algorithm: "TLSH",
            reason,
        };
        let hex = s.strip_prefix("T1").unwrap_or(s).as_bytes();
        if hex.len() != HEX_LEN {
            return Err(invalid("expected `T1` and 70 hex digits"));
        }
        let mut bytes = [0u8; HEX_LEN / 2];
        for (out, &[hi, lo]) in bytes.iter_mut().zip(hex.as_chunks::<2>().0) {
            let digit = |c: u8| {
                char::from(c)
                    .to_digit(16)
                    .ok_or_else(|| invalid("not a hex digit"))
            };
            let value = digit(hi)? << 4 | digit(lo)?;
            *out = u8::try_from(value).map_err(|_| invalid("not a hex digit"))?;
        }
        let mut code = [0u8; CODE_SIZE];
        for (dst, src) in code.iter_mut().zip(bytes[3..].iter().rev()) {
            *dst = *src;
        }
        Ok(Self {
            checksum: swap_nibbles(bytes[0]),
            lvalue: swap_nibbles(bytes[1]),
            q1_ratio: bytes[2] >> 4,
            q2_ratio: bytes[2] & 0x0F,
            code,
        })
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for Tlsh {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for Tlsh {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = <std::borrow::Cow<'de, str>>::deserialize(d)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pearson_table_is_a_permutation() {
        let mut seen = [false; 256];
        for &v in &PEARSON {
            seen[usize::from(v)] = true;
        }
        assert!(seen.iter().all(|&s| s));
    }

    #[test]
    fn topval_is_strictly_increasing() {
        assert!(TOPVAL.windows(2).all(|w| w[0] < w[1]));
    }

    #[test]
    fn l_capturing_boundaries() {
        assert_eq!(l_capturing(1), 0);
        assert_eq!(l_capturing(2), 1);
        assert_eq!(l_capturing(656), 15);
        assert_eq!(l_capturing(657), 16);
        assert_eq!(l_capturing(MAX_LEN), 169);
    }

    #[test]
    fn rejects_short_and_uniform_input() {
        assert!(matches!(
            Tlsh::hash(&[7; 49]),
            Err(Error::TooShort {
                len: 49,
                min: 50,
                ..
            })
        ));
        assert_eq!(Tlsh::hash(&[7; 5000]), Err(Error::LowVariation));
        let mut b = TlshBuilder::new();
        b.update(&(0..=255).collect::<Vec<u8>>());
        assert!(b.finish().is_ok());
        assert!(b.finish_conservative().is_ok());
        let mut b = TlshBuilder::new();
        b.update(&(0..=254).collect::<Vec<u8>>());
        assert!(matches!(
            b.finish_conservative(),
            Err(Error::TooShort { min: 256, .. })
        ));
    }

    #[test]
    fn mod_diff_wraps() {
        assert_eq!(mod_diff(1, 15, 16), 2);
        assert_eq!(mod_diff(15, 1, 16), 2);
        assert_eq!(mod_diff(0, 128, 256), 128);
        assert_eq!(mod_diff(3, 3, 16), 0);
    }

    #[test]
    fn bit_pair_costs_match_reference_table() {
        // Row 0 of TLSH's bit_pairs_diff_table, first 16 entries.
        let expected = [0, 1, 2, 6, 1, 2, 3, 7, 2, 3, 4, 8, 6, 7, 8, 12];
        let zero = Tlsh {
            checksum: 0,
            lvalue: 0,
            q1_ratio: 0,
            q2_ratio: 0,
            code: [0; CODE_SIZE],
        };
        for (y, want) in expected.into_iter().enumerate() {
            let mut other = zero;
            other.code[0] = u8::try_from(y).unwrap();
            assert_eq!(zero.distance(&other), want, "byte {y}");
        }
    }

    #[test]
    fn parse_rejects_malformed() {
        let good = "T109F05A198CC69A5A4F0F9380A9EE93F2B927CF42089EA74276DC5F0BB2D34E68114448";
        assert!(good.parse::<Tlsh>().is_ok());
        assert!(good[2..].parse::<Tlsh>().is_ok());
        assert!(
            good.to_lowercase()
                .replace('t', "T")
                .parse::<Tlsh>()
                .is_ok()
        );
        assert!(good[..71].parse::<Tlsh>().is_err());
        assert!(format!("{good}0").parse::<Tlsh>().is_err());
        assert!(good.replace('F', "G").parse::<Tlsh>().is_err());
        assert!("TNULL".parse::<Tlsh>().is_err());
        assert!(good.replace('9', "+").parse::<Tlsh>().is_err());
    }

    #[test]
    fn bucket_accessor() {
        let t: Tlsh = "T109F05A198CC69A5A4F0F9380A9EE93F2B927CF42089EA74276DC5F0BB2D34E68114448"
            .parse()
            .unwrap();
        assert!((0..128).all(|i| t.bucket(i).is_some_and(|v| v < 4)));
        assert_eq!(t.bucket(128), None);
    }
}
