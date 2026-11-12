//! ssdeep, context-triggered piecewise hashing (CTPH).
//!
//! Produces and compares `blocksize:digest1:digest2` signatures exactly as
//! ssdeep 2.14 (`fuzzy_hash_buf`, `fuzzy_compare`) does. See J. Kornblum,
//! *Identifying almost identical files using context triggered piecewise
//! hashing*, Digital Investigation 3S, 2006, and A. Tridgell's spamsum.
//!
//! A rolling hash over a 7-byte window cuts the input wherever it hits a
//! trigger value that depends on the block size. Each piece contributes
//! one base64 character (6 bits of an FNV-style hash), so a local edit
//! changes only a character or two. `digest1` uses the block size,
//! `digest2` twice the block size, so digests one size step apart can
//! still be compared.

use std::fmt;
use std::str::FromStr;

use crate::Error;

const ROLLING_WINDOW: usize = 7;
const MIN_BLOCKSIZE: u64 = 3;
const SPAMSUM_LENGTH: usize = 64;
const HASH_INIT: u8 = 0x27;
const FNV_PRIME: u32 = 0x0100_0193;
const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
/// Number of block sizes `3 · 2^i` used for hashing.
const LEVELS: u32 = 30;

/// Longest input accepted: the largest block size times 64 (96 GiB).
pub const MAX_LEN: u64 = (MIN_BLOCKSIZE << (LEVELS - 1)) * SPAMSUM_LENGTH as u64;

/// Recommended minimum [`Ssdeep::compare`] score to call two inputs
/// similar.
///
/// Any score above 0 already means the digests share a 7-character run,
/// i.e. the inputs share content; scores are not probabilities. 50 and
/// above usually means versions of the same file. Lower it toward 1 for
/// recall (e.g. hunting for embedded copies), raise it for precision.
pub const RECOMMENDED_MIN_SCORE: u32 = 50;

/// The Adler-style rolling hash over the last 7 bytes.
#[derive(Debug, Clone, Default)]
struct Roll {
    window: [u8; ROLLING_WINDOW],
    h1: u32,
    h2: u32,
    h3: u32,
    n: usize,
}

impl Roll {
    fn push(&mut self, c: u8) {
        let c32 = u32::from(c);
        self.h2 = self.h2.wrapping_sub(self.h1).wrapping_add(7 * c32);
        self.h1 = self
            .h1
            .wrapping_add(c32)
            .wrapping_sub(u32::from(self.window[self.n]));
        self.window[self.n] = c;
        self.n = (self.n + 1) % ROLLING_WINDOW;
        self.h3 = (self.h3 << 5) ^ c32;
    }

    const fn sum(&self) -> u32 {
        self.h1.wrapping_add(self.h2).wrapping_add(self.h3)
    }
}

/// The low 6 bits of an FNV-1 step; only those bits ever reach a digest.
const fn fnv6(h: u8, c: u8) -> u8 {
    #[allow(clippy::cast_possible_truncation, reason = "masked to 6 bits")]
    let out = ((h as u32).wrapping_mul(FNV_PRIME) ^ c as u32) as u8 & 0x3F;
    out
}

/// Piecewise digest state for one block size.
#[derive(Debug, Clone)]
struct Level {
    block_size: u32,
    /// Characters committed so far (at most 63).
    digest: Vec<u8>,
    /// Hash of the piece in progress.
    h: u8,
    /// The value written into the last slot when the digest is full: the
    /// tail of the input folds into a single final character.
    full_tail: Option<u8>,
    /// Like `h`, but stops resetting after 32 characters, for the
    /// 32-character truncated form.
    half_h: u8,
    half_tail: Option<u8>,
}

impl Level {
    fn new(block_size: u32) -> Self {
        Self {
            block_size,
            digest: Vec::with_capacity(SPAMSUM_LENGTH),
            h: HASH_INIT,
            full_tail: None,
            half_h: HASH_INIT,
            half_tail: None,
        }
    }

    fn feed(&mut self, c: u8, trigger: u32) {
        self.h = fnv6(self.h, c);
        self.half_h = fnv6(self.half_h, c);
        if !trigger.is_multiple_of(self.block_size) {
            return;
        }
        let ch = B64[usize::from(self.h)];
        self.half_tail = Some(B64[usize::from(self.half_h)]);
        if self.digest.len() < SPAMSUM_LENGTH - 1 {
            self.digest.push(ch);
            self.full_tail = None;
            self.h = HASH_INIT;
            if self.digest.len() < SPAMSUM_LENGTH / 2 {
                self.half_h = HASH_INIT;
                self.half_tail = None;
            }
        } else {
            self.full_tail = Some(ch);
        }
    }

    /// The full digest (up to 64 characters).
    fn full(&self, roll_nonzero: bool) -> String {
        let tail = if roll_nonzero {
            Some(B64[usize::from(self.h)])
        } else {
            self.full_tail
        };
        collect(&self.digest, tail)
    }

    /// The digest truncated to 32 characters, as ssdeep prints `digest2`.
    fn truncated(&self, roll_nonzero: bool) -> String {
        let n = self.digest.len().min(SPAMSUM_LENGTH / 2 - 1);
        let tail = if roll_nonzero {
            Some(B64[usize::from(self.half_h)])
        } else {
            self.half_tail
        };
        collect(&self.digest[..n], tail)
    }
}

fn collect(chars: &[u8], tail: Option<u8>) -> String {
    chars
        .iter()
        .chain(tail.as_ref())
        .map(|&b| char::from(b))
        .collect()
}

/// Runs the engine over `data` for block sizes `bs` and `2·bs`.
fn levels(data: &[u8], bs: u32) -> (Level, Level, bool) {
    let mut roll = Roll::default();
    let mut lo = Level::new(bs);
    let mut hi = Level::new(bs.saturating_mul(2));
    for &c in data {
        roll.push(c);
        let sum = roll.sum();
        // A piece ends where `sum + 1 ≡ 0 (mod block size)`; ssdeep skips
        // the wrap-around value `sum = 2^32 − 1`.
        let trigger = if sum == u32::MAX { 1 } else { sum + 1 };
        lo.feed(c, trigger);
        hi.feed(c, trigger);
    }
    (lo, hi, roll.sum() != 0)
}

/// An ssdeep signature: `blocksize:digest1:digest2`.
///
/// ```
/// use rune_fuzzyhash::ssdeep::Ssdeep;
///
/// let digest: Ssdeep = "3:AXGBicFlgVNhBGcL6wCrFQEv:AXGHsNhxLsr2C".parse()?;
/// assert_eq!(digest.block_size(), 3);
/// assert_eq!(digest.compare(&digest), 100);
/// assert_eq!(Ssdeep::hash(b"")?.to_string(), "3::");
/// # Ok::<(), rune_fuzzyhash::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Ssdeep {
    block_size: u64,
    digest1: String,
    digest2: String,
}

impl Ssdeep {
    /// Hashes `data`, matching `fuzzy_hash_buf` of ssdeep 2.14.
    ///
    /// # Errors
    ///
    /// [`Error::TooLong`] above [`MAX_LEN`] bytes.
    pub fn hash(data: &[u8]) -> Result<Self, Error> {
        let len = data.len() as u64;
        if len > MAX_LEN {
            return Err(Error::TooLong {
                algorithm: "ssdeep",
                len,
                max: MAX_LEN,
            });
        }
        // Initial guess: the smallest block size whose 64 pieces cover the
        // input. Then halve while the digest is shorter than 32 characters.
        let mut level = 0u32;
        while (MIN_BLOCKSIZE << level) * (SPAMSUM_LENGTH as u64) < len {
            level += 1;
        }
        loop {
            let bs = u32::try_from(MIN_BLOCKSIZE << level).unwrap_or(u32::MAX);
            let (lo, hi, roll_nonzero) = levels(data, bs);
            if level > 0 && lo.digest.len() < SPAMSUM_LENGTH / 2 {
                level -= 1;
                continue;
            }
            return Ok(Self {
                block_size: u64::from(bs),
                digest1: lo.full(roll_nonzero),
                digest2: hi.truncated(roll_nonzero),
            });
        }
    }

    /// The block size.
    #[must_use]
    pub const fn block_size(&self) -> u64 {
        self.block_size
    }

    /// The digest at the block size.
    #[must_use]
    pub fn digest1(&self) -> &str {
        &self.digest1
    }

    /// The digest at twice the block size.
    #[must_use]
    pub fn digest2(&self) -> &str {
        &self.digest2
    }

    /// The ssdeep match score, 0 (no match) to 100 (identical or nearly
    /// so), as `fuzzy_compare` computes it.
    ///
    /// Signatures whose block sizes differ by more than a factor of two
    /// are not comparable and score 0. See [`RECOMMENDED_MIN_SCORE`].
    #[must_use]
    pub fn compare(&self, other: &Self) -> u32 {
        let (bs1, bs2) = (self.block_size, other.block_size);
        let comparable =
            bs1 == bs2 || bs1.checked_mul(2) == Some(bs2) || (bs1 % 2 == 0 && bs1 / 2 == bs2);
        if !comparable {
            return 0;
        }
        let a1 = eliminate_sequences(&self.digest1);
        let a2 = eliminate_sequences(&self.digest2);
        let b1 = eliminate_sequences(&other.digest1);
        let b2 = eliminate_sequences(&other.digest2);
        if bs1 == bs2 && a1 == b1 && a2 == b2 {
            return 100;
        }
        if bs1 == bs2 {
            score_strings(&a1, &b1, bs1).max(score_strings(&a2, &b2, bs1.saturating_mul(2)))
        } else if bs1.checked_mul(2) == Some(bs2) {
            score_strings(&b1, &a2, bs2)
        } else {
            score_strings(&a1, &b2, bs1)
        }
    }

    /// Whether `compare(other) ≥ RECOMMENDED_MIN_SCORE`.
    #[must_use]
    pub fn is_similar(&self, other: &Self) -> bool {
        self.compare(other) >= RECOMMENDED_MIN_SCORE
    }
}

/// Drops the 4th and later repeats of any character run: long runs carry
/// little information and would inflate scores.
fn eliminate_sequences(s: &str) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::with_capacity(s.len());
    for &c in s.as_bytes() {
        if out.len() >= 3 && out[out.len() - 3..].iter().all(|&p| p == c) {
            continue;
        }
        out.push(c);
    }
    out
}

/// Whether `a` and `b` share a substring of `ROLLING_WINDOW` characters.
fn has_common_substring(a: &[u8], b: &[u8]) -> bool {
    a.windows(ROLLING_WINDOW)
        .any(|wa| b.windows(ROLLING_WINDOW).any(|wb| wa == wb))
}

/// Edit distance with insert and delete cost 1 and substitution cost 2,
/// i.e. `|a| + |b| − 2·LCS(a, b)`.
fn edit_distance(a: &[u8], b: &[u8]) -> usize {
    let mut prev: Vec<usize> = (0..=b.len()).collect();
    let mut cur = vec![0; b.len() + 1];
    for (i, &ca) in a.iter().enumerate() {
        cur[0] = i + 1;
        for (j, &cb) in b.iter().enumerate() {
            let replace = prev[j] + if ca == cb { 0 } else { 2 };
            cur[j + 1] = (prev[j + 1] + 1).min(cur[j] + 1).min(replace);
        }
        std::mem::swap(&mut prev, &mut cur);
    }
    prev[b.len()]
}

fn score_strings(a: &[u8], b: &[u8], block_size: u64) -> u32 {
    if a.len() < ROLLING_WINDOW || b.len() < ROLLING_WINDOW || !has_common_substring(a, b) {
        return 0;
    }
    // Digests are at most 64 characters, so these all fit easily.
    let total = (a.len() + b.len()) as u64;
    let scaled = edit_distance(a, b) as u64 * SPAMSUM_LENGTH as u64 / total;
    let score = 100 - (100 * scaled / SPAMSUM_LENGTH as u64).min(100);
    // Small block sizes would exaggerate matches between tiny inputs.
    let cap_from = (99 + ROLLING_WINDOW as u64) / ROLLING_WINDOW as u64 * MIN_BLOCKSIZE;
    let score = if block_size >= cap_from {
        score
    } else {
        score.min(block_size / MIN_BLOCKSIZE * a.len().min(b.len()) as u64)
    };
    u32::try_from(score).unwrap_or(0)
}

impl fmt::Display for Ssdeep {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}:{}", self.block_size, self.digest1, self.digest2)
    }
}

impl FromStr for Ssdeep {
    type Err = Error;

    /// Parses `blocksize:digest1:digest2`. A trailing `,"filename"` (as
    /// the `ssdeep` tool prints) is ignored.
    fn from_str(s: &str) -> Result<Self, Error> {
        let invalid = |reason| Error::InvalidDigest {
            algorithm: "ssdeep",
            reason,
        };
        let s = s.split_once(',').map_or(s, |(sig, _)| sig);
        let mut parts = s.splitn(3, ':');
        let (Some(bs), Some(d1), Some(d2)) = (parts.next(), parts.next(), parts.next()) else {
            return Err(invalid("expected `blocksize:digest1:digest2`"));
        };
        if bs.is_empty() || !bs.bytes().all(|b| b.is_ascii_digit()) {
            return Err(invalid("block size is not a decimal number"));
        }
        let block_size = bs
            .parse::<u64>()
            .map_err(|_| invalid("block size out of range"))?;
        for d in [d1, d2] {
            if d.len() > SPAMSUM_LENGTH {
                return Err(invalid("digest longer than 64 characters"));
            }
            if !d.bytes().all(|b| B64.contains(&b)) {
                return Err(invalid("digest has a non-base64 character"));
            }
        }
        Ok(Self {
            block_size,
            digest1: d1.to_owned(),
            digest2: d2.to_owned(),
        })
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for Ssdeep {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for Ssdeep {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = <std::borrow::Cow<'de, str>>::deserialize(d)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fnv6_matches_reference_sum_table() {
        // Spot checks against sum_table[h][c] of ssdeep 2.14.
        assert_eq!(fnv6(0x01, 0x00), 0x13);
        assert_eq!(fnv6(0x01, 0x01), 0x12);
        assert_eq!(fnv6(0x02, 0x00), 0x26);
        assert_eq!(fnv6(0x02, 0x3F), 0x19);
        // Only the low 6 bits of the input byte matter.
        assert_eq!(fnv6(0x27, b'a'), fnv6(0x27, b'a' & 0x3F));
    }

    #[test]
    fn eliminates_runs_longer_than_three() {
        assert_eq!(eliminate_sequences("AAAAAABBBCDDDD"), b"AAABBBCDDD");
        assert_eq!(eliminate_sequences(""), b"");
    }

    #[test]
    fn edit_distance_costs() {
        assert_eq!(edit_distance(b"", b"Hello World!"), 12);
        assert_eq!(edit_distance(b"Hello World!", b"Hello World!"), 0);
        assert_eq!(edit_distance(b"Hello World!", b"Hello world!"), 2);
        assert_eq!(edit_distance(b"Hello World!", b"Hello World"), 1);
    }

    #[test]
    fn incomparable_block_sizes_score_zero() {
        let a: Ssdeep = "3:ABCDEFGH:ABCD".parse().unwrap();
        let b: Ssdeep = "12:ABCDEFGH:ABCD".parse().unwrap();
        assert_eq!(a.compare(&b), 0);
    }

    #[test]
    fn identical_after_elimination_is_100() {
        let a: Ssdeep = "3:AAAAAAA:B".parse().unwrap();
        let b: Ssdeep = "3:AAAA:B".parse().unwrap();
        assert_eq!(a.compare(&b), 100);
    }

    #[test]
    fn parse_rules() {
        assert!("3::".parse::<Ssdeep>().is_ok());
        let with_name: Ssdeep = "96:abc:de,\"file,name\"".parse().unwrap();
        assert_eq!(with_name.digest2(), "de");
        for bad in [
            "",
            "3",
            "3:a",
            "x:a:b",
            "-3:a:b",
            "3:a!:b",
            "99999999999999999999999:a:b",
        ] {
            assert!(bad.parse::<Ssdeep>().is_err(), "{bad:?}");
        }
        assert!(format!("3:{}:", "A".repeat(65)).parse::<Ssdeep>().is_err());
    }

    #[test]
    fn small_block_size_caps_the_score() {
        // Uncapped this pair scores 88; at block size 3 the cap is 3/3 · 8.
        // ssdeep 2.14.1 `fuzzy_compare` gives 8 too.
        let a: Ssdeep = "3:ABCDEFGH:".parse().unwrap();
        let b: Ssdeep = "3:ABCDEFGX:".parse().unwrap();
        assert_eq!(a.compare(&b), 8);
    }
}
