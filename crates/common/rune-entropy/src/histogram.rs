//! Byte histogram and the order-0 statistics derived from it.

use core::fmt;
use core::ops::Index;

use crate::math;

/// Inputs shorter than this are counted with a plain loop; longer ones use
/// four interleaved tables, which avoids stalls when the same byte repeats.
const INTERLEAVE_MIN: usize = 512;

/// Per-byte occurrence counts, updated incrementally.
///
/// A `Histogram` is the building block for every statistic in this crate.
/// It takes a fixed 2 KiB regardless of how much data is fed through it, and
/// its counters are `u64`, so they cannot overflow on any realistic input.
///
/// # Examples
///
/// ```rust
/// use rune_entropy::Histogram;
///
/// let mut hist = Histogram::new();
/// hist.update(b"hello ");
/// hist.update(b"world");
///
/// assert_eq!(hist.total(), 11);
/// assert_eq!(hist.count(b'l'), 3);
/// assert_eq!(hist.distinct(), 8);
/// assert!((hist.shannon() - 2.845_350_936).abs() < 1e-9);
/// ```
#[derive(Clone, PartialEq, Eq)]
pub struct Histogram {
    counts: [u64; 256],
    total: u64,
}

impl Default for Histogram {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for Histogram {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Histogram")
            .field("total", &self.total)
            .field("distinct", &self.distinct())
            .finish_non_exhaustive()
    }
}

impl Histogram {
    /// Creates an empty histogram.
    ///
    /// # Examples
    ///
    /// ```rust
    /// let hist = rune_entropy::Histogram::new();
    /// assert!(hist.is_empty());
    /// assert_eq!(hist.shannon(), 0.0);
    /// ```
    #[must_use]
    pub const fn new() -> Self {
        Self {
            counts: [0; 256],
            total: 0,
        }
    }

    /// Builds a histogram of `data`.
    ///
    /// # Examples
    ///
    /// ```rust
    /// let hist = rune_entropy::Histogram::from_bytes(b"aab");
    /// assert_eq!(hist.count(b'a'), 2);
    /// assert_eq!(hist.count(b'b'), 1);
    /// ```
    #[must_use]
    pub fn from_bytes(data: &[u8]) -> Self {
        let mut hist = Self::new();
        hist.update(data);
        hist
    }

    /// Adds every byte of `data` to the counts.
    ///
    /// # Examples
    ///
    /// ```rust
    /// let mut hist = rune_entropy::Histogram::new();
    /// for chunk in [&b"ab"[..], b"cd"] {
    ///     hist.update(chunk);
    /// }
    /// assert_eq!(hist.shannon(), 2.0);
    /// ```
    pub fn update(&mut self, data: &[u8]) {
        count_into(&mut self.counts, data);
        self.total += data.len() as u64;
    }

    /// Adds a single byte.
    ///
    /// # Examples
    ///
    /// ```rust
    /// let mut hist = rune_entropy::Histogram::new();
    /// hist.push(0xff);
    /// assert_eq!(hist[0xff], 1);
    /// ```
    pub const fn push(&mut self, byte: u8) {
        self.counts[byte as usize] += 1;
        self.total += 1;
    }

    /// Adds the counts of `other` to this histogram.
    ///
    /// Useful for combining histograms computed in parallel over separate
    /// chunks of the same input.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rune_entropy::Histogram;
    ///
    /// let mut left = Histogram::from_bytes(b"abc");
    /// left.merge(&Histogram::from_bytes(b"def"));
    /// assert_eq!(left, Histogram::from_bytes(b"abcdef"));
    /// ```
    pub fn merge(&mut self, other: &Self) {
        for (mine, theirs) in self.counts.iter_mut().zip(other.counts.iter()) {
            *mine += theirs;
        }
        self.total += other.total;
    }

    /// Resets all counts to zero.
    ///
    /// # Examples
    ///
    /// ```rust
    /// let mut hist = rune_entropy::Histogram::from_bytes(b"abc");
    /// hist.clear();
    /// assert!(hist.is_empty());
    /// ```
    pub const fn clear(&mut self) {
        *self = Self::new();
    }

    /// Returns the raw counts, indexed by byte value.
    ///
    /// # Examples
    ///
    /// ```rust
    /// let hist = rune_entropy::Histogram::from_bytes(&[0, 0, 7]);
    /// assert_eq!(hist.counts()[0], 2);
    /// assert_eq!(hist.counts()[7], 1);
    /// ```
    #[must_use]
    pub const fn counts(&self) -> &[u64; 256] {
        &self.counts
    }

    /// Returns how many times `byte` was seen.
    ///
    /// # Examples
    ///
    /// ```rust
    /// assert_eq!(rune_entropy::Histogram::from_bytes(b"xx").count(b'x'), 2);
    /// ```
    #[must_use]
    pub const fn count(&self, byte: u8) -> u64 {
        self.counts[byte as usize]
    }

    /// Returns the total number of bytes counted.
    ///
    /// # Examples
    ///
    /// ```rust
    /// assert_eq!(rune_entropy::Histogram::from_bytes(b"four").total(), 4);
    /// ```
    #[must_use]
    pub const fn total(&self) -> u64 {
        self.total
    }

    /// Returns `true` if no bytes have been counted.
    ///
    /// # Examples
    ///
    /// ```rust
    /// assert!(rune_entropy::Histogram::new().is_empty());
    /// ```
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.total == 0
    }

    /// Returns how many distinct byte values were seen (0–256).
    ///
    /// # Examples
    ///
    /// ```rust
    /// assert_eq!(rune_entropy::Histogram::from_bytes(b"banana").distinct(), 3);
    /// ```
    #[must_use]
    pub fn distinct(&self) -> usize {
        self.counts.iter().filter(|&&c| c > 0).count()
    }

    /// Returns the most frequent byte and its count, or `None` when empty.
    ///
    /// Ties go to the smallest byte value.
    ///
    /// # Examples
    ///
    /// ```rust
    /// let hist = rune_entropy::Histogram::from_bytes(b"banana");
    /// assert_eq!(hist.most_common(), Some((b'a', 3)));
    /// ```
    #[must_use]
    pub fn most_common(&self) -> Option<(u8, u64)> {
        let mut best: Option<(u8, u64)> = None;
        for (byte, &count) in (0..=u8::MAX).zip(self.counts.iter()) {
            if count > 0 && best.is_none_or(|(_, top)| count > top) {
                best = Some((byte, count));
            }
        }
        best
    }

    /// Shannon entropy in bits per byte, in `[0.0, 8.0]`.
    ///
    /// Empty input gives `0.0`, never `NaN`. This is the plug-in estimate,
    /// which reads low on short inputs: `n` truly random bytes score about
    /// [`random_entropy_baseline(n)`](crate::random_entropy_baseline), not 8.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rune_entropy::Histogram;
    ///
    /// assert_eq!(Histogram::from_bytes(&[9; 100]).shannon(), 0.0);
    /// assert_eq!(Histogram::from_bytes(b"abcd").shannon(), 2.0);
    /// ```
    #[must_use]
    pub fn shannon(&self) -> f64 {
        shannon_from_counts(&self.counts, self.total)
    }

    /// Min-entropy `-log2(p_max)` in bits per byte, in `[0.0, 8.0]`.
    ///
    /// Min-entropy is the conservative measure used when judging randomness
    /// for cryptographic purposes: it only looks at the most likely byte, so
    /// it is always less than or equal to the Shannon entropy.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rune_entropy::Histogram;
    ///
    /// let hist = Histogram::from_bytes(b"aaab");
    /// assert!((hist.min_entropy() - 0.415_037_5).abs() < 1e-6);
    /// assert!(hist.min_entropy() <= hist.shannon());
    /// ```
    #[must_use]
    pub fn min_entropy(&self) -> f64 {
        let Some((_, top)) = self.most_common() else {
            return 0.0;
        };
        if top == self.total {
            return 0.0;
        }
        let bits = -math::log2(to_f64(top) / to_f64(self.total));
        bits.clamp(0.0, 8.0)
    }

    /// Pearson chi-square statistic against a uniform byte distribution,
    /// with 255 degrees of freedom. `None` when empty.
    ///
    /// Uniformly random data scores around 255; compressed data usually
    /// scores far higher once there are a few kilobytes of it. See
    /// [`chi_square_p_value`](Self::chi_square_p_value).
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rune_entropy::Histogram;
    ///
    /// let cycle: Vec<u8> = (0..=255).collect();
    /// assert_eq!(Histogram::from_bytes(&cycle).chi_square(), Some(0.0));
    /// assert_eq!(Histogram::new().chi_square(), None);
    /// ```
    #[must_use]
    pub fn chi_square(&self) -> Option<f64> {
        if self.total == 0 {
            return None;
        }
        let expected = to_f64(self.total) / 256.0;
        let sum = self
            .counts
            .iter()
            .map(|&count| {
                let diff = to_f64(count) - expected;
                diff * diff
            })
            .sum::<f64>();
        Some(sum / expected)
    }

    /// Probability that uniformly random bytes would give a chi-square value
    /// at least as large as this one. `None` when empty.
    ///
    /// Values below about `0.001` mean the data is measurably non-uniform.
    /// Values extremely close to `1.0` mean it is *too* uniform to be random
    /// (counters, lookup tables). The statistic needs roughly five expected
    /// hits per byte value, so treat results on inputs under ~1.3 KiB as
    /// rough. Computed with the Wilson–Hilferty approximation.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rune_entropy::Histogram;
    ///
    /// let text = Histogram::from_bytes(&b"the quick brown fox ".repeat(100));
    /// assert!(text.chi_square_p_value().unwrap() < 1e-6);
    /// ```
    #[must_use]
    pub fn chi_square_p_value(&self) -> Option<f64> {
        self.chi_square()
            .map(|chi| math::chi_square_upper_tail(chi, 255.0))
    }

    /// Arithmetic mean of the byte values. `None` when empty.
    ///
    /// Random data averages close to `127.5`.
    ///
    /// # Examples
    ///
    /// ```rust
    /// let hist = rune_entropy::Histogram::from_bytes(&[0, 255]);
    /// assert_eq!(hist.mean(), Some(127.5));
    /// ```
    #[must_use]
    pub fn mean(&self) -> Option<f64> {
        if self.total == 0 {
            return None;
        }
        let (sum, _) = self.moments();
        Some(u128_to_f64(sum) / to_f64(self.total))
    }

    /// Fraction of bytes that are printable ASCII or common whitespace
    /// (`\t`, `\n`, `\r`). `None` when empty.
    ///
    /// # Examples
    ///
    /// ```rust
    /// let hist = rune_entropy::Histogram::from_bytes(b"ok\n\x00");
    /// assert_eq!(hist.printable_ratio(), Some(0.75));
    /// ```
    #[must_use]
    pub fn printable_ratio(&self) -> Option<f64> {
        if self.total == 0 {
            return None;
        }
        let printable = self.counts[0x20..=0x7e].iter().sum::<u64>()
            + self.counts[usize::from(b'\t')]
            + self.counts[usize::from(b'\n')]
            + self.counts[usize::from(b'\r')];
        Some(to_f64(printable) / to_f64(self.total))
    }

    /// Returns `(sum of values, sum of squared values)`.
    pub(crate) fn moments(&self) -> (u128, u128) {
        let mut sum = 0u128;
        let mut sum_sq = 0u128;
        for (value, &count) in (0u128..).zip(self.counts.iter()) {
            sum += value * u128::from(count);
            sum_sq += value * value * u128::from(count);
        }
        (sum, sum_sq)
    }
}

impl Index<u8> for Histogram {
    type Output = u64;

    fn index(&self, byte: u8) -> &u64 {
        &self.counts[usize::from(byte)]
    }
}

impl Extend<u8> for Histogram {
    fn extend<I: IntoIterator<Item = u8>>(&mut self, iter: I) {
        for byte in iter {
            self.push(byte);
        }
    }
}

impl<'a> Extend<&'a u8> for Histogram {
    fn extend<I: IntoIterator<Item = &'a u8>>(&mut self, iter: I) {
        self.extend(iter.into_iter().copied());
    }
}

impl FromIterator<u8> for Histogram {
    fn from_iter<I: IntoIterator<Item = u8>>(iter: I) -> Self {
        let mut hist = Self::new();
        hist.extend(iter);
        hist
    }
}

/// Lossy `u64` → `f64`; exact below 2^53, which covers any real input size.
#[allow(
    clippy::cast_precision_loss,
    reason = "counts stay far below 2^53 in practice; rounding beyond that is harmless here"
)]
pub const fn to_f64(value: u64) -> f64 {
    value as f64
}

#[allow(
    clippy::cast_precision_loss,
    reason = "only used for statistics where relative precision is what matters"
)]
pub const fn u128_to_f64(value: u128) -> f64 {
    value as f64
}

/// Shannon entropy of a set of counts summing to `total`.
pub fn shannon_from_counts(counts: &[u64; 256], total: u64) -> f64 {
    if total == 0 {
        return 0.0;
    }
    let n = to_f64(total);
    let mut bits = 0.0;
    for &count in counts {
        if count != 0 {
            let p = to_f64(count) / n;
            bits -= p * math::log2(p);
        }
    }
    bits.clamp(0.0, 8.0)
}

fn count_into(counts: &mut [u64; 256], data: &[u8]) {
    if data.len() < INTERLEAVE_MIN {
        for &byte in data {
            counts[usize::from(byte)] += 1;
        }
        return;
    }
    // Each table sees at most a quarter of a piece, so u32 cannot overflow.
    let mut tables = [[0u32; 256]; 4];
    for piece in data.chunks(1 << 30) {
        let (quads, rest) = piece.as_chunks::<4>();
        for quad in quads {
            tables[0][usize::from(quad[0])] += 1;
            tables[1][usize::from(quad[1])] += 1;
            tables[2][usize::from(quad[2])] += 1;
            tables[3][usize::from(quad[3])] += 1;
        }
        for &byte in rest {
            tables[0][usize::from(byte)] += 1;
        }
        for (i, slot) in counts.iter_mut().enumerate() {
            *slot += tables.iter().map(|table| u64::from(table[i])).sum::<u64>();
        }
        tables = [[0u32; 256]; 4];
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    #[test]
    fn interleaved_counting_matches_naive() {
        let data: Vec<u8> = (0..10_007u32)
            .map(|i| u8::try_from(i.wrapping_mul(2_654_435_761) >> 24).unwrap_or(0))
            .collect();
        let fast = Histogram::from_bytes(&data);
        let mut slow = Histogram::new();
        for &b in &data {
            slow.push(b);
        }
        assert_eq!(fast, slow);
    }

    #[test]
    fn empty_statistics_have_no_nan() {
        let hist = Histogram::new();
        assert_eq!(hist.shannon(), 0.0);
        assert_eq!(hist.min_entropy(), 0.0);
        assert_eq!(hist.chi_square(), None);
        assert_eq!(hist.mean(), None);
        assert_eq!(hist.most_common(), None);
    }

    #[test]
    fn moments_are_exact() {
        let hist = Histogram::from_bytes(&[1, 2, 3, 255]);
        assert_eq!(hist.moments(), (261, 1 + 4 + 9 + 65_025));
    }

    #[test]
    fn chi_square_of_constant_input() {
        // 256 bytes of one value: (256-1)^2/1 + 255 * 1 = 65280.
        let hist = Histogram::from_bytes(&[0u8; 256]);
        assert_eq!(hist.chi_square(), Some(65_280.0));
        assert!(hist.chi_square_p_value().unwrap_or(1.0) < 1e-12);
    }
}
