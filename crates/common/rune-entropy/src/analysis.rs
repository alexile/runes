//! Streaming analyzer with `ent`-style statistics and a cautious verdict.

use core::fmt;

use crate::histogram::{Histogram, to_f64, u128_to_f64};
use crate::math;

/// Shannon entropy at or above which data counts as high entropy.
pub const HIGH_ENTROPY_THRESHOLD: f64 = 7.0;

/// Shannon entropy below which data counts as repetitive.
pub const LOW_ENTROPY_THRESHOLD: f64 = 3.0;

/// Fraction of printable bytes at or above which data counts as text.
pub const TEXT_PRINTABLE_RATIO: f64 = 0.95;

/// Smallest input on which [`Analysis::assess`] runs its statistical tests.
pub const MIN_STATISTICAL_SAMPLE: u64 = 128;

/// Chi-square p-value below which data is considered measurably non-uniform.
pub const CHI_SQUARE_ALPHA: f64 = 0.001;

/// Bytes per Monte Carlo point: two 24-bit coordinates, as `ent` does it.
const MONTE_CARLO_BYTES: usize = 6;

/// Squared radius of the Monte Carlo circle, `(2^24 - 1)^2`.
const MONTE_CARLO_RADIUS_SQ: u64 = ((1 << 24) - 1) * ((1 << 24) - 1);

/// Incremental analyzer: feed it chunks, read statistics at any point.
///
/// Memory use is fixed (a few kilobytes) no matter how much data passes
/// through, so it is suitable for multi-gigabyte files and network streams.
/// With the `std` feature it also implements [`std::io::Write`], so
/// [`std::io::copy`] can drive it.
///
/// # Examples
///
/// ```rust
/// use rune_entropy::Analyzer;
///
/// let mut analyzer = Analyzer::new();
/// for chunk in [&b"first chunk, "[..], b"second chunk"] {
///     analyzer.update(chunk);
///     println!("running entropy: {:.3}", analyzer.shannon());
/// }
/// let report = analyzer.analysis();
/// assert_eq!(report.len, 25);
/// assert!(report.shannon > 3.0 && report.shannon < 4.0);
/// ```
#[derive(Debug, Clone, Default)]
pub struct Analyzer {
    histogram: Histogram,
    first: Option<u8>,
    last: u8,
    /// Sum of `x[i] * x[i + 1]` over adjacent pairs seen so far.
    adjacent_products: u128,
    mc_buffer: [u8; MONTE_CARLO_BYTES],
    mc_buffered: usize,
    mc_points: u64,
    mc_inside: u64,
}

impl Analyzer {
    /// Creates an empty analyzer.
    ///
    /// # Examples
    ///
    /// ```rust
    /// let analyzer = rune_entropy::Analyzer::new();
    /// assert_eq!(analyzer.len(), 0);
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Feeds the next chunk of input.
    ///
    /// # Examples
    ///
    /// ```rust
    /// let mut analyzer = rune_entropy::Analyzer::new();
    /// analyzer.update(b"abcd");
    /// assert_eq!(analyzer.shannon(), 2.0);
    /// ```
    pub fn update(&mut self, data: &[u8]) {
        let (Some(&head), Some(&tail)) = (data.first(), data.last()) else {
            return;
        };
        self.histogram.update(data);

        if self.first.is_some() {
            self.adjacent_products += u128::from(self.last) * u128::from(head);
        } else {
            self.first = Some(head);
        }
        // Sum in u64 per piece (at most 2^30 * 65025 < 2^46), then widen.
        let mut prev_tail = None;
        for piece in data.chunks(1 << 30) {
            if let (Some(prev), Some(&next)) = (prev_tail, piece.first()) {
                self.adjacent_products += u128::from(prev) * u128::from(next);
            }
            let sum: u64 = piece
                .windows(2)
                .map(|pair| u64::from(pair[0]) * u64::from(pair[1]))
                .sum();
            self.adjacent_products += u128::from(sum);
            prev_tail = piece.last().copied();
        }
        self.last = tail;

        self.update_monte_carlo(data);
    }

    fn update_monte_carlo(&mut self, mut data: &[u8]) {
        if self.mc_buffered > 0 {
            let need = MONTE_CARLO_BYTES - self.mc_buffered;
            let take = need.min(data.len());
            self.mc_buffer[self.mc_buffered..self.mc_buffered + take]
                .copy_from_slice(&data[..take]);
            self.mc_buffered += take;
            data = &data[take..];
            if self.mc_buffered < MONTE_CARLO_BYTES {
                return;
            }
            let point = self.mc_buffer;
            self.add_point(&point);
            self.mc_buffered = 0;
        }
        let (points, rest) = data.as_chunks::<MONTE_CARLO_BYTES>();
        for point in points {
            self.add_point(point);
        }
        self.mc_buffer[..rest.len()].copy_from_slice(rest);
        self.mc_buffered = rest.len();
    }

    fn add_point(&mut self, point: &[u8]) {
        let coord = |bytes: &[u8]| {
            bytes
                .iter()
                .fold(0u64, |acc, &byte| (acc << 8) | u64::from(byte))
        };
        let x = coord(&point[..3]);
        let y = coord(&point[3..]);
        self.mc_points += 1;
        if x * x + y * y <= MONTE_CARLO_RADIUS_SQ {
            self.mc_inside += 1;
        }
    }

    /// Number of bytes fed so far.
    ///
    /// # Examples
    ///
    /// ```rust
    /// let mut analyzer = rune_entropy::Analyzer::new();
    /// analyzer.update(&[0; 10]);
    /// assert_eq!(analyzer.len(), 10);
    /// ```
    #[must_use]
    pub const fn len(&self) -> u64 {
        self.histogram.total()
    }

    /// Returns `true` if nothing has been fed yet.
    ///
    /// # Examples
    ///
    /// ```rust
    /// assert!(rune_entropy::Analyzer::new().is_empty());
    /// ```
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.histogram.is_empty()
    }

    /// The byte histogram accumulated so far.
    ///
    /// # Examples
    ///
    /// ```rust
    /// let mut analyzer = rune_entropy::Analyzer::new();
    /// analyzer.update(b"zz");
    /// assert_eq!(analyzer.histogram()[b'z'], 2);
    /// ```
    #[must_use]
    pub const fn histogram(&self) -> &Histogram {
        &self.histogram
    }

    /// Shannon entropy of everything fed so far, in bits per byte.
    ///
    /// Cheap enough to call after every chunk.
    ///
    /// # Examples
    ///
    /// ```rust
    /// let mut analyzer = rune_entropy::Analyzer::new();
    /// analyzer.update(&[1, 2]);
    /// assert_eq!(analyzer.shannon(), 1.0);
    /// ```
    #[must_use]
    pub fn shannon(&self) -> f64 {
        self.histogram.shannon()
    }

    /// Serial correlation coefficient between each byte and the next,
    /// wrapping the last byte around to the first exactly like `ent`.
    ///
    /// Near `0.0` for random data, near `1.0` for slowly varying data such
    /// as counters or audio samples. `None` when fewer than two bytes have
    /// been fed or every byte is identical (the coefficient is undefined).
    ///
    /// # Examples
    ///
    /// ```rust
    /// let mut analyzer = rune_entropy::Analyzer::new();
    /// analyzer.update(&[0, 255, 0, 255]);
    /// assert_eq!(analyzer.serial_correlation(), Some(-1.0));
    /// ```
    #[must_use]
    pub fn serial_correlation(&self) -> Option<f64> {
        let first = self.first?;
        let n = u128::from(self.len());
        if n < 2 {
            return None;
        }
        let (sum, sum_sq) = self.histogram.moments();
        let products = self.adjacent_products + u128::from(self.last) * u128::from(first);

        let exact = || {
            let sum_squared = sum.checked_mul(sum)?;
            let numer_pos = n.checked_mul(products)?;
            let denom_pos = n.checked_mul(sum_sq)?;
            let denom = denom_pos.checked_sub(sum_squared)?;
            let numer = if numer_pos >= sum_squared {
                u128_to_f64(numer_pos - sum_squared)
            } else {
                -u128_to_f64(sum_squared - numer_pos)
            };
            Some((numer, u128_to_f64(denom)))
        };
        let (numer, denom) = exact().unwrap_or_else(|| {
            let (n, sum, sum_sq, products) = (
                u128_to_f64(n),
                u128_to_f64(sum),
                u128_to_f64(sum_sq),
                u128_to_f64(products),
            );
            let sum_squared = sum * sum;
            (n * products - sum_squared, n * sum_sq - sum_squared)
        });
        if denom <= 0.0 {
            return None;
        }
        Some((numer / denom).clamp(-1.0, 1.0))
    }

    /// Monte Carlo estimate of π, computed the way `ent` does it: each
    /// 6-byte group is a point with two 24-bit coordinates, and π is four
    /// times the fraction that lands inside the quarter circle.
    ///
    /// Random data converges on π; structured data drifts away. `None` until
    /// at least one full group has been seen.
    ///
    /// # Examples
    ///
    /// ```rust
    /// let mut analyzer = rune_entropy::Analyzer::new();
    /// analyzer.update(&[0; 6]);
    /// assert_eq!(analyzer.monte_carlo_pi(), Some(4.0));
    /// ```
    #[must_use]
    pub fn monte_carlo_pi(&self) -> Option<f64> {
        (self.mc_points > 0).then(|| 4.0 * to_f64(self.mc_inside) / to_f64(self.mc_points))
    }

    /// Takes a snapshot of every statistic.
    ///
    /// # Examples
    ///
    /// ```rust
    /// let mut analyzer = rune_entropy::Analyzer::new();
    /// analyzer.update(b"hello world");
    /// let report = analyzer.analysis();
    /// assert_eq!(report.distinct, 8);
    /// ```
    #[must_use]
    pub fn analysis(&self) -> Analysis {
        let hist = &self.histogram;
        Analysis {
            len: hist.total(),
            distinct: hist.distinct(),
            shannon: hist.shannon(),
            min_entropy: hist.min_entropy(),
            chi_square: hist.chi_square(),
            chi_square_p_value: hist.chi_square_p_value(),
            mean: hist.mean(),
            serial_correlation: self.serial_correlation(),
            monte_carlo_pi: self.monte_carlo_pi(),
            printable_ratio: hist.printable_ratio(),
        }
    }

    /// Clears all state so the analyzer can be reused.
    ///
    /// # Examples
    ///
    /// ```rust
    /// let mut analyzer = rune_entropy::Analyzer::new();
    /// analyzer.update(b"abc");
    /// analyzer.reset();
    /// assert!(analyzer.is_empty());
    /// ```
    pub fn reset(&mut self) {
        *self = Self::default();
    }
}

#[cfg(feature = "std")]
impl std::io::Write for Analyzer {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.update(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// A snapshot of statistics for some input, as produced by [`analyze`] or
/// [`Analyzer::analysis`].
///
/// Statistics that are undefined for the input (empty data, a single
/// repeated byte, too few bytes) are `None` rather than `NaN`.
///
/// [`analyze`]: crate::analyze
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Analysis {
    /// Number of bytes analysed.
    pub len: u64,
    /// Number of distinct byte values seen (0–256).
    pub distinct: usize,
    /// Shannon entropy in bits per byte, `[0.0, 8.0]`.
    pub shannon: f64,
    /// Min-entropy in bits per byte, `[0.0, 8.0]`, never above `shannon`.
    pub min_entropy: f64,
    /// Chi-square statistic against uniform bytes (255 degrees of freedom).
    pub chi_square: Option<f64>,
    /// Upper-tail probability of `chi_square` for uniformly random bytes.
    pub chi_square_p_value: Option<f64>,
    /// Arithmetic mean of byte values (`127.5` for random data).
    pub mean: Option<f64>,
    /// Serial correlation of adjacent bytes (`0.0` for random data).
    pub serial_correlation: Option<f64>,
    /// Monte Carlo estimate of π (close to π for random data).
    pub monte_carlo_pi: Option<f64>,
    /// Fraction of printable ASCII and common whitespace bytes.
    pub printable_ratio: Option<f64>,
}

impl Analysis {
    /// Size of an ideal order-0 compression relative to the input, as a
    /// fraction (`shannon / 8`). `1.0` means order-0 coding cannot shrink it.
    ///
    /// # Examples
    ///
    /// ```rust
    /// let report = rune_entropy::analyze(b"abcd");
    /// assert_eq!(report.compression_ratio(), 0.25);
    /// ```
    #[must_use]
    pub fn compression_ratio(&self) -> f64 {
        self.shannon / 8.0
    }

    /// Classifies the data with the rules described on [`Verdict`].
    ///
    /// This is a heuristic based on order-0 statistics. It is good for
    /// triage, not proof: it cannot tell encryption from strong compression,
    /// and it labels non-ASCII text as binary.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rune_entropy::{analyze, Verdict};
    ///
    /// let text = b"Entropy is a measure of surprise. ".repeat(20);
    /// assert_eq!(analyze(&text).assess().verdict, Verdict::Text);
    ///
    /// assert_eq!(analyze(&[0; 4096]).assess().verdict, Verdict::Repetitive);
    /// assert_eq!(analyze(b"").assess().verdict, Verdict::Empty);
    /// ```
    #[must_use]
    pub fn assess(&self) -> Assessment {
        let confidence = match self.len {
            0 => Confidence::High,
            n if n < MIN_STATISTICAL_SAMPLE => Confidence::Low,
            n if n < 4096 => Confidence::Medium,
            _ => Confidence::High,
        };
        let verdict = self.verdict();
        let confidence = if verdict == Verdict::Inconclusive {
            Confidence::Low
        } else {
            confidence
        };
        Assessment {
            verdict,
            confidence,
        }
    }

    fn verdict(&self) -> Verdict {
        if self.len == 0 {
            return Verdict::Empty;
        }
        if self.printable_ratio.unwrap_or(0.0) >= TEXT_PRINTABLE_RATIO {
            return Verdict::Text;
        }
        if self.len < MIN_STATISTICAL_SAMPLE {
            return if self.shannon < LOW_ENTROPY_THRESHOLD {
                Verdict::Repetitive
            } else {
                Verdict::Inconclusive
            };
        }
        if self.looks_random() {
            return Verdict::RandomLike;
        }
        if self.shannon >= HIGH_ENTROPY_THRESHOLD {
            Verdict::HighEntropy
        } else if self.shannon < LOW_ENTROPY_THRESHOLD {
            Verdict::Repetitive
        } else {
            Verdict::Binary
        }
    }

    fn looks_random(&self) -> bool {
        let uniform = self
            .chi_square_p_value
            .is_some_and(|p| p >= CHI_SQUARE_ALPHA);
        // Serial correlation of random data has a standard deviation of
        // about 1/sqrt(n); allow four of those, and never less than 0.05.
        let limit = (4.0 / math::sqrt(to_f64(self.len))).max(0.05);
        let uncorrelated = self.serial_correlation.is_some_and(|r| r.abs() <= limit);
        uniform && uncorrelated
    }
}

/// What the data most likely is, judged from order-0 statistics.
///
/// [`Analysis::assess`] applies these rules in order:
///
/// 1. No bytes → [`Empty`](Self::Empty).
/// 2. At least 95% printable ASCII → [`Text`](Self::Text).
/// 3. Fewer than [`MIN_STATISTICAL_SAMPLE`] bytes → [`Repetitive`](Self::Repetitive)
///    if Shannon entropy is below 3.0, otherwise [`Inconclusive`](Self::Inconclusive).
/// 4. Chi-square p-value ≥ 0.001 and serial correlation near zero →
///    [`RandomLike`](Self::RandomLike).
/// 5. Shannon entropy ≥ 7.0 → [`HighEntropy`](Self::HighEntropy).
/// 6. Shannon entropy < 3.0 → [`Repetitive`](Self::Repetitive).
/// 7. Otherwise → [`Binary`](Self::Binary).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Verdict {
    /// No data.
    Empty,
    /// Mostly printable ASCII: prose, source code, markup, base64, hex.
    Text,
    /// Low entropy: padding, zero-filled regions, sparse tables, long runs.
    Repetitive,
    /// Medium entropy, not text: machine code, structured binary formats,
    /// non-ASCII text, mixed content.
    Binary,
    /// High entropy but measurably non-uniform. Typical of compressed data
    /// and media; also counters and lookup tables.
    HighEntropy,
    /// Statistically indistinguishable from uniform random bytes at this
    /// sample size: encrypted, random, or (especially for small inputs)
    /// compressed data.
    RandomLike,
    /// Too little data to say anything useful.
    Inconclusive,
}

impl Verdict {
    /// Short machine-friendly label, e.g. `"random-like"`.
    ///
    /// # Examples
    ///
    /// ```rust
    /// assert_eq!(rune_entropy::Verdict::HighEntropy.as_str(), "high-entropy");
    /// ```
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Empty => "empty",
            Self::Text => "text",
            Self::Repetitive => "repetitive",
            Self::Binary => "binary",
            Self::HighEntropy => "high-entropy",
            Self::RandomLike => "random-like",
            Self::Inconclusive => "inconclusive",
        }
    }
}

impl fmt::Display for Verdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// How much weight a [`Verdict`] can bear, based mostly on sample size.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Confidence {
    /// Under [`MIN_STATISTICAL_SAMPLE`] bytes, or an inconclusive verdict.
    Low,
    /// Under 4 KiB: the statistics are noisy.
    Medium,
    /// 4 KiB or more (or empty input, which is certain).
    High,
}

impl Confidence {
    /// Lowercase label, e.g. `"medium"`.
    ///
    /// # Examples
    ///
    /// ```rust
    /// assert_eq!(rune_entropy::Confidence::Low.as_str(), "low");
    /// ```
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
        }
    }
}

impl fmt::Display for Confidence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A [`Verdict`] together with its [`Confidence`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Assessment {
    /// What the data most likely is.
    pub verdict: Verdict,
    /// How far to trust the verdict.
    pub confidence: Confidence,
}

impl fmt::Display for Assessment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({} confidence)", self.verdict, self.confidence)
    }
}
