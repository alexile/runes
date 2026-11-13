//! Sliding-window entropy profiles and high-entropy region detection.

use alloc::vec::Vec;
use core::fmt;
use core::ops::Range;

use crate::histogram::{shannon_from_counts, to_f64};
use crate::math;

/// Windows up to this size get a precomputed `-p*log2(p)` table, so each
/// window costs 256 lookups instead of up to 256 logarithms.
const TABLE_MAX_WINDOW: usize = 1 << 16;

/// Errors from invalid window or step parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// The window size was zero.
    ZeroWindow,
    /// The step was zero.
    ZeroStep,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroWindow => f.write_str("window size must be greater than zero"),
            Self::ZeroStep => f.write_str("step must be greater than zero"),
        }
    }
}

impl core::error::Error for Error {}

#[cfg(feature = "std")]
impl From<Error> for std::io::Error {
    fn from(error: Error) -> Self {
        Self::new(std::io::ErrorKind::InvalidInput, error)
    }
}

/// Entropy of one window of an [`entropy_profile`].
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Window {
    /// Byte offset where the window starts.
    pub offset: u64,
    /// Window length in bytes. Equal to the configured window size unless
    /// the whole input was shorter than that.
    pub len: usize,
    /// Shannon entropy of the window, in bits per byte.
    pub entropy: f64,
}

impl Window {
    /// Byte range covered by this window.
    ///
    /// # Examples
    ///
    /// ```rust
    /// let w = rune_entropy::Window { offset: 512, len: 256, entropy: 7.1 };
    /// assert_eq!(w.range(), 512..768);
    /// ```
    #[must_use]
    pub const fn range(&self) -> Range<u64> {
        self.offset..self.offset + self.len as u64
    }
}

/// Streaming sliding-window entropy calculator.
///
/// Emits one [`Window`] every `step` bytes once `window` bytes have been
/// seen. Memory use is at most `window` bytes plus a lookup table of up to
/// 512 KiB, however long the input. Windows always have the full configured size, except
/// when the entire input is shorter than one window:
///
/// - windows start at offsets `0, step, 2*step, ...`;
/// - if the last of those doesn't reach the end of the input, [`finish`]
///   adds one more window aligned to the end, so every byte is covered;
/// - an input shorter than `window` yields a single window over all of it.
///
/// [`finish`]: Self::finish
///
/// # Examples
///
/// ```rust
/// use rune_entropy::Profiler;
///
/// let mut profiler = Profiler::new(4, 2)?;
/// let mut windows = Vec::new();
/// profiler.push(b"aaaab", |w| windows.push(w));
/// profiler.push(b"cd", |w| windows.push(w));
/// profiler.finish(|w| windows.push(w));
///
/// let offsets: Vec<u64> = windows.iter().map(|w| w.offset).collect();
/// assert_eq!(offsets, [0, 2, 3]); // the last one is aligned to the end
/// assert_eq!(windows[0].entropy, 0.0);
/// assert_eq!(windows[2].entropy, 2.0); // "abcd"
/// # Ok::<(), rune_entropy::Error>(())
/// ```
#[derive(Debug, Clone)]
pub struct Profiler {
    window: usize,
    step: u64,
    ring: Vec<u8>,
    pos: usize,
    counts: [u64; 256],
    table: Vec<f64>,
    seen: u64,
    next_emit: u64,
    last_offset: Option<u64>,
}

impl Profiler {
    /// Creates a profiler with the given window size and step, in bytes.
    ///
    /// `step` may be smaller than `window` (overlapping windows), equal to
    /// it (adjacent blocks), or larger (sampling).
    ///
    /// # Errors
    ///
    /// Returns [`Error::ZeroWindow`] or [`Error::ZeroStep`] for zero
    /// arguments.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rune_entropy::{Error, Profiler};
    ///
    /// assert!(Profiler::new(1024, 256).is_ok());
    /// assert_eq!(Profiler::new(0, 1).unwrap_err(), Error::ZeroWindow);
    /// ```
    pub const fn new(window: usize, step: usize) -> Result<Self, Error> {
        if window == 0 {
            return Err(Error::ZeroWindow);
        }
        if step == 0 {
            return Err(Error::ZeroStep);
        }
        Ok(Self {
            window,
            step: step as u64,
            ring: Vec::new(),
            pos: 0,
            counts: [0; 256],
            table: Vec::new(),
            seen: 0,
            next_emit: window as u64,
            last_offset: None,
        })
    }

    /// Feeds the next chunk, calling `emit` for every window it completes.
    pub fn push(&mut self, data: &[u8], mut emit: impl FnMut(Window)) {
        for &byte in data {
            if self.ring.len() < self.window {
                // Still filling the first window; the ring grows with the
                // input, so short inputs never allocate a full window.
                self.ring.push(byte);
            } else {
                let old = core::mem::replace(&mut self.ring[self.pos], byte);
                self.counts[usize::from(old)] -= 1;
                self.pos += 1;
                if self.pos == self.window {
                    self.pos = 0;
                }
            }
            self.counts[usize::from(byte)] += 1;
            self.seen += 1;
            if self.seen == self.next_emit {
                self.next_emit = self.next_emit.saturating_add(self.step);
                let offset = self.seen - self.window as u64;
                self.last_offset = Some(offset);
                let entropy = self.current_entropy();
                emit(Window {
                    offset,
                    len: self.window,
                    entropy,
                });
            }
        }
    }

    /// Emits the final window, if any is still owed, and ends the stream.
    pub fn finish(mut self, mut emit: impl FnMut(Window)) {
        if self.seen == 0 {
            return;
        }
        if self.ring.len() < self.window {
            emit(Window {
                offset: 0,
                len: self.ring.len(),
                entropy: shannon_from_counts(&self.counts, self.seen),
            });
            return;
        }
        let tail = self.seen - self.window as u64;
        if self.last_offset != Some(tail) {
            let entropy = self.current_entropy();
            emit(Window {
                offset: tail,
                len: self.window,
                entropy,
            });
        }
    }

    /// Total bytes fed so far.
    #[must_use]
    pub const fn bytes_seen(&self) -> u64 {
        self.seen
    }

    /// Entropy of the current (full) window.
    fn current_entropy(&mut self) -> f64 {
        if self.window > TABLE_MAX_WINDOW {
            return shannon_from_counts(&self.counts, self.window as u64);
        }
        if self.table.is_empty() {
            // Built on the first full window, so its cost (one log per
            // possible count) is never more than the bytes already read.
            let n = to_f64(self.window as u64);
            self.table = (0..=self.window as u64)
                .map(|count| {
                    if count == 0 {
                        0.0
                    } else {
                        let p = to_f64(count) / n;
                        -(p * math::log2(p))
                    }
                })
                .collect();
        }
        let mut bits = 0.0;
        for &count in &self.counts {
            if count != 0 {
                // `count <= window`, the table's last index.
                bits += self.table[usize::try_from(count).unwrap_or(0)];
            }
        }
        bits.clamp(0.0, 8.0)
    }
}

/// Computes a sliding-window entropy profile of `data`.
///
/// See [`Profiler`] for exactly which windows are produced. A typical setup
/// for locating packed or encrypted regions is a 1 KiB window with a 256-byte
/// step.
///
/// # Errors
///
/// Returns an [`Error`] if `window` or `step` is zero.
///
/// # Examples
///
/// ```rust
/// use rune_entropy::entropy_profile;
///
/// let mut data = vec![0u8; 1024];
/// data.extend((0..=255u8).cycle().take(1024));
///
/// let profile = entropy_profile(&data, 512, 512)?;
/// let scores: Vec<f64> = profile.iter().map(|w| w.entropy).collect();
/// assert_eq!(scores, [0.0, 0.0, 8.0, 8.0]);
/// # Ok::<(), rune_entropy::Error>(())
/// ```
pub fn entropy_profile(data: &[u8], window: usize, step: usize) -> Result<Vec<Window>, Error> {
    let mut profiler = Profiler::new(window, step)?;
    let mut out = Vec::with_capacity(data.len().saturating_sub(window) / step + 2);
    profiler.push(data, |w| out.push(w));
    profiler.finish(|w| out.push(w));
    Ok(out)
}

/// A contiguous byte range whose windows all matched a condition.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Region {
    /// First byte of the region.
    pub start: u64,
    /// One past the last byte of the region.
    pub end: u64,
    /// Mean entropy of the windows that make up the region.
    pub mean_entropy: f64,
    /// Highest window entropy in the region.
    pub max_entropy: f64,
}

impl Region {
    /// Region length in bytes.
    ///
    /// # Examples
    ///
    /// ```rust
    /// let r = rune_entropy::Region { start: 10, end: 30, mean_entropy: 7.5, max_entropy: 7.9 };
    /// assert_eq!(r.len(), 20);
    /// ```
    #[must_use]
    pub const fn len(&self) -> u64 {
        self.end - self.start
    }

    /// Returns `true` if the region covers no bytes.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.end == self.start
    }

    /// The byte range `start..end`.
    #[must_use]
    pub const fn range(&self) -> Range<u64> {
        self.start..self.end
    }
}

/// Groups windows that satisfy `predicate` into regions.
///
/// The result is the union of the matching windows: windows that overlap or
/// touch are merged, so regions never overlap and come out sorted by
/// offset. A region spans from the start of its first window to the end of
/// its last, so boundaries are only accurate to about one window. Regions
/// shorter than `min_len` bytes are dropped. `profile` must be sorted by
/// offset, as [`entropy_profile`] and [`Profiler`] produce it.
///
/// # Examples
///
/// Find low-entropy runs (padding, zero fill) instead of high ones:
///
/// ```rust
/// use rune_entropy::{entropy_profile, regions_where};
///
/// let mut data: Vec<u8> = (0..=255u8).cycle().take(2048).collect();
/// data.extend([0u8; 2048]);
///
/// let profile = entropy_profile(&data, 256, 256)?;
/// let low = regions_where(&profile, |e| e < 1.0, 0);
/// assert_eq!(low.len(), 1);
/// assert_eq!(low[0].range(), 2048..4096);
/// # Ok::<(), rune_entropy::Error>(())
/// ```
pub fn regions_where(
    profile: &[Window],
    mut predicate: impl FnMut(f64) -> bool,
    min_len: u64,
) -> Vec<Region> {
    #[derive(Clone, Copy)]
    struct Open {
        start: u64,
        end: u64,
        sum: f64,
        windows: u32,
        max: f64,
    }

    fn close(open: Open, min_len: u64, out: &mut Vec<Region>) {
        if open.end - open.start >= min_len {
            out.push(Region {
                start: open.start,
                end: open.end,
                mean_entropy: open.sum / f64::from(open.windows),
                max_entropy: open.max,
            });
        }
    }

    let mut out = Vec::new();
    let mut current: Option<Open> = None;
    for window in profile {
        let range = window.range();
        if !predicate(window.entropy) {
            continue;
        }
        match current.as_mut() {
            Some(open) if range.start <= open.end => {
                open.end = open.end.max(range.end);
                open.sum += window.entropy;
                open.windows = open.windows.saturating_add(1);
                open.max = open.max.max(window.entropy);
            }
            _ => {
                if let Some(open) = current.take() {
                    close(open, min_len, &mut out);
                }
                current = Some(Open {
                    start: range.start,
                    end: range.end,
                    sum: window.entropy,
                    windows: 1,
                    max: window.entropy,
                });
            }
        }
    }
    if let Some(open) = current {
        close(open, min_len, &mut out);
    }
    out
}

/// Settings for [`high_entropy_regions`].
///
/// The defaults (1 KiB window, 256-byte step, threshold 7.0, minimum
/// length one window) suit executables and firmware images. Smaller windows
/// give sharper boundaries but noisier scores: `n` random bytes only score
/// about [`random_entropy_baseline(n)`](random_entropy_baseline) on average,
/// so lower the threshold along with the window (7.0 is fine down to about
/// 512 bytes; use ~6.5 for 256).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct RegionOptions {
    /// Window size in bytes.
    pub window: usize,
    /// Distance between window starts, in bytes.
    pub step: usize,
    /// Minimum window entropy, in bits per byte.
    pub threshold: f64,
    /// Regions shorter than this many bytes are dropped.
    pub min_len: u64,
}

impl Default for RegionOptions {
    fn default() -> Self {
        Self {
            window: 1024,
            step: 256,
            threshold: 7.0,
            min_len: 1024,
        }
    }
}

/// Finds byte ranges whose sliding-window entropy is at or above a
/// threshold: candidates for packed, compressed, or encrypted content.
///
/// # Errors
///
/// Returns an [`Error`] if the window or step is zero.
///
/// # Examples
///
/// ```rust
/// use rune_entropy::{high_entropy_regions, RegionOptions};
///
/// // 8 KiB of zeros with 4 KiB of pseudo-random bytes in the middle.
/// let mut data = vec![0u8; 8192];
/// let mut x = 0x2545_f491_4f6c_dd1du64;
/// for byte in &mut data[2048..6144] {
///     x ^= x << 13; x ^= x >> 7; x ^= x << 17;
///     *byte = (x >> 32) as u8;
/// }
///
/// let regions = high_entropy_regions(&data, &RegionOptions::default())?;
/// assert_eq!(regions.len(), 1);
/// let found = regions[0].range();
/// assert!(found.start >= 1024 && found.start <= 2048);
/// assert!(found.end >= 6144 && found.end <= 7168);
/// # Ok::<(), rune_entropy::Error>(())
/// ```
pub fn high_entropy_regions(data: &[u8], options: &RegionOptions) -> Result<Vec<Region>, Error> {
    let profile = entropy_profile(data, options.window, options.step)?;
    let threshold = options.threshold;
    Ok(regions_where(&profile, |e| e >= threshold, options.min_len))
}

/// Expected Shannon entropy of `n` uniformly random bytes, in bits per byte.
///
/// Short samples of perfectly random data score below 8.0 because not every
/// byte value gets a fair share: 256 random bytes average about 7.17, 1 KiB
/// about 7.81. Use this to pick thresholds that match your window size.
///
/// Exact (from the binomial distribution) for `n <= 65536`; above that the
/// first-order bias correction `8 - 255 / (2 n ln 2)` is used, which agrees to
/// better than 1e-5.
///
/// # Examples
///
/// ```rust
/// use rune_entropy::random_entropy_baseline;
///
/// assert_eq!(random_entropy_baseline(0), 0.0);
/// assert_eq!(random_entropy_baseline(1), 0.0);
/// assert!((random_entropy_baseline(256) - 7.175).abs() < 0.001);
/// assert!(random_entropy_baseline(1 << 20) > 7.999);
/// ```
#[must_use]
pub fn random_entropy_baseline(n: u64) -> f64 {
    if n <= 1 {
        return 0.0;
    }
    let nf = to_f64(n);
    if n > 1 << 16 {
        return 8.0 - 255.0 / (2.0 * nf * core::f64::consts::LN_2);
    }
    // E[H] = 256 * sum_k P(K = k) * (k/n) * log2(n/k), K ~ Binomial(n, 1/256).
    let mut pmf = math::exp(nf * math::log2(255.0 / 256.0) * core::f64::consts::LN_2);
    let mut expected = 0.0;
    for k in 0..n {
        let kf = to_f64(k);
        pmf *= (nf - kf) / ((kf + 1.0) * 255.0);
        let next = kf + 1.0;
        expected += pmf * (next / nf) * math::log2(nf / next);
        if next > nf / 256.0 && pmf < 1e-18 {
            break;
        }
    }
    (256.0 * expected).clamp(0.0, 8.0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entropy;

    #[test]
    fn profile_windows_match_direct_entropy() {
        let data: Vec<u8> = (0..5000u32).map(|i| (i * i % 251) as u8).collect();
        for (window, step) in [(256, 64), (1000, 1000), (300, 700), (70_000, 1)] {
            let profile = entropy_profile(&data, window, step).unwrap();
            for w in &profile {
                let start = usize::try_from(w.offset).unwrap();
                let direct = entropy(&data[start..start + w.len]);
                assert!((w.entropy - direct).abs() < 1e-12, "{window}/{step}");
            }
            let last = profile.last().unwrap();
            assert_eq!(last.range().end, data.len() as u64);
        }
    }

    #[test]
    fn huge_step_does_not_overflow() {
        let profile = entropy_profile(b"abcdef", 2, usize::MAX).unwrap();
        let offsets: Vec<u64> = profile.iter().map(|w| w.offset).collect();
        assert_eq!(offsets, [0, 4]);
    }

    #[test]
    fn large_window_without_table() {
        let data: Vec<u8> = (0..=255u8).cycle().take(200_000).collect();
        let profile = entropy_profile(&data, 100_096, 50_000).unwrap();
        assert!(profile.iter().all(|w| (w.entropy - 8.0).abs() < 1e-3));
    }

    #[test]
    fn empty_profile() {
        assert_eq!(entropy_profile(&[], 16, 4), Ok(Vec::new()));
        assert_eq!(entropy_profile(&[1], 0, 4), Err(Error::ZeroWindow));
        assert_eq!(entropy_profile(&[1], 4, 0), Err(Error::ZeroStep));
    }

    #[test]
    fn regions_split_on_gaps() {
        let windows = [
            Window {
                offset: 0,
                len: 10,
                entropy: 7.5,
            },
            Window {
                offset: 10,
                len: 10,
                entropy: 7.9,
            },
            Window {
                offset: 20,
                len: 10,
                entropy: 2.0,
            },
            Window {
                offset: 30,
                len: 10,
                entropy: 7.1,
            },
            Window {
                offset: 50,
                len: 10,
                entropy: 7.1,
            },
        ];
        let regions = regions_where(&windows, |e| e >= 7.0, 0);
        assert_eq!(regions.len(), 3);
        assert_eq!(regions[0].range(), 0..20);
        assert!((regions[0].mean_entropy - 7.7).abs() < 1e-12);
        assert_eq!(regions[0].max_entropy, 7.9);
        assert_eq!(regions[1].range(), 30..40);
        assert_eq!(regions[2].range(), 50..60);
        assert_eq!(regions_where(&windows, |e| e >= 7.0, 15).len(), 1);

        // Overlapping windows around a dip still form one region.
        let w = |offset, entropy| Window {
            offset,
            len: 40,
            entropy,
        };
        let merged = regions_where(&[w(0, 7.5), w(10, 5.0), w(20, 7.5)], |e| e >= 7.0, 0);
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].range(), 0..60);
    }

    #[test]
    fn baseline_matches_simulation_scale() {
        // Known values of the expected plug-in entropy of uniform bytes.
        assert!((random_entropy_baseline(2) - 255.0 / 256.0).abs() < 1e-12);
        // Reference values from the exact binomial sum.
        assert!((random_entropy_baseline(256) - 7.174_966_35).abs() < 1e-6);
        assert!((random_entropy_baseline(512) - 7.590_437_68).abs() < 1e-6);
        assert!((random_entropy_baseline(1024) - 7.808_756_57).abs() < 1e-6);
        let below = random_entropy_baseline(1 << 16);
        let above = random_entropy_baseline((1 << 16) + 1);
        assert!((below - above).abs() < 1e-5, "{below} vs {above}");
    }
}
