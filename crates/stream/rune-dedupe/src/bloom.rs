//! Approximate mode: a time-partitioned Bloom filter with rotating generations.

use std::collections::VecDeque;
use std::time::Duration;

use crate::error::ConfigError;
use crate::time::Timestamp;

/// Largest filter accepted per generation: 2^34 bits (2 GiB).
const MAX_BITS: u64 = 1 << 34;

/// Settings for [`Mode::Approximate`](crate::Mode::Approximate).
///
/// The window is split into `generations - 1` equal spans. Each span gets its
/// own Bloom filter sized for `expected_keys / (generations - 1)` keys. A check
/// asks every live filter; a new key goes into the newest one. Filters whose
/// newest key is older than the window are dropped whole, so memory is fixed at
/// `generations + 1` filters no matter how long the stream runs.
///
/// # False-positive rate
///
/// Each filter is built for `false_positive_rate / (generations + 1)`, so by the
/// union bound a key never seen is reported as a duplicate with probability at
/// most `false_positive_rate`, as long as no more than `expected_keys` distinct
/// keys arrive per window. Measured rates are usually well under the target
/// because most generations are only partly full.
///
/// # What else differs from exact mode
///
/// - No false negatives within the window: a key accepted at `t` is reported as
///   a duplicate up to `t + window`, as long as the generation holding it was
///   not dropped early (see below).
/// - Keys may be remembered for up to one extra span past the window, because a
///   generation is dropped only once its *newest* key has expired.
/// - If more than `expected_keys / (generations - 1)` keys arrive within one
///   span, a new generation starts early. If that would exceed `generations + 1`
///   filters, the oldest is dropped (reported as a
///   [`Capacity`](crate::EvictionReason::Capacity) eviction) and its keys can be
///   accepted again inside their window.
///
/// # Example
///
/// ```rust
/// use rune_dedupe::ApproxConfig;
///
/// let cfg = ApproxConfig::new(1_000_000, 0.001).generations(4);
/// // About 2.3 MiB per generation, five generations.
/// assert!(cfg.memory_bytes().unwrap() < 13 << 20);
/// ```
#[derive(Debug, Clone, Copy, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ApproxConfig {
    expected_keys: usize,
    false_positive_rate: f64,
    generations: u32,
}

impl ApproxConfig {
    /// Default number of generations the window is split into.
    pub const DEFAULT_GENERATIONS: u32 = 4;

    /// Sized for `expected_keys` distinct keys per window, with an overall
    /// false-positive rate of at most `false_positive_rate` (in `(0, 1)`).
    #[must_use]
    pub const fn new(expected_keys: usize, false_positive_rate: f64) -> Self {
        Self {
            expected_keys,
            false_positive_rate,
            generations: Self::DEFAULT_GENERATIONS,
        }
    }

    /// Splits the window into `generations - 1` spans (at least 2). More
    /// generations means less overshoot past the window but more filters to
    /// probe per check.
    #[must_use]
    pub const fn generations(mut self, generations: u32) -> Self {
        self.generations = generations;
        self
    }

    /// Expected distinct keys per window.
    #[must_use]
    pub const fn expected_keys(&self) -> usize {
        self.expected_keys
    }

    /// Target overall false-positive rate.
    #[must_use]
    pub const fn false_positive_rate(&self) -> f64 {
        self.false_positive_rate
    }

    /// Total filter memory in bytes once every generation is allocated.
    ///
    /// # Errors
    ///
    /// The same [`ConfigError`]s as building a deduplicator with this config.
    pub fn memory_bytes(&self) -> Result<usize, ConfigError> {
        let p = self.params()?;
        let bytes = p.words.saturating_mul(8).saturating_mul(p.max_generations);
        Ok(bytes)
    }

    pub(crate) fn params(&self) -> Result<Params, ConfigError> {
        if self.expected_keys == 0 {
            return Err(ConfigError::ZeroExpectedKeys);
        }
        let p = self.false_positive_rate;
        if !(p > 0.0 && p < 1.0) {
            return Err(ConfigError::InvalidFalsePositiveRate);
        }
        if self.generations < 2 {
            return Err(ConfigError::TooFewGenerations);
        }
        let spans = (self.generations - 1) as usize;
        let max_generations = self.generations as usize + 1;
        let per_gen = self.expected_keys.div_ceil(spans).max(1);
        #[allow(clippy::cast_precision_loss)] // small count
        let p_gen = p / max_generations as f64;
        #[allow(clippy::cast_precision_loss)] // sizing only needs an estimate
        let n = per_gen as f64;
        let ln2 = std::f64::consts::LN_2;
        let bits = (-n * p_gen.ln() / (ln2 * ln2)).ceil();
        #[allow(clippy::cast_precision_loss)] // 2^34 is exact in f64
        let max_bits = MAX_BITS as f64;
        if !bits.is_finite() || bits > max_bits {
            return Err(ConfigError::FilterTooLarge);
        }
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        // finite, in (0, MAX_BITS]
        let bits = (bits as u64).max(64).next_multiple_of(64);
        #[allow(clippy::cast_precision_loss)]
        let k = (bits as f64 / n * ln2).round().clamp(1.0, 32.0);
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)] // clamped to 1..=32
        let hashes = k as u32;
        #[allow(clippy::cast_possible_truncation)] // bits <= 2^34 fits usize on 64-bit
        let words = (bits / 64) as usize;
        Ok(Params {
            words,
            hashes,
            per_gen,
            spans: self.generations - 1,
            max_generations,
        })
    }
}

/// Filter geometry derived from an [`ApproxConfig`].
#[derive(Debug, Clone, Copy)]
pub struct Params {
    words: usize,
    hashes: u32,
    per_gen: usize,
    spans: u32,
    max_generations: usize,
}

/// One Bloom filter covering one span of time.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Generation<T> {
    bits: Vec<u64>,
    count: usize,
    start: T,
    newest: T,
}

impl<T> Generation<T> {
    fn probe(h: u64, hashes: u32, bits: u64) -> impl Iterator<Item = (usize, u64)> {
        // Kirsch-Mitzenmacher double hashing: h1 + i*h2 with an odd h2.
        let h2 = splitmix64(h) | 1;
        (0..u64::from(hashes)).map(move |i| {
            let bit = h.wrapping_add(i.wrapping_mul(h2)) % bits;
            #[allow(clippy::cast_possible_truncation)] // bit / 64 < words
            let word = (bit / 64) as usize;
            (word, 1 << (bit % 64))
        })
    }

    fn contains(&self, h: u64, hashes: u32) -> bool {
        let bits = self.bits.len() as u64 * 64;
        Self::probe(h, hashes, bits).all(|(w, m)| self.bits.get(w).is_some_and(|x| x & m != 0))
    }

    fn insert(&mut self, h: u64, hashes: u32) {
        let bits = self.bits.len() as u64 * 64;
        for (w, m) in Self::probe(h, hashes, bits) {
            if let Some(x) = self.bits.get_mut(w) {
                *x |= m;
            }
        }
        self.count += 1;
    }
}

const fn splitmix64(mut z: u64) -> u64 {
    z = z.wrapping_add(0x9e37_79b9_7f4a_7c15);
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^ (z >> 31)
}

/// The rotating set of generations.
#[derive(Debug, Clone)]
pub struct Generations<T> {
    params: Params,
    span: Duration,
    gens: VecDeque<Generation<T>>,
}

/// What one approximate check found and dropped.
pub struct Outcome {
    pub duplicate: bool,
    pub expired: u64,
    pub capacity: u64,
}

impl<T: Timestamp> Generations<T> {
    pub fn new(params: Params, window: Duration) -> Self {
        Self {
            params,
            span: window / params.spans,
            gens: VecDeque::new(),
        }
    }

    /// Distinct keys recorded across live generations.
    pub fn len(&self) -> usize {
        self.gens.iter().map(|g| g.count).sum()
    }

    /// Whether a live generation reports `h`, without changing anything.
    pub fn contains(&self, h: u64, now: T, window: Duration) -> bool {
        self.gens
            .iter()
            .any(|g| now.saturating_since(g.newest) <= window && g.contains(h, self.params.hashes))
    }

    pub fn check(&mut self, h: u64, now: T, window: Duration) -> Outcome {
        let mut expired = 0;
        while let Some(front) = self.gens.front() {
            if now.saturating_since(front.newest) <= window {
                break;
            }
            expired += front.count as u64;
            self.gens.pop_front();
        }
        let hashes = self.params.hashes;
        if self.gens.iter().any(|g| g.contains(h, hashes)) {
            return Outcome {
                duplicate: true,
                expired,
                capacity: 0,
            };
        }
        let mut capacity = 0;
        let rotate = self.gens.back().is_none_or(|g| {
            g.count >= self.params.per_gen || now.saturating_since(g.start) > self.span
        });
        if rotate {
            if self.gens.len() >= self.params.max_generations
                && let Some(old) = self.gens.pop_front()
            {
                capacity += old.count as u64;
            }
            self.gens.push_back(Generation {
                bits: vec![0; self.params.words],
                count: 0,
                start: now,
                newest: now,
            });
        }
        if let Some(g) = self.gens.back_mut() {
            g.insert(h, hashes);
            g.newest = g.newest.max(now);
        }
        Outcome {
            duplicate: false,
            expired,
            capacity,
        }
    }

    pub fn to_vec(&self) -> Vec<Generation<T>>
    where
        T: Clone,
    {
        self.gens.iter().cloned().collect()
    }

    /// Rebuilds from a snapshot, checking every filter has the expected size.
    pub fn from_vec(params: Params, window: Duration, gens: Vec<Generation<T>>) -> Option<Self> {
        if gens.len() > params.max_generations || gens.iter().any(|g| g.bits.len() != params.words)
        {
            return None;
        }
        let mut out = Self::new(params, window);
        out.gens = gens.into();
        Some(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_bad_configs() {
        assert_eq!(
            ApproxConfig::new(0, 0.01).params().err(),
            Some(ConfigError::ZeroExpectedKeys)
        );
        for p in [0.0, 1.0, -0.5, f64::NAN] {
            assert_eq!(
                ApproxConfig::new(10, p).params().err(),
                Some(ConfigError::InvalidFalsePositiveRate)
            );
        }
        assert_eq!(
            ApproxConfig::new(10, 0.01).generations(1).params().err(),
            Some(ConfigError::TooFewGenerations)
        );
        assert_eq!(
            ApproxConfig::new(usize::MAX, 1e-12).params().err(),
            Some(ConfigError::FilterTooLarge)
        );
    }

    #[test]
    fn sizing_matches_textbook_formula() {
        // 1000 keys per span at p = 0.01 / 5 = 0.002 needs ~12.9 bits per key.
        let p = ApproxConfig::new(3000, 0.01).params().unwrap();
        assert_eq!(p.per_gen, 1000);
        assert_eq!(p.max_generations, 5);
        assert_eq!(p.words * 64, 12_992);
        assert_eq!(p.hashes, 9);
    }

    #[test]
    fn generations_roll_and_expire() {
        let params = ApproxConfig::new(30, 0.01).params().unwrap();
        let window = Duration::from_millis(30);
        let mut g = Generations::new(params, window);
        assert!(!g.check(1, 0_u64, window).duplicate);
        assert!(g.check(1, 30_u64, window).duplicate);
        assert!(!g.check(2, 20_u64, window).duplicate);
        assert_eq!(g.gens.len(), 2);
        // At 31 the first generation (newest = 0) expires; key 2 is still there.
        let out = g.check(2, 31_u64, window);
        assert!(out.duplicate);
        assert_eq!(out.expired, 1);
        assert!(!g.check(1, 31_u64, window).duplicate);
    }
}
