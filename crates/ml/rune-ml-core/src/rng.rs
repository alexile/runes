//! Deterministic pseudo-random numbers: [`SplitMix64`] and [`Rng`]
//! (xoshiro256++).
//!
//! Both are fast, non-cryptographic, and fully reproducible from a `u64`
//! seed on every platform, so a fitted model is a pure function of its
//! input and seed. Do not use them for secrets.

use crate::{Float, MlError};

/// `SplitMix64` (Steele, Lea & Flood 2014): a tiny generator used to expand a
/// single `u64` seed into well-mixed state for [`Rng`].
///
/// ```
/// use rune_ml_core::SplitMix64;
///
/// let mut sm = SplitMix64::new(0);
/// assert_eq!(sm.next_u64(), 0xe220_a839_7b1d_cdaf);
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SplitMix64 {
    state: u64,
}

impl SplitMix64 {
    /// Creates a generator from any seed (zero is fine).
    #[must_use]
    pub const fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    /// Next 64 random bits.
    #[inline]
    pub const fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }
}

/// The shared ML random number generator: xoshiro256++ (Blackman & Vigna
/// 2019), seeded through [`SplitMix64`].
///
/// 256 bits of state, period 2²⁵⁶ − 1, passes `BigCrush`. [`jump`](Self::jump)
/// and [`fork`](Self::fork) derive independent streams for parallel work.
///
/// ```
/// use rune_ml_core::Rng;
///
/// let mut a = Rng::new(42);
/// let mut b = Rng::new(42);
/// assert_eq!(a.next_u64(), b.next_u64()); // same seed, same stream
///
/// let x: f64 = a.uniform();
/// assert!((0.0..1.0).contains(&x));
/// assert!(a.below(10) < 10);
///
/// let mut v = [1, 2, 3, 4, 5];
/// a.shuffle(&mut v);
/// v.sort_unstable();
/// assert_eq!(v, [1, 2, 3, 4, 5]);
/// ```
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Rng {
    s: [u64; 4],
    /// Second Box–Muller sample, returned by the next `normal` call.
    spare: Option<f64>,
}

impl Rng {
    /// Seeds the generator from a `u64` (every seed, including zero, is valid).
    #[must_use]
    pub const fn new(seed: u64) -> Self {
        let mut sm = SplitMix64::new(seed);
        // SplitMix64 is a bijection over distinct states, so at most one of
        // these four outputs is zero: the state is never all-zero.
        let s = [sm.next_u64(), sm.next_u64(), sm.next_u64(), sm.next_u64()];
        Self { s, spare: None }
    }

    /// Restores a generator from raw xoshiro256 state.
    ///
    /// Rejects the all-zero state, which is a fixed point.
    pub fn from_state(s: [u64; 4]) -> Result<Self, MlError> {
        if s == [0; 4] {
            return Err(MlError::invalid_parameter(
                "state",
                "xoshiro256 state must not be all zero",
            ));
        }
        Ok(Self { s, spare: None })
    }

    /// The raw xoshiro256 state (for checkpointing).
    #[must_use]
    pub const fn state(&self) -> [u64; 4] {
        self.s
    }

    /// Next 64 random bits.
    #[inline]
    pub const fn next_u64(&mut self) -> u64 {
        let s = &mut self.s;
        let result = s[0].wrapping_add(s[3]).rotate_left(23).wrapping_add(s[0]);
        let t = s[1] << 17;
        s[2] ^= s[0];
        s[3] ^= s[1];
        s[1] ^= s[2];
        s[0] ^= s[3];
        s[2] ^= t;
        s[3] = s[3].rotate_left(45);
        result
    }

    /// Next 32 random bits (the high half of [`next_u64`](Self::next_u64)).
    #[inline]
    #[allow(clippy::cast_possible_truncation, reason = "keeps the high 32 bits")]
    pub const fn next_u32(&mut self) -> u32 {
        (self.next_u64() >> 32) as u32
    }

    /// Uniform `f64` in `[0, 1)` with 53 random bits.
    #[inline]
    #[allow(
        clippy::cast_precision_loss,
        reason = "the value has 53 bits, exact in f64"
    )]
    pub fn next_f64(&mut self) -> f64 {
        (self.next_u64() >> 11) as f64 * (1.0 / (1u64 << 53) as f64)
    }

    /// Uniform `f32` in `[0, 1)` with 24 random bits.
    #[inline]
    #[allow(
        clippy::cast_precision_loss,
        reason = "the value has 24 bits, exact in f32"
    )]
    pub fn next_f32(&mut self) -> f32 {
        (self.next_u64() >> 40) as f32 * (1.0 / (1u32 << 24) as f32)
    }

    /// Uniform float in `[0, 1)` in the precision of `F`.
    #[inline]
    pub fn uniform<F: Float>(&mut self) -> F {
        if core::mem::size_of::<F>() == 4 {
            F::from_f64(f64::from(self.next_f32()))
        } else {
            F::from_f64(self.next_f64())
        }
    }

    /// Uniform float in `[lo, hi)` (or `[hi, lo)` if reversed).
    #[inline]
    pub fn uniform_range<F: Float>(&mut self, lo: F, hi: F) -> F {
        lo + (hi - lo) * self.uniform::<F>()
    }

    /// Unbiased uniform integer in `[0, n)`; returns `0` when `n == 0`.
    ///
    /// Uses Lemire's multiply-and-reject method: no modulo bias and usually
    /// no division.
    #[inline]
    #[allow(
        clippy::cast_possible_truncation,
        reason = "takes the high/low 64-bit halves"
    )]
    pub const fn below(&mut self, n: u64) -> u64 {
        if n == 0 {
            return 0;
        }
        let mut m = (self.next_u64() as u128) * (n as u128);
        if (m as u64) < n {
            let threshold = n.wrapping_neg() % n;
            while (m as u64) < threshold {
                m = (self.next_u64() as u128) * (n as u128);
            }
        }
        (m >> 64) as u64
    }

    /// Unbiased uniform index in `[0, n)`; returns `0` when `n == 0`.
    #[inline]
    #[allow(
        clippy::cast_possible_truncation,
        reason = "the result is below `n`, which came from a usize"
    )]
    pub const fn index(&mut self, n: usize) -> usize {
        self.below(n as u64) as usize
    }

    /// `true` with probability `p` (clamped to `[0, 1]`).
    #[inline]
    pub fn bernoulli(&mut self, p: f64) -> bool {
        self.next_f64() < p
    }

    /// Standard normal sample `N(0, 1)` (Box–Muller; caches the pair).
    pub fn normal(&mut self) -> f64 {
        if let Some(z) = self.spare.take() {
            return z;
        }
        // u1 in (0, 1] so ln(u1) is finite.
        let u1 = 1.0 - self.next_f64();
        let u2 = self.next_f64();
        let r = (-2.0 * u1.ln()).sqrt();
        let (s, c) = (core::f64::consts::TAU * u2).sin_cos();
        self.spare = Some(r * s);
        r * c
    }

    /// Normal sample `N(mean, std²)` in the precision of `F`.
    pub fn normal_with<F: Float>(&mut self, mean: F, std: F) -> F {
        mean + std * F::from_f64(self.normal())
    }

    /// Shuffles a slice in place (Fisher–Yates).
    pub fn shuffle<T>(&mut self, items: &mut [T]) {
        for i in (1..items.len()).rev() {
            let j = self.index(i + 1);
            items.swap(i, j);
        }
    }

    /// A uniformly chosen element, or `None` for an empty slice.
    pub fn choose<'a, T>(&mut self, items: &'a [T]) -> Option<&'a T> {
        if items.is_empty() {
            None
        } else {
            items.get(self.index(items.len()))
        }
    }

    /// `k` distinct indices from `0..n`, uniformly, in random order
    /// (`k` is clamped to `n`). Partial Fisher–Yates: `O(n)` memory.
    pub fn sample_indices(&mut self, n: usize, k: usize) -> Vec<usize> {
        let k = k.min(n);
        let mut pool: Vec<usize> = (0..n).collect();
        for i in 0..k {
            let j = i + self.index(n - i);
            pool.swap(i, j);
        }
        pool.truncate(k);
        pool
    }

    /// Index drawn with probability proportional to `weights[i]`.
    ///
    /// Negative and non-finite weights count as zero. Returns `None` if no
    /// weight is positive. Used e.g. by k-means++ seeding.
    pub fn weighted_index<F: Float>(&mut self, weights: &[F]) -> Option<usize> {
        let clean = |w: F| {
            if w.is_finite() && w > F::ZERO {
                w.to_f64()
            } else {
                0.0
            }
        };
        let total: f64 = weights.iter().map(|&w| clean(w)).sum();
        if total <= 0.0 || !total.is_finite() {
            return None;
        }
        let target = self.next_f64() * total;
        let mut acc = 0.0;
        let mut last = None;
        for (i, &w) in weights.iter().enumerate() {
            let w = clean(w);
            if w > 0.0 {
                acc += w;
                last = Some(i);
                if target < acc {
                    return Some(i);
                }
            }
        }
        // Rounding can leave `target` just above the final sum.
        last
    }

    /// Advances the state by 2¹²⁸ steps: calling `jump` repeatedly yields
    /// non-overlapping sub-streams for up to 2¹²⁸ parallel workers.
    pub const fn jump(&mut self) {
        const JUMP: [u64; 4] = [
            0x180e_c6d3_3cfd_0aba,
            0xd5a6_1266_f0c9_392c,
            0xa958_2618_e03f_c9aa,
            0x39ab_dc45_29b1_661c,
        ];
        let mut acc = [0u64; 4];
        let mut w = 0;
        while w < 4 {
            let mut b = 0;
            while b < 64 {
                if JUMP[w] & (1u64 << b) != 0 {
                    acc[0] ^= self.s[0];
                    acc[1] ^= self.s[1];
                    acc[2] ^= self.s[2];
                    acc[3] ^= self.s[3];
                }
                self.next_u64();
                b += 1;
            }
            w += 1;
        }
        self.s = acc;
        self.spare = None;
    }

    /// A new generator seeded from this one's output: cheap independent
    /// streams for per-thread or per-restart use.
    #[must_use]
    pub const fn fork(&mut self) -> Self {
        Self::new(self.next_u64())
    }
}

impl Default for Rng {
    /// Seed `0`. Prefer an explicit seed in library code.
    fn default() -> Self {
        Self::new(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splitmix_known_answers() {
        let mut sm = SplitMix64::new(0);
        assert_eq!(sm.next_u64(), 0xe220_a839_7b1d_cdaf);
        assert_eq!(sm.next_u64(), 0x6e78_9e6a_a1b9_65f4);
        assert_eq!(sm.next_u64(), 0x06c4_5d18_8009_454f);
    }

    #[test]
    fn xoshiro_known_answers() {
        // Reference implementation (prng.di.unimi.it) from state [1, 2, 3, 4].
        let mut r = Rng::from_state([1, 2, 3, 4]).unwrap();
        assert_eq!(r.next_u64(), 41_943_041);
        assert_eq!(r.next_u64(), 0x0380_0067);
        assert_eq!(r.next_u64(), 0x000c_c000_0380_0067);
        assert_eq!(r.next_u64(), 0x000c_c201_9944_00b2);
    }

    #[test]
    fn rejects_zero_state() {
        assert!(Rng::from_state([0; 4]).is_err());
    }

    #[test]
    fn seeding_is_deterministic_and_distinct() {
        let a: Vec<u64> = (0..8)
            .scan(Rng::new(7), |r, _| Some(r.next_u64()))
            .collect();
        let b: Vec<u64> = (0..8)
            .scan(Rng::new(7), |r, _| Some(r.next_u64()))
            .collect();
        let c: Vec<u64> = (0..8)
            .scan(Rng::new(8), |r, _| Some(r.next_u64()))
            .collect();
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn jump_and_fork_diverge() {
        let mut a = Rng::new(1);
        let mut b = a.clone();
        b.jump();
        assert_ne!(a.state(), b.state());
        let mut c = a.clone();
        c.jump();
        assert_eq!(b, c);
        let mut f = a.fork();
        assert_ne!(f.next_u64(), a.next_u64());
    }

    #[test]
    fn below_edge_cases() {
        let mut r = Rng::new(3);
        assert_eq!(r.below(0), 0);
        assert_eq!(r.below(1), 0);
        for _ in 0..1000 {
            assert!(r.below(3) < 3);
            assert!(r.below(u64::MAX) < u64::MAX);
        }
    }

    #[test]
    fn normal_moments() {
        let mut r = Rng::new(11);
        let n = 200_000;
        let xs: Vec<f64> = (0..n).map(|_| r.normal()).collect();
        let mean = xs.iter().sum::<f64>() / f64::from(n);
        let var = xs.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / f64::from(n);
        assert!(mean.abs() < 0.01, "mean {mean}");
        assert!((var - 1.0).abs() < 0.02, "var {var}");
    }

    #[test]
    fn uniform_is_roughly_flat() {
        let mut r = Rng::new(5);
        let mut buckets = [0u32; 10];
        for _ in 0..100_000 {
            buckets[r.index(10)] += 1;
        }
        for b in buckets {
            assert!((9_000..11_000).contains(&b), "{buckets:?}");
        }
        let x: f32 = r.uniform();
        assert!((0.0..1.0).contains(&x));
        let y = r.uniform_range(-2.0_f64, 2.0);
        assert!((-2.0..2.0).contains(&y));
    }

    #[test]
    fn weighted_index_respects_zeros() {
        let mut r = Rng::new(9);
        assert_eq!(r.weighted_index::<f64>(&[]), None);
        assert_eq!(r.weighted_index(&[0.0_f64, -1.0, f64::NAN]), None);
        for _ in 0..100 {
            assert_eq!(r.weighted_index(&[0.0_f64, 2.0, 0.0]), Some(1));
        }
    }

    #[test]
    fn choose_and_sample() {
        let mut r = Rng::new(2);
        assert_eq!(r.choose::<u8>(&[]), None);
        assert_eq!(r.choose(&[4]), Some(&4));
        let mut s = r.sample_indices(10, 4);
        assert_eq!(s.len(), 4);
        s.sort_unstable();
        s.dedup();
        assert_eq!(s.len(), 4);
        assert_eq!(r.sample_indices(3, 10).len(), 3);
    }
}
