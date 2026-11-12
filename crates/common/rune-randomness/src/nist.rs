//! The NIST SP 800-22 Rev. 1a tests that suit short samples.
//!
//! Each function implements one section of the specification and follows
//! the NIST reference implementation (`sts-2.1.2`) where the text leaves
//! room for interpretation, so the published example p-values are
//! reproduced.

use std::f64::consts::{LN_2, SQRT_2};

use rune_stats::dist::{erfc, gamma_q, normal_cdf};

use crate::bits::count_ones;
use crate::{Error, Test, TestOutcome};

/// Largest pattern length accepted by [`serial`] and
/// [`approximate_entropy`] (their counts table has `2^(m+1)` entries).
pub const MAX_PATTERN_LENGTH: usize = 20;

/// `n as f64`. Bit counts are far below 2⁵³, so this is exact.
#[allow(clippy::cast_precision_loss, reason = "bit counts are far below 2^53")]
pub(crate) const fn to_f64(n: usize) -> f64 {
    n as f64
}

const fn require(test: Test, bits: &[bool], needed: usize) -> Result<(), Error> {
    if bits.len() < needed {
        return Err(Error::TooShort {
            test,
            needed,
            got: bits.len(),
        });
    }
    Ok(())
}

/// Frequency (monobit) test, SP 800-22 §2.1.
///
/// Checks that ones and zeros are about equally common. The statistic is
/// `s_obs = |Σ(2εᵢ − 1)| / √n` and the p-value `erfc(s_obs / √2)`. NIST
/// recommends `n ≥ 100`.
///
/// # Errors
///
/// [`Error::TooShort`] for an empty sequence.
///
/// ```
/// use rune_randomness::{Bits, nist};
///
/// // SP 800-22 §2.1.4.
/// let outcome = nist::frequency(&Bits::parse("1011010101")?)?;
/// assert!((outcome.p_value - 0.527_089).abs() < 1e-6);
/// # Ok::<(), rune_randomness::Error>(())
/// ```
pub fn frequency(bits: &[bool]) -> Result<TestOutcome, Error> {
    require(Test::Frequency, bits, 1)?;
    let n = to_f64(bits.len());
    let ones = to_f64(count_ones(bits));
    let s_obs = (2.0f64.mul_add(ones, -n)).abs() / n.sqrt();
    Ok(TestOutcome::new(
        Test::Frequency,
        s_obs,
        erfc(s_obs / SQRT_2),
    ))
}

/// Frequency test within a block, SP 800-22 §2.2.
///
/// Splits the sequence into `N = ⌊n / M⌋` blocks of `block_length` (`M`)
/// bits, discarding the rest, and checks the proportion of ones in each.
/// `χ² = 4M Σ(πᵢ − ½)²` and the p-value is `igamc(N/2, χ²/2)`. NIST
/// recommends `n ≥ 100`, `M ≥ 20`, `M > 0.01 n` and `N < 100`.
///
/// # Errors
///
/// [`Error::InvalidParameter`] for `block_length = 0`, and
/// [`Error::TooShort`] when the sequence does not fill one block.
pub fn block_frequency(bits: &[bool], block_length: usize) -> Result<TestOutcome, Error> {
    if block_length == 0 {
        return Err(Error::InvalidParameter {
            name: "block_length",
            reason: "must be at least 1",
        });
    }
    require(Test::BlockFrequency, bits, block_length)?;
    let m = to_f64(block_length);
    let mut blocks = 0usize;
    let mut chi_squared = 0.0;
    for block in bits.chunks_exact(block_length) {
        // 4M(ones/M − ½)² = (2·ones − M)² / M, computed exactly.
        let excess = 2.0f64.mul_add(to_f64(count_ones(block)), -m);
        chi_squared += excess * excess / m;
        blocks += 1;
    }
    let p_value = gamma_q(to_f64(blocks) / 2.0, chi_squared / 2.0);
    Ok(TestOutcome::new(Test::BlockFrequency, chi_squared, p_value))
}

/// Runs test, SP 800-22 §2.3.
///
/// Checks that runs of identical bits have the length expected of a random
/// sequence. The statistic is the number of runs `V_n(obs)`. As the
/// specification prescribes, a sequence that fails the frequency
/// prerequisite `|π − ½| < 2/√n` gets a p-value of `0` without computing
/// the runs. NIST recommends `n ≥ 100`.
///
/// # Errors
///
/// [`Error::TooShort`] for an empty sequence.
pub fn runs(bits: &[bool]) -> Result<TestOutcome, Error> {
    require(Test::Runs, bits, 1)?;
    let n = to_f64(bits.len());
    let pi = to_f64(count_ones(bits)) / n;
    let changes = bits.windows(2).filter(|pair| pair[0] != pair[1]).count();
    let v_obs = to_f64(changes + 1);
    let spread = pi * (1.0 - pi);
    if (pi - 0.5).abs() >= 2.0 / n.sqrt() || spread == 0.0 {
        return Ok(TestOutcome::new(Test::Runs, v_obs, 0.0));
    }
    let p_value = erfc((2.0 * n).mul_add(-spread, v_obs).abs() / (2.0 * (2.0 * n).sqrt() * spread));
    Ok(TestOutcome::new(Test::Runs, v_obs, p_value))
}

/// Category bounds and probabilities of the longest-run test for one block
/// length (SP 800-22 §3.4; the values used by `sts-2.1.2`).
struct LongestRunTable {
    block_length: usize,
    shortest: usize,
    probabilities: &'static [f64],
}

const LONGEST_RUN_TABLES: [LongestRunTable; 3] = [
    LongestRunTable {
        block_length: 10_000,
        shortest: 10,
        probabilities: &[0.0882, 0.2092, 0.2483, 0.1933, 0.1208, 0.0675, 0.0727],
    },
    LongestRunTable {
        block_length: 128,
        shortest: 4,
        probabilities: &[
            0.117_403_578_8,
            0.242_955_959,
            0.249_363_483,
            0.175_177_06,
            0.102_701_071,
            0.112_398_847,
        ],
    },
    LongestRunTable {
        block_length: 8,
        shortest: 1,
        probabilities: &[0.214_843_75, 0.367_187_5, 0.230_468_75, 0.1875],
    },
];

/// Smallest sequence the longest-run test accepts.
pub const LONGEST_RUN_MIN_BITS: usize = 128;

/// Test for the longest run of ones in a block, SP 800-22 §2.4.
///
/// The block length follows the specification's table: `M = 8` from 128
/// bits, `M = 128` from 6 272 bits and `M = 10 000` from 750 000 bits. The
/// longest run of ones in each of the `⌊n / M⌋` blocks is binned into
/// `K + 1` categories and compared with the theoretical distribution; the
/// p-value is `igamc(K/2, χ²/2)`.
///
/// # Errors
///
/// [`Error::TooShort`] for fewer than 128 bits.
pub fn longest_run_of_ones(bits: &[bool]) -> Result<TestOutcome, Error> {
    require(Test::LongestRunOfOnes, bits, LONGEST_RUN_MIN_BITS)?;
    let n = bits.len();
    let table = if n >= 750_000 {
        &LONGEST_RUN_TABLES[0]
    } else if n >= 6_272 {
        &LONGEST_RUN_TABLES[1]
    } else {
        &LONGEST_RUN_TABLES[2]
    };
    let categories = table.probabilities.len();
    let longest_category = categories - 1;
    let mut counts = vec![0usize; categories];
    let mut blocks = 0usize;
    for block in bits.chunks_exact(table.block_length) {
        let category = longest_run(block)
            .saturating_sub(table.shortest)
            .min(longest_category);
        counts[category] += 1;
        blocks += 1;
    }
    let blocks = to_f64(blocks);
    let chi_squared: f64 = counts
        .iter()
        .zip(table.probabilities)
        .map(|(&count, &probability)| {
            let expected = blocks * probability;
            let diff = to_f64(count) - expected;
            diff * diff / expected
        })
        .sum();
    let p_value = gamma_q(to_f64(longest_category) / 2.0, chi_squared / 2.0);
    Ok(TestOutcome::new(
        Test::LongestRunOfOnes,
        chi_squared,
        p_value,
    ))
}

/// Length of the longest run of `true` in `bits`.
pub(crate) fn longest_run(bits: &[bool]) -> usize {
    let mut longest = 0;
    let mut current = 0;
    for &bit in bits {
        if bit {
            current += 1;
            longest = longest.max(current);
        } else {
            current = 0;
        }
    }
    longest
}

/// Counts of every overlapping `length`-bit pattern, reading the sequence
/// cyclically (the first `length − 1` bits are appended to the end), as in
/// SP 800-22 §2.11 and §2.12.
/// Requires `length ≤ MAX_PATTERN_LENGTH` and a non-empty sequence.
fn pattern_counts(bits: &[bool], length: usize) -> Vec<u32> {
    let mut counts = vec![0u32; 1 << length];
    if length == 0 {
        counts[0] = u32::try_from(bits.len()).unwrap_or(u32::MAX);
        return counts;
    }
    let n = bits.len();
    let mask = (1usize << length) - 1;
    let mut window = 0usize;
    for i in 0..length - 1 {
        window = (window << 1) | usize::from(bits[i % n]);
    }
    for i in 0..n {
        window = ((window << 1) | usize::from(bits[(i + length - 1) % n])) & mask;
        counts[window] = counts[window].saturating_add(1);
    }
    counts
}

const fn invalid_m(reason: &'static str) -> Error {
    Error::InvalidParameter { name: "m", reason }
}

/// Sequences longer than this are rejected by the overlapping-pattern
/// tests, whose counters are 32-bit.
const MAX_PATTERN_BITS: usize = u32::MAX as usize;

fn check_pattern_input(test: Test, bits: &[bool]) -> Result<(), Error> {
    require(test, bits, 1)?;
    if bits.len() > MAX_PATTERN_BITS {
        return Err(Error::InvalidParameter {
            name: "bits",
            reason: "longer than 2^32 - 1 bits",
        });
    }
    Ok(())
}

/// `ψ²ₘ = 2ᵐ/n Σ νᵢ² − n`, with `ψ²₀ = 0`.
fn psi_squared(bits: &[bool], m: usize) -> f64 {
    if m == 0 {
        return 0.0;
    }
    let n = to_f64(bits.len());
    let sum_of_squares: f64 = pattern_counts(bits, m)
        .iter()
        .map(|&count| {
            let count = f64::from(count);
            count * count
        })
        .sum();
    (to_f64(1 << m) / n).mul_add(sum_of_squares, -n)
}

/// Serial test, SP 800-22 §2.11.
///
/// Compares the frequencies of all overlapping `m`-bit patterns (read
/// cyclically) with the uniform distribution. Returns the two outcomes
/// `[∇ψ²ₘ, ∇²ψ²ₘ]` with p-values `igamc(2^(m−2), ∇ψ²ₘ/2)` and
/// `igamc(2^(m−3), ∇²ψ²ₘ/2)`. NIST recommends `m < ⌊log₂ n⌋ − 2`.
///
/// # Errors
///
/// [`Error::InvalidParameter`] unless `2 ≤ m ≤` [`MAX_PATTERN_LENGTH`], and
/// [`Error::TooShort`] for an empty sequence.
pub fn serial(bits: &[bool], m: usize) -> Result<[TestOutcome; 2], Error> {
    if m < 2 {
        return Err(invalid_m("must be at least 2"));
    }
    if m > MAX_PATTERN_LENGTH {
        return Err(invalid_m("must be at most MAX_PATTERN_LENGTH"));
    }
    check_pattern_input(Test::Serial1, bits)?;
    let psi_m = psi_squared(bits, m);
    let psi_m1 = psi_squared(bits, m - 1);
    let psi_m2 = psi_squared(bits, m - 2);
    // Both statistics are non-negative; clamp away rounding noise.
    let delta1 = (psi_m - psi_m1).max(0.0);
    let delta2 = (2.0f64.mul_add(-psi_m1, psi_m) + psi_m2).max(0.0);
    let p1 = gamma_q(to_f64(1 << m) / 4.0, delta1 / 2.0);
    let p2 = gamma_q(to_f64(1 << m) / 8.0, delta2 / 2.0);
    Ok([
        TestOutcome::new(Test::Serial1, delta1, p1),
        TestOutcome::new(Test::Serial2, delta2, p2),
    ])
}

/// `φ⁽ᵐ⁾ = Σ πᵢ ln πᵢ` over the overlapping `m`-bit patterns.
fn phi(bits: &[bool], m: usize) -> f64 {
    if m == 0 {
        return 0.0;
    }
    let n = to_f64(bits.len());
    pattern_counts(bits, m)
        .iter()
        .filter(|&&count| count > 0)
        .map(|&count| {
            let p = f64::from(count) / n;
            p * p.ln()
        })
        .sum()
}

/// Approximate entropy test, SP 800-22 §2.12.
///
/// Compares the frequencies of overlapping `m`- and `(m+1)`-bit patterns.
/// `ApEn(m) = φ⁽ᵐ⁾ − φ⁽ᵐ⁺¹⁾`, `χ² = 2n(ln 2 − ApEn(m))` and the p-value
/// is `igamc(2^(m−1), χ²/2)`. NIST recommends `m < ⌊log₂ n⌋ − 5`.
///
/// # Errors
///
/// [`Error::InvalidParameter`] unless `1 ≤ m < ` [`MAX_PATTERN_LENGTH`], and
/// [`Error::TooShort`] for an empty sequence.
pub fn approximate_entropy(bits: &[bool], m: usize) -> Result<TestOutcome, Error> {
    if m < 1 {
        return Err(invalid_m("must be at least 1"));
    }
    if m >= MAX_PATTERN_LENGTH {
        return Err(invalid_m("must be below MAX_PATTERN_LENGTH"));
    }
    check_pattern_input(Test::ApproximateEntropy, bits)?;
    let n = to_f64(bits.len());
    let ap_en = phi(bits, m) - phi(bits, m + 1);
    // ApEn(m) ≤ ln 2; clamp away rounding noise.
    let chi_squared = (2.0 * n * (LN_2 - ap_en)).max(0.0);
    let p_value = gamma_q(to_f64(1 << m) / 2.0, chi_squared / 2.0);
    Ok(TestOutcome::new(
        Test::ApproximateEntropy,
        chi_squared,
        p_value,
    ))
}

/// Direction of the [`cumulative_sums`] walk.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub enum Direction {
    /// From the first bit to the last (mode 0).
    Forward,
    /// From the last bit to the first (mode 1).
    Backward,
}

/// Cumulative sums (cusum) test, SP 800-22 §2.13.
///
/// Walks the sequence as a ±1 random walk and checks that its largest
/// excursion `z = max |Sₖ|` from zero is consistent with a random walk.
/// NIST recommends `n ≥ 100`.
///
/// # Errors
///
/// [`Error::TooShort`] for an empty sequence.
#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    reason = "summation bounds are within ±n/4, far below 2^53"
)]
pub fn cumulative_sums(bits: &[bool], direction: Direction) -> Result<TestOutcome, Error> {
    let test = match direction {
        Direction::Forward => Test::CumulativeSumsForward,
        Direction::Backward => Test::CumulativeSumsBackward,
    };
    require(test, bits, 1)?;
    let step = |(sum, max): (i64, i64), &bit: &bool| {
        let sum = sum + if bit { 1 } else { -1 };
        (sum, max.max(sum.abs()))
    };
    let (_, z) = match direction {
        Direction::Forward => bits.iter().fold((0, 0), step),
        Direction::Backward => bits.iter().rev().fold((0, 0), step),
    };
    let n = to_f64(bits.len());
    #[allow(clippy::cast_precision_loss, reason = "z is at most n, far below 2^53")]
    let z = z as f64;
    let sqrt_n = n.sqrt();
    let ratio = n / z;
    // `sts-2.1.2` truncates the (real) summation bounds toward zero.
    let mut sum1 = 0.0;
    let mut k = ((1.0 - ratio) / 4.0).trunc() as i64;
    let upper = ((ratio - 1.0) / 4.0).trunc() as i64;
    while k <= upper {
        let kf = k as f64;
        sum1 += normal_cdf(4.0f64.mul_add(kf, 1.0) * z / sqrt_n)
            - normal_cdf(4.0f64.mul_add(kf, -1.0) * z / sqrt_n);
        k += 1;
    }
    let mut sum2 = 0.0;
    let mut k = ((-3.0 - ratio) / 4.0).trunc() as i64;
    while k <= upper {
        let kf = k as f64;
        sum2 += normal_cdf(4.0f64.mul_add(kf, 3.0) * z / sqrt_n)
            - normal_cdf(4.0f64.mul_add(kf, 1.0) * z / sqrt_n);
        k += 1;
    }
    let p_value = (1.0 - sum1 + sum2).clamp(0.0, 1.0);
    Ok(TestOutcome::new(test, z, p_value))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pattern_counts_wrap_around() {
        // 0011011101 with m = 3, SP 800-22 §2.11.4: ν000 = 0, ν001 = 1,
        // ν010 = 1, ν011 = 2, ν100 = 1, ν101 = 2, ν110 = 2, ν111 = 1.
        let bits: Vec<bool> = "0011011101".bytes().map(|b| b == b'1').collect();
        assert_eq!(pattern_counts(&bits, 3), vec![0, 1, 1, 2, 1, 2, 2, 1]);
        assert_eq!(pattern_counts(&bits, 1), vec![4, 6]);
        assert_eq!(pattern_counts(&bits, 0), vec![10]);
    }

    #[test]
    fn longest_run_counts() {
        assert_eq!(longest_run(&[]), 0);
        assert_eq!(longest_run(&[true, true, false, true, true, true]), 3);
    }

    #[test]
    fn parameter_validation() {
        let bits = [true, false];
        assert!(matches!(
            block_frequency(&bits, 0),
            Err(Error::InvalidParameter { .. })
        ));
        assert!(matches!(
            block_frequency(&bits, 3),
            Err(Error::TooShort { needed: 3, .. })
        ));
        assert!(serial(&bits, 1).is_err());
        assert!(serial(&bits, MAX_PATTERN_LENGTH + 1).is_err());
        assert!(approximate_entropy(&bits, 0).is_err());
        assert!(approximate_entropy(&bits, MAX_PATTERN_LENGTH).is_err());
        assert!(frequency(&[]).is_err());
        assert!(runs(&[]).is_err());
        assert!(cumulative_sums(&[], Direction::Forward).is_err());
        assert!(longest_run_of_ones(&[true; 127]).is_err());
    }

    #[test]
    fn constant_sequence_fails_runs() {
        let outcome = runs(&[true; 200]);
        assert_eq!(outcome.map(|o| o.p_value), Ok(0.0));
    }
}
