//! The FIPS 140-2 power-up statistical tests (FIPS 140-2 §4.9.1, as
//! published in 2001; later change notices withdrew them from the
//! standard, but they remain a quick and widely used sanity check).

use crate::Error;
use crate::nist::to_f64;

/// Number of bits the FIPS 140-2 tests examine.
pub const FIPS_SAMPLE_BITS: usize = 20_000;

/// Accepted counts for runs of length 1, 2, 3, 4, 5 and 6 or more
/// (inclusive bounds), for runs of zeros and of ones alike.
pub const FIPS_RUN_BOUNDS: [(usize, usize); 6] = [
    (2_315, 2_685),
    (1_114, 1_386),
    (527, 723),
    (240, 384),
    (103, 209),
    (103, 209),
];

/// A run of this many identical bits or more fails the long-run test.
pub const FIPS_LONG_RUN: usize = 26;

/// Results of the four FIPS 140-2 power-up tests on a 20 000-bit sample.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
#[allow(
    clippy::struct_excessive_bools,
    reason = "one verdict per FIPS test, next to its statistic"
)]
pub struct FipsReport {
    /// Number of ones. The monobit test passes for `9725 < ones < 10275`.
    pub ones: usize,
    /// Whether the monobit test passed.
    pub monobit_passed: bool,
    /// Poker statistic `X = 16/5000 · Σ f(i)² − 5000` over the 5 000
    /// four-bit nibbles. Passes for `2.16 < X < 46.17`.
    pub poker: f64,
    /// Whether the poker test passed.
    pub poker_passed: bool,
    /// Runs of zeros of length 1, 2, 3, 4, 5 and 6 or more.
    pub runs_of_zeros: [usize; 6],
    /// Runs of ones of length 1, 2, 3, 4, 5 and 6 or more.
    pub runs_of_ones: [usize; 6],
    /// Whether every run count lies within [`FIPS_RUN_BOUNDS`].
    pub runs_passed: bool,
    /// Length of the longest run of identical bits.
    pub longest_run: usize,
    /// Whether the long-run test passed (no run of 26 or more).
    pub long_run_passed: bool,
}

impl FipsReport {
    /// Whether all four tests passed.
    #[must_use]
    pub const fn passed(&self) -> bool {
        self.monobit_passed && self.poker_passed && self.runs_passed && self.long_run_passed
    }
}

/// Runs the FIPS 140-2 monobit, poker, runs and long-run tests on the
/// first 20 000 bits of `bits`.
///
/// # Errors
///
/// [`Error::FipsSampleTooShort`] for fewer than 20 000 bits.
///
/// ```
/// use rune_randomness::{Bits, fips_140_2};
///
/// // A sequence of all zeros fails everything.
/// let report = fips_140_2(&Bits::from_bytes(&[0; 2500]))?;
/// assert!(!report.passed());
/// assert!(!report.monobit_passed);
/// assert_eq!(report.longest_run, 20_000);
/// # Ok::<(), rune_randomness::Error>(())
/// ```
pub fn fips_140_2(bits: &[bool]) -> Result<FipsReport, Error> {
    let Some(sample) = bits.get(..FIPS_SAMPLE_BITS) else {
        return Err(Error::FipsSampleTooShort {
            needed: FIPS_SAMPLE_BITS,
            got: bits.len(),
        });
    };

    let ones = crate::bits::count_ones(sample);
    let monobit_passed = 9_725 < ones && ones < 10_275;

    let mut nibbles = [0usize; 16];
    for chunk in sample.as_chunks::<4>().0 {
        let value = chunk
            .iter()
            .fold(0usize, |acc, &bit| (acc << 1) | usize::from(bit));
        nibbles[value] += 1;
    }
    let sum_of_squares: f64 = nibbles
        .iter()
        .map(|&f| {
            let f = to_f64(f);
            f * f
        })
        .sum();
    let poker = (16.0f64 / 5_000.0).mul_add(sum_of_squares, -5_000.0);
    let poker_passed = 2.16 < poker && poker < 46.17;

    let mut runs_of_zeros = [0usize; 6];
    let mut runs_of_ones = [0usize; 6];
    let mut longest_run = 0;
    let mut record = |bit: bool, length: usize| {
        let bucket = length.min(6) - 1;
        if bit {
            runs_of_ones[bucket] += 1;
        } else {
            runs_of_zeros[bucket] += 1;
        }
        longest_run = longest_run.max(length);
    };
    let mut current = sample[0];
    let mut length = 0;
    for &bit in sample {
        if bit == current {
            length += 1;
        } else {
            record(current, length);
            current = bit;
            length = 1;
        }
    }
    record(current, length);

    let within = |counts: &[usize; 6]| {
        counts
            .iter()
            .zip(FIPS_RUN_BOUNDS)
            .all(|(&count, (low, high))| (low..=high).contains(&count))
    };
    let runs_passed = within(&runs_of_zeros) && within(&runs_of_ones);

    Ok(FipsReport {
        ones,
        monobit_passed,
        poker,
        poker_passed,
        runs_of_zeros,
        runs_of_ones,
        runs_passed,
        longest_run,
        long_run_passed: longest_run < FIPS_LONG_RUN,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_sample_is_rejected() {
        assert_eq!(
            fips_140_2(&[true; 100]),
            Err(Error::FipsSampleTooShort {
                needed: 20_000,
                got: 100
            })
        );
    }

    #[test]
    fn alternating_bits_fail_poker_and_runs() {
        let bits: Vec<bool> = (0..20_000).map(|i| i % 2 == 0).collect();
        let report = fips_140_2(&bits).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(report.ones, 10_000);
        assert!(report.monobit_passed);
        // Every nibble is 1010: 16/5000 · 5000² − 5000 = 75 000.
        assert!((report.poker - 75_000.0).abs() < 1e-9);
        assert!(!report.poker_passed);
        assert_eq!(report.runs_of_ones, [10_000, 0, 0, 0, 0, 0]);
        assert!(!report.runs_passed);
        assert_eq!(report.longest_run, 1);
        assert!(report.long_run_passed);
        assert!(!report.passed());
    }

    #[test]
    fn uniform_nibbles_give_minimal_poker() {
        // Every nibble value equally often (312 or 313 times): X close to 0.
        let bits: Vec<bool> = (0..20_000usize)
            .map(|i| ((i / 4) % 16) >> (3 - i % 4) & 1 == 1)
            .collect();
        let report = fips_140_2(&bits).unwrap_or_else(|e| panic!("{e}"));
        // f = 313 for 8 values and 312 for 8: 16/5000·(8·313² + 8·312²) − 5000.
        // = 16/5000 · 1 562 504 − 5000 = 0.0128
        let expected = 0.012_8;
        assert!((report.poker - expected).abs() < 1e-9);
        assert!(!report.poker_passed);
    }
}
