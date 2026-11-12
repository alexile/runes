//! The full battery: every test that applies to the sample, in one call.

use crate::fips::{FIPS_SAMPLE_BITS, FipsReport, fips_140_2};
use crate::nist::{
    self, Direction, approximate_entropy, block_frequency, cumulative_sums, frequency,
    longest_run_of_ones, runs, serial,
};
use crate::{Error, Test, TestOutcome};

/// Smallest sequence NIST recommends for the frequency, block frequency,
/// runs, cumulative sums, serial and approximate entropy tests.
pub const RECOMMENDED_MIN_BITS: usize = 100;

/// Largest pattern length the battery picks on its own for the serial and
/// approximate entropy tests.
const AUTO_PATTERN_CAP: usize = 10;

/// Settings for [`run`].
#[derive(Debug, Clone, Copy, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub struct Options {
    /// Significance level `α`; a test passes when its p-value is at least
    /// this. Defaults to `0.01`, as in SP 800-22.
    pub alpha: f64,
    /// Block length `M` for the block frequency test. `None` picks
    /// `max(20, ⌊n/100⌋ + 1)`, which meets NIST's `M ≥ 20`, `M > 0.01 n`.
    pub block_length: Option<usize>,
    /// Pattern length `m` for the serial test. `None` picks the largest
    /// `m < ⌊log₂ n⌋ − 2` that NIST recommends, between 2 and 10.
    pub serial_m: Option<usize>,
    /// Pattern length `m` for the approximate entropy test. `None` picks the
    /// largest `m < ⌊log₂ n⌋ − 5` that NIST recommends, between 1 and 10.
    pub approximate_entropy_m: Option<usize>,
    /// Whether to run the tests NIST recommends against for sequences
    /// shorter than [`RECOMMENDED_MIN_BITS`]. Off by default: such tests are
    /// reported in [`Report::skipped`] instead.
    pub allow_short: bool,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            alpha: 0.01,
            block_length: None,
            serial_m: None,
            approximate_entropy_m: None,
            allow_short: false,
        }
    }
}

impl Options {
    /// Sets [`Options::alpha`].
    #[must_use]
    pub const fn with_alpha(mut self, alpha: f64) -> Self {
        self.alpha = alpha;
        self
    }

    /// Sets [`Options::block_length`].
    #[must_use]
    pub const fn with_block_length(mut self, block_length: usize) -> Self {
        self.block_length = Some(block_length);
        self
    }

    /// Sets [`Options::serial_m`].
    #[must_use]
    pub const fn with_serial_m(mut self, m: usize) -> Self {
        self.serial_m = Some(m);
        self
    }

    /// Sets [`Options::approximate_entropy_m`].
    #[must_use]
    pub const fn with_approximate_entropy_m(mut self, m: usize) -> Self {
        self.approximate_entropy_m = Some(m);
        self
    }

    /// Sets [`Options::allow_short`].
    #[must_use]
    pub const fn with_allow_short(mut self, allow_short: bool) -> Self {
        self.allow_short = allow_short;
        self
    }

    fn validate(&self) -> Result<(), Error> {
        if !(self.alpha > 0.0 && self.alpha < 1.0) {
            return Err(Error::InvalidParameter {
                name: "alpha",
                reason: "must lie strictly between 0 and 1",
            });
        }
        if self.block_length == Some(0) {
            return Err(Error::InvalidParameter {
                name: "block_length",
                reason: "must be at least 1",
            });
        }
        if let Some(m) = self.serial_m
            && !(2..=nist::MAX_PATTERN_LENGTH).contains(&m)
        {
            return Err(Error::InvalidParameter {
                name: "serial_m",
                reason: "must lie in 2..=MAX_PATTERN_LENGTH",
            });
        }
        if let Some(m) = self.approximate_entropy_m
            && !(1..nist::MAX_PATTERN_LENGTH).contains(&m)
        {
            return Err(Error::InvalidParameter {
                name: "approximate_entropy_m",
                reason: "must lie in 1..MAX_PATTERN_LENGTH",
            });
        }
        Ok(())
    }
}

/// A test the battery did not run because the sequence was too short.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub struct Skipped {
    /// The test.
    pub test: Test,
    /// Number of bits it needs.
    pub needed: usize,
}

/// Results of [`run`].
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub struct Report {
    /// Number of bits tested.
    pub bits: usize,
    /// The significance level the pass/fail verdicts use.
    pub alpha: f64,
    /// One outcome per test statistic that was computed.
    pub outcomes: Vec<TestOutcome>,
    /// Tests that were not run because the sequence was too short.
    pub skipped: Vec<Skipped>,
    /// FIPS 140-2 power-up tests on the first 20 000 bits, when there are
    /// that many.
    pub fips: Option<FipsReport>,
}

impl Report {
    /// Whether every computed test passed at [`Report::alpha`], including
    /// the FIPS 140-2 tests when they ran.
    #[must_use]
    pub fn passed(&self) -> bool {
        self.outcomes.iter().all(|o| o.passed(self.alpha))
            && self.fips.as_ref().is_none_or(FipsReport::passed)
    }

    /// The outcomes whose p-value is below [`Report::alpha`].
    pub fn failures(&self) -> impl Iterator<Item = &TestOutcome> {
        self.outcomes.iter().filter(|o| !o.passed(self.alpha))
    }

    /// The outcome of `test`, if it ran.
    #[must_use]
    pub fn get(&self, test: Test) -> Option<&TestOutcome> {
        self.outcomes.iter().find(|o| o.test == test)
    }
}

/// `⌊log₂ n⌋` for `n ≥ 1`.
const fn floor_log2(n: usize) -> usize {
    (usize::BITS - 1 - n.leading_zeros()) as usize
}

/// Runs every SP 800-22 test in this crate that applies to `bits`, plus
/// the FIPS 140-2 tests when there are at least 20 000 bits.
///
/// Tests the sequence is too short for are listed in [`Report::skipped`].
///
/// # Errors
///
/// [`Error::InvalidParameter`] when an [`Options`] field is out of range.
///
/// ```
/// use rune_randomness::{Bits, Options, run};
///
/// // A weak 64-bit "token" generator: a counter.
/// let bits: Bits = (0u64..32).flat_map(|i| (0..64).rev().map(move |s| (i >> s) & 1 == 1)).collect();
/// let report = run(&bits, &Options::default())?;
/// assert!(!report.passed());
/// # Ok::<(), rune_randomness::Error>(())
/// ```
pub fn run(bits: &[bool], options: &Options) -> Result<Report, Error> {
    options.validate()?;
    let n = bits.len();
    let mut outcomes = Vec::new();
    let mut skipped = Vec::new();
    let min_bits = if options.allow_short {
        1
    } else {
        RECOMMENDED_MIN_BITS
    };
    let mut attempt = |result: Result<Vec<TestOutcome>, Error>, test: Test| match result {
        Ok(found) => outcomes.extend(found),
        Err(Error::TooShort { needed, .. }) => skipped.push(Skipped { test, needed }),
        Err(_) => skipped.push(Skipped {
            test,
            needed: n + 1,
        }),
    };
    let short = |test: Test| {
        Err(Error::TooShort {
            test,
            needed: min_bits,
            got: n,
        })
    };

    if n >= min_bits {
        attempt(frequency(bits).map(|o| vec![o]), Test::Frequency);
        let block_length = options
            .block_length
            .unwrap_or_else(|| (n / 100 + 1).max(20));
        attempt(
            block_frequency(bits, block_length).map(|o| vec![o]),
            Test::BlockFrequency,
        );
        attempt(runs(bits).map(|o| vec![o]), Test::Runs);
    } else {
        for test in [Test::Frequency, Test::BlockFrequency, Test::Runs] {
            attempt(short(test), test);
        }
    }
    attempt(
        longest_run_of_ones(bits).map(|o| vec![o]),
        Test::LongestRunOfOnes,
    );
    if n >= min_bits {
        let log2 = floor_log2(n.max(1));
        let serial_m = options
            .serial_m
            .unwrap_or_else(|| log2.saturating_sub(3).clamp(2, AUTO_PATTERN_CAP));
        attempt(serial(bits, serial_m).map(Vec::from), Test::Serial1);
        let apen_m = options
            .approximate_entropy_m
            .unwrap_or_else(|| log2.saturating_sub(6).clamp(1, AUTO_PATTERN_CAP));
        attempt(
            approximate_entropy(bits, apen_m).map(|o| vec![o]),
            Test::ApproximateEntropy,
        );
        attempt(
            cumulative_sums(bits, Direction::Forward).map(|o| vec![o]),
            Test::CumulativeSumsForward,
        );
        attempt(
            cumulative_sums(bits, Direction::Backward).map(|o| vec![o]),
            Test::CumulativeSumsBackward,
        );
    } else {
        for test in [
            Test::Serial1,
            Test::ApproximateEntropy,
            Test::CumulativeSumsForward,
            Test::CumulativeSumsBackward,
        ] {
            attempt(short(test), test);
        }
    }

    let fips = if n >= FIPS_SAMPLE_BITS {
        fips_140_2(bits).ok()
    } else {
        None
    };
    Ok(Report {
        bits: n,
        alpha: options.alpha,
        outcomes,
        skipped,
        fips,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn floor_log2_values() {
        assert_eq!(floor_log2(1), 0);
        assert_eq!(floor_log2(100), 6);
        assert_eq!(floor_log2(1_000_000), 19);
    }

    #[test]
    fn short_sequences_are_skipped() {
        let bits = [true, false, true, true, false];
        let report = run(&bits, &Options::default()).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(report.outcomes, []);
        assert_eq!(report.skipped.len(), 8);
        assert!(report.passed());

        let report = run(&bits, &Options::default().with_allow_short(true))
            .unwrap_or_else(|e| panic!("{e}"));
        assert!(report.get(Test::Frequency).is_some());
        assert!(
            report
                .skipped
                .iter()
                .any(|s| s.test == Test::LongestRunOfOnes && s.needed == 128)
        );
    }

    #[test]
    fn invalid_options() {
        let bits = [true; 200];
        for options in [
            Options::default().with_alpha(0.0),
            Options::default().with_alpha(f64::NAN),
            Options::default().with_block_length(0),
            Options::default().with_serial_m(1),
            Options::default().with_approximate_entropy_m(0),
        ] {
            assert!(matches!(
                run(&bits, &options),
                Err(Error::InvalidParameter { .. })
            ));
        }
    }
}
