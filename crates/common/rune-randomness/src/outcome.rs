//! Test identifiers and results.

use std::fmt;

/// One statistical test (or, for the two-statistic tests, one of its
/// statistics).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub enum Test {
    /// SP 800-22 §2.1, frequency (monobit) test.
    Frequency,
    /// SP 800-22 §2.2, frequency test within a block.
    BlockFrequency,
    /// SP 800-22 §2.3, runs test.
    Runs,
    /// SP 800-22 §2.4, test for the longest run of ones in a block.
    LongestRunOfOnes,
    /// SP 800-22 §2.11, serial test, first statistic `∇ψ²ₘ`.
    Serial1,
    /// SP 800-22 §2.11, serial test, second statistic `∇²ψ²ₘ`.
    Serial2,
    /// SP 800-22 §2.12, approximate entropy test.
    ApproximateEntropy,
    /// SP 800-22 §2.13, cumulative sums test, forward mode.
    CumulativeSumsForward,
    /// SP 800-22 §2.13, cumulative sums test, backward mode.
    CumulativeSumsBackward,
}

impl Test {
    /// The name used in reports, such as `"frequency"`.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Frequency => "frequency",
            Self::BlockFrequency => "block frequency",
            Self::Runs => "runs",
            Self::LongestRunOfOnes => "longest run of ones",
            Self::Serial1 => "serial (1)",
            Self::Serial2 => "serial (2)",
            Self::ApproximateEntropy => "approximate entropy",
            Self::CumulativeSumsForward => "cumulative sums (forward)",
            Self::CumulativeSumsBackward => "cumulative sums (backward)",
        }
    }
}

impl fmt::Display for Test {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// The result of one test: its statistic and p-value.
///
/// The p-value is the probability that a truly random sequence gives a
/// statistic at least this extreme. SP 800-22 rejects randomness when it is
/// below the significance level `α`, usually `0.01`.
#[derive(Debug, Clone, Copy, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub struct TestOutcome {
    /// Which test produced this outcome.
    pub test: Test,
    /// The test statistic, as named in SP 800-22: `s_obs` for frequency,
    /// `χ²(obs)` for block frequency, longest run and approximate entropy,
    /// `V_n(obs)` for runs, `z` for cumulative sums, and `∇ψ²ₘ` / `∇²ψ²ₘ`
    /// for serial.
    pub statistic: f64,
    /// The p-value, in `[0, 1]`.
    pub p_value: f64,
}

impl TestOutcome {
    pub(crate) const fn new(test: Test, statistic: f64, p_value: f64) -> Self {
        Self {
            test,
            statistic,
            p_value,
        }
    }

    /// Whether the sequence passes at significance level `alpha`
    /// (`p_value ≥ alpha`).
    #[must_use]
    pub fn passed(&self, alpha: f64) -> bool {
        self.p_value >= alpha
    }
}
