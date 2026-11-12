//! Statistical randomness tests for session tokens, identifiers and bit
//! streams: the short-sample subset of NIST SP 800-22, the FIPS 140-2
//! power-up tests, and Burp-Sequencer-style per-position analysis of token
//! samples.
//!
//! * **NIST SP 800-22 Rev. 1a** ([specification]) — [`nist::frequency`],
//!   [`nist::block_frequency`], [`nist::runs`],
//!   [`nist::longest_run_of_ones`], [`nist::serial`],
//!   [`nist::approximate_entropy`] and [`nist::cumulative_sums`]. Each
//!   returns a typed [`TestOutcome`] with the statistic and p-value.
//! * **FIPS 140-2** — [`fips_140_2`]: monobit, poker, runs and long run on a
//!   20 000-bit sample.
//! * **Battery** — [`run`] applies every test that suits the sample size
//!   and returns a [`Report`] with pass/fail at a significance level.
//! * **Tokens** — [`analyze_tokens`] reports per-character-position
//!   distribution tests and entropy (via `rune-entropy`), per-bit bias, and
//!   the battery on the encoded bit stream.
//!
//! P-values use the special functions of `rune-stats` (`erfc`, the
//! regularized incomplete gamma function `igamc`). The tests reproduce the
//! example p-values published in SP 800-22, including the one-million-bit
//! expansion of `e` from its Appendix B.
//!
//! [specification]: https://csrc.nist.gov/pubs/sp/800/22/r1/upd1/final
//!
//! # Example
//!
//! ```
//! use rune_randomness::{Bits, Options, Test, nist, run};
//!
//! // SP 800-22 §2.1.8: the first 100 bits of π.
//! let pi = Bits::parse(
//!     "11001001000011111101101010100010001000010110100011\
//!      00001000110100110001001100011001100010100010111000",
//! )?;
//! let outcome = nist::frequency(&pi)?;
//! assert!((outcome.p_value - 0.109_599).abs() < 1e-6);
//!
//! let report = run(&pi, &Options::default())?;
//! assert!(report.passed());
//! assert!(report.get(Test::Runs).is_some());
//! // The longest-run test needs 128 bits.
//! assert!(report.skipped.iter().any(|s| s.test == Test::LongestRunOfOnes));
//! # Ok::<(), rune_randomness::Error>(())
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod battery;
mod bits;
mod error;
mod fips;
pub mod nist;
mod outcome;
mod tokens;

pub use battery::{Options, RECOMMENDED_MIN_BITS, Report, Skipped, run};
pub use bits::Bits;
pub use error::Error;
pub use fips::{FIPS_LONG_RUN, FIPS_RUN_BOUNDS, FIPS_SAMPLE_BITS, FipsReport, fips_140_2};
pub use outcome::{Test, TestOutcome};
pub use tokens::{
    BitPositionReport, PositionReport, TokenOptions, TokenReport, analyze_tokens, token_bits,
};
