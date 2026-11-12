//! The crate's error type.

use crate::outcome::Test;

/// Errors returned by this crate.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The sequence is too short for the test (or for the chosen block
    /// length).
    #[error("{test} needs at least {needed} bits, got {got}")]
    TooShort {
        /// The test that was asked for.
        test: Test,
        /// Minimum number of bits the test needs.
        needed: usize,
        /// Number of bits supplied.
        got: usize,
    },
    /// The FIPS 140-2 power-up tests need a 20 000-bit sample.
    #[error("FIPS 140-2 tests need {needed} bits, got {got}")]
    FipsSampleTooShort {
        /// Number of bits the tests need.
        needed: usize,
        /// Number of bits supplied.
        got: usize,
    },
    /// A parameter is out of its valid range.
    #[error("invalid parameter `{name}`: {reason}")]
    InvalidParameter {
        /// Name of the parameter.
        name: &'static str,
        /// Why the value was rejected.
        reason: &'static str,
    },
    /// A character other than `0`, `1` or ASCII whitespace in a bit string.
    #[error("invalid bit character {found:?} at byte offset {offset}")]
    InvalidBitChar {
        /// Byte offset of the character.
        offset: usize,
        /// The offending character.
        found: char,
    },
    /// No tokens were supplied.
    #[error("no tokens to analyse")]
    NoTokens,
    /// A token contains a byte outside the configured alphabet.
    #[error("token {token} has byte {byte:#04x} at offset {offset}, which is not in the alphabet")]
    NotInAlphabet {
        /// Index of the token.
        token: usize,
        /// Byte offset within the token.
        offset: usize,
        /// The offending byte.
        byte: u8,
    },
}
