//! Shannon entropy and related randomness statistics for files and byte
//! streams, for spotting encrypted, packed, or compressed data.
//!
//! Entropy measures how unpredictable bytes are, from `0.0` bits per byte
//! (one value repeated) to `8.0` (every byte value equally likely). High
//! scores point at compression, encryption, or packing; low scores at
//! padding and repetitive data.
//!
//! # What's here
//!
//! - [`entropy`], [`classify`]: one-call Shannon entropy and a coarse label.
//! - [`Histogram`]: incremental byte counts, Shannon and min-entropy,
//!   chi-square, mean, printable ratio.
//! - [`Analyzer`] / [`analyze`]: streaming, fixed-memory analysis with the
//!   statistics of the classic `ent` tool (chi-square, serial correlation,
//!   Monte Carlo π) and a cautious [`Verdict`].
//! - [`Profiler`] / [`entropy_profile`]: sliding-window entropy over a file.
//! - [`high_entropy_regions`], [`regions_where`]: byte ranges of packed or
//!   encrypted content.
//! - [`random_entropy_baseline`]: what truly random data scores at a given
//!   size, for picking thresholds.
//! - With `std` (default): streaming file and reader helpers.
//!
//! The core is `no_std` + `alloc`. Disable default features and enable
//! `libm` to build without `std`.
//!
//! # Quick start
//!
//! ```rust
//! use rune_entropy::{analyze, classify, entropy, Verdict};
//!
//! let score = entropy(b"hello world");
//! println!("{score:.4} bits/byte ({})", classify(score));
//!
//! let report = analyze(&b"plain ASCII text, repeated. ".repeat(50));
//! assert_eq!(report.assess().verdict, Verdict::Text);
//! ```
//!
//! # Locating packed regions
//!
//! ```rust
//! use rune_entropy::{high_entropy_regions, RegionOptions};
//!
//! let data = vec![0u8; 16 * 1024];
//! let regions = high_entropy_regions(&data, &RegionOptions::default())?;
//! assert!(regions.is_empty());
//! # Ok::<(), rune_entropy::Error>(())
//! ```
//!
//! # Reading the numbers honestly
//!
//! Every statistic here is order-0: it looks at how often each byte value
//! occurs, not at their order (serial correlation aside). That makes it fast
//! and robust, but it cannot tell AES output from a well-compressed archive,
//! and short inputs score low even when perfectly random
//! (see [`random_entropy_baseline`]). Use the results for triage.

#![cfg_attr(not(feature = "std"), no_std)]
#![allow(
    clippy::suboptimal_flops,
    reason = "`mul_add` is missing from core and slow without hardware FMA"
)]

#[cfg(not(any(feature = "std", feature = "libm")))]
compile_error!("rune-entropy needs either the `std` or the `libm` feature for floating-point math");

extern crate alloc;

use alloc::vec::Vec;

mod analysis;
mod classify;
mod histogram;
#[cfg(feature = "std")]
mod io;
mod math;
mod profile;

pub use analysis::{
    Analysis, Analyzer, Assessment, CHI_SQUARE_ALPHA, Confidence, HIGH_ENTROPY_THRESHOLD,
    LOW_ENTROPY_THRESHOLD, MIN_STATISTICAL_SAMPLE, TEXT_PRINTABLE_RATIO, Verdict,
};
pub use classify::{BINARY_ENTROPY_THRESHOLD, EntropyClass, classify};
pub use histogram::Histogram;
#[cfg(feature = "std")]
pub use io::{
    analyze_file, analyze_reader, file_block_entropy, file_entropy, profile_file, profile_reader,
    reader_block_entropy,
};
pub use profile::{
    Error, Profiler, Region, RegionOptions, Window, entropy_profile, high_entropy_regions,
    random_entropy_baseline, regions_where,
};

/// Shannon entropy of a byte slice, in bits per byte.
///
/// Returns a value in `[0.0, 8.0]`; empty input gives `0.0`.
///
/// # Examples
///
/// ```rust
/// use rune_entropy::entropy;
///
/// assert_eq!(entropy(&[]), 0.0);
/// assert_eq!(entropy(&[0u8; 1024]), 0.0);
///
/// // Every byte value equally often → exactly 8.0.
/// let uniform: Vec<u8> = (0..=255u8).cycle().take(4096).collect();
/// assert_eq!(entropy(&uniform), 8.0);
/// ```
#[must_use]
pub fn entropy(data: &[u8]) -> f64 {
    Histogram::from_bytes(data).shannon()
}

/// Full statistics for a byte slice. Shorthand for feeding an [`Analyzer`].
///
/// # Examples
///
/// ```rust
/// let report = rune_entropy::analyze(&[0, 255, 0, 255]);
/// assert_eq!(report.shannon, 1.0);
/// assert_eq!(report.mean, Some(127.5));
/// assert_eq!(report.serial_correlation, Some(-1.0));
/// ```
#[must_use]
pub fn analyze(data: &[u8]) -> Analysis {
    let mut analyzer = Analyzer::new();
    analyzer.update(data);
    analyzer.analysis()
}

/// Shannon entropy of each fixed-size block of `data`.
///
/// Block `i` covers bytes `i * block_size .. (i + 1) * block_size`; the
/// last block is shorter when `data.len()` is not a multiple of
/// `block_size`. Empty input gives an empty `Vec`. For overlapping windows
/// use [`entropy_profile`].
///
/// # Panics
///
/// Panics if `block_size` is zero.
///
/// # Examples
///
/// ```rust
/// use rune_entropy::block_entropy;
///
/// let data: Vec<u8> = (0u8..=255).cycle().take(512).collect();
/// assert_eq!(block_entropy(&data, 256), [8.0, 8.0]);
/// ```
#[must_use]
pub fn block_entropy(data: &[u8], block_size: usize) -> Vec<f64> {
    assert!(block_size > 0, "block_size must be greater than zero");
    data.chunks(block_size).map(entropy).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_vectors() {
        assert_eq!(entropy(b"ab"), 1.0);
        assert_eq!(entropy(b"abcd"), 2.0);
        assert_eq!(entropy(b"abcdefgh"), 3.0);
        // -(0.75 log2 0.75 + 0.25 log2 0.25)
        assert!((entropy(b"aaab") - 0.811_278_124_459_132_8).abs() < 1e-15);
        // "hello world": l×3, o×2, six singletons.
        assert!((entropy(b"hello world") - 2.845_350_936_622_437).abs() < 1e-12);
    }

    #[test]
    fn block_entropy_partial_final_block() {
        assert_eq!(block_entropy(&[0u8; 100], 64), [0.0, 0.0]);
        assert_eq!(block_entropy(&[], 64), Vec::<f64>::new());
    }

    #[test]
    #[should_panic(expected = "block_size must be greater than zero")]
    fn block_entropy_zero_block_size_panics() {
        let _ = block_entropy(b"hello", 0);
    }
}
