//! Detects missing/gap intervals in an expected-cadence timestamped series.
//!
//! Given a series of timestamps that's supposed to arrive at a roughly fixed
//! interval (a heartbeat, a sensor poll, a scheduled job), this finds the
//! intervals where samples were skipped — useful for spotting outages, dropped
//! connections, or missed scheduled runs after the fact.
//!
//! # Features
//!
//! - [`detect_gaps`] — scans a sorted timestamp series and reports each interval
//!   that exceeded the expected cadence plus tolerance.
//!
//! # Quick Start
//!
//! ```rust
//! use rune_gap_detect::detect_gaps;
//!
//! // Regular 1000ms cadence, but one sample was dropped around t=3000.
//! let timestamps = vec![0, 1000, 2000, 4000, 5000];
//! let gaps = detect_gaps(&timestamps, 1000, 100);
//! assert_eq!(gaps.len(), 1);
//! assert_eq!(gaps[0].missing_count, 1);
//! ```
//!
//! # CLI
//!
//! ```bash
//! rune-gap-detect timestamps.txt --interval 1000 --tolerance 100
//! ```

#![cfg_attr(not(any(feature = "std", test)), no_std)]

extern crate alloc;

use alloc::vec::Vec;

/// A detected gap between two consecutive timestamps.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Gap {
    /// Timestamp of the last sample before the gap.
    pub start_ms: i64,
    /// Timestamp of the first sample after the gap.
    pub end_ms: i64,
    /// Estimated number of samples that should have arrived but didn't.
    pub missing_count: usize,
}

/// Scans a sorted-ascending series of millisecond timestamps and reports every
/// interval that exceeded `expected_interval_ms + tolerance_ms`.
///
/// `missing_count` is estimated as `delta / expected_interval_ms - 1`, floored,
/// with a minimum of `1` for any reported gap.
///
/// # Example
///
/// ```rust
/// use rune_gap_detect::detect_gaps;
///
/// let timestamps = vec![0, 1000, 2000, 3000];
/// assert!(detect_gaps(&timestamps, 1000, 50).is_empty());
/// ```
#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    reason = "the value is non-negative and bounded by the input size; float-to-int `as` saturates"
)]
#[must_use]
pub fn detect_gaps(
    timestamps_ms: &[i64],
    expected_interval_ms: i64,
    tolerance_ms: i64,
) -> Vec<Gap> {
    if timestamps_ms.len() < 2 || expected_interval_ms <= 0 {
        return Vec::new();
    }

    let threshold = expected_interval_ms + tolerance_ms;
    let mut gaps = Vec::new();

    for pair in timestamps_ms.windows(2) {
        let delta = pair[1] - pair[0];
        if delta > threshold {
            let missing_count = ((delta / expected_interval_ms) - 1).max(1) as usize;
            gaps.push(Gap {
                start_ms: pair[0],
                end_ms: pair[1],
                missing_count,
            });
        }
    }

    gaps
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn regular_series_reports_no_gaps() {
        let timestamps = vec![0, 1000, 2000, 3000, 4000];
        assert_eq!(detect_gaps(&timestamps, 1000, 50), [] as [Gap; 0]);
    }

    #[test]
    fn small_jitter_within_tolerance_reports_no_gaps() {
        let timestamps = vec![0, 1010, 2005, 2990, 4020];
        assert_eq!(detect_gaps(&timestamps, 1000, 100), [] as [Gap; 0]);
    }

    #[test]
    fn single_dropped_sample_reports_missing_count_one() {
        let timestamps = vec![0, 1000, 3000, 4000];
        let gaps = detect_gaps(&timestamps, 1000, 100);
        assert_eq!(gaps.len(), 1);
        assert_eq!(gaps[0].start_ms, 1000);
        assert_eq!(gaps[0].end_ms, 3000);
        assert_eq!(gaps[0].missing_count, 1);
    }

    #[test]
    fn large_outage_reports_proportional_missing_count() {
        let timestamps = vec![0, 1000, 11_000, 12_000];
        let gaps = detect_gaps(&timestamps, 1000, 100);
        assert_eq!(gaps.len(), 1);
        assert_eq!(gaps[0].missing_count, 9);
    }

    #[test]
    fn multiple_gaps_are_all_reported() {
        let timestamps = vec![0, 1000, 3000, 4000, 6000, 7000];
        let gaps = detect_gaps(&timestamps, 1000, 100);
        assert_eq!(gaps.len(), 2);
    }

    #[test]
    fn empty_or_single_timestamp_does_not_panic() {
        assert_eq!(detect_gaps(&[], 1000, 100), [] as [Gap; 0]);
        assert_eq!(detect_gaps(&[42], 1000, 100), [] as [Gap; 0]);
    }

    #[test]
    fn zero_expected_interval_does_not_panic() {
        assert_eq!(detect_gaps(&[0, 1000], 0, 100), [] as [Gap; 0]);
    }
}
