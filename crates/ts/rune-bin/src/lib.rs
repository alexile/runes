//! Fixed-width and adaptive (equal-frequency) histogram binning for numeric
//! distributions.
//!
//! Fixed bins are what most people mean by "a histogram": equal-width buckets
//! spanning the data's range. Adaptive bins instead choose bucket edges so each
//! bucket holds roughly the same *count* of points — useful for skewed
//! distributions where fixed-width bins leave most buckets empty and one bucket
//! overloaded.
//!
//! # Features
//!
//! - [`fixed_bins`] — equal-width buckets.
//! - [`adaptive_bins`] — equal-frequency (quantile) buckets.
//!
//! # Quick Start
//!
//! ```rust
//! use rune_bin::fixed_bins;
//!
//! let data = vec![0.0, 1.0, 2.0, 3.0, 4.0, 5.0];
//! let hist = fixed_bins(&data, 5);
//! assert_eq!(hist.counts.iter().sum::<usize>(), data.len());
//! ```
//!
//! # CLI
//!
//! ```bash
//! rune-bin data.csv --bins 10
//! rune-bin data.csv --bins 10 --adaptive
//! ```

/// A histogram: `bin_edges.len() == counts.len() + 1`.
#[derive(Debug, Clone, PartialEq)]
pub struct Histogram {
    /// Bin boundaries, ascending, one more than `counts`.
    pub bin_edges: Vec<f64>,
    /// Count of data points falling in each `[bin_edges[i], bin_edges[i+1])` range
    /// (the final bin is closed on both ends, so the maximum value is included).
    pub counts: Vec<usize>,
}

/// Builds a histogram with `num_bins` equal-width buckets spanning `[min, max]`
/// of `data`.
///
/// # Panics
///
/// Panics if `data` is empty or `num_bins` is `0`.
///
/// # Example
///
/// ```rust
/// use rune_bin::fixed_bins;
///
/// let data = vec![0.0, 1.0, 2.0, 3.0];
/// let hist = fixed_bins(&data, 2);
/// assert_eq!(hist.bin_edges, vec![0.0, 1.5, 3.0]);
/// assert_eq!(hist.counts, vec![2, 2]);
/// ```
#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss,
    reason = "the value is non-negative and bounded by the input size; float-to-int `as` saturates"
)]
pub fn fixed_bins(data: &[f64], num_bins: usize) -> Histogram {
    assert!(!data.is_empty(), "data must not be empty");
    assert!(num_bins > 0, "num_bins must be at least 1");

    let min = data.iter().copied().fold(f64::INFINITY, f64::min);
    let max = data.iter().copied().fold(f64::NEG_INFINITY, f64::max);

    let width = if max > min {
        (max - min) / num_bins as f64
    } else {
        1.0 // degenerate: all values identical, give every bucket unit width
    };

    let bin_edges: Vec<f64> = (0..=num_bins)
        .map(|i| f64::mul_add(width, i as f64, min))
        .collect();
    let mut counts = vec![0usize; num_bins];

    for &value in data {
        let index = if max > min {
            (((value - min) / width) as usize).min(num_bins - 1)
        } else {
            0
        };
        counts[index] += 1;
    }

    Histogram { bin_edges, counts }
}

/// Builds a histogram with `num_bins` buckets chosen so each holds roughly the
/// same count of points (equal-frequency / quantile binning).
///
/// # Panics
///
/// Panics if `data` is empty or `num_bins` is `0`.
///
/// # Example
///
/// ```rust
/// use rune_bin::adaptive_bins;
///
/// let data: Vec<f64> = (0..100).map(|i| i as f64).collect();
/// let hist = adaptive_bins(&data, 4);
/// assert_eq!(hist.counts.iter().sum::<usize>(), 100);
/// ```
#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss,
    reason = "the value is non-negative and bounded by the input size; float-to-int `as` saturates"
)]
#[must_use]
pub fn adaptive_bins(data: &[f64], num_bins: usize) -> Histogram {
    assert!(!data.is_empty(), "data must not be empty");
    assert!(num_bins > 0, "num_bins must be at least 1");

    let mut sorted = data.to_vec();
    sorted.sort_by(f64::total_cmp);

    let n = sorted.len();
    let min = sorted[0];
    let max = sorted[n - 1];

    // Quantile-based edges; dedup identical edges when data has heavy ties or
    // fewer distinct values than requested bins.
    let mut bin_edges: Vec<f64> = (0..=num_bins)
        .map(|i| {
            if i == 0 {
                min
            } else if i == num_bins {
                max
            } else {
                let rank = (i as f64 / num_bins as f64) * (n - 1) as f64;
                let lo = rank.floor() as usize;
                let hi = rank.ceil() as usize;
                let frac = rank - lo as f64;
                (sorted[hi] - sorted[lo]).mul_add(frac, sorted[lo])
            }
        })
        .collect();
    bin_edges.dedup();

    let effective_bins = bin_edges.len() - 1;
    let mut counts = vec![0usize; effective_bins.max(1)];

    if effective_bins == 0 {
        // All data identical: single degenerate bin containing everything.
        counts[0] = n;
        return Histogram {
            bin_edges: vec![min, max.max(min + 1.0)],
            counts,
        };
    }

    for &value in &sorted {
        let mut index = match bin_edges.binary_search_by(|edge| edge.total_cmp(&value)) {
            Ok(i) => i,
            Err(i) => i.saturating_sub(1),
        };
        index = index.min(effective_bins - 1);
        counts[index] += 1;
    }

    Histogram { bin_edges, counts }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_bins_known_dataset() {
        let data = vec![0.0, 1.0, 2.0, 3.0];
        let hist = fixed_bins(&data, 2);
        assert_eq!(hist.bin_edges, vec![0.0, 1.5, 3.0]);
        assert_eq!(hist.counts, vec![2, 2]);
    }

    #[test]
    fn fixed_bins_accounts_for_all_points() {
        let data: Vec<f64> = (0..97).map(|i| f64::from(i) * 0.37).collect();
        let hist = fixed_bins(&data, 9);
        assert_eq!(hist.counts.iter().sum::<usize>(), data.len());
    }

    #[test]
    fn fixed_bins_max_value_in_last_bin() {
        let data = vec![0.0, 5.0, 10.0];
        let hist = fixed_bins(&data, 5);
        assert_eq!(hist.counts.iter().sum::<usize>(), 3);
        assert_eq!(*hist.counts.last().unwrap(), 1);
    }

    #[test]
    fn fixed_bins_single_value_dataset_does_not_panic() {
        let data = vec![5.0, 5.0, 5.0];
        let hist = fixed_bins(&data, 3);
        assert_eq!(hist.counts.iter().sum::<usize>(), 3);
    }

    #[test]
    fn adaptive_bins_accounts_for_all_points() {
        let data: Vec<f64> = (0..100).map(f64::from).collect();
        let hist = adaptive_bins(&data, 7);
        assert_eq!(hist.counts.iter().sum::<usize>(), 100);
    }

    #[allow(
        clippy::cast_possible_wrap,
        reason = "lengths and lags stay far below 2^52 and i64::MAX"
    )]
    #[test]
    fn adaptive_bins_balances_skewed_distribution() {
        // Heavily skewed: 90 points clustered near 0, 10 points spread out to 1000.
        let mut data: Vec<f64> = (0..90).map(|i| f64::from(i) * 0.01).collect();
        data.extend((0..10).map(|i| f64::mul_add(f64::from(i), 100.0, 100.0)));

        let fixed = fixed_bins(&data, 5);
        let adaptive = adaptive_bins(&data, 5);

        // Fixed-width binning on this data leaves at least one bin empty or
        // wildly overloaded relative to an even split of 20 per bin.
        let fixed_max = *fixed.counts.iter().max().unwrap();
        assert!(
            fixed_max > 40,
            "fixed bins should be unbalanced on skewed data"
        );

        // Adaptive binning should keep every bin within a reasonable band of the
        // ideal 20-per-bin split (100 points / 5 bins).
        for &count in &adaptive.counts {
            assert!(
                (count as i64 - 20).abs() <= 15,
                "adaptive bin count {count} too far from balanced"
            );
        }
    }

    #[test]
    fn adaptive_bins_single_value_dataset_does_not_panic() {
        let data = vec![7.0, 7.0, 7.0, 7.0];
        let hist = adaptive_bins(&data, 4);
        assert_eq!(hist.counts.iter().sum::<usize>(), 4);
    }

    #[test]
    #[should_panic(expected = "data must not be empty")]
    fn fixed_bins_rejects_empty_data() {
        fixed_bins(&[], 3);
    }
}
