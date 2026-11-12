//! Classical additive/multiplicative seasonal decomposition.
//!
//! Splits a series into trend, seasonal, and residual components: trend via a
//! centered moving average of the given `period`, seasonal as the average
//! detrended value at each phase of the period, and residual as whatever's left.
//! The same technique behind R's `decompose()` and statsmodels'
//! `seasonal_decompose`.
//!
//! # Features
//!
//! - [`decompose`] — additive (`series = trend + seasonal + residual`) or
//!   multiplicative (`series = trend * seasonal * residual`) decomposition.
//! - Edge points where the centered moving average isn't defined are `NaN` in the
//!   trend and residual (there aren't enough neighbors to center a window there).
//!
//! # Quick Start
//!
//! ```rust
//! use rune_season_decomp::{decompose, DecompMode};
//!
//! let series = [10.0, 20.0, 10.0, 20.0, 10.0, 20.0, 10.0, 20.0];
//! let result = decompose(&series, 2, DecompMode::Additive);
//! assert_eq!(result.seasonal.len(), series.len());
//! ```
//!
//! # CLI
//!
//! ```bash
//! rune-season-decomp --series "10,20,10,20,10,20" --period 2 --mode additive
//! ```

/// Whether the series is modeled as `trend + seasonal + residual` or
/// `trend * seasonal * residual`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecompMode {
    /// `value = trend + seasonal + residual`.
    Additive,
    /// `value = trend * seasonal * residual`.
    Multiplicative,
}

/// The three components produced by [`decompose`], each the same length as the input.
#[derive(Debug, Clone, PartialEq)]
pub struct Decomposition {
    /// Centered moving average. `NaN` at the edges where the window doesn't fit.
    pub trend: Vec<f64>,
    /// Average detrended value at this index's phase within the period, repeating.
    pub seasonal: Vec<f64>,
    /// What's left after removing trend and seasonal. `NaN` wherever trend is `NaN`.
    pub residual: Vec<f64>,
}

#[allow(
    clippy::cast_precision_loss,
    reason = "counts and indices stay far below 2^52, so the f64 conversion is exact"
)]
fn centered_moving_average(series: &[f64], period: usize) -> Vec<f64> {
    let n = series.len();
    let mut trend = vec![f64::NAN; n];
    if period == 0 || period > n {
        return trend;
    }

    let half = period / 2;
    if half >= n.saturating_sub(half) {
        return trend;
    }

    if period.is_multiple_of(2) {
        // 2xperiod moving average: average of two period-length windows offset by one,
        // which centers an even-width window on integer indices.
        for i in half..(n - half) {
            let w1: f64 = series[i - half..i - half + period].iter().sum::<f64>() / period as f64;
            let w2: f64 = series[i - half + 1..i - half + 1 + period]
                .iter()
                .sum::<f64>()
                / period as f64;
            trend[i] = f64::midpoint(w1, w2);
        }
    } else {
        for i in half..(n - half) {
            let window = &series[i - half..=i + half];
            trend[i] = window.iter().sum::<f64>() / period as f64;
        }
    }

    trend
}

/// Decomposes `series` into trend, seasonal, and residual components using a
/// centered moving average of width `period`.
///
/// # Panics
///
/// Does not panic; returns `NaN`-filled trend/residual and a zero/one-filled
/// seasonal component if `period` is `0` or exceeds the series length.
///
/// # Example
///
/// ```rust
/// use rune_season_decomp::{decompose, DecompMode};
///
/// let series = [1.0, 2.0, 1.0, 2.0, 1.0, 2.0];
/// let result = decompose(&series, 2, DecompMode::Additive);
/// // The seasonal component averages to ~0 across a full period, by construction.
/// let period_sum: f64 = result.seasonal[..2].iter().sum();
/// assert!(period_sum.abs() < 1e-9);
/// ```
#[allow(
    clippy::cast_precision_loss,
    reason = "counts and indices stay far below 2^52, so the f64 conversion is exact"
)]
#[must_use]
pub fn decompose(series: &[f64], period: usize, mode: DecompMode) -> Decomposition {
    let n = series.len();
    let trend = centered_moving_average(series, period);
    let effective_period = period.max(1);

    let mut detrended = vec![f64::NAN; n];
    for i in 0..n {
        if !trend[i].is_nan() {
            detrended[i] = match mode {
                DecompMode::Additive => series[i] - trend[i],
                DecompMode::Multiplicative => series[i] / trend[i],
            };
        }
    }

    let mut phase_sums = vec![0.0; effective_period];
    let mut phase_counts = vec![0usize; effective_period];
    for (i, &d) in detrended.iter().enumerate() {
        if !d.is_nan() {
            let phase = i % effective_period;
            phase_sums[phase] += d;
            phase_counts[phase] += 1;
        }
    }

    let neutral = match mode {
        DecompMode::Additive => 0.0,
        DecompMode::Multiplicative => 1.0,
    };
    let mut phase_avg: Vec<f64> = phase_sums
        .iter()
        .zip(&phase_counts)
        .map(|(&sum, &count)| {
            if count > 0 {
                sum / count as f64
            } else {
                neutral
            }
        })
        .collect();

    let overall = phase_avg.iter().sum::<f64>() / phase_avg.len() as f64;
    match mode {
        DecompMode::Additive => {
            for v in &mut phase_avg {
                *v -= overall;
            }
        }
        DecompMode::Multiplicative => {
            if overall != 0.0 {
                for v in &mut phase_avg {
                    *v /= overall;
                }
            }
        }
    }

    let seasonal: Vec<f64> = (0..n).map(|i| phase_avg[i % effective_period]).collect();

    let residual: Vec<f64> = (0..n)
        .map(|i| {
            if trend[i].is_nan() {
                f64::NAN
            } else {
                match mode {
                    DecompMode::Additive => series[i] - trend[i] - seasonal[i],
                    DecompMode::Multiplicative => series[i] / trend[i] / seasonal[i],
                }
            }
        })
        .collect();

    Decomposition {
        trend,
        seasonal,
        residual,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[allow(
        clippy::cast_precision_loss,
        reason = "counts and indices stay far below 2^52, so the f64 conversion is exact"
    )]
    #[test]
    fn additive_reconstruction_of_synthetic_series() {
        // trend = 10 + i, seasonal pattern = [5, -5] repeating.
        let seasonal_pattern = [5.0, -5.0];
        let series: Vec<f64> = (0..20)
            .map(|i| 10.0 + i as f64 + seasonal_pattern[i % 2])
            .collect();

        let result = decompose(&series, 2, DecompMode::Additive);

        for i in 4..16 {
            assert!(
                (result.trend[i] - (10.0 + i as f64)).abs() < 1.0,
                "trend[{i}]={} expected ~{}",
                result.trend[i],
                10.0 + i as f64
            );
        }
        assert!((result.seasonal[0] - 5.0).abs() < 1.0);
        assert!((result.seasonal[1] - (-5.0)).abs() < 1.0);
    }

    #[allow(
        clippy::cast_precision_loss,
        reason = "counts and indices stay far below 2^52, so the f64 conversion is exact"
    )]
    #[test]
    fn multiplicative_reconstruction_of_synthetic_series() {
        let seasonal_pattern = [1.5, 0.5];
        let series: Vec<f64> = (0..20)
            .map(|i| (10.0 + i as f64) * seasonal_pattern[i % 2])
            .collect();

        let result = decompose(&series, 2, DecompMode::Multiplicative);

        for i in 4..16 {
            let expected = 10.0 + i as f64;
            assert!(
                (result.trend[i] - expected).abs() / expected < 0.1,
                "trend[{i}]={} expected ~{expected}",
                result.trend[i]
            );
        }
        assert!((result.seasonal[0] - 1.5).abs() < 0.1);
        assert!((result.seasonal[1] - 0.5).abs() < 0.1);
    }

    #[test]
    fn seasonal_averages_to_zero_additive() {
        let series: Vec<f64> = (0..24)
            .map(|i| f64::mul_add(f64::from(i), 0.1, (f64::from(i) * 0.3).sin()))
            .collect();
        let result = decompose(&series, 4, DecompMode::Additive);
        let period_sum: f64 = result.seasonal[..4].iter().sum();
        assert!(period_sum.abs() < 1e-6, "seasonal sum was {period_sum}");
    }

    #[test]
    fn seasonal_averages_to_one_multiplicative() {
        let series: Vec<f64> = (1..=24)
            .map(|i| f64::from(i) + (f64::from(i) * 0.5).sin())
            .collect();
        let result = decompose(&series, 4, DecompMode::Multiplicative);
        let period_avg: f64 = result.seasonal[..4].iter().sum::<f64>() / 4.0;
        assert!(
            (period_avg - 1.0).abs() < 1e-6,
            "seasonal avg was {period_avg}"
        );
    }

    #[test]
    fn period_one_is_trivial() {
        let series = [1.0, 2.0, 3.0, 4.0, 5.0];
        let result = decompose(&series, 1, DecompMode::Additive);
        for (i, &x) in series.iter().enumerate() {
            assert!((result.trend[i] - x).abs() < 1e-9);
            assert!(result.seasonal[i].abs() < 1e-9);
            assert!(result.residual[i].abs() < 1e-9);
        }
    }

    #[test]
    fn period_larger_than_series_yields_nan_trend() {
        let series = [1.0, 2.0, 3.0];
        let result = decompose(&series, 10, DecompMode::Additive);
        assert!(result.trend.iter().all(|v| v.is_nan()));
    }

    #[test]
    fn odd_period_trend_matches_hand_computed_centered_average() {
        let series = [1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0];
        let result = decompose(&series, 3, DecompMode::Additive);
        // Centered 3-average at index 3 (value 4.0) is mean(3,4,5) = 4.0.
        assert!((result.trend[3] - 4.0).abs() < 1e-9);
        assert!(result.trend[0].is_nan());
        assert!(result.trend[6].is_nan());
    }
}
