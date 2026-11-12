//! Single-pole low-pass and high-pass digital filters for noisy scalar signals.
//!
//! Both filters are the standard single-pole (first-order) RC-style IIR
//! filters used for lightweight real-time smoothing: O(1) memory, O(1) time
//! per sample, no lookahead.
//!
//! # Features
//!
//! - [`LowPassFilter`] — `y[n] = alpha*x[n] + (1-alpha)*y[n-1]`.
//! - [`HighPassFilter`] — `y[n] = alpha*(y[n-1] + x[n] - x[n-1])`, the standard
//!   single-pole high-pass difference equation (complementary to the low-pass
//!   form above).
//! - [`cutoff_to_alpha`] — converts a desired cutoff frequency and sample rate
//!   into the equivalent `alpha`.
//!
//! # Quick Start
//!
//! ```rust
//! use rune_lowpass::{LowPassFilter, cutoff_to_alpha};
//!
//! let alpha = cutoff_to_alpha(2.0, 100.0);
//! let mut filter = LowPassFilter::new(alpha);
//! let smoothed: Vec<f64> = [1.0, 5.0, 1.0, 5.0, 1.0].iter().map(|&x| filter.apply(x)).collect();
//! assert!(smoothed[4] < 5.0);
//! ```
//!
//! # CLI
//!
//! ```bash
//! rune-lowpass --alpha 0.2 1.0 5.0 1.0 5.0 1.0
//! rune-lowpass --alpha 0.2 --high-pass 1.0 5.0 1.0 5.0 1.0
//! ```

/// Single-pole low-pass filter: `y[n] = alpha*x[n] + (1-alpha)*y[n-1]`.
pub struct LowPassFilter {
    alpha: f64,
    prev: Option<f64>,
}

impl LowPassFilter {
    /// Creates a new filter with smoothing factor `alpha` in `(0.0, 1.0]`. Smaller
    /// `alpha` means heavier smoothing (lower cutoff).
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_lowpass::LowPassFilter;
    ///
    /// let filter = LowPassFilter::new(0.3);
    /// ```
    #[must_use]
    pub const fn new(alpha: f64) -> Self {
        Self { alpha, prev: None }
    }

    /// Filters one sample and returns the smoothed output. The first call returns
    /// `x` unchanged (there is no prior output to blend with).
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_lowpass::LowPassFilter;
    ///
    /// let mut filter = LowPassFilter::new(0.5);
    /// assert_eq!(filter.apply(10.0), 10.0);
    /// assert_eq!(filter.apply(20.0), 15.0);
    /// ```
    pub fn apply(&mut self, x: f64) -> f64 {
        let y = match self.prev {
            None => x,
            Some(prev) => (1.0 - self.alpha).mul_add(prev, self.alpha * x),
        };
        self.prev = Some(y);
        y
    }
}

/// Single-pole high-pass filter: `y[n] = alpha*(y[n-1] + x[n] - x[n-1])`.
pub struct HighPassFilter {
    alpha: f64,
    prev_input: Option<f64>,
    prev_output: f64,
}

impl HighPassFilter {
    /// Creates a new filter with smoothing factor `alpha` in `(0.0, 1.0]`. Larger
    /// `alpha` retains more high-frequency content.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_lowpass::HighPassFilter;
    ///
    /// let filter = HighPassFilter::new(0.9);
    /// ```
    #[must_use]
    pub const fn new(alpha: f64) -> Self {
        Self {
            alpha,
            prev_input: None,
            prev_output: 0.0,
        }
    }

    /// Filters one sample and returns the high-pass output. The first call returns
    /// `0.0` (no prior sample to take a difference against).
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_lowpass::HighPassFilter;
    ///
    /// let mut filter = HighPassFilter::new(0.5);
    /// assert_eq!(filter.apply(10.0), 0.0);
    /// ```
    pub fn apply(&mut self, x: f64) -> f64 {
        let y = match self.prev_input {
            None => 0.0,
            Some(prev_x) => self.alpha * (self.prev_output + x - prev_x),
        };
        self.prev_input = Some(x);
        self.prev_output = y;
        y
    }
}

/// Converts a cutoff frequency (Hz) and sample rate (Hz) into a filter `alpha`.
///
/// Uses the standard RC-circuit approximation for a single-pole filter:
/// `dt = 1/sample_rate`, `rc = 1/(2*pi*cutoff)`, `alpha = dt/(rc+dt)`.
///
/// # Example
///
/// ```rust
/// use rune_lowpass::cutoff_to_alpha;
///
/// let alpha = cutoff_to_alpha(10.0, 1000.0);
/// assert!(alpha > 0.0 && alpha < 1.0);
/// ```
#[must_use]
pub fn cutoff_to_alpha(cutoff_hz: f64, sample_rate_hz: f64) -> f64 {
    let dt = 1.0 / sample_rate_hz;
    let rc = 1.0 / (2.0 * std::f64::consts::PI * cutoff_hz);
    dt / (rc + dt)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[allow(
        clippy::cast_precision_loss,
        reason = "counts and indices stay far below 2^52, so the f64 conversion is exact"
    )]
    fn variance(xs: &[f64]) -> f64 {
        let mean = xs.iter().sum::<f64>() / xs.len() as f64;
        xs.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / xs.len() as f64
    }

    #[test]
    fn lowpass_constant_input_settles_to_constant() {
        let mut filter = LowPassFilter::new(0.3);
        let mut last = 0.0;
        for _ in 0..50 {
            last = filter.apply(7.0);
        }
        assert!((last - 7.0).abs() < 1e-9);
    }

    #[test]
    fn lowpass_reduces_variance_of_alternating_signal() {
        let input: Vec<f64> = (0..100)
            .map(|i| if i % 2 == 0 { 0.0 } else { 10.0 })
            .collect();
        let mut filter = LowPassFilter::new(0.1);
        let output: Vec<f64> = input.iter().map(|&x| filter.apply(x)).collect();
        assert!(variance(&output[10..]) < variance(&input[10..]));
    }

    #[test]
    fn highpass_constant_input_converges_to_zero() {
        let mut filter = HighPassFilter::new(0.5);
        let mut last = 1.0;
        for _ in 0..50 {
            last = filter.apply(7.0);
        }
        assert!(last.abs() < 1e-9);
    }

    #[test]
    fn highpass_first_sample_is_zero() {
        let mut filter = HighPassFilter::new(0.5);
        assert_eq!(filter.apply(100.0), 0.0);
    }

    #[test]
    fn cutoff_to_alpha_in_valid_range() {
        let alpha = cutoff_to_alpha(5.0, 100.0);
        assert!(alpha > 0.0 && alpha < 1.0);
    }

    #[test]
    fn cutoff_to_alpha_matches_formula() {
        let cutoff = 10.0;
        let rate = 1000.0;
        let dt = 1.0 / rate;
        let rc = 1.0 / (2.0 * std::f64::consts::PI * cutoff);
        let expected = dt / (rc + dt);
        assert!((cutoff_to_alpha(cutoff, rate) - expected).abs() < 1e-12);
    }

    #[test]
    fn higher_cutoff_yields_larger_alpha() {
        let low = cutoff_to_alpha(1.0, 1000.0);
        let high = cutoff_to_alpha(50.0, 1000.0);
        assert!(high > low);
    }
}
