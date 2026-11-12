//! Exponentially weighted moving average over a numeric stream.
//!
//! An EWMA gives more weight to recent observations than a simple moving
//! average, without needing to keep a window of past values around: each
//! update only needs the previous EWMA value and the smoothing factor `alpha`.
//!
//! # Features
//!
//! - [`Ewma`] — an incremental, O(1)-per-update EWMA accumulator.
//! - [`alpha_from_span`] — converts a "span" (roughly, how many recent points
//!   dominate the average) into the equivalent `alpha`, matching the
//!   convention used by pandas' `.ewm(span=...)`.
//!
//! # Quick Start
//!
//! ```rust
//! use rune_ewma::Ewma;
//!
//! let mut ewma = Ewma::new(0.5);
//! assert_eq!(ewma.update(10.0), 10.0); // first update seeds the value
//! assert_eq!(ewma.update(20.0), 15.0); // 0.5*20 + 0.5*10
//! ```
//!
//! # CLI
//!
//! ```bash
//! rune-ewma 0.3 10 12 11 15 20
//! ```

/// Incremental exponentially weighted moving average.
///
/// Construct with [`Ewma::new`], then call [`Ewma::update`] for each new
/// observation.
pub struct Ewma {
    alpha: f64,
    value: Option<f64>,
}

impl Ewma {
    /// Creates a new `Ewma` with smoothing factor `alpha`.
    ///
    /// `alpha` must lie in `(0.0, 1.0]`; values closer to `1.0` track new
    /// observations more closely, values closer to `0.0` smooth more
    /// aggressively. Out-of-range values are clamped into `(0.0, 1.0]`
    /// rather than panicking, so a caller-supplied configuration value
    /// can never crash the pipeline. A `NaN` alpha is treated as `1.0`
    /// (no smoothing) so it cannot poison every later output.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_ewma::Ewma;
    ///
    /// let ewma = Ewma::new(0.2);
    /// assert_eq!(ewma.value(), None);
    /// ```
    #[must_use]
    pub const fn new(alpha: f64) -> Self {
        let alpha = if alpha.is_nan() {
            1.0
        } else {
            alpha.clamp(f64::EPSILON, 1.0)
        };
        Self { alpha, value: None }
    }

    /// Feeds one new observation and returns the updated EWMA value.
    ///
    /// The first call seeds the average with `x` exactly (there is no prior
    /// history to blend against).
    ///
    /// A `NaN` observation is treated as missing: the state is left unchanged
    /// and the current value is returned (`NaN` if nothing has been seen yet).
    /// This matches pandas' `ewm(adjust=False, ignore_na=True)` and keeps one
    /// missing sample from poisoning the average forever.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_ewma::Ewma;
    ///
    /// let mut ewma = Ewma::new(0.5);
    /// assert_eq!(ewma.update(4.0), 4.0);
    /// assert_eq!(ewma.update(8.0), 6.0);
    /// ```
    pub fn update(&mut self, x: f64) -> f64 {
        if x.is_nan() {
            return self.value.unwrap_or(f64::NAN);
        }
        let updated = match self.value {
            None => x,
            Some(prev) => (1.0 - self.alpha).mul_add(prev, self.alpha * x),
        };
        self.value = Some(updated);
        updated
    }

    /// Returns the current EWMA value, or `None` if [`update`](Ewma::update)
    /// has never been called.
    #[must_use]
    pub const fn value(&self) -> Option<f64> {
        self.value
    }
}

/// Converts a "span" (the pandas-style parameter: roughly how many recent
/// points dominate the average) into the equivalent smoothing factor `alpha`,
/// via `alpha = 2 / (span + 1)`.
///
/// # Example
///
/// ```rust
/// use rune_ewma::alpha_from_span;
///
/// assert!((alpha_from_span(9.0) - 0.2).abs() < 1e-9);
/// ```
#[must_use]
pub fn alpha_from_span(span: f64) -> f64 {
    2.0 / (span + 1.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_update_seeds_exactly() {
        let mut ewma = Ewma::new(0.3);
        assert_eq!(ewma.update(42.0), 42.0);
        assert_eq!(ewma.value(), Some(42.0));
    }

    #[test]
    fn known_sequence_hand_computed() {
        let mut ewma = Ewma::new(0.5);
        assert_eq!(ewma.update(10.0), 10.0);
        assert_eq!(ewma.update(20.0), 15.0);
        assert_eq!(ewma.update(10.0), 12.5);
    }

    #[test]
    fn alpha_near_one_tracks_input_closely() {
        let mut ewma = Ewma::new(0.999);
        ewma.update(0.0);
        let value = ewma.update(100.0);
        assert!((value - 100.0).abs() < 0.2);
    }

    #[test]
    fn alpha_near_zero_barely_moves() {
        let mut ewma = Ewma::new(0.001);
        ewma.update(0.0);
        let value = ewma.update(100.0);
        assert!(value < 1.0);
    }

    #[test]
    fn alpha_from_span_matches_standard_formula() {
        assert!((alpha_from_span(9.0) - 0.2).abs() < 1e-9);
        assert!((alpha_from_span(19.0) - 0.1).abs() < 1e-9);
        assert!((alpha_from_span(1.0) - 1.0).abs() < 1e-9);
    }

    #[test]
    fn alpha_is_clamped_into_range() {
        let mut ewma_low = Ewma::new(0.0);
        assert!(ewma_low.update(1.0).is_finite());

        let mut ewma_high = Ewma::new(5.0);
        ewma_high.update(1.0);
        assert_eq!(ewma_high.update(2.0), 2.0);
    }

    /// Reference: pandas `Series([1, 2, 3, 4, 5]).ewm(alpha=0.5, adjust=False).mean()`.
    #[test]
    fn matches_pandas_adjust_false_reference() {
        let mut ewma = Ewma::new(0.5);
        let got: Vec<f64> = [1.0, 2.0, 3.0, 4.0, 5.0]
            .iter()
            .map(|&x| ewma.update(x))
            .collect();
        assert_eq!(got, [1.0, 1.5, 2.25, 3.125, 4.0625]);
    }

    /// Reference: pandas `Series([10, 20, 30]).ewm(span=3, adjust=False).mean()`
    /// (span 3 gives alpha 0.5).
    #[test]
    fn span_based_reference() {
        let mut ewma = Ewma::new(alpha_from_span(3.0));
        let got: Vec<f64> = [10.0, 20.0, 30.0].iter().map(|&x| ewma.update(x)).collect();
        assert_eq!(got, [10.0, 15.0, 22.5]);
    }

    #[test]
    fn constant_series_is_a_fixed_point() {
        let mut ewma = Ewma::new(0.37);
        for _ in 0..1000 {
            assert!((ewma.update(7.25) - 7.25).abs() < 1e-12);
        }
    }

    #[test]
    fn output_stays_within_input_range() {
        let data = [3.0, -1.0, 8.0, 2.5, 0.0, 7.0, -4.0, 6.0];
        let mut ewma = Ewma::new(0.3);
        for &x in &data {
            let v = ewma.update(x);
            assert!((-4.0..=8.0).contains(&v), "{v} escaped the input range");
        }
    }

    /// Regression: a `NaN` sample used to poison every later output.
    #[test]
    fn nan_observation_is_skipped() {
        let mut ewma = Ewma::new(0.5);
        assert!(ewma.update(f64::NAN).is_nan());
        assert_eq!(ewma.value(), None);
        assert_eq!(ewma.update(10.0), 10.0);
        assert_eq!(ewma.update(f64::NAN), 10.0);
        assert_eq!(ewma.update(20.0), 15.0);
    }

    /// Regression: `Ewma::new(NaN)` used to produce `NaN` for every update after the first.
    #[test]
    fn nan_alpha_falls_back_to_no_smoothing() {
        let mut ewma = Ewma::new(f64::NAN);
        ewma.update(1.0);
        assert_eq!(ewma.update(2.0), 2.0);
    }

    #[test]
    fn value_is_none_before_first_update() {
        let ewma = Ewma::new(0.5);
        assert_eq!(ewma.value(), None);
    }
}
