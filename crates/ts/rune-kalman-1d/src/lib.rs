//! A scalar (1-dimensional) Kalman filter for smoothing a single noisy signal.
//!
//! Tracks one hidden state — the true value of the signal — with a Gaussian
//! belief (`estimate`, `error_covariance`). Each [`Kalman1D::update`] call runs
//! the standard predict step (grow uncertainty by `process_variance`) followed
//! by the correct step (blend the new measurement in, weighted by how
//! trustworthy the measurement is relative to the current belief).
//!
//! # Features
//!
//! - [`Kalman1D`] — O(1) memory and time per update, no matrices needed since
//!   the state is scalar.
//!
//! # Quick Start
//!
//! ```rust
//! use rune_kalman_1d::Kalman1D;
//!
//! let mut kalman = Kalman1D::new(0.001, 1.0, 0.0, 1.0);
//! for _ in 0..20 {
//!     kalman.update(10.0);
//! }
//! assert!((kalman.estimate() - 10.0).abs() < 0.5);
//! ```
//!
//! # CLI
//!
//! ```bash
//! rune-kalman-1d --process-variance 0.001 --measurement-variance 1.0 9.8 10.2 9.9 10.1
//! ```

/// A scalar Kalman filter.
pub struct Kalman1D {
    process_variance: f64,
    measurement_variance: f64,
    estimate: f64,
    error_covariance: f64,
}

impl Kalman1D {
    /// Creates a new filter.
    ///
    /// - `process_variance` — how much the true value is expected to drift between
    ///   updates. Larger values make the filter trust new measurements more.
    /// - `measurement_variance` — how noisy the sensor is. Larger values make the
    ///   filter trust new measurements less.
    /// - `initial_estimate` / `initial_error_covariance` — the starting belief and
    ///   its uncertainty.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_kalman_1d::Kalman1D;
    ///
    /// let kalman = Kalman1D::new(0.01, 1.0, 0.0, 1.0);
    /// assert_eq!(kalman.estimate(), 0.0);
    /// ```
    #[must_use]
    pub const fn new(
        process_variance: f64,
        measurement_variance: f64,
        initial_estimate: f64,
        initial_error_covariance: f64,
    ) -> Self {
        Self {
            process_variance,
            measurement_variance,
            estimate: initial_estimate,
            error_covariance: initial_error_covariance,
        }
    }

    /// The current state estimate.
    #[must_use]
    pub const fn estimate(&self) -> f64 {
        self.estimate
    }

    /// The current estimate's error covariance (uncertainty).
    #[must_use]
    pub const fn error_covariance(&self) -> f64 {
        self.error_covariance
    }

    /// Runs one predict+update cycle against a new measurement, and returns the
    /// updated estimate.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_kalman_1d::Kalman1D;
    ///
    /// let mut kalman = Kalman1D::new(0.01, 4.0, 0.0, 1.0);
    /// let estimate = kalman.update(10.0);
    /// assert!(estimate > 0.0 && estimate < 10.0);
    /// ```
    pub fn update(&mut self, measurement: f64) -> f64 {
        // Predict: uncertainty grows by the process variance.
        self.error_covariance += self.process_variance;

        // Update: blend the measurement in, weighted by the Kalman gain.
        let kalman_gain =
            self.error_covariance / (self.error_covariance + self.measurement_variance);
        self.estimate = kalman_gain.mul_add(measurement - self.estimate, self.estimate);
        self.error_covariance *= 1.0 - kalman_gain;

        self.estimate
    }
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
    fn converges_on_repeated_identical_measurements() {
        let mut kalman = Kalman1D::new(0.01, 1.0, 0.0, 1.0);
        let mut last = 0.0;
        // Steady-state gain here is ~0.1, so error decays by ~10%/step; need
        // several hundred iterations, not 50, to get within 1e-3 of the true value.
        for _ in 0..500 {
            last = kalman.update(5.0);
        }
        assert!((last - 5.0).abs() < 1e-3, "last={last}");
    }

    #[test]
    fn converges_near_true_value_with_noisy_measurements() {
        let true_value = 20.0;
        let noisy = [19.5, 20.8, 19.2, 20.5, 19.9, 20.3, 19.7, 20.1, 20.0, 19.8];
        let mut kalman = Kalman1D::new(0.01, 1.0, 0.0, 10.0);
        let mut last = 0.0;
        for &m in &noisy {
            last = kalman.update(m);
        }
        assert!((last - true_value).abs() < 1.0, "estimate={last}");
    }

    #[test]
    fn reduces_variance_relative_to_raw_measurements() {
        let noisy = [19.5, 20.8, 19.2, 20.5, 19.9, 20.3, 19.7, 20.1, 20.0, 19.8];
        let mut kalman = Kalman1D::new(0.01, 1.0, 20.0, 1.0);
        let filtered: Vec<f64> = noisy.iter().map(|&m| kalman.update(m)).collect();
        assert!(variance(&filtered) < variance(&noisy));
    }

    #[test]
    fn high_measurement_variance_moves_slowly() {
        let mut kalman = Kalman1D::new(0.001, 1000.0, 0.0, 1.0);
        let estimate = kalman.update(100.0);
        assert!(estimate.abs() < 1.0, "estimate={estimate}");
    }

    #[test]
    fn low_measurement_variance_converges_fast() {
        let mut kalman = Kalman1D::new(0.001, 0.0001, 0.0, 1.0);
        let estimate = kalman.update(100.0);
        assert!(estimate > 90.0, "estimate={estimate}");
    }

    #[test]
    fn error_covariance_shrinks_after_updates() {
        let mut kalman = Kalman1D::new(0.001, 1.0, 0.0, 10.0);
        let initial = kalman.error_covariance();
        kalman.update(1.0);
        assert!(kalman.error_covariance() < initial);
    }
}
