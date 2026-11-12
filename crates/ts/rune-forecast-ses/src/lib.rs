//! Exponential smoothing forecasters: simple exponential smoothing, Holt's
//! linear and damped trend methods, and Holt-Winters with additive or
//! multiplicative seasonality.
//!
//! Two layers are provided:
//!
//! - Streaming smoothers with fixed parameters: [`SimpleExpSmoothing`] (flat
//!   forecast) and [`DoubleExpSmoothing`] (Holt's linear method). Feed values
//!   one at a time, no fitting.
//! - Fitted models: [`Model`] covers the additive-error exponential
//!   smoothing family (trend none/additive/damped, seasonality
//!   none/additive/multiplicative). [`Model::fit`] estimates the smoothing
//!   parameters and initial states by minimising the sum of squared
//!   one-step errors, [`Fit::forecast_intervals`] gives prediction
//!   intervals, and [`Auto`] picks the best model by `AICc` (or AIC/BIC).
//!
//! The model equations follow Hyndman & Athanasopoulos, *Forecasting:
//! Principles and Practice* (2nd ed.), chapter 7. Estimates match the
//! textbook's worked examples (which come from R's `forecast` package) to
//! about three significant figures; see the tests.
//!
//! Estimation: for models without multiplicative seasonality the one-step
//! errors are affine in the initial state, so the initial state is solved
//! exactly by least squares and a coarse grid plus bounded Nelder-Mead
//! searches only the smoothing parameters. Multiplicative models search
//! parameters and initial states together. Estimated parameters are kept in
//! `[0.0001, 0.9999]`, with `gamma <= 1 - alpha` and `0.8 <= phi <= 0.98`.
//!
//! # Quick Start
//!
//! ```rust
//! use rune_forecast_ses::{Auto, Model, Seasonal};
//!
//! // Quarterly data with trend and a fixed seasonal pattern.
//! let y: Vec<f64> = (0..32)
//!     .map(|t| 20.0 + 0.8 * f64::from(t) + [6.0, -2.0, -7.0, 3.0][t as usize % 4])
//!     .collect();
//!
//! let fit = Model::holt_winters(Seasonal::Additive, 4).fit(&y)?;
//! let next_year = fit.forecast_intervals(4, 0.95)?;
//! assert_eq!(next_year.len(), 4);
//!
//! // Or let the information criterion decide.
//! let best = Auto::new().period(4).fit(&y)?;
//! println!("{} AICc={:.1}", best.model(), best.aicc());
//! # Ok::<(), rune_forecast_ses::Error>(())
//! ```
//!
//! Streaming smoother with a fixed `alpha`:
//!
//! ```rust
//! use rune_forecast_ses::SimpleExpSmoothing;
//!
//! let mut ses = SimpleExpSmoothing::new(0.5);
//! ses.update(10.0);
//! ses.update(10.0);
//! ses.update(10.0);
//! let forecast = ses.forecast(3);
//! assert_eq!(forecast.len(), 3);
//! assert!((forecast[0] - 10.0).abs() < 1e-9);
//! ```
//!
//! # CLI
//!
//! ```bash
//! rune-forecast-ses --alpha 0.3 --steps 5 10 12 11 15 20
//! rune-forecast-ses --alpha 0.3 --beta 0.2 --steps 5 10 12 11 15 20
//! rune-forecast-ses --model auto --period 4 --level 0.95 --steps 4 <values...>
//! ```

mod dist;
mod ets;
mod optim;

pub use ets::{Auto, Criterion, Error, Fit, Interval, Model, Params, Seasonal, Trend};

/// Simple exponential smoothing: a single smoothed level, forecast flat.
pub struct SimpleExpSmoothing {
    alpha: f64,
    level: Option<f64>,
}

impl SimpleExpSmoothing {
    /// Creates a new `SimpleExpSmoothing` with smoothing factor `alpha` in `(0.0, 1.0]`.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_forecast_ses::SimpleExpSmoothing;
    ///
    /// let ses = SimpleExpSmoothing::new(0.3);
    /// assert!(ses.level().is_none());
    /// ```
    #[must_use]
    pub const fn new(alpha: f64) -> Self {
        Self { alpha, level: None }
    }

    /// Current smoothed level, or `None` before the first observation.
    #[must_use]
    pub const fn level(&self) -> Option<f64> {
        self.level
    }

    /// Feeds one observation and returns the updated level.
    ///
    /// The first call seeds the level directly with `x`.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_forecast_ses::SimpleExpSmoothing;
    ///
    /// let mut ses = SimpleExpSmoothing::new(0.5);
    /// assert_eq!(ses.update(10.0), 10.0);
    /// assert_eq!(ses.update(20.0), 15.0);
    /// ```
    pub fn update(&mut self, x: f64) -> f64 {
        let new_level = match self.level {
            None => x,
            Some(prev) => (1.0 - self.alpha).mul_add(prev, self.alpha * x),
        };
        self.level = Some(new_level);
        new_level
    }

    /// Forecasts `steps` values into the future: the current level, repeated flat.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_forecast_ses::SimpleExpSmoothing;
    ///
    /// let mut ses = SimpleExpSmoothing::new(0.5);
    /// ses.update(10.0);
    /// assert_eq!(ses.forecast(3), vec![10.0, 10.0, 10.0]);
    /// ```
    #[must_use]
    pub fn forecast(&self, steps: usize) -> Vec<f64> {
        let level = self.level.unwrap_or(0.0);
        vec![level; steps]
    }
}

/// Double exponential smoothing (Holt's linear method): a smoothed level and
/// trend, forecast linearly.
pub struct DoubleExpSmoothing {
    alpha: f64,
    beta: f64,
    level: Option<f64>,
    trend: f64,
}

impl DoubleExpSmoothing {
    /// Creates a new `DoubleExpSmoothing` with level smoothing `alpha` and trend
    /// smoothing `beta`, both in `(0.0, 1.0]`.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_forecast_ses::DoubleExpSmoothing;
    ///
    /// let des = DoubleExpSmoothing::new(0.5, 0.3);
    /// assert!(des.level().is_none());
    /// ```
    #[must_use]
    pub const fn new(alpha: f64, beta: f64) -> Self {
        Self {
            alpha,
            beta,
            level: None,
            trend: 0.0,
        }
    }

    /// Current smoothed level, or `None` before the first observation.
    #[must_use]
    pub const fn level(&self) -> Option<f64> {
        self.level
    }

    /// Current smoothed trend (per-step slope).
    #[must_use]
    pub const fn trend(&self) -> f64 {
        self.trend
    }

    /// Feeds one observation and returns the updated level.
    ///
    /// The first call seeds the level with `x` and leaves trend at `0.0`. The
    /// second call seeds the trend from the change between the first two
    /// observations; from then on both level and trend are smoothed.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_forecast_ses::DoubleExpSmoothing;
    ///
    /// let mut des = DoubleExpSmoothing::new(0.8, 0.8);
    /// des.update(1.0);
    /// des.update(2.0);
    /// let level = des.update(3.0);
    /// assert!((level - 3.0).abs() < 0.5);
    /// ```
    pub fn update(&mut self, x: f64) -> f64 {
        let new_level = match self.level {
            None => x,
            Some(prev_level) => {
                let new_level = (1.0 - self.alpha).mul_add(prev_level + self.trend, self.alpha * x);
                let new_trend =
                    (1.0 - self.beta).mul_add(self.trend, self.beta * (new_level - prev_level));
                self.trend = new_trend;
                new_level
            }
        };
        self.level = Some(new_level);
        new_level
    }

    /// Forecasts `steps` values into the future: `level + trend * horizon` for
    /// `horizon` in `1..=steps`.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_forecast_ses::DoubleExpSmoothing;
    ///
    /// let mut des = DoubleExpSmoothing::new(0.9, 0.9);
    /// for x in [1.0, 2.0, 3.0, 4.0, 5.0] {
    ///     des.update(x);
    /// }
    /// let forecast = des.forecast(2);
    /// assert_eq!(forecast.len(), 2);
    /// assert!(forecast[1] > forecast[0]);
    /// ```
    #[allow(
        clippy::cast_precision_loss,
        reason = "counts and indices stay far below 2^52, so the f64 conversion is exact"
    )]
    #[must_use]
    pub fn forecast(&self, steps: usize) -> Vec<f64> {
        let level = self.level.unwrap_or(0.0);
        (1..=steps)
            .map(|h| self.trend.mul_add(h as f64, level))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ses_constant_series_converges_to_constant() {
        let mut ses = SimpleExpSmoothing::new(0.5);
        for _ in 0..20 {
            ses.update(42.0);
        }
        assert!((ses.level().unwrap() - 42.0).abs() < 1e-9);
    }

    #[test]
    fn ses_first_update_seeds_level() {
        let mut ses = SimpleExpSmoothing::new(0.1);
        assert_eq!(ses.update(7.0), 7.0);
    }

    #[test]
    fn ses_forecast_length_matches_steps() {
        let mut ses = SimpleExpSmoothing::new(0.5);
        ses.update(1.0);
        assert_eq!(ses.forecast(5).len(), 5);
    }

    #[test]
    fn ses_forecast_before_any_update_is_zero() {
        let ses = SimpleExpSmoothing::new(0.5);
        assert_eq!(ses.forecast(3), vec![0.0, 0.0, 0.0]);
    }

    #[test]
    fn des_linear_series_trend_converges_to_slope() {
        let mut des = DoubleExpSmoothing::new(0.9, 0.9);
        for i in 0..50 {
            des.update(2.0f64.mul_add(f64::from(i), 3.0));
        }
        assert!((des.trend() - 2.0).abs() < 0.1, "trend={}", des.trend());
    }

    #[test]
    fn des_linear_series_forecast_continues_the_line() {
        let mut des = DoubleExpSmoothing::new(0.9, 0.9);
        for i in 0..50 {
            des.update(2.0f64.mul_add(f64::from(i), 3.0));
        }
        let forecast = des.forecast(3);
        let expected_next = 2.0f64.mul_add(50.0, 3.0);
        assert!(
            (forecast[0] - expected_next).abs() < 1.0,
            "forecast={forecast:?}"
        );
    }

    #[test]
    fn des_forecast_length_matches_steps() {
        let mut des = DoubleExpSmoothing::new(0.5, 0.5);
        des.update(1.0);
        des.update(2.0);
        assert_eq!(des.forecast(4).len(), 4);
    }
}
