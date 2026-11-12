//! Exponential smoothing models with additive errors: simple exponential
//! smoothing, Holt's linear and damped trend, and Holt-Winters with additive
//! or multiplicative seasonality, fitted by least squares.

#![allow(
    clippy::cast_precision_loss,
    reason = "series lengths and season periods stay far below 2^52, so usize -> f64 is exact"
)]
#![allow(
    clippy::many_single_char_names,
    reason = "the textbook symbols (y, e, k, m, z, ...) read better than long names"
)]

use core::fmt;

use crate::dist::{Rng, normal_quantile};
use crate::optim::{least_squares, minimize};

/// Lower bound for estimated smoothing parameters (same as R's `forecast::ets`).
const PARAM_LO: f64 = 1e-4;
/// Upper bound for estimated smoothing parameters.
const PARAM_HI: f64 = 0.9999;
/// Lower bound for an estimated damping parameter.
const PHI_LO: f64 = 0.8;
/// Upper bound for an estimated damping parameter.
const PHI_HI: f64 = 0.98;
/// Number of simulated sample paths behind intervals for multiplicative models.
const SIM_PATHS: usize = 10_000;
/// Fixed seed so simulated intervals are reproducible.
const SIM_SEED: u64 = 0x5eed_f00d_cafe_d00d;

/// Trend component of a [`Model`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Trend {
    /// No trend: the level is forecast flat.
    None,
    /// Additive (linear) trend, as in Holt's linear method.
    Additive,
    /// Additive trend damped towards a flat line by `phi`.
    Damped,
}

/// Seasonal component of a [`Model`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Seasonal {
    /// No seasonality.
    None,
    /// Seasonal effects added to the level (constant amplitude).
    Additive,
    /// Seasonal factors multiplying the level (amplitude grows with the
    /// level). Needs a strictly positive series.
    Multiplicative,
}

/// Information criterion used to compare fitted models.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum Criterion {
    /// Akaike's information criterion.
    Aic,
    /// AIC corrected for small samples (the default, as in R's `ets`).
    #[default]
    Aicc,
    /// Bayesian (Schwarz) information criterion.
    Bic,
}

/// Errors from fitting or forecasting.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum Error {
    /// The series is too short for the model: `needed` observations are
    /// required, `got` were supplied.
    TooShort {
        /// Minimum number of observations for this model.
        needed: usize,
        /// Number of observations supplied.
        got: usize,
    },
    /// The value at `index` is `NaN` or infinite.
    NonFinite {
        /// Position of the offending value.
        index: usize,
    },
    /// A multiplicative model was asked to fit a value `<= 0` at `index`.
    NonPositive {
        /// Position of the offending value.
        index: usize,
    },
    /// A seasonal model needs a period of at least 2.
    InvalidPeriod {
        /// The period that was given.
        period: usize,
    },
    /// A fixed smoothing parameter is outside its allowed range.
    InvalidParameter {
        /// Parameter name (`alpha`, `beta`, `gamma` or `phi`).
        name: &'static str,
        /// The value that was given.
        value: f64,
    },
    /// A prediction-interval level outside `(0, 1)`.
    InvalidLevel {
        /// The level that was given.
        level: f64,
    },
    /// The optimiser could not find parameters with a finite error.
    FitFailed,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooShort { needed, got } => {
                write!(
                    f,
                    "series too short: need at least {needed} values, got {got}"
                )
            }
            Self::NonFinite { index } => write!(f, "value at index {index} is not finite"),
            Self::NonPositive { index } => write!(
                f,
                "multiplicative seasonality needs positive values, index {index} is not"
            ),
            Self::InvalidPeriod { period } => {
                write!(f, "seasonal period must be at least 2, got {period}")
            }
            Self::InvalidParameter { name, value } => {
                write!(f, "parameter {name} = {value} is out of range")
            }
            Self::InvalidLevel { level } => {
                write!(f, "interval level must be in (0, 1), got {level}")
            }
            Self::FitFailed => f.write_str("could not find parameters with a finite error"),
        }
    }
}

impl std::error::Error for Error {}

/// Smoothing parameters. A `None` field is estimated when fitting; a `Some`
/// field is held fixed. Fields a model does not use are ignored.
///
/// `beta` is the trend smoothing parameter in the component form of Holt's
/// method (often written `beta*`); the innovations-form value reported by
/// R's `ets` is `alpha * beta`.
///
/// # Example
///
/// ```rust
/// use rune_forecast_ses::{Model, Params};
///
/// // Damped Holt with phi fixed at 0.9, alpha and beta estimated.
/// let y: Vec<f64> = (0..30).map(|t| 10.0 + 2.0 * f64::from(t)).collect();
/// let fit = Model::damped_holt().fit_with(&y, Params::new().with_phi(0.9)).unwrap();
/// assert_eq!(fit.phi(), Some(0.9));
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct Params {
    /// Level smoothing, in `[0, 1]`.
    pub alpha: Option<f64>,
    /// Trend smoothing (component form), in `[0, 1]`.
    pub beta: Option<f64>,
    /// Seasonal smoothing, in `[0, 1]`.
    pub gamma: Option<f64>,
    /// Damping, in `(0, 1]`.
    pub phi: Option<f64>,
}

impl Params {
    /// All parameters left free, to be estimated.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_forecast_ses::Params;
    ///
    /// assert_eq!(Params::new().alpha, None);
    /// ```
    #[must_use]
    pub const fn new() -> Self {
        Self {
            alpha: None,
            beta: None,
            gamma: None,
            phi: None,
        }
    }

    /// Fixes `alpha`.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_forecast_ses::Params;
    ///
    /// assert_eq!(Params::new().with_alpha(0.3).alpha, Some(0.3));
    /// ```
    #[must_use]
    pub const fn with_alpha(mut self, alpha: f64) -> Self {
        self.alpha = Some(alpha);
        self
    }

    /// Fixes `beta`.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_forecast_ses::Params;
    ///
    /// assert_eq!(Params::new().with_beta(0.1).beta, Some(0.1));
    /// ```
    #[must_use]
    pub const fn with_beta(mut self, beta: f64) -> Self {
        self.beta = Some(beta);
        self
    }

    /// Fixes `gamma`.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_forecast_ses::Params;
    ///
    /// assert_eq!(Params::new().with_gamma(0.2).gamma, Some(0.2));
    /// ```
    #[must_use]
    pub const fn with_gamma(mut self, gamma: f64) -> Self {
        self.gamma = Some(gamma);
        self
    }

    /// Fixes `phi`.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_forecast_ses::Params;
    ///
    /// assert_eq!(Params::new().with_phi(0.9).phi, Some(0.9));
    /// ```
    #[must_use]
    pub const fn with_phi(mut self, phi: f64) -> Self {
        self.phi = Some(phi);
        self
    }
}

/// An exponential smoothing model: a trend type, a seasonal type and a
/// seasonal period.
///
/// The recursions are the component forms from Hyndman & Athanasopoulos,
/// *Forecasting: Principles and Practice* (2nd ed.), chapter 7, with
/// additive errors. Smoothing parameters and initial states are chosen by
/// minimising the sum of squared one-step errors.
///
/// # Example
///
/// ```rust
/// use rune_forecast_ses::{Model, Seasonal};
///
/// let y: Vec<f64> = (0..48)
///     .map(|t| 100.0 + f64::from(t) + [10.0, -5.0, -15.0, 10.0][t as usize % 4])
///     .collect();
/// let fit = Model::holt_winters(Seasonal::Additive, 4).fit(&y).unwrap();
/// let next = fit.forecast(4);
/// assert!((next[0] - (100.0 + 48.0 + 10.0)).abs() < 1.0);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Model {
    trend: Trend,
    seasonal: Seasonal,
    period: usize,
}

impl Model {
    /// A model with the given components. `period` is ignored when
    /// `seasonal` is [`Seasonal::None`].
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_forecast_ses::{Model, Seasonal, Trend};
    ///
    /// let model = Model::new(Trend::Damped, Seasonal::Multiplicative, 12);
    /// assert_eq!(model.to_string(), "ETS(A,Ad,M)[12]");
    /// ```
    #[must_use]
    pub const fn new(trend: Trend, seasonal: Seasonal, period: usize) -> Self {
        let period = match seasonal {
            Seasonal::None => 1,
            Seasonal::Additive | Seasonal::Multiplicative => period,
        };
        Self {
            trend,
            seasonal,
            period,
        }
    }

    /// Simple exponential smoothing: level only.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_forecast_ses::Model;
    ///
    /// let fit = Model::ses().fit(&[3.0, 4.0, 3.5, 4.2, 3.9, 4.1]).unwrap();
    /// assert_eq!(fit.forecast(2).len(), 2);
    /// ```
    #[must_use]
    pub const fn ses() -> Self {
        Self::new(Trend::None, Seasonal::None, 1)
    }

    /// Holt's linear trend method.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_forecast_ses::Model;
    ///
    /// let y: Vec<f64> = (0..20).map(|t| 2.0 * f64::from(t)).collect();
    /// let fit = Model::holt().fit(&y).unwrap();
    /// assert!((fit.forecast(1)[0] - 40.0).abs() < 1e-3);
    /// ```
    #[must_use]
    pub const fn holt() -> Self {
        Self::new(Trend::Additive, Seasonal::None, 1)
    }

    /// Holt's method with a damped trend.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_forecast_ses::Model;
    ///
    /// assert_eq!(Model::damped_holt().to_string(), "ETS(A,Ad,N)");
    /// ```
    #[must_use]
    pub const fn damped_holt() -> Self {
        Self::new(Trend::Damped, Seasonal::None, 1)
    }

    /// Holt-Winters: additive trend plus a seasonal component of the given
    /// kind and period.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_forecast_ses::{Model, Seasonal};
    ///
    /// assert_eq!(
    ///     Model::holt_winters(Seasonal::Multiplicative, 4).to_string(),
    ///     "ETS(A,A,M)[4]"
    /// );
    /// ```
    #[must_use]
    pub const fn holt_winters(seasonal: Seasonal, period: usize) -> Self {
        Self::new(Trend::Additive, seasonal, period)
    }

    /// The trend component.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_forecast_ses::{Model, Trend};
    ///
    /// assert_eq!(Model::holt().trend(), Trend::Additive);
    /// ```
    #[must_use]
    pub const fn trend(&self) -> Trend {
        self.trend
    }

    /// The seasonal component.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_forecast_ses::{Model, Seasonal};
    ///
    /// assert_eq!(Model::ses().seasonal(), Seasonal::None);
    /// ```
    #[must_use]
    pub const fn seasonal(&self) -> Seasonal {
        self.seasonal
    }

    /// The seasonal period (1 for non-seasonal models).
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_forecast_ses::{Model, Seasonal};
    ///
    /// assert_eq!(Model::holt_winters(Seasonal::Additive, 12).period(), 12);
    /// assert_eq!(Model::ses().period(), 1);
    /// ```
    #[must_use]
    pub const fn period(&self) -> usize {
        self.period
    }

    /// Fits the model, estimating every smoothing parameter.
    ///
    /// # Errors
    ///
    /// See [`Model::fit_with`].
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_forecast_ses::{Error, Model};
    ///
    /// assert_eq!(
    ///     Model::ses().fit(&[1.0, f64::NAN, 2.0]).unwrap_err(),
    ///     Error::NonFinite { index: 1 }
    /// );
    /// ```
    pub fn fit(&self, y: &[f64]) -> Result<Fit, Error> {
        self.fit_with(y, Params::new())
    }

    /// Fits the model, holding the `Some` fields of `params` fixed and
    /// estimating the rest. Initial states are always estimated.
    ///
    /// # Errors
    ///
    /// - [`Error::NonFinite`] for a `NaN` or infinite value.
    /// - [`Error::InvalidPeriod`] for a seasonal model with period below 2.
    /// - [`Error::InvalidParameter`] for a fixed parameter out of range.
    /// - [`Error::NonPositive`] for a value `<= 0` with multiplicative
    ///   seasonality.
    /// - [`Error::TooShort`] when there are fewer than two full seasons, or
    ///   too few values to leave two degrees of freedom after estimation.
    /// - [`Error::FitFailed`] if no parameters give a finite error.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_forecast_ses::{Model, Params};
    ///
    /// let y = [10.0, 12.0, 11.0, 13.0, 12.5, 12.0];
    /// let fit = Model::ses().fit_with(&y, Params::new().with_alpha(0.5)).unwrap();
    /// assert_eq!(fit.alpha(), 0.5);
    /// ```
    pub fn fit_with(&self, y: &[f64], params: Params) -> Result<Fit, Error> {
        check_finite(y)?;
        self.check_spec(y, &params)?;
        let free = self.free_params(&params);
        let n_states = self.n_states();
        let needed = (free.len() + n_states + 3).max(if self.is_seasonal() {
            2 * self.period
        } else {
            0
        });
        if y.len() < needed {
            return Err(Error::TooShort {
                needed,
                got: y.len(),
            });
        }
        if self.seasonal == Seasonal::Multiplicative {
            self.estimate_multiplicative(y, &params, &free)
        } else {
            self.estimate_linear(y, &params, &free)
        }
    }

    const fn is_seasonal(&self) -> bool {
        !matches!(self.seasonal, Seasonal::None)
    }

    const fn has_trend(&self) -> bool {
        !matches!(self.trend, Trend::None)
    }

    /// Number of estimated initial states: level, trend, and `m - 1`
    /// seasonal states (the last one is pinned by normalisation).
    const fn n_states(&self) -> usize {
        1 + self.has_trend() as usize
            + if self.is_seasonal() {
                self.period - 1
            } else {
                0
            }
    }

    fn check_spec(&self, y: &[f64], params: &Params) -> Result<(), Error> {
        if self.is_seasonal() && self.period < 2 {
            return Err(Error::InvalidPeriod {
                period: self.period,
            });
        }
        let unit = |name: &'static str, v: Option<f64>| match v {
            Some(value) if !(0.0..=1.0).contains(&value) => {
                Err(Error::InvalidParameter { name, value })
            }
            _ => Ok(()),
        };
        unit("alpha", params.alpha)?;
        if self.has_trend() {
            unit("beta", params.beta)?;
        }
        if self.is_seasonal() {
            unit("gamma", params.gamma)?;
        }
        if self.trend == Trend::Damped
            && let Some(value) = params.phi
            && !(value > 0.0 && value <= 1.0)
        {
            return Err(Error::InvalidParameter { name: "phi", value });
        }
        if self.seasonal == Seasonal::Multiplicative
            && let Some(index) = y.iter().position(|v| *v <= 0.0)
        {
            return Err(Error::NonPositive { index });
        }
        Ok(())
    }

    fn free_params(&self, params: &Params) -> Vec<Which> {
        let mut free = Vec::with_capacity(4);
        if params.alpha.is_none() {
            free.push(Which::Alpha);
        }
        if self.has_trend() && params.beta.is_none() {
            free.push(Which::Beta);
        }
        if self.is_seasonal() && params.gamma.is_none() {
            free.push(Which::Gamma);
        }
        if self.trend == Trend::Damped && params.phi.is_none() {
            free.push(Which::Phi);
        }
        free
    }

    /// Maps optimiser coordinates in `[0, 1]` to smoothing parameters,
    /// keeping `gamma <= 1 - alpha` when either is estimated.
    fn decode(&self, params: &Params, free: &[Which], u: &[f64]) -> Coef {
        let get = |w: Which| free.iter().position(|f| *f == w).map(|i| u[i]);
        let scale = |lo: f64, hi: f64, v: f64| v.mul_add((hi - lo).max(0.0), lo);
        let alpha = params.alpha.unwrap_or_else(|| {
            let hi = params
                .gamma
                .filter(|_| self.is_seasonal())
                .map_or(PARAM_HI, |g| (1.0 - g).clamp(PARAM_LO, PARAM_HI));
            scale(PARAM_LO, hi, get(Which::Alpha).unwrap_or(0.5))
        });
        let beta = if self.has_trend() {
            params
                .beta
                .unwrap_or_else(|| scale(PARAM_LO, PARAM_HI, get(Which::Beta).unwrap_or(0.5)))
        } else {
            0.0
        };
        let gamma = if self.is_seasonal() {
            params.gamma.unwrap_or_else(|| {
                let hi = (1.0 - alpha).min(PARAM_HI);
                scale(PARAM_LO, hi, get(Which::Gamma).unwrap_or(0.5)).min(hi.max(0.0))
            })
        } else {
            0.0
        };
        let phi = match self.trend {
            Trend::Damped => params
                .phi
                .unwrap_or_else(|| scale(PHI_LO, PHI_HI, get(Which::Phi).unwrap_or(0.5))),
            Trend::None | Trend::Additive => 1.0,
        };
        Coef {
            alpha,
            beta,
            gamma,
            phi,
        }
    }

    /// Additive (linear) models: the one-step errors are affine in the
    /// initial state, so for given smoothing parameters the best initial
    /// state is a least-squares solve and only the parameters need a search.
    fn estimate_linear(&self, y: &[f64], params: &Params, free: &[Which]) -> Result<Fit, Error> {
        let mut scratch = Scratch::new(self, y.len());
        let mut objective = |u: &[f64]| {
            let coef = self.decode(params, free, u);
            self.profile(&coef, y, &mut scratch).1
        };
        let u = search(&mut objective, free.len(), &[], &[]);
        let coef = self.decode(params, free, &u);
        let (state, _) = self.profile(&coef, y, &mut Scratch::new(self, y.len()));
        self.finish(y, free.len(), coef, state)
    }

    /// Initial state minimising the squared one-step errors for fixed
    /// smoothing parameters, and that error.
    fn profile(&self, coef: &Coef, y: &[f64], scratch: &mut Scratch) -> (State, f64) {
        let n = y.len();
        let zero_state = State::zero(self);
        run(self, coef, &zero_state, y, Some(&mut scratch.base));
        for (i, column) in scratch.columns.iter_mut().enumerate() {
            let basis = State::basis(self, i);
            run(self, coef, &basis, &scratch.zeros, Some(column));
        }
        if scratch
            .base
            .iter()
            .chain(scratch.columns.iter().flatten())
            .any(|v| !v.is_finite())
        {
            return (zero_state, f64::INFINITY);
        }
        let target: Vec<f64> = scratch.base.iter().map(|e| -e).collect();
        let c = least_squares(&scratch.columns, &target);
        let mut sse = 0.0;
        for t in 0..n {
            let e = scratch.base[t]
                + scratch
                    .columns
                    .iter()
                    .zip(&c)
                    .map(|(col, ci)| col[t] * ci)
                    .sum::<f64>();
            sse = e.mul_add(e, sse);
        }
        (State::from_coords(self, &c), sse)
    }

    /// Multiplicative seasonality is not linear in the initial state, so the
    /// search covers the parameters and the initial states together, starting
    /// from a classical-decomposition guess.
    fn estimate_multiplicative(
        &self,
        y: &[f64],
        params: &Params,
        free: &[Which],
    ) -> Result<Fit, Error> {
        let m = self.period;
        let scale = y.iter().map(|v| v.abs()).sum::<f64>() / y.len() as f64;
        let start = self.heuristic_state(y);
        let mut states0 = vec![start.level / scale];
        if self.has_trend() {
            states0.push(start.trend / scale);
        }
        states0.extend_from_slice(&start.season[..m - 1]);

        let unpack = |v: &[f64]| -> State {
            let mut state = State {
                level: v[0] * scale,
                trend: 0.0,
                season: Vec::with_capacity(m),
            };
            let mut rest = &v[1..];
            if self.has_trend() {
                state.trend = rest[0] * scale;
                rest = &rest[1..];
            }
            state.season.extend_from_slice(rest);
            state.season.push(m as f64 - rest.iter().sum::<f64>());
            state
        };
        let k = free.len();
        let mut objective = |x: &[f64]| {
            let coef = self.decode(params, free, &x[..k]);
            run(self, &coef, &unpack(&x[k..]), y, None).0
        };
        let steps: Vec<f64> = states0.iter().map(|v| (0.1 * v.abs()).max(0.01)).collect();
        let x = search(&mut objective, k, &states0, &steps);
        let coef = self.decode(params, free, &x[..k]);
        self.finish(y, free.len(), coef, unpack(&x[k..]))
    }

    /// Level and trend from the first two seasons, seasonal factors from the
    /// first season relative to that line, normalised to average 1.
    fn heuristic_state(&self, y: &[f64]) -> State {
        let m = self.period;
        let mf = m as f64;
        let first = y[..m].iter().sum::<f64>() / mf;
        let second = y[m..2 * m].iter().sum::<f64>() / mf;
        let trend = if self.has_trend() {
            (second - first) / mf
        } else {
            0.0
        };
        let level = trend.mul_add(-(mf + 1.0) / 2.0, first);
        let mut season: Vec<f64> = (0..m)
            .map(|i| {
                let base = trend.mul_add((i + 1) as f64, level);
                if base > 0.0 { y[i] / base } else { 1.0 }
            })
            .collect();
        let mean = season.iter().sum::<f64>() / mf;
        for s in &mut season {
            *s /= mean;
        }
        State {
            level,
            trend,
            season,
        }
    }

    fn finish(&self, y: &[f64], n_free: usize, coef: Coef, initial: State) -> Result<Fit, Error> {
        let mut errors = vec![0.0; y.len()];
        let (sse, last) = run(self, &coef, &initial, y, Some(&mut errors));
        if !sse.is_finite() {
            return Err(Error::FitFailed);
        }
        let fitted = y.iter().zip(&errors).map(|(v, e)| v - e).collect();
        let estimated = n_free + self.n_states();
        let n = y.len();
        Ok(Fit {
            model: *self,
            params: Params {
                alpha: Some(coef.alpha),
                beta: self.has_trend().then_some(coef.beta),
                gamma: self.is_seasonal().then_some(coef.gamma),
                phi: (self.trend == Trend::Damped).then_some(coef.phi),
            },
            coef,
            initial,
            last,
            fitted,
            residuals: errors,
            sse,
            sigma2: sse / (n - estimated) as f64,
            n,
            n_params: estimated + 1,
        })
    }
}

impl fmt::Display for Model {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let trend = match self.trend {
            Trend::None => "N",
            Trend::Additive => "A",
            Trend::Damped => "Ad",
        };
        let season = match self.seasonal {
            Seasonal::None => "N",
            Seasonal::Additive => "A",
            Seasonal::Multiplicative => "M",
        };
        write!(f, "ETS(A,{trend},{season})")?;
        if self.is_seasonal() {
            write!(f, "[{}]", self.period)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Which {
    Alpha,
    Beta,
    Gamma,
    Phi,
}

/// Resolved smoothing parameters. Without a trend `beta` is 0 and `phi` 1;
/// without seasonality `gamma` is 0.
#[derive(Debug, Clone, Copy, PartialEq)]
struct Coef {
    alpha: f64,
    beta: f64,
    gamma: f64,
    phi: f64,
}

/// Level, trend and seasonal states. `season[i]` is the seasonal state for
/// observations whose index is `i` modulo the period.
#[derive(Debug, Clone, PartialEq)]
struct State {
    level: f64,
    trend: f64,
    season: Vec<f64>,
}

impl State {
    fn zero(model: &Model) -> Self {
        Self {
            level: 0.0,
            trend: 0.0,
            season: vec![0.0; if model.is_seasonal() { model.period } else { 0 }],
        }
    }

    /// Unit vector for the `i`-th free state coordinate (seasonal basis
    /// vectors keep the seasonal states summing to zero).
    fn basis(model: &Model, i: usize) -> Self {
        let mut coords = vec![0.0; model.n_states()];
        coords[i] = 1.0;
        Self::from_coords(model, &coords)
    }

    fn from_coords(model: &Model, c: &[f64]) -> Self {
        let mut state = Self::zero(model);
        state.level = c[0];
        let mut rest = &c[1..];
        if model.has_trend() {
            state.trend = rest[0];
            rest = &rest[1..];
        }
        if model.is_seasonal() {
            let m = model.period;
            state.season[..m - 1].copy_from_slice(rest);
            state.season[m - 1] = -rest.iter().sum::<f64>();
        }
        state
    }
}

/// Reusable buffers for the least-squares profile.
struct Scratch {
    zeros: Vec<f64>,
    base: Vec<f64>,
    columns: Vec<Vec<f64>>,
}

impl Scratch {
    fn new(model: &Model, n: usize) -> Self {
        Self {
            zeros: vec![0.0; n],
            base: vec![0.0; n],
            columns: vec![vec![0.0; n]; model.n_states()],
        }
    }
}

/// Runs the smoothing recursions over `y`, writing one-step errors into
/// `errors` when given. Returns the sum of squared errors (infinite if a
/// multiplicative model hits a non-positive level or seasonal factor) and
/// the final state.
fn run(
    model: &Model,
    c: &Coef,
    init: &State,
    y: &[f64],
    mut errors: Option<&mut Vec<f64>>,
) -> (f64, State) {
    let mut state = init.clone();
    let mut sse = 0.0;
    let m = state.season.len();
    for (t, &obs) in y.iter().enumerate() {
        let (e, next) = step(model, c, &state, t, m, obs);
        if !e.is_finite() {
            return (f64::INFINITY, state);
        }
        if let Some(out) = errors.as_deref_mut() {
            out[t] = e;
        }
        sse = e.mul_add(e, sse);
        state.level = next.0;
        state.trend = next.1;
        if m > 0 {
            state.season[t % m] = next.2;
        }
    }
    (sse, state)
}

/// One step of the component-form recursions (fpp2 section 7.3, with
/// damping as in section 7.4). Returns the one-step error and the updated
/// `(level, trend, season)`.
fn step(
    model: &Model,
    c: &Coef,
    s: &State,
    t: usize,
    m: usize,
    obs: f64,
) -> (f64, (f64, f64, f64)) {
    let damped = c.phi * s.trend;
    let base = s.level + damped;
    let (fitted, level, season) = match model.seasonal {
        Seasonal::None => (base, c.alpha.mul_add(obs - base, base), 0.0),
        Seasonal::Additive => {
            let old = s.season[t % m];
            (
                base + old,
                c.alpha.mul_add(obs - old - base, base),
                c.gamma.mul_add(obs - base - old, old),
            )
        }
        Seasonal::Multiplicative => {
            let old = s.season[t % m];
            if base <= 0.0 || old <= 0.0 {
                return (f64::INFINITY, (0.0, 0.0, 0.0));
            }
            (
                base * old,
                c.alpha.mul_add(obs / old - base, base),
                c.gamma.mul_add(obs / base - old, old),
            )
        }
    };
    let trend = c.beta.mul_add(level - s.level - damped, damped);
    (obs - fitted, (level, trend, season))
}

/// Grid over the `[0, 1]` parameter box, then bounded Nelder-Mead from the
/// best grid point. `extra` holds unbounded coordinates appended after the
/// parameters (with their initial step sizes).
fn search<F: FnMut(&[f64]) -> f64>(
    f: &mut F,
    k: usize,
    extra: &[f64],
    extra_step: &[f64],
) -> Vec<f64> {
    const GRID: [f64; 4] = [0.05, 0.35, 0.65, 0.95];
    let mut best = vec![0.5; k];
    best.extend_from_slice(extra);
    let mut best_val = f(&best);
    if k > 0 {
        let mut idx = vec![0usize; k];
        let mut x = best.clone();
        loop {
            for (slot, &i) in x.iter_mut().zip(&idx) {
                *slot = GRID[i];
            }
            let v = f(&x);
            if v < best_val {
                best_val = v;
                best.clone_from(&x);
            }
            let mut d = 0;
            while d < k {
                idx[d] += 1;
                if idx[d] < GRID.len() {
                    break;
                }
                idx[d] = 0;
                d += 1;
            }
            if d == k {
                break;
            }
        }
    }
    let dim = best.len();
    if dim == 0 {
        return best;
    }
    let mut step = vec![0.1; k];
    step.extend_from_slice(extra_step);
    let mut lower = vec![0.0; k];
    lower.extend(core::iter::repeat_n(f64::NEG_INFINITY, extra.len()));
    let mut upper = vec![1.0; k];
    upper.extend(core::iter::repeat_n(f64::INFINITY, extra.len()));
    let (x, _) = minimize(f, &best, &step, &lower, &upper, 400 * (dim + 1));
    x
}

fn check_finite(y: &[f64]) -> Result<(), Error> {
    y.iter()
        .position(|v| !v.is_finite())
        .map_or(Ok(()), |index| Err(Error::NonFinite { index }))
}

/// A point forecast with a prediction interval.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Interval {
    /// Point forecast.
    pub mean: f64,
    /// Lower bound.
    pub lower: f64,
    /// Upper bound.
    pub upper: f64,
}

/// A fitted model: estimated parameters and states, in-sample errors and
/// information criteria, and forecasting.
///
/// Information criteria follow R's `forecast::ets`: with additive errors
/// `-2 log L` is taken as `n * ln(SSE)` (constant terms dropped), and the
/// parameter count `k` covers the estimated smoothing parameters, the
/// estimated initial states and the error variance. Only compare criteria
/// between models fitted to the same series.
#[derive(Debug, Clone)]
pub struct Fit {
    model: Model,
    params: Params,
    coef: Coef,
    initial: State,
    last: State,
    fitted: Vec<f64>,
    residuals: Vec<f64>,
    sse: f64,
    sigma2: f64,
    n: usize,
    n_params: usize,
}

impl Fit {
    /// The fitted model.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_forecast_ses::Model;
    ///
    /// let fit = Model::ses().fit(&[1.0, 2.0, 1.5, 1.8, 1.6]).unwrap();
    /// assert_eq!(fit.model(), Model::ses());
    /// ```
    #[must_use]
    pub const fn model(&self) -> Model {
        self.model
    }

    /// The smoothing parameters used: `Some` for every one the model has.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_forecast_ses::Model;
    ///
    /// let fit = Model::ses().fit(&[1.0, 2.0, 1.5, 1.8, 1.6]).unwrap();
    /// assert!(fit.params().alpha.is_some());
    /// assert!(fit.params().beta.is_none());
    /// ```
    #[must_use]
    pub const fn params(&self) -> Params {
        self.params
    }

    /// Level smoothing parameter.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_forecast_ses::Model;
    ///
    /// let fit = Model::ses().fit(&[1.0, 2.0, 1.5, 1.8, 1.6]).unwrap();
    /// assert!((0.0..=1.0).contains(&fit.alpha()));
    /// ```
    #[must_use]
    pub const fn alpha(&self) -> f64 {
        self.coef.alpha
    }

    /// Trend smoothing parameter (component form), if the model has a trend.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_forecast_ses::Model;
    ///
    /// let fit = Model::holt().fit(&[1.0, 2.0, 3.1, 3.9, 5.2, 6.0, 7.1]).unwrap();
    /// assert!(fit.beta().is_some());
    /// ```
    #[must_use]
    pub const fn beta(&self) -> Option<f64> {
        self.params.beta
    }

    /// Seasonal smoothing parameter, if the model is seasonal.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_forecast_ses::Model;
    ///
    /// let fit = Model::ses().fit(&[1.0, 2.0, 1.5, 1.8, 1.6]).unwrap();
    /// assert_eq!(fit.gamma(), None);
    /// ```
    #[must_use]
    pub const fn gamma(&self) -> Option<f64> {
        self.params.gamma
    }

    /// Damping parameter, if the trend is damped.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_forecast_ses::Model;
    ///
    /// let y: Vec<f64> = (0..20).map(|t| f64::from(t).sqrt()).collect();
    /// let phi = Model::damped_holt().fit(&y).unwrap().phi().unwrap();
    /// assert!((0.8..=0.98).contains(&phi));
    /// ```
    #[must_use]
    pub const fn phi(&self) -> Option<f64> {
        self.params.phi
    }

    /// Estimated level before the first observation.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_forecast_ses::Model;
    ///
    /// let fit = Model::ses().fit(&[5.0; 8]).unwrap();
    /// assert!((fit.initial_level() - 5.0).abs() < 1e-6);
    /// ```
    #[must_use]
    pub const fn initial_level(&self) -> f64 {
        self.initial.level
    }

    /// Estimated trend before the first observation, if the model has one.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_forecast_ses::Model;
    ///
    /// let y: Vec<f64> = (0..10).map(|t| 3.0 * f64::from(t)).collect();
    /// let b0 = Model::holt().fit(&y).unwrap().initial_trend().unwrap();
    /// assert!((b0 - 3.0).abs() < 1e-6);
    /// ```
    #[must_use]
    pub fn initial_trend(&self) -> Option<f64> {
        self.model.has_trend().then_some(self.initial.trend)
    }

    /// Estimated initial seasonal states. Entry `i` applies to the
    /// observations at indices `i`, `i + m`, ... until it is updated; it is
    /// empty for non-seasonal models. Additive states sum to 0,
    /// multiplicative ones average 1.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_forecast_ses::{Model, Seasonal};
    ///
    /// let y: Vec<f64> = (0..24).map(|t| [5.0, -5.0][t % 2] + 50.0).collect();
    /// let fit = Model::holt_winters(Seasonal::Additive, 2).fit(&y).unwrap();
    /// assert!((fit.initial_seasonal()[0] - 5.0).abs() < 1e-3);
    /// ```
    #[must_use]
    pub fn initial_seasonal(&self) -> &[f64] {
        &self.initial.season
    }

    /// Level after the last observation.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_forecast_ses::Model;
    ///
    /// let fit = Model::ses().fit(&[5.0; 8]).unwrap();
    /// assert!((fit.level() - 5.0).abs() < 1e-6);
    /// ```
    #[must_use]
    pub const fn level(&self) -> f64 {
        self.last.level
    }

    /// Trend after the last observation, if the model has one.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_forecast_ses::Model;
    ///
    /// let y: Vec<f64> = (0..10).map(|t| 3.0 * f64::from(t)).collect();
    /// assert!((Model::holt().fit(&y).unwrap().trend().unwrap() - 3.0).abs() < 1e-6);
    /// ```
    #[must_use]
    pub fn trend(&self) -> Option<f64> {
        self.model.has_trend().then_some(self.last.trend)
    }

    /// Seasonal states after the last observation, indexed like
    /// [`Fit::initial_seasonal`] (entry `i` is for indices `i` mod `m`).
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_forecast_ses::Model;
    ///
    /// assert!(Model::ses().fit(&[1.0, 2.0, 1.0, 2.0, 1.5]).unwrap().seasonal().is_empty());
    /// ```
    #[must_use]
    pub fn seasonal(&self) -> &[f64] {
        &self.last.season
    }

    /// One-step-ahead in-sample forecasts, one per observation.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_forecast_ses::Model;
    ///
    /// let y = [1.0, 2.0, 1.5, 1.8, 1.6];
    /// assert_eq!(Model::ses().fit(&y).unwrap().fitted().len(), y.len());
    /// ```
    #[must_use]
    pub fn fitted(&self) -> &[f64] {
        &self.fitted
    }

    /// In-sample one-step errors, `y - fitted`.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_forecast_ses::Model;
    ///
    /// let fit = Model::ses().fit(&[1.0, 2.0, 1.5, 1.8, 1.6]).unwrap();
    /// let sse: f64 = fit.residuals().iter().map(|e| e * e).sum();
    /// assert!((sse - fit.sse()).abs() < 1e-9);
    /// ```
    #[must_use]
    pub fn residuals(&self) -> &[f64] {
        &self.residuals
    }

    /// Sum of squared one-step errors.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_forecast_ses::Model;
    ///
    /// assert!(Model::ses().fit(&[4.0; 6]).unwrap().sse() < 1e-12);
    /// ```
    #[must_use]
    pub const fn sse(&self) -> f64 {
        self.sse
    }

    /// Residual variance, `SSE / (n - estimated)` where `estimated` counts
    /// the estimated smoothing parameters and initial states.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_forecast_ses::Model;
    ///
    /// let fit = Model::ses().fit(&[1.0, 2.0, 1.5, 1.8, 1.6]).unwrap();
    /// assert!((fit.sigma2() - fit.sse() / 3.0).abs() < 1e-12);
    /// ```
    #[must_use]
    pub const fn sigma2(&self) -> f64 {
        self.sigma2
    }

    /// Number of parameters behind the information criteria, including the
    /// error variance.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_forecast_ses::Model;
    ///
    /// // alpha, initial level, variance
    /// assert_eq!(Model::ses().fit(&[1.0, 2.0, 1.5, 1.8, 1.6]).unwrap().n_params(), 3);
    /// ```
    #[must_use]
    pub const fn n_params(&self) -> usize {
        self.n_params
    }

    /// `-2 log L` as used by the criteria: `n * ln(SSE)`.
    fn neg2_loglik(&self) -> f64 {
        self.n as f64 * self.sse.ln()
    }

    /// Akaike's information criterion, `n ln(SSE) + 2k`.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_forecast_ses::Model;
    ///
    /// let fit = Model::ses().fit(&[1.0, 2.0, 1.5, 1.8, 1.6, 1.7]).unwrap();
    /// assert!(fit.aicc() > fit.aic());
    /// ```
    #[must_use]
    pub fn aic(&self) -> f64 {
        2.0f64.mul_add(self.n_params as f64, self.neg2_loglik())
    }

    /// Small-sample corrected AIC, `AIC + 2k(k + 1) / (n - k - 1)`.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_forecast_ses::Model;
    ///
    /// let fit = Model::ses().fit(&[1.0, 2.0, 1.5, 1.8, 1.6, 1.7]).unwrap();
    /// assert!(fit.aicc().is_finite());
    /// ```
    #[must_use]
    pub fn aicc(&self) -> f64 {
        let k = self.n_params as f64;
        let n = self.n as f64;
        self.aic() + 2.0 * k * (k + 1.0) / (n - k - 1.0)
    }

    /// Bayesian information criterion, `n ln(SSE) + k ln(n)`.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_forecast_ses::Model;
    ///
    /// let fit = Model::ses().fit(&[1.0, 2.0, 1.5, 1.8, 1.6, 1.7]).unwrap();
    /// assert!(fit.bic().is_finite());
    /// ```
    #[must_use]
    pub fn bic(&self) -> f64 {
        (self.n_params as f64).mul_add((self.n as f64).ln(), self.neg2_loglik())
    }

    /// The value of the given criterion.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_forecast_ses::{Criterion, Model};
    ///
    /// let fit = Model::ses().fit(&[1.0, 2.0, 1.5, 1.8, 1.6, 1.7]).unwrap();
    /// assert_eq!(fit.criterion(Criterion::Bic), fit.bic());
    /// ```
    #[must_use]
    pub fn criterion(&self, criterion: Criterion) -> f64 {
        match criterion {
            Criterion::Aic => self.aic(),
            Criterion::Aicc => self.aicc(),
            Criterion::Bic => self.bic(),
        }
    }

    /// Point forecasts for horizons `1..=steps`:
    /// `level + (phi + ... + phi^h) * trend`, plus or times the matching
    /// seasonal state.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_forecast_ses::Model;
    ///
    /// let y: Vec<f64> = (0..10).map(|t| 3.0 * f64::from(t)).collect();
    /// let fc = Model::holt().fit(&y).unwrap().forecast(2);
    /// assert!((fc[1] - 33.0).abs() < 1e-6);
    /// ```
    #[must_use]
    pub fn forecast(&self, steps: usize) -> Vec<f64> {
        let mut damp_sum = 0.0;
        let mut damp_pow = 1.0;
        (1..=steps)
            .map(|h| {
                damp_pow *= self.coef.phi;
                damp_sum += damp_pow;
                let base = damp_sum.mul_add(self.last.trend, self.last.level);
                self.apply_season(base, self.n + h - 1)
            })
            .collect()
    }

    fn apply_season(&self, base: f64, t: usize) -> f64 {
        let m = self.last.season.len();
        match self.model.seasonal {
            Seasonal::None => base,
            Seasonal::Additive => base + self.last.season[t % m],
            Seasonal::Multiplicative => base * self.last.season[t % m],
        }
    }

    /// Point forecasts with prediction intervals at `level` (for example
    /// `0.95`), assuming normally distributed errors.
    ///
    /// For models without multiplicative seasonality the forecast variance
    /// has a closed form (Hyndman et al., *Forecasting with Exponential
    /// Smoothing*, 2008, table 6.1; fpp2 table 7.8):
    /// `sigma2 * (1 + sum_{j=1}^{h-1} c_j^2)` with
    /// `c_j = alpha + alpha*beta*(phi + ... + phi^j) + gamma * [j mod m == 0]`.
    /// For multiplicative seasonality there is no simple closed form, so the
    /// bounds are empirical quantiles of 10 000 simulated sample paths
    /// (fixed seed, so results are reproducible); the mean is still the point
    /// forecast.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidLevel`] unless `0 < level < 1`.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_forecast_ses::Model;
    ///
    /// let fit = Model::ses().fit(&[10.0, 12.0, 11.0, 13.0, 12.0, 11.5]).unwrap();
    /// let iv = fit.forecast_intervals(3, 0.95).unwrap();
    /// assert!(iv[0].lower < iv[0].mean && iv[0].mean < iv[0].upper);
    /// assert!(iv[2].upper - iv[2].lower >= iv[0].upper - iv[0].lower);
    /// ```
    pub fn forecast_intervals(&self, steps: usize, level: f64) -> Result<Vec<Interval>, Error> {
        if !(level > 0.0 && level < 1.0) {
            return Err(Error::InvalidLevel { level });
        }
        let means = self.forecast(steps);
        if self.model.seasonal == Seasonal::Multiplicative {
            return Ok(self.simulated_intervals(&means, level));
        }
        let z = normal_quantile(0.5 + level / 2.0);
        let Coef {
            alpha,
            beta,
            gamma,
            phi,
        } = self.coef;
        let m = self.model.period;
        let mut acc = 0.0;
        let mut damp_sum = 0.0;
        let mut damp_pow = 1.0;
        Ok(means
            .iter()
            .enumerate()
            .map(|(i, &mean)| {
                let h = i + 1;
                if h > 1 {
                    let j = h - 1;
                    damp_pow *= phi;
                    damp_sum += damp_pow;
                    let seasonal_hit = self.model.is_seasonal() && j % m == 0;
                    let c = (alpha * beta)
                        .mul_add(damp_sum, alpha + if seasonal_hit { gamma } else { 0.0 });
                    acc = c.mul_add(c, acc);
                }
                let half = z * (self.sigma2 * (1.0 + acc)).sqrt();
                Interval {
                    mean,
                    lower: mean - half,
                    upper: mean + half,
                }
            })
            .collect())
    }

    fn simulated_intervals(&self, means: &[f64], level: f64) -> Vec<Interval> {
        let steps = means.len();
        let sigma = self.sigma2.sqrt();
        let m = self.last.season.len();
        let mut rng = Rng::new(SIM_SEED);
        let mut paths = vec![Vec::with_capacity(SIM_PATHS); steps];
        for _ in 0..SIM_PATHS {
            let mut state = self.last.clone();
            for (h, column) in paths.iter_mut().enumerate() {
                let t = self.n + h;
                let base = self.coef.phi.mul_add(state.trend, state.level);
                let point = base * state.season[t % m];
                let obs = sigma.mul_add(rng.normal(), point);
                column.push(obs);
                let (_, next) = step(&self.model, &self.coef, &state, t, m, obs);
                if next.0.is_finite() && next.2 > 0.0 {
                    state.level = next.0;
                    state.trend = next.1;
                    state.season[t % m] = next.2;
                }
            }
        }
        let tail = (1.0 - level) / 2.0;
        paths
            .iter_mut()
            .zip(means)
            .map(|(column, &mean)| {
                column.sort_by(f64::total_cmp);
                Interval {
                    mean,
                    lower: quantile(column, tail),
                    upper: quantile(column, 1.0 - tail),
                }
            })
            .collect()
    }
}

/// Linear-interpolation quantile of sorted data (R's type 7).
#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    reason = "the position is non-negative and below the slice length"
)]
fn quantile(sorted: &[f64], p: f64) -> f64 {
    let pos = p * (sorted.len() - 1) as f64;
    let lo = pos.floor() as usize;
    let hi = (lo + 1).min(sorted.len() - 1);
    let frac = pos - lo as f64;
    frac.mul_add(sorted[hi] - sorted[lo], sorted[lo])
}

/// Automatic model selection: fits SES, Holt, damped Holt and (with a
/// period) the Holt-Winters variants, and keeps the one with the lowest
/// information criterion (`AICc` unless changed).
///
/// Seasonal candidates are skipped when the series has fewer than two full
/// seasons, multiplicative ones when it has a value `<= 0`, and any model
/// whose parameter count leaves fewer than two degrees of freedom.
///
/// # Example
///
/// ```rust
/// use rune_forecast_ses::{Auto, Seasonal};
///
/// let y: Vec<f64> = (0..40)
///     .map(|t| 50.0 + 0.5 * f64::from(t) + [8.0, -3.0, -9.0, 4.0][t as usize % 4])
///     .collect();
/// let fit = Auto::new().period(4).fit(&y).unwrap();
/// assert_eq!(fit.model().seasonal(), Seasonal::Additive);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Auto {
    period: Option<usize>,
    criterion: Criterion,
    damped: bool,
    multiplicative: bool,
}

impl Default for Auto {
    fn default() -> Self {
        Self::new()
    }
}

impl Auto {
    /// Non-seasonal search with `AICc`, damped and multiplicative models allowed.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_forecast_ses::Auto;
    ///
    /// let fit = Auto::new().fit(&[3.0, 3.2, 2.9, 3.1, 3.0, 3.3, 2.8, 3.1]).unwrap();
    /// assert_eq!(fit.forecast(1).len(), 1);
    /// ```
    #[must_use]
    pub const fn new() -> Self {
        Self {
            period: None,
            criterion: Criterion::Aicc,
            damped: true,
            multiplicative: true,
        }
    }

    /// Also consider seasonal models with this period.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_forecast_ses::Auto;
    ///
    /// let auto = Auto::new().period(12);
    /// # let _ = auto;
    /// ```
    #[must_use]
    pub const fn period(mut self, period: usize) -> Self {
        self.period = Some(period);
        self
    }

    /// Criterion used to rank candidates.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_forecast_ses::{Auto, Criterion};
    ///
    /// let auto = Auto::new().criterion(Criterion::Bic);
    /// # let _ = auto;
    /// ```
    #[must_use]
    pub const fn criterion(mut self, criterion: Criterion) -> Self {
        self.criterion = criterion;
        self
    }

    /// Whether damped-trend models are candidates (default `true`).
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_forecast_ses::Auto;
    ///
    /// let auto = Auto::new().allow_damped(false);
    /// # let _ = auto;
    /// ```
    #[must_use]
    pub const fn allow_damped(mut self, allow: bool) -> Self {
        self.damped = allow;
        self
    }

    /// Whether multiplicative-seasonal models are candidates (default `true`).
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_forecast_ses::Auto;
    ///
    /// let auto = Auto::new().period(4).allow_multiplicative(false);
    /// # let _ = auto;
    /// ```
    #[must_use]
    pub const fn allow_multiplicative(mut self, allow: bool) -> Self {
        self.multiplicative = allow;
        self
    }

    /// The candidate models for a series of length `n` with these values.
    fn models(&self, y: &[f64]) -> Vec<Model> {
        let mut trends = vec![Trend::None, Trend::Additive];
        if self.damped {
            trends.push(Trend::Damped);
        }
        let mut seasons = vec![(Seasonal::None, 1)];
        if let Some(m) = self.period.filter(|m| *m >= 2 && y.len() >= 2 * m) {
            seasons.push((Seasonal::Additive, m));
            if self.multiplicative && y.iter().all(|v| *v > 0.0) {
                seasons.push((Seasonal::Multiplicative, m));
            }
        }
        seasons
            .iter()
            .flat_map(|&(s, m)| trends.iter().map(move |&t| Model::new(t, s, m)))
            .collect()
    }

    /// Fits every candidate and returns the successful fits, best first.
    ///
    /// # Errors
    ///
    /// [`Error::NonFinite`] for a `NaN`/infinite value, [`Error::InvalidPeriod`]
    /// for a period below 2, or the error of the simplest candidate if none
    /// could be fitted (usually [`Error::TooShort`]).
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_forecast_ses::Auto;
    ///
    /// let y: Vec<f64> = (0..20).map(|t| f64::from(t) + if t % 2 == 0 { 0.3 } else { -0.3 }).collect();
    /// let fits = Auto::new().candidates(&y).unwrap();
    /// assert_eq!(fits.len(), 3);
    /// assert!(fits[0].aicc() <= fits[1].aicc());
    /// ```
    pub fn candidates(&self, y: &[f64]) -> Result<Vec<Fit>, Error> {
        check_finite(y)?;
        if let Some(period) = self.period.filter(|m| *m < 2) {
            return Err(Error::InvalidPeriod { period });
        }
        let mut first_err = None;
        let mut fits = Vec::new();
        for model in self.models(y) {
            match model.fit(y) {
                Ok(fit) if !fit.criterion(self.criterion).is_nan() => fits.push(fit),
                Ok(_) => {}
                Err(e) => {
                    first_err.get_or_insert(e);
                }
            }
        }
        if fits.is_empty() {
            return Err(first_err.unwrap_or(Error::FitFailed));
        }
        fits.sort_by(|a, b| {
            a.criterion(self.criterion)
                .total_cmp(&b.criterion(self.criterion))
        });
        Ok(fits)
    }

    /// Fits every candidate and returns the best by the chosen criterion.
    ///
    /// # Errors
    ///
    /// As for [`Auto::candidates`].
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_forecast_ses::{Auto, Trend};
    ///
    /// let y: Vec<f64> = (0..30).map(|t| 5.0 * f64::from(t) + [0.4, -0.2, 0.1][t as usize % 3]).collect();
    /// let fit = Auto::new().fit(&y).unwrap();
    /// assert_ne!(fit.model().trend(), Trend::None);
    /// ```
    pub fn fit(&self, y: &[f64]) -> Result<Fit, Error> {
        let mut fits = self.candidates(y)?;
        Ok(fits.swap_remove(0))
    }
}

#[cfg(test)]
#[allow(clippy::suboptimal_flops, clippy::float_cmp)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn seasonal_series(n: usize, pattern: &[f64], mult: bool) -> Vec<f64> {
        (0..n)
            .map(|t| {
                let base = 0.5f64.mul_add(t as f64, 40.0);
                let s = pattern[t % pattern.len()];
                if mult { base * s } else { base + s }
            })
            .collect()
    }

    #[test]
    fn rejects_non_finite() {
        let err = Model::holt()
            .fit(&[1.0, 2.0, f64::INFINITY, 4.0])
            .unwrap_err();
        assert_eq!(err, Error::NonFinite { index: 2 });
        assert_eq!(
            Auto::new().fit(&[1.0, f64::NAN]).unwrap_err(),
            Error::NonFinite { index: 1 }
        );
    }

    #[test]
    fn rejects_short_series() {
        assert_eq!(
            Model::ses().fit(&[1.0, 2.0, 3.0, 4.0]).unwrap_err(),
            Error::TooShort { needed: 5, got: 4 }
        );
        assert_eq!(
            Model::ses().fit(&[]).unwrap_err(),
            Error::TooShort { needed: 5, got: 0 }
        );
        // Seasonal models need two full seasons.
        let y = vec![1.0; 23];
        assert_eq!(
            Model::holt_winters(Seasonal::Additive, 12)
                .fit(&y)
                .unwrap_err(),
            Error::TooShort {
                needed: 24,
                got: 23
            }
        );
        // ...and two degrees of freedom left after estimating 8 values.
        let y = vec![1.0; 7];
        assert_eq!(
            Model::holt_winters(Seasonal::Additive, 4)
                .fit(&y)
                .unwrap_err(),
            Error::TooShort { needed: 11, got: 7 }
        );
    }

    #[test]
    fn rejects_bad_period_and_params() {
        let y = vec![1.0; 30];
        assert_eq!(
            Model::holt_winters(Seasonal::Additive, 1)
                .fit(&y)
                .unwrap_err(),
            Error::InvalidPeriod { period: 1 }
        );
        assert_eq!(
            Auto::new().period(0).fit(&y).unwrap_err(),
            Error::InvalidPeriod { period: 0 }
        );
        assert_eq!(
            Model::ses()
                .fit_with(&y, Params::new().with_alpha(1.5))
                .unwrap_err(),
            Error::InvalidParameter {
                name: "alpha",
                value: 1.5
            }
        );
        assert_eq!(
            Model::damped_holt()
                .fit_with(&y, Params::new().with_phi(0.0))
                .unwrap_err(),
            Error::InvalidParameter {
                name: "phi",
                value: 0.0
            }
        );
        // Parameters the model does not use are ignored.
        assert!(
            Model::ses()
                .fit_with(&y, Params::new().with_beta(7.0))
                .is_ok()
        );
    }

    #[test]
    fn multiplicative_needs_positive_values() {
        let mut y = seasonal_series(24, &[1.2, 0.8], true);
        y[5] = 0.0;
        assert_eq!(
            Model::holt_winters(Seasonal::Multiplicative, 2)
                .fit(&y)
                .unwrap_err(),
            Error::NonPositive { index: 5 }
        );
        // Auto silently drops the multiplicative candidates instead.
        let fits = Auto::new().period(2).candidates(&y).unwrap();
        assert!(
            fits.iter()
                .all(|f| f.model().seasonal() != Seasonal::Multiplicative)
        );
    }

    #[test]
    fn interval_level_is_checked() {
        let fit = Model::ses().fit(&[1.0, 2.0, 1.5, 1.8, 1.6]).unwrap();
        for level in [0.0, 1.0, -0.2, f64::NAN] {
            assert!(matches!(
                fit.forecast_intervals(2, level),
                Err(Error::InvalidLevel { .. })
            ));
        }
    }

    #[test]
    fn additive_seasonal_pattern_is_recovered() {
        let pattern = [6.0, -2.0, -7.0, 3.0];
        let y = seasonal_series(40, &pattern, false);
        let fit = Model::holt_winters(Seasonal::Additive, 4).fit(&y).unwrap();
        assert!(fit.sse() < 1e-8, "sse {}", fit.sse());
        for (got, want) in fit.initial_seasonal().iter().zip(pattern) {
            assert!((got - want).abs() < 1e-4, "{:?}", fit.initial_seasonal());
        }
        let fc = fit.forecast(4);
        let truth = seasonal_series(44, &pattern, false);
        for (f, t) in fc.iter().zip(&truth[40..]) {
            assert!((f - t).abs() < 1e-4, "{fc:?}");
        }
    }

    #[test]
    fn multiplicative_seasonal_pattern_is_recovered() {
        let pattern = [1.3, 0.9, 0.7, 1.1];
        let y = seasonal_series(48, &pattern, true);
        let fit = Model::holt_winters(Seasonal::Multiplicative, 4)
            .fit(&y)
            .unwrap();
        for (got, want) in fit.initial_seasonal().iter().zip(pattern) {
            assert!((got - want).abs() < 0.02, "{:?}", fit.initial_seasonal());
        }
        let truth = seasonal_series(52, &pattern, true);
        for (f, t) in fit.forecast(4).iter().zip(&truth[48..]) {
            assert!((f - t).abs() / t < 0.01, "{f} vs {t}");
        }
        let iv = fit.forecast_intervals(4, 0.9).unwrap();
        assert!(iv.iter().all(|i| i.lower <= i.mean && i.mean <= i.upper));
        // Simulation uses a fixed seed: identical on every call.
        assert_eq!(iv, fit.forecast_intervals(4, 0.9).unwrap());
    }

    #[test]
    fn fixed_parameters_are_kept() {
        let y = seasonal_series(32, &[2.0, -2.0], false);
        let params = Params::new().with_alpha(0.3).with_beta(0.1).with_gamma(0.2);
        let fit = Model::holt_winters(Seasonal::Additive, 2)
            .fit_with(&y, params)
            .unwrap();
        assert_eq!(fit.alpha(), 0.3);
        assert_eq!(fit.beta(), Some(0.1));
        assert_eq!(fit.gamma(), Some(0.2));
        // level, trend, one seasonal state, variance
        assert_eq!(fit.n_params(), 4);
    }

    #[test]
    fn fitted_plus_residuals_is_the_data() {
        let y = [3.0, 5.0, 4.0, 6.0, 5.5, 7.0, 6.5, 8.0];
        let fit = Model::damped_holt().fit(&y).unwrap();
        for ((f, e), v) in fit.fitted().iter().zip(fit.residuals()).zip(y) {
            assert!((f + e - v).abs() < 1e-12);
        }
    }

    #[test]
    fn auto_picks_flat_model_for_noise_and_trend_for_lines() {
        let noise: Vec<f64> = (0..40)
            .map(|t| 10.0 + [0.3, -0.5, 0.1, 0.4, -0.2][t % 5])
            .collect();
        let flat = Auto::new().fit(&noise).unwrap();
        assert_eq!(flat.model().trend(), Trend::None);
        let line: Vec<f64> = noise
            .iter()
            .enumerate()
            .map(|(t, v)| v + 3.0 * t as f64)
            .collect();
        assert_ne!(Auto::new().fit(&line).unwrap().model().trend(), Trend::None);
        let ranked = Auto::new()
            .allow_damped(false)
            .criterion(Criterion::Bic)
            .candidates(&line)
            .unwrap();
        assert_eq!(ranked.len(), 2);
        assert!(ranked[0].bic() <= ranked[1].bic());
    }

    #[test]
    fn ses_variance_formula() {
        let y = [10.0, 12.0, 11.0, 13.0, 12.0, 11.5, 12.5];
        let fit = Model::ses().fit(&y).unwrap();
        let iv = fit.forecast_intervals(3, 0.95).unwrap();
        let z = 1.959_963_985;
        let a = fit.alpha();
        for (h, i) in iv.iter().enumerate() {
            let var = fit.sigma2() * (a * a).mul_add(h as f64, 1.0);
            assert!(((i.upper - i.mean) - z * var.sqrt()).abs() < 1e-6);
        }
    }

    #[test]
    fn display_names() {
        assert_eq!(Model::ses().to_string(), "ETS(A,N,N)");
        assert_eq!(Model::holt().to_string(), "ETS(A,A,N)");
        assert_eq!(
            Model::new(Trend::None, Seasonal::Additive, 7).to_string(),
            "ETS(A,N,A)[7]"
        );
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(24))]

        /// The estimate is at least as good as any fixed parameter choice.
        #[test]
        fn estimate_beats_fixed_parameters(
            values in prop::collection::vec(1.0f64..100.0, 12..40),
            alpha in 0.05f64..0.95,
            beta in 0.05f64..0.95,
        ) {
            let fixed = Params::new().with_alpha(alpha).with_beta(beta);
            let est = Model::holt().fit(&values).unwrap();
            let other = Model::holt().fit_with(&values, fixed).unwrap();
            prop_assert!(est.sse() <= other.sse() * (1.0 + 1e-6) + 1e-9);
        }

        /// Intervals contain the point forecast and never narrow with horizon.
        #[test]
        fn intervals_widen(
            values in prop::collection::vec(1.0f64..100.0, 16..40),
            level in 0.5f64..0.99,
        ) {
            let fit = Model::holt_winters(Seasonal::Additive, 4).fit(&values).unwrap();
            let iv = fit.forecast_intervals(8, level).unwrap();
            let mut prev = 0.0;
            for i in &iv {
                prop_assert!(i.lower <= i.mean && i.mean <= i.upper);
                let width = i.upper - i.lower;
                prop_assert!(width + 1e-9 >= prev);
                prev = width;
            }
        }
    }
}
