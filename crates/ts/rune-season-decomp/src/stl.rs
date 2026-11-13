//! STL: Seasonal-Trend decomposition using Loess.
//!
//! This follows Cleveland et al. (1990), "STL: A Seasonal-Trend Decomposition
//! Procedure Based on Loess", Journal of Official Statistics 6(1), and mirrors
//! the reference Fortran implementation that R's `stl()` calls, including its
//! defaults, so results line up with R to within floating-point noise.

use std::fmt;

/// Degree of the local polynomial fitted by a loess smoother.
///
/// STL only uses locally constant or locally linear fits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Degree {
    /// Locally constant (weighted moving average).
    Constant,
    /// Locally linear.
    Linear,
}

/// Span of the seasonal (cycle-subseries) smoother.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SeasonalWindow {
    /// Force an identical seasonal pattern in every cycle. Same as
    /// `s.window = "periodic"` in R: the cycle-subseries are smoothed with a
    /// span wider than the series and the seasonal component is then replaced by
    /// its per-phase mean.
    Periodic,
    /// Loess span, in cycles (the paper's `n_s`). Must be odd and at least 7.
    /// Larger values give a seasonal pattern that changes more slowly.
    Window(usize),
}

/// Why an STL or MSTL decomposition couldn't run.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum StlError {
    /// The series contains `NaN` or an infinite value at this index.
    NonFinite {
        /// Position of the first offending value.
        index: usize,
    },
    /// The seasonal period is below 2.
    PeriodTooShort {
        /// The rejected period.
        period: usize,
    },
    /// The series doesn't cover at least two full periods.
    SeriesTooShort {
        /// Length of the series.
        len: usize,
        /// The period it was checked against.
        period: usize,
    },
    /// A smoother window is even. Loess spans must be odd so they center on a point.
    EvenWindow {
        /// Which window (`"seasonal"`, `"trend"` or `"low-pass"`).
        name: &'static str,
        /// The rejected value.
        value: usize,
    },
    /// A smoother window is below its minimum (7 for seasonal, 3 otherwise).
    WindowTooSmall {
        /// Which window (`"seasonal"`, `"trend"` or `"low-pass"`).
        name: &'static str,
        /// The rejected value.
        value: usize,
        /// Smallest accepted value.
        min: usize,
    },
    /// A jump (evaluation stride) of zero was given.
    ZeroJump {
        /// Which smoother (`"seasonal"`, `"trend"` or `"low-pass"`).
        name: &'static str,
    },
    /// The inner loop count was zero.
    ZeroInnerIterations,
    /// MSTL was given no periods.
    NoPeriods,
    /// MSTL was given the same period twice.
    DuplicatePeriod {
        /// The repeated period.
        period: usize,
    },
    /// MSTL was given a number of seasonal windows that doesn't match the
    /// number of periods.
    WindowCountMismatch {
        /// Number of periods.
        periods: usize,
        /// Number of seasonal windows.
        windows: usize,
    },
}

impl fmt::Display for StlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NonFinite { index } => write!(f, "series value at index {index} is not finite"),
            Self::PeriodTooShort { period } => {
                write!(f, "period must be at least 2, got {period}")
            }
            Self::SeriesTooShort { len, period } => write!(
                f,
                "series of length {len} is shorter than two periods of {period}"
            ),
            Self::EvenWindow { name, value } => {
                write!(f, "{name} window must be odd, got {value}")
            }
            Self::WindowTooSmall { name, value, min } => {
                write!(f, "{name} window must be at least {min}, got {value}")
            }
            Self::ZeroJump { name } => write!(f, "{name} jump must be at least 1"),
            Self::ZeroInnerIterations => f.write_str("inner iterations must be at least 1"),
            Self::NoPeriods => f.write_str("at least one seasonal period is required"),
            Self::DuplicatePeriod { period } => write!(f, "period {period} was given twice"),
            Self::WindowCountMismatch { periods, windows } => {
                write!(f, "got {windows} seasonal windows for {periods} periods")
            }
        }
    }
}

impl std::error::Error for StlError {}

/// Result of an STL fit. All vectors have the same length as the input and
/// `series[i] == trend[i] + seasonal[i] + remainder[i]` up to rounding.
#[derive(Debug, Clone, PartialEq)]
pub struct StlDecomposition {
    /// Smooth long-run component.
    pub trend: Vec<f64>,
    /// Repeating component with the given period.
    pub seasonal: Vec<f64>,
    /// What's left: `series - trend - seasonal`.
    pub remainder: Vec<f64>,
    /// Final bisquare robustness weights in `[0, 1]`. Points the fit treated as
    /// outliers get weights near zero. All ones when no robustness iterations ran.
    pub weights: Vec<f64>,
}

impl StlDecomposition {
    /// Strength of the trend, `max(0, 1 - Var(R) / Var(T + R))`, after Wang,
    /// Smith & Hyndman (2006). Close to 1 for a series dominated by its trend,
    /// close to 0 when the trend explains little beyond the noise.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_season_decomp::Stl;
    ///
    /// let series: Vec<f64> = (0..48).map(|i| i as f64 + [0.0, 2.0, 0.0, -2.0][i % 4]).collect();
    /// let fit = Stl::new(4, 7).fit(&series)?;
    /// assert!(fit.trend_strength() > 0.9);
    /// # Ok::<(), rune_season_decomp::StlError>(())
    /// ```
    #[must_use]
    pub fn trend_strength(&self) -> f64 {
        strength(&self.trend, &self.remainder)
    }

    /// Strength of the seasonality, `max(0, 1 - Var(R) / Var(S + R))`, after
    /// Wang, Smith & Hyndman (2006).
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_season_decomp::Stl;
    ///
    /// let series: Vec<f64> = (0..48).map(|i| [0.0, 5.0, 0.0, -5.0][i % 4]).collect();
    /// let fit = Stl::new(4, 7).fit(&series)?;
    /// assert!(fit.seasonal_strength() > 0.9);
    /// # Ok::<(), rune_season_decomp::StlError>(())
    /// ```
    #[must_use]
    pub fn seasonal_strength(&self) -> f64 {
        strength(&self.seasonal, &self.remainder)
    }
}

/// Strength of a component relative to the remainder.
///
/// Computes `max(0, 1 - Var(remainder) / Var(component + remainder))`, as
/// defined by Wang, Smith & Hyndman (2006), "Characteristic-based clustering
/// for time series data". Returns 0 when `component + remainder` has no variance, and
/// only uses the common prefix if the slices differ in length.
///
/// # Example
///
/// ```rust
/// use rune_season_decomp::strength;
///
/// let component = [1.0, -1.0, 1.0, -1.0];
/// let remainder = [0.0, 0.0, 0.0, 0.0];
/// assert!((strength(&component, &remainder) - 1.0).abs() < 1e-12);
/// ```
#[must_use]
pub fn strength(component: &[f64], remainder: &[f64]) -> f64 {
    let n = component.len().min(remainder.len());
    let combined: Vec<f64> = component[..n]
        .iter()
        .zip(&remainder[..n])
        .map(|(c, r)| c + r)
        .collect();
    let total = variance(&combined);
    if total <= 0.0 || !total.is_finite() {
        return 0.0;
    }
    (1.0 - variance(&remainder[..n]) / total).clamp(0.0, 1.0)
}

#[allow(
    clippy::cast_precision_loss,
    reason = "lengths stay far below 2^52, so the f64 conversion is exact"
)]
fn variance(values: &[f64]) -> f64 {
    if values.len() < 2 {
        return 0.0;
    }
    let n = values.len() as f64;
    let mean = values.iter().sum::<f64>() / n;
    values.iter().map(|v| (v - mean).powi(2)).sum::<f64>() / (n - 1.0)
}

/// STL decomposition settings, built with [`Stl::new`] or [`Stl::periodic`]
/// and run with [`Stl::fit`].
///
/// Anything not set explicitly takes R's `stl()` default:
///
/// | setting | paper | default |
/// |---|---|---|
/// | period | `n_p` | required |
/// | seasonal window | `n_s` | required (odd, ≥ 7) or periodic |
/// | trend window | `n_t` | smallest odd ≥ `1.5 n_p / (1 - 1.5 / n_s)` |
/// | low-pass window | `n_l` | smallest odd ≥ `n_p` |
/// | seasonal degree | | 0 ([`Degree::Constant`]) |
/// | trend degree | | 1 ([`Degree::Linear`]) |
/// | low-pass degree | | same as the trend degree |
/// | jumps | | `ceil(window / 10)` for each smoother |
/// | inner loops | `n_i` | 2, or 1 when robust |
/// | outer loops | `n_o` | 0, or 15 when robust |
///
/// The paper itself fits the seasonal smoother with degree 1; set
/// [`Stl::seasonal_degree`] to [`Degree::Linear`] for that.
///
/// # Example
///
/// ```rust
/// use rune_season_decomp::Stl;
///
/// let series: Vec<f64> = (0..60)
///     .map(|i| 0.1 * i as f64 + [3.0, 1.0, -1.0, -3.0, 0.0][i % 5])
///     .collect();
/// let fit = Stl::new(5, 7).robust(true).fit(&series)?;
/// for i in 0..series.len() {
///     let sum = fit.trend[i] + fit.seasonal[i] + fit.remainder[i];
///     assert!((sum - series[i]).abs() < 1e-9);
/// }
/// # Ok::<(), rune_season_decomp::StlError>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stl {
    period: usize,
    seasonal: SeasonalWindow,
    seasonal_degree: Degree,
    trend_window: Option<usize>,
    trend_degree: Degree,
    low_pass_window: Option<usize>,
    low_pass_degree: Option<Degree>,
    seasonal_jump: Option<usize>,
    trend_jump: Option<usize>,
    low_pass_jump: Option<usize>,
    inner: Option<usize>,
    outer: Option<usize>,
    robust: bool,
}

impl Stl {
    /// STL with a seasonal smoother spanning `seasonal_window` cycles
    /// (odd, at least 7; checked by [`Stl::fit`]).
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_season_decomp::Stl;
    ///
    /// let stl = Stl::new(12, 7);
    /// # let _ = stl;
    /// ```
    #[must_use]
    pub const fn new(period: usize, seasonal_window: usize) -> Self {
        Self::with_window(period, SeasonalWindow::Window(seasonal_window))
    }

    /// STL with a strictly periodic seasonal component (R's
    /// `s.window = "periodic"`).
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_season_decomp::Stl;
    ///
    /// let series: Vec<f64> = (0..36).map(|i| i as f64 + [1.0, 0.0, -1.0][i % 3]).collect();
    /// let fit = Stl::periodic(3).fit(&series)?;
    /// assert!((fit.seasonal[0] - fit.seasonal[3]).abs() < 1e-12);
    /// # Ok::<(), rune_season_decomp::StlError>(())
    /// ```
    #[must_use]
    pub const fn periodic(period: usize) -> Self {
        Self::with_window(period, SeasonalWindow::Periodic)
    }

    /// STL with an explicit [`SeasonalWindow`].
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_season_decomp::{SeasonalWindow, Stl};
    ///
    /// assert_eq!(Stl::with_window(12, SeasonalWindow::Periodic), Stl::periodic(12));
    /// ```
    #[must_use]
    pub const fn with_window(period: usize, seasonal: SeasonalWindow) -> Self {
        Self {
            period,
            seasonal,
            seasonal_degree: Degree::Constant,
            trend_window: None,
            trend_degree: Degree::Linear,
            low_pass_window: None,
            low_pass_degree: None,
            seasonal_jump: None,
            trend_jump: None,
            low_pass_jump: None,
            inner: None,
            outer: None,
            robust: false,
        }
    }

    /// Degree of the seasonal smoother. Ignored for [`SeasonalWindow::Periodic`],
    /// which always uses [`Degree::Constant`].
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_season_decomp::{Degree, Stl};
    ///
    /// let stl = Stl::new(12, 7).seasonal_degree(Degree::Linear);
    /// # let _ = stl;
    /// ```
    #[must_use]
    pub const fn seasonal_degree(mut self, degree: Degree) -> Self {
        self.seasonal_degree = degree;
        self
    }

    /// Span of the trend smoother (`n_t`, odd, at least 3).
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_season_decomp::Stl;
    ///
    /// let stl = Stl::new(12, 7).trend_window(31);
    /// # let _ = stl;
    /// ```
    #[must_use]
    pub const fn trend_window(mut self, window: usize) -> Self {
        self.trend_window = Some(window);
        self
    }

    /// Degree of the trend smoother.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_season_decomp::{Degree, Stl};
    ///
    /// let stl = Stl::new(12, 7).trend_degree(Degree::Constant);
    /// # let _ = stl;
    /// ```
    #[must_use]
    pub const fn trend_degree(mut self, degree: Degree) -> Self {
        self.trend_degree = degree;
        self
    }

    /// Span of the low-pass filter's loess step (`n_l`, odd, at least 3).
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_season_decomp::Stl;
    ///
    /// let stl = Stl::new(12, 7).low_pass_window(13);
    /// # let _ = stl;
    /// ```
    #[must_use]
    pub const fn low_pass_window(mut self, window: usize) -> Self {
        self.low_pass_window = Some(window);
        self
    }

    /// Degree of the low-pass filter's loess step.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_season_decomp::{Degree, Stl};
    ///
    /// let stl = Stl::new(12, 7).low_pass_degree(Degree::Constant);
    /// # let _ = stl;
    /// ```
    #[must_use]
    pub const fn low_pass_degree(mut self, degree: Degree) -> Self {
        self.low_pass_degree = Some(degree);
        self
    }

    /// Evaluation strides for the seasonal, trend and low-pass smoothers. Loess
    /// is evaluated at every `jump`-th point and linearly interpolated in
    /// between, which trades a little accuracy for speed on long series. Use 1
    /// everywhere for the exact fit.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_season_decomp::Stl;
    ///
    /// let exact = Stl::new(12, 7).jumps(1, 1, 1);
    /// # let _ = exact;
    /// ```
    #[must_use]
    pub const fn jumps(mut self, seasonal: usize, trend: usize, low_pass: usize) -> Self {
        self.seasonal_jump = Some(seasonal);
        self.trend_jump = Some(trend);
        self.low_pass_jump = Some(low_pass);
        self
    }

    /// Number of inner-loop passes (`n_i`) per outer iteration.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_season_decomp::Stl;
    ///
    /// let stl = Stl::new(12, 7).inner_iterations(5);
    /// # let _ = stl;
    /// ```
    #[must_use]
    pub const fn inner_iterations(mut self, inner: usize) -> Self {
        self.inner = Some(inner);
        self
    }

    /// Number of robustness (outer-loop) iterations (`n_o`). Each one
    /// recomputes the bisquare weights from the current remainder and refits.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_season_decomp::Stl;
    ///
    /// let stl = Stl::new(12, 7).outer_iterations(10);
    /// # let _ = stl;
    /// ```
    #[must_use]
    pub const fn outer_iterations(mut self, outer: usize) -> Self {
        self.outer = Some(outer);
        self
    }

    /// Turns on robust fitting, which changes the default loop counts to one
    /// inner and fifteen outer iterations so outliers end up in the remainder
    /// instead of bending the trend and seasonal components. Explicit
    /// [`Stl::inner_iterations`] / [`Stl::outer_iterations`] still win.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_season_decomp::Stl;
    ///
    /// let stl = Stl::new(12, 7).robust(true);
    /// # let _ = stl;
    /// ```
    #[must_use]
    pub const fn robust(mut self, robust: bool) -> Self {
        self.robust = robust;
        self
    }

    /// The period this decomposition uses.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_season_decomp::Stl;
    ///
    /// assert_eq!(Stl::new(12, 7).period(), 12);
    /// ```
    #[must_use]
    pub const fn period(&self) -> usize {
        self.period
    }

    /// Decomposes `series` into trend, seasonal and remainder.
    ///
    /// # Errors
    ///
    /// Returns [`StlError`] if the series has non-finite values, the period is
    /// below 2, the series is shorter than two periods, any window is even or
    /// too small, a jump is zero, or the inner iteration count is zero.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_season_decomp::{Stl, StlError};
    ///
    /// let series: Vec<f64> = (0..24).map(|i| [1.0, 2.0, 3.0][i % 3]).collect();
    /// let fit = Stl::new(3, 7).fit(&series)?;
    /// assert_eq!(fit.trend.len(), 24);
    ///
    /// assert_eq!(
    ///     Stl::new(3, 8).fit(&series),
    ///     Err(StlError::EvenWindow { name: "seasonal", value: 8 })
    /// );
    /// # Ok::<(), StlError>(())
    /// ```
    pub fn fit(&self, series: &[f64]) -> Result<StlDecomposition, StlError> {
        let cfg = self.resolve(series)?;
        let n = series.len();
        let mut trend = vec![0.0; n];
        let mut seasonal = vec![0.0; n];
        let mut weights = vec![1.0; n];
        let mut work = Workspace::new(n, cfg.period);

        let mut use_weights = false;
        let mut pass = 0;
        loop {
            inner_loop(
                series,
                &cfg,
                use_weights.then_some(weights.as_slice()),
                &mut seasonal,
                &mut trend,
                &mut work,
            );
            pass += 1;
            if pass > cfg.outer {
                break;
            }
            for i in 0..n {
                work.fit[i] = trend[i] + seasonal[i];
            }
            robustness_weights(series, &work.fit, &mut weights);
            use_weights = true;
        }
        if cfg.outer == 0 {
            weights.fill(1.0);
        }

        if self.seasonal == SeasonalWindow::Periodic {
            make_periodic(&mut seasonal, cfg.period);
        }

        let remainder = series
            .iter()
            .zip(trend.iter().zip(&seasonal))
            .map(|(y, (t, s))| y - t - s)
            .collect();
        Ok(StlDecomposition {
            trend,
            seasonal,
            remainder,
            weights,
        })
    }

    fn resolve(&self, series: &[f64]) -> Result<Resolved, StlError> {
        if let Some(index) = series.iter().position(|v| !v.is_finite()) {
            return Err(StlError::NonFinite { index });
        }
        let period = self.period;
        if period < 2 {
            return Err(StlError::PeriodTooShort { period });
        }
        let n = series.len();
        if n < period.saturating_mul(2) {
            return Err(StlError::SeriesTooShort { len: n, period });
        }

        let (seasonal_window, seasonal_degree) = match self.seasonal {
            SeasonalWindow::Periodic => (n.saturating_mul(10).saturating_add(1), Degree::Constant),
            SeasonalWindow::Window(w) => {
                check_window("seasonal", w, 7)?;
                (w, self.seasonal_degree)
            }
        };
        let trend_window = match self.trend_window {
            Some(w) => {
                check_window("trend", w, 3)?;
                w
            }
            None => default_trend_window(period, seasonal_window),
        };
        let low_pass_window = match self.low_pass_window {
            Some(w) => {
                check_window("low-pass", w, 3)?;
                w
            }
            None => next_odd(period),
        };

        let seasonal_jump = jump_or_default("seasonal", self.seasonal_jump, seasonal_window)?;
        let trend_jump = jump_or_default("trend", self.trend_jump, trend_window)?;
        let low_pass_jump = jump_or_default("low-pass", self.low_pass_jump, low_pass_window)?;

        let inner = self.inner.unwrap_or(if self.robust { 1 } else { 2 });
        if inner == 0 {
            return Err(StlError::ZeroInnerIterations);
        }
        let outer = self.outer.unwrap_or(if self.robust { 15 } else { 0 });

        Ok(Resolved {
            period,
            seasonal_window,
            seasonal_degree,
            seasonal_jump,
            trend_window,
            trend_degree: self.trend_degree,
            trend_jump,
            low_pass_window,
            low_pass_degree: self.low_pass_degree.unwrap_or(self.trend_degree),
            low_pass_jump,
            inner,
            outer,
        })
    }
}

const fn check_window(name: &'static str, value: usize, min: usize) -> Result<(), StlError> {
    if value.is_multiple_of(2) {
        return Err(StlError::EvenWindow { name, value });
    }
    if value < min {
        return Err(StlError::WindowTooSmall { name, value, min });
    }
    Ok(())
}

const fn jump_or_default(
    name: &'static str,
    jump: Option<usize>,
    window: usize,
) -> Result<usize, StlError> {
    match jump {
        Some(0) => Err(StlError::ZeroJump { name }),
        Some(j) => Ok(j),
        None => Ok(window.div_ceil(10)),
    }
}

/// Smallest odd integer at or above `x`, the way R rounds window sizes.
const fn next_odd(x: usize) -> usize {
    if x.is_multiple_of(2) { x + 1 } else { x }
}

/// R's default trend span: `nextodd(ceiling(1.5 * period / (1 - 1.5 / s.window)))`.
#[allow(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    reason = "period and window are small positive counts; the result is a small positive span"
)]
fn default_trend_window(period: usize, seasonal_window: usize) -> usize {
    let raw = (1.5 * period as f64 / (1.0 - 1.5 / seasonal_window as f64)).ceil();
    next_odd((raw as usize).max(3))
}

/// Replaces each seasonal value by the mean over its phase, so every cycle is identical.
#[allow(
    clippy::cast_precision_loss,
    reason = "counts stay far below 2^52, so the f64 conversion is exact"
)]
fn make_periodic(seasonal: &mut [f64], period: usize) {
    let mut sums = vec![0.0; period];
    let mut counts = vec![0usize; period];
    for (i, s) in seasonal.iter().enumerate() {
        sums[i % period] += s;
        counts[i % period] += 1;
    }
    for (i, s) in seasonal.iter_mut().enumerate() {
        let phase = i % period;
        *s = sums[phase] / counts[phase] as f64;
    }
}

#[derive(Debug, Clone, Copy)]
struct Resolved {
    period: usize,
    seasonal_window: usize,
    seasonal_degree: Degree,
    seasonal_jump: usize,
    trend_window: usize,
    trend_degree: Degree,
    trend_jump: usize,
    low_pass_window: usize,
    low_pass_degree: Degree,
    low_pass_jump: usize,
    inner: usize,
    outer: usize,
}

/// Scratch buffers reused across iterations.
struct Workspace {
    detrended: Vec<f64>,
    /// Cycle-subseries smooth, extended one period on each side (length n + 2 * period).
    cycle: Vec<f64>,
    ma1: Vec<f64>,
    ma2: Vec<f64>,
    low_pass: Vec<f64>,
    deseasonal: Vec<f64>,
    fit: Vec<f64>,
    loess_weights: Vec<f64>,
    sub: Vec<f64>,
    sub_rw: Vec<f64>,
    sub_fit: Vec<f64>,
}

impl Workspace {
    fn new(n: usize, period: usize) -> Self {
        let ext = n + 2 * period;
        let sub_len = n / period + 1;
        Self {
            detrended: vec![0.0; n],
            cycle: vec![0.0; ext],
            ma1: vec![0.0; ext],
            ma2: vec![0.0; ext],
            low_pass: vec![0.0; n],
            deseasonal: vec![0.0; n],
            fit: vec![0.0; n],
            loess_weights: vec![0.0; ext],
            sub: vec![0.0; sub_len],
            sub_rw: vec![0.0; sub_len],
            sub_fit: vec![0.0; sub_len + 2],
        }
    }
}

/// One outer iteration: `inner` passes of detrend, cycle-subseries smoothing,
/// low-pass filtering, deseasonalising and trend smoothing (steps 1–6 of the paper).
fn inner_loop(
    y: &[f64],
    cfg: &Resolved,
    rw: Option<&[f64]>,
    seasonal: &mut [f64],
    trend: &mut [f64],
    work: &mut Workspace,
) {
    let n = y.len();
    let np = cfg.period;
    for _ in 0..cfg.inner {
        for i in 0..n {
            work.detrended[i] = y[i] - trend[i];
        }
        let detrended = std::mem::take(&mut work.detrended);
        cycle_subseries(&detrended, cfg, rw, work);
        work.detrended = detrended;

        // Low-pass filter of the extended cycle smooth: MA(np), MA(np), MA(3), loess.
        let ext = n + 2 * np;
        moving_average(&work.cycle[..ext], np, &mut work.ma1);
        moving_average(&work.ma1[..=(ext - np)], np, &mut work.ma2);
        moving_average(&work.ma2[..ext - 2 * np + 2], 3, &mut work.ma1);
        loess(
            &work.ma1[..n],
            cfg.low_pass_window,
            cfg.low_pass_degree,
            cfg.low_pass_jump,
            None,
            &mut work.low_pass,
            &mut work.loess_weights,
        );

        for i in 0..n {
            seasonal[i] = work.cycle[np + i] - work.low_pass[i];
            work.deseasonal[i] = y[i] - seasonal[i];
        }
        loess(
            &work.deseasonal,
            cfg.trend_window,
            cfg.trend_degree,
            cfg.trend_jump,
            rw,
            trend,
            &mut work.loess_weights,
        );
    }
}

/// Smooths each cycle-subseries with loess and extrapolates one step past both
/// ends, writing the result into `work.cycle` (length `n + 2 * period`).
fn cycle_subseries(y: &[f64], cfg: &Resolved, rw: Option<&[f64]>, work: &mut Workspace) {
    let n = y.len();
    let np = cfg.period;
    let ns = cfg.seasonal_window;
    for phase in 0..np {
        let k = (n - 1 - phase) / np + 1;
        for i in 0..k {
            work.sub[i] = y[i * np + phase];
            if let Some(rw) = rw {
                work.sub_rw[i] = rw[i * np + phase];
            }
        }
        let sub = &work.sub[..k];
        let sub_rw = rw.map(|_| &work.sub_rw[..k]);
        loess(
            sub,
            ns,
            cfg.seasonal_degree,
            cfg.seasonal_jump,
            sub_rw,
            &mut work.sub_fit[1..=k],
            &mut work.loess_weights,
        );
        let nright = ns.min(k);
        work.sub_fit[0] = loess_at(
            sub,
            ns,
            cfg.seasonal_degree,
            0.0,
            1,
            nright,
            &mut work.loess_weights,
            sub_rw,
        )
        .unwrap_or(work.sub_fit[1]);
        let nleft = k.saturating_sub(ns) + 1;
        work.sub_fit[k + 1] = loess_at(
            sub,
            ns,
            cfg.seasonal_degree,
            to_f64(k + 1),
            nleft,
            k,
            &mut work.loess_weights,
            sub_rw,
        )
        .unwrap_or(work.sub_fit[k]);
        for m in 0..k + 2 {
            work.cycle[m * np + phase] = work.sub_fit[m];
        }
    }
}

#[allow(
    clippy::cast_precision_loss,
    reason = "indices stay far below 2^52, so the f64 conversion is exact"
)]
const fn to_f64(x: usize) -> f64 {
    x as f64
}

/// Running mean of width `len`; writes `x.len() - len + 1` values into `out`.
fn moving_average(x: &[f64], len: usize, out: &mut [f64]) {
    let count = x.len() + 1 - len;
    let width = to_f64(len);
    let mut sum: f64 = x[..len].iter().sum();
    out[0] = sum / width;
    for j in 1..count {
        sum += x[j + len - 1] - x[j - 1];
        out[j] = sum / width;
    }
}

/// Loess smooth of `y` with span `len`, evaluated every `jump` points and
/// linearly interpolated in between. Positions are 1-based, as in the paper.
#[allow(
    clippy::too_many_arguments,
    clippy::many_single_char_names,
    reason = "mirrors the reference routine and the paper's notation"
)]
fn loess(
    y: &[f64],
    len: usize,
    degree: Degree,
    jump: usize,
    rw: Option<&[f64]>,
    ys: &mut [f64],
    w: &mut [f64],
) {
    let n = y.len();
    if n == 0 {
        return;
    }
    if n < 2 {
        ys[0] = y[0];
        return;
    }
    let jump = jump.clamp(1, n - 1);
    let mut nleft = 1;
    let mut nright = n;
    if len >= n {
        for i in (1..=n).step_by(jump) {
            ys[i - 1] =
                loess_at(y, len, degree, to_f64(i), nleft, nright, w, rw).unwrap_or(y[i - 1]);
        }
    } else if jump == 1 {
        let half = len.div_ceil(2);
        nright = len;
        for i in 1..=n {
            if i > half && nright != n {
                nleft += 1;
                nright += 1;
            }
            ys[i - 1] =
                loess_at(y, len, degree, to_f64(i), nleft, nright, w, rw).unwrap_or(y[i - 1]);
        }
    } else {
        let half = len.div_ceil(2);
        for i in (1..=n).step_by(jump) {
            if i < half {
                nleft = 1;
                nright = len;
            } else if i > n - half {
                nleft = n - len + 1;
                nright = n;
            } else {
                nleft = i + 1 - half;
                nright = len + i - half;
            }
            ys[i - 1] =
                loess_at(y, len, degree, to_f64(i), nleft, nright, w, rw).unwrap_or(y[i - 1]);
        }
    }

    if jump != 1 {
        let mut i = 1;
        while i + jump <= n {
            let delta = (ys[i + jump - 1] - ys[i - 1]) / to_f64(jump);
            for j in i + 1..i + jump {
                ys[j - 1] = delta.mul_add(to_f64(j - i), ys[i - 1]);
            }
            i += jump;
        }
        let k = ((n - 1) / jump) * jump + 1;
        if k != n {
            ys[n - 1] =
                loess_at(y, len, degree, to_f64(n), nleft, nright, w, rw).unwrap_or(y[n - 1]);
            if k != n - 1 {
                let delta = (ys[n - 1] - ys[k - 1]) / to_f64(n - k);
                for j in k + 1..n {
                    ys[j - 1] = delta.mul_add(to_f64(j - k), ys[k - 1]);
                }
            }
        }
    }
}

/// Loess estimate at 1-based position `xs` from the points `nleft..=nright`
/// with tricube neighbourhood weights (times the robustness weights, if any).
/// Returns `None` when every weight is zero.
#[allow(
    clippy::too_many_arguments,
    clippy::many_single_char_names,
    reason = "mirrors the reference routine and the paper's notation"
)]
fn loess_at(
    y: &[f64],
    len: usize,
    degree: Degree,
    xs: f64,
    nleft: usize,
    nright: usize,
    w: &mut [f64],
    rw: Option<&[f64]>,
) -> Option<f64> {
    let n = y.len();
    let range = to_f64(n) - 1.0;
    let mut h = (xs - to_f64(nleft)).max(to_f64(nright) - xs);
    if len > n {
        h += to_f64((len - n) / 2);
    }
    let h9 = 0.999 * h;
    let h1 = 0.001 * h;

    let mut total = 0.0;
    for j in nleft..=nright {
        let r = (to_f64(j) - xs).abs();
        let mut wj = 0.0;
        if r <= h9 {
            wj = if r <= h1 {
                1.0
            } else {
                (1.0 - (r / h).powi(3)).powi(3)
            };
            if let Some(rw) = rw {
                wj *= rw[j - 1];
            }
            total += wj;
        }
        w[j - 1] = wj;
    }
    if total <= 0.0 {
        return None;
    }
    for wj in &mut w[nleft - 1..nright] {
        *wj /= total;
    }

    if h > 0.0 && degree == Degree::Linear {
        let mut center = 0.0;
        for j in nleft..=nright {
            center = w[j - 1].mul_add(to_f64(j), center);
        }
        let mut c = 0.0;
        for j in nleft..=nright {
            c = w[j - 1].mul_add((to_f64(j) - center).powi(2), c);
        }
        if c.sqrt() > 0.001 * range {
            let slope = (xs - center) / c;
            for j in nleft..=nright {
                w[j - 1] *= slope.mul_add(to_f64(j) - center, 1.0);
            }
        }
    }

    Some((nleft..=nright).map(|j| w[j - 1] * y[j - 1]).sum())
}

/// Bisquare robustness weights from the residuals `y - fit`, scaled by six
/// times their median absolute value.
///
/// For even lengths the median is the mean of the two true middle values. The
/// reference Fortran asks its partial sort for those two positions in an order
/// it doesn't handle, so R's robust fits on even-length series can differ
/// slightly from ours; odd lengths match exactly.
fn robustness_weights(y: &[f64], fit: &[f64], rw: &mut [f64]) {
    let n = y.len();
    let mut abs: Vec<f64> = y.iter().zip(fit).map(|(a, b)| (a - b).abs()).collect();
    abs.sort_unstable_by(f64::total_cmp);
    let mid1 = n / 2;
    let mid2 = n - mid1 - 1;
    let cmad = 3.0 * (abs[mid1] + abs[mid2]);
    let c9 = 0.999 * cmad;
    let c1 = 0.001 * cmad;
    for i in 0..n {
        let r = (y[i] - fit[i]).abs();
        rw[i] = if r <= c1 {
            1.0
        } else if r <= c9 {
            (-(r / cmad)).mul_add(r / cmad, 1.0).powi(2)
        } else {
            0.0
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_trend_window_matches_r() {
        // R: nextodd(ceiling(1.5 * 12 / (1 - 1.5 / 7))) = 23
        assert_eq!(default_trend_window(12, 7), 23);
        assert_eq!(default_trend_window(7, 11), 13);
    }

    #[test]
    fn moving_average_window_three() {
        let mut out = [0.0; 3];
        moving_average(&[1.0, 2.0, 3.0, 4.0, 5.0], 3, &mut out);
        assert_eq!(out, [2.0, 3.0, 4.0]);
    }

    #[test]
    fn loess_reproduces_a_line() {
        let y: Vec<f64> = (0..20).map(|i| 2.0f64.mul_add(f64::from(i), 1.0)).collect();
        let mut ys = vec![0.0; 20];
        let mut w = vec![0.0; 20];
        for jump in [1, 3] {
            loess(&y, 7, Degree::Linear, jump, None, &mut ys, &mut w);
            for (a, b) in y.iter().zip(&ys) {
                assert!((a - b).abs() < 1e-9, "jump {jump}: {a} vs {b}");
            }
        }
    }

    #[test]
    fn robustness_weights_zero_out_gross_outliers() {
        let y = [0.0, 0.1, -0.1, 0.05, 100.0, -0.05, 0.0];
        let fit = [0.0; 7];
        let mut rw = [0.0; 7];
        robustness_weights(&y, &fit, &mut rw);
        assert!(rw[4].abs() < 1e-12);
        assert!(rw[0] > 0.99);
    }
}
