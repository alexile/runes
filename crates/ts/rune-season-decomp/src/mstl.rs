//! MSTL: STL extended to several seasonal periods.
//!
//! Follows Bandara, Hyndman & Bergmeir (2021), "MSTL: A Seasonal-Trend
//! Decomposition Algorithm for Time Series with Multiple Seasonal Patterns":
//! each seasonal component is extracted in turn with STL, shortest period
//! first, and the whole sweep is repeated a few times so every component is
//! estimated from a series with the others removed.

use crate::stl::{Stl, StlError, strength};

/// Result of an MSTL fit. `series[i] == trend[i] + sum(seasonal[k][i]) + remainder[i]`
/// up to rounding.
#[derive(Debug, Clone, PartialEq)]
pub struct MstlDecomposition {
    /// The periods, sorted ascending; `seasonal[k]` belongs to `periods[k]`.
    pub periods: Vec<usize>,
    /// Smooth long-run component, from the last STL pass.
    pub trend: Vec<f64>,
    /// One seasonal component per period, each as long as the input.
    pub seasonal: Vec<Vec<f64>>,
    /// What's left after removing the trend and every seasonal component.
    pub remainder: Vec<f64>,
}

impl MstlDecomposition {
    /// Trend strength, `max(0, 1 - Var(R) / Var(T + R))` (Wang, Smith & Hyndman 2006).
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_season_decomp::Mstl;
    ///
    /// let series: Vec<f64> = (0..120).map(|i| i as f64 + [1.0, -1.0][i % 2]).collect();
    /// let fit = Mstl::new(&[2, 5]).fit(&series)?;
    /// assert!(fit.trend_strength() > 0.9);
    /// # Ok::<(), rune_season_decomp::StlError>(())
    /// ```
    #[must_use]
    pub fn trend_strength(&self) -> f64 {
        strength(&self.trend, &self.remainder)
    }

    /// Strength of each seasonal component, `max(0, 1 - Var(R) / Var(S_k + R))`,
    /// in the same order as [`MstlDecomposition::periods`].
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_season_decomp::Mstl;
    ///
    /// let series: Vec<f64> = (0..120).map(|i| [3.0, -3.0][i % 2]).collect();
    /// let fit = Mstl::new(&[2, 5]).fit(&series)?;
    /// let s = fit.seasonal_strengths();
    /// assert!(s[0] > 0.9);
    /// # Ok::<(), rune_season_decomp::StlError>(())
    /// ```
    #[must_use]
    pub fn seasonal_strengths(&self) -> Vec<f64> {
        self.seasonal
            .iter()
            .map(|s| strength(s, &self.remainder))
            .collect()
    }
}

/// MSTL settings, built with [`Mstl::new`] and run with [`Mstl::fit`].
///
/// Defaults match R's `forecast::mstl()`: two sweeps, seasonal windows
/// `11, 15, 19, …` (that is `7 + 4k` for the `k`-th shortest period), and R's
/// `stl()` defaults for everything else.
///
/// # Example
///
/// ```rust
/// use rune_season_decomp::Mstl;
///
/// // Hourly-ish data with a daily (24) and a half-weekly (84) cycle.
/// let series: Vec<f64> = (0..840)
///     .map(|i| {
///         let t = i as f64;
///         10.0 + (t * std::f64::consts::TAU / 24.0).sin()
///             + 2.0 * (t * std::f64::consts::TAU / 84.0).sin()
///     })
///     .collect();
/// let fit = Mstl::new(&[84, 24]).fit(&series)?;
/// assert_eq!(fit.periods, vec![24, 84]);
/// assert_eq!(fit.seasonal.len(), 2);
/// # Ok::<(), rune_season_decomp::StlError>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mstl {
    periods: Vec<usize>,
    seasonal_windows: Option<Vec<usize>>,
    iterations: usize,
    robust: bool,
}

impl Mstl {
    /// MSTL over the given seasonal periods (any order; they're sorted ascending).
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_season_decomp::Mstl;
    ///
    /// let mstl = Mstl::new(&[7, 365]);
    /// # let _ = mstl;
    /// ```
    #[must_use]
    pub fn new(periods: &[usize]) -> Self {
        Self {
            periods: periods.to_vec(),
            seasonal_windows: None,
            iterations: 2,
            robust: false,
        }
    }

    /// Seasonal windows, one per period, in the same order as the periods
    /// passed to [`Mstl::new`]. Each must be odd and at least 7.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_season_decomp::Mstl;
    ///
    /// let mstl = Mstl::new(&[7, 30]).seasonal_windows(&[9, 13]);
    /// # let _ = mstl;
    /// ```
    #[must_use]
    pub fn seasonal_windows(mut self, windows: &[usize]) -> Self {
        self.seasonal_windows = Some(windows.to_vec());
        self
    }

    /// Number of sweeps over all seasonal components (default 2). Zero is
    /// treated as one.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_season_decomp::Mstl;
    ///
    /// let mstl = Mstl::new(&[7, 30]).iterations(3);
    /// # let _ = mstl;
    /// ```
    #[must_use]
    pub const fn iterations(mut self, iterations: usize) -> Self {
        self.iterations = iterations;
        self
    }

    /// Use robust STL for every component.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_season_decomp::Mstl;
    ///
    /// let mstl = Mstl::new(&[7, 30]).robust(true);
    /// # let _ = mstl;
    /// ```
    #[must_use]
    pub const fn robust(mut self, robust: bool) -> Self {
        self.robust = robust;
        self
    }

    /// Decomposes `series` into a trend, one seasonal component per period, and
    /// a remainder.
    ///
    /// # Errors
    ///
    /// Returns [`StlError`] for an empty or duplicated period list, a window
    /// count that doesn't match the periods, or anything [`Stl::fit`] rejects
    /// (each period must fit at least twice in the series).
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_season_decomp::{Mstl, StlError};
    ///
    /// let series = vec![1.0; 30];
    /// assert_eq!(Mstl::new(&[]).fit(&series), Err(StlError::NoPeriods));
    /// assert_eq!(
    ///     Mstl::new(&[4, 4]).fit(&series),
    ///     Err(StlError::DuplicatePeriod { period: 4 })
    /// );
    /// ```
    pub fn fit(&self, series: &[f64]) -> Result<MstlDecomposition, StlError> {
        if self.periods.is_empty() {
            return Err(StlError::NoPeriods);
        }
        let windows: Vec<usize> = match &self.seasonal_windows {
            Some(w) if w.len() != self.periods.len() => {
                return Err(StlError::WindowCountMismatch {
                    periods: self.periods.len(),
                    windows: w.len(),
                });
            }
            Some(w) => w.clone(),
            None => {
                // 7 + 4k by rank of the period, shortest first.
                let mut rank: Vec<usize> = (0..self.periods.len()).collect();
                rank.sort_by_key(|&i| self.periods[i]);
                let mut w = vec![0; self.periods.len()];
                for (k, &i) in rank.iter().enumerate() {
                    w[i] = 11 + 4 * k;
                }
                w
            }
        };

        let mut pairs: Vec<(usize, usize)> = self.periods.iter().copied().zip(windows).collect();
        pairs.sort_by_key(|&(p, _)| p);
        if let Some(pair) = pairs.windows(2).find(|w| w[0].0 == w[1].0) {
            return Err(StlError::DuplicatePeriod { period: pair[0].0 });
        }

        let stls: Vec<Stl> = pairs
            .iter()
            .map(|&(p, w)| Stl::new(p, w).robust(self.robust))
            .collect();

        let n = series.len();
        let mut seasonal = vec![vec![0.0; n]; stls.len()];
        let mut deseasonal = series.to_vec();
        let mut trend = vec![0.0; n];
        for _ in 0..self.iterations.max(1) {
            for (stl, component) in stls.iter().zip(seasonal.iter_mut()) {
                for (d, s) in deseasonal.iter_mut().zip(component.iter()) {
                    *d += s;
                }
                let fit = stl.fit(&deseasonal)?;
                *component = fit.seasonal;
                for (d, s) in deseasonal.iter_mut().zip(component.iter()) {
                    *d -= s;
                }
                trend = fit.trend;
            }
        }

        let remainder = deseasonal.iter().zip(&trend).map(|(d, t)| d - t).collect();
        Ok(MstlDecomposition {
            periods: pairs.iter().map(|&(p, _)| p).collect(),
            trend,
            seasonal,
            remainder,
        })
    }
}
