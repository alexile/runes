//! STL / MSTL behaviour: known values from R, synthetic recovery, robustness
//! and input validation.

// Reference values are pasted verbatim from R's printout.
#![allow(
    clippy::unreadable_literal,
    clippy::excessive_precision,
    clippy::needless_range_loop,
    clippy::cast_precision_loss
)]

use proptest::prelude::*;
use rune_season_decomp::{Degree, Mstl, Stl, StlError, strength};
use std::f64::consts::TAU;

// `nottem` (monthly average air temperature at Nottingham, deg F), 1920-1923,
// from R's datasets package.
const NOTTEM: [f64; 48] = [
    40.6, 40.8, 44.4, 46.7, 54.1, 58.5, 57.7, 56.4, 54.3, 50.5, 42.9, 39.8, //
    44.2, 39.8, 45.1, 47.0, 54.1, 58.7, 66.3, 59.9, 57.0, 54.2, 39.7, 42.8, //
    37.5, 38.7, 39.5, 42.1, 55.7, 57.8, 56.8, 54.3, 54.3, 47.1, 41.8, 41.7, //
    41.8, 40.1, 42.9, 45.8, 49.2, 52.7, 64.2, 59.6, 54.4, 49.2, 36.3, 37.6,
];

// Reference values from R 4.4.1:
//   x <- window(nottem, end = c(1923, 12))
//   f <- stl(x, s.window = 7)
//   f$time.series[, "seasonal"]; f$time.series[, "trend"]
const R_SEASONAL: [f64; 48] = [
    -7.930063, -9.187160, -5.739280, -3.469206, 5.042155, 8.914055, 11.767357, 8.265307, 6.217766,
    1.888196, -7.814774, -7.750578, -8.020190, -9.200081, -5.930291, -3.591671, 5.056944, 8.787436,
    11.999891, 8.400771, 6.335905, 1.766397, -7.917753, -7.644976, -7.872760, -9.164867, -6.161149,
    -3.667721, 4.532240, 8.046636, 13.127666, 9.111095, 6.629369, 1.691683, -8.566400, -7.604733,
    -7.919558, -9.085615, -6.249661, -3.666894, 4.400077, 7.808090, 13.363082, 9.333233, 6.714381,
    1.564739, -8.696134, -7.661235,
];
const R_TREND: [f64; 48] = [
    48.852437, 48.894718, 48.936999, 48.979280, 49.045886, 49.112491, 49.179097, 49.250454,
    49.321810, 49.393167, 49.504662, 49.616158, 49.727653, 49.913124, 50.098595, 50.284066,
    50.242299, 50.200533, 50.158767, 49.960272, 49.761778, 49.563284, 49.279293, 48.995303,
    48.711312, 48.417851, 48.124389, 47.830927, 47.767605, 47.704283, 47.640961, 47.705029,
    47.769097, 47.833166, 47.895644, 47.958122, 48.020601, 47.976213, 47.931826, 47.887438,
    47.790322, 47.693206, 47.596091, 47.478254, 47.360418, 47.242581, 47.104591, 46.966601,
];

// Robust fit on the first 47 months (R 4.4.1):
//   x47 <- ts(as.numeric(x)[1:47], frequency = 12)
//   fr <- stl(x47, s.window = 7, robust = TRUE)
//   fr$time.series[, "seasonal"]; fr$time.series[, "trend"]; fr$weights
// An odd length is used on purpose. For even lengths R's partial sort is asked
// for the two middle order statistics in descending order and doesn't always
// return them, so its robustness scale can drift from the true median; this
// crate always uses the true median of the absolute residuals.
const R_ROBUST_SEASONAL: [f64; 47] = [
    -7.600533, -9.015308, -5.356350, -3.140989, 5.129295, 9.245578, 8.763468, 8.542753, 6.501773,
    1.815403, -7.543100, -7.190896, -7.609180, -9.021789, -5.521890, -3.256097, 5.134515, 9.156435,
    8.818625, 8.666829, 6.598877, 1.705248, -7.663113, -7.005276, -7.296293, -8.939492, -5.690276,
    -3.279087, 4.726626, 8.628751, 8.950789, 9.420555, 6.911179, 1.717274, -8.296075, -6.793691,
    -7.278282, -8.849925, -5.768567, -3.278976, 4.596717, 8.424196, 9.016834, 9.629773, 6.969856,
    1.623744, -8.450697,
];
const R_ROBUST_TREND: [f64; 47] = [
    48.969835, 48.991638, 49.013441, 49.035244, 49.070773, 49.106301, 49.141829, 49.180445,
    49.219062, 49.257679, 49.310805, 49.363932, 49.417059, 49.509145, 49.601231, 49.693318,
    49.623030, 49.552743, 49.482455, 49.304505, 49.126554, 48.948604, 48.772582, 48.596561,
    48.420539, 48.228850, 48.037160, 47.845470, 47.793204, 47.740938, 47.688673, 47.746427,
    47.804180, 47.861934, 47.851960, 47.841986, 47.832012, 47.758158, 47.684304, 47.610451,
    47.520334, 47.430217, 47.340100, 47.235507, 47.130915, 47.026322, 46.914061,
];
const R_ROBUST_WEIGHTS: [f64; 47] = [
    0.978971, 0.975803, 0.979800, 0.976418, 0.999624, 0.999300, 0.998192, 0.937645, 0.928589,
    0.989126, 0.953641, 0.806068, 0.802110, 0.982619, 0.962132, 0.988414, 0.984235, 0.999984,
    0.000000, 0.868761, 0.940716, 0.588278, 0.930514, 0.947149, 0.584831, 0.987793, 0.731791,
    0.794938, 0.665547, 0.928309, 0.999510, 0.727035, 0.994621, 0.798671, 0.823349, 0.985670,
    0.945216, 0.951659, 0.966442, 0.925930, 0.706002, 0.657339, 0.000000, 0.754953, 0.997466,
    0.989393, 0.829586,
];

// R 4.4.1: fp <- stl(x, "periodic"); first cycle of the seasonal, and the trend.
const R_PERIODIC_SEASONAL: [f64; 12] = [
    -7.840806, -9.019328, -5.897849, -3.427188, 4.493477, 8.180803, 12.543128, 8.898142, 6.403158,
    1.749854, -8.228450, -7.854940,
];
const R_PERIODIC_TREND: [f64; 48] = [
    49.187211, 49.145876, 49.104542, 49.091326, 49.078110, 49.091191, 49.104272, 49.109595,
    49.114918, 49.155979, 49.197041, 49.437898, 49.678756, 49.986456, 50.294156, 50.457014,
    50.619872, 50.561163, 50.502454, 50.242318, 49.982181, 49.665764, 49.349346, 48.993807,
    48.638268, 48.236852, 47.835437, 47.593100, 47.350764, 47.398075, 47.445386, 47.631973,
    47.818561, 47.890175, 47.961789, 48.001449, 48.041108, 48.186982, 48.332857, 48.204557,
    48.076258, 47.866158, 47.656058, 47.443636, 47.231214, 47.014635, 46.798055, 46.567494,
];

fn assert_close(label: &str, got: &[f64], want: &[f64], tol: f64) {
    assert_eq!(got.len(), want.len(), "{label}: length");
    for (i, (g, w)) in got.iter().zip(want).enumerate() {
        assert!((g - w).abs() < tol, "{label}[{i}]: got {g}, R gives {w}");
    }
}

fn assert_additive(series: &[f64], trend: &[f64], seasonal: &[f64], remainder: &[f64]) {
    for i in 0..series.len() {
        let sum = trend[i] + seasonal[i] + remainder[i];
        assert!((sum - series[i]).abs() < 1e-9, "index {i}");
    }
}

#[test]
fn matches_r_stl_default() {
    let fit = Stl::new(12, 7).fit(&NOTTEM).unwrap();
    assert_close("seasonal", &fit.seasonal, &R_SEASONAL, 1e-5);
    assert_close("trend", &fit.trend, &R_TREND, 1e-5);
    assert!(fit.weights.iter().all(|&w| (w - 1.0).abs() < 1e-15));
    assert_additive(&NOTTEM, &fit.trend, &fit.seasonal, &fit.remainder);
}

#[test]
fn matches_r_stl_robust() {
    let fit = Stl::new(12, 7).robust(true).fit(&NOTTEM[..47]).unwrap();
    assert_close("seasonal", &fit.seasonal, &R_ROBUST_SEASONAL, 1e-5);
    assert_close("trend", &fit.trend, &R_ROBUST_TREND, 1e-5);
    assert_close("weights", &fit.weights, &R_ROBUST_WEIGHTS, 1e-5);
}

#[test]
fn matches_r_stl_periodic() {
    let fit = Stl::periodic(12).fit(&NOTTEM).unwrap();
    for cycle in 0..4 {
        assert_close(
            "seasonal",
            &fit.seasonal[cycle * 12..(cycle + 1) * 12],
            &R_PERIODIC_SEASONAL,
            1e-5,
        );
    }
    assert_close("trend", &fit.trend, &R_PERIODIC_TREND, 1e-5);
}

/// Small deterministic noise in roughly [-amp, amp].
fn noise(len: usize, amp: f64, mut state: u64) -> Vec<f64> {
    (0..len)
        .map(|_| {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            let u = (state >> 11) as f64 / (1u64 << 53) as f64;
            amp * 2.0f64.mul_add(u, -1.0)
        })
        .collect()
}

fn synthetic(len: usize, period: usize) -> (Vec<f64>, Vec<f64>, Vec<f64>) {
    let trend: Vec<f64> = (0..len)
        .map(|i| {
            let t = i as f64;
            2.0f64.mul_add((t / 80.0).sin(), 0.05f64.mul_add(t, 10.0))
        })
        .collect();
    let seasonal: Vec<f64> = (0..len)
        .map(|i| 3.0 * (TAU * i as f64 / period as f64).sin())
        .collect();
    let eps = noise(len, 0.3, 42);
    let series = (0..len).map(|i| trend[i] + seasonal[i] + eps[i]).collect();
    (series, trend, seasonal)
}

#[test]
fn recovers_synthetic_trend_and_seasonal() {
    let (series, trend, seasonal) = synthetic(240, 12);
    for stl in [
        Stl::new(12, 7),
        Stl::new(12, 13).seasonal_degree(Degree::Linear),
        Stl::new(12, 7).jumps(1, 1, 1),
        Stl::periodic(12),
    ] {
        let fit = stl.fit(&series).unwrap();
        assert_additive(&series, &fit.trend, &fit.seasonal, &fit.remainder);
        // Skip one period at each end, where loess has only one-sided support.
        for i in 12..228 {
            assert!((fit.trend[i] - trend[i]).abs() < 0.35, "{stl:?} trend[{i}]");
            assert!(
                (fit.seasonal[i] - seasonal[i]).abs() < 0.35,
                "{stl:?} seasonal[{i}]"
            );
        }
        assert!(fit.seasonal_strength() > 0.95);
        assert!(fit.trend_strength() > 0.95);
    }
}

#[test]
fn robust_fit_ignores_outliers() {
    let (mut series, trend, seasonal) = synthetic(240, 12);
    let outliers = [17, 50, 51, 99, 140, 181, 203];
    for &i in &outliers {
        series[i] += 40.0;
    }

    let robust = Stl::new(12, 7).robust(true).fit(&series).unwrap();
    let plain = Stl::new(12, 7).fit(&series).unwrap();

    let max_err = |fit: &rune_season_decomp::StlDecomposition| {
        (12..228)
            .map(|i| {
                (fit.seasonal[i] - seasonal[i])
                    .abs()
                    .max((fit.trend[i] - trend[i]).abs())
            })
            .fold(0.0, f64::max)
    };
    assert!(max_err(&robust) < 0.5, "robust error {}", max_err(&robust));
    assert!(max_err(&plain) > 2.0, "plain error {}", max_err(&plain));

    for &i in &outliers {
        assert!(robust.weights[i] < 0.01, "weight at outlier {i}");
        assert!((robust.remainder[i] - 40.0).abs() < 1.0);
    }
    let typical = robust.weights.iter().filter(|&&w| w > 0.5).count();
    assert!(typical > 220);
}

#[test]
fn strength_of_pure_noise_is_low() {
    let series = noise(120, 1.0, 7);
    let fit = Stl::new(12, 7).fit(&series).unwrap();
    assert!(fit.seasonal_strength() < 0.5);
    assert_eq!(strength(&[1.0, 1.0], &[0.0, 0.0]), 0.0);
}

#[test]
fn mstl_separates_two_cycles() {
    let len = 24 * 7 * 6;
    let eps = noise(len, 0.2, 3);
    let daily: Vec<f64> = (0..len)
        .map(|i| 2.0 * (TAU * i as f64 / 24.0).sin())
        .collect();
    let weekly: Vec<f64> = (0..len)
        .map(|i| 4.0 * (TAU * i as f64 / 168.0).cos())
        .collect();
    let series: Vec<f64> = (0..len)
        .map(|i| 50.0 + daily[i] + weekly[i] + eps[i])
        .collect();

    let fit = Mstl::new(&[168, 24]).fit(&series).unwrap();
    assert_eq!(fit.periods, vec![24, 168]);
    for i in 168..len - 168 {
        assert!((fit.seasonal[0][i] - daily[i]).abs() < 0.4, "daily[{i}]");
        assert!((fit.seasonal[1][i] - weekly[i]).abs() < 0.6, "weekly[{i}]");
        assert!((fit.trend[i] - 50.0).abs() < 0.5, "trend[{i}]");
    }
    for i in 0..len {
        let sum = fit.trend[i] + fit.seasonal[0][i] + fit.seasonal[1][i] + fit.remainder[i];
        assert!((sum - series[i]).abs() < 1e-9);
    }
    assert!(fit.seasonal_strengths().iter().all(|&s| s > 0.9));
}

#[test]
fn mstl_with_one_period_is_plain_stl_iterated() {
    let (series, _, _) = synthetic(120, 12);
    let fit = Mstl::new(&[12])
        .iterations(1)
        .seasonal_windows(&[7])
        .fit(&series)
        .unwrap();
    let stl = Stl::new(12, 7).fit(&series).unwrap();
    assert_eq!(fit.seasonal[0], stl.seasonal);
    assert_eq!(fit.trend, stl.trend);
}

#[test]
fn rejects_bad_input() {
    let series: Vec<f64> = (0..48).map(f64::from).collect();
    let mut with_nan = series.clone();
    with_nan[5] = f64::NAN;
    assert_eq!(
        Stl::new(12, 7).fit(&with_nan),
        Err(StlError::NonFinite { index: 5 })
    );
    let mut with_inf = series.clone();
    with_inf[0] = f64::INFINITY;
    assert_eq!(
        Stl::new(12, 7).fit(&with_inf),
        Err(StlError::NonFinite { index: 0 })
    );
    assert_eq!(
        Stl::new(1, 7).fit(&series),
        Err(StlError::PeriodTooShort { period: 1 })
    );
    assert_eq!(
        Stl::new(25, 7).fit(&series),
        Err(StlError::SeriesTooShort {
            len: 48,
            period: 25
        })
    );
    assert!(Stl::new(24, 7).fit(&series).is_ok());
    assert_eq!(
        Stl::new(12, 8).fit(&series),
        Err(StlError::EvenWindow {
            name: "seasonal",
            value: 8
        })
    );
    assert_eq!(
        Stl::new(12, 5).fit(&series),
        Err(StlError::WindowTooSmall {
            name: "seasonal",
            value: 5,
            min: 7
        })
    );
    assert_eq!(
        Stl::new(12, 7).trend_window(20).fit(&series),
        Err(StlError::EvenWindow {
            name: "trend",
            value: 20
        })
    );
    assert_eq!(
        Stl::new(12, 7).low_pass_window(1).fit(&series),
        Err(StlError::WindowTooSmall {
            name: "low-pass",
            value: 1,
            min: 3
        })
    );
    assert_eq!(
        Stl::new(12, 7).jumps(1, 0, 1).fit(&series),
        Err(StlError::ZeroJump { name: "trend" })
    );
    assert_eq!(
        Stl::new(12, 7).inner_iterations(0).fit(&series),
        Err(StlError::ZeroInnerIterations)
    );
    assert_eq!(
        Mstl::new(&[4, 12]).seasonal_windows(&[7]).fit(&series),
        Err(StlError::WindowCountMismatch {
            periods: 2,
            windows: 1
        })
    );
    assert_eq!(
        Mstl::new(&[4, 30]).fit(&series),
        Err(StlError::SeriesTooShort {
            len: 48,
            period: 30
        })
    );
    assert_eq!(
        StlError::NoPeriods.to_string(),
        "at least one seasonal period is required"
    );
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn components_always_add_up(
        values in prop::collection::vec(-1e3f64..1e3, 14..80),
        period in 2usize..7,
        robust in any::<bool>(),
        jump in 1usize..4,
    ) {
        let fit = Stl::new(period, 9).robust(robust).jumps(jump, jump, jump).fit(&values).unwrap();
        for i in 0..values.len() {
            let sum = fit.trend[i] + fit.seasonal[i] + fit.remainder[i];
            prop_assert!((sum - values[i]).abs() < 1e-6);
            prop_assert!(fit.trend[i].is_finite() && fit.seasonal[i].is_finite());
            prop_assert!((0.0..=1.0).contains(&fit.weights[i]));
        }
        let s = fit.seasonal_strength();
        prop_assert!((0.0..=1.0).contains(&s));
    }
}
