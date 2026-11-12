//! Known-value tests against the worked examples in Hyndman &
//! Athanasopoulos, *Forecasting: Principles and Practice*, 2nd edition
//! (OTexts, 2018), chapter 7, <https://otexts.com/fpp2/expsmooth.html>.
//!
//! The book's numbers come from R's `forecast` package, which minimises the
//! same squared-error objective with its own Nelder-Mead run. Where that run
//! stops slightly short of the optimum we accept a fit that is at least as
//! good (lower SSE / AIC) and close in parameters. Data are the `fpp2`
//! package series `oil`, `ausair`, `austourists` and `livestock`.

#![allow(
    clippy::unreadable_literal,
    clippy::excessive_precision,
    clippy::doc_markdown,
    reason = "data copied verbatim; docs quote the textbook output"
)]

use rune_forecast_ses::{Auto, Model, Seasonal, Trend};

/// `window(oil, start = 1996)`: Saudi Arabian oil production, 1996-2013.
const OIL: [f64; 18] = [
    445.364098092,
    453.195010427,
    454.409641012,
    422.378905779,
    456.037121728,
    440.386604674,
    425.194372519,
    486.20517351,
    500.429086073,
    521.27590917,
    508.947617045,
    488.888857729,
    509.870574978,
    456.722912348,
    473.816602915,
    525.950870565,
    549.833807597,
    542.340469826,
];
/// `window(ausair, start = 1990)`: Australian air passengers, 1990-2016.
const AIR: [f64; 27] = [
    17.5534,
    21.8601,
    23.8866,
    26.9293,
    26.8885,
    28.8314,
    30.0751,
    30.9535,
    30.1857,
    31.5797,
    32.577569,
    33.477398,
    39.021581,
    41.386432,
    41.596552,
    44.657324,
    46.951775,
    48.728837,
    51.488427,
    50.026967,
    60.640913,
    63.3603103378,
    66.355274,
    68.197955,
    68.1232376693,
    69.7793454797,
    72.597700806,
];
/// `window(austourists, start = 2005)`: quarterly visitor nights, 2005Q1-2015Q4.
const AUST: [f64; 44] = [
    42.2056638559382,
    24.6491713296294,
    32.6673351386246,
    37.2573540134764,
    45.2424602720635,
    29.3504812742718,
    36.3442072775119,
    41.7820813647366,
    49.2765984345619,
    31.2754013898459,
    37.8506254947152,
    38.83704413019,
    51.236900336137,
    31.8385516171558,
    41.3234212576972,
    42.7990033724349,
    55.708358364385,
    33.4071449171312,
    42.3166379718116,
    45.1571225674731,
    59.5760799633937,
    34.8373301595328,
    44.8416807241332,
    46.971249602779,
    60.0190309438716,
    38.3711785132276,
    46.9758641283558,
    50.7337964560878,
    61.6468731860574,
    39.2995693656296,
    52.6712090814052,
    54.3323168946667,
    66.834358381339,
    40.8711884667851,
    51.8285357927739,
    57.4919099342262,
    65.2514698518726,
    43.0612082202828,
    54.7607571288007,
    59.8344749355003,
    73.2570274672009,
    47.6966237298,
    61.0977680206996,
    66.0557612187001,
];
/// `livestock`: sheep in Asia, 1961-2007.
const LIVESTOCK: [f64; 47] = [
    232.288994, 229.536258, 233.145936, 243.763684, 252.602916, 259.677371, 260.766892, 269.784084,
    266.414974, 263.917747, 268.307222, 260.662556, 266.639419, 277.515778, 283.834045, 290.309028,
    292.474198, 300.830694, 309.286657, 318.331081, 329.37239, 338.883998, 339.244126, 328.600632,
    314.255385, 314.459695, 321.413779, 329.789292, 346.385165, 352.297882, 348.370515, 417.562922,
    417.12357, 417.749459, 412.233904, 411.946817, 394.697075, 401.49927, 408.270468, 414.2428,
    407.997978, 403.460832, 413.824928, 428.104959, 445.338742, 452.994173, 455.74017,
];

fn close(actual: f64, expected: f64, tol: f64) -> bool {
    (actual - expected).abs() <= tol
}

/// fpp2 section 7.1, `ses(oildata, h = 5)`: alpha = 0.8339, l = 446.5868,
/// sigma = 29.8282, AIC 178.1430, AICc 179.8573, BIC 180.8141; point
/// forecast 542.68 with 80% interval [504.4, 580.9] for 2014.
#[test]
fn fpp2_oil_ses() {
    let fit = Model::ses().fit(&OIL).unwrap();
    assert!(close(fit.alpha(), 0.8339, 1e-3), "alpha {}", fit.alpha());
    assert!(
        close(fit.initial_level(), 446.5868, 0.05),
        "l0 {}",
        fit.initial_level()
    );
    assert!(
        close(fit.sigma2().sqrt(), 29.8282, 1e-3),
        "sigma {}",
        fit.sigma2().sqrt()
    );
    assert!(close(fit.aic(), 178.1430, 1e-3), "aic {}", fit.aic());
    assert!(close(fit.aicc(), 179.8573, 1e-3), "aicc {}", fit.aicc());
    assert!(close(fit.bic(), 180.8141, 1e-3), "bic {}", fit.bic());
    let fc = fit.forecast(5);
    assert!(fc.iter().all(|v| close(*v, 542.68, 0.01)), "{fc:?}");
    let iv = fit.forecast_intervals(1, 0.8).unwrap()[0];
    assert!(
        close(iv.lower, 504.4, 0.1) && close(iv.upper, 580.9, 0.1),
        "{iv:?}"
    );
}

/// fpp2 section 7.2, `holt(air, h = 5)`: alpha = 0.8302, beta = 0.0001,
/// l = 15.5715, b = 2.1017, sigma = 2.3645.
#[test]
fn fpp2_ausair_holt() {
    let fit = Model::holt().fit(&AIR).unwrap();
    assert!(close(fit.alpha(), 0.8302, 0.02), "alpha {}", fit.alpha());
    let beta_ets = fit.alpha() * fit.beta().unwrap();
    assert!(beta_ets < 1e-3, "beta {beta_ets}");
    assert!(
        close(fit.initial_level(), 15.5715, 0.5),
        "l0 {}",
        fit.initial_level()
    );
    assert!(
        close(fit.initial_trend().unwrap(), 2.1017, 0.01),
        "b0 {:?}",
        fit.initial_trend()
    );
    let sigma = fit.sigma2().sqrt();
    assert!(
        sigma <= 2.3645 + 1e-4 && close(sigma, 2.3645, 0.01),
        "sigma {sigma}"
    );
}

/// fpp2 section 7.2, `holt(livestock, damped = TRUE)`: alpha = 0.9999,
/// beta = 3e-04, phi = 0.9798, b = 6.9046; AIC 427.6, AICc 429.7, BIC 438.7.
#[test]
fn fpp2_livestock_damped() {
    let fit = Model::damped_holt().fit(&LIVESTOCK).unwrap();
    assert!(fit.alpha() > 0.999, "alpha {}", fit.alpha());
    assert!(
        close(fit.phi().unwrap(), 0.9798, 0.002),
        "phi {:?}",
        fit.phi()
    );
    assert!(
        close(fit.initial_trend().unwrap(), 6.9046, 0.01),
        "b0 {:?}",
        fit.initial_trend()
    );
    assert!(close(fit.aic(), 427.6, 0.05), "aic {}", fit.aic());
    assert!(close(fit.aicc(), 429.7, 0.05), "aicc {}", fit.aicc());
    assert!(close(fit.bic(), 438.7, 0.05), "bic {}", fit.bic());
}

/// fpp2 section 7.3, `hw(aust, seasonal = "additive")`: alpha = 0.3063,
/// beta = 0.0001, gamma = 0.4263, l = 32.2597, b = 0.7014,
/// s = (9.6962, -9.3132, -1.6935, 1.3106) for Q1..Q4, RMSE 1.7630,
/// AIC 234.4171. Our optimum has a slightly lower SSE, so alpha and gamma
/// land a little away from the printed values.
#[test]
fn fpp2_austourists_additive() {
    let fit = Model::holt_winters(Seasonal::Additive, 4)
        .fit(&AUST)
        .unwrap();
    let rmse = (fit.sse() / 44.0).sqrt();
    assert!(rmse <= 1.7630 && close(rmse, 1.7630, 0.02), "rmse {rmse}");
    assert!(
        fit.aic() <= 234.4171 && close(fit.aic(), 234.4171, 0.5),
        "aic {}",
        fit.aic()
    );
    assert!(close(fit.alpha(), 0.3063, 0.06), "alpha {}", fit.alpha());
    assert!(
        close(fit.gamma().unwrap(), 0.4263, 0.06),
        "gamma {:?}",
        fit.gamma()
    );
    assert!(
        close(fit.initial_level(), 32.2597, 0.1),
        "l0 {}",
        fit.initial_level()
    );
    assert!(
        close(fit.initial_trend().unwrap(), 0.7014, 0.01),
        "b0 {:?}",
        fit.initial_trend()
    );
    for (got, want) in fit
        .initial_seasonal()
        .iter()
        .zip([9.6962, -9.3132, -1.6935, 1.3106])
    {
        assert!(close(*got, want, 0.5), "{:?}", fit.initial_seasonal());
    }
}

/// fpp2 section 7.3, `hw(aust, seasonal = "multiplicative")`: b = 0.6974,
/// s = (1.2442, 0.7704, 0.9618, 1.0237) for Q1..Q4, RMSE 1.5764. R fits
/// this one with multiplicative errors; with additive errors we minimise
/// the SSE directly, so our RMSE is lower but the states agree closely.
#[test]
fn fpp2_austourists_multiplicative() {
    let fit = Model::holt_winters(Seasonal::Multiplicative, 4)
        .fit(&AUST)
        .unwrap();
    let rmse = (fit.sse() / 44.0).sqrt();
    assert!(rmse <= 1.5764 && close(rmse, 1.5764, 0.05), "rmse {rmse}");
    assert!(
        close(fit.initial_trend().unwrap(), 0.6974, 0.01),
        "b0 {:?}",
        fit.initial_trend()
    );
    for (got, want) in fit
        .initial_seasonal()
        .iter()
        .zip([1.2442, 0.7704, 0.9618, 1.0237])
    {
        assert!(close(*got, want, 0.01), "{:?}", fit.initial_seasonal());
    }
}

/// fpp2 section 7.3 notes the multiplicative model fits the tourism data
/// better than the additive one; automatic selection agrees.
#[test]
fn fpp2_austourists_auto_prefers_multiplicative() {
    let fit = Auto::new().period(4).fit(&AUST).unwrap();
    assert_eq!(fit.model().seasonal(), Seasonal::Multiplicative);
    assert_eq!(fit.model().trend(), Trend::Additive);
}
