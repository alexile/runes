//! Distribution functions used by the tests: the standard normal, the
//! Kolmogorov limit distribution, and the regularized incomplete gamma
//! functions with the chi-squared distribution built on them.
//!
//! These are accurate to a few ulps over the whole range (relative error
//! below `1e-14` against arbitrary-precision references), so tail
//! p-values such as `1e-30` keep their relative precision.

use std::f64::consts::{FRAC_2_SQRT_PI, PI, SQRT_2};

/// `1 / √π`.
const FRAC_1_SQRT_PI: f64 = 0.5 * FRAC_2_SQRT_PI;
/// `1 / √(2π)`.
const FRAC_1_SQRT_2PI: f64 = 0.398_942_280_401_432_7;

/// `erf(x)` by its everywhere-positive series
/// `2/√π · e^{−x²} · Σ (2x²)ⁿ x / (2n+1)!!`, used for `|x| < 1.5`.
fn erf_series(x: f64) -> f64 {
    let x2 = x * x;
    let mut term = x;
    let mut sum = x;
    let mut n = 0.0;
    loop {
        n += 1.0;
        term *= 2.0 * x2 / 2.0f64.mul_add(n, 1.0);
        sum += term;
        if term.abs() <= sum.abs() * 1e-17 || n > 200.0 {
            break;
        }
    }
    FRAC_2_SQRT_PI * (-x2).exp() * sum
}

/// `erfc(x)` for `x ≥ 1.5` by Laplace's continued fraction, evaluated with
/// the modified Lentz algorithm.
#[allow(
    clippy::many_single_char_names,
    reason = "names follow the textbook formulas"
)]
fn erfc_continued_fraction(x: f64) -> f64 {
    const TINY: f64 = 1e-300;
    let mut f = x;
    let mut c = f;
    let mut d = 0.0;
    let mut k = 0.0f64;
    loop {
        k += 1.0;
        let a = k / 2.0;
        d = a.mul_add(d, x);
        if d == 0.0 {
            d = TINY;
        }
        c = x + a / c;
        if c == 0.0 {
            c = TINY;
        }
        d = 1.0 / d;
        let delta = c * d;
        f *= delta;
        if (delta - 1.0).abs() < 1e-16 || k > 1000.0 {
            break;
        }
    }
    (-x * x).exp() * FRAC_1_SQRT_PI / f
}

/// Complementary error function `erfc(x) = 1 − erf(x)`.
///
/// ```
/// use rune_stats::dist::erfc;
/// assert_eq!(erfc(0.0), 1.0);
/// assert!((erfc(1.0) - 0.157_299_207_050_285_16).abs() < 1e-15);
/// ```
#[must_use]
pub fn erfc(x: f64) -> f64 {
    if x.is_nan() {
        return f64::NAN;
    }
    if x < 0.0 {
        return 2.0 - erfc(-x);
    }
    if x < 1.5 {
        1.0 - erf_series(x)
    } else {
        erfc_continued_fraction(x)
    }
}

/// Error function `erf(x)`.
#[must_use]
pub fn erf(x: f64) -> f64 {
    if x.abs() < 1.5 {
        erf_series(x)
    } else {
        1.0 - erfc(x)
    }
}

/// Standard normal density `φ(z)`.
#[must_use]
pub fn normal_pdf(z: f64) -> f64 {
    FRAC_1_SQRT_2PI * (-0.5 * z * z).exp()
}

/// Standard normal distribution function `Φ(z) = P(Z ≤ z)`.
#[must_use]
pub fn normal_cdf(z: f64) -> f64 {
    0.5 * erfc(-z / SQRT_2)
}

/// Standard normal survival function `P(Z > z) = 1 − Φ(z)`, accurate in
/// the upper tail.
///
/// ```
/// let p = rune_stats::dist::normal_sf(1.959_963_984_540_054);
/// assert!((p - 0.025).abs() < 1e-15);
/// ```
#[must_use]
pub fn normal_sf(z: f64) -> f64 {
    0.5 * erfc(z / SQRT_2)
}

/// Standard normal quantile `Φ⁻¹(p)`: the `z` with `Φ(z) = p`.
///
/// Returns `−∞` for `p = 0`, `+∞` for `p = 1` and `NaN` outside `[0, 1]`.
/// Starts from the Abramowitz & Stegun 26.2.23 approximation and polishes
/// it with Halley steps on the survival function, which gives full double
/// precision in both tails.
///
/// ```
/// let z = rune_stats::dist::normal_quantile(0.975);
/// assert!((z - 1.959_963_984_540_054).abs() < 1e-14);
/// ```
#[must_use]
#[allow(
    clippy::many_single_char_names,
    reason = "names follow the textbook formulas"
)]
#[expect(
    clippy::float_cmp,
    reason = "exact endpoints and midpoint of the domain"
)]
pub fn normal_quantile(p: f64) -> f64 {
    if !(0.0..=1.0).contains(&p) {
        return f64::NAN;
    }
    if p == 0.0 {
        return f64::NEG_INFINITY;
    }
    if p == 1.0 {
        return f64::INFINITY;
    }
    // Solve sf(z) = q for z ≥ 0 with q the smaller tail, then reflect.
    let (q, sign) = if p > 0.5 { (1.0 - p, 1.0) } else { (p, -1.0) };
    if q == 0.5 {
        return 0.0;
    }
    let t = (-2.0 * q.ln()).sqrt();
    let numerator = 0.010_328f64.mul_add(t, 0.802_853).mul_add(t, 2.515_517);
    let denominator = 0.001_308f64
        .mul_add(t, 0.189_269)
        .mul_add(t, 1.432_788)
        .mul_add(t, 1.0);
    let mut z = t - numerator / denominator;
    for _ in 0..50 {
        let density = normal_pdf(z);
        if density == 0.0 {
            break;
        }
        let u = (normal_sf(z) - q) / density;
        let step = u / (-0.5 * z).mul_add(u, 1.0);
        z += step;
        if step.abs() <= 1e-15 * z.abs().max(1.0) {
            break;
        }
    }
    sign * z
}

/// Survival function of the Kolmogorov limit distribution,
/// `Q(λ) = 2 Σ_{k≥1} (−1)^{k−1} e^{−2k²λ²}`.
///
/// This is the large-sample distribution of `√n · D` for the
/// Kolmogorov–Smirnov statistic (`scipy.special.kolmogorov`).
///
/// ```
/// let p = rune_stats::dist::kolmogorov_sf(1.0);
/// assert!((p - 0.269_999_671_677_354_6).abs() < 1e-15);
/// ```
#[must_use]
pub fn kolmogorov_sf(lambda: f64) -> f64 {
    if lambda.is_nan() {
        return f64::NAN;
    }
    if lambda <= 0.0 {
        return 1.0;
    }
    if lambda < 1.0 {
        // Dual (theta-function) form of the distribution function:
        // K(λ) = √(2π)/λ · Σ_{k≥1} e^{−(2k−1)²π²/(8λ²)}.
        let w = -PI * PI / (8.0 * lambda * lambda);
        let mut sum = 0.0;
        let mut k = 1.0f64;
        loop {
            let odd = 2.0f64.mul_add(k, -1.0);
            let term = (w * odd * odd).exp();
            sum += term;
            if term <= sum * 1e-17 || k > 100.0 {
                break;
            }
            k += 1.0;
        }
        let cdf = (2.0 * PI).sqrt() / lambda * sum;
        return (1.0 - cdf).clamp(0.0, 1.0);
    }
    let mut sum = 0.0f64;
    let mut sign = 1.0f64;
    let mut k = 1.0f64;
    loop {
        let term = (-2.0 * k * k * lambda * lambda).exp();
        sum = sign.mul_add(term, sum);
        if term <= sum.abs() * 1e-17 || k > 100.0 {
            break;
        }
        sign = -sign;
        k += 1.0;
    }
    (2.0 * sum).clamp(0.0, 1.0)
}

/// Lanczos coefficients for `g = 7`, `n = 9`.
const LANCZOS: [f64; 9] = [
    0.999_999_999_999_809_9,
    676.520_368_121_885_1,
    -1_259.139_216_722_402_8,
    771.323_428_777_653_1,
    -176.615_029_162_140_6,
    12.507_343_278_686_905,
    -0.138_571_095_265_720_12,
    9.984_369_578_019_572e-6,
    1.505_632_735_149_311_6e-7,
];

/// Natural logarithm of the gamma function, `ln Γ(x)`, for `x > 0`.
///
/// Uses the Lanczos approximation (`g = 7`), with the reflection formula
/// below `½`. The absolute error is below `1e-14` for moderate `x`, which
/// is what matters when the result is exponentiated. Returns `NaN` for
/// `x ≤ 0` or `NaN`, and `+∞` for `x = +∞`.
///
/// ```
/// use rune_stats::dist::ln_gamma;
/// assert!((ln_gamma(5.0) - 24.0f64.ln()).abs() < 1e-13);
/// assert!((ln_gamma(0.5) - std::f64::consts::PI.sqrt().ln()).abs() < 1e-14);
/// ```
#[must_use]
pub fn ln_gamma(x: f64) -> f64 {
    if x.is_nan() || x <= 0.0 {
        return f64::NAN;
    }
    if x.is_infinite() {
        return f64::INFINITY;
    }
    if x < 0.5 {
        // Γ(x) Γ(1 − x) = π / sin(πx); sin(πx) > 0 on (0, ½).
        return (PI / (PI * x).sin()).ln() - ln_gamma(1.0 - x);
    }
    let x = x - 1.0;
    let mut sum = LANCZOS[0];
    let mut denominator = x;
    for &coefficient in &LANCZOS[1..] {
        denominator += 1.0;
        sum += coefficient / denominator;
    }
    let t = x + 7.5;
    0.5f64.mul_add((2.0 * PI).ln(), (x + 0.5) * t.ln()) - t + sum.ln()
}

/// `ln(e^{−x} x^a / Γ(a))`, the common prefactor of the incomplete gamma
/// expansions.
fn gamma_prefactor_ln(a: f64, x: f64) -> f64 {
    a.mul_add(x.ln(), -x) - ln_gamma(a)
}

/// `P(a, x)` by its power series, for `x < a + 1`.
fn gamma_p_series(a: f64, x: f64) -> f64 {
    let mut denominator = a;
    let mut term = 1.0 / a;
    let mut sum = term;
    for _ in 0..10_000 {
        denominator += 1.0;
        term *= x / denominator;
        sum += term;
        if term.abs() <= sum.abs() * 1e-17 {
            break;
        }
    }
    (sum.ln() + gamma_prefactor_ln(a, x)).exp()
}

/// `Q(a, x)` by its Legendre continued fraction (modified Lentz), for
/// `x ≥ a + 1`.
#[allow(
    clippy::many_single_char_names,
    reason = "names follow the textbook formulas"
)]
fn gamma_q_continued_fraction(a: f64, x: f64) -> f64 {
    const TINY: f64 = 1e-300;
    let mut b = x + 1.0 - a;
    let mut c = 1.0 / TINY;
    let mut d = 1.0 / b;
    let mut h = d;
    let mut i = 0.0f64;
    for _ in 0..10_000 {
        i += 1.0;
        let an = -i * (i - a);
        b += 2.0;
        d = an.mul_add(d, b);
        if d.abs() < TINY {
            d = TINY;
        }
        c = b + an / c;
        if c.abs() < TINY {
            c = TINY;
        }
        d = 1.0 / d;
        let delta = d * c;
        h *= delta;
        if (delta - 1.0).abs() <= 1e-16 {
            break;
        }
    }
    (h.ln() + gamma_prefactor_ln(a, x)).exp()
}

/// Lower regularized incomplete gamma function
/// `P(a, x) = γ(a, x) / Γ(a)` (`scipy.special.gammainc`).
///
/// Returns `NaN` unless `a > 0` and `x ≥ 0`.
///
/// ```
/// use rune_stats::dist::gamma_p;
/// // P(1, x) = 1 − e^{−x}
/// assert!((gamma_p(1.0, 2.0) - (1.0 - (-2.0f64).exp())).abs() < 1e-15);
/// ```
#[must_use]
pub fn gamma_p(a: f64, x: f64) -> f64 {
    if !(a > 0.0 && x >= 0.0) || a.is_infinite() {
        return f64::NAN;
    }
    if x == 0.0 {
        return 0.0;
    }
    if x.is_infinite() {
        return 1.0;
    }
    if x < a + 1.0 {
        gamma_p_series(a, x).min(1.0)
    } else {
        (1.0 - gamma_q_continued_fraction(a, x)).max(0.0)
    }
}

/// Upper regularized incomplete gamma function
/// `Q(a, x) = Γ(a, x) / Γ(a) = 1 − P(a, x)` (`scipy.special.gammaincc`,
/// `igamc` in NIST SP 800-22), accurate in the upper tail.
///
/// Returns `NaN` unless `a > 0` and `x ≥ 0`.
///
/// ```
/// use rune_stats::dist::gamma_q;
/// // NIST SP 800-22 §2.2.4: igamc(3/2, 1/2) = 0.801252.
/// assert!((gamma_q(1.5, 0.5) - 0.801_252).abs() < 1e-6);
/// ```
#[must_use]
pub fn gamma_q(a: f64, x: f64) -> f64 {
    if !(a > 0.0 && x >= 0.0) || a.is_infinite() {
        return f64::NAN;
    }
    if x == 0.0 {
        return 1.0;
    }
    if x.is_infinite() {
        return 0.0;
    }
    if x < a + 1.0 {
        (1.0 - gamma_p_series(a, x)).max(0.0)
    } else {
        gamma_q_continued_fraction(a, x).min(1.0)
    }
}

/// Survival function of the chi-squared distribution with `df` degrees of
/// freedom, `P(X > x) = Q(df/2, x/2)` (`scipy.stats.chi2.sf`).
///
/// Returns `1` for `x ≤ 0`, and `NaN` for `df ≤ 0` or `NaN` input.
///
/// ```
/// let p = rune_stats::dist::chi_squared_sf(3.841_458_820_694_124, 1.0);
/// assert!((p - 0.05).abs() < 1e-14);
/// ```
#[must_use]
pub fn chi_squared_sf(x: f64, df: f64) -> f64 {
    if x.is_nan() || df.is_nan() || df <= 0.0 {
        return f64::NAN;
    }
    if x <= 0.0 {
        return 1.0;
    }
    gamma_q(0.5 * df, 0.5 * x)
}
