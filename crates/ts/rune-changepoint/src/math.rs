//! Natural logarithm that also works without `std`.

/// Natural logarithm: `f64::ln` with `std`, a portable series otherwise.
#[cfg(any(feature = "std", test))]
pub fn ln(x: f64) -> f64 {
    x.ln()
}

/// Natural logarithm: `f64::ln` with `std`, a portable series otherwise.
#[cfg(not(any(feature = "std", test)))]
pub fn ln(x: f64) -> f64 {
    portable_ln(x)
}

/// `ln(x)` from the bit pattern: split `x = m * 2^e` with `m` in
/// `[sqrt(1/2), sqrt(2)]`, then `ln(m) = 2 atanh((m - 1) / (m + 1))`, whose
/// series converges fast because `|s| <= 0.172`. Accurate to a few ulps.
#[cfg(any(not(feature = "std"), test))]
#[allow(
    clippy::cast_possible_wrap,
    clippy::cast_precision_loss,
    clippy::suboptimal_flops,
    clippy::many_single_char_names,
    reason = "exponent fits easily; mul_add is not available without std"
)]
pub fn portable_ln(x: f64) -> f64 {
    const TWO_POW_54: f64 = 18_014_398_509_481_984.0;
    if x.is_nan() || x < 0.0 {
        return f64::NAN;
    }
    if x == 0.0 {
        return f64::NEG_INFINITY;
    }
    if x.is_infinite() {
        return x;
    }
    let mut v = x;
    let mut exp: i64 = 0;
    if v.to_bits() >> 52 == 0 {
        // Subnormal: scale into the normal range first.
        v *= TWO_POW_54;
        exp -= 54;
    }
    let bits = v.to_bits();
    exp += ((bits >> 52) & 0x7ff) as i64 - 1023;
    let mut m = f64::from_bits((bits & 0x000f_ffff_ffff_ffff) | 0x3ff0_0000_0000_0000);
    if m > core::f64::consts::SQRT_2 {
        m *= 0.5;
        exp += 1;
    }
    let s = (m - 1.0) / (m + 1.0);
    let s2 = s * s;
    let mut term = s;
    let mut sum = 0.0;
    let mut k = 1.0;
    for _ in 0..16 {
        sum += term / k;
        term *= s2;
        k += 2.0;
    }
    exp as f64 * core::f64::consts::LN_2 + 2.0 * sum
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[allow(clippy::while_float)]
    fn portable_ln_matches_std() {
        let mut x = 1e-310_f64;
        while x < 1e300 {
            let want = x.ln();
            let got = portable_ln(x);
            assert!(
                (got - want).abs() <= 4.0 * f64::EPSILON * want.abs().max(1.0),
                "{x}: {got} vs {want}"
            );
            x *= 1.37;
        }
        for x in [0.5, 1.0, 2.0, core::f64::consts::E, 0.999_999, 1.000_001] {
            assert!((portable_ln(x) - x.ln()).abs() < 1e-15, "{x}");
        }
        assert!(portable_ln(-1.0).is_nan());
        assert_eq!(portable_ln(0.0), f64::NEG_INFINITY);
        assert_eq!(portable_ln(f64::INFINITY), f64::INFINITY);
    }
}
