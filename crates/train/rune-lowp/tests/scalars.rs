//! Spec-pinned behaviour of the scalar types: constants, ties, saturation,
//! NaN / infinity propagation, subnormals and the E8M0 scale type.

#![allow(
    clippy::unwrap_used,
    clippy::float_cmp,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::cast_precision_loss,
    clippy::cast_lossless,
    clippy::many_single_char_names,
    clippy::similar_names,
    clippy::suboptimal_flops,
    clippy::manual_midpoint,
    clippy::missing_const_for_fn,
    clippy::needless_range_loop,
    clippy::assert_is_empty,
    reason = "tests: exact float comparisons and bit casts are the point"
)]

use rune_lowp::{
    Bf16, E8M0, F4E2M1, F6E2M3, F6E3M2, F8E4M3, F8E5M2, F16, Format, LowpError, Overflow, Rounding,
    Specials,
};

#[test]
fn format_constants_match_the_specs() {
    // (format, max, min normal, min subnormal, emax)
    let cases = [
        (
            Format::BF16,
            f32::from_bits(0x7F7F_0000),
            f32::MIN_POSITIVE,
            f32::from_bits(1 << 16),
            127,
        ),
        (Format::F16, 65504.0, 2f32.powi(-14), 2f32.powi(-24), 15),
        (Format::F8_E4M3, 448.0, 2f32.powi(-6), 2f32.powi(-9), 8),
        (Format::F8_E5M2, 57344.0, 2f32.powi(-14), 2f32.powi(-16), 15),
        (Format::F6_E2M3, 7.5, 1.0, 0.125, 2),
        (Format::F6_E3M2, 28.0, 0.25, 0.0625, 4),
        (Format::F4_E2M1, 6.0, 1.0, 0.5, 2),
    ];
    for (f, max, min_normal, min_sub, emax) in cases {
        assert_eq!(f.max_finite(), max, "{f:?}");
        assert_eq!(f.min_normal(), min_normal, "{f:?}");
        assert_eq!(f.min_subnormal(), min_sub, "{f:?}");
        assert_eq!(f.emax(), emax, "{f:?}");
    }
    assert_eq!(F8E4M3::MAX.to_bits(), 0x7E);
    assert_eq!(F8E4M3::MIN.to_f32(), -448.0);
    assert_eq!(F8E5M2::MAX.to_bits(), 0x7B);
    assert_eq!(F8E5M2::INFINITY.to_bits(), 0x7C);
    assert_eq!(F16::MAX.to_bits(), 0x7BFF);
    assert_eq!(F16::NAN.to_bits(), 0x7E00);
    assert_eq!(Bf16::NAN.to_bits(), 0x7FC0);
    assert_eq!(Bf16::INFINITY.to_f32(), f32::INFINITY);
    assert_eq!(Bf16::NEG_INFINITY.to_f32(), f32::NEG_INFINITY);
    assert_eq!(F4E2M1::MAX.to_bits(), 0x7);
    assert_eq!(F6E2M3::MAX.to_bits(), 0x1F);
    assert_eq!(F6E3M2::MAX.to_bits(), 0x1F);
    for one in [
        Bf16::ONE.to_f32(),
        F16::ONE.to_f32(),
        F8E4M3::ONE.to_f32(),
        F8E5M2::ONE.to_f32(),
        F6E2M3::ONE.to_f32(),
        F6E3M2::ONE.to_f32(),
        F4E2M1::ONE.to_f32(),
    ] {
        assert_eq!(one, 1.0);
    }
    assert_eq!(F4E2M1::NEG_ZERO.to_bits(), 0x8);
    assert_eq!(F16::MIN_POSITIVE_SUBNORMAL.to_f32(), 2f32.powi(-24));
    assert_eq!(F8E4M3::MIN_POSITIVE.to_f32(), 2f32.powi(-6));
    assert_eq!(Format::F16.epsilon(), 2f32.powi(-10));
    assert_eq!(Format::BF16.one_code(), Some(0x3F80));
}

#[test]
fn fp4_value_set() {
    let want = [0.0, 0.5, 1.0, 1.5, 2.0, 3.0, 4.0, 6.0];
    for (c, &v) in want.iter().enumerate() {
        assert_eq!(F4E2M1::from_bits(c as u8).to_f32(), v);
        assert_eq!(F4E2M1::from_bits(c as u8 | 8).to_f32(), -v);
    }
}

#[test]
fn round_to_nearest_even_ties() {
    // bf16 around 1: ulp 2^-7.
    let ulp = 2f32.powi(-7);
    assert_eq!(Bf16::from_f32(1.0 + ulp / 2.0).to_f32(), 1.0); // tie, even is 1.0
    assert_eq!(
        Bf16::from_f32(1.0 + 3.0 * ulp / 2.0).to_f32(),
        1.0 + 2.0 * ulp
    ); // tie, round up
    assert_eq!(
        Bf16::from_f32(f32::from_bits(0x3F80_8001)).to_f32(),
        1.0 + ulp
    ); // just above tie
    // f16: 2049 is a tie between 2048 and 2050 → 2048; 2051 → 2052.
    assert_eq!(F16::from_f32(2049.0).to_f32(), 2048.0);
    assert_eq!(F16::from_f32(2051.0).to_f32(), 2052.0);
    // E4M3: 17 is a tie between 16 and 18 → 16; 19 → 20.
    assert_eq!(F8E4M3::from_f32(17.0).to_f32(), 16.0);
    assert_eq!(F8E4M3::from_f32(19.0).to_f32(), 20.0);
    // E5M2: 1.125 is a tie between 1.0 and 1.25 → 1.0; 1.375 → 1.5.
    assert_eq!(F8E5M2::from_f32(1.125).to_f32(), 1.0);
    assert_eq!(F8E5M2::from_f32(1.375).to_f32(), 1.5);
    // FP4: 2.5 → 2, 3.5 → 4, 5 → 4, 0.25 → 0, 0.75 → 1, 1.25 → 1.
    for (x, y) in [
        (2.5, 2.0),
        (3.5, 4.0),
        (5.0, 4.0),
        (0.25, 0.0),
        (0.75, 1.0),
        (1.25, 1.0),
        (1.75, 2.0),
    ] {
        assert_eq!(F4E2M1::from_f32(x).to_f32(), y, "{x}");
        assert_eq!(F4E2M1::from_f32(-x).to_f32(), -y, "-{x}");
    }
    // FP6 E2M3 ties in the subnormal range: 0.0625 → 0, 0.1875 → 0.25.
    assert_eq!(F6E2M3::from_f32(0.0625).to_f32(), 0.0);
    assert_eq!(F6E2M3::from_f32(0.1875).to_f32(), 0.25);
    assert_eq!(F6E3M2::from_f32(26.0).to_f32(), 24.0); // tie 24 / 28 → 24 (even)
}

#[test]
fn overflow_modes() {
    // E4M3: no infinity. Non-saturating overflow is NaN; 464 is the tie
    // that still rounds down to 448.
    assert_eq!(F8E4M3::from_f32(464.0).to_f32(), 448.0);
    assert!(F8E4M3::from_f32(464.000_03).is_nan());
    assert!(F8E4M3::from_f32(f32::INFINITY).is_nan());
    assert_eq!(F8E4M3::from_f32(-1e30).to_bits(), 0xFF);
    assert_eq!(F8E4M3::from_f32_sat(1e30).to_f32(), 448.0);
    assert_eq!(F8E4M3::from_f32_sat(f32::NEG_INFINITY).to_f32(), -448.0);
    // E5M2: 61440 is the tie between 57344 and "65536" → infinity (odd max).
    assert_eq!(F8E5M2::from_f32(61439.0).to_f32(), 57344.0);
    assert_eq!(F8E5M2::from_f32(61440.0).to_f32(), f32::INFINITY);
    assert_eq!(F8E5M2::from_f32_sat(61440.0).to_f32(), 57344.0);
    assert_eq!(F8E5M2::from_f32_sat(f32::INFINITY).to_f32(), 57344.0);
    // f16 / bf16.
    assert_eq!(F16::from_f32(65519.0).to_f32(), 65504.0);
    assert_eq!(F16::from_f32(65520.0).to_f32(), f32::INFINITY);
    assert_eq!(F16::from_f32_sat(1e6).to_f32(), 65504.0);
    assert_eq!(F16::from_f32_sat(-f32::INFINITY).to_f32(), -65504.0);
    assert_eq!(Bf16::from_f32(f32::MAX).to_f32(), f32::INFINITY);
    assert_eq!(Bf16::from_f32_sat(f32::MAX).to_f32(), Bf16::MAX.to_f32());
    // Toward zero never overflows a finite value.
    assert_eq!(
        F16::from_f32_with(1e6, Rounding::TowardZero, Overflow::NonSaturating).to_f32(),
        65504.0
    );
    assert_eq!(
        F8E4M3::from_f32_with(470.0, Rounding::TowardZero, Overflow::NonSaturating).to_f32(),
        448.0
    );
    // MX FP6 / FP4 always saturate, whatever the mode.
    for o in [Overflow::NonSaturating, Overflow::Saturating] {
        assert_eq!(
            F4E2M1::from_f32_with(7.0, Rounding::NearestEven, o).to_f32(),
            6.0
        );
        assert_eq!(
            F4E2M1::from_f32_with(f32::NEG_INFINITY, Rounding::NearestEven, o).to_f32(),
            -6.0
        );
        assert_eq!(
            F6E2M3::from_f32_with(1e9, Rounding::NearestEven, o).to_f32(),
            7.5
        );
        assert_eq!(
            F6E3M2::from_f32_with(-29.0, Rounding::NearestEven, o).to_f32(),
            -28.0
        );
    }
}

#[test]
fn nan_and_infinity_propagation() {
    let neg_nan = f32::from_bits(0xFFC0_0001);
    // NaN never saturates to a number where the format has a NaN.
    for o in [Overflow::NonSaturating, Overflow::Saturating] {
        let r = Rounding::NearestEven;
        assert!(Bf16::from_f32_with(f32::NAN, r, o).is_nan());
        assert!(F16::from_f32_with(neg_nan, r, o).is_nan());
        assert!(F8E4M3::from_f32_with(f32::NAN, r, o).is_nan());
        assert!(F8E5M2::from_f32_with(f32::NAN, r, o).is_nan());
    }
    // Sign and top payload bits survive, quiet bit set.
    assert_eq!(F16::from_f32(neg_nan).to_bits(), 0xFE00);
    assert_eq!(F16::from_f32(f32::from_bits(0x7F80_2000)).to_bits(), 0x7E01); // sNaN → qNaN
    assert_eq!(
        Bf16::from_f32(f32::from_bits(0x7F81_0000)).to_bits(),
        0x7FC1
    );
    assert_eq!(F8E4M3::from_f32(neg_nan).to_bits(), 0xFF);
    assert_eq!(F8E5M2::from_f32(f32::NAN).to_bits(), 0x7E);
    // F16 sNaN widens to a quiet NaN with the payload.
    assert_eq!(F16::from_bits(0x7C01).to_f32().to_bits(), 0x7FC0_2000);
    // Formats without NaN: NaN maps to the largest positive value.
    assert_eq!(F4E2M1::from_f32(f32::NAN).to_f32(), 6.0);
    assert_eq!(F6E3M2::from_f32(neg_nan).to_f32(), 28.0);
    // Infinities.
    assert_eq!(
        Bf16::from_f32(f32::NEG_INFINITY).to_f32(),
        f32::NEG_INFINITY
    );
    assert_eq!(F8E5M2::from_f32(f32::INFINITY).to_bits(), 0x7C);
    assert_eq!(F8E5M2::from_f32(f32::NEG_INFINITY).to_bits(), 0xFC);
    // IEEE comparisons.
    assert_ne!(F16::NAN, F16::NAN);
    assert_eq!(F16::ZERO, F16::NEG_ZERO);
    assert!(F8E4M3::from_f32(1.0) < F8E4M3::from_f32(2.0));
}

#[test]
fn subnormals_are_exact() {
    // E4M3 subnormals are k · 2^-9.
    for k in 0..8u8 {
        let x = f32::from(k) * 2f32.powi(-9);
        assert_eq!(F8E4M3::from_f32(x).to_bits(), k);
        assert_eq!(F8E4M3::from_bits(k).to_f32(), x);
    }
    // Halfway below the smallest subnormal rounds to zero (even), just above
    // rounds up; 1.5 · min rounds to 2 · min (even).
    let min = 2f32.powi(-9);
    assert_eq!(F8E4M3::from_f32(min / 2.0).to_bits(), 0);
    assert_eq!(F8E4M3::from_f32(min / 2.0 * 1.000_001).to_bits(), 1);
    assert_eq!(F8E4M3::from_f32(min * 1.5).to_bits(), 2);
    // Largest subnormal rounds up into the smallest normal.
    assert_eq!(F8E4M3::from_f32(7.5 * min).to_bits(), 8);
    // f16 subnormal boundary and f32 subnormal inputs.
    assert_eq!(F16::from_f32(2f32.powi(-25)).to_bits(), 0);
    assert_eq!(F16::from_f32(2f32.powi(-25) * 1.5).to_bits(), 1);
    assert_eq!(F16::from_f32(-f32::from_bits(1)).to_bits(), 0x8000);
    assert_eq!(Bf16::from_f32(f32::from_bits(0x0000_8000)).to_bits(), 0); // tie to even
    assert_eq!(Bf16::from_f32(f32::from_bits(0x0001_8000)).to_bits(), 2);
    assert_eq!(Bf16::from_bits(1).to_f32(), f32::from_bits(0x0001_0000));
    assert_eq!(F8E5M2::from_f32(-(2f32.powi(-16))).to_bits(), 0x81);
}

#[test]
fn bit_helpers() {
    assert!(F4E2M1::try_from_bits(0x10).is_err());
    assert_eq!(
        F6E2M3::try_from_bits(0x40),
        Err(LowpError::InvalidBits {
            bits: 0x40,
            width: 6
        })
    );
    assert_eq!(F4E2M1::from_bits(0x1F).to_bits(), 0xF);
    assert_eq!(F8E4M3::from_f32(-2.0).abs().to_f32(), 2.0);
    assert_eq!((-F8E5M2::from_f32(3.0)).to_f32(), -3.0);
    assert!(F16::from_f32(-0.0).is_sign_negative());
    assert!(!Bf16::INFINITY.is_finite());
    assert_eq!(format!("{}", F4E2M1::from_f32(1.5)), "1.5");
    assert_eq!(f32::from(F6E3M2::from_f32(0.75)), 0.75);
}

#[test]
fn custom_formats() {
    // E3M4 with bias 3, IEEE-style.
    let f = Format::new(3, 4, 3, Specials::Ieee).unwrap_or(Format::F16);
    assert_eq!(f.bits(), 8);
    assert_eq!(f.max_finite(), 15.5);
    assert_eq!(
        f.decode(f.encode(1.03, Rounding::NearestEven, Overflow::NonSaturating)),
        1.0
    );
    assert!(Format::new(0, 3, 1, Specials::FiniteOnly).is_err());
    assert!(Format::new(8, 8, 127, Specials::Ieee).is_err()); // 17 bits
    assert!(Format::new(2, 0, 1, Specials::NanOnly).is_err());
    assert!(Format::new(8, 7, 100, Specials::Ieee).is_err()); // exceeds f32 range
    assert!(Format::new(8, 7, 145, Specials::Ieee).is_err()); // below f32 subnormals
}

#[test]
fn e8m0_every_code() {
    for c in 0..=254u8 {
        let s = E8M0::from_bits(c);
        let v = s.to_f32();
        assert_eq!(f64::from(v), 2f64.powi(i32::from(c) - 127), "{c}");
        assert_eq!(E8M0::from_f32_floor(v), s);
        assert_eq!(E8M0::from_f32_ceil(v), s);
        assert_eq!(s.exponent(), Some(i32::from(c) - 127));
        if c < 254 {
            // Strictly between two scales: floor goes down, ceil goes up.
            let mid = v * 1.5;
            assert_eq!(E8M0::from_f32_floor(mid), s);
            assert_eq!(E8M0::from_f32_ceil(mid), E8M0::from_bits(c + 1));
            assert_eq!(E8M0::from_f32_floor(-mid), s);
        }
    }
    assert!(E8M0::NAN.to_f32().is_nan());
    assert!(E8M0::from_f32_floor(f32::NAN).is_nan());
    assert_eq!(E8M0::from_f32_floor(f32::INFINITY), E8M0::MAX);
    assert_eq!(E8M0::from_f32_ceil(f32::MAX), E8M0::MAX);
    assert_eq!(E8M0::from_f32_floor(0.0), E8M0::MIN);
    assert_eq!(E8M0::from_f32_floor(f32::from_bits(1)), E8M0::MIN);
    assert_eq!(E8M0::from_exponent(128), None);
    assert_eq!(E8M0::from_exponent(-3).map(E8M0::to_f32), Some(0.125));
    assert_eq!(E8M0::from_exponent_saturating(-500), E8M0::MIN);
    assert_eq!(format!("{:?}", E8M0::ONE), "2^0");
}
