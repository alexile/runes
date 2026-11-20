//! Serde support: scalars as raw bits, validated on the way in.

#![cfg(feature = "serde")]
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
    AmaxReduction, Bf16, E8M0, F4E2M1, F6E3M2, F8E4M3, F16, MxElement, Overflow, Rounding,
    ScalePair, ScalingRecipe,
};

#[test]
fn scalars_round_trip_as_bits() {
    let v = (
        Bf16::from_f32(1.5),
        F16::NAN,
        F8E4M3::MIN,
        F4E2M1::from_f32(-3.0),
        E8M0::ONE,
    );
    let s = serde_json::to_string(&v).unwrap();
    assert_eq!(s, "[16320,32256,254,13,127]");
    let back: (Bf16, F16, F8E4M3, F4E2M1, E8M0) = serde_json::from_str(&s).unwrap();
    assert_eq!(back.0.to_bits(), v.0.to_bits());
    assert_eq!(back.1.to_bits(), v.1.to_bits());
    assert_eq!(back.2.to_bits(), v.2.to_bits());
    assert_eq!(back.3.to_bits(), v.3.to_bits());
    assert_eq!(back.4, v.4);
}

#[test]
fn out_of_range_bits_are_rejected() {
    assert!(serde_json::from_str::<F4E2M1>("16").is_err());
    assert!(serde_json::from_str::<F6E3M2>("64").is_err());
    assert!(serde_json::from_str::<F8E4M3>("256").is_err());
    assert_eq!(serde_json::from_str::<F6E3M2>("63").unwrap().to_bits(), 63);
}

#[test]
fn config_types() {
    let r = ScalingRecipe::for_element::<F8E4M3>().with_power_of_two(true);
    let back: ScalingRecipe = serde_json::from_str(&serde_json::to_string(&r).unwrap()).unwrap();
    assert_eq!(back, r);
    let p = ScalePair::from_scale(2.0).unwrap();
    let back: ScalePair = serde_json::from_str(&serde_json::to_string(&p).unwrap()).unwrap();
    assert_eq!(back, p);
    for x in [Rounding::Stochastic(7), Rounding::TowardZero] {
        let back: Rounding = serde_json::from_str(&serde_json::to_string(&x).unwrap()).unwrap();
        assert_eq!(back, x);
    }
    let back: (Overflow, MxElement, AmaxReduction) = serde_json::from_str(
        &serde_json::to_string(&(
            Overflow::Saturating,
            MxElement::Fp6E2M3,
            AmaxReduction::MostRecent,
        ))
        .unwrap(),
    )
    .unwrap();
    assert_eq!(
        back,
        (
            Overflow::Saturating,
            MxElement::Fp6E2M3,
            AmaxReduction::MostRecent
        )
    );
}
