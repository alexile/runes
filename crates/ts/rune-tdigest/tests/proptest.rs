//! Property tests: quantile estimates stay inside the observed range, are
//! monotone in `q`, and never panic or go `NaN` on arbitrary input.

#![allow(
    clippy::float_cmp,
    reason = "the extreme quantiles are tracked exactly"
)]

use proptest::prelude::*;
use rune_tdigest::TDigest;

fn values() -> impl Strategy<Value = Vec<f64>> {
    prop::collection::vec(
        prop_oneof![
            8 => -1.0e6..1.0e6f64,
            1 => Just(f64::NAN),
            1 => Just(f64::INFINITY),
        ],
        0..2_000,
    )
}

proptest! {
    #[test]
    fn quantiles_are_bounded_and_monotone(data in values(), compression in 1.0..300.0f64) {
        let mut digest = TDigest::new(compression);
        for &x in &data {
            digest.add(x);
        }
        let finite: Vec<f64> = data.iter().copied().filter(|x| x.is_finite()).collect();
        prop_assert_eq!(digest.count(), finite.len());
        if finite.is_empty() {
            prop_assert!(digest.quantile(0.5).is_nan());
            return Ok(());
        }
        let lo = finite.iter().copied().fold(f64::INFINITY, f64::min);
        let hi = finite.iter().copied().fold(f64::NEG_INFINITY, f64::max);
        prop_assert_eq!(digest.quantile(0.0), lo);
        prop_assert_eq!(digest.quantile(1.0), hi);
        let mut prev = lo;
        for i in 0..=100 {
            let v = digest.quantile(f64::from(i) / 100.0);
            prop_assert!(v.is_finite());
            prop_assert!(v >= prev, "not monotone at q={}", f64::from(i) / 100.0);
            prop_assert!(v <= hi);
            prev = v;
        }
    }
}
