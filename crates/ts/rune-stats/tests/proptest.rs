//! Property tests: agreement between the allocating, in-place and sorted
//! variants, invariants of the tests, and bit-for-bit parity with the
//! reference statistics implementation kept below.

#![allow(
    clippy::float_cmp,
    clippy::cast_precision_loss,
    reason = "bit-for-bit equality is the property under test; counts are small"
)]

use proptest::prelude::*;
use rune_stats::{
    Alternative, KsOptions, MannWhitneyOptions, Method, WilcoxonOptions, hodges_lehmann_shift,
    ks_two_sample, mad, mad_in_place, mann_whitney_u, mean, median, median_in_place, median_sorted,
    quantile, quantile_in_place, quantile_sorted, robust_sigma, wilcoxon_signed_rank,
};

/// A reference implementation, kept verbatim (minus serde and its
/// approximate `erfc`) as the reference that
/// `rune-stats` must reproduce exactly.
mod reference {
    pub fn median(values: &[f64]) -> Option<f64> {
        if values.is_empty() {
            return None;
        }
        let mut sorted = values.to_vec();
        sorted.sort_by(f64::total_cmp);
        let mid = sorted.len() / 2;
        if sorted.len().is_multiple_of(2) {
            Some(f64::midpoint(sorted[mid - 1], sorted[mid]))
        } else {
            Some(sorted[mid])
        }
    }

    pub fn mad(values: &[f64]) -> Option<f64> {
        let center = median(values)?;
        let deviations: Vec<f64> = values.iter().map(|value| (value - center).abs()).collect();
        median(&deviations)
    }

    pub fn mean(values: &[f64]) -> Option<f64> {
        if values.is_empty() {
            None
        } else {
            Some(values.iter().sum::<f64>() / values.len() as f64)
        }
    }

    /// `(u, z)` of `mann_whitney_greater`.
    pub fn mann_whitney_greater(greater: &[f64], smaller: &[f64]) -> Option<(f64, f64)> {
        if greater.is_empty() || smaller.is_empty() {
            return None;
        }
        let n1 = greater.len() as f64;
        let n2 = smaller.len() as f64;
        let (ranks, tie_term) = average_ranks(greater, smaller);
        let rank_sum: f64 = ranks.iter().take(greater.len()).sum();
        let u = n1.mul_add(-(n1 + 1.0) / 2.0, rank_sum);
        let n = n1 + n2;
        let expected = n1 * n2 / 2.0;
        let variance = n1 * n2 / 12.0 * ((n + 1.0) - tie_term / (n * (n - 1.0)));
        if variance <= f64::EPSILON {
            return Some((u, 0.0));
        }
        Some((u, (u - expected - 0.5) / variance.sqrt()))
    }

    fn average_ranks(first: &[f64], second: &[f64]) -> (Vec<f64>, f64) {
        let combined: Vec<f64> = first.iter().chain(second).copied().collect();
        let mut order: Vec<usize> = (0..combined.len()).collect();
        order.sort_by(|&a, &b| combined[a].total_cmp(&combined[b]));
        let mut ranks = vec![0.0; combined.len()];
        let mut tie_term = 0.0;
        let mut start = 0;
        while start < order.len() {
            let mut end = start + 1;
            while end < order.len()
                && combined[order[end]]
                    .total_cmp(&combined[order[start]])
                    .is_eq()
            {
                end += 1;
            }
            let average = (start + end + 1) as f64 / 2.0;
            for &index in &order[start..end] {
                ranks[index] = average;
            }
            let tied = (end - start) as f64;
            tie_term += tied.mul_add(tied * tied, -tied);
            start = end;
        }
        (ranks, tie_term)
    }
}

/// Finite samples drawn from a small grid so that ties are common.
fn sample(max_len: usize) -> impl Strategy<Value = Vec<f64>> {
    prop::collection::vec(
        prop_oneof![(-20i32..20).prop_map(|v| f64::from(v) / 2.0), -1e6f64..1e6,],
        1..max_len,
    )
}

proptest! {
    #[test]
    fn reference_parity(x in sample(40), y in sample(40)) {
        prop_assert_eq!(median(&x).ok(), reference::median(&x));
        prop_assert_eq!(mad(&x).ok(), reference::mad(&x));
        prop_assert_eq!(mean(&x).ok(), reference::mean(&x));
        prop_assert_eq!(robust_sigma(&x).ok(), reference::mad(&x).map(|d| d * 1.4826));
        let options = MannWhitneyOptions::default()
            .with_alternative(Alternative::Greater)
            .with_method(Method::Asymptotic);
        let ours = mann_whitney_u(&x, &y, &options).unwrap();
        let (u, z) = reference::mann_whitney_greater(&x, &y).unwrap();
        prop_assert_eq!(ours.u, u);
        prop_assert_eq!(ours.z, z);
    }

    #[test]
    fn order_statistic_variants_agree(x in sample(60), p in 0.0f64..=1.0) {
        let mut sorted = x.clone();
        sorted.sort_by(f64::total_cmp);
        let expected = median(&x).unwrap();
        prop_assert_eq!(median_sorted(&sorted).unwrap(), expected);
        prop_assert_eq!(median_in_place(&mut x.clone()).unwrap(), expected);
        let q = quantile(&x, p).unwrap();
        prop_assert_eq!(quantile_sorted(&sorted, p).unwrap(), q);
        prop_assert_eq!(quantile_in_place(&mut x.clone(), p).unwrap(), q);
        prop_assert!(sorted[0] <= q && q <= sorted[sorted.len() - 1]);
        prop_assert_eq!(mad_in_place(&mut x.clone()).unwrap(), mad(&x).unwrap());
    }

    #[test]
    fn quantile_is_monotone(x in sample(60), a in 0.0f64..=1.0, b in 0.0f64..=1.0) {
        let (lo, hi) = if a <= b { (a, b) } else { (b, a) };
        prop_assert!(quantile(&x, lo).unwrap() <= quantile(&x, hi).unwrap());
    }

    #[test]
    fn mann_whitney_invariants(x in sample(30), y in sample(30)) {
        let pairs = (x.len() * y.len()) as f64;
        for alternative in [Alternative::TwoSided, Alternative::Greater, Alternative::Less] {
            let options = MannWhitneyOptions::default().with_alternative(alternative);
            let forward = mann_whitney_u(&x, &y, &options).unwrap();
            let backward = mann_whitney_u(&y, &x, &options).unwrap();
            prop_assert_eq!(forward.u + backward.u, pairs);
            prop_assert!((0.0..=1.0).contains(&forward.p_value));
            prop_assert!((-1.0..=1.0).contains(&forward.rank_biserial));
        }
        let two = MannWhitneyOptions::default();
        let forward = mann_whitney_u(&x, &y, &two).unwrap();
        let backward = mann_whitney_u(&y, &x, &two).unwrap();
        prop_assert!((forward.p_value - backward.p_value).abs() < 1e-12);
    }

    #[test]
    fn ks_invariants(x in sample(30), y in sample(30)) {
        let result = ks_two_sample(&x, &y, &KsOptions::default()).unwrap();
        let swapped = ks_two_sample(&y, &x, &KsOptions::default()).unwrap();
        prop_assert!((0.0..=1.0).contains(&result.statistic));
        prop_assert!((0.0..=1.0).contains(&result.p_value));
        prop_assert_eq!(result.statistic, swapped.statistic);
        prop_assert_eq!(result.d_plus, swapped.d_minus);
        prop_assert!((result.p_value - swapped.p_value).abs() < 1e-12);
        let asymptotic = ks_two_sample(&x, &y, &KsOptions::default().with_method(Method::Asymptotic)).unwrap();
        prop_assert!((0.0..=1.0).contains(&asymptotic.p_value));
    }

    #[test]
    fn wilcoxon_invariants(d in sample(60)) {
        if let Ok(result) = wilcoxon_signed_rank(&d, &WilcoxonOptions::default()) {
            let n = result.n_nonzero as f64;
            prop_assert!((result.w_plus + result.w_minus - n * (n + 1.0) / 2.0).abs() < 1e-9);
            prop_assert!((0.0..=1.0).contains(&result.p_value));
            let negated: Vec<f64> = d.iter().map(|v| -v).collect();
            let mirror = wilcoxon_signed_rank(&negated, &WilcoxonOptions::default()).unwrap();
            prop_assert_eq!(mirror.w_plus, result.w_minus);
            prop_assert!((mirror.p_value - result.p_value).abs() < 1e-12);
        } else {
            prop_assert!(d.iter().all(|v| *v == 0.0));
        }
    }

    #[test]
    fn shift_interval_contains_estimate(x in sample(25), y in sample(25), confidence in 0.5f64..0.999) {
        let ci = hodges_lehmann_shift(&x, &y, confidence).unwrap();
        prop_assert!(ci.lower <= ci.estimate && ci.estimate <= ci.upper);
    }

    #[test]
    fn never_panics(x in prop::collection::vec(any::<f64>(), 0..20), y in prop::collection::vec(any::<f64>(), 0..20), p in any::<f64>()) {
        let _ = median(&x);
        let _ = quantile(&x, p);
        let _ = mad(&x);
        let _ = rune_stats::variance(&x);
        let _ = rune_stats::median_ci(&x, p);
        let _ = rune_stats::hodges_lehmann_one_sample(&x, p);
        let _ = hodges_lehmann_shift(&x, &y, p);
        let _ = rune_stats::cohens_d(&x, &y);
        for method in [Method::Auto, Method::Exact, Method::Asymptotic] {
            let _ = mann_whitney_u(&x, &y, &MannWhitneyOptions::default().with_method(method));
            let _ = ks_two_sample(&x, &y, &KsOptions::default().with_method(method));
            let _ = wilcoxon_signed_rank(&x, &WilcoxonOptions::default().with_method(method));
        }
        let _ = rune_stats::dist::normal_quantile(p);
        let _ = rune_stats::dist::kolmogorov_sf(p);
        let _ = rune_stats::dist::erfc(p);
        let _ = rune_stats::dist::ln_gamma(p);
        let _ = rune_stats::dist::gamma_p(p, p.abs());
        let _ = rune_stats::dist::gamma_q(p.abs(), p);
        let _ = rune_stats::dist::chi_squared_sf(p, p.abs());
    }
}
