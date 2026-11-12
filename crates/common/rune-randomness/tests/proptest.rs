//! Property tests: p-values stay in range, symmetries of the statistics
//! hold, and nothing panics on arbitrary input.

#![allow(clippy::float_cmp, reason = "the symmetries hold exactly")]

use proptest::prelude::*;
use rune_randomness::nist::{self, Direction};
use rune_randomness::{Options, TokenOptions, analyze_tokens, run};

fn in_unit(p: f64) -> bool {
    (0.0..=1.0).contains(&p)
}

proptest! {
    #[test]
    fn p_values_in_unit_interval(bits in prop::collection::vec(any::<bool>(), 1..600)) {
        let options = Options::default().with_allow_short(true);
        let report = run(&bits, &options).unwrap_or_else(|e| panic!("{e}"));
        for outcome in &report.outcomes {
            prop_assert!(in_unit(outcome.p_value), "{outcome:?}");
        }
        prop_assert_eq!(report.outcomes.len() + report.skipped.len(), 9);
    }

    #[test]
    fn complement_symmetry(bits in prop::collection::vec(any::<bool>(), 1..400)) {
        let flipped: Vec<bool> = bits.iter().map(|b| !b).collect();
        let a = nist::frequency(&bits).unwrap_or_else(|e| panic!("{e}"));
        let b = nist::frequency(&flipped).unwrap_or_else(|e| panic!("{e}"));
        prop_assert_eq!(a, b);
        let a = nist::runs(&bits).unwrap_or_else(|e| panic!("{e}"));
        let b = nist::runs(&flipped).unwrap_or_else(|e| panic!("{e}"));
        prop_assert_eq!(a.statistic, b.statistic);
        let a = nist::cumulative_sums(&bits, Direction::Forward).unwrap_or_else(|e| panic!("{e}"));
        let b = nist::cumulative_sums(&flipped, Direction::Forward).unwrap_or_else(|e| panic!("{e}"));
        prop_assert_eq!(a, b);
    }

    #[test]
    fn backward_is_forward_of_reversed(bits in prop::collection::vec(any::<bool>(), 1..400)) {
        let reversed: Vec<bool> = bits.iter().rev().copied().collect();
        let a = nist::cumulative_sums(&bits, Direction::Backward).unwrap_or_else(|e| panic!("{e}"));
        let b = nist::cumulative_sums(&reversed, Direction::Forward).unwrap_or_else(|e| panic!("{e}"));
        prop_assert_eq!(a.statistic, b.statistic);
        prop_assert_eq!(a.p_value, b.p_value);
    }

    #[test]
    fn tokens_never_panic(tokens in prop::collection::vec(prop::collection::vec(any::<u8>(), 0..12), 0..40)) {
        if let Ok(report) = analyze_tokens(&tokens, &TokenOptions::default()) {
            prop_assert!(report.positions.iter().all(|p| in_unit(p.p_value)));
            prop_assert!(report.bit_positions.iter().all(|p| in_unit(p.p_value)));
        }
        let _ = analyze_tokens(&tokens, &TokenOptions::default().with_alphabet("0123456789abcdef"));
    }

    #[test]
    fn parameters_never_panic(bits in prop::collection::vec(any::<bool>(), 0..300), m in 0usize..30, block in 0usize..400) {
        let _ = nist::serial(&bits, m);
        let _ = nist::approximate_entropy(&bits, m);
        let _ = nist::block_frequency(&bits, block);
        let _ = nist::longest_run_of_ones(&bits);
        let _ = run(&bits, &Options::default().with_block_length(block).with_serial_m(m));
    }
}
