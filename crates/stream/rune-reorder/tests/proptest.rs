//! Ordering properties of the reorder buffer.

use proptest::prelude::*;
use rune_reorder::Reorder;

fn run(window: usize, input: &[u64]) -> Vec<u64> {
    let mut reorder = Reorder::new(window);
    let mut out = Vec::new();
    for &seq in input {
        out.extend(reorder.push(seq, seq));
    }
    out.extend(reorder.flush());
    out
}

proptest! {
    /// With a window at least as large as the stream, any permutation comes
    /// out fully sorted with nothing lost.
    #[test]
    fn permutation_within_window_is_fully_restored(
        perm in (1usize..40).prop_flat_map(|n| Just((0..n as u64).collect::<Vec<_>>()).prop_shuffle())
    ) {
        let n = perm.len();
        let out = run(n, &perm);
        prop_assert_eq!(out, (0..n as u64).collect::<Vec<_>>());
    }

    /// Whatever arrives, the emitted sequence is strictly increasing, contains
    /// only pushed sequence numbers, and never repeats one.
    #[test]
    fn output_is_strictly_increasing_subset(
        window in 1usize..6,
        input in prop::collection::vec(0u64..30, 0..60),
    ) {
        let out = run(window, &input);
        prop_assert!(out.windows(2).all(|w| w[0] < w[1]), "{out:?}");
        prop_assert!(out.iter().all(|s| input.contains(s)));
    }

    /// In-order input is emitted immediately, item by item.
    #[test]
    fn in_order_input_is_never_delayed(n in 0u64..50, window in 1usize..4) {
        let mut reorder = Reorder::new(window);
        for seq in 0..n {
            prop_assert_eq!(reorder.push(seq, seq), vec![seq]);
        }
        prop_assert!(reorder.flush().is_empty());
    }

    /// Bounded displacement: if every item arrives at most `window` positions
    /// away from its sorted slot, nothing is dropped.
    #[test]
    fn bounded_displacement_loses_nothing(n in 1u64..60, window in 1usize..6, seed in any::<u64>()) {
        // Swap disjoint adjacent pairs chosen by `seed`: displacement 1.
        let mut input: Vec<u64> = (0..n).collect();
        let mut i = 0usize;
        while i + 1 < input.len() {
            if (seed >> (i % 64)) & 1 == 1 {
                input.swap(i, i + 1);
                i += 2;
            } else {
                i += 1;
            }
        }
        prop_assert_eq!(run(window, &input), (0..n).collect::<Vec<_>>());
    }
}
