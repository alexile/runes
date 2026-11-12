//! Model-based properties of the admission core: for any interleaving of
//! acquires and releases, the limiter agrees with a simple counter model.

use proptest::prelude::*;
use rune_axum_concurrency::Limiter;

#[derive(Clone, Debug)]
enum Op {
    Acquire,
    /// Release the held permit at this index (modulo the number held).
    Release(usize),
}

fn op() -> impl Strategy<Value = Op> {
    prop_oneof![Just(Op::Acquire), any::<usize>().prop_map(Op::Release)]
}

proptest! {
    #[test]
    fn matches_counter_model(max in 0usize..8, ops in prop::collection::vec(op(), 0..200)) {
        let limiter = Limiter::new(max);
        let mut held = Vec::new();
        let (mut admitted, mut shed, mut peak) = (0u64, 0u64, 0usize);

        for op in ops {
            match op {
                Op::Acquire => {
                    if let Some(p) = limiter.try_acquire() {
                        prop_assert!(held.len() < max);
                        held.push(p);
                        admitted += 1;
                        peak = peak.max(held.len());
                    } else {
                        prop_assert_eq!(held.len(), max);
                        shed += 1;
                    }
                }
                Op::Release(i) if !held.is_empty() => {
                    let idx = i % held.len();
                    drop(held.swap_remove(idx));
                }
                Op::Release(_) => {}
            }
            let m = limiter.metrics();
            prop_assert_eq!(m.in_flight, held.len());
            prop_assert!(m.in_flight <= max);
            prop_assert_eq!(m.admitted, admitted);
            prop_assert_eq!(m.shed, shed);
            prop_assert_eq!(m.peak, peak);
        }
    }
}
