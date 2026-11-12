//! Single-threaded backpressure properties for each policy, checked against a
//! `VecDeque` reference model over random interleavings of send and recv.

#![allow(clippy::unwrap_used, reason = "test helpers fail loudly")]

use std::collections::VecDeque;

use proptest::prelude::*;
use rune_bp_channel::{BackpressurePolicy, PushOutcome, channel};

#[derive(Debug, Clone, Copy)]
enum Op {
    Send,
    Recv,
}

fn ops() -> impl Strategy<Value = Vec<Op>> {
    prop::collection::vec(prop_oneof![3 => Just(Op::Send), 2 => Just(Op::Recv)], 0..80)
}

proptest! {
    /// Drop policies never block, so any interleaving can be replayed on one
    /// thread and compared with the model step by step.
    #[test]
    fn drop_policies_match_model(
        capacity in 1usize..6,
        drop_oldest in any::<bool>(),
        ops in ops(),
    ) {
        let policy = if drop_oldest {
            BackpressurePolicy::DropOldest
        } else {
            BackpressurePolicy::DropNewest
        };
        let (tx, rx) = channel::<u32>(capacity, policy);
        let mut model: VecDeque<u32> = VecDeque::new();
        let mut next = 0u32;
        for op in ops {
            match op {
                Op::Send => {
                    let item = next;
                    next += 1;
                    let want = if model.len() < capacity {
                        model.push_back(item);
                        PushOutcome::Accepted
                    } else if drop_oldest {
                        let old = model.pop_front().unwrap();
                        model.push_back(item);
                        PushOutcome::DroppedOldest(old)
                    } else {
                        PushOutcome::DroppedNewest(item)
                    };
                    prop_assert_eq!(tx.send(item), want);
                    prop_assert!(model.len() <= capacity);
                }
                Op::Recv => {
                    // Only receive when the model says data is buffered:
                    // `recv` on an empty, open channel would block.
                    if let Some(want) = model.pop_front() {
                        prop_assert_eq!(rx.recv(), Some(want));
                    }
                }
            }
        }
        drop(tx);
        let rest: Vec<u32> = std::iter::from_fn(|| rx.recv()).collect();
        prop_assert_eq!(rest, model.into_iter().collect::<Vec<_>>());
    }

    /// Under `Block`, sends that fit are accepted and nothing is ever dropped
    /// or reordered.
    #[test]
    fn block_policy_without_contention_is_lossless_fifo(capacity in 1usize..6, ops in ops()) {
        let (tx, rx) = channel::<u32>(capacity, BackpressurePolicy::Block);
        let mut model: VecDeque<u32> = VecDeque::new();
        let mut next = 0u32;
        for op in ops {
            match op {
                // Skip sends that would block this single thread.
                Op::Send if model.len() < capacity => {
                    prop_assert_eq!(tx.send(next), PushOutcome::Accepted);
                    model.push_back(next);
                    next += 1;
                }
                Op::Send => {}
                Op::Recv => {
                    if let Some(want) = model.pop_front() {
                        prop_assert_eq!(rx.recv(), Some(want));
                    }
                }
            }
        }
        drop(tx);
        let rest: Vec<u32> = std::iter::from_fn(|| rx.recv()).collect();
        prop_assert_eq!(rest, model.into_iter().collect::<Vec<_>>());
    }
}
