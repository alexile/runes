//! Property tests for the window, token-budget and summary invariants.

#![allow(clippy::unwrap_used, reason = "test assertions")]

use proptest::prelude::*;
use rune_chain_core::{ChainError, Memory, Message, Role};
use rune_chain_memory::{
    MemorySnapshot, SimpleMemory, SummaryBufferMemory, TokenBufferMemory, WindowedMemory,
};

/// Token cost = content length, so tests can reason about it exactly.
fn len_cost(m: &Message) -> usize {
    m.content.text_content().len()
}

fn turn() -> impl Strategy<Value = Message> {
    (any::<bool>(), "[a-z]{0,12}").prop_map(|(human, text)| {
        if human {
            Message::human(text)
        } else {
            Message::ai(text)
        }
    })
}

fn run<F: std::future::Future>(f: F) -> F::Output {
    tokio_test::block_on(f)
}

proptest! {
    #[test]
    fn windowed_returns_the_last_n(window in 0usize..8, turns in prop::collection::vec(turn(), 0..40)) {
        let mem = WindowedMemory::new(window);
        run(async {
            for t in &turns {
                mem.add(t.clone()).await.unwrap();
            }
        });
        let got = run(mem.messages()).unwrap();
        let start = turns.len().saturating_sub(window);
        prop_assert_eq!(&got[..], &turns[start..]);
        prop_assert!(mem.len() <= window);
    }

    #[test]
    fn windowed_pins_first_system(window in 0usize..6, turns in prop::collection::vec(turn(), 0..30)) {
        let mem = WindowedMemory::new(window).pin_system(true);
        let sys = Message::system("rules");
        run(async {
            mem.add(sys.clone()).await.unwrap();
            for t in &turns {
                mem.add(t.clone()).await.unwrap();
            }
        });
        let got = run(mem.messages()).unwrap();
        prop_assert_eq!(&got[0], &sys);
        let start = turns.len().saturating_sub(window);
        prop_assert_eq!(&got[1..], &turns[start..]);
    }

    #[test]
    fn token_buffer_keeps_longest_fitting_suffix(
        budget in 0usize..60,
        turns in prop::collection::vec(turn(), 0..40),
    ) {
        let mem = TokenBufferMemory::new(budget, len_cost).pin_system(false);
        run(async {
            for t in &turns {
                mem.add(t.clone()).await.unwrap();
            }
        });
        let got = run(mem.messages()).unwrap();
        prop_assert!(mem.token_count() <= budget);
        prop_assert_eq!(mem.token_count(), got.iter().map(len_cost).sum::<usize>());
        // Longest suffix of `turns` whose cost fits.
        let mut cost = 0;
        let mut start = turns.len();
        while start > 0 && cost + len_cost(&turns[start - 1]) <= budget {
            start -= 1;
            cost += len_cost(&turns[start]);
        }
        prop_assert_eq!(&got[..], &turns[start..]);
    }

    #[test]
    fn token_buffer_pins_system_and_respects_cap(
        budget in 0usize..60,
        cap in 1usize..10,
        turns in prop::collection::vec(turn(), 0..40),
    ) {
        let mem = TokenBufferMemory::new(budget, len_cost).max_messages(cap);
        let sys = Message::system("s");
        run(async {
            mem.add(sys.clone()).await.unwrap();
            for t in &turns {
                mem.add(t.clone()).await.unwrap();
            }
        });
        let got = run(mem.messages()).unwrap();
        prop_assert!(got.len() <= cap);
        if budget >= 1 {
            prop_assert_eq!(&got[0], &sys);
            prop_assert!(mem.token_count() <= budget);
        }
        // Visible turns are an in-order suffix of what was added.
        let rest: Vec<_> = got.iter().filter(|m| m.role != Role::System).cloned().collect();
        prop_assert!(turns.ends_with(&rest));
    }

    #[test]
    fn summary_buffer_loses_nothing(
        budget in 0usize..8,
        n in 0usize..30,
    ) {
        let joiner = |prev: Option<&str>, msgs: &[Message]| -> Result<String, ChainError> {
            let mut parts: Vec<String> = prev.into_iter().map(str::to_owned).collect();
            parts.extend(msgs.iter().map(|m| m.content.text_content()));
            Ok(parts.join(","))
        };
        let mem = SummaryBufferMemory::new(joiner, budget)
            .with_counter(|_: &Message| 1)
            .summary_prefix("");
        let added: Vec<String> = (0..n).map(|i| i.to_string()).collect();
        run(async {
            for t in &added {
                mem.add(Message::human(t.as_str())).await.unwrap();
            }
        });
        let mut seen: Vec<String> = mem
            .summary()
            .map(|s| s.split(',').map(str::to_owned).collect())
            .unwrap_or_default();
        let got = run(mem.messages()).unwrap();
        let verbatim = &got[usize::from(mem.summary().is_some())..];
        seen.extend(verbatim.iter().map(|m| m.content.text_content()));
        prop_assert_eq!(seen, added);
        // After each add at most one compaction runs, so the verbatim part
        // never exceeds the budget by more than the summary's own cost + 1.
        prop_assert!(verbatim.len() <= budget.max(1) + 1);
    }

    #[test]
    fn snapshot_json_roundtrip(turns in prop::collection::vec(turn(), 0..20)) {
        let mem = SimpleMemory::new();
        run(async {
            for t in &turns {
                mem.add(t.clone()).await.unwrap();
            }
        });
        let json = serde_json::to_string(&mem.snapshot()).unwrap();
        let snap: MemorySnapshot = serde_json::from_str(&json).unwrap();
        let other = SimpleMemory::new();
        other.restore(snap).unwrap();
        prop_assert_eq!(run(other.messages()).unwrap(), turns);
    }
}
