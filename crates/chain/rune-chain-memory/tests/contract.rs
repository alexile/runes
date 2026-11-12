//! Every memory backend upholds the `rune_chain_core::Memory` contract:
//! clear empties it, and history is an in-order suffix of what was added.

#![allow(clippy::unwrap_used, reason = "test assertions")]

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use rune_chain_core::testing::check_memory;
use rune_chain_core::{ChainError, Memory, Message};
use rune_chain_memory::{
    SimpleMemory, Summarizer, SummaryBufferMemory, TokenBufferMemory, WindowedMemory,
};

/// Summarizer that yields to the runtime so other tasks interleave with it.
struct SlowJoin;

#[async_trait]
impl Summarizer for SlowJoin {
    async fn summarize(
        &self,
        previous: Option<&str>,
        messages: &[Message],
    ) -> Result<String, ChainError> {
        tokio::time::sleep(Duration::from_millis(2)).await;
        let mut parts: Vec<String> = previous.into_iter().map(str::to_owned).collect();
        parts.extend(messages.iter().map(|m| m.content.text_content()));
        Ok(parts.join(","))
    }
}

#[tokio::test]
async fn simple_memory_meets_contract() {
    check_memory(&SimpleMemory::new()).await.unwrap();
}

#[tokio::test]
async fn windowed_memory_meets_contract_for_any_window() {
    for window in [0, 1, 2, 3, 10] {
        check_memory(&WindowedMemory::new(window)).await.unwrap();
    }
}

#[tokio::test]
async fn new_memories_meet_contract() {
    check_memory(&SimpleMemory::with_max_messages(2))
        .await
        .unwrap();
    check_memory(&WindowedMemory::new(5).pin_system(true))
        .await
        .unwrap();
    check_memory(&TokenBufferMemory::with_char_estimate(1_000))
        .await
        .unwrap();
    check_memory(&TokenBufferMemory::with_char_estimate(0).pin_system(false))
        .await
        .unwrap();
    check_memory(&SummaryBufferMemory::new(SlowJoin, 1_000))
        .await
        .unwrap();
}

#[tokio::test]
async fn memory_works_behind_a_trait_object() {
    let memories: Vec<Arc<dyn Memory>> = vec![
        Arc::new(SimpleMemory::new()),
        Arc::new(WindowedMemory::new(2)),
        Arc::new(TokenBufferMemory::with_char_estimate(100)),
        Arc::new(SummaryBufferMemory::new(SlowJoin, 100)),
    ];
    for m in memories {
        check_memory(m.as_ref()).await.unwrap();
    }
}

#[tokio::test]
async fn concurrent_adds_are_all_kept() {
    let memory = Arc::new(SimpleMemory::new());
    let tasks: Vec<_> = (0..32)
        .map(|i| {
            let m = Arc::clone(&memory);
            tokio::spawn(async move { m.add(Message::human(i.to_string())).await })
        })
        .collect();
    for t in tasks {
        t.await.unwrap().unwrap();
    }
    let mut seen: Vec<u32> = memory
        .messages()
        .await
        .unwrap()
        .iter()
        .map(|m| m.content.text_content().parse().unwrap())
        .collect();
    seen.sort_unstable();
    assert_eq!(seen, (0..32).collect::<Vec<_>>());
}

#[tokio::test]
async fn windowed_memory_keeps_the_newest_turns_after_many_adds() {
    let memory = WindowedMemory::new(3);
    for i in 0..1_000 {
        memory.add(Message::human(i.to_string())).await.unwrap();
    }
    let texts: Vec<String> = memory
        .messages()
        .await
        .unwrap()
        .iter()
        .map(|m| m.content.text_content())
        .collect();
    assert_eq!(texts, ["997", "998", "999"]);
    assert_eq!(memory.window(), 3);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_adds_with_summarization_lose_nothing() {
    let memory = Arc::new(
        SummaryBufferMemory::new(SlowJoin, 4)
            .with_counter(|_: &Message| 1)
            .summary_prefix(""),
    );
    let tasks: Vec<_> = (0..64)
        .map(|i| {
            let m = Arc::clone(&memory);
            tokio::spawn(async move { m.add(Message::human(i.to_string())).await })
        })
        .collect();
    for t in tasks {
        t.await.unwrap().unwrap();
    }
    // Drain any backlog left while another compaction was in flight.
    while memory.compact().await.unwrap() {}

    let summary = memory.summary().unwrap_or_default();
    let mut seen: Vec<u32> = summary
        .split(',')
        .filter(|s| !s.is_empty())
        .map(|s| s.parse().unwrap())
        .collect();
    let verbatim = memory.messages().await.unwrap();
    seen.extend(
        verbatim[usize::from(!summary.is_empty())..]
            .iter()
            .map(|m| m.content.text_content().parse::<u32>().unwrap()),
    );
    seen.sort_unstable();
    assert_eq!(seen, (0..64).collect::<Vec<_>>());
}

#[tokio::test]
async fn clear_during_compaction_discards_stale_summary() {
    let memory = Arc::new(SummaryBufferMemory::new(SlowJoin, 1).with_counter(|_: &Message| 1));
    memory.add(Message::human("a")).await.unwrap();
    let m = Arc::clone(&memory);
    let adder = tokio::spawn(async move { m.add(Message::human("b")).await });
    tokio::task::yield_now().await;
    memory.clear().await.unwrap();
    adder.await.unwrap().unwrap();
    // Either the compaction finished before the clear, or it was discarded:
    // in both cases nothing from before the clear survives.
    assert!(memory.summary().is_none());
    assert_eq!(memory.messages().await.unwrap(), [] as [Message; 0]);
}

#[tokio::test]
async fn cancelled_compaction_does_not_wedge_memory() {
    let memory = SummaryBufferMemory::new(SlowJoin, 1).with_counter(|_: &Message| 1);
    memory.add(Message::human("a")).await.unwrap();
    // Dropping the add future mid-summarize must release the compaction flag.
    let _ = tokio::time::timeout(Duration::from_micros(1), memory.add(Message::human("b"))).await;
    assert!(memory.compact().await.unwrap());
    assert!(memory.summary().is_some());
}
