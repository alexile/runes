//! `MeteredLlm` passes the shared `Llm` contract on every entry point and
//! records each call exactly once.

#![allow(clippy::unwrap_used, reason = "test assertions")]

use std::pin::Pin;

use async_trait::async_trait;
use futures::{Stream, stream};
use rune_chain_core::testing::check_llm;
use rune_chain_core::{
    FunctionDefinition, GenerateResult, Llm, LlmError, Message, Pricing, StreamData, TokenUsage,
    ToolChoice,
};
use std::sync::atomic::{AtomicU32, Ordering};

use rune_chain_core::Cost;
use rune_chain_usage::{Budget, MeteredLlm, UsageMeter};

type BoxStream = Pin<Box<dyn Stream<Item = Result<StreamData, LlmError>> + Send>>;

struct Full;

#[async_trait]
impl Llm for Full {
    async fn generate(&self, _: &[Message]) -> Result<GenerateResult, LlmError> {
        let mut r = GenerateResult::from_text("pong");
        r.tokens = Some(TokenUsage::new(10, 2).with_total_tokens(12));
        Ok(r)
    }

    async fn generate_with_tools(
        &self,
        _: &[Message],
        _: &[FunctionDefinition],
        _: Option<ToolChoice>,
    ) -> Result<GenerateResult, LlmError> {
        Ok(GenerateResult::from_text("no call needed"))
    }

    async fn stream(&self, _: &[Message]) -> Result<BoxStream, LlmError> {
        Ok(Box::pin(stream::iter([
            Ok(StreamData::chunk("po")),
            Ok(StreamData::chunk("ng")),
            Ok(StreamData::done()),
        ])))
    }
}

/// Implements only `generate`, without usage.
struct Minimal;

#[async_trait]
impl Llm for Minimal {
    async fn generate(&self, _: &[Message]) -> Result<GenerateResult, LlmError> {
        Ok(GenerateResult::from_text("pong"))
    }
}

#[test]
fn full_llm_meets_the_contract_and_every_call_is_metered() {
    let meter = UsageMeter::unlimited();
    let llm = MeteredLlm::new(Full, meter.clone(), "p", "m", Pricing::per_mtok(1, 1));
    tokio_test::block_on(check_llm(&llm)).unwrap();
    // generate ×2, generate_with_tools, stream.
    let t = meter.totals();
    assert_eq!(t.calls, 4);
    assert_eq!(
        t.estimated_calls, 2,
        "tools reply and stream report no usage"
    );
}

#[test]
fn minimal_llm_meets_the_contract() {
    let meter = UsageMeter::unlimited();
    let llm = MeteredLlm::new(Minimal, meter.clone(), "p", "m", Pricing::default());
    tokio_test::block_on(check_llm(&llm)).unwrap();
    // Unsupported tools/stream calls fail before reaching the provider and are not billed.
    assert_eq!(meter.totals().calls, 2);
    assert_eq!(
        tokio_test::block_on(llm.inner().generate(&[]))
            .unwrap()
            .generation,
        "pong"
    );
    assert_eq!(llm.meter().totals().calls, 2);
}

/// Counts how often the provider is actually reached.
struct Counting(AtomicU32);

#[async_trait]
impl Llm for Counting {
    async fn generate(&self, _: &[Message]) -> Result<GenerateResult, LlmError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(GenerateResult::from_text("ok").with_tokens(TokenUsage::new(100, 50)))
    }
}

#[test]
fn hard_stop_refuses_before_the_provider_is_called() {
    // $1 in / $1 out per MTok, cap 1000 µ$.
    let meter = UsageMeter::new(Budget::default().with_max_cost(Cost::from_micros(1_000)));
    let llm = MeteredLlm::new(
        Counting(AtomicU32::new(0)),
        meter.clone(),
        "p",
        "m",
        Pricing::per_mtok(1_000_000, 1_000_000),
    )
    .with_tag("search")
    .expected_output_tokens(2_000);
    // Estimated: ~10 prompt tokens + 2000 output = ~2010 µ$ > cap.
    let err = tokio_test::block_on(llm.generate(&[Message::human("hi")])).unwrap_err();
    assert!(
        err.to_string().contains("budget would be exceeded"),
        "{err}"
    );
    assert_eq!(llm.inner().0.load(Ordering::SeqCst), 0);
    assert_eq!(meter.totals().calls, 0);

    // With room in the budget, the call goes through and is tagged.
    let llm = llm.expected_output_tokens(100);
    tokio_test::block_on(llm.generate(&[Message::human("hi")])).unwrap();
    assert_eq!(llm.inner().0.load(Ordering::SeqCst), 1);
    let tags = meter.by_tag();
    assert_eq!(tags[0].0, "search");
    assert_eq!(tags[0].1.cost, Cost::from_micros(150));
}

/// Yields once before answering, so concurrent calls are all in flight at
/// the same time.
struct Slow(AtomicU32);

#[async_trait]
impl Llm for Slow {
    async fn generate(&self, _: &[Message]) -> Result<GenerateResult, LlmError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        let mut yielded = false;
        futures::future::poll_fn(|cx| {
            if yielded {
                std::task::Poll::Ready(())
            } else {
                yielded = true;
                cx.waker().wake_by_ref();
                std::task::Poll::Pending
            }
        })
        .await;
        Ok(GenerateResult::from_text("ok").with_tokens(TokenUsage::new(10, 140)))
    }
}

#[test]
fn concurrent_calls_cannot_all_pass_the_same_preflight() {
    // Each call projects ~150 tokens; the cap leaves room for two of them.
    let meter = UsageMeter::new(Budget::default().with_max_tokens(400));
    let llm = MeteredLlm::new(
        Slow(AtomicU32::new(0)),
        meter.clone(),
        "p",
        "m",
        Pricing::per_mtok(1, 1),
    )
    .expected_output_tokens(140);
    let messages = [Message::human("hi")];
    let calls = (0..5).map(|_| llm.generate(&messages));
    let results = tokio_test::block_on(futures::future::join_all(calls));
    assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 2);
    assert_eq!(llm.inner().0.load(Ordering::SeqCst), 2);
    assert_eq!(meter.totals().total_tokens(), 300);
    // Finished calls hand their reservations back.
    meter.check(Cost::ZERO, 100).unwrap();
}
