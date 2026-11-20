//! `stream_events` through `RetryLlm` and `Router`: native events are
//! forwarded, and retries or fallbacks happen only before the first event.

#![allow(clippy::unwrap_used, reason = "test assertions")]

use std::sync::Arc;

use futures::StreamExt;
use rune_chain_core::testing::{FakeLlm, FakeMethod, FakeReply};
use rune_chain_core::{
    FinishReason, FunctionDefinition, Llm, LlmError, LlmErrorKind, Message, StreamAccumulator,
    StreamEvent, ToolChoice,
};
use rune_chain_retry::{BreakerConfig, BreakerState, Provider, RetryLlm, Router};

fn tools() -> [FunctionDefinition; 1] {
    [FunctionDefinition::single_input(
        "search",
        "Search the web.",
    )]
}

fn tool_events() -> Vec<StreamEvent> {
    vec![
        StreamEvent::tool_call_start(0, "c1", "search"),
        StreamEvent::tool_call_delta(0, r#"{"input":"#),
        StreamEvent::tool_call_delta(0, r#""rust"}"#),
        StreamEvent::ToolCallEnd { index: 0 },
        StreamEvent::Finish(FinishReason::ToolCalls),
    ]
}

fn overloaded() -> LlmError {
    LlmError::provider("Overloaded")
}

async fn collect(llm: &dyn Llm) -> Vec<Result<StreamEvent, LlmError>> {
    let tools = tools();
    llm.stream_events(
        &[Message::human("go")],
        Some(&tools),
        Some(ToolChoice::Auto),
    )
    .await
    .unwrap()
    .collect()
    .await
}

#[tokio::test]
async fn retry_forwards_native_events() {
    let fake = FakeLlm::with_replies([FakeReply::events(tool_events())]);
    let llm = RetryLlm::new(fake.clone()).initial_delay_ms(0);
    let items = collect(&llm).await;
    let events: Vec<StreamEvent> = items.into_iter().map(Result::unwrap).collect();
    assert_eq!(events, tool_events());
    let req = fake.last_request().unwrap();
    assert_eq!(req.method, FakeMethod::StreamEvents);
    assert_eq!(req.tool_names(), ["search"]);
    assert_eq!(req.tool_choice, Some(ToolChoice::Auto));
}

#[tokio::test]
async fn retry_reopens_until_the_first_event() {
    let fake = FakeLlm::with_replies([
        FakeReply::rate_limited(),
        FakeReply::events([]).with_stream_error(overloaded()),
        FakeReply::events(tool_events()),
    ]);
    let llm = RetryLlm::new(fake.clone())
        .max_retries(3)
        .initial_delay_ms(0);
    let mut acc = StreamAccumulator::new();
    for item in collect(&llm).await {
        acc.push(&item.unwrap()).unwrap();
    }
    assert_eq!(acc.finish().tool_calls[0].arguments, r#"{"input":"rust"}"#);
    assert_eq!(fake.call_count(), 3);
}

#[tokio::test]
async fn retry_never_restarts_after_an_event() {
    let fake = FakeLlm::with_replies([
        FakeReply::events([StreamEvent::text("par")]).with_stream_error(overloaded()),
        FakeReply::text("never used"),
    ]);
    let llm = RetryLlm::new(fake.clone())
        .max_retries(3)
        .initial_delay_ms(0);
    let items = collect(&llm).await;
    assert_eq!(items.len(), 2);
    assert_eq!(items[0].as_ref().unwrap(), &StreamEvent::text("par"));
    assert!(items[1].is_err());
    assert_eq!(fake.call_count(), 1);
}

#[tokio::test]
async fn retry_gives_up_on_permanent_errors() {
    let fake = FakeLlm::with_replies([FakeReply::error(LlmError::from_status(401, "bad key"))]);
    let llm = RetryLlm::new(fake.clone()).initial_delay_ms(0);
    let err = llm
        .stream_events(&[Message::human("go")], None, None)
        .await
        .err()
        .unwrap();
    assert_eq!(err.kind(), LlmErrorKind::Auth);
    assert_eq!(fake.call_count(), 1);
}

#[tokio::test]
async fn router_falls_back_only_before_the_first_event() {
    let a = FakeLlm::with_replies([FakeReply::events([]).with_stream_error(overloaded())]);
    let b = FakeLlm::with_replies([
        FakeReply::events([StreamEvent::text("b")]).with_stream_error(overloaded())
    ]);
    let c = FakeLlm::new();
    let router = Router::default()
        .provider(Provider::new("a", a.clone()))
        .provider(Provider::new("b", b.clone()))
        .provider(Provider::new("c", c.clone()));
    let items = collect(&router).await;
    // "b" won; its mid-stream error is passed through, "c" is never spliced in.
    assert_eq!(items.len(), 2);
    assert_eq!(items[0].as_ref().unwrap(), &StreamEvent::text("b"));
    assert!(items[1].is_err());
    assert_eq!((a.call_count(), b.call_count(), c.call_count()), (1, 1, 0));
    assert_eq!(b.last_request().unwrap().method, FakeMethod::StreamEvents);
}

#[tokio::test]
async fn router_breaker_counts_stream_open_failures() {
    let down = FakeLlm::with_replies([FakeReply::error(overloaded())]);
    let up = FakeLlm::with_replies([
        FakeReply::events(tool_events()),
        FakeReply::events(tool_events()),
    ]);
    let router = Router::default()
        .provider(Provider::new("down", down.clone()))
        .provider(Provider::new("up", up))
        .breaker(BreakerConfig::default().with_failure_threshold(1));
    for _ in 0..2 {
        let items = collect(&router).await;
        assert!(items.iter().all(Result::is_ok));
        assert_eq!(items.len(), tool_events().len());
    }
    assert_eq!(router.breaker_state("down"), Some(BreakerState::Open));
    assert_eq!(down.call_count(), 1);
    assert_eq!(router.breaker_state("up"), Some(BreakerState::Closed));
}

#[tokio::test]
async fn shared_router_forwards_through_arc() {
    let fake = FakeLlm::with_replies([FakeReply::events(tool_events())]);
    let shared: Arc<dyn Llm> = Arc::new(RetryLlm::new(fake.clone()));
    let router = Router::default().provider(Provider::from_arc("s", shared));
    assert_eq!(collect(&router).await.len(), tool_events().len());
    assert_eq!(
        fake.last_request().unwrap().method,
        FakeMethod::StreamEvents
    );
}
