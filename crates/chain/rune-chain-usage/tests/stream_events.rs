//! `MeteredLlm::stream_events` forwards the inner model's events and records
//! each stream once, from its reported usage or an estimate.

#![allow(clippy::unwrap_used, reason = "test assertions")]

use futures::StreamExt;
use rune_chain_core::testing::{FakeLlm, FakeMethod, FakeReply};
use rune_chain_core::{
    Cost, FinishReason, FunctionDefinition, Llm, LlmError, Message, Pricing, StreamAccumulator,
    StreamEvent, TokenUsage, ToolChoice,
};
use rune_chain_usage::{Budget, MeteredLlm, UsageMeter};

fn tools() -> [FunctionDefinition; 1] {
    [FunctionDefinition::single_input(
        "search",
        "Search the web.",
    )]
}

fn tool_events() -> Vec<StreamEvent> {
    vec![
        StreamEvent::text("Looking. "),
        StreamEvent::tool_call_start(0, "c1", "search"),
        StreamEvent::tool_call_delta(0, r#"{"input":"#),
        StreamEvent::tool_call_delta(0, r#""rust"}"#),
        StreamEvent::ToolCallEnd { index: 0 },
        StreamEvent::Finish(FinishReason::ToolCalls),
        StreamEvent::Usage(TokenUsage::new(1, 1)),
        // A later report replaces an earlier one.
        StreamEvent::Usage(TokenUsage::new(120, 30)),
    ]
}

fn metered(fake: &FakeLlm, meter: &UsageMeter) -> MeteredLlm<FakeLlm> {
    MeteredLlm::new(
        fake.clone(),
        meter.clone(),
        "p",
        "m",
        Pricing::per_mtok(1_000_000, 1_000_000),
    )
}

#[test]
fn forwards_native_events_and_records_reported_usage() {
    let fake = FakeLlm::with_replies([FakeReply::events(tool_events())]);
    let meter = UsageMeter::unlimited();
    let llm = metered(&fake, &meter);
    let tools = tools();
    let events: Vec<StreamEvent> = tokio_test::block_on(async {
        let stream = llm
            .stream_events(
                &[Message::human("go")],
                Some(&tools),
                Some(ToolChoice::Auto),
            )
            .await
            .unwrap();
        // Nothing is recorded until the stream ends.
        assert_eq!(meter.totals().calls, 0);
        stream.map(Result::unwrap).collect().await
    });
    assert_eq!(events, tool_events());
    let req = fake.last_request().unwrap();
    assert_eq!(req.method, FakeMethod::StreamEvents);
    assert_eq!(req.tool_names(), ["search"]);

    let t = meter.totals();
    assert_eq!((t.calls, t.estimated_calls), (1, 0));
    assert_eq!((t.input_tokens, t.output_tokens), (120, 30));
    assert_eq!(t.cost, Cost::from_micros(150));
}

#[test]
fn without_reported_usage_the_stream_is_estimated() {
    let events = tool_events()
        .into_iter()
        .filter(|e| !matches!(e, StreamEvent::Usage(_)));
    let fake = FakeLlm::with_replies([FakeReply::events(events)]);
    let meter = UsageMeter::unlimited();
    let llm = metered(&fake, &meter);
    let tools = tools();
    let result = tokio_test::block_on(async {
        let s = llm
            .stream_events(&[Message::human("go")], Some(&tools), None)
            .await
            .unwrap();
        StreamAccumulator::new().collect(s).await.unwrap()
    });
    assert_eq!(result.tool_calls[0].name, "search");
    let t = meter.totals();
    assert_eq!((t.calls, t.estimated_calls), (1, 1));
    assert!(t.input_tokens > 0);
    // "Looking. " + "search" + the arguments: 31 chars, about 8 tokens.
    assert_eq!(t.output_tokens, 8);
}

#[test]
fn a_dropped_or_failed_stream_is_recorded_once() {
    let fake = FakeLlm::with_replies([
        FakeReply::events(tool_events()),
        FakeReply::events([StreamEvent::text("par")]).with_stream_error(LlmError::provider("x")),
    ]);
    let meter = UsageMeter::unlimited();
    let llm = metered(&fake, &meter);
    tokio_test::block_on(async {
        let mut s = llm.stream_events(&[], None, None).await.unwrap();
        let _first = s.next().await;
        drop(s);
        assert_eq!(meter.totals().calls, 1);

        let items: Vec<_> = llm
            .stream_events(&[], None, None)
            .await
            .unwrap()
            .collect()
            .await;
        assert!(items[1].is_err());
    });
    assert_eq!(meter.totals().calls, 2);
}

#[test]
fn budget_refuses_before_the_provider_is_called() {
    let fake = FakeLlm::with_replies([
        FakeReply::events(tool_events()),
        FakeReply::events(tool_events()),
    ]);
    // 150 µ$ per call; the cap is reached by the first stream.
    let meter = UsageMeter::new(Budget::default().with_max_cost(Cost::from_micros(100)));
    let llm = metered(&fake, &meter);
    let tools = tools();
    tokio_test::block_on(async {
        let s = llm
            .stream_events(&[Message::human("go")], Some(&tools), None)
            .await
            .unwrap();
        // A call that reaches the cap still returns its result.
        assert_eq!(s.count().await, tool_events().len());
        let err = llm
            .stream_events(&[Message::human("go")], Some(&tools), None)
            .await
            .err()
            .unwrap();
        assert!(err.to_string().contains("budget"), "{err}");
    });
    assert_eq!(fake.call_count(), 1);
    assert_eq!(meter.totals().calls, 1);
}

#[test]
fn preflight_counts_tool_definitions() {
    let fake = FakeLlm::new();
    // Room for the prompt alone, not for the prompt plus the tool schema.
    let meter = UsageMeter::new(Budget::default().with_max_tokens(12));
    let llm = metered(&fake, &meter).expected_output_tokens(0);
    let tools = tools();
    let msgs = [Message::human("go")];
    let err = tokio_test::block_on(llm.stream_events(&msgs, Some(&tools), None))
        .err()
        .unwrap();
    assert!(err.to_string().contains("budget"), "{err}");
    assert_eq!(fake.call_count(), 0);
    // Without the tools the same prompt gets through.
    let _ = tokio_test::block_on(llm.stream_events(&msgs, None, None));
    assert_eq!(fake.call_count(), 1);
}
