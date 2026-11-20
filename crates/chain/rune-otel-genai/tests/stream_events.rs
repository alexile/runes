//! `TracedLlm::stream_events`: the span stays open until the stream ends
//! and records usage, the finish reason and tool-call names, but no content
//! unless capture is on.

#![allow(clippy::unwrap_used, clippy::panic, reason = "test helpers")]

use futures::StreamExt;
use opentelemetry::trace::{Status, TracerProvider as _};
use opentelemetry_sdk::trace::{InMemorySpanExporter, SdkTracerProvider, SpanData};
use rune_chain_core::testing::{FakeLlm, FakeMethod, FakeReply};
use rune_chain_core::{
    FinishReason, FunctionDefinition, Llm, LlmError, Message, Pricing, StreamEvent, TokenUsage,
    ToolChoice,
};
use rune_otel_genai::{ContentPolicy, GenAiConfig, TracedLlm, attr};
use tracing_subscriber::layer::SubscriberExt;

const SECRET: &str = "s3cret-arg";

fn tool_events() -> Vec<StreamEvent> {
    vec![
        StreamEvent::text("Looking it up. "),
        StreamEvent::tool_call_start(0, "c1", "search"),
        StreamEvent::tool_call_delta(0, r#"{"input":""#),
        StreamEvent::tool_call_delta(0, SECRET),
        StreamEvent::tool_call_delta(0, r#""}"#),
        StreamEvent::ToolCallEnd { index: 0 },
        StreamEvent::Finish(FinishReason::ToolCalls),
        StreamEvent::Usage(TokenUsage::new(40, 12)),
    ]
}

fn tools() -> [FunctionDefinition; 1] {
    [FunctionDefinition::single_input(
        "search",
        "Search the web.",
    )]
}

fn get(span: &SpanData, key: &str) -> Option<String> {
    span.attributes
        .iter()
        .find(|kv| kv.key.as_str() == key)
        .map(|kv| kv.value.as_str().into_owned())
}

/// Runs `scenario` under an OpenTelemetry layer. The scenario gets a probe
/// that returns the spans finished so far.
fn run_and_export<F: std::future::Future<Output = ()>>(
    scenario: impl FnOnce(Box<dyn Fn() -> usize>) -> F,
) -> Vec<SpanData> {
    let exporter = InMemorySpanExporter::default();
    let provider = SdkTracerProvider::builder()
        .with_simple_exporter(exporter.clone())
        .build();
    let subscriber = tracing_subscriber::registry()
        .with(tracing_opentelemetry::layer().with_tracer(provider.tracer("test")));
    let probe = exporter.clone();
    let finished = Box::new(move || probe.get_finished_spans().unwrap().len());
    tracing::subscriber::with_default(subscriber, || tokio_test::block_on(scenario(finished)));
    provider.force_flush().unwrap();
    let spans = exporter.get_finished_spans().unwrap();
    provider.shutdown().unwrap();
    spans
}

fn chat(spans: &[SpanData]) -> &SpanData {
    spans
        .iter()
        .find(|s| s.name == "chat fake")
        .unwrap_or_else(|| panic!("no chat span"))
}

/// Everything recorded on a span, as one string.
fn dump(span: &SpanData) -> String {
    format!("{:?} {:?} {:?}", span.attributes, span.events, span.status)
}

#[test]
fn forwards_events_and_records_usage_finish_and_tool_names() {
    let fake = FakeLlm::with_replies([FakeReply::events(tool_events())]);
    let llm = TracedLlm::new(
        fake.clone(),
        GenAiConfig::new("acme", "fake").with_pricing(Pricing::per_mtok(1_000_000, 1_000_000)),
    );
    let tools = tools();
    let spans = run_and_export(|finished| async move {
        let mut stream = llm
            .stream_events(
                &[Message::human("go")],
                Some(&tools),
                Some(ToolChoice::Auto),
            )
            .await
            .unwrap();
        let first = stream.next().await.unwrap().unwrap();
        assert_eq!(first, StreamEvent::text("Looking it up. "));
        // The span is still open mid-stream.
        assert_eq!(finished(), 0);
        let rest: Vec<_> = stream.collect().await;
        assert_eq!(rest.len(), tool_events().len() - 1);
        assert!(rest.iter().all(Result::is_ok));
        // Ending the stream closed it.
        assert_eq!(finished(), 1);
    });
    assert_eq!(
        fake.last_request().unwrap().method,
        FakeMethod::StreamEvents
    );

    let chat = chat(&spans);
    assert_eq!(
        get(chat, attr::GEN_AI_USAGE_INPUT_TOKENS).as_deref(),
        Some("40")
    );
    assert_eq!(
        get(chat, attr::GEN_AI_USAGE_OUTPUT_TOKENS).as_deref(),
        Some("12")
    );
    assert_eq!(
        get(chat, attr::RUNE_USAGE_ESTIMATED).as_deref(),
        Some("false")
    );
    assert!(get(chat, attr::RUNE_USAGE_COST_USD).is_some());
    assert_eq!(
        get(chat, attr::GEN_AI_RESPONSE_FINISH_REASONS).as_deref(),
        Some("tool_call")
    );
    assert_eq!(
        get(chat, attr::RUNE_RESPONSE_TOOL_CALLS).as_deref(),
        Some("1")
    );
    assert_eq!(chat.events.len(), 1);
    let event = &chat.events[0];
    assert_eq!(event.name, attr::EVENT_TOOL_CALL);
    let name = event
        .attributes
        .iter()
        .find(|kv| kv.key.as_str() == attr::GEN_AI_TOOL_NAME)
        .unwrap();
    assert_eq!(name.value.as_str(), "search");

    // Capture is off: no messages, arguments or text anywhere.
    assert!(get(chat, attr::GEN_AI_OUTPUT_MESSAGES).is_none());
    assert!(get(chat, attr::GEN_AI_INPUT_MESSAGES).is_none());
    let all = dump(chat);
    assert!(!all.contains(SECRET), "{all}");
    assert!(!all.contains("Looking"), "{all}");
}

#[test]
fn content_capture_records_text_and_arguments_capped() {
    let fake = FakeLlm::with_replies([FakeReply::events(tool_events())]);
    let llm = TracedLlm::new(
        fake,
        GenAiConfig::new("acme", "fake")
            .with_content_policy(ContentPolicy::capture().with_max_chars(12)),
    );
    let spans = run_and_export(|_| async move {
        let n = llm
            .stream_events(&[], None, None)
            .await
            .unwrap()
            .count()
            .await;
        assert_eq!(n, tool_events().len());
    });
    let output: serde_json::Value =
        serde_json::from_str(&get(chat(&spans), attr::GEN_AI_OUTPUT_MESSAGES).unwrap()).unwrap();
    let parts = &output[0]["parts"];
    assert_eq!(parts[0]["content"], "Looking it u…[truncated]");
    assert_eq!(parts[1]["type"], "tool_call");
    assert_eq!(parts[1]["name"], "search");
    assert_eq!(parts[1]["arguments"], r#"{"input":"s3…[truncated]"#);
    assert_eq!(output[0]["finish_reason"], "tool_call");
}

#[test]
fn streams_without_usage_are_estimated() {
    let events = tool_events()
        .into_iter()
        .filter(|e| !matches!(e, StreamEvent::Usage(_)));
    let llm = TracedLlm::new(
        FakeLlm::with_replies([FakeReply::events(events)]),
        GenAiConfig::new("acme", "fake"),
    );
    let spans = run_and_export(|_| async move {
        let mut s = llm.stream_events(&[], None, None).await.unwrap();
        // Dropped after one event: still recorded.
        s.next().await.unwrap().unwrap();
    });
    let chat = chat(&spans);
    assert_eq!(
        get(chat, attr::RUNE_USAGE_ESTIMATED).as_deref(),
        Some("true")
    );
    // Only "Looking it up. " (15 chars) was read: about 4 tokens.
    assert_eq!(
        get(chat, attr::GEN_AI_USAGE_OUTPUT_TOKENS).as_deref(),
        Some("4")
    );
    assert_eq!(
        get(chat, attr::RUNE_RESPONSE_TOOL_CALLS).as_deref(),
        Some("0")
    );
}

#[test]
fn errors_open_and_mid_stream_mark_the_span() {
    let llm = TracedLlm::new(
        FakeLlm::with_replies([
            FakeReply::rate_limited(),
            FakeReply::events([StreamEvent::text("par")])
                .with_stream_error(LlmError::provider("Overloaded")),
        ]),
        GenAiConfig::new("acme", "fake"),
    );
    let spans = run_and_export(|_| async move {
        assert!(llm.stream_events(&[], None, None).await.is_err());
        let items: Vec<_> = llm
            .stream_events(&[], None, None)
            .await
            .unwrap()
            .collect()
            .await;
        assert!(items[1].is_err());
    });
    assert_eq!(spans.len(), 2);
    assert_eq!(
        get(&spans[0], attr::ERROR_TYPE).as_deref(),
        Some("rate_limit")
    );
    assert_eq!(
        get(&spans[0], attr::HTTP_RESPONSE_STATUS_CODE).as_deref(),
        Some("429")
    );
    assert_eq!(
        get(&spans[1], attr::ERROR_TYPE).as_deref(),
        Some("provider_error")
    );
    assert!(matches!(spans[1].status, Status::Error { .. }));
}
