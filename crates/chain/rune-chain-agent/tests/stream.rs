//! `FunctionCallingAgent::run_stream` against the scriptable `FakeLlm`:
//! fragmented and interleaved tool calls, limits, approval and errors.

#![allow(clippy::unwrap_used, clippy::panic, reason = "test assertions")]

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use futures::StreamExt;
use rune_chain_agent::{
    AgentLimits, AgentStreamEvent, FunctionAgentResult, FunctionCallingAgent, StopReason,
    ToolStatus,
};
use rune_chain_core::testing::{FakeLlm, FakeMethod, FakeReply};
use rune_chain_core::{
    ChainError, FinishReason, LlmError, Message, StreamEvent, TokenUsage, Tool, ToolCall, ToolError,
};
use serde_json::{Value, json};

/// Echoes the `text` argument, upper-cased.
struct Shout;

#[async_trait]
impl Tool for Shout {
    fn name(&self) -> &'static str {
        "shout"
    }
    fn description(&self) -> &'static str {
        "Upper-cases text."
    }
    fn schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": { "text": { "type": "string" } },
            "required": ["text"]
        })
    }
    async fn run(&self, input: &str) -> Result<String, ToolError> {
        let v: Value = serde_json::from_str(input).unwrap();
        Ok(v["text"].as_str().unwrap().to_uppercase())
    }
}

/// Must never run: no approver is set.
struct Gated;
#[async_trait]
impl Tool for Gated {
    fn name(&self) -> &'static str {
        "gated"
    }
    fn description(&self) -> &'static str {
        "Needs approval."
    }
    async fn run(&self, _: &str) -> Result<String, ToolError> {
        panic!("must not run without approval")
    }
}

/// Two parallel calls whose argument fragments interleave.
fn interleaved_calls() -> FakeReply {
    FakeReply::events([
        StreamEvent::text("Let me "),
        StreamEvent::text("shout. "),
        StreamEvent::tool_call_start(0, "c1", "shout"),
        StreamEvent::tool_call_start(1, "c2", "shout"),
        StreamEvent::tool_call_delta(1, r#"{"te"#),
        StreamEvent::tool_call_delta(0, r#"{"text""#),
        StreamEvent::tool_call_delta(1, r#"xt":"b"}"#),
        StreamEvent::tool_call_delta(0, r#":"a"}"#),
        StreamEvent::ToolCallEnd { index: 0 },
        StreamEvent::ToolCallEnd { index: 1 },
        StreamEvent::Usage(TokenUsage::new(10, 4)),
        StreamEvent::Finish(FinishReason::ToolCalls),
    ])
}

fn answer() -> FakeReply {
    FakeReply::text("A and B.").with_usage(TokenUsage::new(20, 3))
}

async fn collect(agent: &FunctionCallingAgent) -> (Vec<AgentStreamEvent>, Option<ChainError>) {
    let mut events = Vec::new();
    let mut stream = agent.run_stream(vec![Message::human("Shout a and b.")]);
    while let Some(item) = stream.next().await {
        match item {
            Ok(e) => events.push(e),
            Err(e) => return (events, Some(e)),
        }
    }
    (events, None)
}

fn done(events: &[AgentStreamEvent]) -> &FunctionAgentResult {
    match events.last() {
        Some(AgentStreamEvent::Done(r)) => r,
        other => panic!("last event is not Done: {other:?}"),
    }
}

fn text(events: &[AgentStreamEvent]) -> String {
    events
        .iter()
        .filter_map(|e| match e {
            AgentStreamEvent::TextDelta(t) => Some(t.as_str()),
            _ => None,
        })
        .collect()
}

#[tokio::test]
async fn streams_every_round_and_matches_the_blocking_run() {
    let llm = FakeLlm::with_replies([interleaved_calls(), answer()]).with_chunk_chars(3);
    let agent = FunctionCallingAgent::new(Arc::new(llm.clone())).tool(Shout);
    let (events, err) = collect(&agent).await;
    assert!(err.is_none(), "{err:?}");

    assert_eq!(text(&events), "Let me shout. A and B.");
    let started: Vec<(usize, &str)> = events
        .iter()
        .filter_map(|e| match e {
            AgentStreamEvent::ToolCallStarted {
                iteration, call_id, ..
            } => Some((*iteration, call_id.as_str())),
            _ => None,
        })
        .collect();
    assert_eq!(started, [(1, "c1"), (1, "c2")]);
    let outputs: Vec<&str> = events
        .iter()
        .filter_map(|e| match e {
            AgentStreamEvent::ToolResult { invocation, .. } => Some(invocation.output.as_str()),
            _ => None,
        })
        .collect();
    assert_eq!(outputs, ["A", "B"]);
    // Tool results come before the second round's text.
    let first_result = events
        .iter()
        .position(|e| matches!(e, AgentStreamEvent::ToolResult { .. }))
        .unwrap();
    let answer_text = events
        .iter()
        .position(|e| matches!(e, AgentStreamEvent::TextDelta(t) if t.starts_with('A')))
        .unwrap();
    assert!(first_result < answer_text);
    assert!(
        llm.requests()
            .iter()
            .all(|r| r.method == FakeMethod::StreamEvents && r.tool_names() == ["shout"])
    );
    // The second request carries the assembled calls and fenced results.
    let second = &llm.requests()[1].messages;
    assert_eq!(second[2].tool_calls[1].arguments, r#"{"text":"b"}"#);

    let streamed = done(&events);
    let blocking_llm = FakeLlm::with_replies([interleaved_calls(), answer()]);
    let blocking = FunctionCallingAgent::new(Arc::new(blocking_llm))
        .tool(Shout)
        .run("Shout a and b.")
        .await
        .unwrap();
    assert_eq!(streamed.output, blocking.output);
    assert_eq!(streamed.iterations, blocking.iterations);
    assert_eq!(streamed.tool_invocations, blocking.tool_invocations);
    assert_eq!(streamed.tokens, blocking.tokens);
    assert_eq!(streamed.tokens.as_ref().unwrap().total_tokens, 37);
    assert_eq!(streamed.stop_reason, StopReason::FinalAnswer);
}

#[tokio::test]
async fn iteration_limit_ends_with_done() {
    let llm = FakeLlm::with_replies([interleaved_calls(), interleaved_calls()]);
    let agent = FunctionCallingAgent::new(Arc::new(llm))
        .tool(Shout)
        .max_iterations(1);
    let (events, err) = collect(&agent).await;
    assert!(err.is_none());
    let result = done(&events);
    assert_eq!(result.stop_reason, StopReason::MaxIterations);
    assert_eq!(result.iterations, 1);
}

#[tokio::test]
async fn invalid_unknown_and_unapproved_calls_are_reported_not_run() {
    let llm = FakeLlm::with_replies([
        FakeReply::tool_calls([
            ToolCall::new("c1", "shout", r#"{"text": 5}"#),
            ToolCall::new("c2", "nope\u{1b}[31m", "{}"),
            ToolCall::new("c3", "gated", r#"{"input":"x"}"#),
        ]),
        FakeReply::text("ok"),
    ]);
    let agent = FunctionCallingAgent::new(Arc::new(llm))
        .tool(Shout)
        .tool_requiring_approval(Gated);
    let (events, err) = collect(&agent).await;
    assert!(err.is_none(), "{err:?}");
    let statuses: Vec<ToolStatus> = events
        .iter()
        .filter_map(|e| match e {
            AgentStreamEvent::ToolResult { invocation, .. } => Some(invocation.status),
            _ => None,
        })
        .collect();
    assert_eq!(
        statuses,
        [ToolStatus::Error, ToolStatus::Error, ToolStatus::Denied]
    );
    let names: Vec<&str> = events
        .iter()
        .filter_map(|e| match e {
            AgentStreamEvent::ToolCallStarted { name, .. } => Some(name.as_str()),
            _ => None,
        })
        .collect();
    assert!(!names[1].contains('\u{1b}'), "names are sanitised");
    assert_eq!(done(&events).output, "ok");
}

#[tokio::test]
async fn oversized_streamed_arguments_end_the_run_with_an_error() {
    let big = "x".repeat(rune_chain_core::MAX_TOOL_ARGUMENTS_BYTES + 1);
    let llm = FakeLlm::with_replies([FakeReply::result(
        rune_chain_core::GenerateResult::default()
            .with_tool_calls(vec![ToolCall::new("c1", "shout", big)]),
    )])
    .with_chunk_chars(64 * 1024);
    let agent = FunctionCallingAgent::new(Arc::new(llm)).tool(Shout);
    let (events, err) = collect(&agent).await;
    assert!(
        !events
            .iter()
            .any(|e| matches!(e, AgentStreamEvent::ToolResult { .. })),
        "nothing ran"
    );
    let err = err.unwrap();
    assert!(err.to_string().contains("limit"), "{err}");
    assert!(!err.to_string().contains("xxx"));
}

#[tokio::test]
async fn stream_errors_and_empty_replies_are_errors() {
    let llm = FakeLlm::with_replies([
        FakeReply::text("partial").with_stream_error(LlmError::request_failed("reset"))
    ]);
    let agent = FunctionCallingAgent::new(Arc::new(llm)).tool(Shout);
    let (events, err) = collect(&agent).await;
    assert_eq!(text(&events), "partial");
    assert!(matches!(err, Some(ChainError::LlmError(e)) if e.message().contains("reset")));

    let llm = FakeLlm::with_replies([FakeReply::text("  ")]);
    let agent = FunctionCallingAgent::new(Arc::new(llm)).tool(Shout);
    assert!(collect(&agent).await.1.is_some());

    let agent = FunctionCallingAgent::new(Arc::new(FakeLlm::new())).tool(Shout);
    let mut stream = agent.run_stream(Vec::new());
    assert!(stream.next().await.unwrap().is_err());
    assert!(stream.next().await.is_none());
}

#[tokio::test]
async fn wall_time_bounds_a_slow_model() {
    let llm = FakeLlm::with_replies([answer()]).with_latency(Duration::from_millis(500));
    let agent = FunctionCallingAgent::new(Arc::new(llm))
        .tool(Shout)
        .limits(AgentLimits::default().max_wall_time(Some(Duration::from_millis(20))));
    let (events, err) = collect(&agent).await;
    assert!(err.is_none());
    assert_eq!(done(&events).stop_reason, StopReason::WallTime);
}
