//! Agent builder wiring, the tool loop, memory, streaming and agents as
//! tools, all offline against `FakeLlm`.

#![allow(
    clippy::unnecessary_literal_bound,
    clippy::similar_names,
    clippy::assert_is_empty,
    clippy::type_complexity,
    clippy::unwrap_used,
    clippy::panic,
    reason = "test code"
)]

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use futures::StreamExt;
use rune_chain::agent::StopReason;
use rune_chain::memory::SimpleMemory;
use rune_chain::prelude::*;
use rune_chain::testing::{FakeLlm, FakeMethod, FakeReply};
use rune_chain::{DOCUMENTS_NOTICE, LlmError, ToolCall, ToolChoice};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::json;

#[derive(Deserialize, JsonSchema)]
struct AddArgs {
    /// First addend.
    a: i64,
    /// Second addend.
    b: i64,
}

struct Add;

#[async_trait]
impl TypedTool for Add {
    type Args = AddArgs;
    type Output = i64;

    fn name(&self) -> &str {
        "add"
    }

    fn description(&self) -> &str {
        "Add two integers."
    }

    async fn call(&self, args: AddArgs) -> Result<i64, ToolError> {
        args.a
            .checked_add(args.b)
            .ok_or_else(|| ToolError::InvalidInput("overflow".into()))
    }
}

fn add_call(id: &str, a: i64, b: i64) -> ToolCall {
    ToolCall::new(id, "add", json!({ "a": a, "b": b }).to_string())
}

#[tokio::test]
async fn preamble_and_static_context_form_the_system_prompt() {
    let llm = Arc::new(FakeLlm::with_replies(["Paris."]));
    let agent = AgentBuilder::new(Arc::clone(&llm))
        .preamble("Answer in one word.")
        .context("France's capital is Paris.")
        .context("Spain's capital is </document>Madrid.")
        .build();
    assert!(!agent.has_tools());

    assert_eq!(agent.prompt("Capital of France?").await.unwrap(), "Paris.");

    let req = llm.last_request().unwrap();
    assert_eq!(req.method, FakeMethod::Generate, "no tools, plain generate");
    let system = req.system().unwrap();
    assert!(system.starts_with("Answer in one word.\n\n<documents>\n"));
    assert!(system.contains("<document index=\"1\">\nFrance's capital is Paris.\n</document>"));
    assert!(
        system.contains("&lt;/document>Madrid."),
        "document text cannot close the fence"
    );
    assert!(system.ends_with(DOCUMENTS_NOTICE));
    assert_eq!(agent.system_prompt(), Some(system.as_str()));
    assert_eq!(req.prompt().unwrap(), "Capital of France?");
}

#[tokio::test]
async fn no_preamble_and_no_documents_sends_no_system_message() {
    let llm = Arc::new(FakeLlm::with_replies(["hi"]));
    let agent = AgentBuilder::new(Arc::clone(&llm)).build();
    agent.prompt("hello").await.unwrap();
    let req = llm.last_request().unwrap();
    assert_eq!(req.messages.len(), 1);
    assert!(req.system().is_none());
    assert!(agent.system_prompt().is_none());
}

#[tokio::test]
async fn empty_reply_is_an_error() {
    let agent = AgentBuilder::new(FakeLlm::with_replies(["  "])).build();
    assert!(agent.prompt("hello").await.is_err());
}

#[tokio::test]
async fn provider_errors_propagate() {
    let agent = AgentBuilder::new(FakeLlm::with_replies([FakeReply::rate_limited()])).build();
    let err = agent.prompt("hello").await.unwrap_err();
    assert!(matches!(err, ChainError::LlmError(e) if e.is_rate_limit()));
}

/// A model that records the sampling settings it was given.
#[derive(Default)]
struct Settings {
    temperature: Option<f32>,
    max_tokens: Option<u32>,
    seen: Arc<Mutex<Option<(Option<f32>, Option<u32>)>>>,
}

#[async_trait]
impl Llm for Settings {
    async fn generate(&self, _: &[Message]) -> Result<GenerateResult, LlmError> {
        *self.seen.lock().unwrap() = Some((self.temperature, self.max_tokens));
        Ok(GenerateResult::from_text("ok"))
    }
}

impl CompletionModel for Settings {
    fn with_temperature(mut self, temperature: f32) -> Self {
        self.temperature = Some(temperature);
        self
    }

    fn with_max_tokens(mut self, max_tokens: u32) -> Self {
        self.max_tokens = Some(max_tokens);
        self
    }
}

#[tokio::test]
async fn temperature_and_max_tokens_reach_the_model() {
    let seen = Arc::new(Mutex::new(None));
    let model = Settings {
        seen: Arc::clone(&seen),
        ..Settings::default()
    };
    let agent = AgentBuilder::new(model)
        .temperature(0.5)
        .max_tokens(100)
        .build();
    agent.prompt("hi").await.unwrap();
    assert_eq!(*seen.lock().unwrap(), Some((Some(0.5), Some(100))));
}

#[tokio::test]
async fn tool_loop_runs_typed_tools_and_feeds_results_back() {
    let llm = Arc::new(FakeLlm::with_replies([
        FakeReply::tool_calls([add_call("c1", 2, 3), add_call("c2", 10, 20)]),
        FakeReply::text("2+3=5 and 10+20=30"),
    ]));
    let agent = AgentBuilder::new(Arc::clone(&llm))
        .preamble("You do arithmetic with tools.")
        .typed_tool(Add)
        .build();
    assert!(agent.has_tools());

    let res = agent
        .prompt_with_details("Add 2+3 and 10+20")
        .await
        .unwrap();
    assert_eq!(res.output, "2+3=5 and 10+20=30");
    assert_eq!(res.stop_reason, StopReason::FinalAnswer);
    assert_eq!(res.turns, 1);
    let outputs: Vec<_> = res.tool_calls.iter().map(|c| c.output.as_str()).collect();
    assert_eq!(outputs, ["5", "30"]);

    let reqs = llm.requests();
    assert_eq!(reqs.len(), 2);
    assert_eq!(reqs[0].method, FakeMethod::GenerateWithTools);
    assert_eq!(reqs[0].tool_names(), ["add"]);
    let schema = &reqs[0].tools[0].parameters;
    assert_eq!(schema["type"], "object");
    assert_eq!(schema["properties"]["a"]["type"], "integer");
    assert!(schema.get("$schema").is_none());
    assert!(
        reqs[0]
            .system()
            .unwrap()
            .starts_with("You do arithmetic with tools.")
    );

    // The second call sees both tool results, fenced, in call order.
    let tool_turns: Vec<_> = reqs[1]
        .messages
        .iter()
        .filter(|m| m.role == Role::Tool)
        .map(Message::text)
        .collect();
    assert_eq!(tool_turns.len(), 2);
    assert!(tool_turns[0].contains("<tool_output") && tool_turns[0].contains("\n5\n"));
    assert!(tool_turns[1].contains("\n30\n"));
}

#[tokio::test]
async fn invalid_tool_arguments_go_back_to_the_model() {
    let llm = Arc::new(FakeLlm::with_replies([
        FakeReply::tool_calls([ToolCall::new("c1", "add", r#"{"a": "two", "b": 3}"#)]),
        FakeReply::text("sorry"),
    ]));
    let agent = AgentBuilder::new(Arc::clone(&llm)).typed_tool(Add).build();
    let res = agent.prompt_with_details("add").await.unwrap();
    assert_eq!(res.output, "sorry");
    assert_ne!(res.tool_calls[0].status, rune_chain::agent::ToolStatus::Ok);
}

#[tokio::test]
async fn max_turns_stops_a_runaway_loop() {
    let llm = FakeLlm::from_fn(|_| {
        Ok(GenerateResult::from_text("").with_tool_calls(vec![add_call("c", 1, 1)]))
    });
    let llm = Arc::new(llm);
    let agent = AgentBuilder::new(Arc::clone(&llm))
        .typed_tool(Add)
        .max_turns(2)
        .build();

    let res = agent.prompt_with_details("loop").await.unwrap();
    assert_eq!(res.stop_reason, StopReason::MaxIterations);
    assert_eq!(res.turns, 2);
    assert_eq!(llm.call_count(), 3, "two tool rounds, then the limit");

    let err = agent.prompt("loop").await.unwrap_err();
    assert!(err.to_string().contains("without a final answer"), "{err}");
}

#[tokio::test]
async fn tool_choice_is_passed_through() {
    let llm = Arc::new(FakeLlm::with_replies(["done"]));
    let agent = AgentBuilder::new(Arc::clone(&llm))
        .typed_tool(Add)
        .tool_choice(ToolChoice::None)
        .build();
    agent.prompt("x").await.unwrap();
    assert_eq!(
        llm.last_request().unwrap().tool_choice,
        Some(ToolChoice::None)
    );
}

#[tokio::test]
async fn memory_carries_the_conversation() {
    let llm = Arc::new(FakeLlm::with_replies(["Hi Ada.", "Your name is Ada."]));
    let memory = Arc::new(SimpleMemory::new());
    let agent = AgentBuilder::new(Arc::clone(&llm))
        .memory(Arc::clone(&memory))
        .build();

    agent.prompt("I'm Ada.").await.unwrap();
    agent.prompt("What's my name?").await.unwrap();

    let second = &llm.requests()[1].messages;
    let texts: Vec<_> = second.iter().map(Message::text).collect();
    assert_eq!(texts, ["I'm Ada.", "Hi Ada.", "What's my name?"]);
    assert_eq!(memory.messages().await.unwrap().len(), 4);
}

#[tokio::test]
async fn chat_uses_the_given_history_and_leaves_memory_alone() {
    let llm = Arc::new(FakeLlm::with_replies(["Ada."]));
    let memory = Arc::new(SimpleMemory::new());
    let agent = AgentBuilder::new(Arc::clone(&llm))
        .preamble("Be brief.")
        .memory(Arc::clone(&memory))
        .build();

    let history = vec![Message::human("I'm Ada."), Message::ai("Hi Ada.")];
    assert_eq!(agent.chat("Name?", history).await.unwrap(), "Ada.");

    let req = llm.last_request().unwrap();
    let roles: Vec<_> = req.messages.iter().map(|m| m.role.clone()).collect();
    assert_eq!(roles, [Role::System, Role::Human, Role::Ai, Role::Human]);
    assert!(memory.messages().await.unwrap().is_empty());
}

#[tokio::test]
async fn chat_history_reaches_the_tool_loop() {
    let llm = Arc::new(FakeLlm::with_replies(["Ada."]));
    let agent = AgentBuilder::new(Arc::clone(&llm)).typed_tool(Add).build();
    let history = vec![Message::human("I'm Ada."), Message::ai("Hi Ada.")];
    agent.chat("Name?", history).await.unwrap();
    let req = llm.last_request().unwrap();
    assert_eq!(req.method, FakeMethod::GenerateWithTools);
    let texts: Vec<_> = req.messages[1..].iter().map(Message::text).collect();
    assert_eq!(texts, ["I'm Ada.", "Hi Ada.", "Name?"]);
}

#[tokio::test]
async fn stream_prompt_streams_tokens_and_records_memory() {
    let llm = Arc::new(FakeLlm::with_replies(["Hello there, Ada."]).with_chunk_chars(4));
    let memory = Arc::new(SimpleMemory::new());
    let agent = AgentBuilder::new(Arc::clone(&llm))
        .memory(Arc::clone(&memory))
        .build();

    let chunks: Vec<_> = agent
        .stream_prompt("hi")
        .await
        .unwrap()
        .map(Result::unwrap)
        .collect()
        .await;
    assert!(chunks.len() > 3, "several chunks");
    assert!(chunks.last().unwrap().is_finished);
    let text: String = chunks.iter().map(|c| c.content.as_str()).collect();
    assert_eq!(text, "Hello there, Ada.");
    assert_eq!(llm.last_request().unwrap().method, FakeMethod::StreamEvents);

    let stored: Vec<_> = memory
        .messages()
        .await
        .unwrap()
        .iter()
        .map(Message::text)
        .collect();
    assert_eq!(stored, ["hi", "Hello there, Ada."]);
}

#[tokio::test]
async fn a_failed_stream_is_not_remembered() {
    let llm = FakeLlm::with_replies([
        FakeReply::text("partial answer").with_stream_error(LlmError::timeout("cut off"))
    ]);
    let memory = Arc::new(SimpleMemory::new());
    let agent = AgentBuilder::new(llm).memory(Arc::clone(&memory)).build();
    let items: Vec<_> = agent.stream_prompt("hi").await.unwrap().collect().await;
    assert!(items.last().unwrap().is_err());
    assert!(memory.messages().await.unwrap().is_empty());
}

#[tokio::test]
async fn stream_prompt_with_tools_streams_every_turn() {
    let llm = Arc::new(
        FakeLlm::with_replies([
            FakeReply::result(
                GenerateResult::from_text("Adding them up. ")
                    .with_tool_calls(vec![add_call("c1", 2, 2)]),
            ),
            FakeReply::text("The sum is 4."),
        ])
        .with_chunk_chars(5),
    );
    let memory = Arc::new(SimpleMemory::new());
    let agent = AgentBuilder::new(Arc::clone(&llm))
        .typed_tool(Add)
        .memory(Arc::clone(&memory))
        .build();
    let chunks: Vec<_> = agent
        .stream_prompt("2+2")
        .await
        .unwrap()
        .map(Result::unwrap)
        .collect()
        .await;
    let text: String = chunks.iter().map(|c| c.content.as_str()).collect();
    assert_eq!(text, "Adding them up. The sum is 4.");
    assert!(chunks.len() > 4, "tokens, not one chunk: {chunks:?}");
    assert!(chunks.last().unwrap().is_finished);
    assert_eq!(llm.call_count(), 2);
    assert!(
        llm.requests()
            .iter()
            .all(|r| r.method == FakeMethod::StreamEvents && r.tool_names() == ["add"])
    );
    let stored: Vec<_> = memory
        .messages()
        .await
        .unwrap()
        .iter()
        .map(Message::text)
        .collect();
    assert_eq!(stored, ["2+2", "The sum is 4."], "only the final answer");
}

#[tokio::test]
async fn stream_events_report_tool_calls_results_and_the_response() {
    use rune_chain::agent::ToolStatus;
    use rune_chain::{AgentStreamItem, StreamEvent};

    // Two calls whose argument fragments interleave across chunks.
    let llm = Arc::new(FakeLlm::with_replies([
        FakeReply::events([
            StreamEvent::tool_call_start(0, "c1", "add"),
            StreamEvent::tool_call_start(1, "c2", "add"),
            StreamEvent::tool_call_delta(0, r#"{"a":1,"#),
            StreamEvent::tool_call_delta(1, r#"{"a":5,"b""#),
            StreamEvent::tool_call_delta(0, r#""b":2}"#),
            StreamEvent::tool_call_delta(1, ":5}"),
        ]),
        FakeReply::text("3 and 10.").with_usage(rune_chain::TokenUsage::new(9, 3)),
    ]));
    let agent = AgentBuilder::new(Arc::clone(&llm)).typed_tool(Add).build();
    let items: Vec<AgentStreamItem> = agent
        .stream_chat_events("1+2 and 5+5?", Vec::new())
        .await
        .unwrap()
        .map(Result::unwrap)
        .collect()
        .await;
    let calls: Vec<(usize, &str)> = items
        .iter()
        .filter_map(|i| match i {
            AgentStreamItem::ToolCall { turn, call_id, .. } => Some((*turn, call_id.as_str())),
            _ => None,
        })
        .collect();
    assert_eq!(calls, [(1, "c1"), (1, "c2")]);
    let results: Vec<(&str, ToolStatus)> = items
        .iter()
        .filter_map(|i| match i {
            AgentStreamItem::ToolResult { invocation, .. } => {
                Some((invocation.output.as_str(), invocation.status))
            }
            _ => None,
        })
        .collect();
    assert_eq!(results, [("3", ToolStatus::Ok), ("10", ToolStatus::Ok)]);
    let Some(AgentStreamItem::Final(response)) = items.last() else {
        panic!("{items:?}")
    };
    assert_eq!(response.output, "3 and 10.");
    assert_eq!(response.turns, 1);
    assert_eq!(response.tool_calls.len(), 2);
    assert_eq!(response.usage.as_ref().unwrap().total_tokens, 12);
}

#[tokio::test]
async fn streamed_limits_end_text_streams_with_an_error() {
    let llm = FakeLlm::with_replies([
        FakeReply::tool_calls([add_call("c1", 1, 1)]),
        FakeReply::tool_calls([add_call("c2", 1, 1)]),
    ]);
    let memory = Arc::new(SimpleMemory::new());
    let agent = AgentBuilder::new(llm)
        .typed_tool(Add)
        .max_turns(1)
        .memory(Arc::clone(&memory))
        .build();
    let items: Vec<_> = agent.stream_prompt("loop").await.unwrap().collect().await;
    let err = items.last().unwrap().as_ref().unwrap_err();
    assert!(err.to_string().contains("iteration limit"), "{err}");
    assert!(memory.messages().await.unwrap().is_empty());
}

#[tokio::test]
async fn stream_events_without_tools_report_usage() {
    use rune_chain::AgentStreamItem;
    let agent = AgentBuilder::new(FakeLlm::with_replies([
        FakeReply::text("pong").with_usage(rune_chain::TokenUsage::new(2, 1))
    ]))
    .build();
    let items: Vec<_> = agent
        .stream_events("ping")
        .await
        .unwrap()
        .map(Result::unwrap)
        .collect()
        .await;
    assert!(matches!(&items[0], AgentStreamItem::Text(t) if t == "pong"));
    let Some(AgentStreamItem::Final(response)) = items.last() else {
        panic!("{items:?}")
    };
    assert_eq!(response.usage.as_ref().unwrap().total_tokens, 3);
}

#[tokio::test]
async fn agent_is_a_chain() {
    let agent = AgentBuilder::new(FakeLlm::with_replies([
        FakeReply::text("pong").with_usage(rune_chain::TokenUsage::new(3, 1))
    ]))
    .build();
    let out = agent
        .call(prompt_args! { "input" => "ping" })
        .await
        .unwrap();
    assert_eq!(out.generation, "pong");
    assert_eq!(out.tokens.unwrap().prompt_tokens, 3);
    assert!(matches!(
        agent.call(prompt_args! { "question" => "ping" }).await,
        Err(ChainError::MissingVariable(_))
    ));
    assert_eq!(agent.input_keys(), ["input"]);
}

#[tokio::test]
async fn agents_can_be_tools_of_other_agents() {
    let inner_llm = Arc::new(FakeLlm::with_replies(["Rust 1.0 shipped in May 2015."]));
    let researcher = AgentBuilder::new(Arc::clone(&inner_llm))
        .preamble("You research release dates.")
        .name("researcher")
        .description("Finds release dates.")
        .build();

    let outer_llm = Arc::new(FakeLlm::with_replies([
        FakeReply::tool_calls([ToolCall::new(
            "c1",
            "researcher",
            r#"{"prompt": "When did Rust 1.0 ship?"}"#,
        )]),
        FakeReply::text("May 2015."),
    ]));
    let lead = AgentBuilder::new(Arc::clone(&outer_llm))
        .tool(researcher.clone())
        .build();

    let res = lead
        .prompt_with_details("When was Rust 1.0?")
        .await
        .unwrap();
    assert_eq!(res.output, "May 2015.");
    assert_eq!(res.tool_calls[0].name, "researcher");
    assert_eq!(res.tool_calls[0].output, "Rust 1.0 shipped in May 2015.");

    let first = &outer_llm.requests()[0];
    assert_eq!(first.tools[0].description, "Finds release dates.");
    assert_eq!(
        inner_llm.last_request().unwrap().prompt().unwrap(),
        "When did Rust 1.0 ship?"
    );

    // As a plain tool: JSON or raw text in, bad arguments rejected.
    inner_llm.push("again");
    assert_eq!(researcher.run("raw question").await.unwrap(), "again");
    assert!(researcher.run(r#"{"prompt": 7}"#).await.is_err());
}

#[tokio::test]
async fn typed_tool_rejects_hostile_input() {
    let tool = Typed::new(Add);
    assert_eq!(tool.run(r#"{"a": 1, "b": 2}"#).await.unwrap(), "3");
    assert!(matches!(
        tool.run("not json").await,
        Err(ToolError::InvalidInput(_))
    ));
    assert!(matches!(
        tool.run(r#"{"a": 1}"#).await,
        Err(ToolError::InvalidInput(_))
    ));
    let max = json!({ "a": i64::MAX, "b": 1 }).to_string();
    assert!(
        tool.run(&max).await.is_err(),
        "overflow is an error, not a panic"
    );
    let huge = format!(r#"{{"a": 1, "b": 2, "pad": "{}"}}"#, "x".repeat(2 << 20));
    assert!(matches!(
        tool.run(&huge).await,
        Err(ToolError::InvalidInput(m)) if m.contains("limit")
    ));
}

#[tokio::test]
async fn approval_gated_tools_are_denied_without_an_approver() {
    let llm = Arc::new(FakeLlm::with_replies([
        FakeReply::tool_calls([add_call("c1", 1, 1)]),
        FakeReply::text("denied"),
    ]));
    let agent = AgentBuilder::new(Arc::clone(&llm))
        .tool_requiring_approval(Typed::new(Add))
        .build();
    let res = agent.prompt_with_details("1+1").await.unwrap();
    assert_eq!(
        res.tool_calls[0].status,
        rune_chain::agent::ToolStatus::Denied
    );
}
