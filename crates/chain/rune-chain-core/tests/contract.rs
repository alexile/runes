//! Trait-contract tests: reference implementations must pass every
//! `rune_chain_core::testing` check, and deliberately broken ones must be
//! caught with the right contract id.

#![cfg(feature = "testing")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test fixtures outside #[test] fns"
)]

use std::pin::Pin;
use std::sync::Mutex;

use async_trait::async_trait;
use futures::{Stream, stream};
use rune_chain_core::testing::{
    ContractViolation, check_chain, check_chain_rejects, check_generate_result, check_llm,
    check_memory, check_stream, check_token_usage, check_tool, check_tool_rejects,
};
use rune_chain_core::{
    Chain, ChainError, FunctionDefinition, GenerateResult, Llm, LlmError, LlmErrorKind, Memory,
    Message, PromptArgs, StreamData, TokenUsage, Tool, ToolCall, ToolChoice, ToolError,
    prompt_args,
};
use serde_json::Value;

type LlmStream = Pin<Box<dyn Stream<Item = Result<StreamData, LlmError>> + Send>>;
type ChainStream = Pin<Box<dyn Stream<Item = Result<StreamData, ChainError>> + Send>>;

fn contract(r: Result<(), ContractViolation>) -> &'static str {
    r.expect_err("expected a contract violation").contract
}

const fn usage(p: u32, c: u32, t: u32) -> TokenUsage {
    TokenUsage::new(p, c).with_total_tokens(t)
}

// ── Llm ───────────────────────────────────────────────────────────────────────

/// Text-only provider relying on every default method.
struct MinimalLlm;

#[async_trait]
impl Llm for MinimalLlm {
    async fn generate(&self, messages: &[Message]) -> Result<GenerateResult, LlmError> {
        let last = messages
            .last()
            .ok_or_else(|| LlmError::invalid_response("no messages"))?;
        Ok(GenerateResult::from_text(last.content.text_content()))
    }
}

/// Fully featured provider: usage, tool calls and streaming.
struct FullLlm;

#[async_trait]
impl Llm for FullLlm {
    async fn generate(&self, messages: &[Message]) -> Result<GenerateResult, LlmError> {
        Ok(
            GenerateResult::from_text(format!("{} turns", messages.len()))
                .with_tokens(usage(3, 2, 5)),
        )
    }

    async fn generate_with_tools(
        &self,
        _messages: &[Message],
        tools: &[FunctionDefinition],
        tool_choice: Option<ToolChoice>,
    ) -> Result<GenerateResult, LlmError> {
        if tool_choice == Some(ToolChoice::None) {
            return Ok(GenerateResult::from_text("no tools"));
        }
        let tool_calls = tools
            .iter()
            .enumerate()
            .map(|(i, t)| ToolCall::new(format!("call_{i}"), &t.name, r#"{"input":"x"}"#))
            .collect();
        Ok(GenerateResult::default().with_tool_calls(tool_calls))
    }

    async fn stream(&self, _messages: &[Message]) -> Result<LlmStream, LlmError> {
        Ok(Box::pin(stream::iter([
            Ok(StreamData::chunk("po")),
            Ok(StreamData::chunk("ng")),
            Ok(StreamData::done()),
        ])))
    }
}

/// A provider whose behaviour is broken in one configurable way.
enum BrokenLlm {
    GenerateFails,
    BadUsage,
    UnrequestedToolCall,
    UnknownTool,
    DuplicateIds,
    EmptyId,
    NonObjectArguments,
    ToolsFailWithOtherError,
    ChunkAfterDone,
    ChunkAfterError,
}

#[async_trait]
impl Llm for BrokenLlm {
    async fn generate(&self, _messages: &[Message]) -> Result<GenerateResult, LlmError> {
        match self {
            Self::GenerateFails => Err(LlmError::request_failed("offline")),
            Self::BadUsage => Ok(GenerateResult::from_text("x").with_tokens(usage(1, 1, 3))),
            Self::UnrequestedToolCall => {
                Ok(GenerateResult::default()
                    .with_tool_calls(vec![ToolCall::new("c", "echo", "{}")]))
            }
            _ => Ok(GenerateResult::from_text("ok")),
        }
    }

    async fn generate_with_tools(
        &self,
        _messages: &[Message],
        _tools: &[FunctionDefinition],
        _tool_choice: Option<ToolChoice>,
    ) -> Result<GenerateResult, LlmError> {
        let calls = match self {
            Self::UnknownTool => vec![ToolCall::new("a", "rm_rf", "{}")],
            Self::DuplicateIds => vec![
                ToolCall::new("a", "echo", "{}"),
                ToolCall::new("a", "echo", "{}"),
            ],
            Self::EmptyId => vec![ToolCall::new("", "echo", "{}")],
            Self::NonObjectArguments => vec![ToolCall::new("a", "echo", "[1]")],
            Self::ToolsFailWithOtherError => {
                return Err(LlmError::provider("quota"));
            }
            _ => {
                return Err(LlmError::unsupported("no"));
            }
        };
        Ok(GenerateResult::default().with_tool_calls(calls))
    }

    async fn stream(&self, _messages: &[Message]) -> Result<LlmStream, LlmError> {
        match self {
            Self::ChunkAfterDone => Ok(Box::pin(stream::iter([
                Ok(StreamData::done()),
                Ok(StreamData::chunk("late")),
            ]))),
            Self::ChunkAfterError => Ok(Box::pin(stream::iter([
                Err(LlmError::other("boom")),
                Ok(StreamData::chunk("late")),
            ]))),
            _ => Err(LlmError::other("no streaming")),
        }
    }
}

#[tokio::test]
async fn reference_llms_satisfy_contract() {
    check_llm(&MinimalLlm).await.unwrap();
    check_llm(&FullLlm).await.unwrap();
    let boxed: Box<dyn Llm> = Box::new(FullLlm);
    check_llm(boxed.as_ref()).await.unwrap();
}

#[tokio::test]
async fn broken_llms_are_caught() {
    for (llm, expected) in [
        (BrokenLlm::GenerateFails, "llm.generate"),
        (BrokenLlm::BadUsage, "usage.total"),
        (BrokenLlm::UnrequestedToolCall, "result.tool_call.name"),
        (BrokenLlm::UnknownTool, "result.tool_call.name"),
        (BrokenLlm::DuplicateIds, "result.tool_call.id"),
        (BrokenLlm::EmptyId, "result.tool_call.id"),
        (BrokenLlm::NonObjectArguments, "result.tool_call.arguments"),
        (
            BrokenLlm::ToolsFailWithOtherError,
            "llm.generate_with_tools",
        ),
        (BrokenLlm::ChunkAfterDone, "stream.terminal"),
        (BrokenLlm::ChunkAfterError, "stream.terminal"),
    ] {
        assert_eq!(contract(check_llm(&llm).await), expected);
    }
}

#[tokio::test]
async fn full_llm_honours_tool_choice_none() {
    let tools = [FunctionDefinition::single_input("echo", "e")];
    let r = FullLlm
        .generate_with_tools(&[], &tools, Some(ToolChoice::None))
        .await
        .unwrap();
    assert!(!r.wants_tool_calls());
    check_generate_result(&r, &tools).unwrap();
}

// ── Streams ───────────────────────────────────────────────────────────────────

#[tokio::test]
async fn stream_check_concatenates_and_reports_errors() {
    let (text, err) = check_stream(stream::iter([
        Ok::<_, LlmError>(StreamData::chunk("a")),
        Ok(StreamData::chunk("b")),
        Ok(StreamData {
            content: "c".into(),
            is_finished: true,
        }),
    ]))
    .await
    .unwrap();
    assert_eq!(text, "abc");
    assert!(err.is_none());

    let (text, err) = check_stream(stream::iter([
        Ok(StreamData::chunk("a")),
        Err(LlmError::request_failed("reset")),
    ]))
    .await
    .unwrap();
    assert_eq!(text, "a");
    assert!(matches!(err, Some(e) if e.kind() == LlmErrorKind::Network));

    // A stream may end without an explicit terminal chunk.
    let (text, err) = check_stream(stream::iter(Vec::<Result<StreamData, LlmError>>::new()))
        .await
        .unwrap();
    assert!(text.is_empty() && err.is_none());
}

#[test]
fn token_usage_check() {
    check_token_usage(&usage(0, 0, 0)).unwrap();
    check_token_usage(&usage(u32::MAX, 0, u32::MAX)).unwrap();
    assert_eq!(
        contract(check_token_usage(&usage(u32::MAX, 1, 0))),
        "usage.total"
    );
}

// ── Chain ─────────────────────────────────────────────────────────────────────

struct Upper;

#[async_trait]
impl Chain for Upper {
    async fn call(&self, input: PromptArgs) -> Result<GenerateResult, ChainError> {
        let text = input
            .get("input")
            .and_then(Value::as_str)
            .ok_or_else(|| ChainError::MissingVariable("input".into()))?;
        Ok(GenerateResult::from_text(text.to_uppercase()))
    }

    async fn stream(&self, input: PromptArgs) -> Result<ChainStream, ChainError> {
        let text = self.invoke(input).await?;
        Ok(Box::pin(stream::iter([
            Ok(StreamData::chunk(text)),
            Ok(StreamData::done()),
        ])))
    }

    fn input_keys(&self) -> Vec<String> {
        vec!["input".into()]
    }

    fn output_keys(&self) -> Vec<String> {
        vec!["upper".into()]
    }
}

/// Overrides `invoke` and `execute` inconsistently with `call`.
enum BrokenChain {
    InvokeDisagrees,
    ExecuteMissingKey,
    ExecuteWrongOutput,
    ExecuteNoResult,
    ExecuteResultDisagrees,
    StreamsPastEnd,
    NeverFails,
}

#[async_trait]
impl Chain for BrokenChain {
    async fn call(&self, _input: PromptArgs) -> Result<GenerateResult, ChainError> {
        Ok(GenerateResult::from_text("call"))
    }

    async fn invoke(&self, input: PromptArgs) -> Result<String, ChainError> {
        match self {
            Self::InvokeDisagrees => Ok("invoke".into()),
            _ => self.call(input).await.map(|r| r.generation),
        }
    }

    async fn execute(
        &self,
        _input: PromptArgs,
    ) -> Result<std::collections::HashMap<String, Value>, ChainError> {
        let mut map = std::collections::HashMap::new();
        match self {
            Self::ExecuteMissingKey => {}
            Self::ExecuteWrongOutput => {
                map.insert("output".to_string(), Value::from("other"));
            }
            _ => {
                map.insert("output".to_string(), Value::from("call"));
            }
        }
        match self {
            Self::ExecuteNoResult => {}
            Self::ExecuteResultDisagrees => {
                map.insert(
                    "generate_result".to_string(),
                    serde_json::json!({ "generation": "other" }),
                );
            }
            _ => {
                map.insert(
                    "generate_result".to_string(),
                    serde_json::json!({ "generation": "call" }),
                );
            }
        }
        Ok(map)
    }

    async fn stream(&self, _input: PromptArgs) -> Result<ChainStream, ChainError> {
        match self {
            Self::StreamsPastEnd => Ok(Box::pin(stream::iter([
                Ok(StreamData::done()),
                Ok(StreamData::done()),
            ]))),
            _ => Err(ChainError::Other("no streaming".into())),
        }
    }
}

#[tokio::test]
async fn reference_chains_satisfy_contract() {
    let input = prompt_args! { "input" => "abc" };
    check_chain(&Upper, &input).await.unwrap();
    check_chain_rejects(&Upper, &PromptArgs::new())
        .await
        .unwrap();
    check_chain_rejects(&Upper, &prompt_args! { "input" => 42 })
        .await
        .unwrap();
    let boxed: Box<dyn Chain> = Upper.into();
    check_chain(boxed.as_ref(), &input).await.unwrap();
}

#[tokio::test]
async fn broken_chains_are_caught() {
    let input = PromptArgs::new();
    for (chain, expected) in [
        (BrokenChain::InvokeDisagrees, "chain.invoke"),
        (BrokenChain::ExecuteMissingKey, "chain.execute.keys"),
        (BrokenChain::ExecuteWrongOutput, "chain.execute.output"),
        (BrokenChain::ExecuteNoResult, "chain.execute.keys"),
        (BrokenChain::ExecuteResultDisagrees, "chain.execute.result"),
        (BrokenChain::StreamsPastEnd, "stream.terminal"),
    ] {
        assert_eq!(contract(check_chain(&chain, &input).await), expected);
    }
    assert_eq!(
        contract(check_chain_rejects(&BrokenChain::NeverFails, &input).await),
        "chain.error"
    );
    assert_eq!(
        contract(check_chain(&Upper, &input).await),
        "chain.call",
        "a chain that fails on the given input cannot pass the success contract"
    );
}

/// A two-step chain: an intermediate `draft` and the final `answer`, the
/// shape of sequential and fan-out chains.
struct Pipeline;

#[async_trait]
impl Chain for Pipeline {
    async fn call(&self, _input: PromptArgs) -> Result<GenerateResult, ChainError> {
        Ok(GenerateResult::from_text("final"))
    }

    async fn execute(
        &self,
        input: PromptArgs,
    ) -> Result<std::collections::HashMap<String, Value>, ChainError> {
        let result = self.call(input).await?;
        let mut map = std::collections::HashMap::new();
        map.insert("draft".to_string(), Value::from("draft"));
        map.insert("answer".to_string(), Value::from(result.generation.clone()));
        map.insert(
            "generate_result".to_string(),
            serde_json::to_value(&result).unwrap(),
        );
        Ok(map)
    }

    fn output_keys(&self) -> Vec<String> {
        vec!["draft".into(), "answer".into(), "generate_result".into()]
    }
}

#[tokio::test]
async fn multi_output_chains_store_the_answer_under_the_last_key() {
    struct NoKeys;
    #[async_trait]
    impl Chain for NoKeys {
        async fn call(&self, _: PromptArgs) -> Result<GenerateResult, ChainError> {
            Ok(GenerateResult::from_text("x"))
        }
        fn output_keys(&self) -> Vec<String> {
            vec!["generate_result".into()]
        }
    }
    assert_eq!(Pipeline.primary_output_key(), "answer");
    check_chain(&Pipeline, &PromptArgs::new()).await.unwrap();
    // Default `execute` honours the same key choice.
    assert_eq!(Upper.primary_output_key(), "upper");
    assert_eq!(NoKeys.primary_output_key(), "output");
    let map = NoKeys.execute(PromptArgs::new()).await.unwrap();
    assert_eq!(map["output"], "x");
    check_chain(&NoKeys, &PromptArgs::new()).await.unwrap();
}

// ── Memory ────────────────────────────────────────────────────────────────────

/// Keeps the most recent `window` messages (`usize::MAX` = unbounded).
struct WindowMemory {
    window: usize,
    stored: Mutex<Vec<Message>>,
}

impl WindowMemory {
    fn new(window: usize) -> Self {
        Self {
            window,
            stored: Mutex::new(vec![Message::human("stale turn from before")]),
        }
    }
}

#[async_trait]
impl Memory for WindowMemory {
    async fn messages(&self) -> Result<Vec<Message>, ChainError> {
        let stored = self.stored.lock().unwrap();
        let start = stored.len().saturating_sub(self.window);
        Ok(stored[start..].to_vec())
    }
    async fn add(&self, message: Message) -> Result<(), ChainError> {
        self.stored.lock().unwrap().push(message);
        Ok(())
    }
    async fn clear(&self) -> Result<(), ChainError> {
        self.stored.lock().unwrap().clear();
        Ok(())
    }
}

enum BrokenMemory {
    ClearIsNoop(Mutex<Vec<Message>>),
    Reversed(Mutex<Vec<Message>>),
    Unavailable,
}

#[async_trait]
impl Memory for BrokenMemory {
    async fn messages(&self) -> Result<Vec<Message>, ChainError> {
        match self {
            Self::ClearIsNoop(m) => Ok(m.lock().unwrap().clone()),
            Self::Reversed(m) => Ok(m.lock().unwrap().iter().rev().cloned().collect()),
            Self::Unavailable => Err(ChainError::MemoryError("db down".into())),
        }
    }
    async fn add(&self, message: Message) -> Result<(), ChainError> {
        if let Self::ClearIsNoop(m) | Self::Reversed(m) = self {
            m.lock().unwrap().push(message);
        }
        Ok(())
    }
    async fn clear(&self) -> Result<(), ChainError> {
        if let Self::Reversed(m) = self {
            m.lock().unwrap().clear();
        }
        Ok(())
    }
}

#[tokio::test]
async fn reference_memories_satisfy_contract() {
    for window in [0, 1, 2, 3, usize::MAX] {
        check_memory(&WindowMemory::new(window)).await.unwrap();
    }
    let boxed: Box<dyn Memory> = Box::new(WindowMemory::new(usize::MAX));
    check_memory(boxed.as_ref()).await.unwrap();
}

#[tokio::test]
async fn broken_memories_are_caught() {
    let noop = BrokenMemory::ClearIsNoop(Mutex::new(vec![Message::ai("old")]));
    assert_eq!(contract(check_memory(&noop).await), "memory.clear");
    let reversed = BrokenMemory::Reversed(Mutex::default());
    assert_eq!(contract(check_memory(&reversed).await), "memory.order");
    assert_eq!(
        contract(check_memory(&BrokenMemory::Unavailable).await),
        "memory.messages"
    );
}

// ── Tool ──────────────────────────────────────────────────────────────────────

struct Reverse;

#[async_trait]
impl Tool for Reverse {
    fn name(&self) -> &'static str {
        "reverse"
    }
    fn description(&self) -> &'static str {
        "Reverses a string."
    }
    async fn run(&self, input: &str) -> Result<String, ToolError> {
        if input.is_empty() {
            return Err(ToolError::InvalidInput("empty".into()));
        }
        Ok(input.chars().rev().collect())
    }
}

struct Meta {
    name: &'static str,
    description: &'static str,
    schema: Value,
    lying_definition: bool,
}

impl Meta {
    fn ok() -> Self {
        Self {
            name: "meta",
            description: "Configurable test tool.",
            schema: serde_json::json!({ "type": "object", "properties": {} }),
            lying_definition: false,
        }
    }
}

#[async_trait]
impl Tool for Meta {
    fn name(&self) -> &str {
        self.name
    }
    fn description(&self) -> &str {
        self.description
    }
    async fn run(&self, input: &str) -> Result<String, ToolError> {
        Ok(input.to_string())
    }
    fn schema(&self) -> Value {
        self.schema.clone()
    }
    fn function_definition(&self) -> FunctionDefinition {
        let name = if self.lying_definition {
            "other"
        } else {
            self.name
        };
        FunctionDefinition::new(name, self.description, self.schema())
    }
}

#[tokio::test]
async fn reference_tools_satisfy_contract() {
    check_tool(&Reverse, "abc").await.unwrap();
    check_tool_rejects(&Reverse, "").await.unwrap();
    check_tool(&Meta::ok(), "{}").await.unwrap();
    let boxed: Box<dyn Tool> = Box::new(Reverse);
    check_tool(boxed.as_ref(), "x").await.unwrap();
}

#[tokio::test]
async fn broken_tools_are_caught() {
    let cases = [
        (
            Meta {
                name: "",
                ..Meta::ok()
            },
            "tool.name",
        ),
        (
            Meta {
                name: "web search",
                ..Meta::ok()
            },
            "tool.name",
        ),
        (
            Meta {
                description: "  ",
                ..Meta::ok()
            },
            "tool.description",
        ),
        (
            Meta {
                schema: serde_json::json!({ "type": "string" }),
                ..Meta::ok()
            },
            "tool.schema",
        ),
        (
            Meta {
                schema: Value::Null,
                ..Meta::ok()
            },
            "tool.schema",
        ),
        (
            Meta {
                lying_definition: true,
                ..Meta::ok()
            },
            "tool.function_definition",
        ),
    ];
    for (tool, expected) in cases {
        assert_eq!(contract(check_tool(&tool, "x").await), expected);
    }
    assert_eq!(contract(check_tool(&Reverse, "").await), "tool.run");
    assert_eq!(
        contract(check_tool_rejects(&Meta::ok(), "anything").await),
        "tool.error"
    );
}

#[test]
fn violation_display_names_contract() {
    let v = check_token_usage(&usage(1, 1, 1)).unwrap_err();
    assert_eq!(
        v.to_string(),
        "contract `usage.total` violated: total_tokens 1 != prompt + completion 2"
    );
}
