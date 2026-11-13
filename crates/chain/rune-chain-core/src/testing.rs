//! Reusable trait-contract checks for [`Llm`], [`Chain`], [`Memory`] and [`Tool`]
//! implementations.
//!
//! Every provider, chain, memory backend and tool in the `rune-chain-*` family
//! is expected to uphold the invariants checked here. Call the matching
//! `check_*` function from your crate's tests (enable the `testing` feature in
//! `[dev-dependencies]`) against an offline instance — a fixture-backed client,
//! an in-process memory, a pure tool — and assert that it returns `Ok(())`.
//!
//! The checks never panic: a broken implementation yields a
//! [`ContractViolation`] naming the contract and what was observed, so the
//! failure message in your test points straight at the problem.
//!
//! [`http`] adds a loopback [`MockServer`](http::MockServer) that replays canned
//! HTTP responses, for testing HTTP-backed providers without the network.
//!
//! [`FakeLlm`] is the other side: a scriptable [`Llm`] for testing code that
//! *uses* the trait. It answers from a queue of [`FakeReply`] values (or a
//! closure) and records every [`FakeRequest`]; see the [`fake`] module.
//!
//! # Example
//!
//! ```rust
//! use async_trait::async_trait;
//! use rune_chain_core::testing::check_tool;
//! use rune_chain_core::{Tool, ToolError};
//!
//! struct Upper;
//!
//! #[async_trait]
//! impl Tool for Upper {
//!     fn name(&self) -> &str { "upper" }
//!     fn description(&self) -> &str { "Upper-cases its input." }
//!     async fn run(&self, input: &str) -> Result<String, ToolError> {
//!         Ok(input.to_uppercase())
//!     }
//! }
//!
//! # tokio_test::block_on(async {
//! check_tool(&Upper, "hello").await.unwrap();
//! # });
//! ```

pub mod fake;
pub mod http;

pub use fake::{FakeLlm, FakeMethod, FakeReply, FakeRequest};

use std::collections::HashSet;

use futures::{Stream, StreamExt};
use serde_json::Value;

use crate::{
    Chain, ChainError, FunctionDefinition, GenerateResult, LlmErrorKind, Memory, Message,
    PromptArgs, StreamData, TokenUsage, Tool,
};
use crate::{Llm, ToolChoice};

/// Key under which [`Chain::execute`] stores the serialised [`GenerateResult`].
const RESULT_KEY: &str = "generate_result";

/// A broken trait contract, reported by one of the `check_*` functions.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("contract `{contract}` violated: {detail}")]
pub struct ContractViolation {
    /// Short identifier of the violated contract, e.g. `"llm.stream.terminal"`.
    pub contract: &'static str,
    /// Human-readable description of what was observed.
    pub detail: String,
}

impl ContractViolation {
    fn new(contract: &'static str, detail: impl Into<String>) -> Self {
        Self {
            contract,
            detail: detail.into(),
        }
    }
}

/// Shorthand for the result of a contract check.
pub type ContractResult = Result<(), ContractViolation>;

fn ensure(cond: bool, contract: &'static str, detail: impl FnOnce() -> String) -> ContractResult {
    if cond {
        Ok(())
    } else {
        Err(ContractViolation::new(contract, detail()))
    }
}

/// Check the invariants of a reported [`TokenUsage`]:
///
/// - `total_tokens == prompt_tokens + completion_tokens`;
/// - cache reads plus cache writes fit within `prompt_tokens`;
/// - `reasoning_tokens` fit within `completion_tokens`.
///
/// # Errors
///
/// Returns a [`ContractViolation`] (`"usage.total"`, `"usage.cache"` or
/// `"usage.reasoning"`) for the first broken invariant.
pub fn check_token_usage(usage: &TokenUsage) -> ContractResult {
    let sum = u64::from(usage.prompt_tokens) + u64::from(usage.completion_tokens);
    ensure(u64::from(usage.total_tokens) == sum, "usage.total", || {
        format!(
            "total_tokens {} != prompt + completion {sum}",
            usage.total_tokens
        )
    })?;
    let cached = u64::from(usage.cache_read_tokens) + u64::from(usage.cache_creation_tokens);
    ensure(
        cached <= u64::from(usage.prompt_tokens),
        "usage.cache",
        || {
            format!(
                "cache read + write {cached} > prompt_tokens {}",
                usage.prompt_tokens
            )
        },
    )?;
    ensure(
        usage.reasoning_tokens <= usage.completion_tokens,
        "usage.reasoning",
        || {
            format!(
                "reasoning_tokens {} > completion_tokens {}",
                usage.reasoning_tokens, usage.completion_tokens
            )
        },
    )
}

/// Check the invariants of a [`GenerateResult`] produced in response to a
/// request that offered `tools`.
///
/// - reported token usage is internally consistent ([`check_token_usage`]);
/// - every tool call has a non-empty, unique `id`;
/// - every tool call names one of the offered `tools`;
/// - every tool call's `arguments` is a JSON object.
///
/// Pass an empty `tools` slice for a plain generation: any tool call is then
/// a violation.
///
/// # Errors
///
/// Returns the first [`ContractViolation`] found.
pub fn check_generate_result(
    result: &GenerateResult,
    tools: &[FunctionDefinition],
) -> ContractResult {
    if let Some(usage) = &result.tokens {
        check_token_usage(usage)?;
    }
    let offered: HashSet<&str> = tools.iter().map(|t| t.name.as_str()).collect();
    let mut ids = HashSet::new();
    for call in &result.tool_calls {
        ensure(!call.id.is_empty(), "result.tool_call.id", || {
            format!("tool call to `{}` has an empty id", call.name)
        })?;
        ensure(ids.insert(call.id.as_str()), "result.tool_call.id", || {
            format!("duplicate tool call id `{}`", call.id)
        })?;
        ensure(
            offered.contains(call.name.as_str()),
            "result.tool_call.name",
            || format!("tool call names `{}`, which was not offered", call.name),
        )?;
        // Same rules as `ToolCall::arguments_object`: size-bounded, `""`
        // counts as `{}`, and the error never echoes the arguments.
        if let Err(e) = call.arguments_object() {
            return Err(ContractViolation::new(
                "result.tool_call.arguments",
                format!("call `{}`: {e}", call.id),
            ));
        }
    }
    Ok(())
}

/// Drain a token stream and check that it is well formed.
///
/// - after a chunk with `is_finished == true`, no further item is yielded;
/// - after an `Err` item, no further item is yielded.
///
/// Returns the concatenated content of all chunks and the first error the
/// stream yielded, if any.
///
/// # Errors
///
/// Returns a [`ContractViolation`] (`"stream.terminal"`) when the stream keeps
/// going after its terminal chunk or error.
pub async fn check_stream<S, E>(stream: S) -> Result<(String, Option<E>), ContractViolation>
where
    S: Stream<Item = Result<StreamData, E>>,
{
    let mut stream = std::pin::pin!(stream);
    let mut text = String::new();
    let mut ended = false;
    let mut error = None;
    while let Some(item) = stream.next().await {
        ensure(!ended, "stream.terminal", || {
            "stream yielded an item after its final chunk or error".to_string()
        })?;
        match item {
            Ok(chunk) => {
                text.push_str(&chunk.content);
                ended = chunk.is_finished;
            }
            Err(e) => {
                error = Some(e);
                ended = true;
            }
        }
    }
    Ok((text, error))
}

/// Check the [`Llm`] contract against an offline instance.
///
/// - `generate` on a one-turn conversation succeeds, and its result passes
///   [`check_generate_result`] with no tools offered;
/// - `generate` on an empty conversation returns (either `Ok` or `Err`);
/// - `generate_with_tools` either fails with [`LlmErrorKind::Unsupported`]
///   or a result that passes [`check_generate_result`] for the offered tools;
/// - `stream` either fails up front or yields a stream that passes
///   [`check_stream`].
///
/// # Errors
///
/// Returns the first [`ContractViolation`] found.
pub async fn check_llm<L: Llm + ?Sized>(llm: &L) -> ContractResult {
    let messages = [
        Message::system("You are a contract test."),
        Message::human("ping"),
    ];
    let result = llm
        .generate(&messages)
        .await
        .map_err(|e| ContractViolation::new("llm.generate", format!("generate failed: {e}")))?;
    check_generate_result(&result, &[])?;

    // Must not panic; either outcome is acceptable.
    let _ = llm.generate(&[]).await;

    let tools = [FunctionDefinition::single_input(
        "echo",
        "Returns its input unchanged.",
    )];
    match llm
        .generate_with_tools(&messages, &tools, Some(ToolChoice::Auto))
        .await
    {
        Ok(result) => check_generate_result(&result, &tools)?,
        Err(e) if e.kind() == LlmErrorKind::Unsupported => {}
        Err(e) => {
            return Err(ContractViolation::new(
                "llm.generate_with_tools",
                format!("generate_with_tools failed: {e}"),
            ));
        }
    }

    if let Ok(stream) = llm.stream(&messages).await {
        check_stream(stream).await?;
    }
    Ok(())
}

/// Check the [`Chain`] contract for a chain that succeeds on `input`.
///
/// `call().generation` is the chain's final answer; every other entry point
/// must agree with it (see [`Chain::execute`]):
///
/// - `call` succeeds and its result passes [`check_generate_result`];
/// - `invoke` returns the same text as `call` (the chain must be
///   deterministic on `input` for this check to be meaningful);
/// - `execute` returns a map that holds every key of [`Chain::output_keys`],
///   stores the final answer under [`Chain::primary_output_key`], and stores
///   under `"generate_result"` a serialised [`GenerateResult`] with that same
///   generation. Multi-step chains (sequential pipelines, fan-outs) may keep
///   intermediate outputs under their other keys;
/// - `stream` either fails up front or yields a stream that passes
///   [`check_stream`].
///
/// # Errors
///
/// Returns the first [`ContractViolation`] found.
pub async fn check_chain<C: Chain + ?Sized>(chain: &C, input: &PromptArgs) -> ContractResult {
    let called = chain
        .call(input.clone())
        .await
        .map_err(|e| ContractViolation::new("chain.call", format!("call failed: {e}")))?;
    check_generate_result(&called, &[])?;

    let invoked = chain
        .invoke(input.clone())
        .await
        .map_err(|e| ContractViolation::new("chain.invoke", format!("invoke failed: {e}")))?;
    ensure(invoked == called.generation, "chain.invoke", || {
        format!(
            "invoke returned {invoked:?}, call returned {:?}",
            called.generation
        )
    })?;

    let map = chain
        .execute(input.clone())
        .await
        .map_err(|e| ContractViolation::new("chain.execute", format!("execute failed: {e}")))?;
    if let Some(missing) = chain
        .output_keys()
        .into_iter()
        .find(|k| !map.contains_key(k))
    {
        return Err(ContractViolation::new(
            "chain.execute.keys",
            format!("execute() lacks declared output key {missing:?}"),
        ));
    }
    let key = chain.primary_output_key();
    ensure(
        map.get(&key) == Some(&Value::String(called.generation.clone())),
        "chain.execute.output",
        || {
            format!(
                "execute()[{key:?}] is {:?}, expected the generation {:?}",
                map.get(&key),
                called.generation
            )
        },
    )?;
    let result = map
        .get(RESULT_KEY)
        .filter(|v| v.is_object())
        .and_then(|v| serde_json::from_value::<GenerateResult>(v.clone()).ok())
        .ok_or_else(|| {
            ContractViolation::new(
                "chain.execute.result",
                format!("execute() has no `{RESULT_KEY}` GenerateResult object"),
            )
        })?;
    check_generate_result(&result, &[])?;
    ensure(
        result.generation == called.generation,
        "chain.execute.result",
        || {
            format!(
                "execute()[{RESULT_KEY:?}].generation is {:?}, call returned {:?}",
                result.generation, called.generation
            )
        },
    )?;

    if let Ok(stream) = chain.stream(input.clone()).await {
        check_stream(stream).await?;
    }
    Ok(())
}

/// Check that a chain rejects `input` with an error instead of panicking or
/// succeeding, and that [`Chain::invoke`] and [`Chain::execute`] propagate it.
///
/// # Errors
///
/// Returns a [`ContractViolation`] (`"chain.error"`) when any entry point
/// succeeds on `input`.
pub async fn check_chain_rejects<C: Chain + ?Sized>(
    chain: &C,
    input: &PromptArgs,
) -> ContractResult {
    let outcomes: [(&str, Result<(), ChainError>); 3] = [
        ("call", chain.call(input.clone()).await.map(drop)),
        ("invoke", chain.invoke(input.clone()).await.map(drop)),
        ("execute", chain.execute(input.clone()).await.map(drop)),
    ];
    for (name, outcome) in outcomes {
        ensure(outcome.is_err(), "chain.error", || {
            format!("{name} succeeded on input that must be rejected")
        })?;
    }
    Ok(())
}

/// Check the [`Memory`] contract. The memory is cleared first and last.
///
/// - after `clear`, `messages` is empty;
/// - after adding a sequence of turns, `messages` is a suffix of that
///   sequence, in order (bounded memories may drop the oldest turns);
/// - a second `clear` empties it again.
///
/// # Errors
///
/// Returns the first [`ContractViolation`] found, including any error the
/// memory itself returned.
pub async fn check_memory<M: Memory + ?Sized>(memory: &M) -> ContractResult {
    let fail = |op: &'static str| move |e: ChainError| ContractViolation::new(op, e.to_string());

    memory.clear().await.map_err(fail("memory.clear"))?;
    let stored = memory.messages().await.map_err(fail("memory.messages"))?;
    ensure(stored.is_empty(), "memory.clear", || {
        format!("{} message(s) left after clear", stored.len())
    })?;

    let turns = [
        Message::system("be brief"),
        Message::human("2 + 2?"),
        Message::ai("4"),
    ];
    for turn in &turns {
        memory.add(turn.clone()).await.map_err(fail("memory.add"))?;
    }
    let stored = memory.messages().await.map_err(fail("memory.messages"))?;
    ensure(turns.ends_with(&stored), "memory.order", || {
        format!("history {stored:?} is not an in-order suffix of the added turns")
    })?;

    memory.clear().await.map_err(fail("memory.clear"))?;
    let stored = memory.messages().await.map_err(fail("memory.messages"))?;
    ensure(stored.is_empty(), "memory.clear", || {
        format!("{} message(s) left after clear", stored.len())
    })
}

/// Check the [`Tool`] contract, running the tool once on `valid_input`.
///
/// - `name` is non-empty and contains no whitespace;
/// - `description` is non-empty;
/// - `schema` is a JSON object with `"type": "object"`;
/// - `function_definition` mirrors `name`, `description` and `schema`;
/// - `run(valid_input)` succeeds.
///
/// # Errors
///
/// Returns the first [`ContractViolation`] found.
pub async fn check_tool<T: Tool + ?Sized>(tool: &T, valid_input: &str) -> ContractResult {
    let name = tool.name();
    ensure(
        !name.is_empty() && !name.chars().any(char::is_whitespace),
        "tool.name",
        || format!("tool name {name:?} is empty or contains whitespace"),
    )?;
    ensure(
        !tool.description().trim().is_empty(),
        "tool.description",
        || format!("tool `{name}` has an empty description"),
    )?;
    let schema = tool.schema();
    ensure(
        schema.get("type").and_then(Value::as_str) == Some("object"),
        "tool.schema",
        || format!("schema of `{name}` is not a JSON object schema: {schema}"),
    )?;
    let def = tool.function_definition();
    ensure(
        def.name == name && def.description == tool.description() && def.parameters == schema,
        "tool.function_definition",
        || format!("function_definition of `{name}` does not mirror the tool metadata"),
    )?;
    tool.run(valid_input)
        .await
        .map(drop)
        .map_err(|e| ContractViolation::new("tool.run", format!("`{name}` failed: {e}")))
}

/// Check that a tool rejects `invalid_input` with a [`ToolError`](crate::ToolError)
/// instead of panicking or succeeding.
///
/// # Errors
///
/// Returns a [`ContractViolation`] (`"tool.error"`) when the tool succeeds.
pub async fn check_tool_rejects<T: Tool + ?Sized>(tool: &T, invalid_input: &str) -> ContractResult {
    let outcome = tool.run(invalid_input).await;
    ensure(outcome.is_err(), "tool.error", || {
        format!(
            "`{}` accepted input that must be rejected: {invalid_input:?}",
            tool.name()
        )
    })
}
