# rune-chain-core

> Core traits and types for the `rune-chain` LLM orchestration framework.

[![crates.io](https://img.shields.io/crates/v/rune-chain-core)](https://crates.io/crates/rune-chain-core)
[![docs.rs](https://img.shields.io/docsrs/rune-chain-core)](https://docs.rs/rune-chain-core)
[![license](https://img.shields.io/crates/l/rune-chain-core)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

## What it does

`rune-chain-core` is the shared foundation for the `rune-chain-*` family of crates — a modern,
async-first Rust port of the LangChain concept. It defines the traits, types, and error variants
that all other `rune-chain-*` crates build on, without depending on any specific LLM provider.

## Installation

```toml
[dependencies]
rune-chain-core = "0.2"
async-trait = "0.1"
```

## Usage

Implement [`Chain`] for any unit of LLM work:

```rust
use rune_chain_core::{Chain, ChainError, GenerateResult, PromptArgs, prompt_args};
use async_trait::async_trait;

struct EchoChain;

#[async_trait]
impl Chain for EchoChain {
    async fn call(&self, input: PromptArgs) -> Result<GenerateResult, ChainError> {
        let text = input
            .get("input")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        Ok(GenerateResult::from_text(text))
    }
}

let chain = EchoChain;
let result = chain.invoke(prompt_args! { "input" => "hello" }).await?;
println!("{result}");
```

## Core abstractions

| Item | Description |
|------|-------------|
| `Chain` | Central trait — implement to create any LLM pipeline step |
| `Llm` | Provider-agnostic interface to any large language model |
| `Memory` | Pluggable conversation history |
| `Message` / `Role` | Typed turns: System, Human, Ai, Tool |
| `GenerateResult` / `TokenUsage` | Generated text, token usage (with cache-read, cache-write and reasoning breakdown), tool calls, `finish_reason`; builders and `to_message()` |
| `FinishReason` | Why the model stopped: `Stop`, `Length`, `ToolCalls`, `ContentFilter`, `Refusal`, `Other(String)` |
| `ReasoningBlock` | Reasoning / thinking kept out of the message text, with opaque provider signatures for multi-turn round-trips |
| `ToolCall` / `FunctionDefinition` | Native function calling; bounded `parse_arguments::<T>()` and schema `validate()` |
| `ResponseFormat` | Structured output (JSON object / JSON Schema) via `Llm::generate_structured` |
| `ChainExt` / `LlmExt` | `.with_fallbacks(…)`, `.map_output(…)`, `.pipe(…)`, `.bind_tools(…)`, `.with_cache(…)`, `.with_callbacks(…)`, `.with_timeout(…)`, `.with_retry(…)` |
| `Chain::batch` / `Llm::batch` | Ordered batches with bounded concurrency |
| `CallbackHandler` | Start / end / error hooks for models, chains and tools |
| `LlmCache` / `InMemoryLlmCache` | Response cache trait and a bounded LRU |
| `ImageData` | URL / base64 images with `validate()` (size, MIME, URL scheme) and redacted `Debug` |
| `StreamData` | Incremental token chunk for streaming responses |
| `PromptArgs` + `prompt_args!` | Ergonomic input map for prompt templates |
| `ChainError` / `LlmError` | Structured errors with `From` conversion between them; `LlmError` has a `kind()` (`LlmErrorKind`), HTTP `status()`, `retry_after()` and `is_retryable()` |
| `testing::check_*` | Trait-contract checks for implementors (feature `testing`) |
| `testing::FakeLlm` | Scriptable offline `Llm` that records requests (feature `testing`) |

## Structured output, fallbacks and safe tool calls

```rust
use std::sync::Arc;
use rune_chain_core::{Llm, LlmExt, Message, ResponseFormat};
use serde_json::json;

// Try a second provider when the first one is down or rate-limited.
let llm = primary.with_fallbacks([Arc::new(backup) as Arc<dyn Llm>]);

let format = ResponseFormat::json_schema("answer", json!({
    "type": "object",
    "properties": { "value": { "type": "integer" } },
    "required": ["value"]
}));
let out = llm.generate_structured(&[Message::human("2 + 2?")], &format).await?;
let value = format.parse_json(&out.generation)?; // tolerates ```json fences, size-capped

// Tool-call arguments come from the model: check them before running the tool.
for call in &out.tool_calls {
    let args = call.validate(&tool.function_definition())?; // required keys, types, enums
}
```

`Arc<T>` implements `Llm`, `Chain`, `Tool` and `Memory` whenever `T` does, so a
single client can be shared across chains and agents.

## Combinators

Runnable-style helpers, all opt-in wrappers (nothing changes for code that
doesn't use them):

```rust
use std::{sync::Arc, time::Duration};
use rune_chain_core::{ChainExt, InMemoryLlmCache, LlmExt, Message, prompt_args};

// Many requests at once, results in input order, at most 8 in flight
// (or pick the limit with `batch_with_concurrency`).
let answers = llm.batch(&[vec![Message::human("a")], vec![Message::human("b")]]).await;
let outputs = chain.batch(vec![prompt_args! { "input" => "a" }]).await;

// Feed one chain's answer into the next (under its primary output key,
// or a key of your choice with `pipe_as`). Token usage is summed.
let pipeline = summarize.pipe_as(translate, "text");

// Always offer these tools; cache answers; report events; bound the time
// and retry transient failures (the last two need feature `tokio`).
let llm = provider
    .with_retry(3)                        // backoff, honours retry-after
    .with_timeout(Duration::from_secs(30))
    .with_cache(Arc::new(InMemoryLlmCache::new(1_000)))
    .with_callbacks(Arc::new(MyHandler))  // on_llm_start / end / error, …
    .bind_tools(tools);
```

- `batch` never runs more than the given number of calls at once (`0` means
  one) and borrows the conversations instead of cloning them.
- Callback events carry the prompts and outputs by reference, but their
  `Debug` output shows only sizes, names and token counts, so logging an
  event never writes prompt text.
- The cache key is the request's canonical JSON; `InMemoryLlmCache` compares
  the full key, so different prompts never collide. Give each model setup a
  `.namespace(…)` when several share one cache. `CacheKey::stable_hash()` is a
  stable 64-bit digest for external stores.
- `with_retry` is deliberately minimal (no jitter, no circuit breakers);
  `rune-chain-retry` covers those.

```toml
rune-chain-core = { version = "0.2", features = ["tokio"] }
```

## Security

- Tool-call arguments and structured output are treated as untrusted: parsing is
  size-capped (`MAX_TOOL_ARGUMENTS_BYTES`, `MAX_JSON_OUTPUT_BYTES`) and error
  messages never echo the raw input.
- `ImageData::validate` rejects non-`image/*` MIME types, malformed base64,
  oversized payloads and non-`http(s)`/`data:image` URLs (e.g. `file://`).
- `Debug` output of images elides base64 payloads, so logging messages does not
  leak image contents.

## Contract tests for implementors

Enable the `testing` feature in your dev-dependencies to check an `Llm`,
`Chain`, `Memory` or `Tool` implementation against the shared trait contracts
(well-formed tool calls, consistent token usage, streams that stop after their
final chunk, ordered memory history, valid tool metadata, …):

```toml
[dev-dependencies]
rune-chain-core = { version = "0.2", features = ["testing"] }
```

```rust
use rune_chain_core::testing::{check_llm, check_memory};

#[tokio::test]
async fn provider_meets_contract() {
    check_llm(&my_fixture_backed_client()).await.unwrap();
    check_memory(&MyMemory::default()).await.unwrap();
}
```

## Testing code that uses an `Llm`

`testing::FakeLlm` (same `testing` feature) is an offline `Llm` you script.
It answers from a queue of replies in order, records every request, and
returns an error, not a panic, when the script runs out:

```rust
use rune_chain_core::testing::{FakeLlm, FakeReply};
use rune_chain_core::{Llm, Message, TokenUsage, ToolCall};

let llm = FakeLlm::with_replies([
    FakeReply::tool_calls([ToolCall::new("call_1", "search", r#"{"q":"rust"}"#)]),
    FakeReply::text("Found it.").with_usage(TokenUsage::new(40, 3)),
    FakeReply::rate_limited(),
]);

run_my_agent(&llm).await?;

assert_eq!(llm.call_count(), 2);
assert_eq!(llm.requests()[0].prompt().as_deref(), Some("find rust crates"));
```

- Replies can be text, JSON (`FakeReply::json`), tool calls, refusals,
  truncated output, any `FinishReason`, token usage, or an `LlmError`
  (`rate_limited()`, `timeout()`, `provider_error(..)`, `error(..)`).
- `FakeLlm::from_fn(|req| ...)` answers per request instead; a responder set
  with `with_responder` also takes over once the queue is empty.
- `with_latency(..)` delays each call (runtime-agnostic), and
  `max_in_flight()` reports peak concurrency, for testing your limits.
- `stream()` sends the reply text in `with_chunk_chars(n)` pieces, then the
  final chunk; `with_stream_error(..)` fails part-way instead.
- Clones share the script and the recorded requests.

## Migrating from 0.1

- `LlmError` is a struct, not an enum. Build it with `LlmError::request_failed`, `provider`, `invalid_response`, `unsupported`, `other`, `timeout`, `from_status(status, msg)` or `new(kind, msg)`, plus `.with_status(..)` / `.with_retry_after(..)`.
  Match on `err.kind()` (`LlmErrorKind::RateLimit`, `Overloaded`, `Auth`, `InvalidRequest`, `ContextLengthExceeded`, `Timeout`, `Network`, `Server`, …) instead of variants, and read `message()`, `status()`, `retry_after()`, `is_retryable()`.
- `Display` is `"<kind>: <message>"`; `ToolUseNotSupported` became `LlmErrorKind::Unsupported`, and the default `Llm::stream` now fails with `Unsupported`.
- `TokenUsage`, `GenerateResult` and `Message` are `#[non_exhaustive]`: struct literals no longer compile outside this crate.
  Use `TokenUsage::new(p, c).with_total_tokens(t)`, `GenerateResult::from_text(..).with_tokens(..).with_tool_calls(..)` and `Message::new(..).with_tool_calls(..)`.
- New data: `TokenUsage::{cache_read_tokens, cache_creation_tokens, reasoning_tokens}` (subsets of the prompt and completion counts), `GenerateResult::finish_reason` (`FinishReason`), and `reasoning: Vec<ReasoningBlock>` on `GenerateResult` and `Message`.
  Reasoning never appears in `text()`; `to_message()` carries it so providers can send it back.
- `GenerateResult::with_tokens` takes a `TokenUsage` or an `Option<TokenUsage>`.
- `Pricing::cost` now prices cache reads and writes at their own rates, and `check_token_usage` also checks the breakdown fields.
- Old JSON (without the new fields) still deserialises.

## License

MIT
