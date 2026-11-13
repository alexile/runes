# rune-chain-anthropic

> Anthropic Claude LLM provider for the `rune-chain` framework.

[![crates.io](https://img.shields.io/crates/v/rune-chain-anthropic)](https://crates.io/crates/rune-chain-anthropic)
[![docs.rs](https://img.shields.io/docsrs/rune-chain-anthropic)](https://docs.rs/rune-chain-anthropic)
[![license](https://img.shields.io/crates/l/rune-chain-anthropic)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

## What it does

Implements the `Llm` trait from `rune-chain-core` for the Anthropic Messages API.
Works with any Claude model — the model is a free-form id — with both blocking
and token-streaming generation.
System messages are automatically extracted and sent in the Anthropic `system` field.

## Installation

```toml
[dependencies]
rune-chain-anthropic = "0.2"
rune-chain-core = "0.2"
```

## Usage

```rust,no_run
use rune_chain_anthropic::Anthropic;
use rune_chain_core::{Llm, Message};

#[tokio::main]
async fn main() {
    let llm = Anthropic::from_env().unwrap(); // reads ANTHROPIC_API_KEY

    let result = llm.generate(&[
        Message::system("You are a helpful assistant."),
        Message::human("What is the capital of France?"),
    ]).await.unwrap();

    println!("{}", result.generation); // "Paris"
}
```

Configure the model and output length:

```rust
use rune_chain_anthropic::{Anthropic, models};

let llm = Anthropic::new("sk-ant-...")
    .model(models::CLAUDE_OPUS_5_5) // or any id string, e.g. "claude-opus-5-5"
    .max_tokens(2048);
```

Without `.max_tokens(..)`, blocking calls ask for 16 000 tokens and streams for
64 000 (capped at a known model's output limit). Thinking tokens count against
this budget, and current models always think, so keep it generous.

`.base_url(..)` points the client at a gateway or proxy, and `.http_client(..)`
takes a preconfigured `reqwest::Client` (timeouts, proxies).

## Prompt caching

Mark stable prefixes with `cache_control` breakpoints — on the last tool
definition, the system prompt and/or the tail of the conversation — and read
cache hits from the full provider response:

```rust,no_run
use rune_chain_anthropic::{Anthropic, CachePolicy, CacheTtl};
use rune_chain_core::Message;

# async fn run() {
let llm = Anthropic::from_env().unwrap()
    .model("claude-sonnet-5-5")
    .cache(CachePolicy::none()
        .with_system(CacheTtl::OneHour)        // longer TTLs must come first
        .with_messages(CacheTtl::FiveMinutes));

let reply = llm
    .generate_message(&[Message::system("…long manual…"), Message::human("Q?")], &[], None)
    .await
    .unwrap();
let u = reply.usage();
println!("read {} / wrote {} cached tokens", u.cache_read_input_tokens, u.cache_creation_input_tokens);
# }
```

Through the portable `Llm` trait, `TokenUsage::prompt_tokens` is the whole
prompt (uncached + cache writes + cache reads). Prefixes below the model's
minimum cacheable length are silently not cached.

## Structured output

`generate_structured` uses native structured output (`output_config.format`,
constrained decoding) on models that support it, falls back to forced tool use
(the schema becomes a tool's input schema) on older models that accept a forced
tool choice, and to prompt instructions otherwise. Override with
`.structured_output(StructuredOutput::…)`. Refusals and answers cut off at
`max_tokens` are errors.

```rust,no_run
use rune_chain_anthropic::Anthropic;
use rune_chain_core::{Llm, Message, ResponseFormat};
use serde_json::json;

# async fn run() {
let llm = Anthropic::from_env().unwrap(); // claude-sonnet-5-5
let format = ResponseFormat::json_schema("city", json!({
    "type": "object",
    "properties": { "name": { "type": "string" } },
    "required": ["name"],
    "additionalProperties": false,
}));
let out = llm.generate_structured(&[Message::human("Capital of France?")], &format).await.unwrap();
let city = format.parse_json(&out.generation).unwrap();
# }
```

## Thinking, effort and token counting

```rust,no_run
use rune_chain_anthropic::{Anthropic, Effort, Thinking, ThinkingDisplay, models};
use rune_chain_core::Message;

# async fn run() {
let llm = Anthropic::from_env().unwrap()
    .model(models::CLAUDE_OPUS_5_5)
    .thinking(Thinking::adaptive().with_display(ThinkingDisplay::Summarized))
    .effort(Effort::High);

let msgs = [Message::human("Prove that √2 is irrational.")];
println!("prompt is {} tokens", llm.count_tokens(&msgs, &[]).await.unwrap());

let reply = llm.generate_message(&msgs, &[], None).await.unwrap();
println!("thought: {}\nanswer: {}", reply.thinking(), reply.text());
# }
```

Current models take adaptive thinking and steer depth with `effort`; a fixed
`Thinking::budget(n)` is accepted only by Claude Opus 4.6, Sonnet 4.6 and
Haiku 4.5, and models whose thinking is always on reject `Thinking::Disabled`.
For a known model, unsupported modes fail locally. Thinking blocks never leak
into `generation`/`text()`.

`stream_message` yields typed `StreamEvent`s — text and thinking fragments,
complete tool calls (streamed `input_json_delta` fragments assembled and
parsed), and finally the whole `MessageResponse` with usage.

## Security and reliability

- The API key is sent only as a sensitive `x-api-key` header; `Debug` prints
  `ApiKey([REDACTED])` and error messages are scrubbed of it.
- The base URL must be `https://` (plain `http://` only for localhost/loopback).
  The default HTTP client does not follow redirects, so the key never goes to
  another origin or over plain HTTP because of a `3xx`.
- Retries on 408/409/429/5xx/529 and connection errors (default 2), honouring
  `retry-after-ms`/`retry-after` up to 60 s, otherwise jittered backoff.
- Default timeouts (30 s connect, 10 min per blocking request / read), response
  bodies capped (32 MiB), error bodies truncated, and an SSE parser that turns
  any malformed or out-of-order stream into an error instead of panicking.

## Models

`rune_chain_anthropic::models` has a constant and a capability note
(`models::lookup(id)` → `ModelInfo`: context window, max output, vision, tool use,
sampling parameters, forced tool choice, always-on thinking) for each model:

| Constant | Id | Context | Max output | Notes |
|---|---|---|---|---|
| `CLAUDE_FABLE_5_2` | `claude-fable-5-2` | 1M | 128K | Most capable; thinking always on |
| `CLAUDE_OPUS_5_5` | `claude-opus-5-5` | 1M | 128K | Current Opus; thinking always on |
| `CLAUDE_SONNET_5_5` | `claude-sonnet-5-5` | 1M | 128K | Current Sonnet — **default** |
| `CLAUDE_HAIKU_5_5` | `claude-haiku-5-5` | 1M | 128K | Current Haiku |
| `CLAUDE_FABLE_5_1`, `CLAUDE_FABLE_5` | | 1M | 128K | Earlier Fable |
| `CLAUDE_OPUS_5`, `CLAUDE_OPUS_4_8`, `CLAUDE_OPUS_4_7`, `CLAUDE_OPUS_4_6` | | 1M | 128K | Earlier Opus |
| `CLAUDE_SONNET_5`, `CLAUDE_SONNET_4_6` | | 1M | 128K | Earlier Sonnet |
| `CLAUDE_HAIKU_4_5` | `claude-haiku-4-5` | 200K | 64K | Earlier Haiku |

Most current models reject a sampling `temperature`, and Fable 5.1/5.2, Opus 5.5
and Sonnet 5.5 accept only an automatic tool choice. `ModelInfo` also records
which thinking modes and whether native structured output each model supports. For a known model the client
rejects such a request locally (`LlmError::other`) instead of sending it; ids
the table does not know are always sent as-is.

## With `LlmChain`

```rust,no_run
use std::sync::Arc;
use rune_chain_anthropic::Anthropic;
use rune_chain_llm::LlmChain;
use rune_chain_prompt::{ChatTemplate, MessageTemplate};
use rune_chain_core::{Chain, prompt_args};

#[tokio::main]
async fn main() {
    let llm = Anthropic::from_env().unwrap();

    let chain = LlmChain::new(llm, ChatTemplate::new(vec![
        MessageTemplate::system("You are a concise assistant."),
        MessageTemplate::human("{question}"),
    ]));

    let answer = chain
        .invoke(prompt_args! { "question" => "What is 2 + 2?" })
        .await
        .unwrap();

    println!("{answer}");
}
```

## Migrating from 0.1

- Uses `rune-chain-core` 0.2, whose `LlmError`, `GenerateResult`, `TokenUsage` and `Message` changed; see its [migration notes](https://crates.io/crates/rune-chain-core).
- Errors are classified from the status and `error.type`: 429 is `RateLimit`, 529 / `overloaded_error` is `Overloaded`, `prompt is too long` is `ContextLengthExceeded`, …, with `status()` and the `Retry-After` delay.
- `to_generate_result` fills `finish_reason` (from `stop_reason`), the cache-read and cache-write token counts, and `reasoning` with thinking blocks and their signatures.
- Thinking blocks (signed or redacted) on earlier assistant turns are sent back first, so multi-turn tool use with extended thinking works through the `Llm` trait. Unsigned reasoning is dropped.

## License

MIT
