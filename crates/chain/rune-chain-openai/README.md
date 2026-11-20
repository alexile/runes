# rune-chain-openai

> OpenAI and OpenAI-compatible LLM provider for the rune-chain framework — Azure OpenAI, Mistral, Groq, Together, DeepSeek, OpenRouter, vLLM and LM Studio; streaming, tool calls and native structured output.

[![crates.io](https://img.shields.io/crates/v/rune-chain-openai)](https://crates.io/crates/rune-chain-openai)
[![docs.rs](https://img.shields.io/docsrs/rune-chain-openai)](https://docs.rs/rune-chain-openai)
[![license](https://img.shields.io/crates/l/rune-chain-openai)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

## What it does

`rune-chain-openai` implements the [`Llm`](https://docs.rs/rune-chain-core/latest/rune_chain_core/trait.Llm.html)
trait from `rune-chain-core` for the chat completions API of OpenAI and of any
server that speaks its dialect. Pass any slice of `Message`s and get back a
`GenerateResult` with the text, tool calls and token usage; stream tokens via a
`futures::Stream`; or ask for JSON that matches a schema.

- **OpenAI-compatible presets** with per-provider quirks (auth header, token-limit
  field, `stream_options`, `response_format` support) — see the table below.
- **Native structured output**: `generate_structured` sends
  `response_format: json_schema` (strict) where supported and falls back to JSON
  mode or prompting elsewhere.
- **Streaming events**: `stream_events` yields text, fully assembled tool calls,
  the finish reason and token usage (`stream_options.include_usage`).
- **Audio and images**: `TranscriptionModel` (`/audio/transcriptions`, multipart
  upload capped at 25 MiB), `ImageGenerationModel` (`/images/generations`, base64
  decoded, `https`-only URLs) and `SpeechModel` (`/audio/speech`), with a 64 MiB
  cap on media responses.
- **Hardened transport**: the API key never appears in `Debug` output or errors and
  is sent as a sensitive header; HTTPS is required except to loopback or explicitly
  allowed hosts; redirects are not followed; 10-minute request timeout; 32 MiB
  response cap; error bodies truncated; retries (2 by default) only on 429/5xx,
  honouring `Retry-After`/`retry-after-ms`.

## Installation

```toml
[dependencies]
rune-chain-openai = "0.2"
rune-chain-core = "0.2"
```

## Usage

Blocking generation:

```rust,no_run
use rune_chain_openai::OpenAi;
use rune_chain_core::{Llm, Message};

let llm = OpenAi::from_env()?;  // reads OPENAI_API_KEY

let result = llm.generate(&[
    Message::system("You are a helpful assistant."),
    Message::human("What is the capital of France?"),
]).await?;

println!("{}", result.generation);
if let Some(usage) = result.tokens {
    println!("tokens: {}", usage.total_tokens);
}
```

Streaming generation:

```rust,no_run
use rune_chain_openai::OpenAi;
use rune_chain_core::{Llm, Message};
use futures::StreamExt;

let llm = OpenAi::from_env()?;
let mut stream = llm.stream(&[Message::human("Count to five.")]).await?;

while let Some(chunk) = stream.next().await {
    let data = chunk?;
    if data.is_finished { break; }
    print!("{}", data.content);
}
```

Tool calls and usage while streaming:

```rust,no_run
use rune_chain_openai::{OpenAi, collect_events};
use rune_chain_core::{FunctionDefinition, Message};

let llm = OpenAi::from_env()?;
let tools = [FunctionDefinition::single_input("search", "Search the web.")];
let events = llm.stream_events(&[Message::human("Find rust news")], &tools, None).await?;
let result = collect_events(events).await?; // text, reasoning, tool calls, finish reason, usage
```

Structured output:

```rust,no_run
use rune_chain_core::{Llm, Message, ResponseFormat};
use serde_json::json;

let format = ResponseFormat::json_schema("city", json!({
    "type": "object",
    "properties": { "name": { "type": "string" } },
    "required": ["name"],
    "additionalProperties": false
}));
let out = llm.generate_structured(&[Message::human("Capital of France?")], &format).await?;
let value = format.parse_json(&out.generation)?;
```

Builder options:

```rust,no_run
use std::time::Duration;
use rune_chain_openai::OpenAi;

let llm = OpenAi::new("sk-...")
    .model("gpt-4.1-mini")      // default: gpt-5-mini; or a `models::` constant
    .temperature(0.2)            // non-reasoning models only
    .max_tokens(512)             // `max_completion_tokens` or `max_tokens` per provider
    .timeout(Duration::from_secs(120))
    .max_retries(3)              // 429/5xx only
    .max_response_bytes(8 << 20)
    .header("OpenAI-Organization", "org-...");
```

`.http_client(..)` takes a preconfigured `reqwest::Client` (proxies, TLS).

## OpenAI-compatible providers

| Constructor | Base URL | Key env var | Default model | JSON Schema |
|---|---|---|---|---|
| `OpenAi::new` / `from_env` | `https://api.openai.com/v1` | `OPENAI_API_KEY` | `gpt-5-mini` | native |
| `OpenAi::azure(endpoint, deployment, key)` | `{endpoint}/openai/deployments/{deployment}` + `api-version` | `AZURE_OPENAI_API_KEY` (`api-key` header) | deployment | native |
| `OpenAi::mistral` | `https://api.mistral.ai/v1` | `MISTRAL_API_KEY` | `mistral-small-latest` | native |
| `OpenAi::groq` | `https://api.groq.com/openai/v1` | `GROQ_API_KEY` | `llama-3.3-70b-versatile` | native |
| `OpenAi::together` | `https://api.together.xyz/v1` | `TOGETHER_API_KEY` | `meta-llama/Llama-3.3-70B-Instruct-Turbo` | JSON mode + prompt |
| `OpenAi::deepseek` | `https://api.deepseek.com/v1` | `DEEPSEEK_API_KEY` | `deepseek-chat` | JSON mode + prompt |
| `OpenAi::openrouter` | `https://openrouter.ai/api/v1` | `OPENROUTER_API_KEY` | `openrouter/auto` | native |
| `OpenAi::vllm(url, model)` | e.g. `http://localhost:8000/v1` | optional `VLLM_API_KEY` | — | native |
| `OpenAi::lm_studio(model)` | `http://localhost:1234/v1` | none | — | native |

`OpenAi::for_provider(Provider::X, key)` and `OpenAi::from_provider_env(Provider::X)`
build the same presets; `OpenAi::azure_from_env(deployment)` reads
`AZURE_OPENAI_ENDPOINT`, `AZURE_OPENAI_API_KEY` and optional `OPENAI_API_VERSION`
(default `2024-10-21`). Any other server works with `.base_url(..)`, and
`.quirks(Provider::X.quirks().with_json_schema(false))` adjusts the wire format
when a particular model lacks a feature.

Plain `http://` is accepted only for `localhost`/loopback addresses unless you opt
in with `.allow_http_host("gpu-box")`.

## Environment

Set your API key before running:

```bash
export OPENAI_API_KEY=sk-...
```

## Supported models

Any model accepted by `/v1/chat/completions` — the model is a free-form id.
`rune_chain_openai::models` has constants and a capability note
(`models::lookup(id)` → `ModelInfo`: context window, max output, vision, tool
calling, reasoning, sampling parameters, list pricing) for:

| Constant | Id | Context | Max output | Kind |
|---|---|---|---|---|
| `GPT_5_2` | `gpt-5.2` | 400K | 128K | reasoning |
| `GPT_5_1` | `gpt-5.1` | 400K | 128K | reasoning |
| `GPT_5` | `gpt-5` | 400K | 128K | reasoning |
| `GPT_5_MINI` | `gpt-5-mini` | 400K | 128K | reasoning — **default** |
| `GPT_5_NANO` | `gpt-5-nano` | 400K | 128K | reasoning |
| `GPT_4_1`, `GPT_4_1_MINI`, `GPT_4_1_NANO` | `gpt-4.1`, … | 1M | 32K | non-reasoning |
| `GPT_4O`, `GPT_4O_MINI` | `gpt-4o`, `gpt-4o-mini` | 128K | 16K | non-reasoning |
| `O3`, `O4_MINI` | `o3`, `o4-mini` | 200K | 100K | reasoning |

Reasoning models accept only the default temperature, and their hidden reasoning
tokens count against `max_tokens`. For a known reasoning model the client rejects
a set temperature locally (`LlmError::other`); unknown ids are sent as-is.

## Migrating from 0.1

- Uses `rune-chain-core` 0.2, whose `LlmError`, `GenerateResult`, `TokenUsage` and `Message` changed; see its [migration notes](https://crates.io/crates/rune-chain-core).
- Errors are classified: HTTP status and `error.code` set `LlmError::kind()` (`insufficient_quota` is `Auth`, `context_length_exceeded` is `ContextLengthExceeded`, …), with `status()` and the `Retry-After` delay. A non-JSON error body is no longer `request_failed`; it gets the kind of its status.
- A refusal is no longer an error from `generate`: the result carries the refusal text with `finish_reason == Some(FinishReason::Refusal)`. `generate_structured` still fails on a refusal.
- Results report `finish_reason`, cached prompt tokens (`prompt_tokens_details.cached_tokens`), reasoning tokens, and `reasoning_content` from compatible servers as `GenerateResult::reasoning`.

## License

MIT
