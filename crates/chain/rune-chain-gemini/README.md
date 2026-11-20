# rune-chain-gemini

> Google Gemini LLM provider for the rune-chain framework — Gemini API and Vertex AI; streaming, function calling, structured output, thinking, safety settings and embeddings.

[![crates.io](https://img.shields.io/crates/v/rune-chain-gemini)](https://crates.io/crates/rune-chain-gemini)
[![docs.rs](https://img.shields.io/docsrs/rune-chain-gemini)](https://docs.rs/rune-chain-gemini)
[![license](https://img.shields.io/crates/l/rune-chain-gemini)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

## What it does

`rune-chain-gemini` implements the `Llm` trait from `rune-chain-core` for
Gemini's `generateContent` and `streamGenerateContent` (server-sent events)
endpoints. Any model id works; `models` has constants, capability notes and list
prices for the current Gemini 2.x and 3.x models.

- **Messages**: system messages become `systemInstruction`; turns map to
  `contents` with Gemini's `user` / `model` roles, consecutive same-role turns
  merged; images go as `inlineData` (base64, `data:` URLs) or `fileData`.
- **Function calling**: tools become `functionDeclarations`, their JSON Schema
  converted to Gemini's OpenAPI subset by `rune-tool-schema` (`$ref` inlining
  with depth and size caps, `nullable`, `anyOf`, `const` as a one-value enum,
  `additionalProperties` and other unsupported keywords removed). A schema
  Gemini cannot express (a recursive one, say) fails before any request.
  `ToolChoice` maps to `toolConfig.functionCallingConfig`; `functionCall` /
  `functionResponse` round trips keep call ids and thought signatures.
- **Structured output**: `generate_structured` sends
  `responseMimeType: application/json` and a converted `responseSchema`.
- **Generation settings**: temperature, `topP`, `topK`, `maxOutputTokens`, stop
  sequences, seed, safety settings, and thinking (a budget or a level, with
  thought summaries returned as `ReasoningBlock`s).
- **Usage and finish reasons**: `usageMetadata` maps to `TokenUsage` with cached
  and thinking tokens; `SAFETY`, `RECITATION` and the other filters map to
  `FinishReason::ContentFilter`, `MAX_TOKENS` to `Length`. A blocked prompt
  (`promptFeedback.blockReason`) is an error.
- **Embeddings** (feature `embed`): `GeminiEmbedder` implements rune-chain-embed's
  `Embedder` over `embedContent` / `batchEmbedContents`.
- **Hardened transport**: the API key goes only in the `x-goog-api-key` header,
  never in the URL, and never appears in `Debug` output or errors; HTTPS is
  required except to loopback; redirects are not followed; model ids are checked
  before they go into the URL path; bodies are capped (32 MiB), as are SSE lines,
  events and streamed content; retries (2 by default) on 408/429/5xx honour
  `Retry-After` and Google's `RetryInfo`.

## Installation

```toml
[dependencies]
rune-chain-gemini = "0.1"
rune-chain-core = "0.2"
```

## Usage

```rust,no_run
use rune_chain_core::{Llm, Message};
use rune_chain_gemini::Gemini;

#[tokio::main]
async fn main() {
    let llm = Gemini::from_env().unwrap(); // reads GEMINI_API_KEY

    let result = llm.generate(&[
        Message::system("You are a helpful assistant."),
        Message::human("What is the capital of France?"),
    ]).await.unwrap();

    println!("{}", result.generation);
}
```

Configure the model and generation:

```rust
use rune_chain_gemini::{Gemini, HarmBlockThreshold, HarmCategory, Thinking, ThinkingLevel, models};

let flash = Gemini::new("AIza...")
    .model(models::GEMINI_2_5_FLASH)
    .temperature(0.3)
    .max_output_tokens(4096)
    .thinking(Thinking::budget(2048).with_thoughts())
    .safety(HarmCategory::DangerousContent, HarmBlockThreshold::BlockOnlyHigh);

let pro3 = Gemini::new("AIza...")
    .model(models::GEMINI_3_PRO_PREVIEW)
    .thinking(Thinking::level(ThinkingLevel::Low));
```

Thinking settings a known model is documented to reject (turning thinking off
on Gemini 2.5 Pro, a budget outside its range, a level on a 2.5 model) fail
locally. Unknown model ids are sent as they are.

### Vertex AI

```rust
use rune_chain_gemini::Gemini;

// An OAuth access token, e.g. from `gcloud auth print-access-token`.
let llm = Gemini::vertex_ai("my-project", "us-central1", "ya29....").unwrap();
```

### Embeddings

```toml
rune-chain-gemini = { version = "0.1", features = ["embed"] }
```

```rust,ignore
use rune_chain_embed::Embedder;
use rune_chain_gemini::Gemini;

let embedder = Gemini::from_env()?.embedder("gemini-embedding-001").dimensions(768);
let docs = embedder.embed_documents(&["first", "second"]).await?;
let query = embedder.embed_query("which one?").await?;
```

Queries are embedded as `RETRIEVAL_QUERY` and documents as `RETRIEVAL_DOCUMENT`.
Vectors truncated below the model's full size are not unit length; normalise
them before dot-product search.

## Thought signatures

Gemini attaches opaque thought signatures to response parts and wants them back
on the next turn; Gemini 3 rejects function-calling turns without them. They
ride in `GenerateResult::reasoning` (`to_message()` keeps them) and go back where
Gemini put them. Function calls that arrive without an id get one starting with
`gemini_call_`, which is not sent back.

## Environment

```bash
export GEMINI_API_KEY=AIza...   # or GOOGLE_API_KEY
```

## Supported models

Any model accepted by `generateContent`. `rune_chain_gemini::models` has notes
(`models::lookup(id)` → `ModelInfo`: context window, max output, thinking
support, list prices) for:

| Constant | Id | Max output | Thinking | $ / MTok in · out |
|---|---|---|---|---|
| `GEMINI_3_PRO_PREVIEW` | `gemini-3-pro-preview` | 64K | level (low, high), always on | 2 · 12 (4 · 18 above 200K) |
| `GEMINI_3_FLASH_PREVIEW` | `gemini-3-flash-preview` | 64K | level (minimal to high) | 0.50 · 3 |
| `GEMINI_2_5_PRO` | `gemini-2.5-pro` | 64K | budget 128–32768, always on | 1.25 · 10 (2.50 · 15 above 200K) |
| `GEMINI_2_5_FLASH` | `gemini-2.5-flash` | 64K | budget 1–24576 or off — **default** | 0.30 · 2.50 |
| `GEMINI_2_5_FLASH_LITE` | `gemini-2.5-flash-lite` | 64K | budget 512–24576 or off | 0.10 · 0.40 |
| `GEMINI_2_0_FLASH` | `gemini-2.0-flash` | 8K | none | 0.10 · 0.40 |
| `GEMINI_2_0_FLASH_LITE` | `gemini-2.0-flash-lite` | 8K | none | 0.075 · 0.30 |

Prices are Gemini API paid-tier list prices as of `models::PRICES_AS_OF`
(2026-01); `ModelInfo::cost` picks the long-context tier for prompts above 200K
tokens. Every model has a 1M-token context window.

## License

MIT
