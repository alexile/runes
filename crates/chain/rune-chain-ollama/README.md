# rune-chain-ollama

> Ollama (local models) provider for the rune-chain framework — streaming, native tool calls, structured output, embeddings and model management.

[![crates.io](https://img.shields.io/crates/v/rune-chain-ollama)](https://crates.io/crates/rune-chain-ollama)
[![docs.rs](https://img.shields.io/docsrs/rune-chain-ollama)](https://docs.rs/rune-chain-ollama)
[![license](https://img.shields.io/crates/l/rune-chain-ollama)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

## What it does

`rune-chain-ollama` implements the [`Llm`](https://docs.rs/rune-chain-core/latest/rune_chain_core/trait.Llm.html)
trait from `rune-chain-core` and the [`Embedder`](https://docs.rs/rune-chain-embed/latest/rune_chain_embed/trait.Embedder.html)
trait from `rune-chain-embed` for an [Ollama](https://ollama.com) server. Any
model you have pulled with `ollama pull <model>` is usable; no API key needed.

- **Generation and streaming** over `/api/chat`, with token usage.
- **Native tool calling** (`tools`), including tool calls in streams via
  `stream_events`. `ToolChoice` is emulated (Ollama has none).
- **Native structured output**: `generate_structured` sends Ollama's `format`
  (a JSON Schema, or `"json"`).
- **Thinking models**: `.think(Think::On)` (or `Low`/`Medium`/`High`); the
  reasoning arrives as `StreamEvent::Thinking` and in `ChatReply::thinking`.
- **Vision**: base64 images (validated) for `llava`, `gemma3`, `qwen2.5vl`, …
- **Embeddings** via `/api/embed` with batch input.
- **Options**: `temperature`, `top_p`, `top_k`, `seed`, `stop`, `num_ctx`,
  `max_tokens`, any raw `option(..)`, and `keep_alive`.
- **Model management**: `list_models`, `show_model` (capabilities, context
  length), `pull_model` with a progress stream.
- **Hardened transport**: NDJSON parsing never panics and is capped per line
  (4 MiB) and per response (32 MiB); 10-minute request and 10-second connect
  timeouts; redirects not followed; plain HTTP only to loopback unless opted
  in; optional bearer token, redacted from `Debug` and errors.

## Installation

```toml
[dependencies]
rune-chain-ollama = "0.3"
rune-chain-core = "0.2"
```

## Usage

```rust,no_run
use rune_chain_ollama::Ollama;
use rune_chain_core::{Llm, Message};

let llm = Ollama::new();   // http://localhost:11434, llama3.2
let result = llm.generate(&[Message::human("What is the capital of France?")]).await?;
println!("{}", result.generation);
```

Configure the model and options:

```rust
use std::time::Duration;
use rune_chain_ollama::{KeepAlive, Ollama, Think};

let llm = Ollama::new()
    .model("qwen3:8b")
    .temperature(0.2)
    .seed(42)
    .num_ctx(16_384)          // Ollama's default context is small
    .max_tokens(512)
    .keep_alive(KeepAlive::For(Duration::from_secs(1800)))
    .think(Think::On);
```

Stream text, thinking and tool calls:

```rust,no_run
use futures::StreamExt;
use rune_chain_core::{FunctionDefinition, Message};
use rune_chain_ollama::{Ollama, StreamEvent};

let tools = [FunctionDefinition::single_input("search", "Search the web.")];
let mut events = Ollama::new()
    .stream_events(&[Message::human("Find Rust news.")], &tools, None)
    .await?;
while let Some(event) = events.next().await {
    match event? {
        StreamEvent::Text(t) => print!("{t}"),
        StreamEvent::ToolCalls(calls) => println!("\ncalls: {calls:?}"),
        _ => {}
    }
}
```

Structured output:

```rust,no_run
use rune_chain_core::{Llm, Message, ResponseFormat};
use serde_json::json;

let format = ResponseFormat::json_schema(
    "capital",
    json!({ "type": "object", "properties": { "city": { "type": "string" } }, "required": ["city"] }),
);
let out = llm.generate_structured(&[Message::human("Capital of France?")], &format).await?;
let value = format.parse_json(&out.generation)?;
```

Embeddings:

```rust,no_run
use rune_chain_embed::Embedder;
use rune_chain_ollama::Ollama;

let embedder = Ollama::new().model("nomic-embed-text");
let vectors = embedder.embed_batch(&["first", "second"]).await?;
```

Models:

```rust,no_run
let llm = rune_chain_ollama::Ollama::new();
for m in llm.list_models().await? {
    println!("{} {}", m.name, m.details.parameter_size);
}
let info = llm.show_model("llama3.2").await?;
assert!(info.supports("tools"));
```

### Images

Ollama's `images` field only takes base64 data. Pass images with
`ContentPart::image_base64` (or a base64 `data:` URL). A remote image URL is
rejected with `LlmError::other` before the request is sent: download and
encode the image first. Malformed or oversized images are rejected too.

## Security

Ollama has **no authentication**: anyone who can reach its port can run and
pull models and read prompts in flight. Keep it bound to loopback, or put it
behind a TLS reverse proxy that authenticates callers; `.bearer_token(..)`
sends `Authorization: Bearer …` for such proxies (Ollama itself ignores it).

Plain HTTP to a non-loopback host is refused unless you accept the exposure:

```rust
use rune_chain_ollama::Ollama;

let lan = Ollama::new()
    .base_url("http://gpu-box:11434")
    .allow_http_host("gpu-box");     // or .allow_insecure_http()
```

## Migrating from 0.2

- Uses `rune-chain-core` 0.2, whose `LlmError`, `GenerateResult`, `TokenUsage` and `Message` changed; see its [migration notes](https://crates.io/crates/rune-chain-core).
- Errors take their kind from the HTTP status (404 is `InvalidRequest`, a full queue's 503 is `Overloaded`, 5xx `Server`) and record `status()` and `Retry-After`.
- `GenerateResult` now carries `finish_reason` (from `done_reason`; `stop` with tool calls is `ToolCalls`) and the thinking as `reasoning`; assistant turns with reasoning send it back as `thinking`.
- Needs `rune-chain-embed` 0.2.

## Migrating from 0.1

0.2 changes default behaviour, so it is a breaking release:

- **Plain HTTP to a non-loopback host now fails** with `LlmError::other`. Add
  `.allow_http_host("<host>")` (or use https). Base URLs with embedded
  credentials (`http://user:pw@…`) are refused; use `.bearer_token(..)`.
- **Timeouts**: requests time out after 10 minutes (`.timeout(..)` /
  `.no_timeout()`), connections after 10 seconds. A custom `.http_client(..)`
  keeps its own connect timeout but still gets the request timeout.
- **Size caps**: responses over 32 MiB and stream lines over 4 MiB are errors
  (`.max_response_bytes(..)`, `.max_line_bytes(..)`).
- **Tool calling is native**: `generate_with_tools` now sends requests instead
  of returning `LlmError::unsupported`.
- **Structured output is native**: `generate_structured` sends `format`.
- **Images are validated**: malformed base64, non-`image/*` MIME types and
  images over the default size cap are rejected before sending.
- Error messages from the server are truncated to 512 characters.
- Redirects are not followed by the default HTTP client.

## License

MIT
