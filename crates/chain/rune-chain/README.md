# rune-chain

> One dependency for LLM apps in Rust: OpenAI/Anthropic/Gemini/Ollama clients, agents with tools, RAG and memory, typed extraction and streaming.

[![crates.io](https://img.shields.io/crates/v/rune-chain)](https://crates.io/crates/rune-chain)
[![docs.rs](https://img.shields.io/docsrs/rune-chain)](https://docs.rs/rune-chain)
[![license](https://img.shields.io/crates/l/rune-chain)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

## Quick start

```toml
[dependencies]
rune-chain = "0.1"
tokio = { version = "1", features = ["macros", "rt-multi-thread"] }
```

```rust,no_run
use rune_chain::{openai, prelude::*};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = openai::Client::from_env()?;
    let comedian = client.agent("gpt-4o-mini").preamble("You are a comedian.").build();
    println!("{}", comedian.prompt("Entertain me!").await?);
    Ok(())
}
```

Tools are plain functions with `#[tool]`:

```rust,no_run
use rune_chain::{openai, prelude::*};

/// Add two integers.
#[tool]
fn add(
    /// The first number.
    a: i64,
    /// The second number.
    b: i64,
) -> i64 {
    a + b
}

# async fn run() -> Result<(), Box<dyn std::error::Error>> {
let agent = openai::Client::from_env()?.agent("gpt-4o-mini").tool(Add).build();
println!("{}", agent.prompt("What is 2 + 40?").await?);
# Ok(())
# }
```

## What it does

`rune-chain` is the front door to the `rune-chain-*` crates. It adds a small ergonomic layer and
re-exports the rest of the stack behind cargo features:

- **Clients.** `openai::Client`, `anthropic::Client`, `gemini::Client` and `ollama::Client`, each with `from_env()`.
  `CompletionClient` gives you `.completion_model(name)`, `.agent(name)` and `.extractor::<T>(name)`.
  `EmbeddingsClient` gives you `.embedding_model(name)` (OpenAI, Gemini, Ollama).
  `TranscriptionClient`, `ImageGenerationClient` and `SpeechClient` give you
  `.transcription_model(name)`, `.image_generation_model(name)` and `.speech_model(name)`
  (OpenAI for all three, Gemini for images and speech).
- **Agents.** `AgentBuilder` takes a preamble, static documents, tools, per-prompt RAG, memory,
  sampling settings and limits. `Agent` has `.prompt()`, `.chat()`, `.stream_prompt()` and
  `.stream_events()`. Streaming works with tools too: tokens stream in every turn.
- **Tools that can't run away.** With tools, the agent runs the multi-turn loop from
  `rune-chain-agent`. Every call is checked against the tool's JSON Schema before it runs. Calls run
  under limits on rounds, calls per round, concurrency, time and output size. Tool output is fenced
  as untrusted data, and sensitive tools can require approval.
- **`#[tool]` functions.** Put `#[tool]` on a plain or `async fn` and pass the generated struct
  to `.tool(..)`. The JSON Schema comes from the argument types and the doc comments. Use
  `#[derive(Embed)]` (`rune_chain::embed::Embed`) to mark the fields of a struct to embed.
- **Typed tools.** Implement `TypedTool` with an `Args` struct. The schema is derived with
  `schemars`, and nested fields are validated too.
- **RAG.** `.dynamic_context(n, index)` retrieves the top `n` documents for each prompt from any
  retriever: `EmbeddingIndex` (any `VectorStore` plus any `Embedder`), BM25, hybrid or reranked.
  Retrieved text is fenced, tag-escaped and capped at 32 000 characters per prompt.
- **Typed extraction.** `client.extractor::<T>(model).build()?.extract(text)` returns a `T`. The
  answer is validated against the full JSON Schema and your own validators, and the model is asked
  again with the error when the answer doesn't fit.
- **Composable.** `Agent` implements `Chain`, so it works with `pipe`, `batch`, `with_fallbacks`,
  callbacks and caching. It also implements `Tool`, so one agent can be a tool of another.
- **Offline tests.** With the `testing` feature, `testing::FakeLlm` scripts replies, tool calls,
  errors and streams.

## Coming from rig or LangChain

| rig | LangChain | rune-chain |
|---|---|---|
| `openai::Client::from_env()` | `ChatOpenAI()` | `openai::Client::from_env()?` |
| `client.agent(m).preamble(p).build()` | `create_agent(model, prompt=p)` | `client.agent(m).preamble(p).build()` |
| `agent.prompt(q).await` | `agent.invoke(...)` | `agent.prompt(q).await` |
| `agent.chat(q, history)` | `RunnableWithMessageHistory` | `agent.chat(q, history)` or `.memory(m)` |
| `.context(doc)` | system prompt with docs | `.context(doc)` |
| `.dynamic_context(n, index)` | retriever + `create_retrieval_chain` | `.dynamic_context(n, index)` |
| `#[rig_tool]` fn | `@tool` | `#[tool]` fn, then `.tool(Add)` |
| `.tool(T)` (`rig::tool::Tool`) | `BaseTool` | `.typed_tool(T)` (`TypedTool`) or `.tool(T)` (`Tool`) |
| `.multi_turn(n)` | `recursion_limit` | `.max_turns(n)` |
| `client.extractor::<T>(m).build()` | `with_structured_output(T)` | `client.extractor::<T>(m).build()?` |
| `agent.stream_prompt(q)` | `.stream(...)` | `agent.stream_prompt(q).await?` |
| `MultiTurnStreamItem` | `astream_events` | `agent.stream_events(q).await?` (`AgentStreamItem`) |
| `InMemoryVectorStore` + `.index(embedder)` | `InMemoryVectorStore` | `EmbeddingIndex::new(embedder, store)` |
| agent as a tool | agent as a tool | `.tool(other_agent)` |
| `client.transcription_model(m)` | `OpenAIWhisperParser` | `client.transcription_model(m)` |
| `client.image_generation_model(m)` | `DallEAPIWrapper` | `client.image_generation_model(m)` |
| `client.audio_generation_model(m)` | `OpenAI TTS` | `client.speech_model(m)` |

## Usage

### An agent with tools

```rust,no_run
use rune_chain::{openai, prelude::*};
use serde::Deserialize;

#[derive(Deserialize, JsonSchema)]
struct Args {
    /// City name.
    city: String,
}

struct Weather;

#[async_trait::async_trait]
impl TypedTool for Weather {
    type Args = Args;
    type Output = String;
    fn name(&self) -> &str { "weather" }
    fn description(&self) -> &str { "Current weather for a city." }
    async fn call(&self, args: Args) -> Result<String, ToolError> {
        Ok(format!("Sunny and 21 °C in {}", args.city))
    }
}

# async fn run() -> Result<(), Box<dyn std::error::Error>> {
let agent = openai::Client::from_env()?
    .agent("gpt-4o-mini")
    .preamble("You are a travel assistant.")
    .typed_tool(Weather)
    .max_turns(5)
    .temperature(0.2)
    .build();
let answer = agent.prompt("Should I pack an umbrella for Lisbon?").await?;
# Ok(())
# }
```

### RAG

```rust,no_run
use rune_chain::{openai, prelude::*, vectorstore::InMemoryVectorStore};

# async fn run() -> Result<(), Box<dyn std::error::Error>> {
let client = openai::Client::from_env()?;
let index = EmbeddingIndex::new(
    client.embedding_model("text-embedding-3-small"),
    InMemoryVectorStore::default(),
);
index.add_documents([("faq-1", "Refunds take 5 business days.")]).await?;

let support = client
    .agent("gpt-4o-mini")
    .preamble("Answer from the documents only.")
    .dynamic_context(3, index)
    .build();
let reply = support.prompt_with_details("How long do refunds take?").await?;
println!("{} (sources: {})", reply.output, reply.documents.len());
# Ok(())
# }
```

### Extraction

```rust,no_run
use rune_chain::{openai, prelude::*};
use serde::Deserialize;

#[derive(Deserialize, JsonSchema)]
struct Person { name: String, age: u32 }

# async fn run() -> Result<(), Box<dyn std::error::Error>> {
let person: Person = openai::Client::from_env()?
    .extractor::<Person>("gpt-4o-mini")
    .build()?
    .extract("Ada Lovelace was 36.")
    .await?;
# Ok(())
# }
```

### Streaming

```rust,no_run
use futures::StreamExt;
use rune_chain::{anthropic, prelude::*};

# async fn run() -> Result<(), Box<dyn std::error::Error>> {
let agent = anthropic::Client::from_env()?.agent("claude-sonnet-5-5").build();
let mut stream = agent.stream_prompt("Write a haiku about Rust.").await?;
while let Some(chunk) = stream.next().await {
    print!("{}", chunk?.content);
}
# Ok(())
# }
```

Tokens arrive as the provider streams them, with or without tools. With tools, each turn streams:
the text the model writes before calling tools, then (after the tools run) the next turn, up to
the answer. Tool calls run under the same checks and limits as `prompt`.

To see the tool calls as well, use `stream_events`. It yields `AgentStreamItem`s: `Text`,
`Reasoning`, `ToolCall` (as soon as the model starts one), `ToolResult` and finally `Final` with
the full `AgentResponse`:

```rust,no_run
use futures::StreamExt;
use rune_chain::{AgentStreamItem, anthropic, prelude::*};

# async fn run(search: impl Tool + 'static) -> Result<(), Box<dyn std::error::Error>> {
let agent = anthropic::Client::from_env()?
    .agent("claude-sonnet-5-5")
    .tool(search)
    .build();
let mut stream = agent.stream_events("What's new in Rust 2024?").await?;
while let Some(item) = stream.next().await {
    match item? {
        AgentStreamItem::Text(t) => print!("{t}"),
        AgentStreamItem::ToolCall { name, .. } => println!("\n[calling {name}]"),
        AgentStreamItem::ToolResult { invocation, .. } => println!("[{}]", invocation.status),
        AgentStreamItem::Final(response) => println!("\n({} tool calls)", response.tool_calls.len()),
        _ => {}
    }
}
# Ok(())
# }
```

Underneath, `Llm::stream_events` streams one model reply as typed `StreamEvent`s (text,
reasoning, tool-call starts and argument fragments, usage, finish reason) and
`StreamAccumulator` folds them back into a `GenerateResult`. The OpenAI, Anthropic, Gemini and
Ollama clients stream tool calls natively; any other `Llm` falls back to one whole reply.

### Audio and images

```rust,no_run
use rune_chain::{openai, prelude::*};

# async fn run() -> Result<(), Box<dyn std::error::Error>> {
let client = openai::Client::from_env()?;
let audio = std::fs::read("memo.m4a")?;
let text = client
    .transcription_model("gpt-4o-transcribe")
    .transcribe(&TranscriptionRequest::new(audio, "memo.m4a").language("en"))
    .await?
    .text;
let picture = client
    .image_generation_model("gpt-image-1")
    .generate_image(&ImageGenerationRequest::new(&text).size("1024x1024"))
    .await?;
let speech = client
    .speech_model("gpt-4o-mini-tts")
    .synthesize(&SpeechRequest::new(text, "coral"))
    .await?;
# let _ = (picture, speech);
# Ok(())
# }
```

Uploads, base64 images and audio bodies are size-capped, image URLs must be `https`, and the key
never shows up in errors.

### Without `serde` and `schemars` in your Cargo.toml

`rune-chain` re-exports both. Point the derives at them:

```rust
use rune_chain::schemars::{self, JsonSchema};
use rune_chain::serde::{self, Deserialize};

#[derive(Deserialize, JsonSchema)]
#[serde(crate = "rune_chain::serde")]
#[schemars(crate = "rune_chain::schemars")]
struct Person { name: String }
```

More in [`examples/`](examples): `agent_with_tools`, `tool_macro`, `rag`, `extractor`, `streaming` and `multimodal`.

## Builder API

| Method | Description |
|---|---|
| `.preamble(s)` | System prompt |
| `.context(doc)` | A document the agent always sees, fenced as data |
| `.tool(t)` / `.tools(boxed)` / `.typed_tool(t)` | Tools; any `Tool`, including another `Agent` |
| `.tool_requiring_approval(t)` / `.approver(a)` | Tools that run only when approved |
| `.dynamic_context(n, index)` | Top-`n` retrieved documents per prompt (feature `retrieval`) |
| `.max_context_chars(n)` | Cap on retrieved context per prompt (default 32 000) |
| `.temperature(t)` / `.max_tokens(n)` | Sampling, for provider models |
| `.max_turns(n)` / `.limits(AgentLimits)` | Tool-loop limits (default 10 rounds) |
| `.tool_choice(c)` / `.tool_error_mode(m)` / `.on_event(f)` | Tool-loop behaviour and events |
| `.memory(m)` | Conversation memory used by `prompt`, `stream_prompt` and `stream_events` |
| `.name(s)` / `.description(s)` | How the agent looks when used as a tool |

`Agent` methods: `prompt`, `prompt_with_details`, `chat`, `chat_with_details`, `stream_prompt`, `stream_chat`,
`stream_events`, `stream_chat_events`.
`*_with_details` returns usage, tool calls, rounds, the stop reason and the retrieved documents.

## Features

| Feature | Default | What it adds |
|---|---|---|
| `openai` | yes | `openai`: OpenAI and compatible APIs (Groq, Mistral, DeepSeek, OpenRouter, vLLM, LM Studio), embeddings |
| `anthropic` | | `anthropic`: Claude |
| `gemini` | | `gemini`: Gemini API and Vertex AI, embeddings |
| `ollama` | | `ollama`: local models and embeddings |
| `embed` | via `openai`/`gemini`/`ollama` | `embed`: `Embedder`, Cohere/Voyage/Jina embedders, batching, caching |
| `vectorstore` | | `vectorstore`: exact and HNSW in-memory stores, filters, snapshots |
| `qdrant` | | `qdrant`: `QdrantStore`, a Qdrant-backed `VectorStore` |
| `pgvector` | | `pgvector`: Postgres + pgvector store (`PgVectorStore`), HNSW or IVFFlat |
| `sqlite` | | `sqlite`: embedded single-file SQLite store (`SqliteVectorStore`), exact search |
| `retrieval` | | `retrieval`, `dynamic_context`, `EmbeddingIndex`: BM25, hybrid, MMR, reranking |
| `eval` | | `eval`: datasets, heuristic, LLM-as-judge, RAG and trajectory metrics, run comparison for CI |
| `graph` | | `graph`: `StateGraph`, checkpoints, human-in-the-loop interrupts, `create_react_agent` (with `sqlite`, `SqliteCheckpointer`) |
| `mcp` | | `mcp`: MCP client and server; remote tools as agent tools |
| `otel` | | `otel`: OpenTelemetry GenAI spans |
| `macros` | yes | `#[tool]` (`rune_chain::tool`) and, with `embed`, `#[derive(Embed)]` (`rune_chain::embed::Embed`) |
| `tokio` | | `.with_timeout(..)` / `.with_retry(..)` on any `Llm` or `Chain` |
| `testing` | | `testing::FakeLlm` and trait-contract checks |
| `full` | | Everything except `testing` |

Always included: core traits and combinators (re-exported at the root), plus `agent`, `memory`,
`prompt`, `output_parser` and `tool_schema`.

## License

MIT
