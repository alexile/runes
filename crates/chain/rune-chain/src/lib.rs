//! One dependency for LLM apps in Rust: provider clients, agents with tools,
//! RAG, memory, typed extraction and streaming.
//!
//! `rune-chain` is the entry point to the `rune-chain-*` crates. It adds a
//! small ergonomic layer (clients, [`AgentBuilder`], [`Agent`],
//! [`Extractor`], [`TypedTool`], [`EmbeddingIndex`]) and re-exports the rest
//! of the stack behind cargo features.
//!
//! # Quick start
//!
//! ```rust,no_run
//! use rune_chain::prelude::*;
//! use rune_chain::openai;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let client = openai::Client::from_env()?;
//!     let comedian = client.agent("gpt-4o-mini").preamble("You are a comedian.").build();
//!     println!("{}", comedian.prompt("Entertain me!").await?);
//!     Ok(())
//! }
//! ```
//!
//! Tools are plain functions with `#[tool]` (feature `macros`, on by
//! default):
//!
//! ```rust,no_run
//! use rune_chain::{openai, prelude::*};
//!
//! /// Add two integers.
//! #[tool]
//! fn add(
//!     /// The first number.
//!     a: i64,
//!     /// The second number.
//!     b: i64,
//! ) -> i64 {
//!     a + b
//! }
//!
//! # async fn run() -> Result<(), Box<dyn std::error::Error>> {
//! let agent = openai::Client::from_env()?.agent("gpt-4o-mini").tool(Add).build();
//! println!("{}", agent.prompt("What is 2 + 40?").await?);
//! # Ok(())
//! # }
//! ```
//!
//! # What you get
//!
//! - **Clients**: `openai::Client`, `anthropic::Client`, `gemini::Client`,
//!   `ollama::Client`, each with `from_env()`. [`CompletionClient`] hands
//!   out models, agents and extractors by name; [`EmbeddingsClient`] hands
//!   out embedders.
//! - **Agents**: [`AgentBuilder`] takes a preamble, static documents
//!   (`.context`), tools (`.tool`, `.typed_tool`), per-prompt RAG
//!   (`.dynamic_context`), memory, sampling settings and limits. With tools
//!   the agent runs the hardened multi-turn loop from `rune-chain-agent`:
//!   arguments are validated against the tool schema, calls run under time
//!   and size limits, and tool output is fenced as untrusted data.
//! - **[`Agent`]**: `.prompt()`, `.chat()`, `.stream_prompt()`. It is also a
//!   [`Chain`] and a [`Tool`], so agents compose into pipelines and into
//!   other agents.
//! - **[`Extractor`]**: `extract::<T>(text)` for any
//!   `T: JsonSchema + Deserialize`, with full schema validation and re-asks.
//! - **Everything below it**, re-exported: core traits and combinators
//!   (`batch`, `pipe`, `bind_tools`, `with_cache`, `with_fallbacks`,
//!   callbacks, and with feature `tokio` `with_timeout` / `with_retry`),
//!   [`memory`], [`prompt`], [`output_parser`], [`tool_schema`], [`agent`].
//!
//! # Coming from rig or `LangChain`
//!
//! | rig | `LangChain` | rune-chain |
//! |---|---|---|
//! | `openai::Client::from_env()` | `ChatOpenAI()` | `openai::Client::from_env()?` |
//! | `client.agent(m).preamble(p).build()` | `create_agent(model, prompt=p)` | `client.agent(m).preamble(p).build()` |
//! | `agent.prompt(q).await` | `agent.invoke(...)` | `agent.prompt(q).await` |
//! | `agent.chat(q, history)` | `RunnableWithMessageHistory` | `agent.chat(q, history)` or `.memory(..)` |
//! | `.dynamic_context(n, index)` | retriever + `create_retrieval_chain` | `.dynamic_context(n, index)` |
//! | `#[rig_tool]` fn | `@tool` | `#[tool]` fn, then `.tool(Add)` |
//! | `.tool(T)` (`rig::tool::Tool`) | `BaseTool` | `.typed_tool(T)` ([`TypedTool`]) or `.tool(T)` ([`Tool`]) |
//! | `.multi_turn(n)` | `recursion_limit` | `.max_turns(n)` |
//! | `client.extractor::<T>(m).build()` | `with_structured_output(T)` | `client.extractor::<T>(m).build()?` |
//! | `agent.stream_prompt(q)` | `.stream(...)` | `agent.stream_prompt(q).await?` |
//! | `InMemoryVectorStore` + `.index(embedder)` | `InMemoryVectorStore` | `EmbeddingIndex::new(embedder, store)` |
//! | agent as tool | agent as tool | `.tool(other_agent)` |
//!
//! # Features
//!
//! | Feature | Default | What it adds |
//! |---|---|---|
//! | `openai` | yes | [`openai`]: `OpenAI` and compatible APIs (Groq, Mistral, `DeepSeek`, `OpenRouter`, vLLM, …), embeddings |
//! | `anthropic` | | [`anthropic`]: Claude |
//! | `gemini` | | [`gemini`]: Gemini API and Vertex AI, embeddings |
//! | `ollama` | | [`ollama`]: local models and embeddings |
//! | `embed` | via `openai`/`gemini`/`ollama` | [`embed`]: `Embedder`, Cohere/Voyage/Jina embedders, batching and caching |
//! | `vectorstore` | | [`vectorstore`]: exact and HNSW in-memory stores, filters, snapshots |
//! | `qdrant` | | [`qdrant`]: `QdrantStore`, a Qdrant-backed `VectorStore` |
//! | `pgvector` | | [`pgvector`]: Postgres + pgvector store, HNSW or `IVFFlat` |
//! | `sqlite` | | [`sqlite`]: embedded single-file SQLite store, exact search |
//! | `retrieval` | | [`retrieval`], `dynamic_context`, [`EmbeddingIndex`]: BM25, hybrid, MMR, reranking |
//! | `eval` | | [`eval`]: datasets, heuristic, judge, RAG and trajectory metrics, run comparison |
//! | `graph` | | [`graph`]: `StateGraph`, checkpoints, interrupts, `create_react_agent` (with `sqlite`, `SqliteCheckpointer`) |
//! | `mcp` | | [`mcp`]: MCP client and server, remote tools as agent tools |
//! | `otel` | | [`otel`]: OpenTelemetry `GenAI` spans |
//! | `macros` | yes | `#[tool]` (`rune_chain::tool`) and, with `embed`, `#[derive(Embed)]` (`embed::Embed`) |
//! | `tokio` | | `.with_timeout(..)` / `.with_retry(..)` |
//! | `testing` | | [`testing`]: `FakeLlm` and contract checks for offline tests |
//! | `full` | | all of the above except `testing` |
//!
//! # Without `serde` and `schemars` in your Cargo.toml
//!
//! Both are re-exported; point the derives at them:
//!
//! ```rust
//! use rune_chain::schemars::{self, JsonSchema};
//! use rune_chain::serde::{self, Deserialize};
//!
//! #[derive(Deserialize, JsonSchema)]
//! #[serde(crate = "rune_chain::serde")]
//! #[schemars(crate = "rune_chain::schemars")]
//! struct Person {
//!     name: String,
//! }
//!
//! let schema = rune_chain::schemars::schema_for!(Person);
//! assert_eq!(schema.as_value()["properties"]["name"]["type"], "string");
//! ```
//!
//! # Testing without a network
//!
//! With the `testing` feature, `testing::FakeLlm` is a scripted model:
//!
//! ```rust
//! use rune_chain::prelude::*;
//! use rune_chain::testing::FakeLlm;
//!
//! # tokio::runtime::Builder::new_current_thread().enable_time().build().unwrap().block_on(async {
//! let llm = FakeLlm::with_replies(["Hello, Ada."]);
//! let agent = AgentBuilder::new(llm).preamble("Be kind.").build();
//! assert_eq!(agent.prompt("Hi, I'm Ada").await.unwrap(), "Hello, Ada.");
//! # });
//! ```

#![forbid(unsafe_code)]

mod builder;
mod client;
mod context;
mod extractor;
#[cfg(feature = "retrieval")]
mod index;
mod providers;
mod tool;

pub mod prelude;

pub use builder::{
    Agent, AgentBuilder, AgentItemStream, AgentResponse, AgentStreamItem, ContextDocument,
    TextStream,
};
#[cfg(feature = "embed")]
pub use client::EmbeddingsClient;
pub use client::{
    CompletionClient, CompletionModel, ImageGenerationClient, SpeechClient, TranscriptionClient,
};
pub use context::{DEFAULT_MAX_CONTEXT_CHARS, DOCUMENTS_NOTICE};
pub use extractor::{Extractor, ExtractorBuilder};
#[cfg(feature = "retrieval")]
pub use index::EmbeddingIndex;
pub use tool::{Typed, TypedTool};

#[cfg(feature = "anthropic")]
pub use providers::anthropic;
#[cfg(feature = "gemini")]
pub use providers::gemini;
#[cfg(feature = "ollama")]
pub use providers::ollama;
#[cfg(feature = "openai")]
pub use providers::openai;

/// Core traits and types (`Llm`, `Chain`, `Tool`, `Memory`, `Message`, …)
/// and their combinators.
pub use rune_chain_core::*;

/// The hardened tool-calling loops behind [`Agent`]: `FunctionCallingAgent`,
/// `AgentExecutor` (`ReAct`), [`AgentLimits`](agent::AgentLimits),
/// approvals and events.
pub use rune_chain_agent as agent;
/// Conversation memories: windowed, token-budget and summary buffers.
pub use rune_chain_memory as memory;
/// Typed output: instructor-style extraction, JSON Schema validation,
/// partial streaming and classic parsers.
pub use rune_chain_output_parser as output_parser;
/// Prompt templates, chat templates and few-shot prompts.
pub use rune_chain_prompt as prompt;
/// Tool descriptors and JSON Schema export for provider tool formats.
pub use rune_tool_schema as tool_schema;

/// Embedders: OpenAI-compatible, Cohere, Voyage, Jina, batching, caching.
#[cfg(feature = "embed")]
pub use rune_chain_embed as embed;
/// Retrieval: BM25, embedding retrievers, hybrid fusion, MMR, reranking,
/// `RetrievalQaChain`.
#[cfg(feature = "retrieval")]
pub use rune_chain_retrieval as retrieval;
/// Vector stores: the `VectorStore` trait, exact and HNSW in-memory stores.
#[cfg(feature = "vectorstore")]
pub use rune_vectorstore as vectorstore;
/// Postgres + pgvector vector store: `PgVectorStore`, `PgVectorConfig`, `PgIndex`.
#[cfg(feature = "pgvector")]
pub use rune_vectorstore_pgvector as pgvector;
/// Qdrant vector store: `QdrantStore` and `QdrantConfig`.
#[cfg(feature = "qdrant")]
pub use rune_vectorstore_qdrant as qdrant;
/// Embedded single-file SQLite vector store: `SqliteVectorStore`, `SqliteConfig`.
#[cfg(feature = "sqlite")]
pub use rune_vectorstore_sqlite as sqlite;

/// Evaluation: datasets, heuristic, LLM-as-judge, RAG and trajectory
/// metrics, reports and run comparison for CI gates.
#[cfg(feature = "eval")]
pub use rune_chain_eval as eval;

/// Stateful graphs for workflows and agents: typed state with reducers,
/// parallel supersteps, checkpoints, interrupts and `create_react_agent`.
#[cfg(feature = "graph")]
pub use rune_chain_graph as graph;

/// MCP client and server; remote MCP tools work as agent tools.
#[cfg(feature = "mcp")]
pub use rune_mcp as mcp;
/// OpenTelemetry `GenAI` spans for model calls, tool runs and agents.
#[cfg(feature = "otel")]
pub use rune_otel_genai as otel;

/// `async_trait`, for implementing [`Tool`], [`TypedTool`] and friends.
pub use async_trait::async_trait;
/// `schemars`, for `#[derive(JsonSchema)]` on extraction targets and tool
/// arguments without adding it yourself
/// (`#[schemars(crate = "rune_chain::schemars")]`).
pub use schemars;
/// `serde`, for `#[derive(Deserialize)]` without adding it yourself
/// (`#[serde(crate = "rune_chain::serde")]`).
pub use serde;
/// `serde_json`.
pub use serde_json;

// Compile the README examples as doctests.
#[cfg(all(
    doctest,
    feature = "openai",
    feature = "anthropic",
    feature = "retrieval"
))]
#[doc = include_str!("../README.md")]
struct ReadmeDoctests;
