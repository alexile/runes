//! Ollama (local models) provider for the `rune-chain` framework.
//!
//! Implements [`Llm`](rune_chain_core::Llm) for a locally-running
//! [Ollama](https://ollama.com) server. Any model you have pulled via
//! `ollama pull <model>` is immediately usable. Defaults to
//! `http://localhost:11434` and the `llama3.2` model.
//!
//! # Features
//!
//! - [`Ollama`] — the client; configure once, call many times. Cheap to
//!   clone, `Debug` never shows the bearer token.
//! - [`Llm`](rune_chain_core::Llm): `generate`, `stream`, native tool
//!   calling (`generate_with_tools`, `/api/chat` `tools`) and native
//!   structured output (`generate_structured`, Ollama's `format` with a JSON
//!   Schema or `"json"`).
//! - [`Ollama::stream_events`] — streamed text, thinking, tool calls, finish
//!   reason and token usage as [`StreamEvent`]s; [`collect_events`] folds
//!   them into a [`GenerateResult`].
//! - [`Ollama::chat`] — the full reply including the model's thinking.
//! - Embeddings via `/api/embed` (batched): [`Ollama::embed_texts`] and the
//!   [`Embedder`](rune_chain_embed::Embedder) trait.
//! - Options: `temperature`, `top_p`, `top_k`, `seed`, `stop`, `num_ctx`,
//!   `max_tokens` (`num_predict`), any raw `option`, [`KeepAlive`],
//!   [`Think`] for reasoning models, base64 images for vision models.
//! - Model management: [`Ollama::list_models`], [`Ollama::show_model`],
//!   [`Ollama::pull_model`] with a progress stream.
//! - Hardened transport: NDJSON parsing never panics and is bounded per line
//!   ([`DEFAULT_MAX_LINE_BYTES`]) and in total
//!   ([`DEFAULT_MAX_RESPONSE_BYTES`]); 10-minute request and 10-second
//!   connect timeouts; plain HTTP only to loopback unless opted in; optional
//!   bearer token for authenticating proxies.
//!
//! # Security
//!
//! Ollama has no authentication. Anyone who can reach its port can run and
//! pull models and see prompts in flight. Keep it on loopback or behind an
//! authenticating TLS reverse proxy. Plain HTTP to a non-loopback host is
//! refused unless you accept the exposure with
//! [`Ollama::allow_http_host`]:
//!
//! ```rust
//! use rune_chain_ollama::Ollama;
//!
//! // A GPU box on a trusted LAN:
//! let lan = Ollama::new()
//!     .base_url("http://gpu-box:11434")
//!     .allow_http_host("gpu-box");
//! // Behind a TLS proxy that checks a token:
//! let proxied = Ollama::new()
//!     .base_url("https://llm.example.com/ollama")
//!     .bearer_token("s3cret-token-value");
//! assert!(!format!("{proxied:?}").contains("s3cret"));
//! # let _ = lan;
//! ```
//!
//! # Configuring a client
//!
//! Building a client is cheap and does not contact the server. It implements
//! [`Llm`](rune_chain_core::Llm), so it can be handed to any provider-agnostic
//! chain or agent as a trait object:
//!
//! ```rust
//! use std::sync::Arc;
//!
//! use rune_chain_core::Llm;
//! use rune_chain_ollama::Ollama;
//!
//! fn shared(llm: impl Llm + 'static) -> Arc<dyn Llm> {
//!     Arc::new(llm)
//! }
//!
//! let _llm: Arc<dyn Llm> = shared(
//!     Ollama::new()
//!         .base_url("http://gpu-box:11434/")
//!         .allow_http_host("gpu-box")
//!         .model("mistral")
//!         .temperature(0.0)
//!         .max_tokens(128),
//! );
//! ```
//!
//! # Quick Start
//!
//! ```rust,no_run
//! use rune_chain_ollama::Ollama;
//! use rune_chain_core::{Llm, Message};
//!
//! # tokio_test::block_on(async {
//! let llm = Ollama::new();  // localhost:11434, llama3.2
//!
//! let result = llm.generate(&[
//!     Message::human("What is the capital of France?"),
//! ]).await.unwrap();
//!
//! println!("{}", result.generation);
//! # });
//! ```
//!
//! Stream tokens as they arrive:
//!
//! ```rust,no_run
//! use rune_chain_ollama::Ollama;
//! use rune_chain_core::{Llm, Message};
//! use futures::StreamExt;
//!
//! # tokio_test::block_on(async {
//! let llm = Ollama::new().model("mistral");
//! let mut stream = llm.stream(&[Message::human("Count to five.")]).await.unwrap();
//!
//! while let Some(chunk) = stream.next().await {
//!     let data = chunk.unwrap();
//!     if data.is_finished { break; }
//!     print!("{}", data.content);
//! }
//! # });
//! ```
//!
//! Structured output with a JSON Schema:
//!
//! ```rust,no_run
//! use rune_chain_core::{Llm, Message, ResponseFormat};
//! use rune_chain_ollama::Ollama;
//! use serde_json::json;
//!
//! # tokio_test::block_on(async {
//! let format = ResponseFormat::json_schema(
//!     "capital",
//!     json!({
//!         "type": "object",
//!         "properties": { "city": { "type": "string" } },
//!         "required": ["city"]
//!     }),
//! );
//! let out = Ollama::new()
//!     .generate_structured(&[Message::human("Capital of France?")], &format)
//!     .await
//!     .unwrap();
//! let value = format.parse_json(&out.generation).unwrap();
//! println!("{}", value["city"]);
//! # });
//! ```
//!
//! [`Stream`]: futures::Stream
//! [`GenerateResult`]: rune_chain_core::GenerateResult
//! [`StreamData`]: rune_chain_core::StreamData

mod client;
mod embed;
mod http;
pub mod models;
mod ndjson;
mod options;
mod stream;
mod types;

pub use client::{
    ChatReply, DEFAULT_BASE_URL, DEFAULT_CONNECT_TIMEOUT, DEFAULT_MAX_LINE_BYTES,
    DEFAULT_MAX_RESPONSE_BYTES, DEFAULT_MODEL, DEFAULT_TIMEOUT, Ollama,
};
pub use embed::Embeddings;
pub use models::{ModelDetails, ModelInfo, ModelSummary, PullProgress, PullStream};
pub use options::{KeepAlive, Think};
pub use stream::{EventStream, MAX_TOOL_CALLS, StreamEvent, collect_events};
