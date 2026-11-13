//! Anthropic Claude LLM provider for the `rune-chain` framework.
//!
//! Implements [`Llm`](rune_chain_core::Llm) for the Anthropic Messages API,
//! covering every model available at `/v1/messages`. The model is a free-form
//! id: [`models`] has constants for the current Claude 5 family — Fable 5.2,
//! Opus 5.5, Sonnet 5.5 (the default) and Haiku 5.5 — plus the earlier models
//! still served, each with a capability note; newer ids work without a crate
//! update. Both blocking and token-streaming generation are supported.
//!
//! # Features
//!
//! - [`Anthropic`] — the client struct; configure once, call many times
//! - `from_env()` — reads `ANTHROPIC_API_KEY` from the environment
//! - Builder methods — `model()`, `temperature()`, `max_tokens()`, `base_url()`,
//!   `http_client()`, `cache()`, `thinking()`, `effort()`, `structured_output()`,
//!   `max_retries()`, `timeout()`, `max_response_bytes()`
//! - Output budget defaults sized for thinking models: [`DEFAULT_MAX_TOKENS`]
//!   (16 000) for blocking calls, [`DEFAULT_STREAM_MAX_TOKENS`] (64 000) for
//!   streams, capped at a known model's output limit
//! - [`models`] — model id constants and [`ModelInfo`] capability notes; requests a
//!   known model is documented to reject fail locally before any network I/O
//! - `generate()` — returns the full response as [`GenerateResult`] with token usage
//! - `stream()` — returns a [`Stream`] of [`StreamData`] chunks for real-time output,
//!   parsed with [`rune-sse`](rune_sse); mid-stream `error` events and truncated
//!   streams surface as errors
//! - System messages are automatically extracted and sent in the Anthropic `system` field
//! - `generate_structured()` — native structured output (`output_config.format`)
//!   with a forced-tool-use fallback for models without it; see [`StructuredOutput`]
//! - Prompt caching — `cache_control` breakpoints on tools, system prompt and
//!   conversation tail via [`CachePolicy`]; cache reads/writes are reported in
//!   [`Usage`]
//! - Extended thinking — [`Thinking`] (adaptive or a fixed budget) and
//!   [`Effort`]; thinking blocks are parsed into [`MessageResponse`] and never
//!   mixed into the response text
//! - [`Anthropic::generate_message`] / [`Anthropic::stream_message`] — the full
//!   provider response (thinking, stop reason, cache-token usage) and typed
//!   [`StreamEvent`]s with tool-call JSON assembled by [`MessageAccumulator`]
//! - [`Anthropic::count_tokens`] — `/v1/messages/count_tokens`
//! - Hardened transport — redacted API key, HTTPS-only (except localhost),
//!   redirects not followed, bounded bodies, default timeouts, retries on
//!   408/409/429/5xx/529 honouring `retry-after`
//!
//! # Prompt caching and usage
//!
//! ```rust,no_run
//! use rune_chain_anthropic::{Anthropic, CachePolicy, CacheTtl, models};
//! use rune_chain_core::Message;
//!
//! # tokio_test::block_on(async {
//! let llm = Anthropic::from_env()
//!     .unwrap()
//!     .model(models::CLAUDE_SONNET_5_5)
//!     .cache(CachePolicy::all(CacheTtl::FiveMinutes));
//!
//! let long_manual = "…a long, stable system prompt…";
//! let reply = llm
//!     .generate_message(&[Message::system(long_manual), Message::human("Summarise §3.")], &[], None)
//!     .await
//!     .unwrap();
//! let usage = reply.usage();
//! println!(
//!     "{} uncached, {} written to cache, {} read from cache",
//!     usage.input_tokens, usage.cache_creation_input_tokens, usage.cache_read_input_tokens,
//! );
//! # });
//! ```
//!
//! # Structured output
//!
//! ```rust,no_run
//! use rune_chain_anthropic::Anthropic;
//! use rune_chain_core::{Llm, Message, ResponseFormat};
//! use serde_json::json;
//!
//! # tokio_test::block_on(async {
//! let llm = Anthropic::from_env().unwrap();
//! let format = ResponseFormat::json_schema("city", json!({
//!     "type": "object",
//!     "properties": { "name": { "type": "string" }, "country": { "type": "string" } },
//!     "required": ["name", "country"],
//!     "additionalProperties": false,
//! }));
//! let out = llm.generate_structured(&[Message::human("Capital of France?")], &format).await.unwrap();
//! let city = format.parse_json(&out.generation).unwrap();
//! assert_eq!(city["name"], "Paris");
//! # });
//! ```
//!
//! # Configuring a client
//!
//! Building a client is cheap and offline. It implements
//! [`Llm`](rune_chain_core::Llm), so it can be handed to any provider-agnostic
//! chain or agent as a trait object:
//!
//! ```rust
//! use std::sync::Arc;
//!
//! use rune_chain_anthropic::{Anthropic, models};
//! use rune_chain_core::Llm;
//!
//! fn shared(llm: impl Llm + 'static) -> Arc<dyn Llm> {
//!     Arc::new(llm)
//! }
//!
//! let _llm: Arc<dyn Llm> = shared(
//!     Anthropic::new("sk-ant-example")
//!         .model(models::CLAUDE_HAIKU_4_5) // still accepts a temperature
//!         .temperature(0.2)
//!         .max_tokens(256),
//! );
//! ```
//!
//! # Quick Start
//!
//! ```rust,no_run
//! use rune_chain_anthropic::Anthropic;
//! use rune_chain_core::{Llm, Message};
//!
//! # tokio_test::block_on(async {
//! let llm = Anthropic::from_env().unwrap();
//!
//! let result = llm.generate(&[
//!     Message::system("You are a helpful assistant."),
//!     Message::human("What is the capital of France?"),
//! ]).await.unwrap();
//!
//! println!("{}", result.generation); // "Paris"
//! # });
//! ```
//!
//! Stream tokens as they arrive:
//!
//! ```rust,no_run
//! use rune_chain_anthropic::Anthropic;
//! use rune_chain_core::{Llm, Message};
//! use futures::StreamExt;
//!
//! # tokio_test::block_on(async {
//! let llm = Anthropic::from_env().unwrap();
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
//! [`Stream`]: futures::Stream
//! [`GenerateResult`]: rune_chain_core::GenerateResult
//! [`StreamData`]: rune_chain_core::StreamData

mod client;
mod config;
mod http;
pub mod models;
mod response;
mod stream;
mod types;

pub use client::{
    Anthropic, DEFAULT_BASE_URL, DEFAULT_CONNECT_TIMEOUT, DEFAULT_MAX_RESPONSE_BYTES,
    DEFAULT_MAX_RETRIES, DEFAULT_MAX_TOKENS, DEFAULT_STREAM_MAX_TOKENS, DEFAULT_TIMEOUT,
    MessageStream,
};
pub use config::{CachePolicy, CacheTtl, Effort, StructuredOutput, Thinking, ThinkingDisplay};
pub use models::ModelInfo;
pub use response::{ContentBlock, MessageResponse, Usage, finish_reason};
pub use stream::{DEFAULT_MAX_STREAM_BYTES, MessageAccumulator, StreamEvent};
