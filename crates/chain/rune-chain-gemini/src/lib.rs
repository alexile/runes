//! Google Gemini LLM provider for the `rune-chain` framework.
//!
//! Implements [`Llm`](rune_chain_core::Llm) for the Gemini API
//! (`generativelanguage.googleapis.com`, `v1beta`) and Vertex AI, with
//! blocking (`generateContent`) and streaming (`streamGenerateContent`,
//! server-sent events) generation. The model is a free-form id: [`models`]
//! has constants, capability notes and list prices for current Gemini 2.x
//! and 3.x models; newer ids work without a crate update.
//!
//! # Features
//!
//! - [`Gemini`] — the client; `from_env()` reads `GEMINI_API_KEY` (or
//!   `GOOGLE_API_KEY`), [`Gemini::vertex_ai`] targets Vertex AI with an
//!   access token
//! - Messages map onto `contents` with Gemini's `user` / `model` roles;
//!   system messages become `systemInstruction`; consecutive same-role turns
//!   are merged; images go as `inlineData` or `fileData`
//! - Function calling — `functionDeclarations` with schemas converted to
//!   Gemini's `OpenAPI` subset by [`rune_tool_schema`] (`$ref` inlining with
//!   depth and size caps, `nullable`, `anyOf`, unsupported keywords removed),
//!   `toolConfig` from [`ToolChoice`](rune_chain_core::ToolChoice), and
//!   `functionCall` / `functionResponse` round trips with call ids and
//!   thought signatures preserved
//! - Structured output — `responseMimeType: application/json` plus a
//!   converted `responseSchema` via
//!   [`generate_structured`](rune_chain_core::Llm::generate_structured)
//! - Generation settings — temperature, `topP`, `topK`, `maxOutputTokens`,
//!   stop sequences, seed, [`SafetySetting`]s and [`Thinking`] (budget or
//!   level, with thought summaries returned as
//!   [`ReasoningBlock`](rune_chain_core::ReasoningBlock)s)
//! - Usage — `usageMetadata` to [`TokenUsage`](rune_chain_core::TokenUsage),
//!   cached and thinking tokens included; [`ModelInfo::cost`] prices it
//! - Finish reasons — `SAFETY`, `RECITATION` and the other filters map to
//!   `ContentFilter`, `MAX_TOKENS` to `Length`, the rest (e.g.
//!   `MALFORMED_FUNCTION_CALL`) are kept verbatim; a blocked prompt
//!   (`promptFeedback.blockReason`) is an error
//! - [`Gemini::generate_content`] / [`Gemini::stream_content`] — the full
//!   [`GeminiResponse`] and typed [`StreamEvent`]s assembled by
//!   [`ResponseAccumulator`]
//! - `GeminiEmbedder` (feature `embed`) — `embedContent` /
//!   `batchEmbedContents` behind rune-chain-embed's `Embedder`
//! - Images and speech — [`ImageGenerationModel`](rune_chain_core::ImageGenerationModel)
//!   for Imagen (`predict`) and Gemini image-output models, and
//!   [`SpeechModel`](rune_chain_core::SpeechModel) for the TTS models (PCM,
//!   or WAV-wrapped); base64 payloads are decoded under the response cap
//! - Hardened transport — key only in the `x-goog-api-key` header and
//!   redacted everywhere, HTTPS-only (except localhost), redirects not
//!   followed, bounded bodies, SSE line, event and content caps, retries on
//!   408/429/5xx honouring `Retry-After` and `RetryInfo`
//!
//! # Quick start
//!
//! ```rust,no_run
//! use rune_chain_core::{Llm, Message};
//! use rune_chain_gemini::Gemini;
//!
//! # tokio_test::block_on(async {
//! let llm = Gemini::from_env().unwrap();
//! let result = llm
//!     .generate(&[
//!         Message::system("You are a helpful assistant."),
//!         Message::human("What is the capital of France?"),
//!     ])
//!     .await
//!     .unwrap();
//! println!("{}", result.generation);
//! # });
//! ```
//!
//! # Configuring a client
//!
//! Building a client is cheap and offline:
//!
//! ```rust
//! use std::sync::Arc;
//!
//! use rune_chain_core::Llm;
//! use rune_chain_gemini::{Gemini, HarmBlockThreshold, HarmCategory, Thinking, models};
//!
//! let llm: Arc<dyn Llm> = Arc::new(
//!     Gemini::new("AIza-example")
//!         .model(models::GEMINI_2_5_FLASH)
//!         .temperature(0.2)
//!         .max_output_tokens(2048)
//!         .thinking(Thinking::budget(1024).with_thoughts())
//!         .safety(HarmCategory::DangerousContent, HarmBlockThreshold::BlockOnlyHigh),
//! );
//! ```
//!
//! # Streaming
//!
//! ```rust,no_run
//! use futures::StreamExt;
//! use rune_chain_core::Message;
//! use rune_chain_gemini::{Gemini, StreamEvent};
//!
//! # tokio_test::block_on(async {
//! let llm = Gemini::from_env().unwrap();
//! let mut events = llm
//!     .stream_content(&[Message::human("Count to five.")], &[], None)
//!     .await
//!     .unwrap();
//! while let Some(event) = events.next().await {
//!     match event.unwrap() {
//!         StreamEvent::Text(text) => print!("{text}"),
//!         StreamEvent::Done(response) => println!("\n{:?}", response.usage()),
//!         _ => {}
//!     }
//! }
//! # });
//! ```
//!
//! # Structured output
//!
//! ```rust,no_run
//! use rune_chain_core::{Llm, Message, ResponseFormat};
//! use rune_chain_gemini::Gemini;
//! use serde_json::json;
//!
//! # tokio_test::block_on(async {
//! let llm = Gemini::from_env().unwrap();
//! let format = ResponseFormat::json_schema("city", json!({
//!     "type": "object",
//!     "properties": { "name": { "type": "string" }, "country": { "type": "string" } },
//!     "required": ["name", "country"],
//! }));
//! let out = llm.generate_structured(&[Message::human("Capital of France?")], &format).await.unwrap();
//! let city = format.parse_json(&out.generation).unwrap();
//! assert_eq!(city["name"], "Paris");
//! # });
//! ```
//!
//! # Thought signatures
//!
//! Gemini attaches opaque `thoughtSignature`s to parts of a response and
//! expects them back on the next turn (Gemini 3 rejects function-calling
//! turns without them). They travel in
//! [`GenerateResult::reasoning`](rune_chain_core::GenerateResult::reasoning):
//! a thought keeps its text, a signature on a text or function-call part
//! becomes a block with empty text. [`GenerateResult::to_message`](rune_chain_core::GenerateResult::to_message)
//! keeps them, and this crate puts them back where Gemini expects. They mean
//! nothing to other providers.

mod client;
mod config;
mod convert;
#[cfg(feature = "embed")]
mod embed;
mod http;
mod media;
pub mod models;
mod response;
mod stream;
mod types;

pub use client::{
    API_KEY_ENV_VARS, ContentStream, DEFAULT_BASE_URL, DEFAULT_CONNECT_TIMEOUT,
    DEFAULT_MAX_RESPONSE_BYTES, DEFAULT_MAX_RETRIES, DEFAULT_TIMEOUT, Gemini, MAX_STOP_SEQUENCES,
};
pub use config::{
    HarmBlockThreshold, HarmCategory, SafetySetting, Thinking, ThinkingBudget, ThinkingLevel,
};
#[cfg(feature = "embed")]
pub use embed::{
    DEFAULT_EMBED_BATCH_SIZE, DEFAULT_EMBED_CONCURRENCY, DEFAULT_EMBEDDING_MODEL, GeminiEmbedder,
    TaskType,
};
pub use models::{ModelInfo, ThinkingSupport};
pub use response::{
    GeminiResponse, ResponsePart, SYNTHETIC_CALL_ID_PREFIX, SafetyRating, Usage, finish_reason,
};
pub use stream::{
    DEFAULT_MAX_STREAM_BYTES, MAX_SSE_EVENT_BYTES, MAX_STREAM_EVENTS, ResponseAccumulator,
    StreamEvent,
};
