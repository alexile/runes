//! Core traits and types for the `rune-chain` LLM orchestration framework.
//!
//! `rune-chain-core` is the foundation layer of the `rune-chain-*` crate family —
//! a modern, async-first Rust port of the `LangChain` concept. It defines the shared
//! vocabulary (types, traits, error variants) that every other `rune-chain-*` crate
//! depends on, without pulling in any LLM provider SDK itself.
//!
//! # Features
//!
//! - [`Chain`] — the central trait; implement it to create any unit of LLM work
//! - [`Llm`] — provider-agnostic interface supporting text generation, streaming,
//!   and native function/tool calling
//! - [`Tool`] — async, fallible tool implementations for agent function calling
//! - [`Memory`] — pluggable conversation history (in-process, DB, vector store, …)
//! - [`Message`] / [`Role`] — typed conversation turns (System, Human, Ai, Tool)
//! - [`MessageContent`] / [`ContentPart`] — multi-modal content (text + images)
//! - [`GenerateResult`] / [`TokenUsage`] / [`FinishReason`] — structured
//!   output with token accounting (cache and reasoning breakdown) and the
//!   stop reason
//! - [`ReasoningBlock`] — model reasoning / thinking, kept out of the message
//!   text, with opaque provider signatures for multi-turn round-trips
//! - [`ToolCall`] / [`FunctionDefinition`] — native function-calling protocol,
//!   with bounded argument parsing ([`ToolCall::parse_arguments`]) and
//!   schema checks ([`ToolCall::validate`]) for untrusted model output
//! - [`ResponseFormat`] — structured output (JSON / JSON Schema) via
//!   [`Llm::generate_structured`]
//! - [`ChainExt`] / [`LlmExt`] — `.with_fallbacks(…)`, `.map_output(…)`,
//!   `.pipe(…)`, `.bind_tools(…)`, `.with_cache(…)`, `.with_callbacks(…)` and,
//!   with feature `tokio`, `.with_timeout(…)` / `.with_retry(…)`;
//!   `Arc<T>` implements every core trait when `T` does
//! - [`Chain::batch`] / [`Llm::batch`] — ordered, bounded-concurrency batches
//! - [`CallbackHandler`] — start / end / error hooks for models, chains and
//!   tools; event `Debug` output never contains prompt text
//! - [`LlmCache`] / [`InMemoryLlmCache`] — response cache with a bounded LRU
//! - [`ImageData::validate`] — size, MIME and URL-scheme checks for images
//!   from untrusted sources
//! - [`Pricing`] / [`Cost`] — per-model token prices and exact cost arithmetic
//! - [`TranscriptionModel`] / [`ImageGenerationModel`] / [`SpeechModel`] —
//!   speech-to-text, image generation and text-to-speech behind small
//!   provider-agnostic traits with request builders
//! - [`StreamData`] — incremental token chunks for streaming responses
//! - [`StreamEvent`] / [`StreamAccumulator`] — typed streaming with tool
//!   calls ([`Llm::stream_events`]): text, reasoning and tool-call argument
//!   deltas, usage and the finish reason, folded back into a
//!   [`GenerateResult`] with bounded argument buffers
//! - [`PromptArgs`] + [`prompt_args!`] — ergonomic key-value input for templates
//! - [`ChainError`] / [`LlmError`] / [`ToolError`] — structured error types;
//!   [`LlmError`] carries an [`LlmErrorKind`], the HTTP status and the
//!   provider's retry-after delay
//! - `testing` (feature `testing`) — reusable trait-contract checks that every
//!   `Llm`, `Chain`, `Memory` and `Tool` implementation should pass, plus
//!   `FakeLlm`, a scriptable offline `Llm` for testing code built on it
//! - `#[tool]` (feature `macros`) — turn a plain or `async fn` into a
//!   [`Tool`] with a JSON Schema generated from its argument types
//!
//! # Security notes
//!
//! - Tool-call arguments and model output are untrusted: the parsing helpers
//!   cap input size ([`MAX_TOOL_ARGUMENTS_BYTES`], [`MAX_JSON_OUTPUT_BYTES`])
//!   and their errors never echo the raw input.
//! - [`ImageData`]'s `Debug` output elides base64 payloads, so logging a
//!   message never dumps image bytes.
//!
//! # Quick Start
//!
//! ```rust
//! use rune_chain_core::{Chain, ChainError, GenerateResult, PromptArgs, prompt_args};
//! use async_trait::async_trait;
//!
//! struct EchoChain;
//!
//! #[async_trait]
//! impl Chain for EchoChain {
//!     async fn call(&self, input: PromptArgs) -> Result<GenerateResult, ChainError> {
//!         let text = input
//!             .get("input")
//!             .and_then(|v| v.as_str())
//!             .unwrap_or("")
//!             .to_string();
//!         Ok(GenerateResult::from_text(text))
//!     }
//! }
//!
//! # tokio_test::block_on(async {
//! let chain = EchoChain;
//! let result = chain.invoke(prompt_args! { "input" => "hello" }).await.unwrap();
//! assert_eq!(result, "hello");
//! # });
//! ```
//!
//! # `#[tool]`
//!
//! With the `macros` feature:
//!
//! ```rust
//! # #[cfg(feature = "macros")] {
//! use rune_chain_core::{Tool, tool};
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
//! # tokio_test::block_on(async {
//! assert_eq!(Add.name(), "add");
//! assert_eq!(Add.schema()["required"], serde_json::json!(["a", "b"]));
//! assert_eq!(Add.run(r#"{"a": 2, "b": 3}"#).await.unwrap(), "5");
//! assert!(Add.run(r#"{"a": "two"}"#).await.is_err());
//! # });
//! # }
//! ```

// Lets `#[tool]` refer to `::rune_chain_core` from inside this crate and its
// doctests.
extern crate self as rune_chain_core;

#[doc(hidden)]
#[path = "macro_support.rs"]
pub mod __private;
mod cache;
mod callbacks;
mod chain;
mod error;
mod ext;
mod function_call;
mod generate;
mod llm;
mod media;
mod memory;
mod message;
mod pricing;
mod prompt;
#[cfg(feature = "tokio")]
mod resilience;
mod response_format;
mod stream;
mod stream_event;
#[cfg(feature = "testing")]
pub mod testing;
#[cfg(test)]
mod tests;
mod tool;

pub use cache::{CacheKey, CachedLlm, DEFAULT_MAX_CACHE_ENTRY_BYTES, InMemoryLlmCache, LlmCache};
pub use callbacks::{
    CallbackHandler, ChainEnd, ChainFailure, ChainStart, LlmCall, LlmEnd, LlmFailure, LlmStart,
    ToolEnd, ToolExt, ToolFailure, ToolStart, WithCallbacks,
};
pub use chain::{Chain, DEFAULT_BATCH_CONCURRENCY};
pub use error::{ChainError, LlmError, LlmErrorKind, ToolError};
pub use ext::{
    BoundTools, ChainExt, ChainWithFallbacks, LlmExt, LlmWithFallbacks, MapOutput, Pipe,
};
pub use function_call::{
    FunctionDefinition, MAX_TOOL_ARGUMENTS_BYTES, MAX_TOOL_NAME_LEN, ToolCall, ToolChoice,
};
pub use generate::{FinishReason, GenerateResult, TokenUsage};
pub use llm::Llm;
pub use media::{
    AudioFormat, GeneratedImage, ImageFormat, ImageGenerationModel, ImageGenerationRequest,
    ImageGenerationResponse, ImageResponseFormat, SpeechModel, SpeechRequest, SpeechResponse,
    TimestampGranularity, TranscriptionFormat, TranscriptionModel, TranscriptionRequest,
    TranscriptionResponse, TranscriptionSegment,
};
pub use memory::Memory;
pub use message::{
    ContentPart, DEFAULT_MAX_IMAGE_BYTES, ImageData, ImageError, MAX_IMAGE_URL_LEN, Message,
    MessageContent, ReasoningBlock, Role,
};
pub use pricing::{Cost, Pricing};
pub use prompt::PromptArgs;
#[cfg(feature = "tokio")]
pub use resilience::{MAX_RETRY_AFTER, WithRetry, WithTimeout};
pub use response_format::{MAX_JSON_OUTPUT_BYTES, ResponseFormat};
pub use stream::StreamData;
pub use stream_event::{EventStream, StreamAccumulator, StreamEvent};
pub use tool::Tool;

/// Turn a function into a [`Tool`]. See the [crate docs](crate#tool).
#[cfg(feature = "macros")]
pub use rune_chain_macros::tool;

#[doc(hidden)]
#[cfg(feature = "macros")]
#[macro_export]
macro_rules! __rune_chain_core_require_macros {
    () => {};
}

#[doc(hidden)]
#[cfg(not(feature = "macros"))]
#[macro_export]
macro_rules! __rune_chain_core_require_macros {
    () => {
        ::core::compile_error!(
            "#[tool] needs the `macros` feature of rune-chain-core: \
             rune-chain-core = { version = \"0.2\", features = [\"macros\"] }"
        );
    };
}
