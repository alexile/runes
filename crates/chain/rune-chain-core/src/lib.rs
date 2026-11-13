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
//! - [`ChainExt`] / [`LlmExt`] — `.with_fallbacks(…)` and `.map_output(…)`
//!   combinators; `Arc<T>` implements every core trait when `T` does
//! - [`ImageData::validate`] — size, MIME and URL-scheme checks for images
//!   from untrusted sources
//! - [`Pricing`] / [`Cost`] — per-model token prices and exact cost arithmetic
//! - [`StreamData`] — incremental token chunks for streaming responses
//! - [`PromptArgs`] + [`prompt_args!`] — ergonomic key-value input for templates
//! - [`ChainError`] / [`LlmError`] / [`ToolError`] — structured error types;
//!   [`LlmError`] carries an [`LlmErrorKind`], the HTTP status and the
//!   provider's retry-after delay
//! - `testing` (feature `testing`) — reusable trait-contract checks that every
//!   `Llm`, `Chain`, `Memory` and `Tool` implementation should pass, plus
//!   `FakeLlm`, a scriptable offline `Llm` for testing code built on it
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

mod chain;
mod error;
mod ext;
mod function_call;
mod generate;
mod llm;
mod memory;
mod message;
mod pricing;
mod prompt;
mod response_format;
mod stream;
#[cfg(feature = "testing")]
pub mod testing;
#[cfg(test)]
mod tests;
mod tool;

pub use chain::Chain;
pub use error::{ChainError, LlmError, LlmErrorKind, ToolError};
pub use ext::{ChainExt, ChainWithFallbacks, LlmExt, LlmWithFallbacks, MapOutput};
pub use function_call::{
    FunctionDefinition, MAX_TOOL_ARGUMENTS_BYTES, MAX_TOOL_NAME_LEN, ToolCall, ToolChoice,
};
pub use generate::{FinishReason, GenerateResult, TokenUsage};
pub use llm::Llm;
pub use memory::Memory;
pub use message::{
    ContentPart, DEFAULT_MAX_IMAGE_BYTES, ImageData, ImageError, MAX_IMAGE_URL_LEN, Message,
    MessageContent, ReasoningBlock, Role,
};
pub use pricing::{Cost, Pricing};
pub use prompt::PromptArgs;
pub use response_format::{MAX_JSON_OUTPUT_BYTES, ResponseFormat};
pub use stream::StreamData;
pub use tool::Tool;
