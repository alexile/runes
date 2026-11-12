//! `LlmChain` — a prompt template, an LLM, optional memory and an optional
//! output parser, wired into a single [`Chain`](rune_chain_core::Chain).
//!
//! # Features
//!
//! - [`LlmChain`]: renders a [`ChatTemplate`](rune_chain_prompt::ChatTemplate),
//!   splices in memory, calls the [`Llm`](rune_chain_core::Llm) and returns
//!   its [`GenerateResult`](rune_chain_core::GenerateResult) unchanged, so
//!   token usage (cache and reasoning included) and the finish reason reach
//!   the caller.
//! - Structured output: [`LlmChain::with_response_format`] goes through
//!   [`Llm::generate_structured`](rune_chain_core::Llm::generate_structured)
//!   and parses the JSON; [`LlmChain::invoke_structured`] deserializes it
//!   into your type.
//! - Output parsers: [`LlmChain::with_output_parser`] takes any
//!   [`OutputParser`](rune_chain_output_parser::OutputParser) and adds its
//!   format instructions to the prompt.
//! - [`LlmChain::run`] returns an [`LlmOutput`] with text, usage, finish
//!   reason and parsed value in one place.
//! - Streaming that still records the full answer in memory once the stream
//!   ends; [`with_stream_completion`] exposes the same mechanism for other
//!   chains.
//! - A context budget checked before the model is called.
//!
//! # Message order
//!
//! ```text
//! System messages (from the template, always first)
//! ↓ parser format instructions (if any)
//! ↓ prior Human / Ai turns (from memory)
//! ↓ new input (from the template)
//! ```
//!
//! Only `Human` turns and the answer are recorded in memory; `System`
//! messages are rendered fresh from the template on every call.
//!
//! # Quick Start
//!
//! ```rust
//! use rune_chain_llm::LlmChain;
//! use rune_chain_prompt::{ChatTemplate, MessageTemplate};
//! use rune_chain_core::{Chain, prompt_args};
//!
//! # async fn run() -> Result<(), Box<dyn std::error::Error>> {
//! # struct FakeLlm;
//! # use async_trait::async_trait;
//! # use rune_chain_core::{Llm, Message, GenerateResult, LlmError};
//! # #[async_trait] impl Llm for FakeLlm {
//! #     async fn generate(&self, _: &[Message]) -> Result<GenerateResult, LlmError> {
//! #         Ok(GenerateResult::from_text("4"))
//! #     }
//! # }
//! let chain = LlmChain::new(FakeLlm, ChatTemplate::new(vec![
//!     MessageTemplate::system("You are helpful."),
//!     MessageTemplate::human("{question}"),
//! ]));
//!
//! let answer = chain.invoke(prompt_args! { "question" => "What is 2 + 2?" }).await?;
//! assert_eq!(answer, "4");
//! # Ok(()) }
//! # tokio_test::block_on(run()).unwrap();
//! ```

mod chain;
mod output;
mod stream;

pub use chain::LlmChain;
pub use output::LlmOutput;
pub use stream::{ChainStream, with_stream_completion};
