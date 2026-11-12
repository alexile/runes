//! `SequentialChain` — run [`Chain`](rune_chain_core::Chain)s in order,
//! each step's answer feeding the steps after it.
//!
//! # Features
//!
//! - [`SequentialChain::builder`] checks the key wiring before anything
//!   runs: every variable a step needs must be a declared input or an
//!   earlier step's output, output keys must be unique, and mapped outputs
//!   must exist ([`BuildError`]).
//! - Key mapping per [`Step`]: feed a variable to a chain under the name it
//!   expects ([`Step::map_input`]) and lift extra outputs out of a
//!   multi-output chain ([`Step::map_output`]).
//! - Per-step timeouts ([`Step::timeout`], or a default with
//!   [`SequentialChainBuilder::step_timeout`]).
//! - Per-step retries with deterministic exponential backoff that honours a
//!   provider's retry-after ([`RetryPolicy`]).
//! - Early exit when a step's result says there is nothing left to do
//!   ([`Step::exit_if`]).
//! - A callback per step event ([`StepEvent`]) for logging and tracing.
//! - Token usage summed across steps; [`SequentialChain::run`] also returns
//!   a [`StepReport`] per step.
//! - Streaming: earlier steps run to completion, the last one streams.
//!
//! # Quick Start
//!
//! ```rust
//! use rune_chain_sequential::SequentialChain;
//! use rune_chain_core::{Chain, ChainError, GenerateResult, PromptArgs, prompt_args};
//! use async_trait::async_trait;
//!
//! struct UpperCase;
//!
//! #[async_trait]
//! impl Chain for UpperCase {
//!     async fn call(&self, input: PromptArgs) -> Result<GenerateResult, ChainError> {
//!         let text = input["input"].as_str().unwrap_or_default().to_uppercase();
//!         Ok(GenerateResult::from_text(text))
//!     }
//!     fn input_keys(&self) -> Vec<String> {
//!         vec!["input".into()]
//!     }
//! }
//!
//! struct Exclaim;
//!
//! #[async_trait]
//! impl Chain for Exclaim {
//!     async fn call(&self, input: PromptArgs) -> Result<GenerateResult, ChainError> {
//!         let text = input["shouted"].as_str().unwrap_or_default();
//!         Ok(GenerateResult::from_text(format!("{text}!!!")))
//!     }
//!     fn input_keys(&self) -> Vec<String> {
//!         vec!["shouted".into()]
//!     }
//! }
//!
//! # tokio_test::block_on(async {
//! let seq = SequentialChain::builder()
//!     .inputs(["input"])
//!     .chain(UpperCase, "shouted")
//!     .chain(Exclaim, "final")
//!     .build()
//!     .unwrap();
//!
//! let result = seq.invoke(prompt_args! { "input" => "hello" }).await.unwrap();
//! assert_eq!(result, "HELLO!!!");
//! # });
//! ```

mod chain;
mod event;
mod retry;
mod step;

pub use chain::{BuildError, SequentialChain, SequentialChainBuilder};
pub use event::{SequentialRun, StepEvent, StepReport};
pub use retry::{RetryPolicy, is_transient};
pub use step::Step;
