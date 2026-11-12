//! OpenTelemetry `GenAI` semantic-convention spans for
//! [`rune-chain`](rune_chain_core) model calls, tool executions and agents.
//!
//! - [`TracedLlm`] wraps any [`Llm`](rune_chain_core::Llm): each call is a
//!   client span named `chat {model}` carrying the provider, model, request
//!   settings, token usage, cost, requested tool calls and errors.
//! - [`TracedTool`] wraps any [`Tool`](rune_chain_core::Tool): each run is an
//!   `execute_tool {name}` span.
//! - [`agent_span`] opens an `invoke_agent {name}` span for an agent loop to
//!   nest its model and tool spans under.
//! - [`metrics`]: per-call duration and token histograms
//!   (`gen_ai.client.operation.duration`, `gen_ai.client.token.usage`)
//!   through the [`GenAiMetrics`] sink; `OtelMetrics` (feature
//!   `opentelemetry`) records them on an OpenTelemetry `Meter`.
//! - [`model_span`], [`record_result`], [`record_usage`], [`record_llm_error`]
//!   and [`tool_span`] are the building blocks, for code that drives a
//!   provider without the wrappers.
//!
//! Attribute keys follow the [OpenTelemetry GenAI semantic conventions]
//! (semconv v1.40.0; see [`attr`] for the exact names and version notes).
//! Values the conventions do not define, such as cost, use the
//! `rune.gen_ai.*` prefix.
//!
//! # Privacy
//!
//! Prompts, completions, tool arguments and tool results are **not**
//! recorded unless you opt in with a [`ContentPolicy`]. When on, each value
//! goes through your redaction hook (or `rune-redact` with the `redact`
//! feature), then is cut to a size cap, and only the most recent input
//! messages are kept.
//!
//! # Features
//!
//! - `opentelemetry`: `OtelMetrics`, a [`GenAiMetrics`] sink on an
//!   OpenTelemetry `Meter`.
//! - `redact`: [`ContentPolicy::with_default_redaction`] via `rune-redact`.
//!
//! The spans are plain [`tracing`] spans with `otel.name`, `otel.kind` and
//! `otel.status_code` fields, so this crate has no OpenTelemetry
//! dependency. They are exported by `rune-telemetry` (with its `otlp`
//! feature) or any other `tracing-opentelemetry` layer.
//!
//! [OpenTelemetry GenAI semantic conventions]: https://opentelemetry.io/docs/specs/semconv/gen-ai/gen-ai-spans/
//!
//! # Example
//!
//! ```
//! use async_trait::async_trait;
//! use rune_chain_core::{GenerateResult, Llm, LlmError, Message, Pricing, TokenUsage};
//! use rune_otel_genai::{GenAiConfig, TracedLlm, agent_span};
//! use tracing::Instrument;
//!
//! struct Model;
//! #[async_trait]
//! impl Llm for Model {
//!     async fn generate(&self, _: &[Message]) -> Result<GenerateResult, LlmError> {
//!         let mut r = GenerateResult::from_text("4");
//!         r.tokens = Some(TokenUsage::new(12, 1).with_total_tokens(13));
//!         Ok(r)
//!     }
//! }
//!
//! let llm = TracedLlm::new(
//!     Model,
//!     GenAiConfig::new("acme", "acme-small")
//!         .with_pricing(Pricing::per_mtok(500_000, 1_500_000))
//!         .with_max_tokens(256),
//! );
//!
//! // Spans: `invoke_agent calculator` > `chat acme-small`.
//! let answer = tokio_test::block_on(
//!     async { llm.generate(&[Message::human("2 + 2?")]).await }
//!         .instrument(agent_span("calculator", None, None)),
//! )?;
//! assert_eq!(answer.generation, "4");
//! # Ok::<(), LlmError>(())
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod attr;
mod content;
mod llm;
pub mod metrics;
mod span;
mod tool;

pub use content::{
    ContentPolicy, DEFAULT_MAX_CHARS, DEFAULT_MAX_MESSAGES, RedactFn, TRUNCATED_MARKER,
};
pub use llm::TracedLlm;
#[cfg(feature = "opentelemetry")]
pub use metrics::OtelMetrics;
pub use metrics::{GenAiMetrics, OperationMetrics};
pub use span::{
    GenAiConfig, TARGET, agent_span, llm_error_type, model_span, record_error, record_input,
    record_llm_error, record_result, record_usage, tool_error_type, tool_span,
};
pub use tool::TracedTool;
