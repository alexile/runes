//! Agent loop implementations for `rune-chain`.
//!
//! Two agent strategies are provided:
//!
//! - [`AgentExecutor`] — text-based `ReAct` (Reasoning + Acting) loop. Parses
//!   `Action:` / `Final Answer:` from the LLM's freeform text. Works with any
//!   model but is fragile against outputs that deviate from the format.
//!
//! - [`FunctionCallingAgent`] — structured native function-calling loop. Uses
//!   [`Llm::generate_with_tools`](rune_chain_core::Llm::generate_with_tools)
//!   and JSON tool-call protocol. More reliable, requires a provider that
//!   supports function calling (`OpenAI`, Anthropic).
//!
//! Both implement [`Chain`](rune_chain_core::Chain) and accept the `"input"` key.
//!
//! # Tool-execution safety
//!
//! Model output decides which tools run and with what arguments, and tool
//! output flows back into the model, so both directions are treated as
//! untrusted:
//!
//! - **Validation.** Every call is checked before it runs: unknown tool names
//!   and arguments that do not match the tool's schema
//!   ([`ToolCall::validate`](rune_chain_core::ToolCall::validate), 1 MiB cap)
//!   become an error result for the model, never a panic. Tool sets with
//!   invalid or duplicate names are rejected up front.
//! - **Limits.** [`AgentLimits`] bounds iterations, tool calls per turn,
//!   concurrency, per-tool time, total wall time and output size (truncated
//!   with a `[truncated N bytes]` marker). All are on by default.
//! - **Fencing.** Tool output is wrapped in `<tool_output>` tags (with any
//!   embedded closing tag escaped) and the system prompt tells the model
//!   fenced text is data. Tool output is only ever added as tool/AI turns;
//!   the system prompt is fixed for the run. The `ReAct` agent also discards
//!   `Observation:` lines the model writes itself.
//! - **Approval.** Tools registered with `tool_requiring_approval` run only
//!   after an [`Approver`] allows them (fail-closed without one); approvers
//!   can also edit arguments, which are re-validated.
//! - **Errors.** Tool errors, timeouts and panics are returned to the model as
//!   results ([`ToolErrorMode`]), truncated and passed through
//!   [`sanitize::redact_secrets`].
//! - **Reuse.** [`ToolExecutor`] runs one turn's tool calls under the same
//!   rules for loops you drive yourself, such as a state graph.
//! - **Observability.** [`AgentEvent`]s report each step, tool call, tool
//!   result and the final answer to an [`AgentObserver`].
//!
//! Timeouts use Tokio's timer, so run agents inside a Tokio runtime with the
//! time driver enabled (the default for `#[tokio::main]`).
//!
//! # Quick Start — `ReAct`
//!
//! The agent works with any [`Llm`](rune_chain_core::Llm). This example plugs
//! in a scripted model so it runs offline: the model first asks for the
//! `upper` tool, then reads the observation and answers.
//!
//! ```rust
//! use std::sync::Arc;
//!
//! use async_trait::async_trait;
//! use rune_chain_agent::AgentExecutor;
//! use rune_chain_core::{GenerateResult, Llm, LlmError, Message, Tool, ToolError};
//!
//! struct Upper;
//!
//! #[async_trait]
//! impl Tool for Upper {
//!     fn name(&self) -> &str { "upper" }
//!     fn description(&self) -> &str { "Converts text to upper case." }
//!     async fn run(&self, input: &str) -> Result<String, ToolError> {
//!         Ok(input.to_uppercase())
//!     }
//! }
//!
//! /// Stands in for a real provider such as `rune-chain-openai`.
//! struct ScriptedLlm;
//!
//! #[async_trait]
//! impl Llm for ScriptedLlm {
//!     async fn generate(&self, messages: &[Message]) -> Result<GenerateResult, LlmError> {
//!         let last = messages.last().map(|m| m.content.text_content()).unwrap_or_default();
//!         // Tool output arrives fenced on the lines after `Observation:`.
//!         let observed = last.lines().skip_while(|l| !l.starts_with("Observation:")).nth(1);
//!         let reply = match observed {
//!             Some(observation) => format!("Final Answer: {observation}"),
//!             None => "Thought: I should use a tool.\nAction: upper\nAction Input: hello".into(),
//!         };
//!         Ok(GenerateResult::from_text(reply))
//!     }
//! }
//!
//! # tokio_test::block_on(async {
//! let agent = AgentExecutor::new(Arc::new(ScriptedLlm)).tool(Upper).max_iterations(5);
//! let result = agent.run("Convert 'hello' to upper case.").await.unwrap();
//! assert_eq!(result.output, "HELLO");
//! assert_eq!(result.iterations, 1);
//! # });
//! ```
//!
//! # Quick Start — Function Calling
//!
//! With native function calling the model returns structured
//! [`ToolCall`](rune_chain_core::ToolCall)s; the agent runs them and feeds the
//! results back as tool turns until the model answers in text.
//!
//! ```rust
//! use std::sync::Arc;
//!
//! use async_trait::async_trait;
//! use rune_chain_agent::FunctionCallingAgent;
//! use rune_chain_core::{
//!     FunctionDefinition, GenerateResult, Llm, LlmError, Message, Role, Tool, ToolCall,
//!     ToolChoice, ToolError,
//! };
//!
//! struct Multiply;
//!
//! #[async_trait]
//! impl Tool for Multiply {
//!     fn name(&self) -> &str { "multiply" }
//!     fn description(&self) -> &str { "Multiplies two integers." }
//!     async fn run(&self, input: &str) -> Result<String, ToolError> {
//!         let v: serde_json::Value =
//!             serde_json::from_str(input).map_err(|e| ToolError::InvalidInput(e.to_string()))?;
//!         Ok((v["a"].as_i64().unwrap_or(0) * v["b"].as_i64().unwrap_or(0)).to_string())
//!     }
//!     // The agent validates every call against this schema before `run`.
//!     fn schema(&self) -> serde_json::Value {
//!         serde_json::json!({
//!             "type": "object",
//!             "properties": { "a": { "type": "integer" }, "b": { "type": "integer" } },
//!             "required": ["a", "b"],
//!             "additionalProperties": false
//!         })
//!     }
//! }
//!
//! /// Calls the tool on the first turn, then answers with its result.
//! struct ScriptedLlm;
//!
//! #[async_trait]
//! impl Llm for ScriptedLlm {
//!     async fn generate(&self, _: &[Message]) -> Result<GenerateResult, LlmError> {
//!         unreachable!("the agent always passes tools")
//!     }
//!     async fn generate_with_tools(
//!         &self,
//!         messages: &[Message],
//!         tools: &[FunctionDefinition],
//!         _: Option<ToolChoice>,
//!     ) -> Result<GenerateResult, LlmError> {
//!         assert_eq!(tools[0].name, "multiply");
//!         let last = messages.last().unwrap();
//!         if last.role == Role::Tool {
//!             // `<tool_output tool="multiply" status="ok">\n21\n</tool_output>`
//!             let fenced = last.content.text_content();
//!             let value = fenced.lines().nth(1).unwrap_or_default();
//!             return Ok(GenerateResult::from_text(format!("3 * 7 = {value}")));
//!         }
//!         Ok(GenerateResult::default().with_tool_calls(vec![ToolCall::new("call_1", "multiply", r#"{"a":3,"b":7}"#)]))
//!     }
//! }
//!
//! # tokio_test::block_on(async {
//! let agent = FunctionCallingAgent::new(Arc::new(ScriptedLlm)).tool(Multiply);
//! let result = agent.run("What is 3 * 7?").await.unwrap();
//! assert_eq!(result.output, "3 * 7 = 21");
//! assert_eq!(result.tool_invocations[0].output, "21");
//! # });
//! ```

/// ReAct-style text agent.
pub mod agent;
/// Human-in-the-loop approval.
pub mod approval;
mod builder;
/// Observability events.
pub mod event;
mod executor;
/// Agent driven by native function calling.
pub mod function_agent;
mod runner;
/// Truncation, fencing and redaction helpers applied to tool output.
pub mod sanitize;

pub use agent::{AgentExecutor, AgentResult};
pub use approval::{Approval, ApprovalRequest, Approver};
pub use event::{AgentEvent, AgentObserver, StopReason, ToolStatus};
pub use executor::ToolExecutor;
pub use function_agent::{FunctionAgentResult, FunctionCallingAgent};
pub use runner::{AgentLimits, ToolErrorMode, ToolInvocation};
