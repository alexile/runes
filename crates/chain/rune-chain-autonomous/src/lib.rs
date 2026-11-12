//! Budgeted autonomous agent for `rune-chain`.
//!
//! [`AutonomousAgent`] takes a *goal* rather than a question and works toward
//! it without further input, in the style of `AutoGPT` and `BabyAGI`:
//!
//! 1. **Plan.** A [`TaskPlanner`] turns the goal into a queue of tasks.
//! 2. **Execute.** Tasks run one at a time. With tools registered, each task
//!    runs in a hardened [`rune_chain_agent::FunctionCallingAgent`]; without
//!    tools it is a single LLM call.
//! 3. **Review.** When the queue is empty the planner judges progress and
//!    either declares the goal done or queues more tasks.
//!
//! Every run ends with a [`RunOutcome`]: `Completed`, `BudgetExceeded`,
//! `LoopDetected`, `Stopped` or `Error`, together with an [`AgentState`]
//! that can be serialized and [resumed](AutonomousAgent::resume).
//!
//! # Security model
//!
//! An autonomous loop lets model output decide what happens next, over and
//! over, so the agent assumes that output can be wrong or hostile:
//!
//! - **Hard limits, on by default.** [`Limits`] caps tasks, planning cycles,
//!   LLM calls, wall time, total tokens and cost (with a
//!   [`Pricing`](rune_chain_core::Pricing)), plus the number of generated
//!   tasks and the queue length. Every LLM call, from the planner, the task
//!   loop or a custom planner, goes through one governor that checks the
//!   limits first, so nothing can spend past them by more than the call in
//!   flight.
//! - **A stop the model cannot override.** Limits live in the agent's
//!   configuration, never in a prompt. A [`StopHandle`] and an optional
//!   [`stop_when`](AutonomousAgent::stop_when) predicate end the run from
//!   outside. The model can only end a run early (by declaring the goal
//!   done), never extend it.
//! - **Loop detection.** A task that already ran
//!   [`max_task_repeats`](Limits::max_task_repeats) times is not queued again,
//!   and a review that proposes only such tasks (or nothing) ends the run as
//!   [`LoopDetected`](RunOutcome::LoopDetected). A tool called with identical
//!   arguments more than
//!   [`max_identical_tool_calls`](Limits::max_identical_tool_calls) times is
//!   refused and ends the run the same way.
//! - **Checked tools.** Tool calls get the same treatment as in
//!   `rune-chain-agent`: schema validation, per-call timeouts, output size
//!   caps, secret redaction in errors, and an [`Approver`] for tools
//!   registered with
//!   [`tool_requiring_approval`](AutonomousAgent::tool_requiring_approval)
//!   (fail-closed without one).
//! - **Untrusted text stays fenced.** Generated tasks, task results and tool
//!   output are quoted in `<task>`, `<task_result>` and `<tool_output>` blocks
//!   with embedded closing tags escaped, always in user/tool turns. System
//!   prompts are fixed strings and say that fenced text is data. Task text is
//!   cleaned to one line and capped in length.
//! - **Bounded memory.** The queue, the stored history, each stored result
//!   and the context quoted into prompts all have byte or item limits.
//!
//! # Quick start
//!
//! This runs offline against a scripted model: the planner asks for two
//! look-ups, each task calls the `price_lookup` tool, and the review reports
//! the goal done.
//!
//! ```rust
//! use std::sync::Arc;
//!
//! use async_trait::async_trait;
//! use rune_chain_autonomous::{AutonomousAgent, RunOutcome};
//! use rune_chain_core::{
//!     FunctionDefinition, GenerateResult, Llm, LlmError, Message, Role, Tool, ToolCall,
//!     ToolChoice, ToolError,
//! };
//!
//! struct PriceLookup;
//!
//! #[async_trait]
//! impl Tool for PriceLookup {
//!     fn name(&self) -> &str { "price_lookup" }
//!     fn description(&self) -> &str { "Returns the list price of a company's product." }
//!     async fn run(&self, input: &str) -> Result<String, ToolError> {
//!         Ok(if input.contains("Acme") { "Acme: $49".into() } else { "Globex: $59".into() })
//!     }
//! }
//!
//! /// Recognises which step it is asked for from the system prompt.
//! struct ScriptedLlm;
//!
//! #[async_trait]
//! impl Llm for ScriptedLlm {
//!     async fn generate(&self, messages: &[Message]) -> Result<GenerateResult, LlmError> {
//!         let system = messages[0].content.text_content();
//!         let reply = if system.contains("planning") {
//!             "1. Look up Acme pricing\n2. Look up Globex pricing"
//!         } else {
//!             "STATUS: DONE\nANSWER: Acme $49 vs Globex $59"
//!         };
//!         Ok(GenerateResult::from_text(reply))
//!     }
//!
//!     async fn generate_with_tools(
//!         &self,
//!         messages: &[Message],
//!         _: &[FunctionDefinition],
//!         _: Option<ToolChoice>,
//!     ) -> Result<GenerateResult, LlmError> {
//!         let last = messages.last().unwrap();
//!         if last.role == Role::Tool {
//!             // `<tool_output tool="price_lookup" status="ok">\nAcme: $49\n</tool_output>`
//!             let fenced = last.content.text_content();
//!             return Ok(GenerateResult::from_text(fenced.lines().nth(1).unwrap_or_default()));
//!         }
//!         let prompt = last.content.text_content();
//!         let current = prompt.split("Current task:").nth(1).unwrap_or_default();
//!         let company = if current.contains("Acme") { "Acme" } else { "Globex" };
//!         let args = serde_json::json!({ "input": company }).to_string();
//!         Ok(GenerateResult::default().with_tool_calls(vec![ToolCall::new("call_1", "price_lookup", args)]))
//!     }
//! }
//!
//! # tokio_test::block_on(async {
//! let agent = AutonomousAgent::new(Arc::new(ScriptedLlm))
//!     .tool(PriceLookup)
//!     .max_tasks(10);
//!
//! let run = agent.run("Compare Acme and Globex pricing.").await.unwrap();
//! assert_eq!(run.outcome, RunOutcome::Completed { answer: "Acme $49 vs Globex $59".into() });
//! assert_eq!(run.state.history[0].result, "Acme: $49");
//! assert_eq!(run.state.history[1].result, "Globex: $59");
//! assert_eq!(run.state.llm_calls, 6); // plan + 2 × (tool call + answer) + review
//! # });
//! ```

mod agent;
mod event;
mod governor;
mod limits;
mod outcome;
mod planner;
mod state;
mod untrusted;

pub use agent::{AutonomousAgent, AutonomousRun};
pub use event::{AutonomousEvent, AutonomousObserver, DropReason, StopHandle};
pub use limits::{BudgetKind, Limits};
pub use outcome::{LoopKind, RunOutcome, StopCause};
pub use planner::{LlmPlanner, PlanContext, Review, StaticPlanner, TaskPlanner};
pub use state::{AgentState, CHECKPOINT_VERSION, Task, TaskRecord};
pub use untrusted::UNTRUSTED_NOTICE;

pub use rune_chain_agent::{
    AgentEvent, AgentLimits, Approval, ApprovalRequest, Approver, ToolErrorMode, ToolStatus,
};
