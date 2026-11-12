//! Autonomous goal-driven agent for `rune-chain`.
//!
//! [`AutonomousAgent`] takes a single high-level *goal* — not a single question —
//! and drives itself to completion without further human input:
//!
//! 1. **Plan** — the LLM breaks the goal into an ordered list of concrete tasks.
//! 2. **Execute** — each task is run in turn, calling registered [`Tool`](rune_chain_core::Tool)s as needed.
//! 3. **Reflect** — after the plan is exhausted, the LLM judges whether the goal
//!    is fully achieved. If not, it produces a revised task list and the loop
//!    continues from step 2.
//!
//! The run ends when reflection reports the goal is done, the replanning limit
//! is reached (`Blocked`), or the total step budget is exhausted.
//!
//! This differs from [`AgentExecutor`](https://docs.rs/rune-chain-agent) and
//! [`FunctionCallingAgent`](https://docs.rs/rune-chain-agent), which each answer
//! *one* input in a single bounded loop. `AutonomousAgent` sits a level above:
//! it decomposes a goal into multiple such tasks and keeps re-planning across
//! them until the goal — not just one task — is satisfied.
//!
//! # Quick Start
//!
//! The agent works with any [`Llm`](rune_chain_core::Llm). This example runs
//! offline against a scripted model: it plans two look-ups, executes each by
//! calling the `price_lookup` tool, then reflects and reports the goal done.
//!
//! ```rust
//! use std::sync::Arc;
//!
//! use async_trait::async_trait;
//! use rune_chain_autonomous::{AutonomousAgent, RunStatus};
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
//! /// A real model reads the prompts; this script only recognises which phase
//! /// (planning, task execution, reflection) it is being asked for.
//! struct ScriptedLlm;
//!
//! #[async_trait]
//! impl Llm for ScriptedLlm {
//!     async fn generate(&self, messages: &[Message]) -> Result<GenerateResult, LlmError> {
//!         let system = messages[0].content.text_content();
//!         let reply = if system.contains("planning") {
//!             "1. Look up Acme pricing\n2. Look up Globex pricing".to_string()
//!         } else {
//!             "STATUS: DONE\nANSWER: Acme $49 vs Globex $59".to_string()
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
//!             return Ok(GenerateResult::from_text(last.content.text_content()));
//!         }
//!         let company = if last.content.text_content().contains("task: Look up Acme") {
//!             "Acme"
//!         } else {
//!             "Globex"
//!         };
//!         let args = serde_json::json!({ "input": company }).to_string();
//!         Ok(GenerateResult::default().with_tool_calls(vec![ToolCall::new("call_1", "price_lookup", args)]))
//!     }
//! }
//!
//! # tokio_test::block_on(async {
//! let agent = AutonomousAgent::new(Arc::new(ScriptedLlm))
//!     .tool(PriceLookup)
//!     .max_steps(25)
//!     .max_replans(3);
//!
//! let result = agent.run("Compare Acme and Globex pricing.").await.unwrap();
//! assert_eq!(result.status, RunStatus::Completed);
//! assert_eq!(result.output, "Acme $49 vs Globex $59");
//! assert_eq!(result.plans[0], ["Look up Acme pricing", "Look up Globex pricing"]);
//! assert_eq!(result.history[0].output, "Acme: $49");
//! assert_eq!(result.history[1].output, "Globex: $59");
//! # });
//! ```

mod agent;

pub use agent::{AutonomousAgent, AutonomousResult, RunStatus, StepRecord};
