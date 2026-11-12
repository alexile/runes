//! Shared, hardened tool execution used by both agents.

use std::collections::HashSet;
use std::panic::AssertUnwindSafe;
use std::sync::Arc;
use std::time::Duration;

use futures::future::BoxFuture;
use futures::{FutureExt, StreamExt};
use rune_chain_core::{ChainError, FunctionDefinition, Tool, ToolCall, ToolError};
use tokio::time::Instant;

use crate::approval::{Approval, ApprovalRequest, Approver};
use crate::event::{AgentEvent, AgentObserver, ToolStatus};
use crate::sanitize::{FENCE_NOTICE, fence, redact_secrets, sanitize_name, truncate_with_marker};

/// Resource limits for an agent run. Every limit is on by default.
///
/// ```rust
/// use std::time::Duration;
/// use rune_chain_agent::AgentLimits;
///
/// let limits = AgentLimits::default()
///     .max_iterations(5)
///     .tool_timeout(Some(Duration::from_secs(5)))
///     .max_tool_output_bytes(8 * 1024);
/// assert_eq!(limits.max_iterations, 5);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct AgentLimits {
    /// Maximum tool-call rounds (default 10).
    pub max_iterations: usize,
    /// Maximum tool calls executed from one model turn (default 16). Extra
    /// calls are answered with a `skipped` result instead of being run.
    pub max_tool_calls_per_turn: usize,
    /// Maximum tool calls of one turn running at the same time (default 4).
    pub max_concurrency: usize,
    /// Per-tool-call timeout (default 60 s). `None` disables it.
    pub tool_timeout: Option<Duration>,
    /// Wall-clock budget for the whole run, LLM calls included (default
    /// 10 min). `None` disables it.
    pub max_wall_time: Option<Duration>,
    /// Tool output above this many bytes is truncated with a marker before
    /// it reaches the model (default 64 KiB).
    pub max_tool_output_bytes: usize,
    /// Tool error text above this many bytes is truncated (default 1 KiB).
    pub max_error_bytes: usize,
}

impl Default for AgentLimits {
    fn default() -> Self {
        Self {
            max_iterations: 10,
            max_tool_calls_per_turn: 16,
            max_concurrency: 4,
            tool_timeout: Some(Duration::from_secs(60)),
            max_wall_time: Some(Duration::from_secs(600)),
            max_tool_output_bytes: 64 * 1024,
            max_error_bytes: 1024,
        }
    }
}

impl AgentLimits {
    /// Set [`max_iterations`](Self::max_iterations).
    #[must_use]
    pub const fn max_iterations(mut self, n: usize) -> Self {
        self.max_iterations = n;
        self
    }
    /// Set [`max_tool_calls_per_turn`](Self::max_tool_calls_per_turn).
    #[must_use]
    pub const fn max_tool_calls_per_turn(mut self, n: usize) -> Self {
        self.max_tool_calls_per_turn = n;
        self
    }
    /// Set [`max_concurrency`](Self::max_concurrency) (0 is treated as 1).
    #[must_use]
    pub const fn max_concurrency(mut self, n: usize) -> Self {
        self.max_concurrency = n;
        self
    }
    /// Set [`tool_timeout`](Self::tool_timeout).
    #[must_use]
    pub const fn tool_timeout(mut self, timeout: Option<Duration>) -> Self {
        self.tool_timeout = timeout;
        self
    }
    /// Set [`max_wall_time`](Self::max_wall_time).
    #[must_use]
    pub const fn max_wall_time(mut self, budget: Option<Duration>) -> Self {
        self.max_wall_time = budget;
        self
    }
    /// Set [`max_tool_output_bytes`](Self::max_tool_output_bytes).
    #[must_use]
    pub const fn max_tool_output_bytes(mut self, n: usize) -> Self {
        self.max_tool_output_bytes = n;
        self
    }
    /// Set [`max_error_bytes`](Self::max_error_bytes).
    #[must_use]
    pub const fn max_error_bytes(mut self, n: usize) -> Self {
        self.max_error_bytes = n;
        self
    }
}

/// What to do when a tool call fails (unknown tool, invalid arguments, tool
/// error, timeout or panic).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum ToolErrorMode {
    /// Report the (truncated, redacted) error to the model as the tool
    /// result and keep going. The default.
    #[default]
    ReturnToModel,
    /// Abort the run with [`ChainError::ToolError`].
    Abort,
}

/// One executed (or refused) tool call.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ToolInvocation {
    /// Tool-call id.
    pub call_id: String,
    /// Tool name (sanitised if the model named an unknown tool).
    pub name: String,
    /// Arguments the tool actually ran with (after an approver's edit).
    pub arguments: String,
    /// Output or error text as given to the model, before fencing.
    pub output: String,
    /// Outcome.
    pub status: ToolStatus,
    /// Whether `output` was truncated.
    pub truncated: bool,
}

/// How the model phrased a call: `ReAct` passes free text, native function
/// calling passes a JSON object.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallStyle {
    Text,
    Json,
}

struct Registered {
    tool: Arc<dyn Tool>,
    definition: FunctionDefinition,
    requires_approval: bool,
}

/// Tools plus the policy for running them.
pub struct Toolbox {
    tools: Vec<Registered>,
    pub(crate) limits: AgentLimits,
    pub(crate) error_mode: ToolErrorMode,
    pub(crate) fence_outputs: bool,
    approver: Option<Arc<dyn Approver>>,
    observer: Option<Arc<dyn AgentObserver>>,
}

impl Default for Toolbox {
    fn default() -> Self {
        Self {
            tools: Vec::new(),
            limits: AgentLimits::default(),
            error_mode: ToolErrorMode::default(),
            fence_outputs: true,
            approver: None,
            observer: None,
        }
    }
}

impl Toolbox {
    pub(crate) fn add(&mut self, tool: Arc<dyn Tool>, requires_approval: bool) {
        let definition = tool.function_definition();
        self.tools.push(Registered {
            tool,
            definition,
            requires_approval,
        });
    }

    pub(crate) fn set_approver(&mut self, approver: Arc<dyn Approver>) {
        self.approver = Some(approver);
    }

    pub(crate) fn set_observer(&mut self, observer: Arc<dyn AgentObserver>) {
        self.observer = Some(observer);
    }

    pub(crate) fn emit(&self, event: &AgentEvent) {
        if let Some(observer) = &self.observer {
            observer.on_event(event);
        }
    }

    pub(crate) fn definitions(&self) -> Vec<FunctionDefinition> {
        self.tools.iter().map(|r| r.definition.clone()).collect()
    }

    pub(crate) fn tools(&self) -> impl Iterator<Item = &dyn Tool> {
        self.tools.iter().map(|r| r.tool.as_ref())
    }

    /// Reject tool sets the model could not address unambiguously.
    pub(crate) fn check(&self) -> Result<(), ChainError> {
        let mut seen = HashSet::new();
        for r in &self.tools {
            if !r.definition.has_valid_name() {
                return Err(ChainError::Other(format!(
                    "tool name `{}` is invalid: use 1-64 ASCII letters, digits, `_` or `-`",
                    sanitize_name(&r.definition.name)
                )));
            }
            if !seen.insert(r.definition.name.as_str()) {
                return Err(ChainError::Other(format!(
                    "tool `{}` is registered twice",
                    r.definition.name
                )));
            }
        }
        Ok(())
    }

    /// The system prompt with the fencing notice appended when fencing is on.
    pub(crate) fn system_prompt(&self, base: String) -> String {
        if self.fence_outputs {
            format!("{base}\n\n{FENCE_NOTICE}")
        } else {
            base
        }
    }

    /// Render an invocation for insertion into the conversation.
    pub(crate) fn render(&self, inv: &ToolInvocation) -> String {
        if self.fence_outputs {
            fence(&inv.name, inv.status.as_str(), &inv.output)
        } else {
            inv.output.clone()
        }
    }

    pub(crate) fn deadline(&self) -> Option<Instant> {
        self.limits.max_wall_time.map(|d| Instant::now() + d)
    }

    /// Execute one model turn's tool calls: at most
    /// `max_tool_calls_per_turn`, `max_concurrency` at a time, results in call
    /// order.
    pub(crate) async fn execute(
        &self,
        calls: &[ToolCall],
        style: CallStyle,
        iteration: usize,
        deadline: Option<Instant>,
    ) -> Result<Vec<ToolInvocation>, ChainError> {
        let limit = self.limits.max_tool_calls_per_turn;
        // Boxed up front: a lazily-mapped stream of borrowing futures trips
        // rustc's higher-ranked `Send` inference inside `async_trait` callers.
        let mut pending: Vec<BoxFuture<'_, ToolInvocation>> = Vec::with_capacity(calls.len());
        for (i, call) in calls.iter().enumerate() {
            if i < limit {
                pending.push(self.execute_one(call, style, iteration, deadline).boxed());
            } else {
                let inv = ToolInvocation {
                    call_id: call.id.clone(),
                    name: sanitize_name(&call.name),
                    arguments: call.arguments.clone(),
                    output: format!("not executed: at most {limit} tool calls are run per turn"),
                    status: ToolStatus::Skipped,
                    truncated: false,
                };
                pending.push(async move { inv }.boxed());
            }
        }
        let results: Vec<ToolInvocation> = futures::stream::iter(pending)
            .buffered(self.limits.max_concurrency.max(1))
            .collect()
            .await;
        for inv in results.iter().skip(limit) {
            self.emit_result(iteration, inv);
        }

        if self.error_mode == ToolErrorMode::Abort
            && let Some(failed) = results.iter().find(|r| r.status == ToolStatus::Error)
        {
            return Err(ChainError::ToolError(ToolError::ExecutionFailed(format!(
                "tool `{}` failed: {}",
                failed.name, failed.output
            ))));
        }
        Ok(results)
    }

    async fn execute_one(
        &self,
        call: &ToolCall,
        style: CallStyle,
        iteration: usize,
        deadline: Option<Instant>,
    ) -> ToolInvocation {
        let name = sanitize_name(&call.name);
        self.emit(&AgentEvent::ToolCalled {
            iteration,
            call_id: call.id.clone(),
            name: name.clone(),
            arguments: call.arguments.clone(),
        });
        let mut inv = ToolInvocation {
            call_id: call.id.clone(),
            name,
            arguments: call.arguments.clone(),
            output: String::new(),
            status: ToolStatus::Error,
            truncated: false,
        };
        match self
            .run_checked(call, style, iteration, deadline, &mut inv)
            .await
        {
            Ok(output) => {
                let (out, cut) = truncate_with_marker(&output, self.limits.max_tool_output_bytes);
                inv.output = out;
                inv.truncated = cut;
                inv.status = ToolStatus::Ok;
            }
            Err((status, message)) => {
                let message = if status == ToolStatus::Error {
                    redact_secrets(&message)
                } else {
                    message
                };
                let (out, cut) = truncate_with_marker(&message, self.limits.max_error_bytes);
                inv.output = out;
                inv.truncated = cut;
                inv.status = status;
            }
        }
        self.emit_result(iteration, &inv);
        inv
    }

    fn emit_result(&self, iteration: usize, inv: &ToolInvocation) {
        self.emit(&AgentEvent::ToolResult {
            iteration,
            call_id: inv.call_id.clone(),
            name: inv.name.clone(),
            status: inv.status,
            output: inv.output.clone(),
            truncated: inv.truncated,
        });
    }

    async fn run_checked(
        &self,
        call: &ToolCall,
        style: CallStyle,
        iteration: usize,
        deadline: Option<Instant>,
        inv: &mut ToolInvocation,
    ) -> Result<String, (ToolStatus, String)> {
        let err = |m: String| (ToolStatus::Error, m);
        let Some(reg) = self.tools.iter().find(|r| r.definition.name == call.name) else {
            let available: Vec<&str> = self
                .tools
                .iter()
                .map(|r| r.definition.name.as_str())
                .collect();
            return Err(err(format!(
                "unknown tool `{}`; available tools: {}",
                inv.name,
                if available.is_empty() {
                    "(none)".to_owned()
                } else {
                    available.join(", ")
                }
            )));
        };
        validate(call, style, &reg.definition).map_err(|e| err(e.to_string()))?;

        let mut input = call.arguments.clone();
        if reg.requires_approval {
            let Some(approver) = &self.approver else {
                return Err((
                    ToolStatus::Denied,
                    "this tool requires approval and no approver is configured".to_owned(),
                ));
            };
            let request = ApprovalRequest {
                iteration,
                call_id: call.id.clone(),
                tool: reg.definition.name.clone(),
                arguments: input.clone(),
            };
            match approver.approve(request).await {
                Approval::Allow => {}
                Approval::Deny(reason) => {
                    return Err((ToolStatus::Denied, format!("denied by approver: {reason}")));
                }
                Approval::Edit(edited) => {
                    let edited_call = ToolCall::new(&call.id, &call.name, edited);
                    validate(&edited_call, style, &reg.definition)
                        .map_err(|e| err(format!("edited arguments are invalid: {e}")))?;
                    input = edited_call.arguments;
                    inv.arguments.clone_from(&input);
                }
            }
        }

        let timeout = match (self.limits.tool_timeout, deadline) {
            (Some(t), Some(d)) => Some(t.min(d.saturating_duration_since(Instant::now()))),
            (t, None) => t,
            (None, Some(d)) => Some(d.saturating_duration_since(Instant::now())),
        };
        let fut = AssertUnwindSafe(reg.tool.run(&input)).catch_unwind();
        let outcome = match timeout {
            Some(t) => tokio::time::timeout(t, fut)
                .await
                .map_err(|_| err(format!("timed out after {} ms", t.as_millis())))?,
            None => fut.await,
        };
        match outcome {
            Ok(Ok(output)) => Ok(output),
            Ok(Err(e)) => Err(err(format!("tool error: {e}"))),
            Err(_) => Err(err("tool panicked".to_owned())),
        }
    }
}

/// Validate a call against the tool's schema.
///
/// Native calls are validated as-is. `ReAct` text input that is not a JSON
/// object is checked as `{"input": <text>}`, the shape of the default schema,
/// so free-text tools pass and tools that need structured arguments reject it.
fn validate(
    call: &ToolCall,
    style: CallStyle,
    definition: &FunctionDefinition,
) -> Result<(), ToolError> {
    if style == CallStyle::Text && !call.arguments.trim_start().starts_with('{') {
        if call.arguments.len() > rune_chain_core::MAX_TOOL_ARGUMENTS_BYTES {
            return Err(ToolError::InvalidInput(format!(
                "input is {} bytes, above the {}-byte limit",
                call.arguments.len(),
                rune_chain_core::MAX_TOOL_ARGUMENTS_BYTES
            )));
        }
        let wrapped = serde_json::json!({ "input": call.arguments }).to_string();
        return ToolCall::new(&call.id, &call.name, wrapped)
            .validate(definition)
            .map(drop);
    }
    call.validate(definition).map(drop)
}
