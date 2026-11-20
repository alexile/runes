//! The hardened tool runner on its own, for loops you write yourself.

use rune_chain_core::{ChainError, FunctionDefinition, Message, ToolCall};

use crate::builder::toolbox_builder;
use crate::runner::{CallStyle, ToolInvocation, Toolbox};

/// Runs model-requested tool calls with the same checks, limits, approval and
/// fencing as [`FunctionCallingAgent`](crate::FunctionCallingAgent), without
/// owning the loop around them.
///
/// Use it when something else drives the conversation, such as a state
/// graph: hand it the tool calls of one AI turn and add the returned tool
/// messages to the history.
///
/// [`AgentLimits::max_wall_time`](crate::AgentLimits::max_wall_time) bounds a
/// single [`execute`](Self::execute) call here, and
/// [`AgentLimits::max_iterations`](crate::AgentLimits::max_iterations) is not
/// used.
///
/// ```rust
/// use async_trait::async_trait;
/// use rune_chain_agent::{ToolExecutor, ToolStatus};
/// use rune_chain_core::{Tool, ToolCall, ToolError};
///
/// struct Upper;
///
/// #[async_trait]
/// impl Tool for Upper {
///     fn name(&self) -> &str { "upper" }
///     fn description(&self) -> &str { "Upper-cases text." }
///     async fn run(&self, input: &str) -> Result<String, ToolError> {
///         Ok(input.to_uppercase())
///     }
/// }
///
/// # tokio_test::block_on(async {
/// let tools = ToolExecutor::new().tool(Upper);
/// let calls = [
///     ToolCall::new("c1", "upper", r#"{"input":"hi"}"#),
///     ToolCall::new("c2", "nope", "{}"),
/// ];
/// let runs = tools.execute(&calls, 1).await.unwrap();
/// assert_eq!(runs[0].status, ToolStatus::Ok);
/// assert_eq!(runs[1].status, ToolStatus::Error);
///
/// let messages = tools.tool_messages(&runs);
/// assert_eq!(messages[0].tool_call_id.as_deref(), Some("c1"));
/// assert!(messages[0].text().contains("<tool_output"));
/// # });
/// ```
#[derive(Default)]
pub struct ToolExecutor {
    toolbox: Toolbox,
}

impl std::fmt::Debug for ToolExecutor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ToolExecutor")
            .field(
                "tools",
                &self
                    .toolbox
                    .tools()
                    .map(rune_chain_core::Tool::name)
                    .collect::<Vec<_>>(),
            )
            .field("limits", &self.toolbox.limits)
            .finish_non_exhaustive()
    }
}

impl ToolExecutor {
    /// An executor with no tools and default limits.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    toolbox_builder!();

    /// Function definitions to pass to
    /// [`Llm::generate_with_tools`](rune_chain_core::Llm::generate_with_tools).
    #[must_use]
    pub fn definitions(&self) -> Vec<FunctionDefinition> {
        self.toolbox.definitions()
    }

    /// Reject tool sets with invalid or duplicate names.
    ///
    /// [`execute`](Self::execute) runs this check too.
    pub fn check(&self) -> Result<(), ChainError> {
        self.toolbox.check()
    }

    /// `base` with the untrusted-output notice appended while fencing is on.
    /// Use it as the system prompt of the model that reads the results.
    #[must_use]
    pub fn system_prompt(&self, base: impl Into<String>) -> String {
        self.toolbox.system_prompt(base.into())
    }

    /// Run one AI turn's tool calls and return one invocation per call, in
    /// call order. `iteration` is only reported in events and approval
    /// requests.
    ///
    /// # Errors
    ///
    /// An invalid tool set, or a failed call under
    /// [`ToolErrorMode::Abort`](crate::ToolErrorMode::Abort).
    pub async fn execute(
        &self,
        calls: &[ToolCall],
        iteration: usize,
    ) -> Result<Vec<ToolInvocation>, ChainError> {
        self.toolbox.check()?;
        self.toolbox
            .execute(calls, CallStyle::Json, iteration, self.toolbox.deadline())
            .await
    }

    /// The text the model should see for `invocation` (fenced while fencing
    /// is on).
    #[must_use]
    pub fn render(&self, invocation: &ToolInvocation) -> String {
        self.toolbox.render(invocation)
    }

    /// One [`Role::Tool`](rune_chain_core::Role::Tool) message per invocation.
    #[must_use]
    pub fn tool_messages(&self, invocations: &[ToolInvocation]) -> Vec<Message> {
        invocations
            .iter()
            .map(|inv| Message::tool_result(&inv.call_id, self.render(inv)))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AgentLimits, Approval, ApprovalRequest, ToolStatus};
    use async_trait::async_trait;
    use rune_chain_core::{Tool, ToolError};

    struct Echo(&'static str);

    #[async_trait]
    impl Tool for Echo {
        fn name(&self) -> &str {
            self.0
        }
        fn description(&self) -> &'static str {
            "echo"
        }
        async fn run(&self, input: &str) -> Result<String, ToolError> {
            Ok(input.to_owned())
        }
    }

    #[tokio::test]
    async fn applies_limits_and_approval() {
        let tools = ToolExecutor::new()
            .tool(Echo("echo"))
            .tool_requiring_approval(Echo("gated"))
            .approver(|_: ApprovalRequest| async { Approval::Deny("no".into()) })
            .limits(AgentLimits::default().max_tool_calls_per_turn(2));
        let calls = [
            ToolCall::new("1", "echo", r#"{"input":"a"}"#),
            ToolCall::new("2", "gated", r#"{"input":"b"}"#),
            ToolCall::new("3", "echo", r#"{"input":"c"}"#),
        ];
        let runs = tools.execute(&calls, 1).await.unwrap();
        let statuses: Vec<_> = runs.iter().map(|r| r.status).collect();
        assert_eq!(
            statuses,
            [ToolStatus::Ok, ToolStatus::Denied, ToolStatus::Skipped]
        );
        assert_eq!(tools.definitions().len(), 2);
        assert!(tools.system_prompt("hi").starts_with("hi\n\n"));
    }

    #[tokio::test]
    async fn rejects_duplicate_tools() {
        let tools = ToolExecutor::new().tool(Echo("echo")).tool(Echo("echo"));
        assert!(tools.execute(&[], 1).await.is_err());
    }
}
