//! Human-in-the-loop approval for sensitive tools.
//!
//! Register a tool with `tool_requiring_approval` and give the agent an
//! [`Approver`]. Before every call to that tool the approver sees the exact
//! arguments and may allow the call, deny it (the reason goes back to the
//! model as the tool result), or edit the arguments (they are re-validated
//! against the tool's schema before the tool runs).
//!
//! Approval fails closed: a tool that requires approval is never run when the
//! agent has no approver.

use std::future::Future;

use async_trait::async_trait;

/// A pending call to a tool that requires approval.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ApprovalRequest {
    /// Agent iteration (tool-call round) the call belongs to, from 1.
    pub iteration: usize,
    /// Provider tool-call id (synthesised for the `ReAct` agent).
    pub call_id: String,
    /// Name of the tool to run.
    pub tool: String,
    /// Arguments exactly as they would be passed to [`Tool::run`](rune_chain_core::Tool::run).
    pub arguments: String,
}

/// An approver's decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Approval {
    /// Run the tool with the original arguments.
    Allow,
    /// Do not run the tool; the reason is reported to the model.
    Deny(String),
    /// Run the tool with these arguments instead (re-validated first).
    Edit(String),
}

/// Decides whether a tool call that requires approval may run.
///
/// When one model turn asks for several gated calls, `approve` may be called
/// for them concurrently (up to [`AgentLimits::max_concurrency`](crate::AgentLimits::max_concurrency)),
/// while ungated calls of the same turn run. A pending approval counts against
/// [`AgentLimits::max_wall_time`](crate::AgentLimits::max_wall_time): if the
/// budget runs out first, or `approve` panics, the call is denied.
///
/// Implemented for any `Fn(ApprovalRequest) -> impl Future<Output = Approval>`:
///
/// ```rust
/// use rune_chain_agent::{Approval, ApprovalRequest, Approver};
///
/// let approver = |req: ApprovalRequest| async move {
///     if req.arguments.contains("rm -rf") {
///         Approval::Deny("destructive".into())
///     } else {
///         Approval::Allow
///     }
/// };
/// fn takes(_: impl Approver) {}
/// takes(approver);
/// ```
#[async_trait]
pub trait Approver: Send + Sync {
    /// Decide on `request`.
    async fn approve(&self, request: ApprovalRequest) -> Approval;
}

#[async_trait]
impl<F, Fut> Approver for F
where
    F: Fn(ApprovalRequest) -> Fut + Send + Sync,
    Fut: Future<Output = Approval> + Send,
{
    async fn approve(&self, request: ApprovalRequest) -> Approval {
        self(request).await
    }
}
