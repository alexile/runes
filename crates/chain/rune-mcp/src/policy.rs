//! Per-tool policy: which tools are visible and which calls may run.
//!
//! A [`ToolPolicy`] is consulted by [`McpServer`](crate::McpServer) before a
//! registered tool runs, and by [`McpClient`](crate::McpClient) before a call
//! is sent to a remote server. It sees the tool's
//! [`ToolDescriptor`] (with its [`SafetyLevel`]) and the call's arguments,
//! and returns a [`Decision`]. Policies are plain synchronous code with no
//! I/O, so they are easy to test on their own.

use std::collections::BTreeSet;
use std::fmt;
use std::sync::Arc;

use rune_tool_schema::{SafetyLevel, ToolDescriptor};
use serde_json::{Map, Value};

/// Which end of the MCP session a call is checked on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Side {
    /// [`McpServer`](crate::McpServer), before it runs a local tool.
    Server,
    /// [`McpClient`](crate::McpClient), before it calls a remote tool.
    Client,
}

/// A tool call presented to a [`ToolPolicy`].
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct ToolCall<'a> {
    /// The called tool. On the client side, its safety level reflects the
    /// client's [`ServerTrust`](crate::ServerTrust).
    pub tool: &'a ToolDescriptor,
    /// The call's arguments.
    pub arguments: &'a Map<String, Value>,
    /// Where the check runs.
    pub side: Side,
}

impl<'a> ToolCall<'a> {
    /// A call of `tool` with `arguments`, checked on `side`.
    #[must_use]
    pub const fn new(
        tool: &'a ToolDescriptor,
        arguments: &'a Map<String, Value>,
        side: Side,
    ) -> Self {
        Self {
            tool,
            arguments,
            side,
        }
    }
}

/// A policy's verdict on a call.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Decision {
    /// Run the call.
    Allow,
    /// Refuse the call, with a reason for the caller.
    Deny(String),
}

impl Decision {
    /// A denial with this reason.
    #[must_use]
    pub fn deny(reason: impl Into<String>) -> Self {
        Self::Deny(reason.into())
    }

    /// Whether the call may run.
    #[must_use]
    pub const fn is_allowed(&self) -> bool {
        matches!(self, Self::Allow)
    }
}

/// Decides which tools are listed and which calls run.
///
/// Any `Fn(&ToolCall) -> Decision` closure is a policy that lists every
/// tool:
///
/// ```
/// use rune_mcp::{Decision, Side, ToolCall, ToolPolicy};
/// use rune_tool_schema::ToolDescriptor;
///
/// let no_empty_input = |call: &ToolCall<'_>| match call.arguments.get("input") {
///     Some(serde_json::Value::String(s)) if s.is_empty() => Decision::deny("empty input"),
///     _ => Decision::Allow,
/// };
///
/// let tool = ToolDescriptor::new("echo", "Echo the input.");
/// let args = serde_json::json!({"input": ""});
/// let args = args.as_object().unwrap();
/// let call = ToolCall::new(&tool, args, Side::Server);
/// assert_eq!(no_empty_input.check(&call), Decision::deny("empty input"));
/// ```
pub trait ToolPolicy: Send + Sync {
    /// Whether `tool` is listed at all. A hidden tool cannot be called.
    /// The default lists every tool.
    fn visible(&self, tool: &ToolDescriptor) -> bool {
        let _ = tool;
        true
    }

    /// Whether this call may run.
    fn check(&self, call: &ToolCall<'_>) -> Decision;
}

impl<F> ToolPolicy for F
where
    F: Fn(&ToolCall<'_>) -> Decision + Send + Sync,
{
    fn check(&self, call: &ToolCall<'_>) -> Decision {
        self(call)
    }
}

impl<P: ToolPolicy + ?Sized> ToolPolicy for Arc<P> {
    fn visible(&self, tool: &ToolDescriptor) -> bool {
        (**self).visible(tool)
    }

    fn check(&self, call: &ToolCall<'_>) -> Decision {
        (**self).check(call)
    }
}

/// Lists and allows every tool. The default policy.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AllowAll;

impl ToolPolicy for AllowAll {
    fn check(&self, _call: &ToolCall<'_>) -> Decision {
        Decision::Allow
    }
}

/// Lists and allows only tools at or below a [`SafetyLevel`].
///
/// ```
/// use rune_mcp::{MaxSafety, ToolPolicy};
/// use rune_tool_schema::{SafetyLevel, ToolDescriptor};
///
/// let policy = MaxSafety(SafetyLevel::Active);
/// let scan = ToolDescriptor::new("scan", "Port scan.").with_safety(SafetyLevel::Intrusive);
/// assert!(!policy.visible(&scan));
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MaxSafety(pub SafetyLevel);

impl ToolPolicy for MaxSafety {
    fn visible(&self, tool: &ToolDescriptor) -> bool {
        tool.safety <= self.0
    }

    fn check(&self, call: &ToolCall<'_>) -> Decision {
        if call.tool.safety <= self.0 {
            Decision::Allow
        } else {
            Decision::Deny(format!(
                "safety level {} exceeds the allowed {}",
                call.tool.safety.as_str(),
                self.0.as_str()
            ))
        }
    }
}

/// Lists and allows only the named tools.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AllowNames(BTreeSet<String>);

impl AllowNames {
    /// Allow exactly these tool names.
    pub fn new<I, S>(names: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self(names.into_iter().map(Into::into).collect())
    }
}

impl ToolPolicy for AllowNames {
    fn visible(&self, tool: &ToolDescriptor) -> bool {
        self.0.contains(&tool.name)
    }

    fn check(&self, call: &ToolCall<'_>) -> Decision {
        if self.0.contains(&call.tool.name) {
            Decision::Allow
        } else {
            Decision::deny("tool is not on the allow list")
        }
    }
}

/// Lists and allows every tool except the named ones.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DenyNames(BTreeSet<String>);

impl DenyNames {
    /// Deny exactly these tool names.
    pub fn new<I, S>(names: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self(names.into_iter().map(Into::into).collect())
    }
}

impl ToolPolicy for DenyNames {
    fn visible(&self, tool: &ToolDescriptor) -> bool {
        !self.0.contains(&tool.name)
    }

    fn check(&self, call: &ToolCall<'_>) -> Decision {
        if self.0.contains(&call.tool.name) {
            Decision::deny("tool is on the deny list")
        } else {
            Decision::Allow
        }
    }
}

/// Every policy must agree: a tool is visible if all list it, and a call
/// runs if all allow it. The first denial wins.
///
/// ```
/// use rune_mcp::{AllOf, DenyNames, MaxSafety, ToolPolicy};
/// use rune_tool_schema::{SafetyLevel, ToolDescriptor};
///
/// let policy = AllOf::new()
///     .with(MaxSafety(SafetyLevel::Active))
///     .with(DenyNames::new(["shell"]));
/// assert!(policy.visible(&ToolDescriptor::new("hex_encode", "Hex.")));
/// assert!(!policy.visible(&ToolDescriptor::new("shell", "Run a command.")));
/// ```
#[derive(Clone, Default)]
pub struct AllOf(Vec<Arc<dyn ToolPolicy>>);

impl AllOf {
    /// No policies yet: allows everything.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a policy.
    #[must_use]
    pub fn with(mut self, policy: impl ToolPolicy + 'static) -> Self {
        self.0.push(Arc::new(policy));
        self
    }
}

impl fmt::Debug for AllOf {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AllOf")
            .field("policies", &self.0.len())
            .finish()
    }
}

impl ToolPolicy for AllOf {
    fn visible(&self, tool: &ToolDescriptor) -> bool {
        self.0.iter().all(|policy| policy.visible(tool))
    }

    fn check(&self, call: &ToolCall<'_>) -> Decision {
        for policy in &self.0 {
            let decision = policy.check(call);
            if !decision.is_allowed() {
                return decision;
            }
        }
        Decision::Allow
    }
}

/// Run the full policy gate for a call: the tool must be visible and the
/// call allowed.
pub fn gate(policy: &dyn ToolPolicy, call: &ToolCall<'_>) -> Decision {
    if policy.visible(call.tool) {
        policy.check(call)
    } else {
        Decision::deny("tool is hidden by policy")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn args(value: &Value) -> &Map<String, Value> {
        value.as_object().unwrap()
    }

    #[test]
    fn max_safety_orders_levels() {
        let empty = json!({});
        let policy = MaxSafety(SafetyLevel::Active);
        for (level, allowed) in [
            (SafetyLevel::Passive, true),
            (SafetyLevel::Active, true),
            (SafetyLevel::Intrusive, false),
        ] {
            let tool = ToolDescriptor::new("t", "d").with_safety(level);
            assert_eq!(policy.visible(&tool), allowed);
            let call = ToolCall::new(&tool, args(&empty), Side::Server);
            assert_eq!(policy.check(&call).is_allowed(), allowed);
        }
    }

    #[test]
    fn name_lists() {
        let empty = json!({});
        let a = ToolDescriptor::new("a", "d");
        let b = ToolDescriptor::new("b", "d");
        let allow = AllowNames::new(["a"]);
        let deny = DenyNames::new(["a"]);
        assert!(allow.visible(&a) && !allow.visible(&b));
        assert!(!deny.visible(&a) && deny.visible(&b));
        let call = ToolCall::new(&b, args(&empty), Side::Client);
        assert!(!allow.check(&call).is_allowed());
        assert!(deny.check(&call).is_allowed());
    }

    #[test]
    fn all_of_first_denial_wins() {
        let empty = json!({});
        let tool = ToolDescriptor::new("a", "d").with_safety(SafetyLevel::Intrusive);
        let policy = AllOf::new()
            .with(|_: &ToolCall<'_>| Decision::deny("first"))
            .with(MaxSafety(SafetyLevel::Passive));
        let call = ToolCall::new(&tool, args(&empty), Side::Server);
        assert_eq!(policy.check(&call), Decision::deny("first"));
        assert!(AllOf::new().check(&call).is_allowed());
    }

    #[test]
    fn gate_rejects_hidden_tools() {
        let empty = json!({});
        let tool = ToolDescriptor::new("a", "d");
        let call = ToolCall::new(&tool, args(&empty), Side::Server);
        assert!(!gate(&DenyNames::new(["a"]), &call).is_allowed());
        assert!(gate(&AllowAll, &call).is_allowed());
    }
}
