//! Bridges to `rune-chain-core` tools (`chain` feature).
//!
//! - [`ChainTool`] serves any [`rune_chain_core::Tool`] over MCP.
//! - [`RemoteTool`] implements [`rune_chain_core::Tool`], so a `rune-chain`
//!   agent can call tools of external MCP servers; its results come back
//!   capped and fenced as untrusted data.

use std::fmt;

use async_trait::async_trait;
use rune_chain_core::Tool;
use serde_json::{Map, Value};

use crate::sanitize::fence;
use crate::{RemoteTool, ToolError, ToolHandler, ToolOutput};

/// Serves a [`rune_chain_core::Tool`] as an MCP tool.
///
/// A chain tool takes one input string. A call whose arguments are exactly
/// `{"input": "<text>"}` (the default chain tool schema) passes `<text>`;
/// any other argument object is passed as its JSON encoding, as
/// function-calling agents do.
///
/// A failure reaches the MCP caller as an `isError` result. Invalid-input
/// errors keep their message (it is about the caller's input); other
/// errors become a fixed "tool execution failed", so paths, hostnames or
/// stack details in an error message do not leak to a remote client.
/// [`with_error_detail`](Self::with_error_detail) passes them through.
///
/// ```
/// use async_trait::async_trait;
/// use rune_chain_core::{Tool, ToolError};
/// use rune_mcp::{ChainTool, McpServer};
///
/// struct Upper;
///
/// #[async_trait]
/// impl Tool for Upper {
///     fn name(&self) -> &str { "upper" }
///     fn description(&self) -> &str { "Upper-case the input." }
///     async fn run(&self, input: &str) -> Result<String, ToolError> {
///         Ok(input.to_uppercase())
///     }
/// }
///
/// let (descriptor, handler) = ChainTool::described(Upper);
/// let server = McpServer::new("demo", "0.1.0").tool(descriptor, handler)?;
/// # tokio::runtime::Builder::new_current_thread().build().unwrap().block_on(async {
/// let args = serde_json::json!({"input": "hi"}).as_object().unwrap().clone();
/// assert_eq!(server.call("upper", args).await?.text_content(), "HI");
/// # Ok::<(), rune_mcp::Error>(())
/// # })?;
/// # Ok::<(), rune_mcp::Error>(())
/// ```
pub struct ChainTool<T> {
    tool: T,
    error_detail: bool,
}

impl<T> fmt::Debug for ChainTool<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ChainTool")
            .field("error_detail", &self.error_detail)
            .finish_non_exhaustive()
    }
}

impl<T> ChainTool<T> {
    /// Serve `tool`, hiding error details.
    #[must_use]
    pub const fn new(tool: T) -> Self {
        Self {
            tool,
            error_detail: false,
        }
    }

    /// Pass every error message through to the MCP caller (default: only
    /// invalid-input messages).
    #[must_use]
    pub const fn with_error_detail(mut self, on: bool) -> Self {
        self.error_detail = on;
        self
    }

    /// The wrapped tool.
    pub const fn inner(&self) -> &T {
        &self.tool
    }
}

impl<T: Tool> ChainTool<T> {
    /// The tool with a descriptor built from its name, description and
    /// schema. Nothing is known about its behaviour, so the descriptor is
    /// conservative ([`SafetyLevel::Intrusive`], MCP default hints); refine
    /// it, or build your own descriptor, for tools you know to be safe.
    ///
    /// [`SafetyLevel::Intrusive`]: rune_tool_schema::SafetyLevel::Intrusive
    #[must_use]
    pub fn described(tool: T) -> (rune_tool_schema::ToolDescriptor, Self) {
        let descriptor = rune_tool_schema::ToolDescriptor::new(tool.name(), tool.description())
            .with_input_schema(tool.schema())
            .with_safety(rune_tool_schema::SafetyLevel::Intrusive)
            .with_hints(rune_tool_schema::ToolHints::MCP_DEFAULT);
        (descriptor, Self::new(tool))
    }
}

/// The input string a chain tool receives for an MCP argument object.
#[must_use]
pub fn chain_input(arguments: &Map<String, Value>) -> String {
    match arguments.get("input") {
        Some(Value::String(input)) if arguments.len() == 1 => input.clone(),
        _ => Value::Object(arguments.clone()).to_string(),
    }
}

#[async_trait]
impl<T: Tool> ToolHandler for ChainTool<T> {
    async fn call(&self, arguments: Map<String, Value>) -> Result<ToolOutput, ToolError> {
        match self.tool.run(&chain_input(&arguments)).await {
            Ok(text) => Ok(ToolOutput::text(text)),
            Err(err @ rune_chain_core::ToolError::InvalidInput(_)) => {
                Err(ToolError::new(err.to_string()))
            }
            Err(err) if self.error_detail => Err(ToolError::new(err.to_string())),
            Err(_) => Err(ToolError::new("tool execution failed")),
        }
    }
}

#[async_trait]
impl Tool for RemoteTool {
    fn name(&self) -> &str {
        &self.descriptor().name
    }

    fn description(&self) -> &str {
        &self.descriptor().description
    }

    fn schema(&self) -> Value {
        self.descriptor().input_schema.clone()
    }

    /// `input` is parsed as a JSON argument object; anything else is sent
    /// as `{"input": input}`. The result is capped, and with
    /// [`fence_results`](crate::ClientOptions::fence_results) (the default)
    /// wrapped in an `<mcp_result>` fence naming the server and tool. A
    /// tool-level failure becomes
    /// [`ToolError::ExecutionFailed`](rune_chain_core::ToolError::ExecutionFailed),
    /// fenced the same way since its message is the server's.
    async fn run(&self, input: &str) -> Result<String, rune_chain_core::ToolError> {
        let arguments = if let Ok(Value::Object(map)) = serde_json::from_str::<Value>(input) {
            map
        } else {
            let mut map = Map::new();
            map.insert("input".to_owned(), Value::String(input.to_owned()));
            map
        };
        let output = Self::call(self, arguments)
            .await
            .map_err(|err| rune_chain_core::ToolError::ExecutionFailed(err.to_string()))?;
        let text = output
            .structured
            .as_ref()
            .filter(|_| output.content.is_empty())
            .map_or_else(|| output.text_content(), Value::to_string);
        let status = if output.is_error { "error" } else { "ok" };
        let text = if self.client().options().fence_results {
            fence(self.namespace(), self.remote_name(), status, &text)
        } else {
            text
        };
        if output.is_error {
            Err(rune_chain_core::ToolError::ExecutionFailed(text))
        } else {
            Ok(text)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn single_input_is_unwrapped() {
        let args = json!({"input": "hello"});
        assert_eq!(chain_input(args.as_object().unwrap()), "hello");
        let args = json!({"a": 1, "b": 2});
        assert_eq!(chain_input(args.as_object().unwrap()), r#"{"a":1,"b":2}"#);
        let args = json!({"input": 5});
        assert_eq!(chain_input(args.as_object().unwrap()), r#"{"input":5}"#);
    }
}
