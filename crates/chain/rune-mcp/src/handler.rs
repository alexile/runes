//! [`ToolHandler`]: the code behind a served tool.

use std::fmt;
use std::future::Future;
use std::sync::Arc;

use async_trait::async_trait;
use serde_json::{Map, Value};

use crate::{ToolError, ToolOutput};

/// Runs one tool. Register it on an [`McpServer`](crate::McpServer) with the
/// tool's [`ToolDescriptor`](rune_tool_schema::ToolDescriptor).
///
/// Return `Err(ToolError)` (or an [`ToolOutput::error`]) when the tool runs
/// and fails: the caller receives it as an `isError` result.
#[async_trait]
pub trait ToolHandler: Send + Sync {
    /// Run the tool with the call's argument object.
    async fn call(&self, arguments: Map<String, Value>) -> Result<ToolOutput, ToolError>;
}

#[async_trait]
impl<H: ToolHandler + ?Sized> ToolHandler for Arc<H> {
    async fn call(&self, arguments: Map<String, Value>) -> Result<ToolOutput, ToolError> {
        (**self).call(arguments).await
    }
}

#[async_trait]
impl<H: ToolHandler + ?Sized> ToolHandler for Box<H> {
    async fn call(&self, arguments: Map<String, Value>) -> Result<ToolOutput, ToolError> {
        (**self).call(arguments).await
    }
}

/// A [`ToolHandler`] made from an async closure; see [`tool_fn`].
#[derive(Clone)]
pub struct FnHandler<F>(F);

impl<F> fmt::Debug for FnHandler<F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("FnHandler")
    }
}

/// Wrap an async closure as a [`ToolHandler`].
///
/// ```
/// use rune_mcp::{tool_fn, ToolError, ToolOutput};
///
/// let upper = tool_fn(|args| async move {
///     let input = args
///         .get("input")
///         .and_then(|v| v.as_str())
///         .ok_or_else(|| ToolError::new("missing `input`"))?;
///     Ok(ToolOutput::text(input.to_uppercase()))
/// });
/// # let _ = upper;
/// ```
pub const fn tool_fn<F, Fut>(f: F) -> FnHandler<F>
where
    F: Fn(Map<String, Value>) -> Fut + Send + Sync,
    Fut: Future<Output = Result<ToolOutput, ToolError>> + Send,
{
    FnHandler(f)
}

#[async_trait]
impl<F, Fut> ToolHandler for FnHandler<F>
where
    F: Fn(Map<String, Value>) -> Fut + Send + Sync,
    Fut: Future<Output = Result<ToolOutput, ToolError>> + Send,
{
    async fn call(&self, arguments: Map<String, Value>) -> Result<ToolOutput, ToolError> {
        (self.0)(arguments).await
    }
}
