use async_trait::async_trait;

use crate::{FunctionDefinition, ToolError};

/// An LLM-callable tool that an agent can invoke during its reasoning loop.
///
/// Implement this trait to expose any async capability — a web search, database
/// query, API call, or local computation — to a [`Chain`](crate::Chain)-based
/// agent. The agent selects a tool by matching its [`Tool::name`] and calls
/// [`Tool::run`] with a plain-text or JSON input string.
///
/// # Example
///
/// ```rust
/// use rune_chain_core::{Tool, ToolError};
/// use async_trait::async_trait;
///
/// struct Echo;
///
/// #[async_trait]
/// impl Tool for Echo {
///     fn name(&self) -> &str { "echo" }
///     fn description(&self) -> &str { "Returns the input unchanged." }
///     async fn run(&self, input: &str) -> Result<String, ToolError> {
///         Ok(input.to_string())
///     }
/// }
///
/// # tokio_test::block_on(async {
/// let result = Echo.run("hello").await.unwrap();
/// assert_eq!(result, "hello");
/// # });
/// ```
#[async_trait]
pub trait Tool: Send + Sync {
    /// Short identifier used in prompts: `"calculator"`, `"web_search"`, etc.
    ///
    /// Must be unique within an agent's tool list and contain no spaces.
    fn name(&self) -> &str;

    /// One-sentence description the LLM uses to decide when to call this tool.
    fn description(&self) -> &str;

    /// Execute the tool with the given `input` string and return the result.
    ///
    /// The input is either a raw string (ReAct-style) or a JSON-encoded object
    /// (function-calling style). The return value is fed back to the LLM as an
    /// observation. Return [`ToolError`] for recoverable failures — the agent
    /// will report the error to the model rather than crashing.
    async fn run(&self, input: &str) -> Result<String, ToolError>;

    /// JSON Schema describing the tool's parameter object for native function calling.
    ///
    /// The default returns a single `"input"` string parameter. Override this to
    /// expose typed, multi-field schemas to models that support function calling.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_chain_core::{Tool, ToolError};
    /// use async_trait::async_trait;
    ///
    /// struct Add;
    ///
    /// #[async_trait]
    /// impl Tool for Add {
    ///     fn name(&self) -> &str { "add" }
    ///     fn description(&self) -> &str { "Adds two integers." }
    ///     async fn run(&self, input: &str) -> Result<String, ToolError> {
    ///         let v: serde_json::Value = serde_json::from_str(input)
    ///             .map_err(|e| ToolError::InvalidInput(e.to_string()))?;
    ///         let a = v["a"].as_i64().unwrap_or(0);
    ///         let b = v["b"].as_i64().unwrap_or(0);
    ///         Ok((a + b).to_string())
    ///     }
    ///     fn schema(&self) -> serde_json::Value {
    ///         serde_json::json!({
    ///             "type": "object",
    ///             "properties": {
    ///                 "a": { "type": "integer" },
    ///                 "b": { "type": "integer" }
    ///             },
    ///             "required": ["a", "b"]
    ///         })
    ///     }
    /// }
    /// ```
    fn schema(&self) -> serde_json::Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "input": {
                    "type": "string",
                    "description": "The input to the tool"
                }
            },
            "required": ["input"]
        })
    }

    /// Build a [`FunctionDefinition`] from this tool's metadata.
    ///
    /// Used by function-calling agents to register tools with the LLM provider.
    fn function_definition(&self) -> FunctionDefinition {
        FunctionDefinition::new(self.name(), self.description(), self.schema())
    }
}
