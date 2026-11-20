//! Typed tools: arguments as a Rust struct, schema derived with `schemars`.

use std::fmt;

use async_trait::async_trait;
use rune_chain_core::{MAX_TOOL_ARGUMENTS_BYTES, Tool, ToolError};
use rune_tool_schema::{ToolDescriptor, json_schema_for};
use schemars::JsonSchema;
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::Value;

/// A tool with typed arguments and output.
///
/// The argument schema the model sees is generated from [`Self::Args`], and
/// every call is validated against it (nested fields included) before
/// [`call`](Self::call) runs. Register it with
/// [`AgentBuilder::typed_tool`](crate::AgentBuilder::typed_tool), or wrap it
/// in [`Typed`] to get a plain [`Tool`].
///
/// ```rust
/// use rune_chain::prelude::*;
/// use rune_chain::ToolError;
/// use schemars::JsonSchema;
/// use serde::Deserialize;
///
/// #[derive(Deserialize, JsonSchema)]
/// struct AddArgs {
///     /// First addend.
///     a: i64,
///     /// Second addend.
///     b: i64,
/// }
///
/// struct Add;
///
/// #[async_trait::async_trait]
/// impl TypedTool for Add {
///     type Args = AddArgs;
///     type Output = i64;
///     fn name(&self) -> &str { "add" }
///     fn description(&self) -> &str { "Add two integers." }
///     async fn call(&self, args: AddArgs) -> Result<i64, ToolError> {
///         args.a.checked_add(args.b).ok_or_else(|| ToolError::InvalidInput("overflow".into()))
///     }
/// }
///
/// # tokio::runtime::Builder::new_current_thread().build().unwrap().block_on(async {
/// let tool = Typed::new(Add);
/// assert_eq!(tool.run(r#"{"a": 2, "b": 40}"#).await.unwrap(), "42");
/// assert!(tool.run(r#"{"a": "two", "b": 40}"#).await.is_err());
/// # });
/// ```
#[async_trait]
pub trait TypedTool: Send + Sync + 'static {
    /// The argument object. Must be a struct (the schema root is an object).
    type Args: DeserializeOwned + JsonSchema + Send;
    /// What the tool returns. Strings go back to the model as they are,
    /// anything else as compact JSON.
    type Output: Serialize + Send;

    /// Tool name: 1-64 ASCII letters, digits, `_` or `-`.
    fn name(&self) -> &str;

    /// What the tool does and when to use it, written for the model.
    fn description(&self) -> &str;

    /// Run the tool on validated arguments.
    async fn call(&self, args: Self::Args) -> Result<Self::Output, ToolError>;
}

/// Adapter that turns a [`TypedTool`] into a [`Tool`].
pub struct Typed<T> {
    tool: T,
    descriptor: ToolDescriptor,
}

impl<T: TypedTool> Typed<T> {
    /// Wrap `tool`, generating its argument schema once.
    pub fn new(tool: T) -> Self {
        let descriptor = ToolDescriptor::new(tool.name(), tool.description())
            .with_input_schema(input_schema::<T::Args>());
        Self { tool, descriptor }
    }

    /// The wrapped tool.
    pub const fn inner(&self) -> &T {
        &self.tool
    }
}

impl<T> fmt::Debug for Typed<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Typed")
            .field("name", &self.descriptor.name)
            .finish_non_exhaustive()
    }
}

/// The schema for `A`, without the `$schema` and `title` keys that some
/// providers reject in function parameters.
fn input_schema<A: JsonSchema>() -> Value {
    let mut schema = json_schema_for::<A>();
    if let Some(obj) = schema.as_object_mut() {
        obj.remove("$schema");
        obj.remove("title");
    }
    schema
}

#[async_trait]
impl<T: TypedTool> Tool for Typed<T> {
    fn name(&self) -> &str {
        &self.descriptor.name
    }

    fn description(&self) -> &str {
        &self.descriptor.description
    }

    fn schema(&self) -> Value {
        self.descriptor.input_schema.clone()
    }

    async fn run(&self, input: &str) -> Result<String, ToolError> {
        if input.len() > MAX_TOOL_ARGUMENTS_BYTES {
            return Err(ToolError::InvalidInput(format!(
                "arguments are {} bytes, above the {MAX_TOOL_ARGUMENTS_BYTES}-byte limit",
                input.len()
            )));
        }
        let value: Value = serde_json::from_str(input)
            .map_err(|e| ToolError::InvalidInput(format!("arguments are not valid JSON: {e}")))?;
        let args: T::Args = self
            .descriptor
            .parse_arguments(&value)
            .map_err(|e| ToolError::InvalidInput(e.to_string()))?;
        let output = self.tool.call(args).await?;
        match serde_json::to_value(output) {
            Ok(Value::String(s)) => Ok(s),
            Ok(v) => Ok(v.to_string()),
            Err(e) => Err(ToolError::ExecutionFailed(format!(
                "could not serialize the tool output: {e}"
            ))),
        }
    }
}
