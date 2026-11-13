//! MCP-shaped tool descriptors: one description of an LLM-callable tool,
//! shared by `rune-chain` tools, other tool catalogs and MCP servers and
//! clients.
//!
//! A [`ToolDescriptor`] holds a tool's name, title, description, the JSON
//! Schema of its arguments (and optionally of its result), a
//! [`SafetyLevel`], behaviour [`ToolHints`], a [`ToolCategory`], tags and a
//! version. It is plain data with no I/O: build one, [`validate`] it against
//! the MCP rules, and export it as an MCP [`McpTool`] definition (the shape
//! `tools/list` returns), or import one listed by an external server.
//!
//! For direct use with a model provider:
//!
//! - [`ToolDescriptor::export`] emits the definition a [`Dialect`]
//!   (`OpenAI`, `OpenAI` strict mode, Anthropic, Gemini) expects, rewriting the
//!   schema into the provider's subset and reporting each change as a
//!   [`SchemaFinding`]; [`Dialect::lint`] reports without exporting.
//! - [`Validator`] (or [`ToolDescriptor::validate_arguments`] and
//!   [`ToolDescriptor::parse_arguments`]) checks the arguments a model
//!   sends back, with JSON Pointer error paths and bounded work.
//! - [`strip_hidden`], [`ToolDescriptor::check_hygiene`] and
//!   [`ToolDescriptor::sanitized`] deal with invisible and bidirectional
//!   characters in model-facing text, a prompt-injection channel.
//!
//! The `schemars` feature generates argument and result schemas from Rust
//! types ([`ToolDescriptor::with_input_type`]) and derives
//! `schemars::JsonSchema` for the descriptor types themselves.
//!
//! Field names and defaults follow the [MCP specification, Tools][mcp].
//!
//! [`validate`]: ToolDescriptor::validate
//! [mcp]: https://modelcontextprotocol.io/specification/2025-11-25/server/tools
//!
//! # Example
//!
//! ```
//! use rune_tool_schema::{
//!     single_input_schema, McpTool, SafetyLevel, ToolCategory, ToolDescriptor, ToolHints,
//! };
//!
//! let tool = ToolDescriptor::new("base64_decode", "Decode standard base64 to UTF-8 text.")
//!     .with_title("Base64 decode")
//!     .with_category(ToolCategory::ENCODING)
//!     .with_hints(ToolHints::PURE)
//!     .with_input_schema(single_input_schema("Base64 text"));
//!
//! // Export: the JSON an MCP server lists for this tool.
//! let mcp: McpTool = tool.to_mcp()?;
//! let json = serde_json::to_value(&mcp).unwrap();
//! assert_eq!(json["name"], "base64_decode");
//! assert_eq!(json["inputSchema"]["required"][0], "input");
//! assert_eq!(json["annotations"]["openWorldHint"], false);
//!
//! // Import: back to a descriptor, losslessly.
//! assert_eq!(mcp.to_descriptor()?, tool);
//! assert_eq!(tool.safety, SafetyLevel::Passive);
//! # Ok::<(), rune_tool_schema::Error>(())
//! ```
#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod args;
mod category;
mod descriptor;
mod dialect;
mod error;
mod mcp;
mod safety;
mod text;

pub use args::{ArgumentError, Limits, Validator, Violation, ViolationKind, Violations};
pub use category::ToolCategory;
pub use descriptor::{
    MAX_NAME_LEN, ToolDescriptor, empty_object_schema, single_input_schema, validate_name,
};
pub use dialect::{
    Action, Dialect, ExportOptions, ProviderTool, SchemaFinding, Severity, drop_optional_nulls,
};
pub use error::Error;
pub use mcp::{META_KEY, McpTool, McpToolAnnotations};
pub use safety::{SafetyLevel, ToolHints};
pub use text::{MAX_DESCRIPTION_CHARS, find_hidden, is_hidden_char, strip_hidden, truncate_chars};

/// The JSON Schema (draft 2020-12) [`schemars`] generates for `T`.
///
/// ```
/// # #[cfg(feature = "schemars")] {
/// #[derive(schemars::JsonSchema)]
/// #[allow(dead_code, reason = "only the schema is used")]
/// struct Args { host: String, port: u16 }
///
/// let schema = rune_tool_schema::json_schema_for::<Args>();
/// assert_eq!(schema["type"], "object");
/// assert_eq!(schema["required"], serde_json::json!(["host", "port"]));
/// # }
/// ```
#[cfg(feature = "schemars")]
#[must_use]
pub fn json_schema_for<T: schemars::JsonSchema>() -> serde_json::Value {
    schemars::schema_for!(T).into()
}
