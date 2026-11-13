//! Export gathered MCP tools as tool definitions for a model provider
//! (`OpenAI`, `OpenAI` strict, Anthropic, Gemini), through
//! [`rune_tool_schema::Dialect`].

use std::fmt;

use rune_tool_schema::{Dialect, ExportOptions, ProviderTool, SchemaFinding, ToolDescriptor};
use serde_json::Value;

use crate::Rejection;

/// A schema change made while exporting one tool: a keyword the provider
/// would reject or ignore, and what was done about it.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ExportWarning {
    /// The exposed tool name.
    pub tool: String,
    /// The lint finding.
    pub finding: SchemaFinding,
}

impl fmt::Display for ExportWarning {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.tool, self.finding)
    }
}

/// Tools exported for one provider.
///
/// [`definitions`](Self::definitions) go in the request's tool list.
/// [`warnings`](Self::warnings) list every keyword that was removed or
/// rewritten on the way, so a constraint the model no longer sees does not
/// go unnoticed (the arguments that come back are still checked against
/// the original schema before a call is sent). Tools the provider cannot
/// take at all (a name it refuses, a schema it rejects even after
/// rewriting) are in [`skipped`](Self::skipped).
///
/// With [`Dialect::OpenAiStrict`] every optional property becomes required
/// and nullable, so the model sends `null` for the ones it leaves out; run
/// [`drop_optional_nulls`](rune_tool_schema::drop_optional_nulls) on the
/// arguments against the tool's own schema before calling it.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct DialectExport {
    /// The provider format.
    pub dialect: Dialect,
    /// The exported tools, in the order given.
    pub tools: Vec<ProviderTool>,
    /// Every lint finding of the exported tools, tool by tool.
    pub warnings: Vec<ExportWarning>,
    /// Tools left out, and why.
    pub skipped: Vec<Rejection>,
}

impl DialectExport {
    /// The JSON definitions, ready for the request's tool list.
    #[must_use]
    pub fn definitions(&self) -> Vec<Value> {
        self.tools.iter().map(|t| t.definition.clone()).collect()
    }

    /// Whether every tool was exported without a schema change.
    #[must_use]
    pub const fn is_clean(&self) -> bool {
        self.warnings.is_empty() && self.skipped.is_empty()
    }
}

/// Export `tools` in `dialect`'s format with
/// [`ToolDescriptor::export_with`], collecting lint findings as
/// [`ExportWarning`]s and skipping (not failing on) tools the provider
/// cannot take.
///
/// [`McpClient::export_tools`](crate::McpClient::export_tools) and
/// [`McpToolset::export_tools`](crate::McpToolset::export_tools) call this
/// on the tools they gather; call it directly on any descriptors.
///
/// ```
/// use rune_mcp::export_tools;
/// use rune_tool_schema::{Dialect, ExportOptions, ToolDescriptor};
/// use serde_json::json;
///
/// let tools = [
///     ToolDescriptor::new("docs__search", "Search the docs.").with_input_schema(json!({
///         "type": "object",
///         "properties": {
///             "q": { "type": "string", "maxLength": 200 },
///             "limit": { "type": "integer" }
///         },
///         "required": ["q"]
///     })),
///     ToolDescriptor::new("files.read", "Read a file."),
/// ];
///
/// let out = export_tools(&tools, Dialect::OpenAiStrict, &ExportOptions::default());
/// let defs = out.definitions();
/// assert_eq!(defs.len(), 1);
/// assert_eq!(defs[0]["function"]["name"], "docs__search");
/// assert_eq!(defs[0]["function"]["strict"], true);
///
/// // `maxLength` is not allowed in strict mode and `limit` became required.
/// let warnings: Vec<String> = out.warnings.iter().map(ToString::to_string).collect();
/// assert_eq!(warnings.len(), 2);
/// assert!(warnings[0].starts_with("docs__search: /properties/q/maxLength"));
///
/// // `.` is not allowed in OpenAI tool names.
/// assert_eq!(out.skipped[0].name, "files.read");
///
/// let anthropic = export_tools(&tools, Dialect::Anthropic, &ExportOptions::default());
/// assert!(anthropic.warnings.is_empty());
/// assert_eq!(anthropic.tools.len(), 1);
/// ```
#[must_use]
pub fn export_tools<'a>(
    tools: impl IntoIterator<Item = &'a ToolDescriptor>,
    dialect: Dialect,
    options: &ExportOptions,
) -> DialectExport {
    let mut out = DialectExport {
        dialect,
        tools: Vec::new(),
        warnings: Vec::new(),
        skipped: Vec::new(),
    };
    for tool in tools {
        match tool.export_with(dialect, options) {
            Ok(exported) => {
                out.warnings
                    .extend(exported.findings.iter().map(|finding| ExportWarning {
                        tool: tool.name.clone(),
                        finding: finding.clone(),
                    }));
                out.tools.push(exported);
            }
            Err(err) => out.skipped.push(Rejection {
                name: tool.name.clone(),
                reason: err.to_string(),
            }),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn gemini_rewrites_and_skips() {
        let tools = [
            ToolDescriptor::new("a", "A.").with_input_schema(json!({
                "type": "object",
                "properties": {"x": {"type": ["string", "null"]}},
                "additionalProperties": false
            })),
            ToolDescriptor::new("1bad", "B."),
        ];
        let out = export_tools(&tools, Dialect::Gemini, &ExportOptions::default());
        assert_eq!(out.dialect, Dialect::Gemini);
        assert_eq!(out.tools.len(), 1);
        let params = &out.tools[0].definition["parameters"];
        assert_eq!(params["type"], "OBJECT");
        assert_eq!(params["properties"]["x"]["nullable"], true);
        assert!(params.get("additionalProperties").is_none());
        assert!(out.warnings.len() >= 2, "{:?}", out.warnings);
        assert!(out.warnings.iter().all(|w| w.tool == "a"));
        assert_eq!(out.skipped.len(), 1);
        assert!(out.skipped[0].reason.contains("must start with a letter"));
        assert!(!out.is_clean());
    }

    #[test]
    fn clean_export_has_no_warnings() {
        let tools = [ToolDescriptor::new("ok", "Fine.")];
        for dialect in Dialect::ALL {
            let out = export_tools(&tools, dialect, &ExportOptions::default());
            assert!(out.is_clean(), "{dialect}: {:?}", out.warnings);
            assert_eq!(out.definitions().len(), 1);
        }
    }
}
