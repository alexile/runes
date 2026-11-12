//! [`McpTool`]: the MCP `Tool` definition, as listed by `tools/list`.
//!
//! Field names and defaults follow the `Tool` and `ToolAnnotations` types of
//! the [MCP specification](https://modelcontextprotocol.io/specification/2025-11-25/server/tools).

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::descriptor::{check_object_schema, validate_name};
use crate::{Error, SafetyLevel, ToolCategory, ToolDescriptor, ToolHints};

/// The `_meta` key under which [`McpTool::from_descriptor`] stores the
/// descriptor fields MCP has no slot for (category, tags, safety, version).
pub const META_KEY: &str = "runes/tool";

/// An MCP tool definition.
///
/// Serializes to the exact JSON an MCP server returns from `tools/list`
/// (camelCase keys, `_meta`). Fields this type does not model, such as
/// `icons` or `execution`, are kept in [`McpTool::extra`] so a definition
/// read from a server re-serializes unchanged.
///
/// ```
/// use rune_tool_schema::{McpTool, SafetyLevel, ToolDescriptor, ToolHints};
///
/// let tool = ToolDescriptor::new("hex_encode", "Hex-encode a UTF-8 string.")
///     .with_hints(ToolHints::PURE)
///     .to_mcp()?;
/// let json = serde_json::to_value(&tool).unwrap();
/// assert_eq!(json["inputSchema"]["type"], "object");
/// assert_eq!(json["annotations"]["readOnlyHint"], true);
///
/// let back: McpTool = serde_json::from_value(json).unwrap();
/// assert_eq!(back.to_descriptor()?.safety, SafetyLevel::Passive);
/// # Ok::<(), rune_tool_schema::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct McpTool {
    /// Programmatic name.
    pub name: String,
    /// Display title.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    /// Model-facing description.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// JSON Schema of the arguments; `type` must be `"object"`.
    pub input_schema: Value,
    /// JSON Schema of the structured result; `type` must be `"object"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_schema: Option<Value>,
    /// Behaviour hints.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub annotations: Option<McpToolAnnotations>,
    /// Extension metadata (`_meta`).
    #[serde(rename = "_meta", default, skip_serializing_if = "Option::is_none")]
    pub meta: Option<Map<String, Value>>,
    /// Every other field, kept verbatim.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// MCP `ToolAnnotations`. A missing hint means the MCP default
/// ([`ToolHints::MCP_DEFAULT`]).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct McpToolAnnotations {
    /// Display title.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    /// The tool does not modify its environment.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub read_only_hint: Option<bool>,
    /// The tool may perform destructive updates.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub destructive_hint: Option<bool>,
    /// Repeated calls with the same arguments have no additional effect.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idempotent_hint: Option<bool>,
    /// The tool interacts with an open world of external entities.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub open_world_hint: Option<bool>,
}

impl McpToolAnnotations {
    /// Every hint set explicitly from `hints`.
    #[must_use]
    pub const fn from_hints(hints: ToolHints, title: Option<String>) -> Self {
        Self {
            title,
            read_only_hint: Some(hints.read_only),
            destructive_hint: Some(hints.destructive),
            idempotent_hint: Some(hints.idempotent),
            open_world_hint: Some(hints.open_world),
        }
    }

    /// The hints, with MCP defaults for those not given.
    #[must_use]
    pub fn hints(&self) -> ToolHints {
        let default = ToolHints::MCP_DEFAULT;
        ToolHints {
            read_only: self.read_only_hint.unwrap_or(default.read_only),
            destructive: self.destructive_hint.unwrap_or(default.destructive),
            idempotent: self.idempotent_hint.unwrap_or(default.idempotent),
            open_world: self.open_world_hint.unwrap_or(default.open_world),
        }
    }
}

/// What [`META_KEY`] holds.
#[derive(Debug, Serialize, Deserialize)]
struct RunesMeta {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    category: Option<ToolCategory>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    tags: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    safety: Option<SafetyLevel>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    version: Option<String>,
}

impl McpTool {
    /// Export a descriptor without validating it; prefer
    /// [`ToolDescriptor::to_mcp`], which validates first.
    ///
    /// Hints become explicit annotations; category, tags, safety and version
    /// go under `_meta["runes/tool"]`.
    #[must_use]
    pub fn from_descriptor(tool: &ToolDescriptor) -> Self {
        let meta = RunesMeta {
            category: tool.category.clone(),
            tags: tool.tags.clone(),
            safety: Some(tool.safety),
            version: tool.version.clone(),
        };
        let mut meta_map = Map::new();
        // Serializing plain strings and enums cannot fail; fall back to
        // omitting the entry rather than panicking.
        if let Ok(value) = serde_json::to_value(meta) {
            meta_map.insert(META_KEY.to_owned(), value);
        }
        Self {
            name: tool.name.clone(),
            title: tool.title.clone(),
            description: Some(tool.description.clone()),
            input_schema: tool.input_schema.clone(),
            output_schema: tool.output_schema.clone(),
            annotations: Some(McpToolAnnotations::from_hints(
                tool.hints,
                tool.title.clone(),
            )),
            meta: Some(meta_map),
            extra: Map::new(),
        }
    }

    /// Check the fields MCP requires: a valid name and object-typed input
    /// and output schemas. The description is optional in MCP.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidName`] or [`Error::SchemaNotObject`].
    pub fn validate(&self) -> Result<(), Error> {
        validate_name(&self.name)?;
        check_object_schema(&self.name, "inputSchema", &self.input_schema)?;
        if let Some(output) = &self.output_schema {
            check_object_schema(&self.name, "outputSchema", output)?;
        }
        Ok(())
    }

    /// Import as a descriptor.
    ///
    /// Hints come from `annotations`, with MCP defaults for missing ones.
    /// Category, tags, safety and version come from `_meta["runes/tool"]`
    /// when present; otherwise the safety level is
    /// [inferred from the hints](SafetyLevel::infer_from_hints), which
    /// treats an unannotated tool as [`SafetyLevel::Intrusive`]. A missing
    /// description becomes an empty string.
    ///
    /// Annotations and `_meta` are claims made by whoever wrote the
    /// definition; a policy for untrusted servers should not rely on them.
    ///
    /// # Errors
    ///
    /// Whatever [`Self::validate`] reports, or [`Error::InvalidMeta`] if
    /// `_meta["runes/tool"]` is present but malformed.
    pub fn to_descriptor(&self) -> Result<ToolDescriptor, Error> {
        self.validate()?;
        let hints = self
            .annotations
            .as_ref()
            .map_or(ToolHints::MCP_DEFAULT, McpToolAnnotations::hints);
        let meta = match self.meta.as_ref().and_then(|m| m.get(META_KEY)) {
            Some(value) => {
                Some(
                    RunesMeta::deserialize(value).map_err(|err| Error::InvalidMeta {
                        tool: self.name.clone(),
                        key: META_KEY,
                        reason: err.to_string(),
                    })?,
                )
            }
            None => None,
        };
        let title = self.title.clone().or_else(|| {
            self.annotations
                .as_ref()
                .and_then(|annotations| annotations.title.clone())
        });
        let (category, tags, safety, version) = match meta {
            Some(meta) => (
                meta.category,
                meta.tags,
                meta.safety
                    .unwrap_or_else(|| SafetyLevel::infer_from_hints(hints)),
                meta.version,
            ),
            None => (None, Vec::new(), SafetyLevel::infer_from_hints(hints), None),
        };
        Ok(ToolDescriptor {
            name: self.name.clone(),
            title,
            description: self.description.clone().unwrap_or_default(),
            category,
            tags,
            safety,
            hints,
            version,
            input_schema: self.input_schema.clone(),
            output_schema: self.output_schema.clone(),
        })
    }
}

impl TryFrom<&ToolDescriptor> for McpTool {
    type Error = Error;

    fn try_from(tool: &ToolDescriptor) -> Result<Self, Error> {
        tool.to_mcp()
    }
}

impl TryFrom<&McpTool> for ToolDescriptor {
    type Error = Error;

    fn try_from(tool: &McpTool) -> Result<Self, Error> {
        tool.to_descriptor()
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn sample() -> ToolDescriptor {
        ToolDescriptor::new("port_scan", "TCP connect scan.")
            .with_title("Port scanner")
            .with_category(ToolCategory::NETWORK)
            .with_tags(["tcp"])
            .with_safety(SafetyLevel::Active)
            .with_version("1.2.3")
            .with_input_schema(json!({
                "type": "object",
                "properties": { "host": { "type": "string" } },
                "required": ["host"]
            }))
            .with_output_schema(json!({ "type": "object" }))
    }

    /// Known answer: the exact MCP JSON for a fully populated descriptor.
    #[test]
    fn export_known_answer() {
        let json = serde_json::to_value(sample().to_mcp().unwrap()).unwrap();
        assert_eq!(
            json,
            json!({
                "name": "port_scan",
                "title": "Port scanner",
                "description": "TCP connect scan.",
                "inputSchema": {
                    "type": "object",
                    "properties": { "host": { "type": "string" } },
                    "required": ["host"]
                },
                "outputSchema": { "type": "object" },
                "annotations": {
                    "title": "Port scanner",
                    "readOnlyHint": false,
                    "destructiveHint": false,
                    "idempotentHint": false,
                    "openWorldHint": true
                },
                "_meta": {
                    "runes/tool": {
                        "category": "network",
                        "tags": ["tcp"],
                        "safety": "active",
                        "version": "1.2.3"
                    }
                }
            })
        );
    }

    #[test]
    fn round_trips_through_mcp_json() {
        let tool = sample();
        let json = serde_json::to_string(&tool.to_mcp().unwrap()).unwrap();
        let back: McpTool = serde_json::from_str(&json).unwrap();
        assert_eq!(back.to_descriptor().unwrap(), tool);
    }

    #[test]
    fn export_rejects_invalid_descriptor() {
        let err = ToolDescriptor::new("bad name", "d").to_mcp().unwrap_err();
        assert!(matches!(err, Error::InvalidName { .. }));
    }

    #[test]
    fn foreign_tool_uses_mcp_defaults() {
        // A tool as a third-party server lists it: no annotations, no _meta,
        // plus fields this crate does not model.
        let raw = json!({
            "name": "delete_repo",
            "inputSchema": { "type": "object" },
            "icons": [{ "src": "https://example.com/i.png" }],
            "execution": { "taskSupport": "optional" }
        });
        let tool: McpTool = serde_json::from_value(raw.clone()).unwrap();
        assert_eq!(tool.extra.len(), 2);
        assert_eq!(serde_json::to_value(&tool).unwrap(), raw);

        let descriptor = tool.to_descriptor().unwrap();
        assert_eq!(descriptor.hints, ToolHints::MCP_DEFAULT);
        assert_eq!(descriptor.safety, SafetyLevel::Intrusive);
        assert_eq!(descriptor.description, "");
        assert_eq!(descriptor.category, None);
    }

    #[test]
    fn partial_annotations_infer_safety() {
        let tool: McpTool = serde_json::from_value(json!({
            "name": "get_weather",
            "description": "Weather for a city.",
            "inputSchema": { "type": "object" },
            "annotations": { "title": "Weather", "readOnlyHint": true }
        }))
        .unwrap();
        let descriptor = tool.to_descriptor().unwrap();
        assert_eq!(descriptor.safety, SafetyLevel::Passive);
        assert_eq!(descriptor.title.as_deref(), Some("Weather"));
        assert!(descriptor.hints.open_world);
    }

    #[test]
    fn import_rejects_bad_tools() {
        let bad_schema: McpTool = serde_json::from_value(json!({
            "name": "x", "inputSchema": { "type": "string" }
        }))
        .unwrap();
        assert!(matches!(
            bad_schema.to_descriptor(),
            Err(Error::SchemaNotObject { .. })
        ));

        let bad_meta: McpTool = serde_json::from_value(json!({
            "name": "x",
            "inputSchema": { "type": "object" },
            "_meta": { "runes/tool": { "safety": "nuclear" } }
        }))
        .unwrap();
        assert!(matches!(
            bad_meta.to_descriptor(),
            Err(Error::InvalidMeta { .. })
        ));
    }

    #[test]
    fn missing_input_schema_does_not_deserialize() {
        assert!(serde_json::from_value::<McpTool>(json!({ "name": "x" })).is_err());
    }
}
