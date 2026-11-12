//! [`ToolDescriptor`]: the protocol-neutral description of one tool.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{Error, McpTool, SafetyLevel, ToolCategory, ToolHints};

/// Longest tool name MCP accepts, in characters.
pub const MAX_NAME_LEN: usize = 128;

/// Everything an agent runtime needs to present a tool: identity, the JSON
/// Schema of its arguments (and optionally its result), how aggressive it
/// is, and discovery metadata.
///
/// [`ToolDescriptor::to_mcp`] exports an MCP `Tool` definition and
/// [`ToolDescriptor::from_mcp`] imports one.
///
/// ```
/// use rune_tool_schema::{SafetyLevel, ToolCategory, ToolDescriptor, ToolHints};
/// use serde_json::json;
///
/// let tool = ToolDescriptor::new("sha256", "SHA-256 of a UTF-8 string, as hex.")
///     .with_category(ToolCategory::HASHING)
///     .with_hints(ToolHints::PURE)
///     .with_input_schema(json!({
///         "type": "object",
///         "properties": { "input": { "type": "string" } },
///         "required": ["input"]
///     }));
/// tool.validate()?;
/// assert_eq!(tool.safety, SafetyLevel::Passive);
/// # Ok::<(), rune_tool_schema::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[non_exhaustive]
pub struct ToolDescriptor {
    /// Stable programmatic id: 1 to 128 characters of `A-Z a-z 0-9 _ - .`.
    pub name: String,
    /// Human-friendly display title.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    /// Model-facing description of what the tool does and when to use it.
    pub description: String,
    /// Broad area, for grouping and discovery.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub category: Option<ToolCategory>,
    /// Free-form discovery tags.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    /// How aggressive the tool is.
    #[serde(default)]
    pub safety: SafetyLevel,
    /// Behaviour hints (MCP annotations).
    #[serde(default)]
    pub hints: ToolHints,
    /// Version of the tool implementation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// JSON Schema of the argument object; its `type` must be `"object"`.
    #[serde(default = "empty_object_schema")]
    pub input_schema: Value,
    /// JSON Schema of the structured result, if the tool returns one; its
    /// `type` must be `"object"`. A JSON `null` reads as `None`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_schema: Option<Value>,
}

/// `{"type": "object"}`: an argument object with no declared properties.
#[must_use]
pub fn empty_object_schema() -> Value {
    serde_json::json!({ "type": "object" })
}

/// The JSON Schema `{"type":"object","properties":{"input":{"type":"string"}},
/// "required":["input"]}` for tools that take one string argument named
/// `input` (the `rune-chain-core` `Tool` default).
#[must_use]
pub fn single_input_schema(description: &str) -> Value {
    serde_json::json!({
        "type": "object",
        "properties": {
            "input": { "type": "string", "description": description }
        },
        "required": ["input"]
    })
}

impl ToolDescriptor {
    /// Start a passive, uncategorised descriptor whose input is an object
    /// with no declared properties. Hints follow
    /// [`SafetyLevel::default_hints`] until set with [`Self::with_hints`].
    pub fn new(name: impl Into<String>, description: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            title: None,
            description: description.into(),
            category: None,
            tags: Vec::new(),
            safety: SafetyLevel::Passive,
            hints: SafetyLevel::Passive.default_hints(),
            version: None,
            input_schema: empty_object_schema(),
            output_schema: None,
        }
    }

    /// Set the display title.
    #[must_use]
    pub fn with_title(mut self, title: impl Into<String>) -> Self {
        self.title = Some(title.into());
        self
    }

    /// Set the category.
    #[must_use]
    pub fn with_category(mut self, category: ToolCategory) -> Self {
        self.category = Some(category);
        self
    }

    /// Replace the tags.
    #[must_use]
    pub fn with_tags<I, S>(mut self, tags: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.tags = tags.into_iter().map(Into::into).collect();
        self
    }

    /// Set the safety level and reset the hints to its
    /// [`default_hints`](SafetyLevel::default_hints). Call
    /// [`Self::with_hints`] afterwards to override them.
    #[must_use]
    pub const fn with_safety(mut self, safety: SafetyLevel) -> Self {
        self.safety = safety;
        self.hints = safety.default_hints();
        self
    }

    /// Override the behaviour hints.
    #[must_use]
    pub const fn with_hints(mut self, hints: ToolHints) -> Self {
        self.hints = hints;
        self
    }

    /// Set the implementation version.
    #[must_use]
    pub fn with_version(mut self, version: impl Into<String>) -> Self {
        self.version = Some(version.into());
        self
    }

    /// Set the input JSON Schema.
    #[must_use]
    pub fn with_input_schema(mut self, schema: Value) -> Self {
        self.input_schema = schema;
        self
    }

    /// Set the output JSON Schema.
    #[must_use]
    pub fn with_output_schema(mut self, schema: Value) -> Self {
        self.output_schema = Some(schema);
        self
    }

    /// Generate the input schema from a type with
    /// [`schemars`](https://docs.rs/schemars).
    #[cfg(feature = "schemars")]
    #[must_use]
    pub fn with_input_type<T: schemars::JsonSchema>(self) -> Self {
        self.with_input_schema(crate::json_schema_for::<T>())
    }

    /// Generate the output schema from a type with
    /// [`schemars`](https://docs.rs/schemars).
    #[cfg(feature = "schemars")]
    #[must_use]
    pub fn with_output_type<T: schemars::JsonSchema>(self) -> Self {
        self.with_output_schema(crate::json_schema_for::<T>())
    }

    /// Check the descriptor against the MCP rules: a valid name, a
    /// non-empty description, and object-typed input and output schemas.
    ///
    /// # Errors
    ///
    /// The first rule broken, as [`Error::InvalidName`],
    /// [`Error::EmptyDescription`] or [`Error::SchemaNotObject`].
    pub fn validate(&self) -> Result<(), Error> {
        validate_name(&self.name)?;
        if self.description.trim().is_empty() {
            return Err(Error::EmptyDescription(self.name.clone()));
        }
        check_object_schema(&self.name, "inputSchema", &self.input_schema)?;
        if let Some(output) = &self.output_schema {
            check_object_schema(&self.name, "outputSchema", output)?;
        }
        Ok(())
    }

    /// Validate and export as an MCP `Tool` definition.
    ///
    /// # Errors
    ///
    /// Whatever [`Self::validate`] reports.
    pub fn to_mcp(&self) -> Result<McpTool, Error> {
        self.validate()?;
        Ok(McpTool::from_descriptor(self))
    }

    /// Import an MCP `Tool` definition; see [`McpTool::to_descriptor`].
    ///
    /// # Errors
    ///
    /// Whatever [`McpTool::to_descriptor`] reports.
    pub fn from_mcp(tool: &McpTool) -> Result<Self, Error> {
        tool.to_descriptor()
    }
}

/// Check a tool name against the MCP naming rules: 1 to 128 characters,
/// each an ASCII letter, digit, `_`, `-` or `.`.
///
/// ```
/// use rune_tool_schema::validate_name;
///
/// assert!(validate_name("files.read_v2").is_ok());
/// assert!(validate_name("read file").is_err());
/// ```
///
/// # Errors
///
/// [`Error::InvalidName`] naming the rule broken.
pub fn validate_name(name: &str) -> Result<(), Error> {
    let reason = if name.is_empty() {
        "empty"
    } else if name.len() > MAX_NAME_LEN {
        "longer than 128 characters"
    } else if !name
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
    {
        "only A-Z, a-z, 0-9, '_', '-' and '.' are allowed"
    } else {
        return Ok(());
    };
    Err(Error::InvalidName {
        name: name.to_owned(),
        reason,
    })
}

/// MCP requires both schemas to be objects with `"type": "object"`.
pub fn check_object_schema(tool: &str, field: &'static str, schema: &Value) -> Result<(), Error> {
    let is_object = schema
        .as_object()
        .and_then(|map| map.get("type"))
        .and_then(Value::as_str)
        == Some("object");
    if is_object {
        Ok(())
    } else {
        Err(Error::SchemaNotObject {
            tool: tool.to_owned(),
            field,
        })
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn new_descriptor_is_valid() {
        ToolDescriptor::new("echo", "Echo the input.")
            .validate()
            .unwrap();
    }

    #[test]
    fn names() {
        assert!(validate_name("a").is_ok());
        assert!(validate_name("A-z_0.9").is_ok());
        assert!(validate_name(&"x".repeat(128)).is_ok());
        for bad in ["", "a b", "a/b", "a,b", "café", &"x".repeat(129)] {
            assert!(
                matches!(validate_name(bad), Err(Error::InvalidName { .. })),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn empty_description_is_rejected() {
        let err = ToolDescriptor::new("x", "  ").validate().unwrap_err();
        assert_eq!(err, Error::EmptyDescription("x".into()));
    }

    #[test]
    fn schemas_must_be_objects() {
        for schema in [
            json!(null),
            json!({"type": "string"}),
            json!(["object"]),
            json!({}),
        ] {
            let err = ToolDescriptor::new("x", "d")
                .with_input_schema(schema.clone())
                .validate()
                .unwrap_err();
            assert!(
                matches!(
                    err,
                    Error::SchemaNotObject {
                        field: "inputSchema",
                        ..
                    }
                ),
                "{schema}"
            );
            let err = ToolDescriptor::new("x", "d")
                .with_output_schema(schema)
                .validate()
                .unwrap_err();
            assert!(matches!(
                err,
                Error::SchemaNotObject {
                    field: "outputSchema",
                    ..
                }
            ));
        }
    }

    #[test]
    fn with_safety_resets_hints() {
        let tool = ToolDescriptor::new("x", "d")
            .with_hints(ToolHints::PURE)
            .with_safety(SafetyLevel::Active);
        assert_eq!(tool.hints, SafetyLevel::Active.default_hints());
    }

    /// A tool manifest in the descriptor's JSON shape.
    #[test]
    fn reads_a_tool_manifest() {
        let manifest = json!({
            "name": "network_port_scanner",
            "title": "Port scanner",
            "description": "TCP connect scan of the given ports.",
            "category": "network",
            "tags": ["ports", "tcp"],
            "safety": "active",
            "hints": {
                "read_only": false,
                "destructive": false,
                "idempotent": false,
                "open_world": true
            },
            "version": "0.1.0",
            "input_schema": {
                "$schema": "https://json-schema.org/draft/2020-12/schema",
                "title": "PortScanOptions",
                "type": "object",
                "properties": { "ports": { "type": "array", "items": { "type": "integer" } } }
            },
            "output_schema": null
        });
        let tool: ToolDescriptor = serde_json::from_value(manifest).unwrap();
        tool.validate().unwrap();
        assert_eq!(tool.category, Some(ToolCategory::NETWORK));
        assert_eq!(tool.safety, SafetyLevel::Active);
        assert_eq!(tool.output_schema, None);
        assert_eq!(tool.tags, ["ports", "tcp"]);
    }

    #[test]
    fn minimal_json_fills_defaults() {
        let tool: ToolDescriptor =
            serde_json::from_value(json!({"name": "x", "description": "d"})).unwrap();
        assert_eq!(tool, ToolDescriptor::new("x", "d"));
    }
}
