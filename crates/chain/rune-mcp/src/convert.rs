//! Conversions between [`ToolDescriptor`] / [`McpTool`] and rmcp's
//! [`Tool`]. Both sides serialize to the MCP `Tool` JSON, so the conversion
//! goes through that JSON and loses nothing either way.

use rmcp::model::Tool;
use rune_tool_schema::{McpTool, SafetyLevel, ToolDescriptor, Validator};

use crate::Error;
use crate::sanitize::clean_text;
use crate::schema::{self, MAX_SCHEMA_DEPTH, deeper_than};

/// How far a client believes what a remote server says about its tools.
///
/// Tool annotations and the `_meta["runes/tool"]` entry are claims made by
/// the server. Policies compare [`SafetyLevel`]s, so an untrusted server must
/// not be able to lower the level of its own tools.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ServerTrust {
    /// Every remote tool is treated as [`SafetyLevel::Intrusive`], whatever
    /// the server claims. The default.
    #[default]
    Untrusted,
    /// The server's annotations and `_meta` are believed (a server you run
    /// yourself, such as another rune-mcp server).
    Trusted,
}

/// Export a descriptor as an rmcp [`Tool`], validating it first.
pub fn descriptor_to_tool(descriptor: &ToolDescriptor) -> Result<Tool, Error> {
    mcp_to_tool(&descriptor.to_mcp()?)
}

/// Convert a [`McpTool`] to rmcp's [`Tool`].
///
/// # Errors
///
/// [`Error::Convert`] if rmcp rejects the JSON (for example, a schema that
/// is not an object).
pub fn mcp_to_tool(tool: &McpTool) -> Result<Tool, Error> {
    serde_json::to_value(tool)
        .and_then(serde_json::from_value)
        .map_err(|err| Error::Convert {
            what: "tool definition",
            reason: err.to_string(),
        })
}

/// Convert rmcp's [`Tool`] to a [`McpTool`].
///
/// # Errors
///
/// [`Error::Convert`] if the definition is not valid MCP tool JSON.
pub fn tool_to_mcp(tool: &Tool) -> Result<McpTool, Error> {
    serde_json::to_value(tool)
        .and_then(serde_json::from_value)
        .map_err(|err| Error::Convert {
            what: "tool definition",
            reason: err.to_string(),
        })
}

/// Limits applied to a tool definition received from a server.
#[derive(Debug, Clone, Copy)]
pub struct ImportLimits {
    pub trust: ServerTrust,
    pub max_description_bytes: usize,
    pub max_schema_bytes: usize,
}

/// Import a tool listed by a remote server: check it, apply `trust`, strip
/// hidden characters from its text (description, title, tags, and the
/// `description`/`title` strings inside its schemas) and cap the
/// description and title, refuse oversized or over-deep schemas, input
/// schemas the validator cannot compile, and hidden characters left where
/// stripping them would change the interface (property names, `enum`
/// values). Returns the descriptor and the compiled input-schema validator.
pub fn import_tool(
    tool: &Tool,
    limits: ImportLimits,
) -> Result<(ToolDescriptor, Validator), Error> {
    let rejected = |reason: String| Error::Rejected {
        name: clean_text(&tool.name, 128),
        reason,
    };
    let descriptor = tool_to_mcp(tool)
        .and_then(|mcp| mcp.to_descriptor().map_err(Error::from))
        .map_err(|err| rejected(err.to_string()))?;
    for (field, schema) in [
        ("inputSchema", Some(&descriptor.input_schema)),
        ("outputSchema", descriptor.output_schema.as_ref()),
    ] {
        let Some(schema) = schema else { continue };
        if deeper_than(schema, MAX_SCHEMA_DEPTH) {
            return Err(rejected(format!(
                "{field} is nested deeper than {MAX_SCHEMA_DEPTH}"
            )));
        }
        let size = serde_json::to_vec(schema).map_or(usize::MAX, |bytes| bytes.len());
        if size > limits.max_schema_bytes {
            return Err(rejected(format!(
                "{field} is {size} bytes, over the {}-byte limit",
                limits.max_schema_bytes
            )));
        }
    }
    let validator = schema::compile(&descriptor.input_schema)
        .map_err(|err| rejected(format!("inputSchema: {err}")))?;
    let mut descriptor = descriptor.sanitized();
    descriptor.description = clean_text(&descriptor.description, limits.max_description_bytes);
    descriptor.title = descriptor
        .title
        .as_deref()
        .map(|title| clean_text(title, 256))
        .filter(|title| !title.is_empty());
    descriptor
        .check_hygiene(usize::MAX)
        .map_err(|err| rejected(err.to_string()))?;
    if limits.trust == ServerTrust::Untrusted {
        descriptor.safety = SafetyLevel::Intrusive;
    }
    Ok((descriptor, validator))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rune_tool_schema::{ToolCategory, ToolHints, single_input_schema};
    use serde_json::json;

    fn sample() -> ToolDescriptor {
        ToolDescriptor::new("hex_encode", "Hex-encode text.")
            .with_title("Hex encode")
            .with_category(ToolCategory::ENCODING)
            .with_hints(ToolHints::PURE)
            .with_tags(["codec"])
            .with_version("1.2.3")
            .with_input_schema(single_input_schema("Text"))
    }

    const fn limits(trust: ServerTrust) -> ImportLimits {
        ImportLimits {
            trust,
            max_description_bytes: 1024,
            max_schema_bytes: 64 * 1024,
        }
    }

    #[test]
    fn descriptor_round_trips_through_rmcp_tool() {
        let tool = descriptor_to_tool(&sample()).unwrap();
        assert_eq!(tool.name, "hex_encode");
        assert_eq!(tool.title.as_deref(), Some("Hex encode"));
        assert_eq!(
            tool.annotations.as_ref().unwrap().read_only_hint,
            Some(true)
        );
        let (back, _) = import_tool(&tool, limits(ServerTrust::Trusted)).unwrap();
        assert_eq!(back, sample());
    }

    #[test]
    fn untrusted_import_is_intrusive() {
        let tool = descriptor_to_tool(&sample()).unwrap();
        let (back, _) = import_tool(&tool, limits(ServerTrust::Untrusted)).unwrap();
        assert_eq!(back.safety, SafetyLevel::Intrusive);
        assert_eq!(back.hints, ToolHints::PURE);
    }

    #[test]
    fn invalid_descriptor_is_rejected() {
        let bad = ToolDescriptor::new("has space", "d");
        assert!(matches!(
            descriptor_to_tool(&bad),
            Err(Error::Descriptor(_))
        ));
    }

    #[test]
    fn import_cleans_and_caps_descriptions() {
        let desc = format!("Adds.\u{e0049}\u{200b}{}", "x".repeat(5000));
        let tool = descriptor_to_tool(&ToolDescriptor::new("add", desc)).unwrap();
        let (back, _) = import_tool(&tool, limits(ServerTrust::Untrusted)).unwrap();
        assert!(back.description.starts_with("Adds.xxx"));
        assert!(back.description.len() <= 1024 + '…'.len_utf8());
    }

    #[test]
    fn import_refuses_huge_or_deep_schemas() {
        let mut props = serde_json::Map::new();
        for i in 0..5000 {
            props.insert(format!("p{i}"), json!({"type": "string"}));
        }
        let big = descriptor_to_tool(
            &ToolDescriptor::new("big", "d")
                .with_input_schema(json!({"type": "object", "properties": props})),
        )
        .unwrap();
        let err = import_tool(&big, limits(ServerTrust::Trusted)).unwrap_err();
        assert!(matches!(err, Error::Rejected { .. }), "{err}");

        let mut deep = json!({"type": "string"});
        for _ in 0..40 {
            deep = json!({"type": "object", "properties": {"a": deep}});
        }
        let deep =
            descriptor_to_tool(&ToolDescriptor::new("deep", "d").with_input_schema(deep)).unwrap();
        assert!(import_tool(&deep, limits(ServerTrust::Trusted)).is_err());
    }

    #[test]
    fn import_strips_schema_annotations_and_refuses_hidden_names() {
        let schema = json!({
            "type": "object",
            "properties": {"q": {"type": "string", "description": "Query.\u{e0041}\u{200b}"}}
        });
        let tool =
            descriptor_to_tool(&ToolDescriptor::new("s", "d").with_input_schema(schema)).unwrap();
        let (back, _) = import_tool(&tool, limits(ServerTrust::Untrusted)).unwrap();
        assert_eq!(
            back.input_schema["properties"]["q"]["description"],
            "Query."
        );

        let schema = json!({"type": "object", "properties": {"q\u{200b}": {"type": "string"}}});
        let tool =
            descriptor_to_tool(&ToolDescriptor::new("s", "d").with_input_schema(schema)).unwrap();
        let err = import_tool(&tool, limits(ServerTrust::Untrusted)).unwrap_err();
        assert!(err.to_string().contains("hidden character U+200B"), "{err}");
    }

    #[test]
    fn import_refuses_schemas_the_validator_cannot_compile() {
        for schema in [
            json!({"type": "object", "properties": {"a": {"$ref": "https://evil.example/s"}}}),
            json!({"type": "object", "properties": {"a": {"$ref": "#/$defs/missing"}}}),
            json!({"type": "object", "properties": {"a": {"type": "string", "pattern": "(?=x)"}}}),
            json!({"type": "object", "required": "a"}),
        ] {
            let tool = descriptor_to_tool(&ToolDescriptor::new("s", "d").with_input_schema(schema))
                .unwrap();
            let err = import_tool(&tool, limits(ServerTrust::Trusted)).unwrap_err();
            assert!(
                err.to_string().contains("inputSchema: invalid schema"),
                "{err}"
            );
        }
    }
}
