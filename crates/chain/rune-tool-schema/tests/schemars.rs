//! Schema generation from Rust types (`schemars` feature).
#![cfg(feature = "schemars")]

use rune_tool_schema::{Error, ToolDescriptor, json_schema_for};
use schemars::JsonSchema;

/// Arguments of an example tool.
#[derive(JsonSchema)]
#[allow(dead_code, reason = "only the schema is used")]
struct ScanArgs {
    /// Host to scan.
    host: String,
    /// Ports; all common ports when absent.
    ports: Option<Vec<u16>>,
}

/// Result of an example tool.
#[derive(JsonSchema)]
#[allow(dead_code, reason = "only the schema is used")]
struct ScanReport {
    open: Vec<u16>,
}

#[test]
fn typed_schemas_validate_and_export() {
    let tool = ToolDescriptor::new("scan", "Scan a host.")
        .with_input_type::<ScanArgs>()
        .with_output_type::<ScanReport>();
    let mcp = tool.to_mcp().unwrap();
    assert_eq!(mcp.input_schema["required"], serde_json::json!(["host"]));
    assert_eq!(
        mcp.input_schema["properties"]["host"]["description"],
        "Host to scan."
    );
    assert_eq!(mcp.output_schema.unwrap()["type"], "object");
}

#[test]
fn non_object_types_are_rejected() {
    let err = ToolDescriptor::new("x", "d")
        .with_input_type::<String>()
        .validate()
        .unwrap_err();
    assert!(matches!(err, Error::SchemaNotObject { .. }));
}

#[test]
fn descriptor_types_have_schemas() {
    let schema = json_schema_for::<ToolDescriptor>();
    assert_eq!(schema["type"], "object");
    let required = schema["required"].as_array().unwrap();
    assert!(required.contains(&"name".into()));
    assert!(required.contains(&"description".into()));
}
