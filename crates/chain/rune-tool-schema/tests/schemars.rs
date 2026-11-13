//! Schema generation from Rust types (`schemars` feature).
#![cfg(feature = "schemars")]

use rune_tool_schema::{Dialect, Error, ToolDescriptor, json_schema_for};
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

/// A richer argument type: nested struct, enum, optional fields, defaults.
#[derive(JsonSchema, serde::Serialize, serde::Deserialize, Debug, PartialEq)]
struct SearchArgs {
    /// What to look for.
    query: String,
    /// Result count.
    #[serde(default = "default_limit")]
    limit: u8,
    /// Sort order.
    order: Option<Order>,
    /// Restrict to a site.
    site: Option<Site>,
    tags: Vec<String>,
}

const fn default_limit() -> u8 {
    10
}

#[derive(JsonSchema, serde::Serialize, serde::Deserialize, Debug, PartialEq)]
#[serde(rename_all = "snake_case")]
enum Order {
    Newest,
    Relevance,
}

#[derive(JsonSchema, serde::Serialize, serde::Deserialize, Debug, PartialEq)]
struct Site {
    host: String,
}

fn search_tool() -> ToolDescriptor {
    ToolDescriptor::new("search", "Search the index.").with_input_type::<SearchArgs>()
}

#[test]
fn generated_schemas_validate_their_own_values() {
    let validator = rune_tool_schema::Validator::for_type::<SearchArgs>().unwrap();
    let args = SearchArgs {
        query: "rust".into(),
        limit: 3,
        order: Some(Order::Newest),
        site: Some(Site {
            host: "example.com".into(),
        }),
        tags: vec!["a".into()],
    };
    let value = serde_json::to_value(&args).unwrap();
    validator.validate(&value).unwrap();
    assert_eq!(
        search_tool().parse_arguments::<SearchArgs>(&value).unwrap(),
        args
    );

    let bad = serde_json::json!({"query": 1, "limit": 300, "order": "oldest", "tags": []});
    let found: Vec<String> = validator
        .validate(&bad)
        .unwrap_err()
        .iter()
        .map(ToString::to_string)
        .collect();
    assert_eq!(
        found,
        [
            "/limit: greater than the maximum 255",
            "/order: matches none of the allowed alternatives",
            "/query: expected string, got integer",
        ]
    );
}

#[test]
fn generated_schemas_export_to_every_dialect() {
    let tool = search_tool();
    for dialect in Dialect::ALL {
        let exported = tool.export(dialect).unwrap();
        assert!(
            exported.findings.iter().all(|f| !f.is_blocking()),
            "{dialect}"
        );
    }
    let gemini = tool.export(Dialect::Gemini).unwrap().definition;
    let site = &gemini["parameters"]["properties"]["site"];
    assert_eq!(site["type"], "OBJECT");
    assert_eq!(site["nullable"], true);
    assert!(!gemini.to_string().contains("$ref"));
}

/// The full strict-mode loop: the model fills every key, nulls for the
/// ones it leaves out; normalizing restores what the type expects.
#[test]
fn strict_round_trip_through_a_type() {
    let tool = search_tool();
    let strict = tool.export(Dialect::OpenAiStrict).unwrap();
    let parameters = &strict.definition["function"]["parameters"];
    let mut from_model = serde_json::json!({
        "query": "rust", "limit": null, "order": null, "site": null, "tags": []
    });
    rune_tool_schema::Validator::new(parameters)
        .unwrap()
        .validate(&from_model)
        .unwrap();
    rune_tool_schema::drop_optional_nulls(&tool.input_schema, &mut from_model);
    let args: SearchArgs = tool.parse_arguments(&from_model).unwrap();
    assert_eq!(args.limit, 10);
    assert_eq!(args.order, None);
}
