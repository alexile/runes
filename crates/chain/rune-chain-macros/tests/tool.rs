//! Runtime behaviour of `#[tool]`.
#![allow(
    clippy::cast_precision_loss,
    clippy::missing_const_for_fn,
    clippy::needless_pass_by_value,
    clippy::unused_async,
    clippy::use_self,
    reason = "the tool functions are written the way users write them"
)]

use std::collections::BTreeMap;
use std::fmt;

use rune_chain_core::{MAX_TOOL_ARGUMENTS_BYTES, Tool, ToolError, tool};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

/// Add two integers.
#[tool]
fn add(
    /// The first number.
    a: i64,
    /// The second number.
    b: i64,
) -> i64 {
    a + b
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "lowercase")]
enum Unit {
    Celsius,
    Fahrenheit,
}

#[derive(Debug, Serialize)]
struct Report {
    city: String,
    temp: f64,
}

/// Current weather for a city.
///
/// Uses the cached forecast.
#[tool(name = "weather")]
async fn get_weather(
    /// City name, like "Oslo".
    city: &str,
    #[arg(desc = "Temperature unit")] unit: Option<Unit>,
    #[arg(default)] days: u8,
) -> Result<Report, String> {
    if city.is_empty() {
        return Err("empty city".into());
    }
    let temp = match unit {
        Some(Unit::Fahrenheit) => 70.0,
        _ => 21.0 + f64::from(days),
    };
    Ok(Report {
        city: city.to_owned(),
        temp,
    })
}

#[derive(Debug)]
/// Lookup miss.
pub struct NotFound;

impl fmt::Display for NotFound {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("no such user")
    }
}

/// Look a user up.
#[tool(description = "Find a user by id.")]
pub async fn find_user(id: u64) -> Result<String, NotFound> {
    if id == 1 {
        Ok("ada".into())
    } else {
        Err(NotFound)
    }
}

/// Validates its own input.
#[tool]
fn strict(n: i32) -> Result<i32, ToolError> {
    if n < 0 {
        Err(ToolError::InvalidInput("n must not be negative".into()))
    } else {
        Ok(n)
    }
}

/// Sum a list.
#[tool]
fn total(xs: &[f64], labels: Vec<String>, weights: BTreeMap<String, f64>) -> f64 {
    let w: f64 = weights.values().sum();
    xs.iter().sum::<f64>() + w + labels.len() as f64
}

/// Takes nothing.
#[tool]
async fn ping() -> &'static str {
    "pong"
}

/// Returns nothing.
#[tool]
fn noop() {}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct Filter {
    /// Field to match.
    field: String,
    /// Nested filters.
    #[serde(default)]
    any: Vec<Filter>,
}

/// Count filters, recursively.
#[tool]
fn count_filters(filter: Filter) -> usize {
    fn count(f: &Filter) -> usize {
        1 + f.any.iter().map(count).sum::<usize>()
    }
    let _ = &filter.field;
    count(&filter)
}

/// Uses a raw identifier.
#[tool]
fn r#match(r#type: String) -> String {
    r#type
}

#[tokio::test]
async fn sync_fn_with_doc_args() {
    assert_eq!(Add.name(), "add");
    assert_eq!(Add.description(), "Add two integers.");
    assert_eq!(Add.run(r#"{"a": 2, "b": 40}"#).await.unwrap(), "42");
    // The fn itself is still there.
    assert_eq!(add(1, 1), 2);
    assert_eq!(
        Add.schema(),
        json!({
            "type": "object",
            "properties": {
                "a": { "type": "integer", "format": "int64", "description": "The first number." },
                "b": { "type": "integer", "format": "int64", "description": "The second number." }
            },
            "required": ["a", "b"],
            "additionalProperties": false
        })
    );
    let def = Add.function_definition();
    assert_eq!(def.name, "add");
    assert!(def.has_valid_name());
}

#[tokio::test]
async fn async_fn_with_options_and_enum() {
    let t = GetWeather;
    assert_eq!(t.name(), "weather");
    assert_eq!(
        t.description(),
        "Current weather for a city.\n\nUses the cached forecast."
    );
    let schema = t.schema();
    assert_eq!(schema["required"], json!(["city"]));
    assert_eq!(
        schema["properties"]["city"]["description"],
        "City name, like \"Oslo\"."
    );
    assert_eq!(
        schema["properties"]["unit"]["description"],
        "Temperature unit"
    );
    let unit = schema["properties"]["unit"].to_string();
    assert!(
        unit.contains("celsius") && unit.contains("fahrenheit"),
        "{unit}"
    );
    assert!(
        schema.get("$defs").is_none(),
        "subschemas are inlined: {schema}"
    );
    assert!(schema.get("$schema").is_none());
    assert!(schema.get("title").is_none());

    let out = t.run(r#"{"city":"Oslo"}"#).await.unwrap();
    assert_eq!(out, r#"{"city":"Oslo","temp":21.0}"#);
    let out = t
        .run(r#"{"city":"Oslo","unit":"fahrenheit"}"#)
        .await
        .unwrap();
    assert_eq!(serde_json::from_str::<Value>(&out).unwrap()["temp"], 70.0);
    let out = t
        .run(r#"{"city":"Oslo","days":2,"unit":null}"#)
        .await
        .unwrap();
    assert_eq!(serde_json::from_str::<Value>(&out).unwrap()["temp"], 23.0);
    // Escaped strings work although the fn takes `&str`.
    let out = t.run(r#"{"city":"O\"slo"}"#).await.unwrap();
    assert!(out.contains(r#"O\"slo"#));

    let err = t.run(r#"{"city":""}"#).await.unwrap_err();
    assert!(
        matches!(err, ToolError::ExecutionFailed(ref m) if m == "empty city"),
        "{err:?}"
    );
}

#[tokio::test]
async fn bad_model_input_is_an_error_never_a_panic() {
    let t = GetWeather;
    let cases = [
        "",
        "   ",
        "{",
        "null",
        "[]",
        "42",
        r#""Oslo""#,
        r#"{"city": 5}"#,
        r#"{"unit": "kelvin", "city": "x"}"#,
        r#"{"city": "x", "days": 300}"#,
        r#"{"city": "x", "days": -1}"#,
        r#"{"city": "x", "extra": true}"#,
        r#"{"city": "x", "city": "y"}"#,
        "{\"city\": \"\u{0}\"",
    ];
    for input in cases {
        let err = t.run(input).await.unwrap_err();
        assert!(
            matches!(err, ToolError::InvalidInput(_)),
            "{input:?} -> {err:?}"
        );
    }
    let deep = format!("{}{}", "[".repeat(10_000), "]".repeat(10_000));
    assert!(matches!(
        t.run(&deep).await,
        Err(ToolError::InvalidInput(_))
    ));
    let huge = format!(r#"{{"city":"{}"}}"#, "x".repeat(MAX_TOOL_ARGUMENTS_BYTES));
    let err = t.run(&huge).await.unwrap_err();
    assert!(
        matches!(err, ToolError::InvalidInput(ref m) if m.contains("limit")),
        "{err:?}"
    );
}

#[tokio::test]
async fn display_errors_and_tool_errors() {
    assert_eq!(FindUser.description(), "Find a user by id.");
    assert_eq!(FindUser.run(r#"{"id":1}"#).await.unwrap(), "ada");
    let err = FindUser.run(r#"{"id":2}"#).await.unwrap_err();
    assert!(matches!(err, ToolError::ExecutionFailed(ref m) if m == "no such user"));

    assert_eq!(Strict.run(r#"{"n":3}"#).await.unwrap(), "3");
    let err = Strict.run(r#"{"n":-3}"#).await.unwrap_err();
    assert!(matches!(err, ToolError::InvalidInput(ref m) if m == "n must not be negative"));
}

#[tokio::test]
async fn borrowed_and_collection_args() {
    let s = Total.schema();
    assert_eq!(s["properties"]["xs"]["type"], "array");
    assert_eq!(s["properties"]["labels"]["items"]["type"], "string");
    assert_eq!(s["properties"]["weights"]["type"], "object");
    let out = Total
        .run(r#"{"xs":[1.5,2.5],"labels":["a"],"weights":{"w":10}}"#)
        .await
        .unwrap();
    assert_eq!(out, "15.0");
}

#[tokio::test]
async fn no_args_and_unit_return() {
    assert_eq!(
        Ping.schema(),
        json!({"type": "object", "properties": {}, "additionalProperties": false})
    );
    assert_eq!(Ping.run("").await.unwrap(), "pong");
    assert_eq!(Ping.run("{}").await.unwrap(), "pong");
    assert!(Ping.run(r#"{"x":1}"#).await.is_err());
    assert_eq!(Noop.run("{}").await.unwrap(), "null");
}

#[tokio::test]
async fn recursive_types_keep_a_ref() {
    let s = CountFilters.schema();
    assert!(s.to_string().contains("$ref"), "{s}");
    let out = CountFilters
        .run(
            r#"{"filter":{"field":"a","any":[{"field":"b"},{"field":"c","any":[{"field":"d"}]}]}}"#,
        )
        .await
        .unwrap();
    assert_eq!(out, "4");
}

#[tokio::test]
async fn raw_identifiers() {
    assert_eq!(Match.name(), "match");
    assert_eq!(Match.schema()["required"], json!(["type"]));
    assert_eq!(Match.run(r#"{"type":"x"}"#).await.unwrap(), "x");
}

#[tokio::test]
async fn works_as_a_trait_object() {
    let tools: Vec<Box<dyn Tool>> = vec![Box::new(Add), Box::new(GetWeather), Box::new(Ping)];
    let names: Vec<&str> = tools.iter().map(|t| t.name()).collect();
    assert_eq!(names, ["add", "weather", "ping"]);
    for t in &tools {
        assert_eq!(t.schema()["type"], "object");
    }
}

mod renamed {
    //! The crate under another name, through the `crate` override.
    use rune_chain_core as chain;

    /// Echo.
    #[chain::tool(crate = "chain")]
    pub fn echo(text: String) -> String {
        text
    }
}

#[tokio::test]
async fn crate_override() {
    assert_eq!(renamed::Echo.run(r#"{"text":"hi"}"#).await.unwrap(), "hi");
}
