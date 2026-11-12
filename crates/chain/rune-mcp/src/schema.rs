//! Argument checks against a tool's JSON Schema, before the tool runs, and
//! size and depth checks on schemas received from servers.
//!
//! The validator covers the keywords tool schemas use in practice: `type`,
//! `enum`, `const`, `properties`, `required`, `additionalProperties`,
//! `items`, `minItems`/`maxItems`, `minLength`/`maxLength`,
//! `minimum`/`maximum`/`exclusiveMinimum`/`exclusiveMaximum`, `allOf`,
//! `anyOf` and `oneOf`. Other keywords (`$ref`, `pattern`, `format`, …)
//! are not checked, so a value is only rejected for a rule it really
//! breaks. Reasons name the JSON path and the rule, never the schema text.

use serde_json::{Map, Value};

/// Nesting deeper than this is refused, in schemas and in values checked
/// against them.
pub const MAX_SCHEMA_DEPTH: usize = 32;

/// Check a tool's arguments against its input schema.
///
/// # Errors
///
/// A short reason naming the offending path, such as
/// ``/count: expected integer, got string``.
///
/// ```
/// use rune_mcp::validate_arguments;
/// use serde_json::json;
///
/// let schema = json!({
///     "type": "object",
///     "properties": {"count": {"type": "integer", "minimum": 1}},
///     "required": ["count"],
///     "additionalProperties": false
/// });
/// let args = |v: serde_json::Value| v.as_object().unwrap().clone();
/// assert!(validate_arguments(&schema, &args(json!({"count": 2}))).is_ok());
/// assert!(validate_arguments(&schema, &args(json!({"count": 0}))).is_err());
/// assert!(validate_arguments(&schema, &args(json!({}))).is_err());
/// assert!(validate_arguments(&schema, &args(json!({"count": 1, "x": 1}))).is_err());
/// ```
pub fn validate_arguments(schema: &Value, arguments: &Map<String, Value>) -> Result<(), String> {
    check(schema, &Value::Object(arguments.clone()), "", 0)
}

/// Depth of nested arrays and objects in `value` (a scalar is 0).
pub fn depth(value: &Value) -> usize {
    match value {
        Value::Array(items) => 1 + items.iter().map(depth).max().unwrap_or(0),
        Value::Object(map) => 1 + map.values().map(depth).max().unwrap_or(0),
        _ => 0,
    }
}

fn type_name(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(n) if is_integer(n) => "integer",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

fn is_integer(n: &serde_json::Number) -> bool {
    n.is_i64() || n.is_u64() || n.as_f64().is_some_and(|f| f.fract() == 0.0)
}

fn type_matches(name: &str, value: &Value) -> bool {
    match name {
        "string" => value.is_string(),
        "integer" => value.as_number().is_some_and(is_integer),
        "number" => value.is_number(),
        "boolean" => value.is_boolean(),
        "object" => value.is_object(),
        "array" => value.is_array(),
        "null" => value.is_null(),
        _ => true,
    }
}

const fn at(path: &str) -> &str {
    if path.is_empty() { "/" } else { path }
}

fn child(path: &str, key: &str) -> String {
    let key = key.replace('~', "~0").replace('/', "~1");
    let mut key: String = key.chars().take(64).collect();
    if key.len() >= 64 {
        key.push('…');
    }
    format!("{path}/{key}")
}

/// Check `value` against `schema`.
fn check(schema: &Value, value: &Value, path: &str, depth: usize) -> Result<(), String> {
    if depth > MAX_SCHEMA_DEPTH {
        return Err(format!("{}: nested too deeply", at(path)));
    }
    if let Value::Object(map) = value {
        check_object(schema, map, path, depth)?;
    }
    check_common(schema, value, path, depth)
}

/// The keywords that apply to every value.
fn check_common(schema: &Value, value: &Value, path: &str, depth: usize) -> Result<(), String> {
    let Some(schema) = schema.as_object() else {
        return match schema {
            Value::Bool(false) => Err(format!("{}: no value is allowed here", at(path))),
            _ => Ok(()),
        };
    };
    if let Some(declared) = schema.get("type") {
        let ok = match declared {
            Value::String(t) => type_matches(t, value),
            Value::Array(ts) => ts
                .iter()
                .filter_map(Value::as_str)
                .any(|t| type_matches(t, value)),
            _ => true,
        };
        if !ok {
            return Err(format!(
                "{}: expected {}, got {}",
                at(path),
                match declared {
                    Value::String(t) => t.clone(),
                    other => other.to_string(),
                },
                type_name(value)
            ));
        }
    }
    if let Some(allowed) = schema.get("enum").and_then(Value::as_array)
        && !allowed.contains(value)
    {
        return Err(format!("{}: not one of the allowed values", at(path)));
    }
    if let Some(expected) = schema.get("const")
        && expected != value
    {
        return Err(format!(
            "{}: does not match the required constant",
            at(path)
        ));
    }
    match value {
        Value::String(s) => {
            let len = s.chars().count() as u64;
            if let Some(min) = schema.get("minLength").and_then(Value::as_u64)
                && len < min
            {
                return Err(format!("{}: shorter than {min} characters", at(path)));
            }
            if let Some(max) = schema.get("maxLength").and_then(Value::as_u64)
                && len > max
            {
                return Err(format!("{}: longer than {max} characters", at(path)));
            }
        }
        Value::Number(n) => {
            if let Some(f) = n.as_f64() {
                let bound = |key: &str| schema.get(key).and_then(Value::as_f64);
                if bound("minimum").is_some_and(|m| f < m)
                    || bound("exclusiveMinimum").is_some_and(|m| f <= m)
                {
                    return Err(format!("{}: below the minimum", at(path)));
                }
                if bound("maximum").is_some_and(|m| f > m)
                    || bound("exclusiveMaximum").is_some_and(|m| f >= m)
                {
                    return Err(format!("{}: above the maximum", at(path)));
                }
            }
        }
        Value::Array(items) => {
            let len = items.len() as u64;
            if let Some(min) = schema.get("minItems").and_then(Value::as_u64)
                && len < min
            {
                return Err(format!("{}: fewer than {min} items", at(path)));
            }
            if let Some(max) = schema.get("maxItems").and_then(Value::as_u64)
                && len > max
            {
                return Err(format!("{}: more than {max} items", at(path)));
            }
            if let Some(item_schema) = schema.get("items")
                && (item_schema.is_object() || item_schema.is_boolean())
            {
                for (i, item) in items.iter().enumerate() {
                    check(item_schema, item, &child(path, &i.to_string()), depth + 1)?;
                }
            }
        }
        _ => {}
    }
    if let Some(all) = schema.get("allOf").and_then(Value::as_array) {
        for sub in all {
            check(sub, value, path, depth + 1)?;
        }
    }
    if let Some(any) = schema.get("anyOf").and_then(Value::as_array)
        && !any.is_empty()
        && !any
            .iter()
            .any(|sub| check(sub, value, path, depth + 1).is_ok())
    {
        return Err(format!("{}: matches none of the allowed forms", at(path)));
    }
    if let Some(one) = schema.get("oneOf").and_then(Value::as_array)
        && !one.is_empty()
    {
        let matching = one
            .iter()
            .filter(|sub| check(sub, value, path, depth + 1).is_ok())
            .count();
        if matching != 1 {
            return Err(format!(
                "{}: must match exactly one allowed form, matches {matching}",
                at(path)
            ));
        }
    }
    Ok(())
}

/// The object keywords: `required`, `properties`, `additionalProperties`.
fn check_object(
    schema: &Value,
    map: &Map<String, Value>,
    path: &str,
    depth: usize,
) -> Result<(), String> {
    let Some(schema) = schema.as_object() else {
        return Ok(());
    };
    if let Some(required) = schema.get("required").and_then(Value::as_array) {
        for key in required.iter().filter_map(Value::as_str) {
            if !map.contains_key(key) {
                return Err(format!("{}: missing required property", child(path, key)));
            }
        }
    }
    let properties = schema.get("properties").and_then(Value::as_object);
    let additional = schema.get("additionalProperties");
    for (key, value) in map {
        let key_path = child(path, key);
        if let Some(prop) = properties.and_then(|p| p.get(key)) {
            check(prop, value, &key_path, depth + 1)?;
        } else {
            match additional {
                Some(Value::Bool(false)) => {
                    return Err(format!("{key_path}: unknown property"));
                }
                Some(extra @ Value::Object(_)) => check(extra, value, &key_path, depth + 1)?,
                _ => {}
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn args(v: Value) -> Map<String, Value> {
        match v {
            Value::Object(map) => map,
            _ => Map::new(),
        }
    }

    fn schema() -> Value {
        json!({
            "type": "object",
            "properties": {
                "host": {"type": "string", "minLength": 1, "maxLength": 10},
                "port": {"type": "integer", "minimum": 1, "maximum": 65535},
                "mode": {"enum": ["fast", "slow"]},
                "tags": {"type": "array", "items": {"type": "string"}, "maxItems": 2},
                "opts": {
                    "type": "object",
                    "properties": {"deep": {"type": "boolean"}},
                    "additionalProperties": false
                },
                "either": {"anyOf": [{"type": "string"}, {"type": "null"}]},
                "ratio": {"type": "number", "exclusiveMaximum": 1}
            },
            "required": ["host"],
            "additionalProperties": false
        })
    }

    #[test]
    fn accepts_valid_arguments() {
        let ok = args(json!({
            "host": "a.b", "port": 443, "mode": "fast", "tags": ["x"],
            "opts": {"deep": true}, "either": null, "ratio": 0.5
        }));
        assert_eq!(validate_arguments(&schema(), &ok), Ok(()));
        // 2.0 is an integer in JSON Schema.
        let ok = args(json!({"host": "h", "port": 2.0}));
        assert_eq!(validate_arguments(&schema(), &ok), Ok(()));
    }

    #[test]
    fn rejects_each_rule_with_a_path() {
        let s = schema();
        let cases = [
            (json!({}), "/host: missing required property"),
            (json!({"host": 1}), "/host: expected string, got integer"),
            (json!({"host": ""}), "/host: shorter than 1 characters"),
            (json!({"host": "h", "port": 0}), "/port: below the minimum"),
            (
                json!({"host": "h", "port": 1.5}),
                "/port: expected integer, got number",
            ),
            (
                json!({"host": "h", "mode": "x"}),
                "/mode: not one of the allowed values",
            ),
            (
                json!({"host": "h", "tags": [1]}),
                "/tags/0: expected string, got integer",
            ),
            (
                json!({"host": "h", "tags": ["a", "b", "c"]}),
                "/tags: more than 2 items",
            ),
            (
                json!({"host": "h", "opts": {"x": 1}}),
                "/opts/x: unknown property",
            ),
            (
                json!({"host": "h", "either": 1}),
                "/either: matches none of the allowed forms",
            ),
            (
                json!({"host": "h", "ratio": 1}),
                "/ratio: above the maximum",
            ),
            (json!({"host": "h", "evil": 1}), "/evil: unknown property"),
        ];
        for (value, reason) in cases {
            assert_eq!(
                validate_arguments(&s, &args(value.clone())),
                Err(reason.to_owned()),
                "{value}"
            );
        }
    }

    #[test]
    fn open_schemas_and_unknown_keywords_accept() {
        let s = json!({"type": "object", "properties": {"p": {"pattern": "^x$", "$ref": "#/x"}}});
        assert!(validate_arguments(&s, &args(json!({"p": "y", "q": [1]}))).is_ok());
        assert!(validate_arguments(&json!({}), &args(json!({"a": 1}))).is_ok());
    }

    #[test]
    fn deep_values_are_refused_not_recursed_forever() {
        let mut value = json!(1);
        for _ in 0..(MAX_SCHEMA_DEPTH + 4) {
            value = json!({"a": value});
        }
        let mut s = json!({});
        for _ in 0..(MAX_SCHEMA_DEPTH + 4) {
            s = json!({"type": "object", "properties": {"a": s}});
        }
        let err = validate_arguments(&s, value.as_object().unwrap()).unwrap_err();
        assert!(err.ends_with("nested too deeply"), "{err}");
        assert_eq!(depth(&value), MAX_SCHEMA_DEPTH + 4);
    }

    #[test]
    fn path_segments_are_escaped_and_bounded() {
        assert_eq!(child("", "a/b~c"), "/a~1b~0c");
        assert!(child("", &"k".repeat(500)).len() < 80);
    }
}
