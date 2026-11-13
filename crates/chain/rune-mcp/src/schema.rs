//! Schema checks on both sides of the wire, on top of
//! [`rune_tool_schema::Validator`].
//!
//! The validator itself (keywords, JSON Pointer errors, depth, size and
//! work limits, local `$ref`) lives in `rune-tool-schema`. What this module
//! adds is MCP policy: the limits a schema from a server is compiled with,
//! and the JSON nesting cap on schemas received from servers.

use rune_tool_schema::{Limits, Validator};
use serde_json::{Map, Value};

/// Deepest JSON nesting accepted in a schema received from a server, and
/// in argument values checked against any tool schema.
pub const MAX_SCHEMA_DEPTH: usize = 32;

/// Most schema checks one argument validation may perform. Lower than the
/// `rune-tool-schema` default, since a remote schema is written by someone
/// else and a hostile `anyOf` or `$ref` web should fail fast.
pub const MAX_VALIDATION_STEPS: usize = 200_000;

/// The [`Limits`] tool schemas are compiled with, on the server (for
/// registered tools) and on the client (for listed ones).
///
/// ```
/// let limits = rune_mcp::schema_limits();
/// assert_eq!(limits.max_depth, rune_mcp::MAX_SCHEMA_DEPTH);
/// assert_eq!(limits.max_steps, rune_mcp::MAX_VALIDATION_STEPS);
/// ```
#[must_use]
pub fn schema_limits() -> Limits {
    let mut limits = Limits::default();
    limits.max_depth = MAX_SCHEMA_DEPTH;
    limits.max_steps = MAX_VALIDATION_STEPS;
    limits
}

/// Compile a tool's input schema with [`schema_limits`].
pub fn compile(schema: &Value) -> Result<Validator, rune_tool_schema::Error> {
    Validator::with_limits(schema, schema_limits())
}

/// Check `arguments`, returning the violations as one string (one line
/// per violation) for an `isError` tool result.
pub fn check(validator: &Validator, arguments: &Map<String, Value>) -> Result<(), String> {
    let value = Value::Object(arguments.clone());
    validator
        .validate(&value)
        .map_err(|violations| violations.to_string())
}

/// Whether `value` nests arrays and objects deeper than `max` levels (a
/// scalar is 0). Iterative, so a hostile value cannot exhaust the stack.
pub fn deeper_than(value: &Value, max: usize) -> bool {
    let mut stack = vec![(value, 0usize)];
    while let Some((value, depth)) = stack.pop() {
        let children: Box<dyn Iterator<Item = &Value>> = match value {
            Value::Array(items) => Box::new(items.iter()),
            Value::Object(map) => Box::new(map.values()),
            _ => continue,
        };
        if depth >= max {
            return true;
        }
        stack.extend(children.map(|child| (child, depth + 1)));
    }
    false
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

    #[test]
    fn violations_name_the_path_and_rule() {
        let v = compile(&json!({
            "type": "object",
            "properties": {
                "host": {"type": "string", "minLength": 1},
                "port": {"type": "integer", "minimum": 1}
            },
            "required": ["host"],
            "additionalProperties": false
        }))
        .unwrap();
        assert_eq!(check(&v, &args(json!({"host": "h", "port": 2}))), Ok(()));
        assert_eq!(
            check(&v, &args(json!({"port": 0, "evil": 1}))),
            Err("/host: missing required property\n\
                 /evil: unknown property\n\
                 /port: less than the minimum 1"
                .to_owned())
        );
    }

    #[test]
    fn deep_values_are_refused() {
        let v = compile(&json!({"type": "object"})).unwrap();
        let mut value = json!(1);
        for _ in 0..(MAX_SCHEMA_DEPTH + 4) {
            value = json!({"a": value});
        }
        let err = check(&v, value.as_object().unwrap()).unwrap_err();
        assert!(err.contains("nested deeper than 32"), "{err}");
    }

    #[test]
    fn depth_is_measured_without_recursion() {
        assert!(!deeper_than(&json!(1), 0));
        assert!(!deeper_than(&json!({"a": [1]}), 2));
        assert!(deeper_than(&json!({"a": [1]}), 1));
        let mut value = json!(null);
        for _ in 0..1000 {
            value = Value::Array(vec![value]);
        }
        assert!(deeper_than(&value, MAX_SCHEMA_DEPTH));
        assert!(!deeper_than(&value, 1000));
    }
}
