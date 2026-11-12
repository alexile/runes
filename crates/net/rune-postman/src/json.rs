//! Forgiving accessors over `serde_json` values.
//!
//! Exports differ in detail: `null` where a field is absent, numbers and
//! booleans where text belongs, `"true"` for `true`. These helpers read
//! all of them the way Postman does.

use serde_json::{Map, Value};

/// Parses UTF-8 JSON, ignoring a leading byte-order mark.
pub fn parse(input: &[u8]) -> Result<Value, crate::PostmanError> {
    let input = input.strip_prefix(b"\xef\xbb\xbf").unwrap_or(input);
    serde_json::from_slice(input).map_err(|error| crate::PostmanError::Json(error.to_string()))
}

/// A value as text: strings as they are, `null` as empty, numbers and
/// booleans as written, anything else as compact JSON.
pub fn text(value: &Value) -> String {
    match value {
        Value::String(text) => text.clone(),
        Value::Null => String::new(),
        Value::Number(number) => number.to_string(),
        Value::Bool(flag) => flag.to_string(),
        other => other.to_string(),
    }
}

/// `object[key]` as text, when present and not `null`.
pub fn field(object: &Map<String, Value>, key: &str) -> Option<String> {
    object.get(key).filter(|value| !value.is_null()).map(text)
}

/// `object[key]` as a non-empty string.
pub fn non_empty(object: &Map<String, Value>, key: &str) -> Option<String> {
    field(object, key).filter(|text| !text.is_empty())
}

/// Whether a flag is set: `true`, `"true"` or `1`.
pub fn flag(value: Option<&Value>) -> bool {
    match value {
        Some(Value::Bool(flag)) => *flag,
        Some(Value::String(text)) => text.eq_ignore_ascii_case("true"),
        Some(Value::Number(number)) => number.as_f64().is_some_and(|number| number != 0.0),
        _ => false,
    }
}

/// `object.disabled` is set.
pub fn disabled(object: &Map<String, Value>) -> bool {
    flag(object.get("disabled"))
}

/// A list field: an array, or nothing for `null` or a missing key.
///
/// # Errors
///
/// A value of another shape, described for a warning.
pub fn list<'a>(object: &'a Map<String, Value>, key: &str) -> Result<&'a [Value], String> {
    match object.get(key) {
        None | Some(Value::Null) => Ok(&[]),
        Some(Value::Array(items)) => Ok(items),
        Some(other) => Err(format!("`{key}` is {}, not an array", kind(other))),
    }
}

/// An object field, or nothing for `null` or a missing key.
///
/// # Errors
///
/// A value of another shape, described for a warning.
pub fn object<'a>(
    object: &'a Map<String, Value>,
    key: &str,
) -> Result<Option<&'a Map<String, Value>>, String> {
    match object.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Object(inner)) => Ok(Some(inner)),
        Some(other) => Err(format!("`{key}` is {}, not an object", kind(other))),
    }
}

/// A description: a string, or an object with `content` (v2.1).
pub fn description(object: &Map<String, Value>) -> Option<String> {
    match object.get("description") {
        Some(Value::String(text)) => Some(text.clone()),
        Some(Value::Object(inner)) => non_empty(inner, "content"),
        _ => None,
    }
    .filter(|text| !text.is_empty())
}

/// What kind of JSON value this is, for messages.
pub const fn kind(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "a boolean",
        Value::Number(_) => "a number",
        Value::String(_) => "a string",
        Value::Array(_) => "an array",
        Value::Object(_) => "an object",
    }
}
