//! Runtime support for the code `#[tool]` generates. Not public API: it can
//! change in any release.

use std::fmt::Display;

use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::{MAX_TOOL_ARGUMENTS_BYTES, ToolError};

pub use async_trait::async_trait;
#[cfg(feature = "macros")]
pub use schemars;
pub use serde;
pub use serde_json;

/// Parse a tool's JSON input into its argument struct, with the limits of
/// [`ToolCall::parse_arguments`](crate::ToolCall::parse_arguments).
pub fn parse_tool_args<T: DeserializeOwned>(tool: &str, input: &str) -> Result<T, ToolError> {
    crate::function_call::parse_bounded(tool, input, MAX_TOOL_ARGUMENTS_BYTES)
}

/// Turn a tool's return value into the observation string: a JSON string
/// as is, anything else as compact JSON.
pub fn to_output<T: Serialize + ?Sized>(value: &T) -> Result<String, ToolError> {
    match serde_json::to_value(value) {
        Ok(serde_json::Value::String(s)) => Ok(s),
        Ok(other) => Ok(other.to_string()),
        Err(e) => Err(ToolError::ExecutionFailed(format!(
            "could not serialize the tool output: {e}"
        ))),
    }
}

/// The argument schema of a generated tool: draft 2020-12 with subschemas
/// inlined (recursive types keep a `$ref`), without `$schema` and `title`.
#[cfg(feature = "macros")]
#[must_use]
pub fn tool_schema<T: schemars::JsonSchema>() -> serde_json::Value {
    let mut settings = schemars::generate::SchemaSettings::draft2020_12();
    settings.inline_subschemas = true;
    settings.meta_schema = None;
    let schema = settings.into_generator().into_root_schema_for::<T>();
    let mut value: serde_json::Value = schema.into();
    if let serde_json::Value::Object(map) = &mut value {
        map.remove("title");
        map.entry("properties")
            .or_insert_with(|| serde_json::Value::Object(serde_json::Map::new()));
    }
    value
}

/// Wrapper used to pick the error conversion at compile time: a
/// [`ToolError`] passes through, any other `Display` error becomes
/// [`ToolError::ExecutionFailed`].
pub struct ErrWrap<E>(pub E);

/// Picked for `ErrWrap<ToolError>`.
pub trait ViaToolError {
    /// The error as a [`ToolError`].
    fn to_tool_error(&self) -> ToolError;
}

impl ViaToolError for ErrWrap<ToolError> {
    fn to_tool_error(&self) -> ToolError {
        self.0.clone()
    }
}

/// Picked for any other `Display` error (one autoref further away).
pub trait ViaDisplay {
    /// The error as a [`ToolError`].
    fn to_tool_error(&self) -> ToolError;
}

impl<E: Display> ViaDisplay for &ErrWrap<E> {
    fn to_tool_error(&self) -> ToolError {
        ToolError::ExecutionFailed(self.0.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn output_strings_are_not_quoted() {
        assert_eq!(to_output("hi").unwrap(), "hi");
        assert_eq!(to_output(&42).unwrap(), "42");
        assert_eq!(to_output(&vec![1, 2]).unwrap(), "[1,2]");
        assert_eq!(to_output(&()).unwrap(), "null");
    }

    #[test]
    fn unserializable_output_is_an_error() {
        let mut map = std::collections::HashMap::new();
        map.insert(vec![1u8], 1);
        assert!(matches!(
            to_output(&map),
            Err(ToolError::ExecutionFailed(_))
        ));
    }

    #[test]
    fn error_conversion_keeps_tool_errors() {
        let e = ErrWrap(ToolError::InvalidInput("x".into())).to_tool_error();
        assert!(matches!(e, ToolError::InvalidInput(m) if m == "x"));
        let e = (&ErrWrap(std::fmt::Error)).to_tool_error();
        assert!(matches!(e, ToolError::ExecutionFailed(_)));
    }

    #[test]
    fn args_are_bounded() {
        let big = format!(r#"{{"a":"{}"}}"#, "x".repeat(MAX_TOOL_ARGUMENTS_BYTES));
        let err = parse_tool_args::<serde_json::Value>("t", &big).unwrap_err();
        assert!(matches!(err, ToolError::InvalidInput(_)));
        let v: serde_json::Value = parse_tool_args("t", "  ").unwrap();
        assert_eq!(v, serde_json::json!({}));
    }
}
