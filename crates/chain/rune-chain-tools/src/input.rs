//! Input handling shared by every tool: argument unwrapping and size caps.
//!
//! Agents call a tool either with free text (`ReAct`) or with the JSON
//! arguments object of a native function call, `{"input": "..."}`. Every tool
//! accepts both: [`tool_input`] unwraps the object form, so `hex_encode`
//! encodes `hello` rather than the JSON text around it.

use std::borrow::Cow;

use rune_chain_core::ToolError;

/// Largest input any tool in this crate accepts (1 MiB).
pub const MAX_INPUT_BYTES: usize = 1024 * 1024;

/// Largest input for [`CaesarBrute`](crate::CaesarBrute) (16 KiB): its output
/// is 26 times its input.
pub const MAX_CAESAR_INPUT_BYTES: usize = 16 * 1024;

/// Largest hex input for [`XorBrute`](crate::XorBrute) (64 KiB): it decrypts
/// the input under all 256 keys.
pub const MAX_XOR_INPUT_BYTES: usize = 64 * 1024;

/// Extract a tool's text input from `raw`, enforcing `max_bytes`.
///
/// A JSON object (after leading whitespace) must be the function-calling
/// form `{"input": "<text>"}` with no other keys; anything else in object
/// form is rejected. Any other `raw` is used verbatim.
///
/// # Errors
///
/// [`ToolError::InvalidInput`] when `raw` (or the unwrapped text) is above
/// `max_bytes`, or when it is a JSON object of the wrong shape.
///
/// ```rust
/// use rune_chain_tools::input::{MAX_INPUT_BYTES, tool_input};
///
/// assert_eq!(tool_input(r#"{"input":"hi"}"#, MAX_INPUT_BYTES).unwrap(), "hi");
/// assert_eq!(tool_input("hi", MAX_INPUT_BYTES).unwrap(), "hi");
/// assert!(tool_input(r#"{"path":"/etc"}"#, MAX_INPUT_BYTES).is_err());
/// assert!(tool_input("hello", 3).is_err());
/// ```
pub fn tool_input(raw: &str, max_bytes: usize) -> Result<Cow<'_, str>, ToolError> {
    let too_big = |len: usize| {
        ToolError::InvalidInput(format!(
            "input is {len} bytes, above this tool's {max_bytes}-byte limit"
        ))
    };
    if !raw.trim_start().starts_with('{') {
        return if raw.len() > max_bytes {
            Err(too_big(raw.len()))
        } else {
            Ok(Cow::Borrowed(raw))
        };
    }
    // Arguments JSON may carry a little overhead (quotes, escapes) on top of
    // the text itself, but never more than the core-wide argument cap.
    if raw.len() > rune_chain_core::MAX_TOOL_ARGUMENTS_BYTES.max(max_bytes) {
        return Err(too_big(raw.len()));
    }
    let shape_err = || {
        ToolError::InvalidInput(r#"expected arguments of the form {"input": "<text>"}"#.to_owned())
    };
    let serde_json::Value::Object(mut map) =
        serde_json::from_str::<serde_json::Value>(raw).map_err(|_| shape_err())?
    else {
        return Err(shape_err());
    };
    match (map.remove("input"), map.is_empty()) {
        (Some(serde_json::Value::String(text)), true) if text.len() <= max_bytes => {
            Ok(Cow::Owned(text))
        }
        (Some(serde_json::Value::String(text)), true) => Err(too_big(text.len())),
        _ => Err(shape_err()),
    }
}

/// The JSON Schema every tool in this crate exposes: one required `input`
/// string, nothing else.
#[must_use]
pub fn input_schema(description: &str, max_bytes: usize) -> serde_json::Value {
    serde_json::json!({
        "type": "object",
        "properties": {
            "input": {
                "type": "string",
                "description": description,
                "maxLength": max_bytes
            }
        },
        "required": ["input"],
        "additionalProperties": false
    })
}
