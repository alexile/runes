//! Turning input bytes into a JSON value, and small JSON helpers.

use std::fmt::Write as _;

use serde_json::Value;

use crate::OpenApiError;

/// Parses JSON (input starting with `{` or `[`) or YAML into a JSON value.
pub fn parse_document(input: &[u8], max_bytes: usize) -> Result<Value, OpenApiError> {
    if input.len() > max_bytes {
        return Err(OpenApiError::TooLarge(format!(
            "input is {} bytes, more than the limit of {max_bytes}",
            input.len()
        )));
    }
    let input = input.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(input);
    let trimmed = input.trim_ascii();
    if trimmed
        .first()
        .is_some_and(|byte| matches!(byte, b'{' | b'['))
    {
        return serde_json::from_slice(trimmed)
            .map_err(|error| OpenApiError::Parse(error.to_string()));
    }
    parse_yaml(trimmed)
}

#[cfg(feature = "yaml")]
fn parse_yaml(input: &[u8]) -> Result<Value, OpenApiError> {
    let text =
        std::str::from_utf8(input).map_err(|error| OpenApiError::Parse(error.to_string()))?;
    crate::yaml::to_json(text)
}

#[cfg(not(feature = "yaml"))]
const fn parse_yaml(_input: &[u8]) -> Result<Value, OpenApiError> {
    Err(OpenApiError::YamlDisabled)
}

/// Text form of a scalar JSON value as it appears in a URL or header.
pub fn scalar_text(value: &Value) -> String {
    match value {
        Value::String(text) => text.clone(),
        Value::Null => String::new(),
        other => other.to_string(),
    }
}

/// Escapes a JSON pointer reference token (`~` to `~0`, `/` to `~1`).
pub fn escape_pointer(token: &str) -> String {
    token.replace('~', "~0").replace('/', "~1")
}

/// Percent-decodes text; invalid escapes are kept verbatim.
pub fn percent_decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while let Some(&byte) = bytes.get(index) {
        if byte == b'%'
            && let Some(hex) = bytes.get(index + 1..index + 3)
            && let Ok(hex) = std::str::from_utf8(hex)
            && let Ok(decoded) = u8::from_str_radix(hex, 16)
        {
            out.push(decoded);
            index += 3;
            continue;
        }
        out.push(byte);
        index += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Percent-encodes a URL path segment value (RFC 3986 unreserved kept).
pub fn encode_segment(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~' | b':' | b'@') {
            out.push(char::from(byte));
        } else {
            let _ = write!(out, "%{byte:02X}");
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_input_with_bom_and_whitespace() {
        let value = parse_document(b"\xEF\xBB\xBF  {\"a\": 1}\n", 1024).unwrap();
        assert_eq!(value["a"], 1);
    }

    #[test]
    fn size_limit() {
        let error = parse_document(b"{\"a\": 1}", 3).unwrap_err();
        assert_eq!(error.code(), "too_large");
    }

    #[test]
    fn bad_json_is_parse_error() {
        assert_eq!(parse_document(b"{", 64).unwrap_err().code(), "parse_error");
    }

    #[cfg(feature = "yaml")]
    #[test]
    fn yaml_input() {
        let value =
            parse_document(b"openapi: 3.0.0\nn: 1.5\n200: ok\nlist: [1, true]\n", 1024).unwrap();
        assert_eq!(value["openapi"], "3.0.0");
        assert_eq!(value["n"], 1.5);
        assert_eq!(value["200"], "ok");
        assert_eq!(value["list"], serde_json::json!([1, true]));
    }

    #[cfg(feature = "yaml")]
    #[test]
    fn yaml_deep_flow_rejected() {
        let text = format!("a: {}{}", "[".repeat(200), "]".repeat(200));
        assert_eq!(
            parse_document(text.as_bytes(), 1 << 20).unwrap_err().code(),
            "too_large"
        );
    }

    #[cfg(not(feature = "yaml"))]
    #[test]
    fn yaml_disabled() {
        assert_eq!(
            parse_document(b"openapi: 3.0.0", 64).unwrap_err(),
            OpenApiError::YamlDisabled
        );
    }

    #[test]
    fn helpers() {
        assert_eq!(scalar_text(&Value::Null), "");
        assert_eq!(scalar_text(&serde_json::json!(1)), "1");
        assert_eq!(escape_pointer("a/b~c"), "a~1b~0c");
        assert_eq!(percent_decode("a%2Fb%zz"), "a/b%zz");
        assert_eq!(encode_segment("a b/ü"), "a%20b%2F%C3%BC");
    }
}
