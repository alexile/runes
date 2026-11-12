use std::marker::PhantomData;

use rune_chain_core::ChainError;
use serde::de::DeserializeOwned;

use crate::{MAX_INPUT_BYTES, OutputParser};

/// How many characters of bad output an error message quotes.
const MAX_QUOTED_CHARS: usize = 200;

/// Parse LLM output as JSON into a deserializable type `T`.
///
/// Automatically strips Markdown code fences (` ```json ... ``` `) before
/// parsing, so the model can return either raw JSON or a fenced block.
///
/// # Example
///
/// ```rust
/// use serde::Deserialize;
/// use rune_chain_output_parser::{OutputParser, JsonOutputParser};
///
/// #[derive(Deserialize, PartialEq, Debug)]
/// struct City { name: String, population: u64 }
///
/// let p = JsonOutputParser::<City>::new();
///
/// // Plain JSON
/// let c = p.parse(r#"{"name":"Paris","population":2161000}"#).unwrap();
/// assert_eq!(c.name, "Paris");
///
/// // Fenced JSON (as models often return)
/// let c2 = p.parse("```json\n{\"name\":\"Berlin\",\"population\":3677000}\n```").unwrap();
/// assert_eq!(c2.name, "Berlin");
/// ```
pub struct JsonOutputParser<T> {
    _phantom: PhantomData<T>,
}

impl<T> JsonOutputParser<T> {
    /// Create a JSON output parser.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            _phantom: PhantomData,
        }
    }
}

impl<T> Default for JsonOutputParser<T> {
    fn default() -> Self {
        Self::new()
    }
}

fn strip_fences(text: &str) -> &str {
    let t = text.trim();
    // Try ```json ... ``` or ``` ... ```
    if let Some(inner) = t.strip_prefix("```json").or_else(|| t.strip_prefix("```"))
        && let Some(stripped) = inner
            .trim_start_matches('\n')
            .trim_end()
            .strip_suffix("```")
    {
        return stripped.trim();
    }
    t
}

impl<T: DeserializeOwned + Send + Sync> OutputParser<T> for JsonOutputParser<T> {
    fn parse(&self, text: &str) -> Result<T, ChainError> {
        if text.len() > MAX_INPUT_BYTES {
            return Err(ChainError::ParseError(format!(
                "JSON output is {} bytes, above the {MAX_INPUT_BYTES}-byte limit",
                text.len()
            )));
        }
        let cleaned = strip_fences(text);
        serde_json::from_str(cleaned).map_err(|e| {
            let quoted: String = cleaned.chars().take(MAX_QUOTED_CHARS).collect();
            ChainError::ParseError(format!("JSON parse error: {e} — input: {quoted}"))
        })
    }

    fn format_instructions(&self) -> Option<String> {
        Some(
            "Respond with a valid JSON object only, with no additional text or markdown fences."
                .to_string(),
        )
    }
}

#[cfg(test)]
mod tests {
    use serde::Deserialize;

    use super::*;

    #[derive(Debug, Deserialize, PartialEq)]
    struct Point {
        x: i32,
        y: i32,
    }

    #[test]
    fn parses_plain_json() {
        let p = JsonOutputParser::<Point>::new();
        let result = p.parse(r#"{"x":1,"y":2}"#).unwrap();
        assert_eq!(result, Point { x: 1, y: 2 });
    }

    #[test]
    fn strips_json_fence() {
        let p = JsonOutputParser::<Point>::new();
        let result = p.parse("```json\n{\"x\":3,\"y\":4}\n```").unwrap();
        assert_eq!(result, Point { x: 3, y: 4 });
    }

    #[test]
    fn strips_plain_fence() {
        let p = JsonOutputParser::<Point>::new();
        let result = p.parse("```\n{\"x\":5,\"y\":6}\n```").unwrap();
        assert_eq!(result, Point { x: 5, y: 6 });
    }

    #[test]
    fn errors_quote_a_bounded_prefix() {
        let p = JsonOutputParser::<Point>::new();
        let err = p.parse(&"x".repeat(10_000)).unwrap_err().to_string();
        assert!(err.len() < 400, "{err}");
        assert!(p.parse(&" ".repeat(MAX_INPUT_BYTES + 1)).is_err());
    }

    #[test]
    fn invalid_json_returns_error() {
        let p = JsonOutputParser::<Point>::new();
        assert!(p.parse("not json").is_err());
    }
}
