use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{LlmError, Message, Role};

/// Upper bound, in bytes, on model output accepted by
/// [`ResponseFormat::parse_json`] (4 MiB).
pub const MAX_JSON_OUTPUT_BYTES: usize = 4 * 1024 * 1024;

/// The shape a model's response must take: free text, any JSON object, or a
/// JSON document matching a schema ("structured output").
///
/// Pass it to [`Llm::generate_structured`](crate::Llm::generate_structured).
/// Providers with native support (`OpenAI` `response_format`, Ollama
/// `format`, Anthropic tool-forced output, …) map it onto their API; the
/// default implementation falls back to prompting for JSON.
///
/// # Example
///
/// ```rust
/// use rune_chain_core::ResponseFormat;
/// use serde_json::json;
///
/// let format = ResponseFormat::json_schema(
///     "weather",
///     json!({
///         "type": "object",
///         "properties": { "temp_c": { "type": "number" } },
///         "required": ["temp_c"]
///     }),
/// );
/// assert!(format.is_json());
///
/// let value = format.parse_json("```json\n{\"temp_c\": 21.5}\n```").unwrap();
/// assert_eq!(value["temp_c"], 21.5);
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "type")]
#[non_exhaustive]
pub enum ResponseFormat {
    /// Unconstrained text (the default).
    #[default]
    Text,
    /// Any syntactically valid JSON object.
    JsonObject,
    /// A JSON document matching `schema`.
    JsonSchema {
        /// Short identifier for the schema (`[A-Za-z0-9_-]`, ≤ 64 chars for
        /// `OpenAI`).
        name: String,
        /// The JSON Schema the response must match.
        schema: Value,
        /// Ask the provider to enforce the schema strictly, where supported.
        #[serde(default)]
        strict: bool,
    },
}

impl ResponseFormat {
    /// A strict [`JsonSchema`](Self::JsonSchema) format.
    pub fn json_schema(name: impl Into<String>, schema: Value) -> Self {
        Self::JsonSchema {
            name: name.into(),
            schema,
            strict: true,
        }
    }

    /// Return `true` for the JSON formats.
    #[must_use]
    pub const fn is_json(&self) -> bool {
        !matches!(self, Self::Text)
    }

    /// The schema, for [`JsonSchema`](Self::JsonSchema).
    #[must_use]
    pub const fn schema(&self) -> Option<&Value> {
        match self {
            Self::JsonSchema { schema, .. } => Some(schema),
            _ => None,
        }
    }

    /// Prompt text asking the model to answer in this format, for providers
    /// without native structured output. `None` for [`Text`](Self::Text).
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_chain_core::ResponseFormat;
    ///
    /// assert!(ResponseFormat::Text.instructions().is_none());
    /// assert!(ResponseFormat::JsonObject.instructions().unwrap().contains("JSON"));
    /// ```
    #[must_use]
    pub fn instructions(&self) -> Option<String> {
        match self {
            Self::Text => None,
            Self::JsonObject => Some(
                "Respond with a single valid JSON object and nothing else: \
                 no prose, no code fences."
                    .to_string(),
            ),
            Self::JsonSchema { schema, .. } => Some(format!(
                "Respond with a single valid JSON value that conforms to this JSON Schema, \
                 and nothing else: no prose, no code fences.\nSchema: {schema}"
            )),
        }
    }

    /// Return `messages` with [`instructions`](Self::instructions) added as a
    /// system message after any leading system messages. Unchanged for
    /// [`Text`](Self::Text).
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_chain_core::{Message, ResponseFormat, Role};
    ///
    /// let msgs = [Message::system("Be terse."), Message::human("Weather in Oslo?")];
    /// let out = ResponseFormat::JsonObject.apply_to(&msgs);
    /// assert_eq!(out.len(), 3);
    /// assert_eq!(out[1].role, Role::System);
    /// assert_eq!(out[2], msgs[1]);
    /// ```
    #[must_use]
    pub fn apply_to(&self, messages: &[Message]) -> Vec<Message> {
        let mut out = messages.to_vec();
        if let Some(instructions) = self.instructions() {
            let at = messages
                .iter()
                .take_while(|m| m.role == Role::System)
                .count();
            out.insert(at, Message::system(instructions));
        }
        out
    }

    /// Parse a model response as JSON, tolerating surrounding whitespace and
    /// a Markdown code fence (```` ```json … ``` ````).
    ///
    /// Outputs above [`MAX_JSON_OUTPUT_BYTES`] are rejected before parsing.
    /// [`JsonObject`](Self::JsonObject) additionally requires an object. The
    /// value is not validated against a [`JsonSchema`](Self::JsonSchema)'s
    /// schema; use a JSON Schema validator for that.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_chain_core::ResponseFormat;
    ///
    /// assert!(ResponseFormat::JsonObject.parse_json("{\"a\": 1}").is_ok());
    /// assert!(ResponseFormat::JsonObject.parse_json("[1, 2]").is_err());
    /// assert!(ResponseFormat::JsonObject.parse_json("Sure! {\"a\": 1}").is_err());
    /// ```
    pub fn parse_json(&self, output: &str) -> Result<Value, LlmError> {
        if output.len() > MAX_JSON_OUTPUT_BYTES {
            return Err(LlmError::invalid_response(format!(
                "structured output is {} bytes, above the {MAX_JSON_OUTPUT_BYTES}-byte limit",
                output.len()
            )));
        }
        let value: Value = serde_json::from_str(strip_code_fence(output)).map_err(|e| {
            LlmError::invalid_response(format!("structured output is not valid JSON: {e}"))
        })?;
        if matches!(self, Self::JsonObject) && !value.is_object() {
            return Err(LlmError::invalid_response(
                "structured output must be a JSON object",
            ));
        }
        Ok(value)
    }
}

/// Strip whitespace and one surrounding Markdown code fence, if present.
fn strip_code_fence(output: &str) -> &str {
    let trimmed = output.trim();
    let Some(inner) = trimmed
        .strip_prefix("```")
        .and_then(|s| s.strip_suffix("```"))
    else {
        return trimmed;
    };
    // Drop an info string such as `json` on the opening fence line.
    inner
        .split_once('\n')
        .map_or(inner, |(info, body)| {
            if info.trim().chars().all(|c| c.is_ascii_alphanumeric()) {
                body
            } else {
                inner
            }
        })
        .trim()
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn serde_shape_is_tagged() {
        let f = ResponseFormat::json_schema("w", json!({"type": "object"}));
        let v = serde_json::to_value(&f).unwrap();
        assert_eq!(
            v,
            json!({"type": "json_schema", "name": "w", "schema": {"type": "object"}, "strict": true})
        );
        assert_eq!(serde_json::from_value::<ResponseFormat>(v).unwrap(), f);
        assert_eq!(
            serde_json::to_value(ResponseFormat::default()).unwrap(),
            json!({"type": "text"})
        );
    }

    #[test]
    fn fence_stripping() {
        assert_eq!(strip_code_fence("  {\"a\":1} "), "{\"a\":1}");
        assert_eq!(strip_code_fence("```json\n{\"a\":1}\n```"), "{\"a\":1}");
        assert_eq!(strip_code_fence("```\n[1]\n```"), "[1]");
        assert_eq!(strip_code_fence("```{\"a\":1}```"), "{\"a\":1}");
    }

    #[test]
    fn text_format_leaves_messages_alone() {
        let msgs = [Message::human("hi")];
        assert_eq!(ResponseFormat::Text.apply_to(&msgs), msgs.to_vec());
    }

    #[test]
    fn oversized_output_is_rejected_without_parsing() {
        let big = "1".repeat(MAX_JSON_OUTPUT_BYTES + 1);
        assert!(
            ResponseFormat::JsonSchema {
                name: "n".into(),
                schema: json!({}),
                strict: false
            }
            .parse_json(&big)
            .is_err()
        );
    }
}
