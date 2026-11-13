use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::{Map, Value};

use crate::ToolError;

/// Upper bound, in bytes, on [`ToolCall::arguments`] accepted by the bounded
/// parsing helpers ([`ToolCall::parse_arguments`], [`ToolCall::arguments_object`],
/// [`ToolCall::validate`]).
///
/// Tool-call arguments are produced by the model and therefore untrusted; the
/// limit stops a runaway or adversarial generation from forcing a huge
/// allocation while parsing. Use [`ToolCall::parse_arguments_with_limit`] for
/// a different bound.
pub const MAX_TOOL_ARGUMENTS_BYTES: usize = 1024 * 1024;

/// Longest tool name accepted by [`FunctionDefinition::has_valid_name`]
/// (the strictest limit among the major providers).
pub const MAX_TOOL_NAME_LEN: usize = 64;

/// A single tool/function call requested by the model in a generation response.
///
/// When an LLM decides to call a tool, it emits one or more `ToolCall` values
/// in [`GenerateResult::tool_calls`](crate::GenerateResult::tool_calls). The
/// caller is responsible for executing each tool and feeding the results back
/// as [`Role::Tool`](crate::Role::Tool) messages.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolCall {
    /// Provider-issued ID correlating this call with its result message.
    pub id: String,
    /// Name of the function/tool to invoke (matches [`Tool::name`](crate::Tool::name)).
    pub name: String,
    /// JSON-encoded argument object the model wants passed to the tool.
    pub arguments: String,
}

impl ToolCall {
    /// Create a new `ToolCall`.
    pub fn new(
        id: impl Into<String>,
        name: impl Into<String>,
        arguments: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            arguments: arguments.into(),
        }
    }

    /// Parse [`arguments`](Self::arguments) as a JSON object and return the value of `key`.
    ///
    /// Returns `None` if the JSON is invalid, larger than
    /// [`MAX_TOOL_ARGUMENTS_BYTES`], or the key is absent.
    #[must_use]
    pub fn arg(&self, key: &str) -> Option<serde_json::Value> {
        self.parse_arguments::<serde_json::Value>()
            .ok()
            .and_then(|v| v.get(key).cloned())
    }

    /// Parse [`arguments`](Self::arguments) as a JSON object and extract the
    /// `"input"` key as a string — the standard single-arg tool convention.
    #[must_use]
    pub fn input(&self) -> Option<String> {
        self.arg("input").map(|v| match v {
            serde_json::Value::String(s) => s,
            other => other.to_string(),
        })
    }

    /// Deserialise [`arguments`](Self::arguments) into `T`, refusing inputs
    /// larger than [`MAX_TOOL_ARGUMENTS_BYTES`].
    ///
    /// Empty (or all-whitespace) arguments are treated as `{}`, since several
    /// providers send `""` for tools without parameters. Error messages never
    /// echo the arguments themselves, so they are safe to log or feed back to
    /// the model.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_chain_core::ToolCall;
    /// use serde::Deserialize;
    ///
    /// #[derive(Deserialize)]
    /// struct Weather { city: String }
    ///
    /// let call = ToolCall::new("call_1", "get_weather", r#"{"city":"Oslo"}"#);
    /// let args: Weather = call.parse_arguments().unwrap();
    /// assert_eq!(args.city, "Oslo");
    ///
    /// let bad = ToolCall::new("call_2", "get_weather", "{not json");
    /// assert!(bad.parse_arguments::<Weather>().is_err());
    /// ```
    pub fn parse_arguments<T: DeserializeOwned>(&self) -> Result<T, ToolError> {
        self.parse_arguments_with_limit(MAX_TOOL_ARGUMENTS_BYTES)
    }

    /// Like [`parse_arguments`](Self::parse_arguments) with an explicit size
    /// limit in bytes.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_chain_core::{ToolCall, ToolError};
    ///
    /// let call = ToolCall::new("c", "echo", r#"{"input":"a long string"}"#);
    /// let err = call.parse_arguments_with_limit::<serde_json::Value>(8).unwrap_err();
    /// assert!(matches!(err, ToolError::InvalidInput(_)));
    /// ```
    pub fn parse_arguments_with_limit<T: DeserializeOwned>(
        &self,
        max_bytes: usize,
    ) -> Result<T, ToolError> {
        let len = self.arguments.len();
        if len > max_bytes {
            return Err(ToolError::InvalidInput(format!(
                "arguments for tool `{}` are {len} bytes, above the {max_bytes}-byte limit",
                self.name
            )));
        }
        let raw = self.arguments.trim();
        let raw = if raw.is_empty() { "{}" } else { raw };
        serde_json::from_str(raw).map_err(|e| {
            ToolError::InvalidInput(format!(
                "arguments for tool `{}` are not valid: {e}",
                self.name
            ))
        })
    }

    /// Parse [`arguments`](Self::arguments) as a JSON object (bounded by
    /// [`MAX_TOOL_ARGUMENTS_BYTES`]), rejecting arrays, strings and other
    /// non-object values.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_chain_core::ToolCall;
    ///
    /// let call = ToolCall::new("c", "add", r#"{"a":1,"b":2}"#);
    /// let obj = call.arguments_object().unwrap();
    /// assert_eq!(obj["a"], 1);
    ///
    /// assert!(ToolCall::new("c", "add", "[1,2]").arguments_object().is_err());
    /// ```
    pub fn arguments_object(&self) -> Result<Map<String, Value>, ToolError> {
        match self.parse_arguments::<Value>()? {
            Value::Object(map) => Ok(map),
            other => Err(ToolError::InvalidInput(format!(
                "arguments for tool `{}` must be a JSON object, got {}",
                self.name,
                json_type_name(&other)
            ))),
        }
    }

    /// Check this call against the tool's [`FunctionDefinition`] before
    /// executing it, and return the parsed argument object.
    ///
    /// This is a deliberately small, dependency-free subset of JSON Schema,
    /// covering what models most often get wrong:
    ///
    /// - the call names this tool;
    /// - the arguments are a JSON object within [`MAX_TOOL_ARGUMENTS_BYTES`];
    /// - every `required` property is present;
    /// - each top-level property matches its declared `type` (a string or a
    ///   list of strings) and, when given, its `enum`;
    /// - no unknown properties when `"additionalProperties": false`.
    ///
    /// Nested schemas are not descended into; use a full JSON Schema validator
    /// for those. Failures are [`ToolError::InvalidInput`] with a message
    /// suitable to feed back to the model so it can correct itself.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_chain_core::{FunctionDefinition, ToolCall};
    /// use serde_json::json;
    ///
    /// let def = FunctionDefinition::new(
    ///     "get_weather",
    ///     "Return the weather for a city.",
    ///     json!({
    ///         "type": "object",
    ///         "properties": { "city": { "type": "string" } },
    ///         "required": ["city"],
    ///         "additionalProperties": false
    ///     }),
    /// );
    ///
    /// let ok = ToolCall::new("1", "get_weather", r#"{"city":"Oslo"}"#);
    /// assert_eq!(ok.validate(&def).unwrap()["city"], "Oslo");
    ///
    /// let missing = ToolCall::new("2", "get_weather", "{}");
    /// assert!(missing.validate(&def).is_err());
    ///
    /// let wrong_type = ToolCall::new("3", "get_weather", r#"{"city":42}"#);
    /// assert!(wrong_type.validate(&def).is_err());
    /// ```
    pub fn validate(
        &self,
        definition: &FunctionDefinition,
    ) -> Result<Map<String, Value>, ToolError> {
        if self.name != definition.name {
            return Err(ToolError::InvalidInput(format!(
                "tool call names `{}` but was checked against `{}`",
                self.name, definition.name
            )));
        }
        let args = self.arguments_object()?;
        let schema = &definition.parameters;
        let properties = schema.get("properties").and_then(Value::as_object);

        if let Some(required) = schema.get("required").and_then(Value::as_array) {
            for key in required.iter().filter_map(Value::as_str) {
                if !args.contains_key(key) {
                    return Err(ToolError::InvalidInput(format!(
                        "tool `{}` is missing required argument `{key}`",
                        self.name
                    )));
                }
            }
        }

        let closed = schema.get("additionalProperties") == Some(&Value::Bool(false));
        for (key, value) in &args {
            let Some(prop) = properties.and_then(|p| p.get(key)) else {
                if closed {
                    return Err(ToolError::InvalidInput(format!(
                        "tool `{}` does not accept argument `{key}`",
                        self.name
                    )));
                }
                continue;
            };
            if !matches_declared_type(prop.get("type"), value) {
                return Err(ToolError::InvalidInput(format!(
                    "argument `{key}` of tool `{}` must be of type {}, got {}",
                    self.name,
                    prop.get("type").map_or_else(String::new, Value::to_string),
                    json_type_name(value)
                )));
            }
            if let Some(allowed) = prop.get("enum").and_then(Value::as_array)
                && !allowed.contains(value)
            {
                return Err(ToolError::InvalidInput(format!(
                    "argument `{key}` of tool `{}` must be one of {}",
                    self.name,
                    Value::Array(allowed.clone())
                )));
            }
        }
        Ok(args)
    }
}

/// JSON Schema type name of `value`.
const fn json_type_name(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

/// Whether `value` satisfies a JSON Schema `type` keyword (string or list).
/// Missing or unrecognised type names accept any value.
fn matches_declared_type(declared: Option<&Value>, value: &Value) -> bool {
    let one = |t: &str| match t {
        "string" => value.is_string(),
        // JSON Schema counts any number with a zero fractional part (`2.0`)
        // as an integer.
        "integer" => {
            value.is_i64()
                || value.is_u64()
                || value
                    .as_f64()
                    .is_some_and(|f| f.is_finite() && f.fract() == 0.0)
        }
        "number" => value.is_number(),
        "boolean" => value.is_boolean(),
        "object" => value.is_object(),
        "array" => value.is_array(),
        "null" => value.is_null(),
        _ => true,
    };
    match declared {
        Some(Value::String(t)) => one(t),
        Some(Value::Array(ts)) => ts.iter().filter_map(Value::as_str).any(one),
        _ => true,
    }
}

/// JSON-Schema-based description of a tool the LLM may call.
///
/// Pass a slice of `FunctionDefinition`s to
/// [`Llm::generate_with_tools`](crate::Llm::generate_with_tools) to enable
/// native function calling instead of text-based `ReAct` parsing.
///
/// # Example
///
/// ```rust
/// use rune_chain_core::FunctionDefinition;
/// use serde_json::json;
///
/// let def = FunctionDefinition::new(
///     "get_weather",
///     "Return the current weather for a city.",
///     json!({
///         "type": "object",
///         "properties": {
///             "city": { "type": "string", "description": "City name" }
///         },
///         "required": ["city"]
///     }),
/// );
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionDefinition {
    /// Unique tool name (no spaces; matches [`Tool::name`](crate::Tool::name)).
    pub name: String,
    /// One-sentence description the LLM uses to decide when to call this tool.
    pub description: String,
    /// JSON Schema object describing the tool's parameter object.
    pub parameters: serde_json::Value,
}

impl FunctionDefinition {
    /// Create a new function definition.
    pub fn new(
        name: impl Into<String>,
        description: impl Into<String>,
        parameters: serde_json::Value,
    ) -> Self {
        Self {
            name: name.into(),
            description: description.into(),
            parameters,
        }
    }

    /// Build a definition with the standard single-string `"input"` parameter.
    ///
    /// Use this as a quick wrapper for tools that accept a plain string.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_chain_core::FunctionDefinition;
    ///
    /// let def = FunctionDefinition::single_input(
    ///     "upper_case",
    ///     "Convert a string to upper case.",
    /// );
    /// ```
    pub fn single_input(name: impl Into<String>, description: impl Into<String>) -> Self {
        Self::new(
            name,
            description,
            serde_json::json!({
                "type": "object",
                "properties": {
                    "input": {
                        "type": "string",
                        "description": "The input string"
                    }
                },
                "required": ["input"]
            }),
        )
    }

    /// Whether [`name`](Self::name) is accepted by every major provider:
    /// 1–[`MAX_TOOL_NAME_LEN`] characters from `[A-Za-z0-9_-]`.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_chain_core::FunctionDefinition;
    ///
    /// assert!(FunctionDefinition::single_input("web_search", "Search.").has_valid_name());
    /// assert!(!FunctionDefinition::single_input("web search", "Search.").has_valid_name());
    /// ```
    #[must_use]
    pub fn has_valid_name(&self) -> bool {
        !self.name.is_empty()
            && self.name.len() <= MAX_TOOL_NAME_LEN
            && self
                .name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    }
}

/// How the model should choose whether to call a tool.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ToolChoice {
    /// The model decides (default).
    Auto,
    /// The model must not call any tool.
    None,
    /// The model must call at least one tool.
    Required,
    /// The model must call the named tool specifically.
    Tool(String),
}
