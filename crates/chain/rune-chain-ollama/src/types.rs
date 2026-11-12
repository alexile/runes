//! Ollama wire types (`/api/chat`, `/api/embed`, `/api/tags`, `/api/show`,
//! `/api/pull`). Internal: the public API speaks `rune-chain-core` types.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

#[derive(Debug, Serialize)]
pub struct ChatRequest {
    pub model: String,
    pub messages: Vec<ApiMessage>,
    pub stream: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub tools: Vec<ApiToolDef>,
    /// `"json"` or a JSON Schema object.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub format: Option<Value>,
    #[serde(skip_serializing_if = "Map::is_empty")]
    pub options: Map<String, Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub keep_alive: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub think: Option<Value>,
}

#[derive(Debug, Serialize)]
pub struct ApiMessage {
    pub role: &'static str,
    pub content: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub images: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub tool_calls: Vec<ApiToolCallOut>,
    /// Name of the tool whose result this `tool` message carries.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_name: Option<String>,
    /// An earlier assistant turn's reasoning (thinking models).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thinking: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ApiToolCallOut {
    pub function: ApiFunctionOut,
}

#[derive(Debug, Serialize)]
pub struct ApiFunctionOut {
    pub name: String,
    /// Ollama takes the arguments as a JSON object, not a string.
    pub arguments: Value,
}

#[derive(Debug, Serialize)]
pub struct ApiToolDef {
    #[serde(rename = "type")]
    pub kind: &'static str,
    pub function: ApiFunctionDef,
}

#[derive(Debug, Serialize)]
pub struct ApiFunctionDef {
    pub name: String,
    pub description: String,
    pub parameters: Value,
}

#[derive(Debug, Default, Deserialize)]
pub struct ApiResponseMessage {
    #[serde(default)]
    pub content: String,
    #[serde(default)]
    pub thinking: Option<String>,
    #[serde(default)]
    pub tool_calls: Vec<ApiToolCallIn>,
}

#[derive(Debug, Deserialize)]
pub struct ApiToolCallIn {
    #[serde(default)]
    pub id: Option<String>,
    pub function: ApiFunctionIn,
}

#[derive(Debug, Deserialize)]
pub struct ApiFunctionIn {
    pub name: String,
    /// Usually an object; tolerate a pre-encoded string or a missing value.
    #[serde(default)]
    pub arguments: Value,
}

/// A non-streaming `/api/chat` response.
#[derive(Debug, Deserialize)]
pub struct ChatResponse {
    pub message: ApiResponseMessage,
    #[serde(default)]
    pub done_reason: Option<String>,
    pub prompt_eval_count: Option<u32>,
    pub eval_count: Option<u32>,
}

/// One line of a streaming `/api/chat` response.
#[derive(Debug, Deserialize)]
pub struct ChatChunk {
    #[serde(default)]
    pub message: Option<ApiResponseMessage>,
    pub done: bool,
    #[serde(default)]
    pub done_reason: Option<String>,
    pub prompt_eval_count: Option<u32>,
    pub eval_count: Option<u32>,
}

#[derive(Debug, Serialize)]
pub struct EmbedRequest<'a> {
    pub model: &'a str,
    pub input: &'a [&'a str],
    #[serde(skip_serializing_if = "Option::is_none")]
    pub truncate: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dimensions: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub keep_alive: Option<Value>,
    #[serde(skip_serializing_if = "Map::is_empty")]
    pub options: Map<String, Value>,
}

#[derive(Debug, Deserialize)]
pub struct EmbedResponse {
    pub embeddings: Vec<Vec<f32>>,
    #[serde(default)]
    pub prompt_eval_count: Option<u32>,
}

#[derive(Debug, Serialize)]
pub struct ModelRequest<'a> {
    pub model: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stream: Option<bool>,
}

/// The message of an `{"error": "..."}` object, if `v` is one.
pub fn error_message(v: &Value) -> Option<String> {
    v.get("error").and_then(Value::as_str).map(str::to_string)
}
