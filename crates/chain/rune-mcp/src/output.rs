//! Tool results: [`ToolOutput`], [`Content`] and [`ToolError`], and their
//! conversion to and from MCP `CallToolResult`.

use rmcp::model::{CallToolResult, ContentBlock};
use serde_json::Value;

use crate::Error;
use crate::sanitize::truncate_with_marker;

/// One block of a tool result.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum Content {
    /// Plain text.
    Text(String),
    /// Any other MCP content block (image, audio, resource, resource link),
    /// as its MCP JSON.
    Other(Value),
}

/// The result of a tool call: content blocks, optional structured content,
/// and whether the tool reports a failure.
///
/// ```
/// use rune_mcp::ToolOutput;
///
/// let ok = ToolOutput::text("68656c6c6f");
/// assert_eq!(ok.text_content(), "68656c6c6f");
/// assert!(!ok.is_error);
///
/// let structured = ToolOutput::structured(serde_json::json!({"sum": 3}));
/// assert_eq!(structured.structured.unwrap()["sum"], 3);
/// ```
#[derive(Debug, Clone, PartialEq, Default)]
#[non_exhaustive]
pub struct ToolOutput {
    /// Content blocks, in order.
    pub content: Vec<Content>,
    /// Structured result, matching the tool's output schema if it has one.
    pub structured: Option<Value>,
    /// The tool ran but failed; the content explains why.
    pub is_error: bool,
    /// The client cut the result to
    /// [`max_result_bytes`](crate::ClientOptions::max_result_bytes): text
    /// was truncated (with a marker), and blocks or structured content that
    /// did not fit were dropped.
    pub truncated: bool,
}

impl ToolOutput {
    /// A successful result with one text block.
    #[must_use]
    pub fn text(text: impl Into<String>) -> Self {
        Self {
            content: vec![Content::Text(text.into())],
            structured: None,
            is_error: false,
            truncated: false,
        }
    }

    /// A successful structured result. A text block with the compact JSON is
    /// added for clients that ignore structured content, as MCP recommends.
    #[must_use]
    pub fn structured(value: Value) -> Self {
        Self {
            content: vec![Content::Text(value.to_string())],
            structured: Some(value),
            is_error: false,
            truncated: false,
        }
    }

    /// A tool-level failure with one text block.
    #[must_use]
    pub fn error(message: impl Into<String>) -> Self {
        Self {
            content: vec![Content::Text(message.into())],
            structured: None,
            is_error: true,
            truncated: false,
        }
    }

    /// Cut the result to about `max_bytes`: text blocks are truncated with
    /// a marker, and other blocks and the structured content are dropped
    /// when they no longer fit (a text note says so). Sets
    /// [`truncated`](Self::truncated) when anything was cut.
    ///
    /// ```
    /// use rune_mcp::ToolOutput;
    ///
    /// let out = ToolOutput::text("x".repeat(100)).capped(10);
    /// assert!(out.truncated);
    /// assert!(out.text_content().starts_with("xxxxxxxxxx\n[truncated 90 bytes]"));
    /// ```
    #[must_use]
    pub fn capped(mut self, max_bytes: usize) -> Self {
        let mut budget = max_bytes;
        let mut content = Vec::with_capacity(self.content.len());
        for block in self.content {
            match block {
                Content::Text(mut text) => {
                    if truncate_with_marker(&mut text, budget) {
                        self.truncated = true;
                    }
                    budget = budget.saturating_sub(text.len());
                    content.push(Content::Text(text));
                }
                Content::Other(value) => {
                    let size = encoded_len(&value);
                    if size <= budget {
                        budget -= size;
                        content.push(Content::Other(value));
                    } else {
                        self.truncated = true;
                        content.push(Content::Text(format!(
                            "[content block of {size} bytes dropped: over the size limit]"
                        )));
                    }
                }
            }
        }
        self.content = content;
        if let Some(structured) = &self.structured
            && encoded_len(structured) > max_bytes
        {
            // Structured content usually repeats the text, so it gets the
            // whole limit, not what the text left over.
            self.structured = None;
            self.truncated = true;
        }
        self
    }

    /// The text blocks joined with newlines; other blocks are skipped.
    #[must_use]
    pub fn text_content(&self) -> String {
        let mut out = String::new();
        for block in &self.content {
            if let Content::Text(text) = block {
                if !out.is_empty() {
                    out.push('\n');
                }
                out.push_str(text);
            }
        }
        out
    }
}

/// A tool that ran and failed. Servers report it to the caller as a result
/// with `isError: true`, not as a protocol error, so the model can see the
/// message and recover.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct ToolError(pub String);

impl ToolError {
    /// A failure with this message.
    #[must_use]
    pub fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl From<String> for ToolError {
    fn from(message: String) -> Self {
        Self(message)
    }
}

impl From<&str> for ToolError {
    fn from(message: &str) -> Self {
        Self(message.to_owned())
    }
}

fn encoded_len(value: &Value) -> usize {
    serde_json::to_vec(value).map_or(usize::MAX, |bytes| bytes.len())
}

/// Convert one content block to the wire type; an `Other` block that is
/// not a valid MCP content block is sent as its JSON text.
pub fn to_content_block(block: Content) -> ContentBlock {
    match block {
        Content::Text(text) => ContentBlock::text(text),
        Content::Other(value) => serde_json::from_value::<ContentBlock>(value.clone())
            .unwrap_or_else(|_| ContentBlock::text(value.to_string())),
    }
}

/// Convert one wire content block.
pub fn from_content_block(block: &ContentBlock) -> Result<Content, Error> {
    if let Some(text) = block.as_text() {
        return Ok(Content::Text(text.text.clone()));
    }
    serde_json::to_value(block)
        .map(Content::Other)
        .map_err(|err| Error::Convert {
            what: "content block",
            reason: err.to_string(),
        })
}

pub fn to_call_tool_result(output: ToolOutput) -> CallToolResult {
    let content = output.content.into_iter().map(to_content_block).collect();
    let mut result = if output.is_error {
        CallToolResult::error(content)
    } else {
        CallToolResult::success(content)
    };
    result.structured_content = output.structured;
    result
}

pub fn from_call_tool_result(result: &CallToolResult) -> Result<ToolOutput, Error> {
    let content = result
        .content
        .iter()
        .map(from_content_block)
        .collect::<Result<_, _>>()?;
    Ok(ToolOutput {
        content,
        structured: result.structured_content.clone(),
        is_error: result.is_error.unwrap_or(false),
        truncated: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn capping_drops_what_does_not_fit() {
        let image = json!({"type": "image", "data": "A".repeat(100), "mimeType": "image/png"});
        let out = ToolOutput {
            content: vec![Content::Text("abc".into()), Content::Other(image)],
            structured: Some(json!({"big": "y".repeat(100)})),
            is_error: false,
            truncated: false,
        }
        .capped(50);
        assert!(out.truncated);
        assert!(out.structured.is_none());
        assert_eq!(out.content[0], Content::Text("abc".into()));
        assert!(matches!(&out.content[1], Content::Text(t) if t.contains("dropped")));

        let small = ToolOutput::structured(json!({"a": 1})).capped(1024);
        assert!(!small.truncated);
        assert_eq!(small, ToolOutput::structured(json!({"a": 1})));
    }

    #[test]
    fn wire_round_trip() {
        let out = ToolOutput::error("nope");
        let back = from_call_tool_result(&to_call_tool_result(out.clone())).unwrap();
        assert_eq!(back, out);
    }
}
