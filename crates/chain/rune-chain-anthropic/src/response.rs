//! Provider-level view of a Messages API response.

use rune_chain_core::{FinishReason, GenerateResult, ReasoningBlock, TokenUsage, ToolCall};
use serde_json::Value;

use crate::types::{MessagesResponse, ResponseContentBlock, UsageReport};

/// Token usage as reported by the Messages API, including prompt-cache
/// accounting.
///
/// The API reports uncached input (`input_tokens`), input written to the
/// cache and input read from it separately; the three add up to the whole
/// prompt ([`total_input_tokens`](Self::total_input_tokens)). The portable
/// [`TokenUsage`] this crate returns through [`Llm`](rune_chain_core::Llm)
/// uses that total as `prompt_tokens`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct Usage {
    /// Input tokens neither read from nor written to the cache.
    pub input_tokens: u32,
    /// Output tokens, thinking included.
    pub output_tokens: u32,
    /// Input tokens written to the prompt cache by this request.
    pub cache_creation_input_tokens: u32,
    /// Input tokens read from the prompt cache.
    pub cache_read_input_tokens: u32,
}

impl Usage {
    /// Build a usage record.
    #[must_use]
    pub const fn new(
        input_tokens: u32,
        output_tokens: u32,
        cache_creation_input_tokens: u32,
        cache_read_input_tokens: u32,
    ) -> Self {
        Self {
            input_tokens,
            output_tokens,
            cache_creation_input_tokens,
            cache_read_input_tokens,
        }
    }

    /// Whole prompt size: uncached + cache-write + cache-read input tokens
    /// (saturating).
    #[must_use]
    pub const fn total_input_tokens(&self) -> u32 {
        self.input_tokens
            .saturating_add(self.cache_creation_input_tokens)
            .saturating_add(self.cache_read_input_tokens)
    }

    /// The portable [`TokenUsage`]: `prompt_tokens` is
    /// [`total_input_tokens`](Self::total_input_tokens), with the cache
    /// reads and writes broken out.
    #[must_use]
    pub const fn to_token_usage(&self) -> TokenUsage {
        TokenUsage::new(self.total_input_tokens(), self.output_tokens)
            .with_cache_read_tokens(self.cache_read_input_tokens)
            .with_cache_creation_tokens(self.cache_creation_input_tokens)
    }

    /// Overwrite the fields a (possibly partial) wire report carries.
    pub(crate) const fn merge(&mut self, report: &UsageReport) {
        if let Some(n) = report.input_tokens {
            self.input_tokens = n;
        }
        if let Some(n) = report.output_tokens {
            self.output_tokens = n;
        }
        if let Some(n) = report.cache_creation_input_tokens {
            self.cache_creation_input_tokens = n;
        }
        if let Some(n) = report.cache_read_input_tokens {
            self.cache_read_input_tokens = n;
        }
    }
}

/// One content block of a response.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum ContentBlock {
    /// Visible text.
    Text {
        /// The text.
        text: String,
    },
    /// A thinking block. `thinking` is a summary or empty depending on the
    /// display setting; `signature` lets the API verify the block when it is
    /// sent back.
    Thinking {
        /// Thinking text (may be empty).
        thinking: String,
        /// Opaque verification signature.
        signature: String,
    },
    /// A redacted thinking block (opaque, encrypted).
    RedactedThinking {
        /// Opaque payload.
        data: String,
    },
    /// A tool call.
    ToolUse {
        /// Call id, referenced by the tool result.
        id: String,
        /// Tool name.
        name: String,
        /// Tool input (a JSON object).
        input: Value,
    },
}

/// A complete Messages API response with everything the portable
/// [`GenerateResult`] cannot carry: thinking blocks, stop reason and
/// cache-token usage.
///
/// Returned by [`Anthropic::generate_message`](crate::Anthropic::generate_message)
/// and at the end of [`Anthropic::stream_message`](crate::Anthropic::stream_message).
#[derive(Debug, Clone, Default, PartialEq)]
#[non_exhaustive]
pub struct MessageResponse {
    /// Message id (`msg_…`).
    pub id: String,
    /// Model that produced the message.
    pub model: String,
    /// Content blocks in order.
    pub content: Vec<ContentBlock>,
    /// Why generation stopped (`end_turn`, `max_tokens`, `tool_use`,
    /// `refusal`, …), if reported.
    pub stop_reason: Option<String>,
    /// Token usage.
    pub usage: Usage,
}

impl MessageResponse {
    /// Token usage including cache reads and writes.
    #[must_use]
    pub const fn usage(&self) -> &Usage {
        &self.usage
    }

    /// The visible text: every text block, joined with a newline. Thinking
    /// is never included.
    #[must_use]
    pub fn text(&self) -> String {
        let mut out = String::new();
        for block in &self.content {
            if let ContentBlock::Text { text } = block {
                if !out.is_empty() {
                    out.push('\n');
                }
                out.push_str(text);
            }
        }
        out
    }

    /// Thinking text of every thinking block, joined with a newline (empty
    /// when thinking was off or its display omitted).
    #[must_use]
    pub fn thinking(&self) -> String {
        let parts: Vec<&str> = self
            .content
            .iter()
            .filter_map(|b| match b {
                ContentBlock::Thinking { thinking, .. } if !thinking.is_empty() => {
                    Some(thinking.as_str())
                }
                _ => None,
            })
            .collect();
        parts.join("\n")
    }

    /// Tool calls, with arguments as JSON text.
    #[must_use]
    pub fn tool_calls(&self) -> Vec<ToolCall> {
        self.content
            .iter()
            .filter_map(|b| match b {
                ContentBlock::ToolUse { id, name, input } => {
                    Some(ToolCall::new(id.clone(), name.clone(), input.to_string()))
                }
                _ => None,
            })
            .collect()
    }

    /// `true` when the model declined (`stop_reason == "refusal"`).
    #[must_use]
    pub fn is_refusal(&self) -> bool {
        self.stop_reason.as_deref() == Some("refusal")
    }

    /// `true` when output was cut off at `max_tokens`.
    #[must_use]
    pub fn is_truncated(&self) -> bool {
        self.stop_reason.as_deref() == Some("max_tokens")
    }

    /// Thinking and redacted-thinking blocks as portable
    /// [`ReasoningBlock`]s, signatures included, in order.
    #[must_use]
    pub fn reasoning(&self) -> Vec<ReasoningBlock> {
        self.content
            .iter()
            .filter_map(|b| match b {
                ContentBlock::Thinking {
                    thinking,
                    signature,
                } => {
                    let block = ReasoningBlock::new(thinking.clone());
                    Some(if signature.is_empty() {
                        block
                    } else {
                        block.with_signature(signature.clone())
                    })
                }
                ContentBlock::RedactedThinking { data } => {
                    Some(ReasoningBlock::redacted(data.clone()))
                }
                _ => None,
            })
            .collect()
    }

    /// The portable [`FinishReason`] for [`stop_reason`](Self::stop_reason).
    #[must_use]
    pub fn finish_reason(&self) -> Option<FinishReason> {
        self.stop_reason.as_deref().map(finish_reason)
    }

    /// Convert to the portable [`GenerateResult`], keeping thinking blocks
    /// (with their signatures) as [`GenerateResult::reasoning`] so
    /// [`GenerateResult::to_message`] can send them back on the next turn.
    #[must_use]
    pub fn to_generate_result(&self) -> GenerateResult {
        let result = GenerateResult::from_text(self.text())
            .with_tokens(self.usage.to_token_usage())
            .with_tool_calls(self.tool_calls())
            .with_reasoning(self.reasoning());
        match self.finish_reason() {
            Some(reason) => result.with_finish_reason(reason),
            None => result,
        }
    }
}

/// Map an Anthropic `stop_reason` onto the portable [`FinishReason`].
///
/// `end_turn` and `stop_sequence` are [`FinishReason::Stop`], `max_tokens`
/// and `model_context_window_exceeded` [`FinishReason::Length`], `tool_use`
/// [`FinishReason::ToolCalls`], `refusal` [`FinishReason::Refusal`]; anything
/// else (`pause_turn`, …) is kept verbatim.
#[must_use]
pub fn finish_reason(stop_reason: &str) -> FinishReason {
    match stop_reason {
        "end_turn" | "stop_sequence" => FinishReason::Stop,
        "max_tokens" | "model_context_window_exceeded" => FinishReason::Length,
        "tool_use" => FinishReason::ToolCalls,
        "refusal" => FinishReason::Refusal,
        other => FinishReason::Other(other.to_string()),
    }
}

impl From<MessagesResponse> for MessageResponse {
    fn from(body: MessagesResponse) -> Self {
        let mut usage = Usage::default();
        usage.merge(&body.usage);
        Self {
            id: body.id,
            model: body.model,
            content: body
                .content
                .into_iter()
                .filter_map(ContentBlock::from_wire)
                .collect(),
            stop_reason: body.stop_reason,
            usage,
        }
    }
}

impl ContentBlock {
    pub(crate) fn from_wire(block: ResponseContentBlock) -> Option<Self> {
        Some(match block {
            ResponseContentBlock::Text { text } => Self::Text { text },
            ResponseContentBlock::ToolUse { id, name, input } => Self::ToolUse { id, name, input },
            ResponseContentBlock::Thinking {
                thinking,
                signature,
            } => Self::Thinking {
                thinking,
                signature,
            },
            ResponseContentBlock::RedactedThinking { data } => Self::RedactedThinking { data },
            ResponseContentBlock::Unknown => return None,
        })
    }
}
