//! Provider-level view of a Messages API response.

use rune_chain_core::{FinishReason, GenerateResult, ReasoningBlock, TokenUsage, ToolCall};
use serde::Serialize;
use serde_json::Value;

use crate::types::{
    IterationReport, MessagesResponse, ResponseContentBlock, StopDetailsReport, UsageReport,
};

/// `usage.iterations` entry type of an attempt served by a fallback model.
pub const FALLBACK_ITERATION: &str = "fallback_message";

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
    /// A server-side fallback switched models here (a `fallback` block).
    /// Output before it came from [`FallbackSwitch::from`], output after it
    /// from [`FallbackSwitch::to`].
    Fallback(FallbackSwitch),
}

/// The models on either side of a `fallback` content block.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct FallbackSwitch {
    /// Model that declined.
    pub from: String,
    /// Model that took over.
    pub to: String,
}

impl FallbackSwitch {
    /// A switch from one model to another.
    #[must_use]
    pub fn new(from: impl Into<String>, to: impl Into<String>) -> Self {
        Self {
            from: from.into(),
            to: to.into(),
        }
    }
}

/// Why the model stopped, beyond the bare `stop_reason` (the response's
/// `stop_details`; set on a refusal).
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct StopDetails {
    /// `type`, e.g. `refusal`.
    pub kind: String,
    /// Refusal category such as `cyber` or `bio`, if one applies.
    pub category: Option<String>,
    /// Human-readable explanation, if given.
    pub explanation: Option<String>,
    /// A model to retry on, given when the fallback model could not run
    /// (for example because it was rate limited).
    pub recommended_model: Option<String>,
}

impl From<StopDetailsReport> for StopDetails {
    fn from(r: StopDetailsReport) -> Self {
        Self {
            kind: r.kind.unwrap_or_default(),
            category: r.category,
            explanation: r.explanation,
            recommended_model: r.recommended_model,
        }
    }
}

/// One attempt's usage from `usage.iterations`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct UsageIteration {
    /// Entry `type`; [`FALLBACK_ITERATION`] for an attempt served by a
    /// fallback model.
    pub kind: String,
    /// Tokens of this attempt (fields the entry leaves out read as 0).
    pub usage: Usage,
}

impl UsageIteration {
    /// `true` for an attempt served by a fallback model.
    #[must_use]
    pub fn is_fallback(&self) -> bool {
        self.kind == FALLBACK_ITERATION
    }
}

impl From<IterationReport> for UsageIteration {
    fn from(r: IterationReport) -> Self {
        Self {
            kind: r.kind,
            usage: Usage::new(
                r.input_tokens.unwrap_or(0),
                r.output_tokens.unwrap_or(0),
                r.cache_creation_input_tokens.unwrap_or(0),
                r.cache_read_input_tokens.unwrap_or(0),
            ),
        }
    }
}

pub fn iterations_from(report: &mut UsageReport) -> Option<Vec<UsageIteration>> {
    report
        .iterations
        .take()
        .map(|list| list.into_iter().map(UsageIteration::from).collect())
}

/// Wire form of a content block, for sending an assistant turn back.
impl Serialize for ContentBlock {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        #[derive(Serialize)]
        struct ModelRef<'a> {
            model: &'a str,
        }
        #[derive(Serialize)]
        #[serde(tag = "type", rename_all = "snake_case")]
        enum Wire<'a> {
            Text {
                text: &'a str,
            },
            Thinking {
                thinking: &'a str,
                signature: &'a str,
            },
            RedactedThinking {
                data: &'a str,
            },
            ToolUse {
                id: &'a str,
                name: &'a str,
                input: &'a Value,
            },
            Fallback {
                from: ModelRef<'a>,
                to: ModelRef<'a>,
            },
        }
        match self {
            Self::Text { text } => Wire::Text { text },
            Self::Thinking {
                thinking,
                signature,
            } => Wire::Thinking {
                thinking,
                signature,
            },
            Self::RedactedThinking { data } => Wire::RedactedThinking { data },
            Self::ToolUse { id, name, input } => Wire::ToolUse { id, name, input },
            Self::Fallback(switch) => Wire::Fallback {
                from: ModelRef {
                    model: &switch.from,
                },
                to: ModelRef { model: &switch.to },
            },
        }
        .serialize(serializer)
    }
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
    /// Model that produced the message (the fallback model when a fallback
    /// served it).
    pub model: String,
    /// Content blocks in order.
    pub content: Vec<ContentBlock>,
    /// Why generation stopped (`end_turn`, `max_tokens`, `tool_use`,
    /// `refusal`, …), if reported.
    pub stop_reason: Option<String>,
    /// Token usage.
    pub usage: Usage,
    /// `stop_details`, when reported (on a refusal).
    pub stop_details: Option<StopDetails>,
    /// Per-attempt usage (`usage.iterations`), when reported.
    pub iterations: Vec<UsageIteration>,
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

    /// Tool calls, with arguments as JSON text. After a server-side
    /// fallback only the calls made after the last switch count.
    #[must_use]
    pub fn tool_calls(&self) -> Vec<ToolCall> {
        self.after_last_fallback()
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

    /// `stop_details` (category, explanation, recommended model), when
    /// reported. On a refusal with fallbacks set, it describes the last
    /// model in the chain.
    #[must_use]
    pub const fn stop_details(&self) -> Option<&StopDetails> {
        self.stop_details.as_ref()
    }

    /// Per-attempt usage (`usage.iterations`); empty when not reported.
    #[must_use]
    pub fn iterations(&self) -> &[UsageIteration] {
        &self.iterations
    }

    /// `true` when a fallback model produced this message.
    ///
    /// Based on a [`FALLBACK_ITERATION`] entry in `usage.iterations`, the
    /// reliable signal: turns routed straight to the fallback model carry no
    /// `fallback` block. A `fallback` block counts too.
    #[must_use]
    pub fn served_by_fallback(&self) -> bool {
        self.iterations.iter().any(UsageIteration::is_fallback)
            || self.fallback_switches().next().is_some()
    }

    /// The points where a server-side fallback switched models, in order.
    pub fn fallback_switches(&self) -> impl Iterator<Item = &FallbackSwitch> {
        self.content.iter().filter_map(|b| match b {
            ContentBlock::Fallback(switch) => Some(switch),
            _ => None,
        })
    }

    /// The content to send back as this assistant turn: every block in
    /// order, `fallback` blocks kept where they appeared, minus the thinking
    /// and tool-use blocks that came before the last `fallback` block.
    /// Serialize the blocks to get the wire form.
    #[must_use]
    pub fn replay_content(&self) -> Vec<ContentBlock> {
        let cut = self.last_fallback_index().unwrap_or(0);
        self.content
            .iter()
            .enumerate()
            .filter(|(i, b)| {
                *i >= cut
                    || !matches!(
                        b,
                        ContentBlock::Thinking { .. }
                            | ContentBlock::RedactedThinking { .. }
                            | ContentBlock::ToolUse { .. }
                    )
            })
            .map(|(_, b)| b.clone())
            .collect()
    }

    fn last_fallback_index(&self) -> Option<usize> {
        self.content
            .iter()
            .rposition(|b| matches!(b, ContentBlock::Fallback(_)))
    }

    fn after_last_fallback(&self) -> &[ContentBlock] {
        self.last_fallback_index()
            .map_or(&self.content[..], |i| &self.content[i + 1..])
    }

    /// `true` when output was cut off at `max_tokens`.
    #[must_use]
    pub fn is_truncated(&self) -> bool {
        self.stop_reason.as_deref() == Some("max_tokens")
    }

    /// Thinking and redacted-thinking blocks as portable
    /// [`ReasoningBlock`]s, signatures included, in order. After a
    /// server-side fallback only the blocks after the last switch count.
    #[must_use]
    pub fn reasoning(&self) -> Vec<ReasoningBlock> {
        self.after_last_fallback()
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
    fn from(mut body: MessagesResponse) -> Self {
        let mut usage = Usage::default();
        usage.merge(&body.usage);
        let iterations = iterations_from(&mut body.usage).unwrap_or_default();
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
            stop_details: body.stop_details.map(StopDetails::from),
            iterations,
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
            ResponseContentBlock::Fallback { from, to } => {
                Self::Fallback(FallbackSwitch::new(from.model, to.model))
            }
            ResponseContentBlock::Unknown => return None,
        })
    }
}
