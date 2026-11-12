use serde::{Deserialize, Serialize};

use crate::{Message, ReasoningBlock, ToolCall};

/// Token consumption reported by a single LLM generation call.
///
/// The breakdown fields are *subsets* of the totals, whatever the provider's
/// own convention:
///
/// - `prompt_tokens` counts the whole prompt, including tokens read from or
///   written to the prompt cache (`cache_read_tokens`,
///   `cache_creation_tokens`);
/// - `completion_tokens` counts all output, including hidden reasoning
///   (`reasoning_tokens`).
///
/// A breakdown field is `0` when the provider does not report it. The struct
/// is `#[non_exhaustive]`: build it with [`new`](Self::new) and the `with_*`
/// builders.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub struct TokenUsage {
    /// Tokens consumed by the prompt (input side), cached ones included.
    pub prompt_tokens: u32,
    /// Tokens produced in the completion (output side), reasoning included.
    pub completion_tokens: u32,
    /// `prompt_tokens + completion_tokens`, unless the provider reported a
    /// different total.
    pub total_tokens: u32,
    /// Prompt tokens served from the provider's prompt cache (`OpenAI`
    /// `cached_tokens`, Anthropic `cache_read_input_tokens`).
    #[serde(default, skip_serializing_if = "is_zero")]
    pub cache_read_tokens: u32,
    /// Prompt tokens written to the provider's prompt cache by this call
    /// (Anthropic `cache_creation_input_tokens`).
    #[serde(default, skip_serializing_if = "is_zero")]
    pub cache_creation_tokens: u32,
    /// Completion tokens spent on reasoning / thinking (`OpenAI`
    /// `reasoning_tokens`).
    #[serde(default, skip_serializing_if = "is_zero")]
    pub reasoning_tokens: u32,
}

#[allow(clippy::trivially_copy_pass_by_ref)] // serde's skip_serializing_if signature
const fn is_zero(n: &u32) -> bool {
    *n == 0
}

impl TokenUsage {
    /// Build a usage record, computing `total_tokens` (saturating at
    /// [`u32::MAX`]). The breakdown fields start at `0`.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_chain_core::TokenUsage;
    ///
    /// let u = TokenUsage::new(12, 30);
    /// assert_eq!(u.total_tokens, 42);
    /// assert_eq!(u.cache_read_tokens, 0);
    /// ```
    #[must_use]
    pub const fn new(prompt_tokens: u32, completion_tokens: u32) -> Self {
        Self {
            prompt_tokens,
            completion_tokens,
            total_tokens: prompt_tokens.saturating_add(completion_tokens),
            cache_read_tokens: 0,
            cache_creation_tokens: 0,
            reasoning_tokens: 0,
        }
    }

    /// Override `total_tokens` with the provider's reported total (builder
    /// style).
    #[must_use]
    pub const fn with_total_tokens(mut self, total_tokens: u32) -> Self {
        self.total_tokens = total_tokens;
        self
    }

    /// Set the prompt tokens read from the prompt cache (builder style).
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_chain_core::TokenUsage;
    ///
    /// let u = TokenUsage::new(1_000, 20)
    ///     .with_cache_read_tokens(800)
    ///     .with_cache_creation_tokens(150)
    ///     .with_reasoning_tokens(12);
    /// assert_eq!(u.cached_tokens(), 950);
    /// assert_eq!(u.uncached_prompt_tokens(), 50);
    /// ```
    #[must_use]
    pub const fn with_cache_read_tokens(mut self, tokens: u32) -> Self {
        self.cache_read_tokens = tokens;
        self
    }

    /// Set the prompt tokens written to the prompt cache (builder style).
    #[must_use]
    pub const fn with_cache_creation_tokens(mut self, tokens: u32) -> Self {
        self.cache_creation_tokens = tokens;
        self
    }

    /// Set the completion tokens spent on reasoning (builder style).
    #[must_use]
    pub const fn with_reasoning_tokens(mut self, tokens: u32) -> Self {
        self.reasoning_tokens = tokens;
        self
    }

    /// Prompt tokens that touched the prompt cache (read or written).
    #[must_use]
    pub const fn cached_tokens(&self) -> u32 {
        self.cache_read_tokens
            .saturating_add(self.cache_creation_tokens)
    }

    /// Prompt tokens billed at the ordinary input rate: `prompt_tokens`
    /// minus [`cached_tokens`](Self::cached_tokens) (saturating at 0).
    #[must_use]
    pub const fn uncached_prompt_tokens(&self) -> u32 {
        self.prompt_tokens.saturating_sub(self.cached_tokens())
    }

    /// Combine two [`TokenUsage`] records by summing each field.
    ///
    /// Each sum saturates at [`u32::MAX`] instead of overflowing.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_chain_core::TokenUsage;
    ///
    /// let a = TokenUsage::new(10, 20).with_cache_read_tokens(4);
    /// let b = TokenUsage::new(5, 8).with_reasoning_tokens(3);
    /// let sum = a.combine(&b);
    /// assert_eq!(sum.total_tokens, 43);
    /// assert_eq!((sum.cache_read_tokens, sum.reasoning_tokens), (4, 3));
    /// ```
    #[must_use]
    pub const fn combine(&self, other: &Self) -> Self {
        Self {
            prompt_tokens: self.prompt_tokens.saturating_add(other.prompt_tokens),
            completion_tokens: self
                .completion_tokens
                .saturating_add(other.completion_tokens),
            total_tokens: self.total_tokens.saturating_add(other.total_tokens),
            cache_read_tokens: self
                .cache_read_tokens
                .saturating_add(other.cache_read_tokens),
            cache_creation_tokens: self
                .cache_creation_tokens
                .saturating_add(other.cache_creation_tokens),
            reasoning_tokens: self.reasoning_tokens.saturating_add(other.reasoning_tokens),
        }
    }

    /// Add `usage` (when reported) to a running `total`, for chains and agents
    /// that make several LLM calls and report their aggregate usage.
    ///
    /// The total stays `None` until at least one call reports usage, so "no
    /// provider reported usage" remains distinguishable from "zero tokens".
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_chain_core::TokenUsage;
    ///
    /// let mut total = None;
    /// TokenUsage::accumulate(&mut total, None);
    /// assert!(total.is_none());
    /// let u = TokenUsage::new(2, 1);
    /// TokenUsage::accumulate(&mut total, Some(&u));
    /// TokenUsage::accumulate(&mut total, Some(&u));
    /// assert_eq!(total.map(|t| t.total_tokens), Some(6));
    /// ```
    pub fn accumulate(total: &mut Option<Self>, usage: Option<&Self>) {
        if let Some(usage) = usage {
            *total = Some(
                total
                    .as_ref()
                    .map_or_else(|| usage.clone(), |t| t.combine(usage)),
            );
        }
    }
}

/// Why the model stopped generating.
///
/// Providers map their own stop reasons onto this enum (Anthropic's
/// `end_turn` and `stop_sequence` are [`Stop`](Self::Stop), `max_tokens` is
/// [`Length`](Self::Length), …) and keep anything else verbatim in
/// [`Other`](Self::Other). It serialises as a plain string.
///
/// # Example
///
/// ```rust
/// use rune_chain_core::FinishReason;
///
/// assert_eq!(FinishReason::from("length"), FinishReason::Length);
/// assert_eq!(FinishReason::from("pause_turn"), FinishReason::Other("pause_turn".into()));
/// assert_eq!(FinishReason::ToolCalls.as_str(), "tool_calls");
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(from = "String", into = "String")]
#[non_exhaustive]
pub enum FinishReason {
    /// The model finished its answer or hit a stop sequence.
    Stop,
    /// The output hit the token limit and is truncated.
    Length,
    /// The model stopped to call one or more tools.
    ToolCalls,
    /// The provider's content filter cut the output.
    ContentFilter,
    /// The model refused to answer.
    Refusal,
    /// A provider-specific reason, kept verbatim.
    Other(String),
}

impl FinishReason {
    /// The canonical name (`stop`, `length`, `tool_calls`, `content_filter`,
    /// `refusal`), or the provider's own string for [`Other`](Self::Other).
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::Stop => "stop",
            Self::Length => "length",
            Self::ToolCalls => "tool_calls",
            Self::ContentFilter => "content_filter",
            Self::Refusal => "refusal",
            Self::Other(s) => s,
        }
    }
}

impl From<&str> for FinishReason {
    /// Parse a canonical name; anything else becomes [`Other`](Self::Other).
    fn from(s: &str) -> Self {
        match s {
            "stop" => Self::Stop,
            "length" => Self::Length,
            "tool_calls" => Self::ToolCalls,
            "content_filter" => Self::ContentFilter,
            "refusal" => Self::Refusal,
            other => Self::Other(other.to_string()),
        }
    }
}

impl From<String> for FinishReason {
    fn from(s: String) -> Self {
        match Self::from(s.as_str()) {
            Self::Other(_) => Self::Other(s),
            known => known,
        }
    }
}

impl From<FinishReason> for String {
    fn from(r: FinishReason) -> Self {
        match r {
            FinishReason::Other(s) => s,
            known => known.as_str().to_string(),
        }
    }
}

impl std::fmt::Display for FinishReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The result of a single LLM generation call.
///
/// When the model requests tool calls (native function calling), `tool_calls`
/// will be non-empty and `generation` may be empty or contain the model's
/// reasoning text. After executing the tools and feeding results back, call the
/// LLM again until `tool_calls` is empty.
///
/// The struct is `#[non_exhaustive]`: build it with
/// [`from_text`](Self::from_text) and the `with_*` builders.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct GenerateResult {
    /// The text produced by the model.
    pub generation: String,
    /// Token usage, if reported by the provider.
    pub tokens: Option<TokenUsage>,
    /// Tool calls the model wants to make (native function calling).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tool_calls: Vec<ToolCall>,
    /// Why the model stopped, if the provider said.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub finish_reason: Option<FinishReason>,
    /// Reasoning / thinking the model emitted before its answer. Kept apart
    /// from `generation`; [`to_message`](Self::to_message) carries it into
    /// the history so providers that need it back (Anthropic thinking with
    /// tool use) receive it.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub reasoning: Vec<ReasoningBlock>,
}

impl GenerateResult {
    /// Create a [`GenerateResult`] with just text, no token data, no tool calls.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_chain_core::GenerateResult;
    ///
    /// let r = GenerateResult::from_text("4");
    /// assert_eq!(r.generation, "4");
    /// assert!(r.tokens.is_none());
    /// assert!(r.tool_calls.is_empty());
    /// assert!(r.finish_reason.is_none());
    /// ```
    pub fn from_text(text: impl Into<String>) -> Self {
        Self {
            generation: text.into(),
            ..Self::default()
        }
    }

    /// Return `true` if the model is requesting tool calls rather than giving a
    /// final text answer.
    #[must_use]
    pub const fn wants_tool_calls(&self) -> bool {
        !self.tool_calls.is_empty()
    }

    /// Attach token usage (builder style).
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_chain_core::{GenerateResult, TokenUsage};
    ///
    /// let r = GenerateResult::from_text("hi").with_tokens(TokenUsage::new(3, 1));
    /// assert_eq!(r.tokens.map(|t| t.total_tokens), Some(4));
    /// ```
    ///
    /// Takes a [`TokenUsage`] or an `Option<TokenUsage>` (`None` clears it).
    #[must_use]
    pub fn with_tokens(mut self, tokens: impl Into<Option<TokenUsage>>) -> Self {
        self.tokens = tokens.into();
        self
    }

    /// Attach tool calls (builder style).
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_chain_core::{GenerateResult, ToolCall};
    ///
    /// let r = GenerateResult::from_text("")
    ///     .with_tool_calls(vec![ToolCall::new("c1", "echo", "{}")]);
    /// assert!(r.wants_tool_calls());
    /// ```
    #[must_use]
    pub fn with_tool_calls(mut self, tool_calls: Vec<ToolCall>) -> Self {
        self.tool_calls = tool_calls;
        self
    }

    /// Record why the model stopped (builder style).
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_chain_core::{FinishReason, GenerateResult};
    ///
    /// let r = GenerateResult::from_text("The answer is").with_finish_reason(FinishReason::Length);
    /// assert!(r.is_truncated());
    /// ```
    #[must_use]
    pub fn with_finish_reason(mut self, reason: FinishReason) -> Self {
        self.finish_reason = Some(reason);
        self
    }

    /// Attach the model's reasoning blocks (builder style).
    #[must_use]
    pub fn with_reasoning(mut self, reasoning: Vec<ReasoningBlock>) -> Self {
        self.reasoning = reasoning;
        self
    }

    /// `true` if the output was cut off by the token limit
    /// ([`FinishReason::Length`]).
    #[must_use]
    pub fn is_truncated(&self) -> bool {
        self.finish_reason == Some(FinishReason::Length)
    }

    /// All reasoning text, blocks joined with a blank line (redacted blocks
    /// contribute nothing).
    #[must_use]
    pub fn reasoning_text(&self) -> String {
        crate::message::join_reasoning(&self.reasoning)
    }

    /// Turn this result into the [`Role::Ai`](crate::Role::Ai) [`Message`] to
    /// append to the conversation history, keeping any tool calls and
    /// reasoning blocks.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_chain_core::{GenerateResult, Message, ToolCall};
    ///
    /// let r = GenerateResult::from_text("")
    ///     .with_tool_calls(vec![ToolCall::new("c1", "echo", "{}")]);
    /// let msg = r.to_message();
    /// assert!(msg.has_tool_calls());
    /// assert_eq!(GenerateResult::from_text("4").to_message(), Message::ai("4"));
    /// ```
    #[must_use]
    pub fn to_message(&self) -> Message {
        Message::ai_with_tool_calls(self.generation.as_str(), self.tool_calls.clone())
            .with_reasoning(self.reasoning.clone())
    }
}
