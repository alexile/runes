//! Typed streaming events: text, reasoning and tool-call deltas, usage and
//! the finish reason, as returned by [`Llm::stream_events`](crate::Llm::stream_events).

use std::pin::Pin;

use futures::{Stream, StreamExt};
use serde::{Deserialize, Serialize};

use crate::{
    FinishReason, GenerateResult, LlmError, MAX_TOOL_ARGUMENTS_BYTES, ReasoningBlock, StreamData,
    TokenUsage, ToolCall,
};

/// A stream of [`StreamEvent`]s, as returned by
/// [`Llm::stream_events`](crate::Llm::stream_events).
pub type EventStream = Pin<Box<dyn Stream<Item = Result<StreamEvent, LlmError>> + Send>>;

/// Most tool calls one streamed reply may carry.
const MAX_STREAMED_TOOL_CALLS: usize = 256;

/// One event of a streamed model reply.
///
/// Tool calls arrive in pieces: a [`ToolCallStart`](Self::ToolCallStart)
/// with the call's id and name, any number of
/// [`ToolCallDelta`](Self::ToolCallDelta)s carrying fragments of the JSON
/// arguments, and a [`ToolCallEnd`](Self::ToolCallEnd). `index` ties the
/// pieces together; parallel calls may interleave. Fold the events with a
/// [`StreamAccumulator`] to get the same [`GenerateResult`] the non-streaming
/// call returns.
///
/// The enum is `#[non_exhaustive]`: match it with a wildcard arm.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", content = "data", rename_all = "snake_case")]
#[non_exhaustive]
pub enum StreamEvent {
    /// A fragment of the answer text.
    TextDelta(String),
    /// A fragment of reasoning / thinking. A `signature` closes the current
    /// reasoning block (Anthropic sends it last).
    ReasoningDelta {
        /// Reasoning text (may be empty when only the signature arrives).
        text: String,
        /// Opaque provider signature of the block.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        signature: Option<String>,
    },
    /// A whole redacted reasoning block (opaque provider data).
    RedactedReasoning(String),
    /// A tool call begins.
    ToolCallStart {
        /// Position of the call in this reply.
        index: usize,
        /// Provider-issued call id.
        id: String,
        /// Tool name as the model wrote it (untrusted).
        name: String,
    },
    /// A fragment of a tool call's JSON arguments.
    ToolCallDelta {
        /// The call this fragment belongs to.
        index: usize,
        /// The next piece of the JSON text.
        arguments_fragment: String,
    },
    /// A tool call is complete.
    ToolCallEnd {
        /// The call that ended.
        index: usize,
    },
    /// Token usage for the whole reply. A later `Usage` replaces an earlier one.
    Usage(TokenUsage),
    /// Why the model stopped.
    Finish(FinishReason),
}

impl StreamEvent {
    /// A [`TextDelta`](Self::TextDelta).
    pub fn text(text: impl Into<String>) -> Self {
        Self::TextDelta(text.into())
    }

    /// A [`ReasoningDelta`](Self::ReasoningDelta) without a signature.
    pub fn reasoning(text: impl Into<String>) -> Self {
        Self::ReasoningDelta {
            text: text.into(),
            signature: None,
        }
    }

    /// A [`ToolCallStart`](Self::ToolCallStart).
    pub fn tool_call_start(index: usize, id: impl Into<String>, name: impl Into<String>) -> Self {
        Self::ToolCallStart {
            index,
            id: id.into(),
            name: name.into(),
        }
    }

    /// A [`ToolCallDelta`](Self::ToolCallDelta).
    pub fn tool_call_delta(index: usize, arguments_fragment: impl Into<String>) -> Self {
        Self::ToolCallDelta {
            index,
            arguments_fragment: arguments_fragment.into(),
        }
    }

    /// The text of a [`TextDelta`](Self::TextDelta), `None` for other events.
    #[must_use]
    pub fn as_text(&self) -> Option<&str> {
        match self {
            Self::TextDelta(t) => Some(t),
            _ => None,
        }
    }
}

impl GenerateResult {
    /// Replay this result as stream events: reasoning, text, each tool call
    /// (start, arguments, end), usage and the finish reason.
    ///
    /// Folding the events with a [`StreamAccumulator`] gives this result
    /// back.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_chain_core::{GenerateResult, StreamAccumulator, ToolCall};
    ///
    /// let result = GenerateResult::from_text("Checking.")
    ///     .with_tool_calls(vec![ToolCall::new("c1", "search", r#"{"q":"rust"}"#)]);
    /// let mut acc = StreamAccumulator::new();
    /// for event in result.clone().into_events() {
    ///     acc.push(&event).unwrap();
    /// }
    /// assert_eq!(acc.finish(), result);
    /// ```
    #[must_use]
    pub fn into_events(self) -> Vec<StreamEvent> {
        let mut events = Vec::with_capacity(self.reasoning.len() + 3 * self.tool_calls.len() + 3);
        for block in self.reasoning {
            match block.redacted {
                Some(data) => events.push(StreamEvent::RedactedReasoning(data)),
                None => events.push(StreamEvent::ReasoningDelta {
                    text: block.text,
                    signature: block.signature,
                }),
            }
        }
        if !self.generation.is_empty() {
            events.push(StreamEvent::TextDelta(self.generation));
        }
        for (index, call) in self.tool_calls.into_iter().enumerate() {
            events.push(StreamEvent::ToolCallStart {
                index,
                id: call.id,
                name: call.name,
            });
            if !call.arguments.is_empty() {
                events.push(StreamEvent::ToolCallDelta {
                    index,
                    arguments_fragment: call.arguments,
                });
            }
            events.push(StreamEvent::ToolCallEnd { index });
        }
        if let Some(usage) = self.tokens {
            events.push(StreamEvent::Usage(usage));
        }
        if let Some(reason) = self.finish_reason {
            events.push(StreamEvent::Finish(reason));
        }
        events
    }
}

/// Replay `result` as an [`EventStream`].
pub fn result_stream(result: GenerateResult) -> EventStream {
    Box::pin(futures::stream::iter(
        result.into_events().into_iter().map(Ok),
    ))
}

/// Turn a plain text stream into text events.
pub fn text_stream(
    stream: Pin<Box<dyn Stream<Item = Result<StreamData, LlmError>> + Send>>,
) -> EventStream {
    Box::pin(stream.filter_map(|item| {
        futures::future::ready(match item {
            Ok(chunk) if chunk.content.is_empty() => None,
            Ok(chunk) => Some(Ok(StreamEvent::TextDelta(chunk.content))),
            Err(e) => Some(Err(e)),
        })
    }))
}

#[derive(Debug, Clone)]
struct PartialCall {
    index: usize,
    call: ToolCall,
}

/// Folds [`StreamEvent`]s into the final [`GenerateResult`], assembling tool
/// calls from their fragments.
///
/// Text deltas are joined into `generation`. Tool calls come out in the
/// order they started; fragments are matched by `index`, so interleaved
/// parallel calls are fine. Each call's arguments are capped at
/// [`MAX_TOOL_ARGUMENTS_BYTES`] (see
/// [`with_max_argument_bytes`](Self::with_max_argument_bytes)) and a reply
/// may carry at most 256 calls; going over either is an error, so a hostile
/// stream cannot grow memory without bound through tool calls.
///
/// A reasoning block ends at a signature, a redacted block or any
/// non-reasoning event.
///
/// # Example
///
/// ```rust
/// use rune_chain_core::{FinishReason, StreamAccumulator, StreamEvent};
///
/// let mut acc = StreamAccumulator::new();
/// for event in [
///     StreamEvent::text("Let me check. "),
///     StreamEvent::tool_call_start(0, "c1", "weather"),
///     StreamEvent::tool_call_start(1, "c2", "time"),
///     StreamEvent::tool_call_delta(0, r#"{"city":"#),
///     StreamEvent::tool_call_delta(1, "{}"),
///     StreamEvent::tool_call_delta(0, r#""Oslo"}"#),
///     StreamEvent::Finish(FinishReason::ToolCalls),
/// ] {
///     acc.push(&event).unwrap();
/// }
/// let result = acc.finish();
/// assert_eq!(result.generation, "Let me check. ");
/// assert_eq!(result.tool_calls[0].arguments, r#"{"city":"Oslo"}"#);
/// assert_eq!(result.tool_calls[1].name, "time");
/// ```
#[derive(Debug, Clone)]
pub struct StreamAccumulator {
    text: String,
    reasoning: Vec<ReasoningBlock>,
    reasoning_open: bool,
    calls: Vec<PartialCall>,
    usage: Option<TokenUsage>,
    finish: Option<FinishReason>,
    max_argument_bytes: usize,
}

impl Default for StreamAccumulator {
    fn default() -> Self {
        Self::new()
    }
}

impl StreamAccumulator {
    /// An empty accumulator with the default argument cap.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            text: String::new(),
            reasoning: Vec::new(),
            reasoning_open: false,
            calls: Vec::new(),
            usage: None,
            finish: None,
            max_argument_bytes: MAX_TOOL_ARGUMENTS_BYTES,
        }
    }

    /// Cap each tool call's arguments at `max_bytes` instead of
    /// [`MAX_TOOL_ARGUMENTS_BYTES`] (builder style).
    #[must_use]
    pub const fn with_max_argument_bytes(mut self, max_bytes: usize) -> Self {
        self.max_argument_bytes = max_bytes;
        self
    }

    /// The text received so far.
    #[must_use]
    pub fn text(&self) -> &str {
        &self.text
    }

    /// Number of tool calls started so far.
    #[must_use]
    pub const fn tool_call_count(&self) -> usize {
        self.calls.len()
    }

    /// Add one event.
    ///
    /// # Errors
    ///
    /// [`LlmErrorKind::InvalidResponse`](crate::LlmErrorKind::InvalidResponse)
    /// when a call's arguments grow past the cap or the reply starts too
    /// many calls. The message never echoes the stream's content.
    pub fn push(&mut self, event: &StreamEvent) -> Result<(), LlmError> {
        if !matches!(event, StreamEvent::ReasoningDelta { .. }) {
            self.reasoning_open = false;
        }
        match event {
            StreamEvent::TextDelta(t) => self.text.push_str(t),
            StreamEvent::ReasoningDelta { text, signature } => {
                if !self.reasoning_open {
                    self.reasoning.push(ReasoningBlock::default());
                    self.reasoning_open = true;
                }
                if let Some(block) = self.reasoning.last_mut() {
                    block.text.push_str(text);
                    if let Some(sig) = signature {
                        block.signature = Some(sig.clone());
                        self.reasoning_open = false;
                    }
                }
            }
            StreamEvent::RedactedReasoning(data) => {
                self.reasoning.push(ReasoningBlock::redacted(data.as_str()));
            }
            StreamEvent::ToolCallStart { index, id, name } => {
                let call = &mut self.call_mut(*index)?.call;
                if call.id.is_empty() {
                    call.id.clone_from(id);
                }
                if call.name.is_empty() {
                    call.name.clone_from(name);
                }
            }
            StreamEvent::ToolCallDelta {
                index,
                arguments_fragment,
            } => {
                let max = self.max_argument_bytes;
                let call = &mut self.call_mut(*index)?.call;
                if call
                    .arguments
                    .len()
                    .saturating_add(arguments_fragment.len())
                    > max
                {
                    return Err(LlmError::invalid_response(format!(
                        "streamed tool-call arguments exceed the {max}-byte limit"
                    )));
                }
                call.arguments.push_str(arguments_fragment);
            }
            StreamEvent::ToolCallEnd { .. } => {}
            StreamEvent::Usage(usage) => self.usage = Some(usage.clone()),
            StreamEvent::Finish(reason) => self.finish = Some(reason.clone()),
        }
        Ok(())
    }

    fn call_mut(&mut self, index: usize) -> Result<&mut PartialCall, LlmError> {
        // Calls usually arrive in order, so look from the back.
        if let Some(pos) = self.calls.iter().rposition(|c| c.index == index) {
            return Ok(&mut self.calls[pos]);
        }
        if self.calls.len() >= MAX_STREAMED_TOOL_CALLS {
            return Err(LlmError::invalid_response(format!(
                "the streamed reply starts more than {MAX_STREAMED_TOOL_CALLS} tool calls"
            )));
        }
        self.calls.push(PartialCall {
            index,
            call: ToolCall::new("", "", ""),
        });
        let last = self.calls.len() - 1;
        Ok(&mut self.calls[last])
    }

    /// The assembled result.
    #[must_use]
    pub fn finish(self) -> GenerateResult {
        GenerateResult::from_text(self.text)
            .with_reasoning(self.reasoning)
            .with_tool_calls(self.calls.into_iter().map(|c| c.call).collect())
            .with_tokens(self.usage)
            .with_finish_reason_opt(self.finish)
    }

    /// Drain `stream` into a [`GenerateResult`].
    ///
    /// # Errors
    ///
    /// The first error the stream yields, or a [`push`](Self::push) error.
    pub async fn collect(mut self, mut stream: EventStream) -> Result<GenerateResult, LlmError> {
        while let Some(event) = stream.next().await {
            self.push(&event?)?;
        }
        Ok(self.finish())
    }
}

impl GenerateResult {
    fn with_finish_reason_opt(mut self, reason: Option<FinishReason>) -> Self {
        self.finish_reason = reason;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::LlmErrorKind;

    fn fold(events: &[StreamEvent]) -> Result<GenerateResult, LlmError> {
        let mut acc = StreamAccumulator::new();
        for e in events {
            acc.push(e)?;
        }
        Ok(acc.finish())
    }

    #[test]
    fn fragmented_arguments_join_up() {
        let json = r#"{"city":"Oslo","days":[1,2,3]}"#;
        let mut events = vec![StreamEvent::tool_call_start(0, "c1", "weather")];
        events.extend(
            json.as_bytes()
                .chunks(3)
                .map(|c| StreamEvent::tool_call_delta(0, std::str::from_utf8(c).unwrap())),
        );
        events.push(StreamEvent::ToolCallEnd { index: 0 });
        let result = fold(&events).unwrap();
        assert_eq!(result.tool_calls, [ToolCall::new("c1", "weather", json)]);
        let args: serde_json::Value = result.tool_calls[0].parse_arguments().unwrap();
        assert_eq!(args["days"][2], 3);
    }

    #[test]
    fn interleaved_parallel_calls_keep_start_order() {
        let events = [
            StreamEvent::tool_call_start(5, "b", "second"),
            StreamEvent::tool_call_start(2, "a", "first"),
            StreamEvent::tool_call_delta(2, "{\"x\""),
            StreamEvent::tool_call_delta(5, "{\"y\":"),
            StreamEvent::tool_call_delta(2, ":1}"),
            StreamEvent::tool_call_delta(5, "2}"),
            StreamEvent::ToolCallEnd { index: 2 },
            StreamEvent::ToolCallEnd { index: 5 },
        ];
        let result = fold(&events).unwrap();
        assert_eq!(
            result.tool_calls,
            [
                ToolCall::new("b", "second", r#"{"y":2}"#),
                ToolCall::new("a", "first", r#"{"x":1}"#)
            ]
        );
    }

    #[test]
    fn delta_before_start_still_assembles() {
        let events = [
            StreamEvent::tool_call_delta(0, "{}"),
            StreamEvent::tool_call_start(0, "c1", "t"),
        ];
        assert_eq!(
            fold(&events).unwrap().tool_calls[0],
            ToolCall::new("c1", "t", "{}")
        );
    }

    #[test]
    fn oversized_arguments_are_rejected_without_echo() {
        let mut acc = StreamAccumulator::new().with_max_argument_bytes(8);
        acc.push(&StreamEvent::tool_call_start(0, "c1", "t"))
            .unwrap();
        acc.push(&StreamEvent::tool_call_delta(0, "{\"a\":"))
            .unwrap();
        let err = acc
            .push(&StreamEvent::tool_call_delta(0, "\"SECRET\"}"))
            .unwrap_err();
        assert_eq!(err.kind(), LlmErrorKind::InvalidResponse);
        assert!(!err.message().contains("SECRET"));
    }

    #[test]
    fn default_cap_is_the_core_limit() {
        let mut acc = StreamAccumulator::new();
        let chunk = "x".repeat(64 * 1024);
        acc.push(&StreamEvent::tool_call_start(0, "c", "t"))
            .unwrap();
        let mut sent = 0;
        let err = loop {
            match acc.push(&StreamEvent::tool_call_delta(0, chunk.as_str())) {
                Ok(()) => sent += chunk.len(),
                Err(e) => break e,
            }
        };
        assert_eq!(sent, MAX_TOOL_ARGUMENTS_BYTES);
        assert_eq!(err.kind(), LlmErrorKind::InvalidResponse);
    }

    #[test]
    fn too_many_calls_are_rejected() {
        let mut acc = StreamAccumulator::new();
        for i in 0..MAX_STREAMED_TOOL_CALLS {
            acc.push(&StreamEvent::tool_call_start(i, "c", "t"))
                .unwrap();
        }
        // Huge indexes do not allocate by index.
        assert!(
            acc.push(&StreamEvent::tool_call_start(usize::MAX, "c", "t"))
                .is_err()
        );
        assert_eq!(acc.tool_call_count(), MAX_STREAMED_TOOL_CALLS);
    }

    #[test]
    fn reasoning_blocks_split_on_signature_and_other_events() {
        let events = [
            StreamEvent::reasoning("think "),
            StreamEvent::reasoning("hard"),
            StreamEvent::ReasoningDelta {
                text: String::new(),
                signature: Some("sig1".into()),
            },
            StreamEvent::reasoning("again"),
            StreamEvent::text("answer"),
            StreamEvent::RedactedReasoning("opaque".into()),
        ];
        let result = fold(&events).unwrap();
        assert_eq!(
            result.reasoning,
            [
                ReasoningBlock::new("think hard").with_signature("sig1"),
                ReasoningBlock::new("again"),
                ReasoningBlock::redacted("opaque"),
            ]
        );
    }

    #[test]
    fn replay_round_trips() {
        let result = GenerateResult::from_text("Let me look.")
            .with_reasoning(vec![
                ReasoningBlock::new("plan").with_signature("s"),
                ReasoningBlock::redacted("r"),
            ])
            .with_tool_calls(vec![
                ToolCall::new("c1", "a", r#"{"q":1}"#),
                ToolCall::new("c2", "b", ""),
            ])
            .with_tokens(TokenUsage::new(10, 5).with_cache_read_tokens(2))
            .with_finish_reason(FinishReason::ToolCalls);
        assert_eq!(fold(&result.clone().into_events()).unwrap(), result);
        assert_eq!(
            fold(&GenerateResult::default().into_events()).unwrap(),
            GenerateResult::default()
        );
    }

    #[test]
    fn last_usage_and_finish_win() {
        let events = [
            StreamEvent::Usage(TokenUsage::new(1, 0)),
            StreamEvent::Usage(TokenUsage::new(1, 9)),
            StreamEvent::Finish(FinishReason::Stop),
        ];
        let r = fold(&events).unwrap();
        assert_eq!(r.tokens, Some(TokenUsage::new(1, 9)));
        assert_eq!(r.finish_reason, Some(FinishReason::Stop));
    }

    #[test]
    fn serialises_with_a_type_tag() {
        let e = StreamEvent::tool_call_delta(1, "{");
        let json = serde_json::to_value(&e).unwrap();
        assert_eq!(json["type"], "tool_call_delta");
        assert_eq!(json["data"]["arguments_fragment"], "{");
        let back: StreamEvent = serde_json::from_value(json).unwrap();
        assert_eq!(back, e);
        let t = serde_json::to_value(StreamEvent::text("hi")).unwrap();
        assert_eq!(t, serde_json::json!({"type": "text_delta", "data": "hi"}));
    }

    #[tokio::test]
    async fn collect_stops_at_the_first_error() {
        let items: Vec<Result<StreamEvent, LlmError>> = vec![
            Ok(StreamEvent::text("a")),
            Err(LlmError::request_failed("reset")),
            Ok(StreamEvent::text("b")),
        ];
        let err = StreamAccumulator::new()
            .collect(Box::pin(futures::stream::iter(items)))
            .await
            .unwrap_err();
        assert_eq!(err.kind(), LlmErrorKind::Network);
    }
}
