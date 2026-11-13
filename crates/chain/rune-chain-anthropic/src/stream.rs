//! Sans-I/O assembly of a streamed Messages API response.

use rune_chain_core::{LlmError, ToolCall};
use serde_json::Value;

use crate::response::{ContentBlock, MessageResponse, Usage};
use crate::types::{Delta, ResponseContentBlock, SseEvent};

/// Default cap on the content a streamed response may accumulate
/// (text, thinking and tool input together).
pub const DEFAULT_MAX_STREAM_BYTES: usize = 32 << 20;

/// Upper bound on content blocks per message; guards the block table against
/// a hostile `index`.
const MAX_BLOCKS: usize = 4096;

/// One step of a streamed response, as yielded by
/// [`Anthropic::stream_message`](crate::Anthropic::stream_message).
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum StreamEvent {
    /// A fragment of visible text.
    Text(String),
    /// A fragment of thinking text (only with a summarized display).
    Thinking(String),
    /// A complete tool call, emitted when its block closes with the
    /// streamed `input_json_delta` fragments assembled and parsed.
    ToolCall(ToolCall),
    /// The final, fully assembled response; always the last event.
    Done(MessageResponse),
}

#[derive(Debug)]
enum Partial {
    Text(String),
    Thinking {
        thinking: String,
        signature: String,
    },
    Redacted(String),
    ToolUse {
        id: String,
        name: String,
        initial: Value,
        json: String,
    },
    /// A block type this crate does not model; deltas to it are ignored.
    Unknown,
}

#[derive(Debug)]
struct Slot {
    partial: Partial,
    done: Option<ContentBlock>,
    closed: bool,
}

/// Incrementally assembles the SSE `data` payloads of one streamed message
/// into a [`MessageResponse`].
///
/// Feed each event's data to [`push`](Self::push). Malformed or
/// out-of-order input is reported as [`LlmError::invalid_response`], an
/// `error` event as an [`LlmError`] classified by its `error.type`
/// (`overloaded_error` is
/// [`LlmErrorKind::Overloaded`](rune_chain_core::LlmErrorKind::Overloaded),
/// …); nothing panics. Tool inputs
/// arrive as `input_json_delta` fragments that are only valid JSON once
/// concatenated, so they are parsed when their block stops.
///
/// ```rust
/// use rune_chain_anthropic::{MessageAccumulator, StreamEvent};
///
/// let mut acc = MessageAccumulator::new();
/// let events = [
///     r#"{"type":"message_start","message":{"id":"msg_1","model":"m","usage":{"input_tokens":5,"cache_read_input_tokens":100}}}"#,
///     r#"{"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"toolu_1","name":"get_weather","input":{}}}"#,
///     r#"{"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"{\"city\": \"Pa"}}"#,
///     r#"{"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"ris\"}"}}"#,
///     r#"{"type":"content_block_stop","index":0}"#,
///     r#"{"type":"message_delta","delta":{"stop_reason":"tool_use"},"usage":{"output_tokens":12}}"#,
///     r#"{"type":"message_stop"}"#,
/// ];
/// let mut out = Vec::new();
/// for data in events {
///     out.extend(acc.push(data).unwrap());
/// }
/// let StreamEvent::ToolCall(call) = &out[0] else { panic!() };
/// assert_eq!(call.arguments, r#"{"city":"Paris"}"#);
/// let StreamEvent::Done(message) = &out[1] else { panic!() };
/// assert_eq!(message.usage().cache_read_input_tokens, 100);
/// ```
#[derive(Debug)]
pub struct MessageAccumulator {
    id: String,
    model: String,
    slots: Vec<Slot>,
    stop_reason: Option<String>,
    usage: Usage,
    bytes: usize,
    max_bytes: usize,
    started: bool,
    finished: bool,
}

impl Default for MessageAccumulator {
    fn default() -> Self {
        Self::new()
    }
}

impl MessageAccumulator {
    /// An accumulator with the [`DEFAULT_MAX_STREAM_BYTES`] content cap.
    #[must_use]
    pub const fn new() -> Self {
        Self::with_limit(DEFAULT_MAX_STREAM_BYTES)
    }

    /// An accumulator that fails once more than `max_bytes` of content
    /// (text, thinking, tool input) has arrived.
    #[must_use]
    pub const fn with_limit(max_bytes: usize) -> Self {
        Self {
            id: String::new(),
            model: String::new(),
            slots: Vec::new(),
            stop_reason: None,
            usage: Usage::new(0, 0, 0, 0),
            bytes: 0,
            max_bytes,
            started: false,
            finished: false,
        }
    }

    /// `true` once `message_stop` has been seen.
    #[must_use]
    pub const fn is_finished(&self) -> bool {
        self.finished
    }

    /// Consume one SSE `data` payload. Returns the event it completes, if
    /// any (pings, starts and unknown event types yield `None`).
    ///
    /// # Errors
    ///
    /// [`LlmError::invalid_response`] for malformed JSON, protocol violations
    /// (deltas to unknown or closed blocks, mismatched delta kinds, events
    /// after `message_stop`), tool input that is not a JSON object, or
    /// content above the size cap; a classified [`LlmError`] for an
    /// `error` event.
    pub fn push(&mut self, data: &str) -> Result<Option<StreamEvent>, LlmError> {
        let event: SseEvent = serde_json::from_str(data)
            .map_err(|e| invalid(format!("malformed stream event: {e}")))?;
        if self.finished && !matches!(event, SseEvent::Unknown) {
            return Err(invalid("stream event after `message_stop`"));
        }
        match event {
            SseEvent::MessageStart { message } => {
                if self.started {
                    return Err(invalid("duplicate `message_start`"));
                }
                self.started = true;
                self.id = message.id;
                self.model = message.model;
                self.usage.merge(&message.usage);
                Ok(None)
            }
            SseEvent::ContentBlockStart {
                index,
                content_block,
            } => self.start_block(index, content_block),
            SseEvent::ContentBlockDelta { index, delta } => self.delta(index, delta),
            SseEvent::ContentBlockStop { index } => self.stop_block(index),
            SseEvent::MessageDelta { delta, usage } => {
                if delta.stop_reason.is_some() {
                    self.stop_reason = delta.stop_reason;
                }
                self.usage.merge(&usage);
                Ok(None)
            }
            SseEvent::MessageStop => {
                self.finished = true;
                Ok(Some(StreamEvent::Done(self.snapshot()?)))
            }
            SseEvent::Error { error } => Err(error.into_llm_error()),
            SseEvent::Unknown => Ok(None),
        }
    }

    /// The response assembled so far. Blocks still open are included as
    /// far as they are complete (an open tool call is left out).
    fn snapshot(&self) -> Result<MessageResponse, LlmError> {
        let mut content = Vec::with_capacity(self.slots.len());
        for slot in &self.slots {
            if let Some(block) = &slot.done {
                content.push(block.clone());
            } else if let Some(block) = finish_partial(&slot.partial, false)? {
                content.push(block);
            }
        }
        Ok(MessageResponse {
            id: self.id.clone(),
            model: self.model.clone(),
            content,
            stop_reason: self.stop_reason.clone(),
            usage: self.usage,
        })
    }

    /// Finish after the transport ended.
    ///
    /// # Errors
    ///
    /// [`LlmError::invalid_response`] if `message_stop` never arrived — a
    /// truncated stream is never mistaken for a complete one.
    pub fn finish(self) -> Result<MessageResponse, LlmError> {
        if !self.finished {
            return Err(invalid("event stream ended before `message_stop`"));
        }
        self.snapshot()
    }

    fn charge(&mut self, n: usize) -> Result<(), LlmError> {
        self.bytes = self.bytes.saturating_add(n);
        if self.bytes > self.max_bytes {
            return Err(invalid(format!(
                "streamed response exceeds the {}-byte limit",
                self.max_bytes
            )));
        }
        Ok(())
    }

    fn start_block(
        &mut self,
        index: usize,
        block: ResponseContentBlock,
    ) -> Result<Option<StreamEvent>, LlmError> {
        if index != self.slots.len() {
            return Err(invalid(format!(
                "content block {index} started out of order (expected {})",
                self.slots.len()
            )));
        }
        if index >= MAX_BLOCKS {
            return Err(invalid("too many content blocks"));
        }
        let partial = match block {
            ResponseContentBlock::Text { text } => {
                self.charge(text.len())?;
                Partial::Text(text)
            }
            ResponseContentBlock::Thinking {
                thinking,
                signature,
            } => {
                self.charge(thinking.len() + signature.len())?;
                Partial::Thinking {
                    thinking,
                    signature,
                }
            }
            ResponseContentBlock::RedactedThinking { data } => {
                self.charge(data.len())?;
                Partial::Redacted(data)
            }
            ResponseContentBlock::ToolUse { id, name, input } => {
                let input_len = serde_json::to_string(&input).map_or(0, |s| s.len());
                self.charge(id.len() + name.len() + input_len)?;
                Partial::ToolUse {
                    id,
                    name,
                    initial: input,
                    json: String::new(),
                }
            }
            ResponseContentBlock::Unknown => Partial::Unknown,
        };
        self.slots.push(Slot {
            partial,
            done: None,
            closed: false,
        });
        Ok(None)
    }

    fn open_slot(&mut self, index: usize) -> Result<&mut Slot, LlmError> {
        match self.slots.get_mut(index) {
            Some(slot) if !slot.closed => Ok(slot),
            Some(_) => Err(invalid(format!("content block {index} is already closed"))),
            None => Err(invalid(format!("content block {index} was never started"))),
        }
    }

    fn delta(&mut self, index: usize, delta: Delta) -> Result<Option<StreamEvent>, LlmError> {
        let len = match &delta {
            Delta::Text { text } => text.len(),
            Delta::InputJson { partial_json } => partial_json.len(),
            Delta::Thinking { thinking } => thinking.len(),
            Delta::Signature { signature } => signature.len(),
            Delta::Other => 0,
        };
        self.charge(len)?;
        let slot = self.open_slot(index)?;
        match (&mut slot.partial, delta) {
            (Partial::Text(buf), Delta::Text { text }) => {
                buf.push_str(&text);
                Ok((!text.is_empty()).then_some(StreamEvent::Text(text)))
            }
            (Partial::ToolUse { json, .. }, Delta::InputJson { partial_json }) => {
                json.push_str(&partial_json);
                Ok(None)
            }
            (Partial::Thinking { thinking: buf, .. }, Delta::Thinking { thinking }) => {
                buf.push_str(&thinking);
                Ok((!thinking.is_empty()).then_some(StreamEvent::Thinking(thinking)))
            }
            (Partial::Thinking { signature: buf, .. }, Delta::Signature { signature }) => {
                buf.push_str(&signature);
                Ok(None)
            }
            // New delta kinds (e.g. citations) and blocks we do not model.
            (_, Delta::Other) | (Partial::Unknown, _) => Ok(None),
            (_, _) => Err(invalid(format!(
                "delta kind does not match content block {index}"
            ))),
        }
    }

    fn stop_block(&mut self, index: usize) -> Result<Option<StreamEvent>, LlmError> {
        let slot = self.open_slot(index)?;
        slot.closed = true;
        let block = finish_partial(&slot.partial, true)?;
        let event = match &block {
            Some(ContentBlock::ToolUse { id, name, input }) => Some(StreamEvent::ToolCall(
                ToolCall::new(id.clone(), name.clone(), input.to_string()),
            )),
            _ => None,
        };
        slot.done = block;
        Ok(event)
    }
}

/// Turn a partial block into a content block. An unclosed tool call yields
/// `None`: its input may be incomplete JSON.
fn finish_partial(partial: &Partial, closed: bool) -> Result<Option<ContentBlock>, LlmError> {
    Ok(match partial {
        Partial::Text(text) => Some(ContentBlock::Text { text: text.clone() }),
        Partial::Thinking {
            thinking,
            signature,
        } => Some(ContentBlock::Thinking {
            thinking: thinking.clone(),
            signature: signature.clone(),
        }),
        Partial::Redacted(data) => Some(ContentBlock::RedactedThinking { data: data.clone() }),
        Partial::ToolUse { .. } if !closed => None,
        Partial::ToolUse {
            id,
            name,
            initial,
            json,
        } => Some(ContentBlock::ToolUse {
            id: id.clone(),
            name: name.clone(),
            input: tool_input(initial, json)?,
        }),
        Partial::Unknown => None,
    })
}

/// The tool input: the concatenated `input_json_delta` fragments, or the
/// `content_block_start` input when no fragment arrived (a tool without
/// arguments).
fn tool_input(initial: &Value, json: &str) -> Result<Value, LlmError> {
    if json.trim().is_empty() {
        return Ok(match initial {
            Value::Null => Value::Object(serde_json::Map::new()),
            other => other.clone(),
        });
    }
    let value: Value = serde_json::from_str(json).map_err(|e| {
        invalid(format!(
            "tool input is not valid JSON (possibly cut off at max_tokens): {e}"
        ))
    })?;
    if !value.is_object() {
        return Err(invalid("tool input is not a JSON object"));
    }
    Ok(value)
}

fn invalid(message: impl Into<String>) -> LlmError {
    LlmError::invalid_response(message)
}
