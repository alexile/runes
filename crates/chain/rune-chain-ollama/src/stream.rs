//! Streaming: a sans-I/O assembler that turns `/api/chat` NDJSON lines into
//! [`StreamEvent`]s (text, thinking, tool calls, finish reason, usage).

use std::pin::Pin;

use futures::{Stream, StreamExt};
use rune_chain_core::{GenerateResult, LlmError, StreamData, TokenUsage, ToolCall};
use serde_json::Value;

use crate::ndjson::{self, Limits};
use crate::types::{ApiToolCallIn, ChatChunk, error_message};

/// Most tool calls one response may carry.
pub const MAX_TOOL_CALLS: usize = 128;

/// One event of a streamed chat response, from
/// [`Ollama::stream_events`](crate::Ollama::stream_events).
///
/// A well-formed stream yields any number of [`Thinking`](Self::Thinking),
/// [`Text`](Self::Text) and [`ToolCalls`](Self::ToolCalls) events, then
/// [`Finished`](Self::Finished), optionally [`Usage`](Self::Usage), and ends
/// with [`Done`](Self::Done). Errors end the stream.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum StreamEvent {
    /// A non-empty fragment of the model's reasoning (with
    /// [`Ollama::think`](crate::Ollama::think) on a thinking model).
    Thinking(String),
    /// A non-empty fragment of the assistant's text.
    Text(String),
    /// Complete tool calls. Ollama sends whole calls rather than deltas, so
    /// each event carries finished calls with ids unique within the stream.
    ToolCalls(Vec<ToolCall>),
    /// The model stopped; `reason` is Ollama's `done_reason` (`"stop"`,
    /// `"length"`, `"load"`, …), or `"stop"` when the server sent none.
    Finished {
        /// The provider's `done_reason`.
        reason: String,
    },
    /// Token usage for the whole request.
    Usage(TokenUsage),
    /// The end of the stream.
    Done,
}

/// A boxed stream of [`StreamEvent`]s.
pub type EventStream = Pin<Box<dyn Stream<Item = Result<StreamEvent, LlmError>> + Send>>;

/// Drain an [`EventStream`] into a [`GenerateResult`]: the concatenated text,
/// every tool call and the reported usage. Thinking text is dropped.
///
/// ```rust,no_run
/// use rune_chain_core::Message;
/// use rune_chain_ollama::{Ollama, collect_events};
///
/// # tokio_test::block_on(async {
/// let llm = Ollama::new();
/// let events = llm.stream_events(&[Message::human("Hi")], &[], None).await.unwrap();
/// let result = collect_events(events).await.unwrap();
/// println!("{} ({:?})", result.generation, result.tokens);
/// # });
/// ```
///
/// # Errors
///
/// The first error the stream yields.
pub async fn collect_events<S>(mut events: S) -> Result<GenerateResult, LlmError>
where
    S: Stream<Item = Result<StreamEvent, LlmError>> + Unpin,
{
    let mut result = GenerateResult::from_text("");
    while let Some(event) = events.next().await {
        match event? {
            StreamEvent::Text(t) => result.generation.push_str(&t),
            StreamEvent::ToolCalls(calls) => result.tool_calls.extend(calls),
            StreamEvent::Usage(u) => result.tokens = Some(u),
            StreamEvent::Thinking(_) | StreamEvent::Finished { .. } => {}
            StreamEvent::Done => break,
        }
    }
    Ok(result)
}

/// Token usage from Ollama's eval counts, when both are present.
pub const fn usage(prompt: Option<u32>, completion: Option<u32>) -> Option<TokenUsage> {
    match (prompt, completion) {
        (Some(p), Some(c)) => Some(TokenUsage::new(p, c)),
        _ => None,
    }
}

/// Convert Ollama tool calls, numbering synthetic ids from `first_index`.
///
/// Ollama sends `arguments` as a JSON object; it is re-encoded as the JSON
/// string [`ToolCall::arguments`] expects (a string is passed through, a
/// missing value becomes `{}`).
pub fn convert_tool_calls(
    calls: Vec<ApiToolCallIn>,
    first_index: usize,
) -> Result<Vec<ToolCall>, LlmError> {
    if calls.len() > MAX_TOOL_CALLS {
        return Err(LlmError::invalid_response(format!(
            "response has more than {MAX_TOOL_CALLS} tool calls"
        )));
    }
    calls
        .into_iter()
        .enumerate()
        .map(|(i, call)| {
            let index = first_index.saturating_add(i);
            if call.function.name.trim().is_empty() {
                return Err(LlmError::invalid_response(format!(
                    "tool call {index} has no function name"
                )));
            }
            let arguments = match call.function.arguments {
                Value::Null => "{}".to_string(),
                Value::String(s) => s,
                other => other.to_string(),
            };
            Ok(ToolCall {
                id: call
                    .id
                    .filter(|id| !id.is_empty())
                    .unwrap_or_else(|| format!("call_{index}")),
                name: call.function.name,
                arguments,
            })
        })
        .collect()
}

/// Decode one NDJSON line: a chat chunk, or Ollama's `{"error": …}`.
fn decode_line(line: &[u8]) -> Result<ChatChunk, LlmError> {
    serde_json::from_slice::<ChatChunk>(line).map_err(|e| {
        serde_json::from_slice::<Value>(line)
            .ok()
            .as_ref()
            .and_then(error_message)
            .map_or_else(
                || LlmError::invalid_response(format!("undecodable stream line: {e}")),
                |m| LlmError::provider(crate::http::truncate(&m, crate::http::MAX_ERROR_CHARS)),
            )
    })
}

/// Sans-I/O state machine over `/api/chat` stream lines.
#[derive(Debug, Default)]
pub struct Assembler {
    tool_calls: usize,
    done: bool,
}

impl Assembler {
    /// Feed one line (without its `\n`); returns the events it produces.
    /// Blank lines produce nothing; lines after `done` are ignored.
    pub fn push(&mut self, line: &[u8]) -> Result<Vec<StreamEvent>, LlmError> {
        let mut out = Vec::new();
        if self.done || line.iter().all(u8::is_ascii_whitespace) {
            return Ok(out);
        }
        let chunk = decode_line(line)?;
        if let Some(message) = chunk.message {
            if let Some(thinking) = message.thinking.filter(|t| !t.is_empty()) {
                out.push(StreamEvent::Thinking(thinking));
            }
            if !message.content.is_empty() {
                out.push(StreamEvent::Text(message.content));
            }
            if !message.tool_calls.is_empty() {
                if self.tool_calls.saturating_add(message.tool_calls.len()) > MAX_TOOL_CALLS {
                    return Err(LlmError::invalid_response(format!(
                        "stream has more than {MAX_TOOL_CALLS} tool calls"
                    )));
                }
                let calls = convert_tool_calls(message.tool_calls, self.tool_calls)?;
                self.tool_calls += calls.len();
                out.push(StreamEvent::ToolCalls(calls));
            }
        }
        if chunk.done {
            self.done = true;
            out.push(StreamEvent::Finished {
                reason: chunk
                    .done_reason
                    .filter(|r| !r.is_empty())
                    .unwrap_or_else(|| "stop".into()),
            });
            if let Some(u) = usage(chunk.prompt_eval_count, chunk.eval_count) {
                out.push(StreamEvent::Usage(u));
            }
            out.push(StreamEvent::Done);
        }
        Ok(out)
    }

    /// Call at end of input: a stream that ends before `"done": true` was
    /// truncated.
    pub fn finish(&self) -> Result<(), LlmError> {
        if self.done {
            Ok(())
        } else {
            Err(LlmError::invalid_response(
                "stream ended before a `done` message",
            ))
        }
    }
}

/// Turn an NDJSON byte stream into [`StreamEvent`]s under `limits`. Ends
/// after [`StreamEvent::Done`] or the first error; never panics on bad input.
pub fn assemble_events<S, B, E>(body: S, limits: Limits) -> EventStream
where
    S: Stream<Item = Result<B, E>> + Send + Unpin + 'static,
    B: AsRef<[u8]> + Send + 'static,
    E: std::fmt::Display + Send + 'static,
{
    let mut lines = Box::pin(ndjson::lines(body, limits));
    Box::pin(async_stream::stream! {
        let mut asm = Assembler::default();
        while let Some(line) = lines.next().await {
            let events = match line.and_then(|l| asm.push(&l)) {
                Ok(events) => events,
                Err(e) => {
                    yield Err(e);
                    return;
                }
            };
            for ev in events {
                let done = matches!(ev, StreamEvent::Done);
                yield Ok(ev);
                if done {
                    return;
                }
            }
        }
        if let Err(e) = asm.finish() {
            yield Err(e);
        }
    })
}

/// Adapt an [`EventStream`] to core [`StreamEvent`](rune_chain_core::StreamEvent)s
/// for [`Llm::stream_events`](rune_chain_core::Llm::stream_events).
///
/// Ollama sends tool calls whole, so each one becomes a start, one
/// argument fragment and an end, numbered across the stream. A `stop` with
/// tool calls finishes as [`FinishReason::ToolCalls`](rune_chain_core::FinishReason::ToolCalls),
/// as in the non-streaming reply.
pub fn core_events(mut events: EventStream) -> rune_chain_core::EventStream {
    use rune_chain_core::{FinishReason, MAX_TOOL_ARGUMENTS_BYTES, StreamEvent as E};
    Box::pin(async_stream::stream! {
        let mut next_index = 0usize;
        while let Some(event) = events.next().await {
            let event = match event {
                Ok(event) => event,
                Err(e) => {
                    yield Err(e);
                    return;
                }
            };
            match event {
                StreamEvent::Thinking(t) => yield Ok(E::reasoning(t)),
                StreamEvent::Text(t) => yield Ok(E::TextDelta(t)),
                StreamEvent::ToolCalls(calls) => {
                    for call in calls {
                        if call.arguments.len() > MAX_TOOL_ARGUMENTS_BYTES {
                            yield Err(LlmError::invalid_response(format!(
                                "tool call {next_index} has arguments over \
                                 {MAX_TOOL_ARGUMENTS_BYTES} bytes"
                            )));
                            return;
                        }
                        let index = next_index;
                        next_index += 1;
                        yield Ok(E::tool_call_start(index, call.id, call.name));
                        yield Ok(E::tool_call_delta(index, call.arguments));
                        yield Ok(E::ToolCallEnd { index });
                    }
                }
                StreamEvent::Finished { reason } => {
                    yield Ok(E::Finish(match reason.as_str() {
                        "stop" if next_index > 0 => FinishReason::ToolCalls,
                        _ => FinishReason::from(reason),
                    }));
                }
                StreamEvent::Usage(u) => yield Ok(E::Usage(u)),
                StreamEvent::Done => return,
            }
        }
    })
}

/// Adapt an [`EventStream`] to the [`Llm::stream`](rune_chain_core::Llm::stream)
/// shape: text chunks, then one terminal chunk.
pub fn text_stream(
    mut events: EventStream,
) -> Pin<Box<dyn Stream<Item = Result<StreamData, LlmError>> + Send>> {
    Box::pin(async_stream::stream! {
        while let Some(event) = events.next().await {
            match event {
                Ok(StreamEvent::Text(t)) => yield Ok(StreamData::chunk(t)),
                Ok(StreamEvent::Done) => {
                    yield Ok(StreamData::done());
                    return;
                }
                Ok(_) => {}
                Err(e) => {
                    yield Err(e);
                    return;
                }
            }
        }
    })
}
