//! Streaming: a sans-I/O assembler that turns `chat.completion.chunk` events
//! into [`StreamEvent`]s, stitching tool-call deltas back together.

use std::collections::BTreeMap;
use std::pin::Pin;

use futures::{Stream, StreamExt};
use rune_chain_core::{
    FinishReason, GenerateResult, LlmError, MAX_TOOL_ARGUMENTS_BYTES, ReasoningBlock, StreamData,
    StreamEvent as CoreEvent, TokenUsage, ToolCall,
};

use crate::types::{ChatChunk, ToolCallDelta, error_message};

/// Most tool calls one streamed response may assemble.
const MAX_TOOL_CALLS: usize = 128;

/// One event of a streamed chat completion, from
/// [`OpenAi::stream_events`](crate::OpenAi::stream_events).
///
/// A well-formed stream yields any number of [`Text`](Self::Text),
/// [`Reasoning`](Self::Reasoning) and [`Refusal`](Self::Refusal) events,
/// then at most one [`ToolCalls`](Self::ToolCalls) and one
/// [`Finished`](Self::Finished), and ends with [`Done`](Self::Done).
/// [`Usage`](Self::Usage) usually comes once near the end, but some servers
/// report it on every chunk. Errors end the stream.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum StreamEvent {
    /// A non-empty fragment of the assistant's text.
    Text(String),
    /// A non-empty fragment of the model's reasoning (`reasoning_content` or
    /// `reasoning` on compatible servers).
    Reasoning(String),
    /// A non-empty fragment of a refusal message.
    Refusal(String),
    /// Tool calls, fully assembled from their streamed deltas, in index order.
    ToolCalls(Vec<ToolCall>),
    /// The model stopped; `reason` is the provider's `finish_reason`
    /// (`"stop"`, `"length"`, `"tool_calls"`, `"content_filter"`, …).
    Finished {
        /// The provider's `finish_reason`.
        reason: String,
    },
    /// Token usage for the whole request.
    Usage(TokenUsage),
    /// The end of the stream.
    Done,
}

/// A boxed stream of [`StreamEvent`]s.
pub type EventStream = Pin<Box<dyn Stream<Item = Result<StreamEvent, LlmError>> + Send>>;

/// Drain an [`EventStream`] into a [`GenerateResult`].
///
/// The result holds the concatenated text and reasoning, the assembled tool
/// calls, the finish reason and the reported usage (if any). A stream that
/// only carries a refusal yields the refusal as text with
/// [`FinishReason::Refusal`].
///
/// ```rust,no_run
/// use rune_chain_core::Message;
/// use rune_chain_openai::{OpenAi, collect_events};
///
/// # tokio_test::block_on(async {
/// let llm = OpenAi::from_env().unwrap();
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
    let mut reasoning = String::new();
    let mut refusal = String::new();
    while let Some(event) = events.next().await {
        match event? {
            StreamEvent::Text(t) => result.generation.push_str(&t),
            StreamEvent::Reasoning(t) => reasoning.push_str(&t),
            StreamEvent::Refusal(t) => refusal.push_str(&t),
            StreamEvent::ToolCalls(calls) => result.tool_calls.extend(calls),
            StreamEvent::Usage(u) => result.tokens = Some(u),
            StreamEvent::Finished { reason } => {
                result.finish_reason = Some(crate::types::finish_reason(&reason));
            }
            StreamEvent::Done => break,
        }
    }
    if !reasoning.is_empty() {
        result.reasoning = vec![ReasoningBlock::new(reasoning)];
    }
    if result.generation.is_empty() && result.tool_calls.is_empty() && !refusal.is_empty() {
        result.generation = refusal;
        result.finish_reason = Some(FinishReason::Refusal);
    }
    Ok(result)
}

#[derive(Debug, Default)]
struct PartialCall {
    id: String,
    name: String,
    arguments: String,
    /// A core `ToolCallStart` went out for this call.
    started: bool,
}

/// State for translating to core [`CoreEvent`]s (tool-call fragments as
/// they arrive, refusals folded the way [`collect_events`] does).
#[derive(Debug, Default)]
struct CoreState {
    /// Start / argument events from tool-call deltas of the current chunk.
    fragments: Vec<CoreEvent>,
    /// Argument fill-ins and end events from the last flush.
    ends: Vec<CoreEvent>,
    refusal: String,
    saw_text: bool,
    saw_calls: bool,
    refusal_sent: bool,
}

impl CoreState {
    /// A refusal with no text or tool calls is the answer, as in
    /// [`collect_events`].
    const fn refusal_only(&self) -> bool {
        !self.refusal_sent && !self.saw_text && !self.saw_calls && !self.refusal.is_empty()
    }
}

/// Sans-I/O state machine over the `data` of SSE events.
#[derive(Debug, Default)]
pub struct Assembler {
    calls: BTreeMap<usize, PartialCall>,
    /// Wire `index` → key in `calls`. Usually the identity, but a server that
    /// reuses an index for a second call (new id) gets a fresh slot.
    slots: BTreeMap<usize, usize>,
    finished: bool,
    done: bool,
    /// Set when translating to core events.
    core: Option<CoreState>,
}

impl Assembler {
    /// An assembler that also tracks what [`push_core`](Self::push_core)
    /// needs.
    pub fn for_core_events() -> Self {
        Self {
            core: Some(CoreState::default()),
            ..Self::default()
        }
    }

    /// Like [`push`](Self::push), translated to core events: tool-call
    /// starts and argument fragments come out as they arrive.
    pub fn push_core(&mut self, data: &str) -> Result<Vec<CoreEvent>, LlmError> {
        let events = self.push(data)?;
        Ok(self.translate(events))
    }

    /// Like [`finish`](Self::finish), translated to core events.
    pub fn finish_core(&mut self) -> Result<Vec<CoreEvent>, LlmError> {
        let events = self.finish()?;
        Ok(self.translate(events))
    }

    fn translate(&mut self, events: Vec<StreamEvent>) -> Vec<CoreEvent> {
        let Some(core) = self.core.as_mut() else {
            return Vec::new();
        };
        let mut fragments = std::mem::take(&mut core.fragments);
        let mut out = Vec::with_capacity(events.len() + fragments.len());
        for event in events {
            match event {
                StreamEvent::Text(t) => {
                    core.saw_text = true;
                    out.push(CoreEvent::TextDelta(t));
                }
                StreamEvent::Reasoning(t) => out.push(CoreEvent::reasoning(t)),
                StreamEvent::Refusal(t) => core.refusal.push_str(&t),
                StreamEvent::ToolCalls(_) => {
                    core.saw_calls = true;
                    out.append(&mut fragments);
                    out.append(&mut core.ends);
                }
                StreamEvent::Finished { reason } => {
                    out.append(&mut fragments);
                    let reason = if core.refusal_only() {
                        core.refusal_sent = true;
                        out.push(CoreEvent::TextDelta(std::mem::take(&mut core.refusal)));
                        FinishReason::Refusal
                    } else {
                        crate::types::finish_reason(&reason)
                    };
                    out.push(CoreEvent::Finish(reason));
                }
                StreamEvent::Usage(u) => {
                    out.append(&mut fragments);
                    out.push(CoreEvent::Usage(u));
                }
                StreamEvent::Done => {
                    out.append(&mut fragments);
                    if core.refusal_only() {
                        core.refusal_sent = true;
                        out.push(CoreEvent::TextDelta(std::mem::take(&mut core.refusal)));
                        out.push(CoreEvent::Finish(FinishReason::Refusal));
                    }
                }
            }
        }
        out.append(&mut fragments);
        out
    }
    /// Feed one event's data; returns the events it produces.
    pub fn push(&mut self, data: &str) -> Result<Vec<StreamEvent>, LlmError> {
        let data = data.trim();
        let mut out = Vec::new();
        if data == "[DONE]" {
            self.flush_calls(&mut out)?;
            self.done = true;
            out.push(StreamEvent::Done);
            return Ok(out);
        }
        if data.is_empty() {
            return Ok(out);
        }
        let chunk: ChatChunk = serde_json::from_str(data).map_err(|e| {
            serde_json::from_str::<serde_json::Value>(data)
                .ok()
                .and_then(|v| error_event(&v))
                .unwrap_or_else(|| {
                    LlmError::invalid_response(format!("undecodable stream event: {e}"))
                })
        })?;
        if let Some(err) = &chunk.error {
            let value = serde_json::json!({ "error": err });
            return Err(
                error_event(&value).unwrap_or_else(|| LlmError::provider("error event in stream"))
            );
        }
        if chunk.choices.is_empty()
            && chunk.usage.is_none()
            && chunk.x_groq.is_none()
            && let Some(err) = bare_error(data)
        {
            return Err(err);
        }
        for choice in chunk.choices.into_iter().filter(|c| c.index == 0) {
            let delta = choice.delta;
            if let Some(text) = delta.reasoning_content.filter(|t| !t.is_empty()) {
                out.push(StreamEvent::Reasoning(text));
            }
            if let Some(text) = delta.content.filter(|t| !t.is_empty()) {
                out.push(StreamEvent::Text(text));
            }
            if let Some(text) = delta.refusal.filter(|t| !t.is_empty()) {
                out.push(StreamEvent::Refusal(text));
            }
            for (pos, delta) in delta.tool_calls.into_iter().enumerate() {
                self.merge(pos, delta)?;
            }
            if let Some(reason) = choice.finish_reason.filter(|r| !r.is_empty()) {
                self.flush_calls(&mut out)?;
                self.finished = true;
                out.push(StreamEvent::Finished { reason });
            }
        }
        if let Some(usage) = chunk.usage.or_else(|| chunk.x_groq.and_then(|x| x.usage)) {
            out.push(StreamEvent::Usage(usage.into_usage()));
        }
        Ok(out)
    }

    /// Call at end of input. A stream that ends before `[DONE]` is complete
    /// only if a `finish_reason` was seen; otherwise it was truncated.
    pub fn finish(&mut self) -> Result<Vec<StreamEvent>, LlmError> {
        if self.done {
            return Ok(Vec::new());
        }
        if !self.finished {
            return Err(LlmError::invalid_response(
                "event stream ended before `[DONE]`",
            ));
        }
        let mut out = Vec::new();
        self.flush_calls(&mut out)?;
        self.done = true;
        out.push(StreamEvent::Done);
        Ok(out)
    }

    /// Merge one tool-call delta. `OpenAI` sends `index` on every delta and
    /// `id`/`name` only on the first; some compatible servers omit `index`
    /// and send whole calls, which are keyed by `id` instead. A new id at an
    /// index that already holds a different call starts a new call.
    fn merge(&mut self, pos: usize, delta: ToolCallDelta) -> Result<(), LlmError> {
        let id = delta.id.filter(|s| !s.is_empty());
        let index = match delta.index {
            Some(i) => self.slot_for(i, id.as_deref()),
            None => match &id {
                Some(id) => self
                    .calls
                    .iter()
                    .find(|(_, c)| &c.id == id)
                    .map_or_else(|| self.next_index().max(pos), |(i, _)| *i),
                None => self.calls.keys().next_back().copied().unwrap_or(pos),
            },
        };
        if !self.calls.contains_key(&index) && self.calls.len() >= MAX_TOOL_CALLS {
            return Err(LlmError::invalid_response(format!(
                "stream has more than {MAX_TOOL_CALLS} tool calls"
            )));
        }
        let call = self.calls.entry(index).or_default();
        if let Some(id) = id
            && call.id.is_empty()
        {
            call.id = id;
        }
        let mut fragment = None;
        if let Some(f) = delta.function {
            if let Some(name) = f.name.filter(|n| !n.is_empty())
                && call.name.is_empty()
            {
                call.name = name;
            }
            if let Some(args) = f.arguments {
                if call.arguments.len().saturating_add(args.len()) > MAX_TOOL_ARGUMENTS_BYTES {
                    return Err(LlmError::invalid_response(format!(
                        "streamed tool call {index} has arguments over \
                         {MAX_TOOL_ARGUMENTS_BYTES} bytes"
                    )));
                }
                call.arguments.push_str(&args);
                fragment = Some(args);
            }
        }
        if let Some(core) = self.core.as_mut() {
            // Start once the name is known; arguments seen before that go
            // out with the start.
            if !call.started && !call.name.is_empty() {
                call.started = true;
                core.fragments.push(CoreEvent::tool_call_start(
                    index,
                    call_id(&call.id, index),
                    call.name.clone(),
                ));
                if !call.arguments.is_empty() {
                    core.fragments
                        .push(CoreEvent::tool_call_delta(index, call.arguments.clone()));
                }
            } else if call.started
                && let Some(args) = fragment.filter(|a| !a.is_empty())
            {
                core.fragments.push(CoreEvent::tool_call_delta(index, args));
            }
        }
        Ok(())
    }

    /// The `calls` key for wire index `wire`, given the delta's id (if any).
    fn slot_for(&mut self, wire: usize, id: Option<&str>) -> usize {
        let current = self.slots.get(&wire).copied();
        let slot = match current {
            Some(slot) => {
                let taken_by_other = id.is_some_and(|id| {
                    self.calls
                        .get(&slot)
                        .is_some_and(|c| !c.id.is_empty() && c.id != id)
                });
                if !taken_by_other {
                    return slot;
                }
                self.next_index()
            }
            None if self.calls.contains_key(&wire) => self.next_index(),
            None => wire,
        };
        self.slots.insert(wire, slot);
        slot
    }

    fn next_index(&self) -> usize {
        self.calls.keys().next_back().map_or(0, |i| i + 1)
    }

    fn flush_calls(&mut self, out: &mut Vec<StreamEvent>) -> Result<(), LlmError> {
        if self.calls.is_empty() {
            return Ok(());
        }
        self.slots.clear();
        if let Some(core) = self.core.as_mut() {
            for (&index, c) in &self.calls {
                if c.started && c.arguments.is_empty() {
                    core.ends.push(CoreEvent::tool_call_delta(index, "{}"));
                }
                core.ends.push(CoreEvent::ToolCallEnd { index });
            }
        }
        let calls = std::mem::take(&mut self.calls)
            .into_iter()
            .map(|(index, c)| {
                if c.name.is_empty() {
                    return Err(LlmError::invalid_response(format!(
                        "streamed tool call {index} has no function name"
                    )));
                }
                let id = call_id(&c.id, index);
                let arguments = if c.arguments.trim().is_empty() {
                    "{}".to_string()
                } else {
                    c.arguments
                };
                Ok(ToolCall {
                    id,
                    name: c.name,
                    arguments,
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        out.push(StreamEvent::ToolCalls(calls));
        Ok(())
    }
}

/// Turn an SSE byte stream into [`StreamEvent`]s. Ends after
/// [`StreamEvent::Done`] or the first error; never panics on bad input.
pub fn assemble_events<S, B, E>(body: S, max_event_len: usize) -> EventStream
where
    S: Stream<Item = Result<B, E>> + Send + Unpin + 'static,
    B: AsRef<[u8]>,
    E: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    drive(
        body,
        max_event_len,
        Assembler::default(),
        Assembler::push,
        Assembler::finish,
    )
}

/// Turn an SSE byte stream into core [`CoreEvent`]s, with tool-call
/// fragments as they arrive. Same parser and limits as [`assemble_events`].
pub fn assemble_core_events<S, B, E>(body: S, max_event_len: usize) -> rune_chain_core::EventStream
where
    S: Stream<Item = Result<B, E>> + Send + Unpin + 'static,
    B: AsRef<[u8]>,
    E: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    drive(
        body,
        max_event_len,
        Assembler::for_core_events(),
        Assembler::push_core,
        Assembler::finish_core,
    )
}

type Step<T> = fn(&mut Assembler, &str) -> Result<Vec<T>, LlmError>;
type Finish<T> = fn(&mut Assembler) -> Result<Vec<T>, LlmError>;

/// Feed SSE events to `asm` until `[DONE]`, the end of input or an error.
fn drive<S, B, E, T>(
    body: S,
    max_event_len: usize,
    mut asm: Assembler,
    step: Step<T>,
    finish: Finish<T>,
) -> Pin<Box<dyn Stream<Item = Result<T, LlmError>> + Send>>
where
    S: Stream<Item = Result<B, E>> + Send + Unpin + 'static,
    B: AsRef<[u8]>,
    E: Into<Box<dyn std::error::Error + Send + Sync>>,
    T: Send + 'static,
{
    let options = rune_sse::Options::default()
        .with_max_event_len(max_event_len)
        .with_max_line_len(max_event_len);
    let mut sse = rune_sse::SseStream::with_options(body, options);
    Box::pin(async_stream::stream! {
        while let Some(item) = sse.next().await {
            let event = match item {
                Ok(item) => match item.into_event() {
                    Some(event) => event,
                    None => continue,
                },
                Err(e) => {
                    yield Err(sse_error(&e));
                    return;
                }
            };
            match step(&mut asm, &event.data) {
                Ok(events) => {
                    for ev in events {
                        yield Ok(ev);
                    }
                    if asm.done {
                        return;
                    }
                }
                Err(e) => {
                    yield Err(e);
                    return;
                }
            }
        }
        match finish(&mut asm) {
            Ok(events) => for ev in events { yield Ok(ev); },
            Err(e) => yield Err(e),
        }
    })
}

/// Adapt an [`EventStream`] to the [`Llm::stream`](rune_chain_core::Llm::stream)
/// shape: text chunks, then one terminal chunk at the first `finish_reason`
/// (or `[DONE]`).
pub fn text_stream(
    mut events: EventStream,
) -> Pin<Box<dyn Stream<Item = Result<StreamData, LlmError>> + Send>> {
    Box::pin(async_stream::stream! {
        while let Some(event) = events.next().await {
            match event {
                Ok(StreamEvent::Text(t)) => yield Ok(StreamData::chunk(t)),
                Ok(StreamEvent::Finished { .. } | StreamEvent::Done) => {
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

/// The call id, or `call_<index>` when the server sent none.
fn call_id(id: &str, index: usize) -> String {
    if id.is_empty() {
        format!("call_{index}")
    } else {
        id.to_owned()
    }
}

/// An error object sent as a stream event, classified by its code.
fn error_event(value: &serde_json::Value) -> Option<LlmError> {
    let message = error_message(value)?;
    let err = LlmError::provider(message);
    Some(match crate::types::error_kind(value) {
        Some(kind) => err.with_kind(kind),
        None => err,
    })
}

/// A chunk with no choices or usage that is really an error object with only
/// top-level fields (`{"object":"error","message":…}`, `{"detail":…}`).
fn bare_error(data: &str) -> Option<LlmError> {
    let value: serde_json::Value = serde_json::from_str(data).ok()?;
    let is_error = |k: &str| value.get(k).and_then(serde_json::Value::as_str) == Some("error");
    if is_error("object") || is_error("type") {
        return Some(
            error_event(&value).unwrap_or_else(|| LlmError::provider("error event in stream")),
        );
    }
    if value.get("message").is_some() || value.get("detail").is_some() {
        return error_event(&value);
    }
    None
}

/// Describe an event-stream failure, including its underlying cause.
fn sse_error(e: &rune_sse::Error) -> LlmError {
    use std::error::Error as _;
    let message = e
        .source()
        .map_or_else(|| e.to_string(), |source| format!("{e}: {source}"));
    match e {
        rune_sse::Error::Transport(_) | rune_sse::Error::Io(_) => LlmError::request_failed(message),
        _ => LlmError::invalid_response(message),
    }
}
