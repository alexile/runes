//! Sans-I/O assembly of a streamed `streamGenerateContent` response.

use rune_chain_core::{LlmError, MAX_TOOL_ARGUMENTS_BYTES, StreamEvent as CoreEvent, ToolCall};

use crate::http::{Credential, api_error};
use crate::response::{
    GeminiResponse, ResponsePart, SafetyRating, Usage, blocked_prompt, convert_part,
};
use crate::types::GenerateContentResponse;

/// Default cap on the content a streamed response may accumulate (text,
/// thoughts, function-call arguments and signatures together).
pub const DEFAULT_MAX_STREAM_BYTES: usize = 32 << 20;
/// Longest single SSE line or event accepted from the wire.
pub const MAX_SSE_EVENT_BYTES: usize = 16 << 20;
/// Most SSE events one stream may carry.
pub const MAX_STREAM_EVENTS: usize = 1 << 20;
/// Most content parts one response may hold.
const MAX_PARTS: usize = 4096;

/// One step of a streamed response, as yielded by
/// [`Gemini::stream_content`](crate::Gemini::stream_content).
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum StreamEvent {
    /// A fragment of visible text.
    Text(String),
    /// A fragment of a thought summary.
    Thought(String),
    /// A complete function call (Gemini streams each call whole).
    ToolCall(ToolCall),
    /// The final, fully assembled response; always the last event.
    Done(GeminiResponse),
}

/// Incrementally assembles the SSE `data` payloads of one streamed response
/// into a [`GeminiResponse`].
///
/// Each payload is a partial `GenerateContentResponse`. Text and thought
/// fragments are appended to the previous part of the same kind; function
/// calls arrive whole. A stream has no end marker, so it is complete only if
/// a chunk carried a `finishReason`: [`finish`](Self::finish) fails
/// otherwise. A blocked prompt, an in-stream `error` object, malformed JSON
/// and content above the size cap are errors; nothing panics.
///
/// ```rust
/// use rune_chain_gemini::{ResponseAccumulator, StreamEvent};
///
/// let mut acc = ResponseAccumulator::new();
/// let chunks = [
///     r#"{"candidates":[{"content":{"role":"model","parts":[{"text":"Hel"}]}}],"responseId":"r1"}"#,
///     r#"{"candidates":[{"content":{"role":"model","parts":[{"text":"lo"}]}}]}"#,
///     r#"{"candidates":[{"content":{"role":"model","parts":[{"functionCall":{"name":"f","args":{"x":1}}}]},"finishReason":"STOP"}],
///        "usageMetadata":{"promptTokenCount":4,"candidatesTokenCount":3}}"#,
/// ];
/// let mut events = Vec::new();
/// for data in chunks {
///     events.extend(acc.push(data).unwrap());
/// }
/// assert_eq!(events[0], StreamEvent::Text("Hel".into()));
/// let StreamEvent::ToolCall(call) = &events[2] else { panic!() };
/// assert_eq!(call.arguments, r#"{"x":1}"#);
/// let done = acc.finish().unwrap();
/// assert_eq!(done.text(), "Hello");
/// assert_eq!(done.usage().prompt_tokens, 4);
/// ```
#[derive(Debug)]
pub struct ResponseAccumulator {
    response: GeminiResponse,
    calls: usize,
    bytes: usize,
    max_bytes: usize,
    events: usize,
    credential: Option<Credential>,
    /// Core events from the current `push`, when translating.
    core: Option<Vec<CoreEvent>>,
}

impl Default for ResponseAccumulator {
    fn default() -> Self {
        Self::new()
    }
}

impl ResponseAccumulator {
    /// An accumulator with the [`DEFAULT_MAX_STREAM_BYTES`] content cap.
    #[must_use]
    pub fn new() -> Self {
        Self::with_limit(DEFAULT_MAX_STREAM_BYTES)
    }

    /// An accumulator that fails once more than `max_bytes` of content has
    /// arrived.
    #[must_use]
    pub fn with_limit(max_bytes: usize) -> Self {
        Self {
            response: GeminiResponse::default(),
            calls: 0,
            bytes: 0,
            max_bytes,
            events: 0,
            credential: None,
            core: None,
        }
    }

    /// Translate to core events with [`push_core`](Self::push_core).
    #[must_use]
    pub fn for_core_events(mut self) -> Self {
        self.core = Some(Vec::new());
        self
    }

    /// Like [`push`](Self::push), translated to core
    /// [`StreamEvent`](rune_chain_core::StreamEvent)s: text and thought
    /// deltas as they arrive, each function call (start, arguments, end) as
    /// soon as its part does, and thought signatures as reasoning
    /// signatures, so the folded result carries them where
    /// [`GeminiResponse::to_generate_result`] puts them.
    ///
    /// # Errors
    ///
    /// As [`push`](Self::push).
    pub fn push_core(&mut self, data: &str) -> Result<Vec<CoreEvent>, LlmError> {
        if self.core.is_none() {
            self.core = Some(Vec::new());
        }
        self.push(data)?;
        Ok(self.core.as_mut().map(std::mem::take).unwrap_or_default())
    }

    /// Like [`finish`](Self::finish): usage and the finish reason as core
    /// events.
    ///
    /// # Errors
    ///
    /// As [`finish`](Self::finish).
    pub fn finish_core(self) -> Result<Vec<CoreEvent>, LlmError> {
        let result = self.finish()?.to_generate_result();
        Ok(result
            .tokens
            .map(CoreEvent::Usage)
            .into_iter()
            .chain(result.finish_reason.map(CoreEvent::Finish))
            .collect())
    }

    fn emit(&mut self, event: CoreEvent) {
        if let Some(out) = self.core.as_mut() {
            out.push(event);
        }
    }

    fn emit_signature(&mut self, signature: Option<&String>) {
        if let Some(sig) = signature {
            self.emit(CoreEvent::ReasoningDelta {
                text: String::new(),
                signature: Some(sig.clone()),
            });
        }
    }

    /// Scrub this credential from in-stream error messages.
    pub(crate) fn scrubbing(mut self, credential: Credential) -> Self {
        self.credential = Some(credential);
        self
    }

    /// `true` once a chunk carried a `finishReason`.
    #[must_use]
    pub const fn is_finished(&self) -> bool {
        self.response.finish_reason.is_some()
    }

    fn charge(&mut self, n: usize) -> Result<(), LlmError> {
        self.bytes = self.bytes.saturating_add(n);
        if self.bytes > self.max_bytes {
            return Err(LlmError::invalid_response(format!(
                "streamed response exceeds the {}-byte limit",
                self.max_bytes
            )));
        }
        Ok(())
    }

    /// Consume one SSE `data` payload and return the events it completes.
    ///
    /// # Errors
    ///
    /// [`LlmError::invalid_response`] for malformed JSON, too many events
    /// or parts, or content above the cap; a `Provider` error for a blocked
    /// prompt; a classified error for an in-stream `error` object.
    pub fn push(&mut self, data: &str) -> Result<Vec<StreamEvent>, LlmError> {
        self.events += 1;
        if self.events > MAX_STREAM_EVENTS {
            return Err(LlmError::invalid_response("too many stream events"));
        }
        let chunk: GenerateContentResponse = serde_json::from_str(data)
            .map_err(|e| LlmError::invalid_response(format!("malformed stream chunk: {e}")))?;
        if let Some(error) = &chunk.error {
            let credential = self
                .credential
                .clone()
                .unwrap_or_else(|| Credential::ApiKey(String::new()));
            return Err(api_error(error, &credential));
        }
        if let Some(err) = chunk.prompt_feedback.as_ref().and_then(blocked_prompt) {
            return Err(err);
        }
        if let Some(id) = chunk.response_id.filter(|s| !s.is_empty()) {
            self.charge(id.len())?;
            self.response.response_id = id;
        }
        if let Some(version) = chunk.model_version.filter(|s| !s.is_empty()) {
            self.charge(version.len())?;
            self.response.model_version = version;
        }
        if let Some(usage) = &chunk.usage_metadata {
            self.response.usage = Usage::from_wire(usage);
        }
        let mut events = Vec::new();
        let Some(candidate) = chunk.candidates.into_iter().next() else {
            return Ok(events);
        };
        for part in candidate.content.map(|c| c.parts).unwrap_or_default() {
            let args_len = part
                .function_call
                .as_ref()
                .map_or(0, |c| c.args.to_string().len());
            if args_len > MAX_TOOL_ARGUMENTS_BYTES {
                return Err(LlmError::invalid_response(format!(
                    "function call arguments exceed {MAX_TOOL_ARGUMENTS_BYTES} bytes"
                )));
            }
            let size = part.text.as_ref().map_or(0, String::len)
                + part.thought_signature.as_ref().map_or(0, String::len)
                + part.function_call.as_ref().map_or(0, |c| c.name.len())
                + args_len;
            self.charge(size)?;
            let response_id = self.response.response_id.clone();
            if let Some(part) = convert_part(part, &response_id, &mut self.calls)?
                && let Some(event) = self.add(part)?
            {
                events.push(event);
            }
        }
        if !candidate.safety_ratings.is_empty() {
            self.response.safety_ratings = candidate
                .safety_ratings
                .into_iter()
                .map(SafetyRating::from)
                .collect();
        }
        if candidate.finish_message.is_some() {
            self.response.finish_message = candidate.finish_message;
        }
        if candidate.finish_reason.is_some() {
            self.response.finish_reason = candidate.finish_reason;
        }
        Ok(events)
    }

    /// Merge a part into the response; returns the event it produces.
    fn add(&mut self, part: ResponsePart) -> Result<Option<StreamEvent>, LlmError> {
        let parts = &mut self.response.parts;
        match (parts.last_mut(), part) {
            // Fragments extend the previous part of the same kind.
            (
                Some(ResponsePart::Text { text, signature }),
                ResponsePart::Text {
                    text: more,
                    signature: sig,
                },
            ) if signature.is_none() => {
                text.push_str(&more);
                signature.clone_from(&sig);
                if !more.is_empty() {
                    self.emit(CoreEvent::text(more.as_str()));
                }
                self.emit_signature(sig.as_ref());
                Ok((!more.is_empty()).then_some(StreamEvent::Text(more)))
            }
            (
                Some(ResponsePart::Thought { text, signature }),
                ResponsePart::Thought {
                    text: more,
                    signature: sig,
                },
            ) if signature.is_none() => {
                text.push_str(&more);
                signature.clone_from(&sig);
                if !more.is_empty() || sig.is_some() {
                    self.emit(CoreEvent::ReasoningDelta {
                        text: more.clone(),
                        signature: sig,
                    });
                }
                Ok((!more.is_empty()).then_some(StreamEvent::Thought(more)))
            }
            // A bare signature closes the previous part.
            (Some(last), ResponsePart::Text { text, signature })
                if text.is_empty() && signature.is_some() =>
            {
                let slot = match last {
                    ResponsePart::Text { signature, .. }
                    | ResponsePart::Thought { signature, .. }
                    | ResponsePart::FunctionCall { signature, .. } => signature,
                };
                if slot.is_none() {
                    slot.clone_from(&signature);
                    self.emit_signature(signature.as_ref());
                    return Ok(None);
                }
                self.emit_signature(signature.as_ref());
                self.push_part(ResponsePart::Text { text, signature })?;
                Ok(None)
            }
            (_, part) => {
                let event = match &part {
                    ResponsePart::Text { text, .. } if !text.is_empty() => {
                        Some(StreamEvent::Text(text.clone()))
                    }
                    ResponsePart::Thought { text, .. } if !text.is_empty() => {
                        Some(StreamEvent::Thought(text.clone()))
                    }
                    ResponsePart::FunctionCall { id, name, args, .. } => {
                        Some(StreamEvent::ToolCall(ToolCall::new(
                            id.clone(),
                            name.clone(),
                            args.to_string(),
                        )))
                    }
                    _ => None,
                };
                self.emit_part(&part);
                self.push_part(part)?;
                Ok(event)
            }
        }
    }

    /// Core events for a new, whole part.
    fn emit_part(&mut self, part: &ResponsePart) {
        if self.core.is_none() {
            return;
        }
        match part {
            ResponsePart::Text { text, signature } => {
                if !text.is_empty() {
                    self.emit(CoreEvent::text(text.as_str()));
                }
                self.emit_signature(signature.as_ref());
            }
            ResponsePart::Thought { text, signature } => self.emit(CoreEvent::ReasoningDelta {
                text: text.clone(),
                signature: signature.clone(),
            }),
            ResponsePart::FunctionCall {
                id,
                name,
                args,
                signature,
            } => {
                // Gemini sends each call whole: index by call order.
                let index = self.calls.saturating_sub(1);
                self.emit(CoreEvent::tool_call_start(
                    index,
                    id.as_str(),
                    name.as_str(),
                ));
                self.emit(CoreEvent::tool_call_delta(index, args.to_string()));
                self.emit(CoreEvent::ToolCallEnd { index });
                self.emit_signature(signature.as_ref());
            }
        }
    }

    fn push_part(&mut self, part: ResponsePart) -> Result<(), LlmError> {
        if self.response.parts.len() >= MAX_PARTS {
            return Err(LlmError::invalid_response("too many content parts"));
        }
        self.response.parts.push(part);
        Ok(())
    }

    /// Finish after the transport ended.
    ///
    /// # Errors
    ///
    /// [`LlmError::invalid_response`] if no chunk carried a `finishReason`:
    /// a truncated stream is never mistaken for a complete one.
    pub fn finish(self) -> Result<GeminiResponse, LlmError> {
        if !self.is_finished() {
            return Err(LlmError::invalid_response(
                "event stream ended before a finish reason",
            ));
        }
        Ok(self.response)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "tests")]

    use rune_chain_core::{FinishReason, LlmErrorKind};

    use super::*;

    fn run(chunks: &[&str]) -> (Vec<StreamEvent>, Result<GeminiResponse, LlmError>) {
        let mut acc = ResponseAccumulator::new();
        let mut events = Vec::new();
        for c in chunks {
            match acc.push(c) {
                Ok(e) => events.extend(e),
                Err(e) => return (events, Err(e)),
            }
        }
        (events, acc.finish())
    }

    #[test]
    fn merges_fragments_and_keeps_signatures() {
        let (events, done) = run(&[
            r#"{"responseId":"abc","candidates":[{"content":{"parts":[{"text":"Plan: ","thought":true}]}}]}"#,
            r#"{"candidates":[{"content":{"parts":[{"text":"look it up.","thought":true}]}}]}"#,
            r#"{"candidates":[{"content":{"parts":[{"text":"It is "}]}}]}"#,
            r#"{"candidates":[{"content":{"parts":[{"text":"sunny."}]}}]}"#,
            r#"{"candidates":[{"content":{"parts":[{"text":"","thoughtSignature":"U0lH"}]},"finishReason":"STOP"}],
               "usageMetadata":{"promptTokenCount":3,"candidatesTokenCount":4,"thoughtsTokenCount":5}}"#,
        ]);
        let done = done.unwrap();
        assert_eq!(
            events,
            [
                StreamEvent::Thought("Plan: ".into()),
                StreamEvent::Thought("look it up.".into()),
                StreamEvent::Text("It is ".into()),
                StreamEvent::Text("sunny.".into()),
            ]
        );
        assert_eq!(done.parts.len(), 2);
        assert_eq!(done.thoughts(), "Plan: look it up.");
        assert_eq!(done.text(), "It is sunny.");
        assert_eq!(
            done.parts[1],
            ResponsePart::Text {
                text: "It is sunny.".into(),
                signature: Some("U0lH".into())
            }
        );
        assert_eq!(done.finish_reason(), Some(FinishReason::Stop));
        assert_eq!(done.usage().thoughts_tokens, 5);
    }

    #[test]
    fn parallel_calls_get_distinct_ids() {
        let (events, done) = run(&[r#"{"responseId":"r9","candidates":[{"content":{"parts":[
                {"functionCall":{"name":"a","args":{}},"thoughtSignature":"c2ln"},
                {"functionCall":{"name":"b","args":{"k":"v"}}}]},"finishReason":"STOP"}]}"#]);
        let ids: Vec<String> = events
            .iter()
            .filter_map(|e| match e {
                StreamEvent::ToolCall(c) => Some(c.id.clone()),
                _ => None,
            })
            .collect();
        assert_eq!(ids, ["gemini_call_r9_0", "gemini_call_r9_1"]);
        let done = done.unwrap();
        assert_eq!(done.finish_reason(), Some(FinishReason::ToolCalls));
        assert_eq!(done.tool_calls().len(), 2);
    }

    /// Fold the core events of `chunks` and compare with the plain result.
    fn core_matches_plain(chunks: &[&str]) -> Vec<CoreEvent> {
        let (_, plain) = run(chunks);
        let expected = plain.unwrap().to_generate_result();
        let mut acc = ResponseAccumulator::new().for_core_events();
        let mut events = Vec::new();
        for c in chunks {
            events.extend(acc.push_core(c).unwrap());
        }
        events.extend(acc.finish_core().unwrap());
        let mut fold = rune_chain_core::StreamAccumulator::new();
        for e in &events {
            fold.push(e).unwrap();
        }
        assert_eq!(fold.finish(), expected, "{events:?}");
        events
    }

    #[test]
    fn core_events_fold_to_the_same_result() {
        let events = core_matches_plain(&[
            r#"{"responseId":"abc","candidates":[{"content":{"parts":[{"text":"Plan: ","thought":true}]}}]}"#,
            r#"{"candidates":[{"content":{"parts":[{"text":"look it up.","thought":true}]}}]}"#,
            r#"{"candidates":[{"content":{"parts":[{"text":"It is "}]}}]}"#,
            r#"{"candidates":[{"content":{"parts":[{"text":"sunny."}]}}]}"#,
            r#"{"candidates":[{"content":{"parts":[{"text":"","thoughtSignature":"U0lH"}]},"finishReason":"STOP"}],
               "usageMetadata":{"promptTokenCount":3,"candidatesTokenCount":4,"thoughtsTokenCount":5}}"#,
        ]);
        assert_eq!(events[0], CoreEvent::reasoning("Plan: "));
        assert_eq!(events[2], CoreEvent::text("It is "));

        // Signed thought, then calls with and without signatures across chunks.
        core_matches_plain(&[
            r#"{"responseId":"r1","candidates":[{"content":{"parts":[{"text":"think","thought":true,"thoughtSignature":"VA=="}]}}]}"#,
            r#"{"candidates":[{"content":{"parts":[{"functionCall":{"name":"a","args":{"x":1}},"thoughtSignature":"QQ=="}]}}]}"#,
            r#"{"candidates":[{"content":{"parts":[{"functionCall":{"name":"b"}},{"text":"Done."}]}}]}"#,
            r#"{"candidates":[{"content":{"parts":[{"text":"","thoughtSignature":"Qg=="}]},"finishReason":"STOP"}]}"#,
        ]);
    }

    #[test]
    fn core_events_stream_parallel_calls_with_distinct_indexes() {
        let events =
            core_matches_plain(&[r#"{"responseId":"r9","candidates":[{"content":{"parts":[
                {"functionCall":{"name":"a","args":{}},"thoughtSignature":"c2ln"},
                {"functionCall":{"name":"b","args":{"k":"v"}}}]},"finishReason":"STOP"}]}"#]);
        let starts: Vec<usize> = events
            .iter()
            .filter_map(|e| match e {
                CoreEvent::ToolCallStart { index, .. } => Some(*index),
                _ => None,
            })
            .collect();
        assert_eq!(starts, [0, 1]);
    }

    #[test]
    fn oversized_function_arguments_are_rejected() {
        let big = "x".repeat(MAX_TOOL_ARGUMENTS_BYTES);
        let chunk = serde_json::json!({"candidates":[{"content":{"parts":[
            {"functionCall":{"name":"f","args":{"v":big}}}]}}]})
        .to_string();
        let err = ResponseAccumulator::new()
            .for_core_events()
            .push_core(&chunk)
            .unwrap_err();
        assert_eq!(err.kind(), LlmErrorKind::InvalidResponse);
        assert!(!err.message().contains("xxx"));
    }

    #[test]
    fn truncated_stream_is_an_error() {
        let (_, done) = run(&[r#"{"candidates":[{"content":{"parts":[{"text":"Hi"}]}}]}"#]);
        assert_eq!(done.unwrap_err().kind(), LlmErrorKind::InvalidResponse);
    }

    #[test]
    fn in_stream_errors_and_blocks() {
        let (_, done) = run(&[
            r#"{"candidates":[{"content":{"parts":[{"text":"Hi"}]}}]}"#,
            r#"{"error":{"code":503,"message":"overloaded","status":"UNAVAILABLE"}}"#,
        ]);
        assert_eq!(done.unwrap_err().kind(), LlmErrorKind::Overloaded);

        let (_, done) = run(&[r#"{"promptFeedback":{"blockReason":"PROHIBITED_CONTENT"}}"#]);
        let err = done.unwrap_err();
        assert_eq!(err.kind(), LlmErrorKind::Provider);
        assert!(err.message().contains("PROHIBITED_CONTENT"));

        let (_, done) = run(&["not json"]);
        assert_eq!(done.unwrap_err().kind(), LlmErrorKind::InvalidResponse);
    }

    #[test]
    fn content_cap() {
        let mut acc = ResponseAccumulator::with_limit(10);
        assert!(
            acc.push(r#"{"candidates":[{"content":{"parts":[{"text":"0123456789"}]}}]}"#)
                .is_ok()
        );
        let err = acc
            .push(r#"{"candidates":[{"content":{"parts":[{"text":"x"}]}}]}"#)
            .unwrap_err();
        assert!(err.message().contains("10-byte limit"));
    }

    #[test]
    fn part_cap() {
        let mut acc = ResponseAccumulator::new();
        let chunk = r#"{"candidates":[{"content":{"parts":[{"functionCall":{"name":"f"}}]}}]}"#;
        for _ in 0..MAX_PARTS {
            acc.push(chunk).unwrap();
        }
        assert!(acc.push(chunk).is_err());
    }
}
