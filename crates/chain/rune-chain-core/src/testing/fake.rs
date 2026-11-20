//! A scriptable, offline [`Llm`] for testing code built on the trait.
//!
//! [`FakeLlm`] answers from a queue of [`FakeReply`] values, in order, and
//! falls back to an optional responder closure once the queue is empty. It
//! records every request it receives, so tests can assert on the messages,
//! tools, tool choice and response format the code under test sent.
//!
//! Latency is simulated with a short-lived background thread, so the fake
//! works under any async runtime (or none, with `futures::executor`).
//!
//! # Example
//!
//! ```rust
//! use rune_chain_core::testing::{FakeLlm, FakeReply};
//! use rune_chain_core::{Llm, Message, TokenUsage};
//!
//! # tokio_test::block_on(async {
//! let llm = FakeLlm::with_replies([
//!     FakeReply::text("Paris").with_usage(TokenUsage::new(12, 1)),
//!     FakeReply::text("Berlin"),
//! ]);
//!
//! let first = llm
//!     .generate(&[Message::system("Answer in one word."), Message::human("Capital of France?")])
//!     .await
//!     .unwrap();
//! assert_eq!(first.generation, "Paris");
//! assert_eq!(first.tokens.map(|u| u.total_tokens), Some(13));
//!
//! let second = llm.generate(&[Message::human("Capital of Germany?")]).await.unwrap();
//! assert_eq!(second.generation, "Berlin");
//!
//! let requests = llm.requests();
//! assert_eq!(llm.call_count(), 2);
//! assert_eq!(requests[0].system().as_deref(), Some("Answer in one word."));
//! assert_eq!(requests[0].prompt().as_deref(), Some("Capital of France?"));
//! # });
//! ```
//!
//! Once the script runs out, calls fail with an error instead of panicking:
//!
//! ```rust
//! use rune_chain_core::testing::{FakeLlm, FakeReply};
//! use rune_chain_core::{Llm, LlmErrorKind, Message};
//!
//! # tokio_test::block_on(async {
//! let llm = FakeLlm::with_replies([FakeReply::rate_limited()]);
//! let msgs = [Message::human("hi")];
//!
//! let err = llm.generate(&msgs).await.unwrap_err();
//! assert!(err.is_rate_limit());
//!
//! let err = llm.generate(&msgs).await.unwrap_err();
//! assert_eq!(err.kind(), LlmErrorKind::Other);
//! assert!(err.to_string().contains("no reply left"));
//! # });
//! ```

use std::collections::VecDeque;
use std::fmt;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use async_trait::async_trait;
use futures::Stream;
use serde_json::Value;

use crate::{
    EventStream, FinishReason, FunctionDefinition, GenerateResult, Llm, LlmError, Message,
    ResponseFormat, Role, StreamAccumulator, StreamData, StreamEvent, TokenUsage, ToolCall,
    ToolChoice,
};

/// Default number of characters per streamed chunk.
const DEFAULT_CHUNK_CHARS: usize = 8;

/// One scripted answer for [`FakeLlm`]: a [`GenerateResult`] or an
/// [`LlmError`].
///
/// The `with_*` builders adjust a successful reply and leave an error reply
/// as it is.
///
/// # Example
///
/// ```rust
/// use rune_chain_core::testing::FakeReply;
/// use rune_chain_core::{FinishReason, TokenUsage, ToolCall};
/// use serde_json::json;
///
/// let replies = [
///     FakeReply::text("hello").with_usage(TokenUsage::new(5, 1)),
///     FakeReply::json(&json!({ "answer": 4 })),
///     FakeReply::tool_calls([ToolCall::new("call_1", "search", r#"{"q":"rust"}"#)]),
///     FakeReply::text("I can't help with that.").with_finish_reason(FinishReason::Refusal),
///     FakeReply::truncated("The answer is"),
///     FakeReply::timeout(),
/// ];
/// assert_eq!(replies.len(), 6);
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FakeReply {
    outcome: Result<GenerateResult, LlmError>,
    stream_error: Option<LlmError>,
    events: Option<Vec<StreamEvent>>,
}

impl FakeReply {
    /// A successful reply carrying `result` as is.
    #[must_use]
    pub const fn result(result: GenerateResult) -> Self {
        Self {
            outcome: Ok(result),
            stream_error: None,
            events: None,
        }
    }

    /// A text answer with [`FinishReason::Stop`].
    pub fn text(text: impl Into<String>) -> Self {
        Self::result(GenerateResult::from_text(text).with_finish_reason(FinishReason::Stop))
    }

    /// A structured answer: `value` serialised as compact JSON, with
    /// [`FinishReason::Stop`]. Parse it back with
    /// [`ResponseFormat::parse_json`].
    #[must_use]
    pub fn json(value: &Value) -> Self {
        Self::text(value.to_string())
    }

    /// A tool-call turn: empty text, the given calls and
    /// [`FinishReason::ToolCalls`].
    pub fn tool_calls(calls: impl IntoIterator<Item = ToolCall>) -> Self {
        Self::result(
            GenerateResult::from_text("")
                .with_tool_calls(calls.into_iter().collect())
                .with_finish_reason(FinishReason::ToolCalls),
        )
    }

    /// A reply scripted as exact [`StreamEvent`]s, for testing how code
    /// handles fragmented or interleaved tool calls.
    ///
    /// [`stream_events`](Llm::stream_events) yields `events` as given; the
    /// other methods answer with what a [`StreamAccumulator`] folds them
    /// into (or its error).
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_chain_core::testing::{FakeLlm, FakeReply};
    /// use rune_chain_core::{Llm, Message, StreamEvent};
    ///
    /// # tokio_test::block_on(async {
    /// let llm = FakeLlm::with_replies([FakeReply::events([
    ///     StreamEvent::tool_call_start(0, "c1", "search"),
    ///     StreamEvent::tool_call_delta(0, r#"{"q":"#),
    ///     StreamEvent::tool_call_delta(0, r#""rust"}"#),
    /// ])]);
    /// let r = llm.generate(&[Message::human("go")]).await.unwrap();
    /// assert_eq!(r.tool_calls[0].arguments, r#"{"q":"rust"}"#);
    /// # });
    /// ```
    pub fn events(events: impl IntoIterator<Item = StreamEvent>) -> Self {
        let events: Vec<StreamEvent> = events.into_iter().collect();
        let mut acc = StreamAccumulator::new();
        let outcome = events
            .iter()
            .try_for_each(|e| acc.push(e))
            .map(|()| acc.finish());
        Self {
            outcome,
            stream_error: None,
            events: Some(events),
        }
    }

    /// A refusal: `text` with [`FinishReason::Refusal`].
    pub fn refusal(text: impl Into<String>) -> Self {
        Self::text(text).with_finish_reason(FinishReason::Refusal)
    }

    /// Output cut off by the token limit: `text` with
    /// [`FinishReason::Length`].
    pub fn truncated(text: impl Into<String>) -> Self {
        Self::text(text).with_finish_reason(FinishReason::Length)
    }

    /// A failed call returning `error`.
    #[must_use]
    pub const fn error(error: LlmError) -> Self {
        Self {
            outcome: Err(error),
            stream_error: None,
            events: None,
        }
    }

    /// A rate-limit failure (HTTP 429, [`LlmErrorKind::RateLimit`](crate::LlmErrorKind::RateLimit)).
    #[must_use]
    pub fn rate_limited() -> Self {
        Self::error(LlmError::from_status(429, "rate limit reached (fake)"))
    }

    /// A timeout ([`LlmErrorKind::Timeout`](crate::LlmErrorKind::Timeout)).
    #[must_use]
    pub fn timeout() -> Self {
        Self::error(LlmError::timeout("request timed out (fake)"))
    }

    /// An unclassified provider error ([`LlmErrorKind::Provider`](crate::LlmErrorKind::Provider)).
    pub fn provider_error(message: impl Into<String>) -> Self {
        Self::error(LlmError::provider(message))
    }

    /// Set the token usage of a successful reply.
    #[must_use]
    pub fn with_usage(self, usage: TokenUsage) -> Self {
        self.map_result(|r| r.with_tokens(usage))
    }

    /// Set the finish reason of a successful reply.
    #[must_use]
    pub fn with_finish_reason(self, reason: FinishReason) -> Self {
        self.map_result(|r| r.with_finish_reason(reason))
    }

    /// Fail part-way: [`stream`](Llm::stream) yields the text chunks and then
    /// `error` instead of the final chunk; the other methods return `error`.
    #[must_use]
    pub fn with_stream_error(mut self, error: LlmError) -> Self {
        self.stream_error = Some(error);
        self
    }

    fn map_result(mut self, f: impl FnOnce(GenerateResult) -> GenerateResult) -> Self {
        self.outcome = self.outcome.map(f);
        self
    }
}

impl From<GenerateResult> for FakeReply {
    fn from(result: GenerateResult) -> Self {
        Self::result(result)
    }
}

impl From<LlmError> for FakeReply {
    fn from(error: LlmError) -> Self {
        Self::error(error)
    }
}

impl From<&str> for FakeReply {
    fn from(text: &str) -> Self {
        Self::text(text)
    }
}

impl From<String> for FakeReply {
    fn from(text: String) -> Self {
        Self::text(text)
    }
}

/// Which [`Llm`] method a [`FakeRequest`] came through.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum FakeMethod {
    /// [`Llm::generate`].
    Generate,
    /// [`Llm::generate_with_tools`].
    GenerateWithTools,
    /// [`Llm::generate_structured`].
    GenerateStructured,
    /// [`Llm::stream`].
    Stream,
    /// [`Llm::stream_events`].
    StreamEvents,
}

/// A request [`FakeLlm`] received, recorded for assertions.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct FakeRequest {
    /// The method that was called.
    pub method: FakeMethod,
    /// The conversation as passed in (for structured output, without the
    /// format instructions the default implementation would add).
    pub messages: Vec<Message>,
    /// Tools offered to [`Llm::generate_with_tools`] or
    /// [`Llm::stream_events`]; empty otherwise.
    pub tools: Vec<FunctionDefinition>,
    /// Tool choice passed to [`Llm::generate_with_tools`] or
    /// [`Llm::stream_events`].
    pub tool_choice: Option<ToolChoice>,
    /// Format passed to [`Llm::generate_structured`].
    pub format: Option<ResponseFormat>,
}

impl FakeRequest {
    fn new(method: FakeMethod, messages: &[Message]) -> Self {
        Self {
            method,
            messages: messages.to_vec(),
            tools: Vec::new(),
            tool_choice: None,
            format: None,
        }
    }

    /// Text of the system messages, joined with a blank line, or `None` when
    /// there are none.
    #[must_use]
    pub fn system(&self) -> Option<String> {
        let parts: Vec<String> = self
            .messages
            .iter()
            .filter(|m| m.role == Role::System)
            .map(Message::text)
            .collect();
        (!parts.is_empty()).then(|| parts.join("\n\n"))
    }

    /// Text of the last human message, or `None` when there is none.
    #[must_use]
    pub fn prompt(&self) -> Option<String> {
        self.messages
            .iter()
            .rev()
            .find(|m| m.role == Role::Human)
            .map(Message::text)
    }

    /// Names of the offered tools, in order.
    #[must_use]
    pub fn tool_names(&self) -> Vec<&str> {
        self.tools.iter().map(|t| t.name.as_str()).collect()
    }
}

type Responder = dyn Fn(&FakeRequest) -> Result<GenerateResult, LlmError> + Send + Sync;

#[derive(Default)]
struct State {
    replies: VecDeque<FakeReply>,
    requests: Vec<FakeRequest>,
}

#[derive(Default)]
struct Shared {
    state: Mutex<State>,
    in_flight: AtomicUsize,
    max_in_flight: AtomicUsize,
}

/// A scriptable [`Llm`] that never touches the network.
///
/// Each call records its [`FakeRequest`], waits for the configured latency,
/// then answers with the next queued [`FakeReply`]. When the queue is empty
/// the responder closure answers, if one is set; otherwise the call fails
/// with an [`LlmErrorKind::Other`](crate::LlmErrorKind::Other) error saying the fake has no reply left.
///
/// Clones share the queue, the recorded requests and the concurrency
/// counters, so a test can hand a clone (or an `Arc`) to the code under test
/// and inspect the original afterwards.
///
/// [`stream`](Llm::stream) splits the reply text into chunks of
/// [`chunk_chars`](Self::chunk_chars) characters followed by the final chunk.
/// [`StreamData`] has no room for tool calls, usage or a finish reason, so a
/// stream carries the text only.
/// [`stream_events`](Llm::stream_events) carries everything: the text and
/// each tool call's arguments in chunks of `chunk_chars`, then usage and the
/// finish reason (or the events of a [`FakeReply::events`] reply as given).
///
/// See the [module docs](self) for examples.
#[derive(Clone)]
pub struct FakeLlm {
    shared: Arc<Shared>,
    responder: Option<Arc<Responder>>,
    latency: Duration,
    chunk_chars: usize,
}

impl Default for FakeLlm {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for FakeLlm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FakeLlm")
            .field("remaining", &self.remaining())
            .field("call_count", &self.call_count())
            .field("has_responder", &self.responder.is_some())
            .field("latency", &self.latency)
            .field("chunk_chars", &self.chunk_chars)
            .finish_non_exhaustive()
    }
}

impl FakeLlm {
    /// A fake with an empty script and no responder: every call fails until
    /// replies are [`push`](Self::push)ed.
    #[must_use]
    pub fn new() -> Self {
        Self {
            shared: Arc::default(),
            responder: None,
            latency: Duration::ZERO,
            chunk_chars: DEFAULT_CHUNK_CHARS,
        }
    }

    /// A fake that answers with `replies`, in order.
    pub fn with_replies<R: Into<FakeReply>>(replies: impl IntoIterator<Item = R>) -> Self {
        let llm = Self::new();
        llm.state()
            .replies
            .extend(replies.into_iter().map(Into::into));
        llm
    }

    /// A fake that answers every call with `responder`, for tests that need
    /// the answer to depend on the request.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_chain_core::testing::FakeLlm;
    /// use rune_chain_core::{GenerateResult, Llm, Message};
    ///
    /// # tokio_test::block_on(async {
    /// let llm = FakeLlm::from_fn(|req| {
    ///     let prompt = req.prompt().unwrap_or_default();
    ///     Ok(GenerateResult::from_text(prompt.to_uppercase()))
    /// });
    /// let out = llm.generate(&[Message::human("shout")]).await.unwrap();
    /// assert_eq!(out.generation, "SHOUT");
    /// # });
    /// ```
    pub fn from_fn<F>(responder: F) -> Self
    where
        F: Fn(&FakeRequest) -> Result<GenerateResult, LlmError> + Send + Sync + 'static,
    {
        Self::new().with_responder(responder)
    }

    /// Set the responder used once the scripted replies run out (builder
    /// style).
    #[must_use]
    pub fn with_responder<F>(mut self, responder: F) -> Self
    where
        F: Fn(&FakeRequest) -> Result<GenerateResult, LlmError> + Send + Sync + 'static,
    {
        self.responder = Some(Arc::new(responder));
        self
    }

    /// Wait `latency` before answering each call (builder style). Use it
    /// with [`max_in_flight`](Self::max_in_flight) to test concurrency
    /// limits.
    ///
    /// # Example
    ///
    /// ```rust
    /// use std::time::Duration;
    /// use futures::future::join_all;
    /// use rune_chain_core::testing::FakeLlm;
    /// use rune_chain_core::{GenerateResult, Llm, Message};
    ///
    /// # tokio_test::block_on(async {
    /// let llm = FakeLlm::from_fn(|_| Ok(GenerateResult::from_text("ok")))
    ///     .with_latency(Duration::from_millis(20));
    /// let msgs = [Message::human("hi")];
    /// join_all((0..3).map(|_| llm.generate(&msgs))).await;
    /// assert_eq!(llm.max_in_flight(), 3);
    /// # });
    /// ```
    #[must_use]
    pub const fn with_latency(mut self, latency: Duration) -> Self {
        self.latency = latency;
        self
    }

    /// Characters per streamed chunk (builder style; default 8, minimum 1).
    #[must_use]
    pub fn with_chunk_chars(mut self, chars: usize) -> Self {
        self.chunk_chars = chars.max(1);
        self
    }

    /// Characters per streamed chunk.
    #[must_use]
    pub const fn chunk_chars(&self) -> usize {
        self.chunk_chars
    }

    /// Append a reply to the script.
    pub fn push(&self, reply: impl Into<FakeReply>) {
        self.state().replies.push_back(reply.into());
    }

    /// Number of scripted replies not yet used.
    #[must_use]
    pub fn remaining(&self) -> usize {
        self.state().replies.len()
    }

    /// Every request received so far, oldest first.
    #[must_use]
    pub fn requests(&self) -> Vec<FakeRequest> {
        self.state().requests.clone()
    }

    /// The most recent request, if any.
    #[must_use]
    pub fn last_request(&self) -> Option<FakeRequest> {
        self.state().requests.last().cloned()
    }

    /// Number of calls received so far.
    #[must_use]
    pub fn call_count(&self) -> usize {
        self.state().requests.len()
    }

    /// Calls currently waiting out their latency.
    #[must_use]
    pub fn in_flight(&self) -> usize {
        self.shared.in_flight.load(Ordering::SeqCst)
    }

    /// The highest number of calls that were in flight at the same time.
    #[must_use]
    pub fn max_in_flight(&self) -> usize {
        self.shared.max_in_flight.load(Ordering::SeqCst)
    }

    fn state(&self) -> MutexGuard<'_, State> {
        self.shared
            .state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// Record `request`, wait out the latency, and pick the answer.
    async fn answer(&self, request: FakeRequest) -> FakeReply {
        let call = {
            let mut state = self.state();
            state.requests.push(request.clone());
            state.requests.len()
        };
        {
            let _guard = InFlight::enter(&self.shared);
            if !self.latency.is_zero() {
                sleep(self.latency).await;
            }
        }
        let scripted = self.state().replies.pop_front();
        match (scripted, &self.responder) {
            (Some(reply), _) => reply,
            (None, Some(responder)) => match responder(&request) {
                Ok(result) => FakeReply::result(result),
                Err(e) => FakeReply::error(e),
            },
            (None, None) => FakeReply::error(LlmError::other(format!(
                "FakeLlm has no reply left for call #{call}: script more replies or set a responder"
            ))),
        }
    }

    async fn complete(&self, request: FakeRequest) -> Result<GenerateResult, LlmError> {
        let reply = self.answer(request).await;
        match reply.stream_error {
            Some(e) => Err(e),
            None => reply.outcome,
        }
    }
}

#[async_trait]
impl Llm for FakeLlm {
    async fn generate(&self, messages: &[Message]) -> Result<GenerateResult, LlmError> {
        self.complete(FakeRequest::new(FakeMethod::Generate, messages))
            .await
    }

    async fn generate_with_tools(
        &self,
        messages: &[Message],
        tools: &[FunctionDefinition],
        tool_choice: Option<ToolChoice>,
    ) -> Result<GenerateResult, LlmError> {
        let mut request = FakeRequest::new(FakeMethod::GenerateWithTools, messages);
        request.tools = tools.to_vec();
        request.tool_choice = tool_choice;
        self.complete(request).await
    }

    async fn generate_structured(
        &self,
        messages: &[Message],
        format: &ResponseFormat,
    ) -> Result<GenerateResult, LlmError> {
        let mut request = FakeRequest::new(FakeMethod::GenerateStructured, messages);
        request.format = Some(format.clone());
        self.complete(request).await
    }

    async fn stream(
        &self,
        messages: &[Message],
    ) -> Result<Pin<Box<dyn Stream<Item = Result<StreamData, LlmError>> + Send>>, LlmError> {
        let reply = self
            .answer(FakeRequest::new(FakeMethod::Stream, messages))
            .await;
        let result = reply.outcome?;
        let chars: Vec<char> = result.generation.chars().collect();
        let mut items: Vec<Result<StreamData, LlmError>> = chars
            .chunks(self.chunk_chars)
            .map(|c| Ok(StreamData::chunk(c.iter().collect::<String>())))
            .collect();
        items.push(
            reply
                .stream_error
                .map_or_else(|| Ok(StreamData::done()), Err),
        );
        Ok(Box::pin(futures::stream::iter(items)))
    }

    async fn stream_events(
        &self,
        messages: &[Message],
        tools: Option<&[FunctionDefinition]>,
        tool_choice: Option<ToolChoice>,
    ) -> Result<EventStream, LlmError> {
        let mut request = FakeRequest::new(FakeMethod::StreamEvents, messages);
        request.tools = tools.unwrap_or_default().to_vec();
        request.tool_choice = tool_choice;
        let reply = self.answer(request).await;
        let events = match reply.events {
            Some(events) => events,
            None => chunked_events(reply.outcome?, self.chunk_chars),
        };
        let mut items: Vec<Result<StreamEvent, LlmError>> = events.into_iter().map(Ok).collect();
        items.extend(reply.stream_error.map(Err));
        Ok(Box::pin(futures::stream::iter(items)))
    }
}

/// Replay `result` as events, splitting text and arguments into chunks.
fn chunked_events(result: GenerateResult, chunk_chars: usize) -> Vec<StreamEvent> {
    let split = |s: &str| -> Vec<String> {
        let chars: Vec<char> = s.chars().collect();
        chars
            .chunks(chunk_chars)
            .map(|c| c.iter().collect())
            .collect()
    };
    let mut out = Vec::new();
    for event in result.into_events() {
        match event {
            StreamEvent::TextDelta(text) => {
                out.extend(split(&text).into_iter().map(StreamEvent::TextDelta));
            }
            StreamEvent::ToolCallDelta {
                index,
                arguments_fragment,
            } => out.extend(
                split(&arguments_fragment)
                    .into_iter()
                    .map(|f| StreamEvent::tool_call_delta(index, f)),
            ),
            other => out.push(other),
        }
    }
    out
}

/// Counts a call as in flight until dropped, so cancelled calls are released
/// too.
struct InFlight<'a>(&'a Shared);

impl<'a> InFlight<'a> {
    fn enter(shared: &'a Shared) -> Self {
        let now = shared.in_flight.fetch_add(1, Ordering::SeqCst) + 1;
        shared.max_in_flight.fetch_max(now, Ordering::SeqCst);
        Self(shared)
    }
}

impl Drop for InFlight<'_> {
    fn drop(&mut self) {
        self.0.in_flight.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Runtime-agnostic sleep: a helper thread completes a oneshot channel.
async fn sleep(duration: Duration) {
    let (tx, rx) = futures::channel::oneshot::channel::<()>();
    std::thread::spawn(move || {
        std::thread::sleep(duration);
        let _ = tx.send(());
    });
    let _ = rx.await;
}

#[cfg(test)]
mod tests {
    use futures::StreamExt;
    use serde_json::json;

    use super::*;
    use crate::LlmErrorKind;
    use crate::testing::{check_llm, check_stream};

    fn msgs() -> [Message; 2] {
        [Message::system("sys"), Message::human("hello")]
    }

    #[tokio::test]
    async fn meets_the_llm_contract_with_a_responder() {
        let llm = FakeLlm::from_fn(|req| {
            let result = GenerateResult::from_text("pong").with_tokens(TokenUsage::new(4, 1));
            Ok(match req.tools.first() {
                Some(tool) => result.with_tool_calls(vec![ToolCall::new(
                    "call_1",
                    &tool.name,
                    r#"{"input":"x"}"#,
                )]),
                None => result,
            })
        });
        check_llm(&llm).await.unwrap();
        let methods: Vec<FakeMethod> = llm.requests().iter().map(|r| r.method).collect();
        assert_eq!(
            methods,
            [
                FakeMethod::Generate,
                FakeMethod::Generate,
                FakeMethod::GenerateWithTools,
                FakeMethod::Stream
            ]
        );
    }

    #[tokio::test]
    async fn meets_the_llm_contract_with_a_script() {
        let llm = FakeLlm::with_replies([
            FakeReply::text("pong").with_usage(TokenUsage::new(2, 1)),
            FakeReply::provider_error("empty conversation"),
            FakeReply::tool_calls([ToolCall::new("c1", "echo", "{}")]),
            FakeReply::text("streamed pong"),
        ]);
        check_llm(&llm).await.unwrap();
        assert_eq!(llm.remaining(), 0);
    }

    #[tokio::test]
    async fn replies_in_order_with_finish_reasons() {
        let llm = FakeLlm::with_replies([
            FakeReply::refusal("no"),
            FakeReply::truncated("The answer"),
            FakeReply::json(&json!({"a": 1})),
        ]);
        let r = llm.generate(&msgs()).await.unwrap();
        assert_eq!(r.finish_reason, Some(FinishReason::Refusal));
        let r = llm.generate(&msgs()).await.unwrap();
        assert!(r.is_truncated());
        let format = ResponseFormat::JsonObject;
        let r = llm.generate_structured(&msgs(), &format).await.unwrap();
        assert_eq!(format.parse_json(&r.generation).unwrap()["a"], 1);

        let req = llm.last_request().unwrap();
        assert_eq!(req.method, FakeMethod::GenerateStructured);
        assert_eq!(req.format, Some(format));
        assert_eq!(req.messages, msgs());
    }

    #[tokio::test]
    async fn records_tools_and_choice() {
        let llm =
            FakeLlm::with_replies([FakeReply::tool_calls([ToolCall::new("c1", "search", "{}")])]);
        let tools = [FunctionDefinition::single_input("search", "Searches.")];
        let r = llm
            .generate_with_tools(&msgs(), &tools, Some(ToolChoice::Required))
            .await
            .unwrap();
        assert_eq!(r.finish_reason, Some(FinishReason::ToolCalls));
        let req = llm.last_request().unwrap();
        assert_eq!(req.tool_names(), ["search"]);
        assert_eq!(req.tool_choice, Some(ToolChoice::Required));
        assert_eq!(req.system().as_deref(), Some("sys"));
        assert_eq!(req.prompt().as_deref(), Some("hello"));
    }

    #[tokio::test]
    async fn scripted_errors_keep_their_kind() {
        let llm = FakeLlm::with_replies([
            FakeReply::rate_limited(),
            FakeReply::timeout(),
            FakeReply::provider_error("boom"),
        ]);
        let kinds = [
            LlmErrorKind::RateLimit,
            LlmErrorKind::Timeout,
            LlmErrorKind::Provider,
        ];
        for kind in kinds {
            assert_eq!(llm.generate(&msgs()).await.unwrap_err().kind(), kind);
        }
        assert_eq!(
            llm.generate(&msgs()).await.unwrap_err().status(),
            None,
            "exhausted script is a local error"
        );
    }

    #[tokio::test]
    async fn exhausted_script_falls_back_to_responder_then_errors() {
        let llm = FakeLlm::with_replies(["first"])
            .with_responder(|_| Ok(GenerateResult::from_text("fallback")));
        assert_eq!(llm.generate(&msgs()).await.unwrap().generation, "first");
        assert_eq!(llm.generate(&msgs()).await.unwrap().generation, "fallback");

        let empty = FakeLlm::new();
        let err = empty.generate(&msgs()).await.unwrap_err();
        assert_eq!(err.kind(), LlmErrorKind::Other);
        assert!(err.message().contains("no reply left for call #1"));
        empty.push("late");
        assert_eq!(empty.generate(&msgs()).await.unwrap().generation, "late");
    }

    #[tokio::test]
    async fn streams_in_chunks() {
        let llm = FakeLlm::with_replies(["héllo world"]).with_chunk_chars(3);
        let chunks: Vec<_> = llm.stream(&msgs()).await.unwrap().collect().await;
        let texts: Vec<String> = chunks
            .iter()
            .map(|c| c.as_ref().unwrap().content.clone())
            .collect();
        assert_eq!(texts, ["hél", "lo ", "wor", "ld", ""]);
        assert!(chunks.last().unwrap().as_ref().unwrap().is_finished);
    }

    #[tokio::test]
    async fn stream_error_mid_way_and_up_front() {
        let llm = FakeLlm::with_replies([
            FakeReply::text("partial").with_stream_error(LlmError::request_failed("reset")),
            FakeReply::timeout(),
        ]);
        let stream = llm.stream(&msgs()).await.unwrap();
        let (text, err) = check_stream(stream).await.unwrap();
        assert_eq!(text, "partial");
        assert_eq!(err.unwrap().kind(), LlmErrorKind::Network);
        assert!(llm.stream(&msgs()).await.is_err());
    }

    #[tokio::test]
    async fn stream_events_chunk_text_and_arguments() {
        let llm = FakeLlm::with_replies([FakeReply::result(
            GenerateResult::from_text("abcdef")
                .with_tool_calls(vec![ToolCall::new("c1", "t", r#"{"a":1}"#)])
                .with_tokens(TokenUsage::new(3, 2))
                .with_finish_reason(FinishReason::ToolCalls),
        )])
        .with_chunk_chars(4);
        let tools = [FunctionDefinition::single_input("t", "T.")];
        let stream = llm
            .stream_events(&msgs(), Some(&tools), Some(ToolChoice::Auto))
            .await
            .unwrap();
        let events: Vec<StreamEvent> = stream.map(Result::unwrap).collect().await;
        assert_eq!(
            events,
            [
                StreamEvent::text("abcd"),
                StreamEvent::text("ef"),
                StreamEvent::tool_call_start(0, "c1", "t"),
                StreamEvent::tool_call_delta(0, "{\"a\""),
                StreamEvent::tool_call_delta(0, ":1}"),
                StreamEvent::ToolCallEnd { index: 0 },
                StreamEvent::Usage(TokenUsage::new(3, 2)),
                StreamEvent::Finish(FinishReason::ToolCalls),
            ]
        );
        let req = llm.last_request().unwrap();
        assert_eq!(req.method, FakeMethod::StreamEvents);
        assert_eq!(req.tool_names(), ["t"]);
        assert_eq!(req.tool_choice, Some(ToolChoice::Auto));
    }

    #[tokio::test]
    async fn scripted_events_play_back_and_fold() {
        let events = [
            StreamEvent::tool_call_start(1, "b", "y"),
            StreamEvent::tool_call_start(0, "a", "x"),
            StreamEvent::tool_call_delta(0, "{}"),
            StreamEvent::tool_call_delta(1, "{}"),
        ];
        let llm = FakeLlm::with_replies([
            FakeReply::events(events.clone()),
            FakeReply::events(events.clone()),
            FakeReply::events([StreamEvent::text("par")])
                .with_stream_error(LlmError::request_failed("reset")),
        ]);
        let played: Vec<StreamEvent> = llm
            .stream_events(&msgs(), None, None)
            .await
            .unwrap()
            .map(Result::unwrap)
            .collect()
            .await;
        assert_eq!(played, events);
        let r = llm.generate(&msgs()).await.unwrap();
        assert_eq!(r.tool_calls[0].id, "b");
        assert_eq!(r.tool_calls[1].id, "a");
        let mut s = llm.stream_events(&msgs(), None, None).await.unwrap();
        assert_eq!(s.next().await.unwrap().unwrap(), StreamEvent::text("par"));
        assert!(s.next().await.unwrap().is_err());
        assert!(s.next().await.is_none());
    }

    #[tokio::test]
    async fn clones_share_state_and_track_concurrency() {
        let llm = FakeLlm::from_fn(|_| Ok(GenerateResult::from_text("ok")))
            .with_latency(Duration::from_millis(30));
        let shared = Arc::new(llm.clone());
        let handles: Vec<_> = (0..4)
            .map(|_| {
                let llm = Arc::clone(&shared);
                tokio::spawn(async move { llm.generate(&[Message::human("x")]).await })
            })
            .collect();
        for h in handles {
            h.await.unwrap().unwrap();
        }
        assert_eq!(llm.call_count(), 4);
        assert_eq!(llm.max_in_flight(), 4);
        assert_eq!(llm.in_flight(), 0);
    }

    #[tokio::test]
    async fn sequential_calls_never_overlap() {
        let llm = FakeLlm::with_replies(["a", "b"]).with_latency(Duration::from_millis(5));
        llm.generate(&msgs()).await.unwrap();
        llm.generate(&msgs()).await.unwrap();
        assert_eq!(llm.max_in_flight(), 1);
    }
}
