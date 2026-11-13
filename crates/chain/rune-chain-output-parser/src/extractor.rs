//! Typed extraction from an LLM: the Rust take on Python's `instructor`.

use std::pin::Pin;

use futures::{Stream, StreamExt};
use rune_chain_core::{
    GenerateResult, Llm, LlmError, Message, ResponseFormat, StreamData, TokenUsage,
};
use serde::de::DeserializeOwned;
use serde_json::Value;

use crate::{
    Partial, PartialJsonParser, RepairRequest, StructuredError, StructuredOutput,
    StructuredOutputParser,
};

/// Schema name used when none is given.
const DEFAULT_NAME: &str = "response";

/// Longest schema name providers accept (`OpenAI`: 64).
const MAX_NAME_CHARS: usize = 64;

/// How the extractor asks the model for JSON.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum Mode {
    /// Call [`Llm::generate_structured`] with
    /// [`ResponseFormat::JsonSchema`]. Providers with native structured
    /// output enforce the schema; the rest fall back (in
    /// `rune-chain-core`'s default implementation) to prompt instructions.
    #[default]
    Native,
    /// Always prompt: add the schema as a system message and call
    /// [`Llm::generate`]. For providers whose native mode rejects the schema.
    Prompt,
}

/// One item of an [`Extractor::stream`].
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum StreamEvent<T> {
    /// An unvalidated preview of the value so far.
    Partial(Partial<T>),
    /// The final, fully validated value. Always the last item on success.
    Done(StructuredOutput<T>),
    /// The answer so far was rejected and the model is being asked again
    /// (only from [`Extractor::stream_with_reask`]). Earlier previews are
    /// stale; the next item is another `Retrying`, the [`Done`](Self::Done)
    /// value or an error.
    Retrying(RepairRequest),
}

/// The stream returned by [`Extractor::stream`].
pub type ExtractStream<T> =
    Pin<Box<dyn Stream<Item = Result<StreamEvent<T>, StructuredError>> + Send>>;

/// The stream returned by [`Extractor::stream_with_reask`]. It borrows the
/// model, which it may call again.
pub type ReaskStream<'a, T> =
    Pin<Box<dyn Stream<Item = Result<StreamEvent<T>, StructuredError>> + Send + 'a>>;

/// Extract a typed, validated `T` from a model, re-asking on bad output.
///
/// An `Extractor` pairs a [`StructuredOutputParser`] (lenient JSON
/// extraction, JSON Schema validation, deserialization, custom validators)
/// with a request strategy ([`Mode`]). [`extract`](Self::extract) sends the
/// conversation, and on any repairable failure — no JSON, a schema
/// violation, a value that does not fit `T`, or a validator's `Err` — sends
/// it again with the rejected answer and the error appended, up to
/// [`with_max_retries`](Self::with_max_retries) times.
///
/// With the `schemars` feature, [`Extractor::for_type`] derives the schema
/// from `T` and the free function [`extract`](crate::extract()) does it all
/// in one call.
///
/// # Example
///
/// ```rust
/// use std::sync::atomic::{AtomicUsize, Ordering};
///
/// use async_trait::async_trait;
/// use rune_chain_core::{GenerateResult, Llm, LlmError, Message};
/// use rune_chain_output_parser::Extractor;
/// use serde::Deserialize;
/// use serde_json::json;
///
/// /// A mock model: the first answer breaks a business rule, the second is fine.
/// struct Mock(AtomicUsize);
///
/// #[async_trait]
/// impl Llm for Mock {
///     async fn generate(&self, _: &[Message]) -> Result<GenerateResult, LlmError> {
///         Ok(GenerateResult::from_text(match self.0.fetch_add(1, Ordering::SeqCst) {
///             0 => r#"Sure! {"name": "Ada", "age": 250}"#,
///             _ => "```json\n{\"name\": \"Ada\", \"age\": 36}\n```",
///         }))
///     }
/// }
///
/// #[derive(Debug, Deserialize)]
/// struct Person { name: String, age: u32 }
///
/// # tokio::runtime::Builder::new_current_thread().build().unwrap().block_on(async {
/// let extractor = Extractor::<Person>::new(json!({
///     "type": "object",
///     "properties": { "name": {"type": "string"}, "age": {"type": "integer", "minimum": 0} },
///     "required": ["name", "age"]
/// }))
/// .unwrap()
/// .with_name("person")
/// .with_validator(|p| if p.age < 150 { Ok(()) } else { Err(format!("age {} is implausible", p.age)) });
///
/// let out = extractor
///     .extract(&Mock(AtomicUsize::new(0)), &[Message::human("Ada Lovelace, 36")])
///     .await
///     .unwrap();
/// assert_eq!(out.value.age, 36);
/// assert_eq!(out.attempts, 2);
/// # });
/// ```
#[derive(Debug, Clone)]
pub struct Extractor<T> {
    parser: StructuredOutputParser<T>,
    name: String,
    mode: Mode,
    strict: bool,
}

impl<T> Extractor<T> {
    /// Create an extractor for `schema` (which should describe `T`).
    pub fn new(schema: Value) -> Result<Self, StructuredError> {
        Ok(Self::from_parser(StructuredOutputParser::new(schema)?))
    }

    /// Create an extractor around a configured parser.
    #[must_use]
    pub fn from_parser(parser: StructuredOutputParser<T>) -> Self {
        Self {
            parser,
            name: DEFAULT_NAME.to_owned(),
            mode: Mode::Native,
            strict: false,
        }
    }

    /// Set the schema name sent to the provider. Characters outside
    /// `[A-Za-z0-9_-]` become `_`, and it is cut to 64 characters.
    #[must_use]
    pub fn with_name(mut self, name: &str) -> Self {
        self.name = sanitize_name(name);
        self
    }

    /// Choose how JSON is requested (default [`Mode::Native`]).
    #[must_use]
    pub const fn with_mode(mut self, mode: Mode) -> Self {
        self.mode = mode;
        self
    }

    /// Ask the provider to enforce the schema strictly (default `false`:
    /// strict modes such as `OpenAI`'s reject schemas that do not mark
    /// every property required and close every object). Output is
    /// validated locally either way.
    #[must_use]
    pub const fn with_strict(mut self, strict: bool) -> Self {
        self.strict = strict;
        self
    }

    /// Set how many re-asks follow a rejected first answer (default
    /// [`DEFAULT_MAX_RETRIES`](crate::DEFAULT_MAX_RETRIES); `0` disables).
    #[must_use]
    pub fn with_max_retries(mut self, max_retries: usize) -> Self {
        self.parser = self.parser.with_max_retries(max_retries);
        self
    }

    /// Add a custom validator; see
    /// [`StructuredOutputParser::with_validator`]. Its error message is fed
    /// back to the model on the next attempt.
    #[must_use]
    pub fn with_validator<F>(mut self, validator: F) -> Self
    where
        F: Fn(&T) -> Result<(), String> + Send + Sync + 'static,
    {
        self.parser = self.parser.with_validator(validator);
        self
    }

    /// Lenient (default) or strict JSON extraction; see
    /// [`StructuredOutputParser::with_lenient`].
    #[must_use]
    pub fn with_lenient(mut self, lenient: bool) -> Self {
        self.parser = self.parser.with_lenient(lenient);
        self
    }

    /// Cap the size of model output that is parsed; see
    /// [`StructuredOutputParser::with_max_input_bytes`].
    #[must_use]
    pub fn with_max_input_bytes(mut self, max: usize) -> Self {
        self.parser = self.parser.with_max_input_bytes(max);
        self
    }

    /// The underlying parser.
    #[must_use]
    pub const fn parser(&self) -> &StructuredOutputParser<T> {
        &self.parser
    }

    /// The schema name sent to the provider.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The configured [`Mode`].
    #[must_use]
    pub const fn mode(&self) -> Mode {
        self.mode
    }

    /// The [`ResponseFormat`] requested from the provider.
    #[must_use]
    pub fn response_format(&self) -> ResponseFormat {
        ResponseFormat::JsonSchema {
            name: self.name.clone(),
            schema: self.parser.schema().as_value().clone(),
            strict: self.strict,
        }
    }
}

#[cfg(feature = "schemars")]
impl<T: schemars::JsonSchema> Extractor<T> {
    /// Create an extractor whose schema is generated from `T` by
    /// [`schemars`], named after the type.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_chain_output_parser::Extractor;
    ///
    /// #[derive(serde::Deserialize, schemars::JsonSchema)]
    /// struct Weather { city: String, temp_c: f64 }
    ///
    /// let ex = Extractor::<Weather>::for_type().unwrap();
    /// assert_eq!(ex.name(), "Weather");
    /// let w = ex.parse(r#"{"city": "Oslo", "temp_c": -3.5}"#).unwrap();
    /// assert_eq!(w.city, "Oslo");
    /// assert!(ex.parse(r#"{"city": "Oslo"}"#).is_err());
    /// ```
    pub fn for_type() -> Result<Self, StructuredError> {
        Ok(Self::new(crate::schema_for::<T>())?.with_name(&T::schema_name()))
    }
}

impl<T: DeserializeOwned> Extractor<T> {
    /// Parse and validate one model answer, without calling a model.
    pub fn parse(&self, text: &str) -> Result<T, StructuredError> {
        self.parser.parse_value(text).map(|(v, _)| v)
    }

    /// Ask `llm` for a `T`, re-asking with the error on bad output.
    ///
    /// Each retry sends `messages`, then the rejected answer (as an AI turn)
    /// and what was wrong with it (as a human turn); only the latest
    /// rejected exchange is kept. Transport errors and over-size output are
    /// returned at once; after the last retry the error is
    /// [`StructuredError::RetriesExhausted`].
    pub async fn extract<L>(
        &self,
        llm: &L,
        messages: &[Message],
    ) -> Result<StructuredOutput<T>, StructuredError>
    where
        L: Llm + ?Sized,
    {
        let format = self.response_format();
        let format = &format;
        self.parser
            .repair_loop(|req| {
                let msgs = with_repair(messages, req.as_ref());
                let mode = self.mode;
                async move { request(llm, mode, format, &msgs).await }
            })
            .await
    }
}

/// `messages`, plus the rejected answer and the feedback on it.
fn with_repair(messages: &[Message], req: Option<&RepairRequest>) -> Vec<Message> {
    let mut msgs = messages.to_vec();
    if let Some(req) = req {
        msgs.push(Message::ai(req.previous.clone()));
        msgs.push(Message::human(req.feedback.clone()));
    }
    msgs
}

/// One non-streaming request in the given mode.
async fn request<L: Llm + ?Sized>(
    llm: &L,
    mode: Mode,
    format: &ResponseFormat,
    messages: &[Message],
) -> Result<GenerateResult, LlmError> {
    match mode {
        Mode::Prompt => llm.generate(&format.apply_to(messages)).await,
        Mode::Native => llm.generate_structured(messages, format).await,
    }
}

impl<T: DeserializeOwned + Send + 'static> Extractor<T> {
    /// Stream a `T` from `llm`, yielding a [`StreamEvent::Partial`] each
    /// time the value grows (for progressive UIs), then one
    /// [`StreamEvent::Done`] with the validated value, or an error.
    ///
    /// Streaming always uses prompt instructions (`Llm::stream` takes no
    /// response format) and does not re-ask: on bad output the final item
    /// is the parse error (use [`stream_with_reask`](Self::stream_with_reask)
    /// to re-ask instead). Output above the size cap ends the stream with
    /// [`StructuredError::TooLarge`].
    ///
    /// # Example
    ///
    /// ```rust
    /// use std::pin::Pin;
    ///
    /// use async_trait::async_trait;
    /// use futures::{Stream, StreamExt, stream};
    /// use rune_chain_core::{GenerateResult, Llm, LlmError, Message, StreamData};
    /// use rune_chain_output_parser::{Extractor, StreamEvent};
    /// use serde::Deserialize;
    /// use serde_json::json;
    ///
    /// struct Mock;
    ///
    /// #[async_trait]
    /// impl Llm for Mock {
    ///     async fn generate(&self, _: &[Message]) -> Result<GenerateResult, LlmError> {
    ///         unimplemented!("only streaming is used here")
    ///     }
    ///     async fn stream(
    ///         &self,
    ///         _: &[Message],
    ///     ) -> Result<Pin<Box<dyn Stream<Item = Result<StreamData, LlmError>> + Send>>, LlmError> {
    ///         let chunks = ["{\"title\": \"Du", "ne\", \"year\":", " 1965}"];
    ///         Ok(Box::pin(stream::iter(chunks.map(|c| Ok(StreamData::chunk(c))))))
    ///     }
    /// }
    ///
    /// #[derive(Debug, Default, Deserialize)]
    /// #[serde(default)]
    /// struct Book { title: String, year: u32 }
    ///
    /// # tokio::runtime::Builder::new_current_thread().build().unwrap().block_on(async {
    /// let ex = Extractor::<Book>::new(json!({"type": "object", "required": ["title", "year"]})).unwrap();
    /// let mut events = ex.stream(&Mock, &[Message::human("A 1965 novel")]).await.unwrap();
    /// let mut titles = vec![];
    /// while let Some(event) = events.next().await {
    ///     match event.unwrap() {
    ///         StreamEvent::Partial(p) => titles.push(p.value.unwrap().title),
    ///         StreamEvent::Done(out) => assert_eq!(out.value.year, 1965),
    ///         _ => {}
    ///     }
    /// }
    /// assert_eq!(titles, ["Du", "Dune", "Dune"]);
    /// # });
    /// ```
    pub async fn stream<L>(
        &self,
        llm: &L,
        messages: &[Message],
    ) -> Result<ExtractStream<T>, StructuredError>
    where
        L: Llm + ?Sized,
    {
        let inner = llm
            .stream(&self.response_format().apply_to(messages))
            .await?;
        let state = StreamState {
            inner,
            acc: PartialJsonParser::new().with_max_bytes(self.parser.max_input_bytes()),
            parser: self.parser.clone(),
            ended: false,
            finished: false,
        };
        Ok(Box::pin(futures::stream::unfold(state, next_event)))
    }

    /// Like [`stream`](Self::stream), but when the streamed answer fails
    /// final validation (no JSON, a schema violation, a value that does not
    /// fit `T`, or a validator's `Err`), the model is asked again without
    /// streaming, with the rejected answer and the error appended — exactly
    /// as [`extract`](Self::extract) does, in the configured [`Mode`]
    /// (`Native` re-asks through [`Llm::generate_structured`]).
    ///
    /// Before each re-ask the stream yields [`StreamEvent::Retrying`], so a
    /// UI can drop its stale preview. The streamed answer counts as the
    /// first attempt, so there are at most
    /// [`with_max_retries`](Self::with_max_retries) re-asks; after the last
    /// one the error is [`StructuredError::RetriesExhausted`]. Transport
    /// errors and over-size output are not retried. The stream borrows
    /// `llm` for the re-asks.
    ///
    /// # Example
    ///
    /// ```rust
    /// use std::pin::Pin;
    ///
    /// use async_trait::async_trait;
    /// use futures::{Stream, StreamExt, stream};
    /// use rune_chain_core::{GenerateResult, Llm, LlmError, Message, ResponseFormat, StreamData};
    /// use rune_chain_output_parser::{Extractor, StreamEvent};
    /// use serde_json::json;
    ///
    /// /// Streams a bad answer, then fixes it when asked again.
    /// struct Mock;
    ///
    /// #[async_trait]
    /// impl Llm for Mock {
    ///     async fn generate(&self, _: &[Message]) -> Result<GenerateResult, LlmError> {
    ///         Ok(GenerateResult::from_text("[1, 2, 3]"))
    ///     }
    ///     async fn generate_structured(
    ///         &self,
    ///         m: &[Message],
    ///         _: &ResponseFormat,
    ///     ) -> Result<GenerateResult, LlmError> {
    ///         self.generate(m).await
    ///     }
    ///     async fn stream(
    ///         &self,
    ///         _: &[Message],
    ///     ) -> Result<Pin<Box<dyn Stream<Item = Result<StreamData, LlmError>> + Send>>, LlmError> {
    ///         Ok(Box::pin(stream::iter(["[1, ", "\"two\"]"].map(|c| Ok(StreamData::chunk(c))))))
    ///     }
    /// }
    ///
    /// # tokio::runtime::Builder::new_current_thread().build().unwrap().block_on(async {
    /// let ex = Extractor::<Vec<u32>>::new(json!({"type": "array", "items": {"type": "integer"}})).unwrap();
    /// let events: Vec<_> = ex
    ///     .stream_with_reask(&Mock, &[Message::human("count to three")])
    ///     .await
    ///     .unwrap()
    ///     .collect()
    ///     .await;
    /// assert!(matches!(&events[events.len() - 2], Ok(StreamEvent::Retrying(r)) if r.attempt == 2));
    /// let Some(Ok(StreamEvent::Done(out))) = events.last() else { panic!() };
    /// assert_eq!((out.value.clone(), out.attempts), (vec![1, 2, 3], 2));
    /// # });
    /// ```
    pub async fn stream_with_reask<'a, L>(
        &self,
        llm: &'a L,
        messages: &[Message],
    ) -> Result<ReaskStream<'a, T>, StructuredError>
    where
        L: Llm + ?Sized,
    {
        let inner = llm
            .stream(&self.response_format().apply_to(messages))
            .await?;
        let state = ReaskState {
            streaming: Some(StreamState {
                inner,
                acc: PartialJsonParser::new().with_max_bytes(self.parser.max_input_bytes()),
                parser: self.parser.clone(),
                ended: false,
                finished: false,
            }),
            llm,
            messages: messages.to_vec(),
            format: self.response_format(),
            mode: self.mode,
            parser: self.parser.clone(),
            pending: None,
            usage: None,
            finished: false,
        };
        Ok(Box::pin(futures::stream::unfold(state, next_reask_event)))
    }
}

type ChunkStream = Pin<Box<dyn Stream<Item = Result<StreamData, LlmError>> + Send>>;

struct StreamState<T> {
    inner: ChunkStream,
    acc: PartialJsonParser<T>,
    parser: StructuredOutputParser<T>,
    /// The model stream has ended; the next item is the final one.
    ended: bool,
    /// The final item has been yielded.
    finished: bool,
}

type EventItem<T> = Result<StreamEvent<T>, StructuredError>;

/// What the model stream produced next.
enum Step<T> {
    /// A preview or an error to pass on.
    Event(EventItem<T>),
    /// The stream ended: the full text and its parse result.
    Final(String, Result<(T, Value), StructuredError>),
}

async fn next_event<T: DeserializeOwned>(
    st: StreamState<T>,
) -> Option<(EventItem<T>, StreamState<T>)> {
    let (step, st) = next_step(st).await?;
    let item = match step {
        Step::Event(item) => item,
        Step::Final(raw, result) => result.map(|(value, json)| {
            StreamEvent::Done(StructuredOutput {
                value,
                json,
                raw,
                attempts: 1,
                usage: None,
            })
        }),
    };
    Some((item, st))
}

async fn next_step<T: DeserializeOwned>(
    mut st: StreamState<T>,
) -> Option<(Step<T>, StreamState<T>)> {
    if st.finished {
        return None;
    }
    while !st.ended {
        match st.inner.next().await {
            Some(Ok(chunk)) => {
                st.ended = chunk.is_finished;
                let len = st.acc.text().len().saturating_add(chunk.content.len());
                let partial = st.acc.push(&chunk.content);
                if st.acc.is_overflowed() {
                    st.finished = true;
                    let limit = st.parser.max_input_bytes();
                    let err = StructuredError::TooLarge { len, limit };
                    return Some((Step::Event(Err(err)), st));
                }
                if let Some(p) = partial {
                    return Some((Step::Event(Ok(StreamEvent::Partial(p))), st));
                }
            }
            Some(Err(e)) => {
                st.finished = true;
                return Some((Step::Event(Err(e.into())), st));
            }
            None => st.ended = true,
        }
    }
    st.finished = true;
    let raw = st.acc.text().to_owned();
    let result = st.parser.parse_value(&raw);
    Some((Step::Final(raw, result), st))
}

struct ReaskState<'a, T, L: ?Sized> {
    /// The streamed first attempt, until it ends.
    streaming: Option<StreamState<T>>,
    llm: &'a L,
    messages: Vec<Message>,
    format: ResponseFormat,
    mode: Mode,
    parser: StructuredOutputParser<T>,
    /// The re-ask to make next.
    pending: Option<RepairRequest>,
    /// Usage summed over the re-asks (streams report none).
    usage: Option<TokenUsage>,
    finished: bool,
}

impl<T, L: ?Sized> ReaskState<'_, T, L> {
    /// Attempt `attempt` produced `raw`, rejected with `error`: re-ask, or
    /// give up once the retries are spent.
    fn rejected(&mut self, attempt: usize, raw: String, error: StructuredError) -> EventItem<T> {
        if !error.is_repairable() {
            self.finished = true;
            return Err(error);
        }
        if attempt > self.parser.max_retries() {
            self.finished = true;
            return Err(StructuredError::RetriesExhausted {
                attempts: attempt,
                last: Box::new(error),
                raw,
            });
        }
        let req = RepairRequest {
            attempt: attempt + 1,
            feedback: self.parser.repair_prompt(&error),
            previous: raw,
        };
        self.pending = Some(req.clone());
        Ok(StreamEvent::Retrying(req))
    }

    fn accepted(
        &mut self,
        attempt: usize,
        raw: String,
        (value, json): (T, Value),
    ) -> StreamEvent<T> {
        self.finished = true;
        StreamEvent::Done(StructuredOutput {
            value,
            json,
            raw,
            attempts: attempt,
            usage: self.usage.take(),
        })
    }
}

async fn next_reask_event<T, L>(
    mut st: ReaskState<'_, T, L>,
) -> Option<(EventItem<T>, ReaskState<'_, T, L>)>
where
    T: DeserializeOwned,
    L: Llm + ?Sized,
{
    if st.finished {
        return None;
    }
    if let Some(stream) = st.streaming.take() {
        let (step, stream) = next_step(stream).await?;
        let item = match step {
            Step::Event(item) => {
                st.finished = item.is_err();
                st.streaming = Some(stream);
                item
            }
            Step::Final(raw, Ok(parsed)) => Ok(st.accepted(1, raw, parsed)),
            Step::Final(raw, Err(e)) => st.rejected(1, raw, e),
        };
        return Some((item, st));
    }
    let req = st.pending.take()?;
    let msgs = with_repair(&st.messages, Some(&req));
    let item = match request(st.llm, st.mode, &st.format, &msgs).await {
        Err(e) => {
            st.finished = true;
            Err(e.into())
        }
        Ok(result) => {
            if let Some(t) = &result.tokens {
                st.usage = Some(st.usage.take().map_or_else(|| t.clone(), |u| u.combine(t)));
            }
            let raw = result.generation;
            match st.parser.parse_value(&raw) {
                Ok(parsed) => Ok(st.accepted(req.attempt, raw, parsed)),
                Err(e) => st.rejected(req.attempt, raw, e),
            }
        }
    };
    Some((item, st))
}

fn sanitize_name(name: &str) -> String {
    let out: String = name
        .chars()
        .take(MAX_NAME_CHARS)
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' || c == '-' {
                c
            } else {
                '_'
            }
        })
        .collect();
    if out.is_empty() {
        DEFAULT_NAME.to_owned()
    } else {
        out
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use async_trait::async_trait;
    use futures::stream;
    use rune_chain_core::{GenerateResult, Role};
    use serde::Deserialize;
    use serde_json::json;

    use super::*;

    #[derive(Debug, Default, Deserialize, PartialEq)]
    #[serde(default)]
    struct Item {
        name: String,
        qty: u32,
    }

    fn extractor() -> Extractor<Item> {
        Extractor::new(json!({
            "type": "object",
            "properties": {"name": {"type": "string"}, "qty": {"type": "integer", "minimum": 1}},
            "required": ["name", "qty"]
        }))
        .unwrap()
    }

    /// Records calls; replies from a script; streams fixed chunks.
    #[derive(Default)]
    struct Mock {
        replies: Mutex<Vec<&'static str>>,
        generate_calls: Mutex<Vec<Vec<Message>>>,
        structured_calls: Mutex<Vec<ResponseFormat>>,
        chunks: Vec<&'static str>,
        native: bool,
    }

    impl Mock {
        fn new(replies: &[&'static str]) -> Self {
            Self {
                replies: Mutex::new(replies.iter().rev().copied().collect()),
                ..Self::default()
            }
        }
    }

    #[async_trait]
    impl Llm for Mock {
        async fn generate(&self, messages: &[Message]) -> Result<GenerateResult, LlmError> {
            self.generate_calls.lock().unwrap().push(messages.to_vec());
            self.replies
                .lock()
                .unwrap()
                .pop()
                .map(GenerateResult::from_text)
                .ok_or_else(|| LlmError::other("exhausted"))
        }

        async fn generate_structured(
            &self,
            messages: &[Message],
            format: &ResponseFormat,
        ) -> Result<GenerateResult, LlmError> {
            self.structured_calls.lock().unwrap().push(format.clone());
            if self.native {
                self.generate(messages).await
            } else {
                self.generate(&format.apply_to(messages)).await
            }
        }

        async fn stream(&self, _: &[Message]) -> Result<ChunkStream, LlmError> {
            let items: Vec<_> = self
                .chunks
                .iter()
                .map(|c| Ok(StreamData::chunk(*c)))
                .collect();
            Ok(Box::pin(stream::iter(items)))
        }
    }

    #[tokio::test]
    async fn native_mode_sends_response_format() {
        let llm = Mock {
            native: true,
            ..Mock::new(&[r#"{"name": "pen", "qty": 2}"#])
        };
        let out = extractor()
            .with_name("line item!")
            .extract(&llm, &[Message::human("2 pens")])
            .await
            .unwrap();
        assert_eq!(
            out.value,
            Item {
                name: "pen".into(),
                qty: 2
            }
        );
        let formats = llm.structured_calls.lock().unwrap().clone();
        let ResponseFormat::JsonSchema { name, strict, .. } = &formats[0] else {
            panic!("{formats:?}")
        };
        assert_eq!(name, "line_item_");
        assert!(!strict);
        // Native: no instructions injected.
        assert_eq!(llm.generate_calls.lock().unwrap()[0].len(), 1);
    }

    #[tokio::test]
    async fn prompt_mode_injects_instructions() {
        let llm = Mock::new(&[r#"{"name": "pen", "qty": 2}"#]);
        extractor()
            .with_mode(Mode::Prompt)
            .extract(&llm, &[Message::human("2 pens")])
            .await
            .unwrap();
        assert!(llm.structured_calls.lock().unwrap().is_empty());
        let calls = llm.generate_calls.lock().unwrap().clone();
        assert_eq!(calls[0][0].role, Role::System);
        assert!(calls[0][0].content.text_content().contains("\"qty\""));
    }

    #[tokio::test]
    async fn reasks_with_validator_message() {
        let llm = Mock::new(&[
            r#"{"name": "", "qty": 0}"#,
            r#"{"name": "", "qty": 3}"#,
            r#"{"name": "pen", "qty": 3}"#,
        ]);
        let out = extractor()
            .with_validator(|i| {
                if i.name.is_empty() {
                    Err("name must not be empty".into())
                } else {
                    Ok(())
                }
            })
            .extract(&llm, &[Message::human("3 pens")])
            .await
            .unwrap();
        assert_eq!(out.attempts, 3);
        let calls = llm.generate_calls.lock().unwrap().clone();
        let last = calls[2].last().unwrap().content.text_content();
        assert!(last.contains("name must not be empty"), "{last}");
        assert!(
            calls[1]
                .last()
                .unwrap()
                .content
                .text_content()
                .contains("/qty")
        );
    }

    #[tokio::test]
    async fn retries_are_bounded() {
        let llm = Mock::new(&["no", "no", "no"]);
        let err = extractor()
            .with_max_retries(1)
            .extract(&llm, &[])
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            StructuredError::RetriesExhausted { attempts: 2, .. }
        ));
    }

    #[tokio::test]
    async fn oversize_output_is_not_retried() {
        let llm = Mock::new(&["[1,2,3,4,5,6,7,8,9]", "{}"]);
        let err = extractor()
            .with_max_input_bytes(8)
            .extract(&llm, &[])
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            StructuredError::TooLarge { len: 19, limit: 8 }
        ));
        assert_eq!(llm.generate_calls.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn stream_yields_partials_then_done() {
        let llm = Mock {
            chunks: vec!["Here: {\"na", "me\": \"pe", "n\", \"qty\": 4}"],
            ..Mock::default()
        };
        let events: Vec<_> = extractor().stream(&llm, &[]).await.unwrap().collect().await;
        let names: Vec<_> = events
            .iter()
            .filter_map(|e| match e {
                Ok(StreamEvent::Partial(p)) => p.value.as_ref().map(|v| v.name.clone()),
                _ => None,
            })
            .collect();
        assert_eq!(names, ["", "pe", "pen"]);
        let Some(Ok(StreamEvent::Done(out))) = events.last() else {
            panic!("{events:?}")
        };
        assert_eq!(out.value.qty, 4);
    }

    #[tokio::test]
    async fn stream_reports_invalid_final_value_and_overflow() {
        let llm = Mock {
            chunks: vec!["{\"name\": \"pen\", \"qty\": 0}"],
            ..Mock::default()
        };
        let events: Vec<_> = extractor().stream(&llm, &[]).await.unwrap().collect().await;
        assert!(matches!(
            events.last(),
            Some(Err(StructuredError::SchemaViolation(_)))
        ));

        let llm = Mock {
            chunks: vec!["[1, 2", ", 3, 4, 5, 6]"],
            ..Mock::default()
        };
        let events: Vec<_> = extractor()
            .with_max_input_bytes(8)
            .stream(&llm, &[])
            .await
            .unwrap()
            .collect()
            .await;
        assert!(matches!(
            events.last(),
            Some(Err(StructuredError::TooLarge { .. }))
        ));
        assert_eq!(events.len(), 2);
    }

    fn streaming(chunks: &[&'static str], replies: &[&'static str]) -> Mock {
        Mock {
            chunks: chunks.to_vec(),
            ..Mock::new(replies)
        }
    }

    async fn reask_events(ex: &Extractor<Item>, llm: &Mock) -> Vec<EventItem<Item>> {
        ex.stream_with_reask(llm, &[Message::human("pens")])
            .await
            .unwrap()
            .collect()
            .await
    }

    #[tokio::test]
    async fn reask_stream_passes_a_valid_answer_through() {
        let llm = streaming(&["{\"name\": \"pen\",", " \"qty\": 2}"], &[]);
        let events = reask_events(&extractor(), &llm).await;
        assert_eq!(events.len(), 3, "{events:?}");
        let Some(Ok(StreamEvent::Done(out))) = events.last() else {
            panic!("{events:?}")
        };
        assert_eq!(out.attempts, 1);
        assert!(llm.structured_calls.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn reask_stream_falls_back_to_structured_generation() {
        let llm = Mock {
            native: true,
            ..streaming(
                &["{\"name\": \"pen\", \"qty\": 0}"],
                &[r#"{"name": "pen"}"#, r#"{"name": "pen", "qty": 5}"#],
            )
        };
        let events = reask_events(&extractor(), &llm).await;
        let retries: Vec<usize> = events
            .iter()
            .filter_map(|e| match e {
                Ok(StreamEvent::Retrying(r)) => Some(r.attempt),
                _ => None,
            })
            .collect();
        assert_eq!(retries, [2, 3]);
        let Some(Ok(StreamEvent::Done(out))) = events.last() else {
            panic!("{events:?}")
        };
        assert_eq!((out.value.qty, out.attempts), (5, 3));

        // Each re-ask is a structured call carrying the rejected answer and
        // what was wrong with it.
        assert_eq!(llm.structured_calls.lock().unwrap().len(), 2);
        let calls = llm.generate_calls.lock().unwrap().clone();
        let first = &calls[0];
        assert_eq!(first[1].role, Role::Ai);
        assert!(first[1].content.text_content().contains("\"qty\": 0"));
        assert!(
            first[2].content.text_content().contains("/qty"),
            "{first:?}"
        );
        assert!(calls[1][2].content.text_content().contains("qty"));
    }

    #[tokio::test]
    async fn reask_stream_retries_are_bounded() {
        let llm = streaming(&["nothing"], &["still nothing", "nope", "never"]);
        let events = reask_events(&extractor().with_max_retries(1), &llm).await;
        assert!(matches!(
            events.last(),
            Some(Err(StructuredError::RetriesExhausted { attempts: 2, .. }))
        ));
        assert_eq!(llm.generate_calls.lock().unwrap().len(), 1);

        let llm = streaming(&["nothing"], &["unused"]);
        let events = reask_events(&extractor().with_max_retries(0), &llm).await;
        assert_eq!(events.len(), 1);
        assert!(matches!(
            events.last(),
            Some(Err(StructuredError::RetriesExhausted { attempts: 1, .. }))
        ));
        assert!(llm.generate_calls.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn reask_stream_does_not_retry_transport_errors_or_overflow() {
        let llm = streaming(&["{\"name\": \"pen\", \"qty\": 0}"], &[]);
        let events = reask_events(&extractor(), &llm).await;
        assert!(matches!(events.last(), Some(Err(StructuredError::Llm(_)))));

        let llm = streaming(&["[1, 2", ", 3, 4, 5, 6]"], &["{}"]);
        let events = reask_events(&extractor().with_max_input_bytes(8), &llm).await;
        assert!(matches!(
            events.last(),
            Some(Err(StructuredError::TooLarge { .. }))
        ));
        assert!(llm.generate_calls.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn reask_stream_respects_prompt_mode() {
        let llm = streaming(&["{}"], &[r#"{"name": "pen", "qty": 1}"#]);
        let events = reask_events(&extractor().with_mode(Mode::Prompt), &llm).await;
        assert!(matches!(events.last(), Some(Ok(StreamEvent::Done(_)))));
        assert!(llm.structured_calls.lock().unwrap().is_empty());
        let calls = llm.generate_calls.lock().unwrap().clone();
        assert_eq!(calls[0][0].role, Role::System);
    }

    #[test]
    fn names_are_sanitized() {
        assert_eq!(sanitize_name(""), "response");
        assert_eq!(sanitize_name("a.b c"), "a_b_c");
        assert_eq!(sanitize_name(&"x".repeat(100)).len(), 64);
        assert_eq!(sanitize_name("Vec<u8>"), "Vec_u8_");
    }
}
