//! Typed extraction from an LLM: the Rust take on Python's `instructor`.

use std::pin::Pin;

use futures::{Stream, StreamExt};
use rune_chain_core::{Llm, LlmError, Message, ResponseFormat, StreamData};
use serde::de::DeserializeOwned;
use serde_json::Value;

use crate::{
    Partial, PartialJsonParser, StructuredError, StructuredOutput, StructuredOutputParser,
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
}

/// The stream returned by [`Extractor::stream`].
pub type ExtractStream<T> =
    Pin<Box<dyn Stream<Item = Result<StreamEvent<T>, StructuredError>> + Send>>;

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
                let mut msgs = messages.to_vec();
                if let Some(req) = req {
                    msgs.push(Message::ai(req.previous));
                    msgs.push(Message::human(req.feedback));
                }
                let mode = self.mode;
                async move {
                    match mode {
                        Mode::Prompt => llm.generate(&format.apply_to(&msgs)).await,
                        Mode::Native => llm.generate_structured(&msgs, format).await,
                    }
                }
            })
            .await
    }
}

impl<T: DeserializeOwned + Send + 'static> Extractor<T> {
    /// Stream a `T` from `llm`, yielding a [`StreamEvent::Partial`] each
    /// time the value grows (for progressive UIs), then one
    /// [`StreamEvent::Done`] with the validated value, or an error.
    ///
    /// Streaming always uses prompt instructions (`Llm::stream` takes no
    /// response format) and does not re-ask: on bad output the final item
    /// is the parse error. Output above the size cap ends the stream with
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

async fn next_event<T: DeserializeOwned>(
    mut st: StreamState<T>,
) -> Option<(Result<StreamEvent<T>, StructuredError>, StreamState<T>)> {
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
                    return Some((Err(StructuredError::TooLarge { len, limit }), st));
                }
                if let Some(p) = partial {
                    return Some((Ok(StreamEvent::Partial(p)), st));
                }
            }
            Some(Err(e)) => {
                st.finished = true;
                return Some((Err(e.into()), st));
            }
            None => st.ended = true,
        }
    }
    st.finished = true;
    let raw = st.acc.text().to_owned();
    let result = st.parser.parse_value(&raw).map(|(value, json)| {
        StreamEvent::Done(StructuredOutput {
            value,
            json,
            raw,
            attempts: 1,
            usage: None,
        })
    });
    Some((result, st))
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

    #[test]
    fn names_are_sanitized() {
        assert_eq!(sanitize_name(""), "response");
        assert_eq!(sanitize_name("a.b c"), "a_b_c");
        assert_eq!(sanitize_name(&"x".repeat(100)).len(), 64);
        assert_eq!(sanitize_name("Vec<u8>"), "Vec_u8_");
    }
}
