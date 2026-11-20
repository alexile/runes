use std::pin::Pin;

use async_trait::async_trait;
use futures::{Stream, StreamExt, stream};

use crate::{
    DEFAULT_BATCH_CONCURRENCY, EventStream, FunctionDefinition, GenerateResult, LlmError,
    LlmErrorKind, Message, ResponseFormat, StreamData, ToolChoice,
    stream_event::{result_stream, text_stream},
};

/// An async interface to a large language model.
///
/// Implementors wrap a specific provider (`OpenAI`, Anthropic, Ollama, …) and
/// translate a slice of [`Message`]s into a [`GenerateResult`].
///
/// All methods have default implementations so providers only need to override
/// what they support. The minimum required method is [`generate`](Llm::generate).
#[async_trait]
pub trait Llm: Sync + Send {
    /// Send a slice of messages and return the model's complete response.
    async fn generate(&self, messages: &[Message]) -> Result<GenerateResult, LlmError>;

    /// Send messages together with tool definitions for native function calling.
    ///
    /// When the model decides to call a tool, the returned [`GenerateResult`]
    /// will have [`tool_calls`](GenerateResult::tool_calls) populated. The
    /// caller should execute those tools and feed results back as
    /// [`Message::tool_result`] turns before calling again.
    ///
    /// Providers that do not support function calling fail with
    /// [`LlmErrorKind::Unsupported`](crate::LlmErrorKind::Unsupported) by
    /// default.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_chain_core::{FunctionDefinition, Llm, LlmError, Message};
    ///
    /// async fn run(llm: &dyn Llm) -> Result<String, LlmError> {
    ///     let tools = [FunctionDefinition::single_input(
    ///         "upper_case",
    ///         "Converts text to upper case.",
    ///     )];
    ///     let mut messages = vec![Message::human("Shout 'hello'.")];
    ///     loop {
    ///         let result = llm.generate_with_tools(&messages, &tools, None).await?;
    ///         if !result.wants_tool_calls() {
    ///             return Ok(result.generation);
    ///         }
    ///         messages.push(result.to_message());
    ///         for call in &result.tool_calls {
    ///             // Validate untrusted arguments before running the tool.
    ///             let output = match call.validate(&tools[0]) {
    ///                 Ok(args) => args["input"].as_str().unwrap_or_default().to_uppercase(),
    ///                 Err(e) => e.to_string(),
    ///             };
    ///             messages.push(Message::tool_result(&call.id, output));
    ///         }
    ///     }
    /// }
    /// ```
    async fn generate_with_tools(
        &self,
        _messages: &[Message],
        _tools: &[FunctionDefinition],
        _tool_choice: Option<ToolChoice>,
    ) -> Result<GenerateResult, LlmError> {
        Err(LlmError::unsupported(
            "this provider does not support native function calling",
        ))
    }

    /// Stream tokens from the model as they are produced.
    ///
    /// Providers that do not support streaming fail with
    /// [`LlmErrorKind::Unsupported`](crate::LlmErrorKind::Unsupported) by default.
    async fn stream(
        &self,
        _messages: &[Message],
    ) -> Result<Pin<Box<dyn Stream<Item = Result<StreamData, LlmError>> + Send>>, LlmError> {
        Err(LlmError::unsupported(
            "streaming is not supported by this LLM provider",
        ))
    }

    /// Stream the reply as typed [`StreamEvent`](crate::StreamEvent)s:
    /// text and reasoning deltas, tool calls in fragments, usage and the
    /// finish reason. Pass `tools` to let the model call them.
    ///
    /// Fold the events with a [`StreamAccumulator`](crate::StreamAccumulator)
    /// to get the [`GenerateResult`] that
    /// [`generate_with_tools`](Llm::generate_with_tools) would have returned.
    ///
    /// Providers with native streaming tool calls override this. The default
    /// works with any provider:
    ///
    /// - without tools (`None` or empty) it adapts [`stream`](Llm::stream),
    ///   or replays [`generate`](Llm::generate) when streaming is
    ///   unsupported;
    /// - with tools it calls [`generate_with_tools`](Llm::generate_with_tools)
    ///   and replays the result as events, so nothing streams but callers
    ///   need only one code path.
    ///
    /// # Example
    ///
    /// ```rust
    /// use async_trait::async_trait;
    /// use futures::StreamExt;
    /// use rune_chain_core::{
    ///     FunctionDefinition, GenerateResult, Llm, LlmError, Message, StreamAccumulator,
    ///     StreamEvent, ToolCall, ToolChoice,
    /// };
    ///
    /// struct Model;
    ///
    /// #[async_trait]
    /// impl Llm for Model {
    ///     async fn generate(&self, _: &[Message]) -> Result<GenerateResult, LlmError> {
    ///         Ok(GenerateResult::from_text("hi"))
    ///     }
    ///     async fn generate_with_tools(
    ///         &self,
    ///         _: &[Message],
    ///         _: &[FunctionDefinition],
    ///         _: Option<ToolChoice>,
    ///     ) -> Result<GenerateResult, LlmError> {
    ///         Ok(GenerateResult::default()
    ///             .with_tool_calls(vec![ToolCall::new("c1", "clock", "{}")]))
    ///     }
    /// }
    ///
    /// # tokio_test::block_on(async {
    /// let tools = [FunctionDefinition::single_input("clock", "Current time.")];
    /// let mut stream = Model
    ///     .stream_events(&[Message::human("time?")], Some(&tools), None)
    ///     .await
    ///     .unwrap();
    /// let mut acc = StreamAccumulator::new();
    /// while let Some(event) = stream.next().await {
    ///     let event = event.unwrap();
    ///     if let StreamEvent::ToolCallStart { name, .. } = &event {
    ///         assert_eq!(name, "clock");
    ///     }
    ///     acc.push(&event).unwrap();
    /// }
    /// assert_eq!(acc.finish().tool_calls[0].id, "c1");
    /// # });
    /// ```
    async fn stream_events(
        &self,
        messages: &[Message],
        tools: Option<&[FunctionDefinition]>,
        tool_choice: Option<ToolChoice>,
    ) -> Result<EventStream, LlmError> {
        if let Some(tools) = tools.filter(|t| !t.is_empty()) {
            let result = self
                .generate_with_tools(messages, tools, tool_choice)
                .await?;
            return Ok(result_stream(result));
        }
        match self.stream(messages).await {
            Ok(stream) => Ok(text_stream(stream)),
            Err(e) if e.kind() == LlmErrorKind::Unsupported => {
                Ok(result_stream(self.generate(messages).await?))
            }
            Err(e) => Err(e),
        }
    }

    /// Generate a response in the requested [`ResponseFormat`] (structured
    /// output).
    ///
    /// Providers with native JSON / JSON-Schema modes should override this.
    /// The default works with any provider: for the JSON formats it adds
    /// [`ResponseFormat::instructions`] as a system message (see
    /// [`ResponseFormat::apply_to`]) and calls [`generate`](Llm::generate);
    /// for [`ResponseFormat::Text`] it is plain `generate`. Either way the
    /// returned `generation` is the raw model text — parse it with
    /// [`ResponseFormat::parse_json`].
    ///
    /// # Example
    ///
    /// ```rust
    /// use async_trait::async_trait;
    /// use rune_chain_core::{GenerateResult, Llm, LlmError, Message, ResponseFormat};
    ///
    /// struct Fixed;
    ///
    /// #[async_trait]
    /// impl Llm for Fixed {
    ///     async fn generate(&self, _: &[Message]) -> Result<GenerateResult, LlmError> {
    ///         Ok(GenerateResult::from_text("```json\n{\"answer\": 4}\n```"))
    ///     }
    /// }
    ///
    /// # tokio_test::block_on(async {
    /// let format = ResponseFormat::JsonObject;
    /// let out = Fixed
    ///     .generate_structured(&[Message::human("2 + 2?")], &format)
    ///     .await
    ///     .unwrap();
    /// assert_eq!(format.parse_json(&out.generation).unwrap()["answer"], 4);
    /// # });
    /// ```
    async fn generate_structured(
        &self,
        messages: &[Message],
        format: &ResponseFormat,
    ) -> Result<GenerateResult, LlmError> {
        if format.is_json() {
            self.generate(&format.apply_to(messages)).await
        } else {
            self.generate(messages).await
        }
    }

    /// Run [`generate`](Llm::generate) on many conversations, at most
    /// [`DEFAULT_BATCH_CONCURRENCY`] at a time.
    ///
    /// Results come back in input order, one per conversation; a failed
    /// request does not stop the others. The conversations are borrowed,
    /// not cloned.
    ///
    /// # Example
    ///
    /// ```rust
    /// use async_trait::async_trait;
    /// use rune_chain_core::{GenerateResult, Llm, LlmError, Message};
    ///
    /// struct Echo;
    /// #[async_trait]
    /// impl Llm for Echo {
    ///     async fn generate(&self, m: &[Message]) -> Result<GenerateResult, LlmError> {
    ///         Ok(GenerateResult::from_text(m[0].text()))
    ///     }
    /// }
    ///
    /// # tokio_test::block_on(async {
    /// let inputs = [vec![Message::human("a")], vec![Message::human("b")]];
    /// let out = Echo.batch(&inputs).await;
    /// assert_eq!(out[1].as_ref().unwrap().generation, "b");
    /// # });
    /// ```
    async fn batch(&self, inputs: &[Vec<Message>]) -> Vec<Result<GenerateResult, LlmError>> {
        self.batch_with_concurrency(inputs, DEFAULT_BATCH_CONCURRENCY)
            .await
    }

    /// Like [`Llm::batch`] with an explicit concurrency limit (`0` is
    /// treated as `1`).
    async fn batch_with_concurrency(
        &self,
        inputs: &[Vec<Message>],
        max_concurrency: usize,
    ) -> Vec<Result<GenerateResult, LlmError>> {
        // Index instead of `iter()` so the closure has no higher-ranked
        // argument lifetime, which `async_trait`'s Send check rejects.
        stream::iter((0..inputs.len()).map(|i| self.generate(&inputs[i])))
            .buffered(max_concurrency.max(1))
            .collect()
            .await
    }
}
