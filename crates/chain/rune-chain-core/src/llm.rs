use std::pin::Pin;

use async_trait::async_trait;
use futures::{Stream, StreamExt, stream};

use crate::{
    DEFAULT_BATCH_CONCURRENCY, FunctionDefinition, GenerateResult, LlmError, Message,
    ResponseFormat, StreamData, ToolChoice,
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
