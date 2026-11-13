use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use futures::StreamExt;
use rune_chain_core::{
    Chain, ChainError, GenerateResult, Llm, LlmError, LlmErrorKind, Memory, Message, PromptArgs,
    ResponseFormat, Role,
};
use rune_chain_output_parser::OutputParser;
use rune_chain_prompt::ChatTemplate;
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::Value;

use crate::{ChainStream, LlmOutput, with_stream_completion};

const DEFAULT_OUTPUT_KEY: &str = "output";
const RESULT_KEY: &str = "generate_result";

type ParseFn = Arc<dyn Fn(&str) -> Result<Value, ChainError> + Send + Sync>;

/// A chain that renders a prompt template, sends it to an [`Llm`] and
/// optionally parses the answer.
///
/// Build it with [`new`](Self::new) and the `with_*` methods:
///
/// - [`with_memory`](Self::with_memory): conversation history between the
///   template's system messages and its new input;
/// - [`with_max_context_tokens`](Self::with_max_context_tokens): refuse
///   prompts over an estimated token budget before calling the model;
/// - [`with_response_format`](Self::with_response_format): structured output
///   through [`Llm::generate_structured`], with the JSON parsed and checked;
/// - [`with_output_parser`](Self::with_output_parser): any
///   [`OutputParser`], with its format instructions added to the prompt;
/// - [`with_output_key`](Self::with_output_key): the key used by
///   [`Chain::execute`].
///
/// [`run`](Self::run) returns an [`LlmOutput`] with the text, usage, finish
/// reason and parsed value; [`invoke_structured`](Self::invoke_structured)
/// deserializes straight into a type.
///
/// The template may contain [`MessagesPlaceholder`](rune_chain_prompt::MessagesPlaceholder)s,
/// filled from inputs built with [`messages_value`](rune_chain_prompt::messages_value).
/// Their messages stay where the placeholder is and, unlike the template's
/// own human turns, are never written to memory.
///
/// # Example
///
/// ```rust
/// use async_trait::async_trait;
/// use rune_chain_core::{
///     FinishReason, GenerateResult, Llm, LlmError, Message, ResponseFormat, TokenUsage,
///     prompt_args,
/// };
/// use rune_chain_llm::LlmChain;
/// use rune_chain_prompt::{ChatTemplate, MessageTemplate};
///
/// struct Mock;
///
/// #[async_trait]
/// impl Llm for Mock {
///     async fn generate(&self, _: &[Message]) -> Result<GenerateResult, LlmError> {
///         Ok(GenerateResult::from_text(r#"{"city": "Oslo"}"#)
///             .with_tokens(TokenUsage::new(20, 5))
///             .with_finish_reason(FinishReason::Stop))
///     }
/// }
///
/// #[derive(serde::Deserialize)]
/// struct Answer { city: String }
///
/// # tokio_test::block_on(async {
/// let chain = LlmChain::new(Mock, ChatTemplate::new(vec![
///     MessageTemplate::human("Which city is the capital of {country}?"),
/// ]))
/// .with_response_format(ResponseFormat::JsonObject);
///
/// let out = chain.run(prompt_args! { "country" => "Norway" }).await.unwrap();
/// assert_eq!(out.usage().unwrap().total_tokens, 25);
/// assert_eq!(out.finish_reason(), Some(&FinishReason::Stop));
/// assert_eq!(out.parse_as::<Answer>().unwrap().city, "Oslo");
/// # });
/// ```
pub struct LlmChain<L: Llm> {
    llm: L,
    prompt: ChatTemplate,
    memory: Option<Arc<dyn Memory>>,
    max_context_tokens: Option<usize>,
    output_key: String,
    response_format: Option<ResponseFormat>,
    parser: Option<ParseFn>,
    format_instructions: Option<String>,
    inject_format_instructions: bool,
}

impl<L: Llm> std::fmt::Debug for LlmChain<L> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LlmChain")
            .field("input_keys", &self.prompt.input_variables())
            .field("has_memory", &self.memory.is_some())
            .field("max_context_tokens", &self.max_context_tokens)
            .field("output_key", &self.output_key)
            .field("response_format", &self.response_format)
            .field("has_parser", &self.parser.is_some())
            .finish_non_exhaustive()
    }
}

impl<L: Llm> LlmChain<L> {
    /// Create a chain from an LLM and a prompt template, with no memory, no
    /// token limit and plain text output.
    pub fn new(llm: L, prompt: ChatTemplate) -> Self {
        Self {
            llm,
            prompt,
            memory: None,
            max_context_tokens: None,
            output_key: DEFAULT_OUTPUT_KEY.to_string(),
            response_format: None,
            parser: None,
            format_instructions: None,
            inject_format_instructions: true,
        }
    }

    /// Attach a [`Memory`] store for multi-turn conversation history.
    ///
    /// Each successful [`call`](Chain::call), and each [`stream`](Chain::stream)
    /// read to the end, records the human turns of the rendered prompt and
    /// the model's answer.
    #[must_use]
    pub fn with_memory(mut self, memory: Arc<dyn Memory>) -> Self {
        self.memory = Some(memory);
        self
    }

    /// Refuse prompts (history included) estimated above `max_tokens`
    /// (about four characters per token) without calling the model. The
    /// error is an [`LlmError`] of kind [`LlmErrorKind::ContextLengthExceeded`].
    #[must_use]
    pub const fn with_max_context_tokens(mut self, max_tokens: usize) -> Self {
        self.max_context_tokens = Some(max_tokens);
        self
    }

    /// Store the answer under `key` in [`Chain::execute`] (default
    /// `"output"`).
    #[must_use]
    pub fn with_output_key(mut self, key: impl Into<String>) -> Self {
        self.output_key = key.into();
        self
    }

    /// Ask for structured output.
    ///
    /// Calls go through [`Llm::generate_structured`], so providers with a
    /// native JSON or JSON-Schema mode use it and others are prompted for
    /// JSON. For the JSON formats the answer is parsed with
    /// [`ResponseFormat::parse_json`]; output that is not valid JSON fails
    /// the call with [`ChainError::ParseError`]. Streams cannot use native
    /// modes, so they get the format's instructions in the prompt instead.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_chain_core::{Chain, ResponseFormat};
    /// use rune_chain_llm::LlmChain;
    /// use rune_chain_prompt::{ChatTemplate, MessageTemplate};
    /// # use rune_chain_core::{GenerateResult, Llm, LlmError, Message};
    /// # struct Mock;
    /// # #[async_trait::async_trait]
    /// # impl Llm for Mock {
    /// #     async fn generate(&self, _: &[Message]) -> Result<GenerateResult, LlmError> {
    /// #         Ok(GenerateResult::from_text("{}"))
    /// #     }
    /// # }
    ///
    /// let chain = LlmChain::new(Mock, ChatTemplate::new(vec![MessageTemplate::human("{q}")]))
    ///     .with_response_format(ResponseFormat::JsonObject);
    /// assert_eq!(chain.output_keys(), ["output_parsed", "output", "generate_result"]);
    /// ```
    #[must_use]
    pub fn with_response_format(mut self, format: ResponseFormat) -> Self {
        self.response_format = Some(format);
        self
    }

    /// Parse every answer with `parser`.
    ///
    /// The parsed value is serialized to JSON and returned in
    /// [`LlmOutput::parsed`] and under `"<output_key>_parsed"` in
    /// [`Chain::execute`]. A parse failure fails the call (and nothing is
    /// written to memory). The parser's
    /// [`format_instructions`](OutputParser::format_instructions), if any,
    /// are added as a system message after the template's own system
    /// messages; turn that off with
    /// [`inject_format_instructions(false)`](Self::inject_format_instructions).
    ///
    /// When both a parser and a JSON response format are set, the parser
    /// produces the parsed value.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_chain_core::prompt_args;
    /// use rune_chain_llm::LlmChain;
    /// use rune_chain_output_parser::ListOutputParser;
    /// use rune_chain_prompt::{ChatTemplate, MessageTemplate};
    /// # use rune_chain_core::{GenerateResult, Llm, LlmError, Message};
    /// # struct Mock;
    /// # #[async_trait::async_trait]
    /// # impl Llm for Mock {
    /// #     async fn generate(&self, _: &[Message]) -> Result<GenerateResult, LlmError> {
    /// #         Ok(GenerateResult::from_text("red, green, blue"))
    /// #     }
    /// # }
    ///
    /// # tokio_test::block_on(async {
    /// let chain = LlmChain::new(Mock, ChatTemplate::new(vec![MessageTemplate::human("Name {n} colours")]))
    ///     .with_output_parser(ListOutputParser::with_delimiter(","));
    /// let colours: Vec<String> = chain.invoke_structured(prompt_args! { "n" => 3 }).await.unwrap();
    /// assert_eq!(colours, ["red", "green", "blue"]);
    /// # });
    /// ```
    #[must_use]
    pub fn with_output_parser<T, P>(mut self, parser: P) -> Self
    where
        T: Serialize,
        P: OutputParser<T> + 'static,
    {
        self.format_instructions = parser.format_instructions();
        self.parser = Some(Arc::new(move |text: &str| {
            let value = parser.parse(text)?;
            serde_json::to_value(value)
                .map_err(|e| ChainError::ParseError(format!("parsed output is not JSON: {e}")))
        }));
        self
    }

    /// Whether to add the output parser's format instructions to the prompt
    /// (default `true`). Turn it off when the template already asks for the
    /// format.
    #[must_use]
    pub const fn inject_format_instructions(mut self, inject: bool) -> Self {
        self.inject_format_instructions = inject;
        self
    }

    /// The LLM this chain calls.
    pub const fn llm(&self) -> &L {
        &self.llm
    }

    /// The memory attached with [`with_memory`](Self::with_memory), if any.
    #[must_use]
    pub const fn memory(&self) -> Option<&Arc<dyn Memory>> {
        self.memory.as_ref()
    }

    fn parsed_key(&self) -> Option<String> {
        self.parses().then(|| format!("{}_parsed", self.output_key))
    }

    fn parses(&self) -> bool {
        self.parser.is_some()
            || self
                .response_format
                .as_ref()
                .is_some_and(ResponseFormat::is_json)
    }

    /// Render the prompt and splice in history. Returns the full
    /// conversation and the turns to record in memory.
    async fn build_messages(
        &self,
        input: &PromptArgs,
    ) -> Result<(Vec<Message>, Vec<Message>), ChainError> {
        // System messages written in the template go first; everything else,
        // including messages a placeholder inserted, keeps its order after
        // the memory history.
        let rendered = self.prompt.render(input)?;
        let (system, new): (Vec<_>, Vec<_>) = rendered
            .into_iter()
            .partition(|r| r.message.role == Role::System && !r.is_from_placeholder());
        let history = match &self.memory {
            Some(memory) => memory.messages().await?,
            None => Vec::new(),
        };
        let instructions = self
            .format_instructions
            .as_ref()
            .filter(|_| self.inject_format_instructions)
            .map(Message::system);
        let mut messages = Vec::with_capacity(system.len() + history.len() + new.len() + 1);
        messages.extend(system.into_iter().map(|r| r.message));
        messages.extend(instructions);
        messages.extend(history);
        messages.extend(new.iter().map(|r| r.message.clone()));
        if let Some(max) = self.max_context_tokens {
            check_budget(&messages, max)?;
        }
        // Only the template's own human turns are new; history passed in
        // through a placeholder is already somewhere else and is not
        // written to memory again.
        let turn = new
            .into_iter()
            .filter(|r| r.message.role == Role::Human && !r.is_from_placeholder())
            .map(|r| r.message)
            .collect();
        Ok((messages, turn))
    }

    fn parse(&self, result: &GenerateResult) -> Result<Option<Value>, ChainError> {
        let text = result.generation.as_str();
        let parsed = match (&self.parser, &self.response_format) {
            (Some(parser), _) => Some(parser(text)),
            (None, Some(format)) if format.is_json() => Some(
                format
                    .parse_json(text)
                    .map_err(|e| ChainError::ParseError(e.message().to_string())),
            ),
            _ => None,
        };
        match parsed.transpose() {
            Err(ChainError::ParseError(msg)) if result.is_truncated() => Err(
                ChainError::ParseError(format!("{msg} (the output hit the token limit)")),
            ),
            other => other,
        }
    }

    /// Run the chain and return the full [`LlmOutput`]: text, token usage,
    /// finish reason and the parsed value.
    ///
    /// # Errors
    ///
    /// A missing template variable, a memory failure, a prompt over the
    /// context budget, the LLM's error, or [`ChainError::ParseError`] when a
    /// configured parser or JSON format rejects the answer.
    pub async fn run(&self, input: PromptArgs) -> Result<LlmOutput, ChainError> {
        let (messages, turn) = self.build_messages(&input).await?;
        let result = match &self.response_format {
            Some(format) => self.llm.generate_structured(&messages, format).await?,
            None => self.llm.generate(&messages).await?,
        };
        let parsed = self.parse(&result)?;
        if let Some(memory) = &self.memory {
            record(memory.as_ref(), turn, &result.generation).await?;
        }
        Ok(LlmOutput::new(result, parsed))
    }

    /// Run the chain and deserialize the parsed answer into `T`.
    ///
    /// Needs an output parser or a JSON response format.
    ///
    /// # Errors
    ///
    /// Everything [`run`](Self::run) can return, plus
    /// [`ChainError::ParseError`] when the parsed value does not match `T`.
    pub async fn invoke_structured<T: DeserializeOwned>(
        &self,
        input: PromptArgs,
    ) -> Result<T, ChainError> {
        self.run(input).await?.parse_as()
    }
}

async fn record(memory: &dyn Memory, turn: Vec<Message>, answer: &str) -> Result<(), ChainError> {
    for message in turn {
        memory.add(message).await?;
    }
    memory.add(Message::ai(answer)).await
}

fn check_budget(messages: &[Message], max_tokens: usize) -> Result<(), ChainError> {
    let chars = messages.iter().fold(0usize, |acc, m| {
        acc.saturating_add(m.content.text_content().chars().count())
            .saturating_add(1)
    });
    let tokens = chars.div_ceil(4);
    if tokens > max_tokens {
        return Err(LlmError::new(
            LlmErrorKind::ContextLengthExceeded,
            format!("prompt is ~{tokens} tokens, above the limit of {max_tokens}"),
        )
        .into());
    }
    Ok(())
}

#[async_trait]
impl<L: Llm + 'static> Chain for LlmChain<L> {
    async fn call(&self, input: PromptArgs) -> Result<GenerateResult, ChainError> {
        self.run(input).await.map(LlmOutput::into_result)
    }

    async fn execute(&self, input: PromptArgs) -> Result<HashMap<String, Value>, ChainError> {
        let out = self.run(input).await?;
        let mut map = HashMap::new();
        if let Some(key) = self.parsed_key() {
            map.insert(key, out.parsed.clone().unwrap_or(Value::Null));
        }
        map.insert(
            self.output_key.clone(),
            Value::String(out.result.generation.clone()),
        );
        map.insert(
            RESULT_KEY.to_string(),
            serde_json::to_value(&out.result)
                .map_err(|e| ChainError::Other(format!("result serialisation failed: {e}")))?,
        );
        Ok(map)
    }

    /// Stream the answer.
    ///
    /// When the stream is read to the end, the full answer is checked by the
    /// configured parser or JSON format (a failure arrives as the last item)
    /// and then recorded in memory. A stream dropped early or cut by an error
    /// records nothing.
    async fn stream(&self, input: PromptArgs) -> Result<ChainStream, ChainError> {
        let (mut messages, turn) = self.build_messages(&input).await?;
        if let Some(format) = &self.response_format {
            messages = format.apply_to(&messages);
        }
        let raw = self.llm.stream(&messages).await?;
        let mapped: ChainStream = Box::pin(raw.map(|item| item.map_err(ChainError::from)));

        let memory = self.memory.clone();
        let checker = self.parses().then(|| {
            let parser = self.parser.clone();
            let format = self.response_format.clone();
            move |text: &str| -> Result<(), ChainError> {
                if let Some(parser) = &parser {
                    return parser(text).map(drop);
                }
                if let Some(format) = &format {
                    format
                        .parse_json(text)
                        .map_err(|e| ChainError::ParseError(e.message().to_string()))?;
                }
                Ok(())
            }
        });
        if memory.is_none() && checker.is_none() {
            return Ok(mapped);
        }
        Ok(with_stream_completion(mapped, move |text| async move {
            if let Some(check) = checker {
                check(&text)?;
            }
            if let Some(memory) = memory {
                record(memory.as_ref(), turn, &text).await?;
            }
            Ok(())
        }))
    }

    fn input_keys(&self) -> Vec<String> {
        self.prompt.input_variables()
    }

    fn output_keys(&self) -> Vec<String> {
        let mut keys: Vec<String> = self.parsed_key().into_iter().collect();
        keys.push(self.output_key.clone());
        keys.push(RESULT_KEY.to_string());
        keys
    }

    fn primary_output_key(&self) -> String {
        self.output_key.clone()
    }
}
