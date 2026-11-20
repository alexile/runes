//! Shared-ownership impls and combinators for [`Chain`] and [`Llm`].

use std::{collections::HashMap, pin::Pin, sync::Arc};

use async_trait::async_trait;
use futures::Stream;
use serde_json::Value;

use crate::{
    CachedLlm, CallbackHandler, Chain, ChainError, EventStream, FunctionDefinition, GenerateResult,
    Llm, LlmCache, LlmError, Memory, Message, PromptArgs, ResponseFormat, StreamData, TokenUsage,
    Tool, ToolChoice, ToolError, WithCallbacks,
};

/// Key under which [`Chain::execute`] stores the serialised [`GenerateResult`].
const RESULT_KEY: &str = "generate_result";

pub type LlmStream = Pin<Box<dyn Stream<Item = Result<StreamData, LlmError>> + Send>>;
pub type ChainStream = Pin<Box<dyn Stream<Item = Result<StreamData, ChainError>> + Send>>;

// ── Arc<T> forwarding impls ──────────────────────────────────────────────────
//
// `Arc` is not `#[fundamental]`, so no downstream crate can have written these
// impls itself: adding them is non-breaking. They let one provider / chain /
// tool / memory be shared between several owners (`Arc<dyn Llm>` included).

#[async_trait]
impl<T: Llm + ?Sized> Llm for Arc<T> {
    async fn generate(&self, messages: &[Message]) -> Result<GenerateResult, LlmError> {
        (**self).generate(messages).await
    }

    async fn generate_with_tools(
        &self,
        messages: &[Message],
        tools: &[FunctionDefinition],
        tool_choice: Option<ToolChoice>,
    ) -> Result<GenerateResult, LlmError> {
        (**self)
            .generate_with_tools(messages, tools, tool_choice)
            .await
    }

    async fn stream(&self, messages: &[Message]) -> Result<LlmStream, LlmError> {
        (**self).stream(messages).await
    }

    async fn stream_events(
        &self,
        messages: &[Message],
        tools: Option<&[FunctionDefinition]>,
        tool_choice: Option<ToolChoice>,
    ) -> Result<EventStream, LlmError> {
        (**self).stream_events(messages, tools, tool_choice).await
    }

    async fn generate_structured(
        &self,
        messages: &[Message],
        format: &ResponseFormat,
    ) -> Result<GenerateResult, LlmError> {
        (**self).generate_structured(messages, format).await
    }

    async fn batch(&self, inputs: &[Vec<Message>]) -> Vec<Result<GenerateResult, LlmError>> {
        (**self).batch(inputs).await
    }

    async fn batch_with_concurrency(
        &self,
        inputs: &[Vec<Message>],
        max_concurrency: usize,
    ) -> Vec<Result<GenerateResult, LlmError>> {
        (**self)
            .batch_with_concurrency(inputs, max_concurrency)
            .await
    }
}

#[async_trait]
impl<T: Chain + ?Sized> Chain for Arc<T> {
    async fn call(&self, input_variables: PromptArgs) -> Result<GenerateResult, ChainError> {
        (**self).call(input_variables).await
    }

    async fn invoke(&self, input_variables: PromptArgs) -> Result<String, ChainError> {
        (**self).invoke(input_variables).await
    }

    async fn execute(
        &self,
        input_variables: PromptArgs,
    ) -> Result<HashMap<String, Value>, ChainError> {
        (**self).execute(input_variables).await
    }

    async fn stream(&self, input_variables: PromptArgs) -> Result<ChainStream, ChainError> {
        (**self).stream(input_variables).await
    }

    async fn batch(&self, inputs: Vec<PromptArgs>) -> Vec<Result<GenerateResult, ChainError>> {
        (**self).batch(inputs).await
    }

    async fn batch_with_concurrency(
        &self,
        inputs: Vec<PromptArgs>,
        max_concurrency: usize,
    ) -> Vec<Result<GenerateResult, ChainError>> {
        (**self)
            .batch_with_concurrency(inputs, max_concurrency)
            .await
    }

    fn input_keys(&self) -> Vec<String> {
        (**self).input_keys()
    }

    fn output_keys(&self) -> Vec<String> {
        (**self).output_keys()
    }

    fn primary_output_key(&self) -> String {
        (**self).primary_output_key()
    }
}

#[async_trait]
impl<T: Tool + ?Sized> Tool for Arc<T> {
    fn name(&self) -> &str {
        (**self).name()
    }

    fn description(&self) -> &str {
        (**self).description()
    }

    async fn run(&self, input: &str) -> Result<String, ToolError> {
        (**self).run(input).await
    }

    fn schema(&self) -> Value {
        (**self).schema()
    }

    fn function_definition(&self) -> FunctionDefinition {
        (**self).function_definition()
    }
}

#[async_trait]
impl<T: Memory + ?Sized> Memory for Arc<T> {
    async fn messages(&self) -> Result<Vec<Message>, ChainError> {
        (**self).messages().await
    }

    async fn add(&self, message: Message) -> Result<(), ChainError> {
        (**self).add(message).await
    }

    async fn clear(&self) -> Result<(), ChainError> {
        (**self).clear().await
    }
}

// ── Chain combinators ────────────────────────────────────────────────────────

/// Combinators available on every [`Chain`].
///
/// Import it (`use rune_chain_core::ChainExt;`) to call `.with_fallbacks(…)`
/// or `.map_output(…)` on any chain.
pub trait ChainExt: Chain + Sized {
    /// Run `fallbacks` in order when this chain fails, returning the first
    /// success or, if all fail, the **last** error.
    ///
    /// Each attempt receives a clone of the original input. Streaming falls
    /// back only when opening the stream fails, not mid-stream.
    ///
    /// # Example
    ///
    /// ```rust
    /// use async_trait::async_trait;
    /// use rune_chain_core::{Chain, ChainError, ChainExt, GenerateResult, PromptArgs};
    ///
    /// struct Broken;
    /// #[async_trait]
    /// impl Chain for Broken {
    ///     async fn call(&self, _: PromptArgs) -> Result<GenerateResult, ChainError> {
    ///         Err(ChainError::Other("down".into()))
    ///     }
    /// }
    ///
    /// struct Backup;
    /// #[async_trait]
    /// impl Chain for Backup {
    ///     async fn call(&self, _: PromptArgs) -> Result<GenerateResult, ChainError> {
    ///         Ok(GenerateResult::from_text("backup"))
    ///     }
    /// }
    ///
    /// # tokio_test::block_on(async {
    /// let chain = Broken.with_fallbacks([Box::new(Backup) as Box<dyn Chain>]);
    /// assert_eq!(chain.invoke(PromptArgs::new()).await.unwrap(), "backup");
    /// # });
    /// ```
    fn with_fallbacks<I>(self, fallbacks: I) -> ChainWithFallbacks<Self>
    where
        I: IntoIterator<Item = Box<dyn Chain>>,
    {
        ChainWithFallbacks {
            primary: self,
            fallbacks: fallbacks.into_iter().collect(),
        }
    }

    /// Post-process the generated text with `f` (token usage and tool calls
    /// are kept). The mapped chain does not stream.
    ///
    /// # Example
    ///
    /// ```rust
    /// use async_trait::async_trait;
    /// use rune_chain_core::{Chain, ChainError, ChainExt, GenerateResult, PromptArgs};
    ///
    /// struct Hello;
    /// #[async_trait]
    /// impl Chain for Hello {
    ///     async fn call(&self, _: PromptArgs) -> Result<GenerateResult, ChainError> {
    ///         Ok(GenerateResult::from_text("  hello  "))
    ///     }
    /// }
    ///
    /// # tokio_test::block_on(async {
    /// let chain = Hello.map_output(|s| s.trim().to_uppercase());
    /// assert_eq!(chain.invoke(PromptArgs::new()).await.unwrap(), "HELLO");
    /// # });
    /// ```
    fn map_output<F>(self, f: F) -> MapOutput<Self, F>
    where
        F: Fn(String) -> String + Send + Sync,
    {
        MapOutput { inner: self, f }
    }

    /// Feed this chain's answer into `next`.
    ///
    /// `next` gets the original input plus everything this chain wrote in
    /// [`Chain::execute`] (except `"generate_result"`), so the answer sits
    /// under this chain's [primary output key](Chain::primary_output_key).
    /// Use [`pipe_as`](Self::pipe_as) when `next` reads a different key.
    ///
    /// The pipe's answer is `next`'s; token usage of both steps is summed.
    /// Streaming runs this chain to completion and then streams `next`.
    ///
    /// # Example
    ///
    /// ```rust
    /// use async_trait::async_trait;
    /// use rune_chain_core::{Chain, ChainError, ChainExt, GenerateResult, PromptArgs, prompt_args};
    ///
    /// struct Upper;
    /// #[async_trait]
    /// impl Chain for Upper {
    ///     async fn call(&self, input: PromptArgs) -> Result<GenerateResult, ChainError> {
    ///         let text = input["input"].as_str().unwrap_or_default().to_uppercase();
    ///         Ok(GenerateResult::from_text(text))
    ///     }
    /// }
    ///
    /// struct Exclaim;
    /// #[async_trait]
    /// impl Chain for Exclaim {
    ///     async fn call(&self, input: PromptArgs) -> Result<GenerateResult, ChainError> {
    ///         let text = input["output"].as_str().unwrap_or_default();
    ///         Ok(GenerateResult::from_text(format!("{text}!")))
    ///     }
    /// }
    ///
    /// # tokio_test::block_on(async {
    /// let chain = Upper.pipe(Exclaim);
    /// assert_eq!(chain.invoke(prompt_args! { "input" => "hi" }).await.unwrap(), "HI!");
    /// # });
    /// ```
    fn pipe<N: Chain>(self, next: N) -> Pipe<Self, N> {
        Pipe {
            first: self,
            next,
            as_key: None,
        }
    }

    /// Like [`pipe`](Self::pipe), but also passes this chain's answer to
    /// `next` under `key` (for example `"input"`).
    fn pipe_as<N: Chain>(self, next: N, key: impl Into<String>) -> Pipe<Self, N> {
        Pipe {
            first: self,
            next,
            as_key: Some(key.into()),
        }
    }

    /// Report every run of this chain to `handler` (see [`CallbackHandler`]).
    fn with_callbacks(self, handler: Arc<dyn CallbackHandler>) -> WithCallbacks<Self> {
        WithCallbacks::new(self, handler)
    }

    /// Fail with a timeout error when the chain takes longer than `limit`
    /// (see [`WithTimeout`](crate::WithTimeout)). Needs a Tokio runtime.
    #[cfg(feature = "tokio")]
    fn with_timeout(self, limit: std::time::Duration) -> crate::WithTimeout<Self> {
        crate::WithTimeout::new(self, limit)
    }

    /// Retry transient LLM failures up to `max_retries` times with
    /// exponential backoff (see [`WithRetry`](crate::WithRetry)). Each
    /// attempt gets a clone of the input. Needs a Tokio runtime.
    #[cfg(feature = "tokio")]
    fn with_retry(self, max_retries: u32) -> crate::WithRetry<Self> {
        crate::WithRetry::new(self, max_retries)
    }
}

impl<C: Chain> ChainExt for C {}

/// Two chains run one after the other; built by [`ChainExt::pipe`] and
/// [`ChainExt::pipe_as`].
pub struct Pipe<A, B> {
    first: A,
    next: B,
    as_key: Option<String>,
}

impl<A, B> std::fmt::Debug for Pipe<A, B> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Pipe")
            .field("as_key", &self.as_key)
            .finish_non_exhaustive()
    }
}

impl<A: Chain, B: Chain> Pipe<A, B> {
    /// Run the first chain and build the input for the second one. Returns
    /// that input plus the first chain's `execute` map (without its
    /// `"generate_result"`) and token usage.
    async fn first_step(
        &self,
        input: PromptArgs,
    ) -> Result<(PromptArgs, HashMap<String, Value>, Option<TokenUsage>), ChainError> {
        let mut outputs = self.first.execute(input.clone()).await?;
        let first_result = outputs.remove(RESULT_KEY);
        let usage = first_result
            .as_ref()
            .and_then(|r| r.get("tokens"))
            .and_then(|t| serde_json::from_value::<TokenUsage>(t.clone()).ok());
        let mut next_input = input;
        if let Some(key) = &self.as_key {
            let answer = outputs
                .get(&self.first.primary_output_key())
                .or_else(|| first_result.as_ref().and_then(|r| r.get("generation")))
                .cloned()
                .unwrap_or_default();
            next_input.insert(key.clone(), answer);
        }
        next_input.extend(outputs.iter().map(|(k, v)| (k.clone(), v.clone())));
        Ok((next_input, outputs, usage))
    }
}

#[async_trait]
impl<A: Chain, B: Chain> Chain for Pipe<A, B> {
    async fn call(&self, input_variables: PromptArgs) -> Result<GenerateResult, ChainError> {
        let (next_input, _, usage) = self.first_step(input_variables).await?;
        let mut result = self.next.call(next_input).await?;
        let mut total = usage;
        TokenUsage::accumulate(&mut total, result.tokens.as_ref());
        result.tokens = total;
        Ok(result)
    }

    /// Returns the first chain's outputs merged with the second's (the
    /// second wins on clashes); `"generate_result"` is the second chain's,
    /// with token usage summed over both.
    async fn execute(
        &self,
        input_variables: PromptArgs,
    ) -> Result<HashMap<String, Value>, ChainError> {
        let (next_input, mut map, usage) = self.first_step(input_variables).await?;
        let mut second = self.next.execute(next_input).await?;
        if let (Some(usage), Some(Value::Object(result))) = (usage, second.get_mut(RESULT_KEY)) {
            let next_usage = result
                .get("tokens")
                .and_then(|t| serde_json::from_value::<TokenUsage>(t.clone()).ok());
            let mut total = Some(usage);
            TokenUsage::accumulate(&mut total, next_usage.as_ref());
            if let Ok(tokens) = serde_json::to_value(total) {
                result.insert("tokens".into(), tokens);
            }
        }
        map.extend(second);
        Ok(map)
    }

    async fn stream(&self, input_variables: PromptArgs) -> Result<ChainStream, ChainError> {
        let (next_input, _, _) = self.first_step(input_variables).await?;
        self.next.stream(next_input).await
    }

    fn input_keys(&self) -> Vec<String> {
        let produced = self.first.output_keys();
        let mut keys = self.first.input_keys();
        for key in self.next.input_keys() {
            if !produced.contains(&key)
                && self.as_key.as_ref() != Some(&key)
                && !keys.contains(&key)
            {
                keys.push(key);
            }
        }
        keys
    }

    fn output_keys(&self) -> Vec<String> {
        let mut keys: Vec<String> = self
            .first
            .output_keys()
            .into_iter()
            .filter(|k| k != RESULT_KEY)
            .collect();
        for key in self.next.output_keys() {
            if let Some(pos) = keys.iter().position(|k| *k == key) {
                keys.remove(pos);
            }
            keys.push(key);
        }
        keys
    }

    fn primary_output_key(&self) -> String {
        self.next.primary_output_key()
    }
}

/// A [`Chain`] that tries fallbacks in order; built by
/// [`ChainExt::with_fallbacks`].
pub struct ChainWithFallbacks<C> {
    primary: C,
    fallbacks: Vec<Box<dyn Chain>>,
}

impl<C> std::fmt::Debug for ChainWithFallbacks<C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChainWithFallbacks")
            .field("fallbacks", &self.fallbacks.len())
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl<C: Chain> Chain for ChainWithFallbacks<C> {
    async fn call(&self, input_variables: PromptArgs) -> Result<GenerateResult, ChainError> {
        let mut last = match self.primary.call(input_variables.clone()).await {
            Ok(result) => return Ok(result),
            Err(e) => e,
        };
        for fallback in &self.fallbacks {
            match fallback.call(input_variables.clone()).await {
                Ok(result) => return Ok(result),
                Err(e) => last = e,
            }
        }
        Err(last)
    }

    /// Runs each chain's own [`Chain::execute`], so keys that a multi-output
    /// chain writes besides its final answer are kept.
    async fn execute(
        &self,
        input_variables: PromptArgs,
    ) -> Result<HashMap<String, Value>, ChainError> {
        let mut last = match self.primary.execute(input_variables.clone()).await {
            Ok(map) => return Ok(map),
            Err(e) => e,
        };
        for fallback in &self.fallbacks {
            match fallback.execute(input_variables.clone()).await {
                Ok(map) => return Ok(map),
                Err(e) => last = e,
            }
        }
        Err(last)
    }

    async fn stream(&self, input_variables: PromptArgs) -> Result<ChainStream, ChainError> {
        let mut last = match self.primary.stream(input_variables.clone()).await {
            Ok(stream) => return Ok(stream),
            Err(e) => e,
        };
        for fallback in &self.fallbacks {
            match fallback.stream(input_variables.clone()).await {
                Ok(stream) => return Ok(stream),
                Err(e) => last = e,
            }
        }
        Err(last)
    }

    fn input_keys(&self) -> Vec<String> {
        self.primary.input_keys()
    }

    fn output_keys(&self) -> Vec<String> {
        self.primary.output_keys()
    }

    fn primary_output_key(&self) -> String {
        self.primary.primary_output_key()
    }
}

/// A [`Chain`] whose output text is post-processed; built by
/// [`ChainExt::map_output`].
pub struct MapOutput<C, F> {
    inner: C,
    f: F,
}

impl<C, F> std::fmt::Debug for MapOutput<C, F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MapOutput").finish_non_exhaustive()
    }
}

#[async_trait]
impl<C, F> Chain for MapOutput<C, F>
where
    C: Chain,
    F: Fn(String) -> String + Send + Sync,
{
    async fn call(&self, input_variables: PromptArgs) -> Result<GenerateResult, ChainError> {
        let mut result = self.inner.call(input_variables).await?;
        result.generation = (self.f)(std::mem::take(&mut result.generation));
        Ok(result)
    }

    /// Runs the inner chain's own [`Chain::execute`] and maps the final
    /// answer (the primary output key and the `generation` stored under
    /// `"generate_result"`); other keys pass through unchanged.
    async fn execute(
        &self,
        input_variables: PromptArgs,
    ) -> Result<HashMap<String, Value>, ChainError> {
        let mut map = self.inner.execute(input_variables).await?;
        let key = self.primary_output_key();
        let text = match map.remove(&key) {
            Some(Value::String(s)) => s,
            _ => map
                .get(RESULT_KEY)
                .and_then(|r| r.get("generation"))
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned(),
        };
        let mapped = (self.f)(text);
        if let Some(Value::Object(result)) = map.get_mut(RESULT_KEY) {
            result.insert("generation".into(), Value::String(mapped.clone()));
        }
        map.insert(key, Value::String(mapped));
        Ok(map)
    }

    fn input_keys(&self) -> Vec<String> {
        self.inner.input_keys()
    }

    fn output_keys(&self) -> Vec<String> {
        self.inner.output_keys()
    }

    fn primary_output_key(&self) -> String {
        self.inner.primary_output_key()
    }
}

// ── Llm combinators ──────────────────────────────────────────────────────────

/// Combinators available on every [`Llm`].
pub trait LlmExt: Llm + Sized {
    /// Try `fallbacks` in order when this model fails (outage, rate limit,
    /// unsupported feature), returning the first success or the **last**
    /// error. Applies to every [`Llm`] method; streaming falls back only when
    /// opening the stream fails.
    ///
    /// # Example
    ///
    /// ```rust
    /// use std::sync::Arc;
    ///
    /// use async_trait::async_trait;
    /// use rune_chain_core::{GenerateResult, Llm, LlmError, LlmExt, Message};
    ///
    /// struct Down;
    /// #[async_trait]
    /// impl Llm for Down {
    ///     async fn generate(&self, _: &[Message]) -> Result<GenerateResult, LlmError> {
    ///         Err(LlmError::request_failed("503"))
    ///     }
    /// }
    ///
    /// struct Up;
    /// #[async_trait]
    /// impl Llm for Up {
    ///     async fn generate(&self, _: &[Message]) -> Result<GenerateResult, LlmError> {
    ///         Ok(GenerateResult::from_text("ok"))
    ///     }
    /// }
    ///
    /// # tokio_test::block_on(async {
    /// let llm = Down.with_fallbacks([Arc::new(Up) as Arc<dyn Llm>]);
    /// let out = llm.generate(&[Message::human("hi")]).await.unwrap();
    /// assert_eq!(out.generation, "ok");
    /// # });
    /// ```
    fn with_fallbacks<I>(self, fallbacks: I) -> LlmWithFallbacks<Self>
    where
        I: IntoIterator<Item = Arc<dyn Llm>>,
    {
        LlmWithFallbacks {
            primary: self,
            fallbacks: fallbacks.into_iter().collect(),
        }
    }

    /// Always offer `tools` to the model: [`generate`](Llm::generate) and
    /// [`generate_structured`](Llm::generate_structured) go through
    /// [`generate_with_tools`](Llm::generate_with_tools). An explicit
    /// `generate_with_tools` call with a non-empty tool list uses that list
    /// instead. Streaming is passed through without tools.
    ///
    /// # Example
    ///
    /// ```rust
    /// use async_trait::async_trait;
    /// use rune_chain_core::{
    ///     FunctionDefinition, GenerateResult, Llm, LlmError, LlmExt, Message, ToolChoice,
    /// };
    ///
    /// struct CountsTools;
    /// #[async_trait]
    /// impl Llm for CountsTools {
    ///     async fn generate(&self, _: &[Message]) -> Result<GenerateResult, LlmError> {
    ///         Ok(GenerateResult::from_text("no tools"))
    ///     }
    ///     async fn generate_with_tools(
    ///         &self,
    ///         _: &[Message],
    ///         tools: &[FunctionDefinition],
    ///         _: Option<ToolChoice>,
    ///     ) -> Result<GenerateResult, LlmError> {
    ///         Ok(GenerateResult::from_text(format!("{} tools", tools.len())))
    ///     }
    /// }
    ///
    /// # tokio_test::block_on(async {
    /// let llm = CountsTools.bind_tools([FunctionDefinition::single_input("search", "Web search")]);
    /// let out = llm.generate(&[Message::human("hi")]).await.unwrap();
    /// assert_eq!(out.generation, "1 tools");
    /// # });
    /// ```
    fn bind_tools<I>(self, tools: I) -> BoundTools<Self>
    where
        I: IntoIterator<Item = FunctionDefinition>,
    {
        BoundTools {
            inner: self,
            tools: tools.into_iter().collect(),
            tool_choice: None,
        }
    }

    /// Report every call to this model to `handler` (see
    /// [`CallbackHandler`]).
    fn with_callbacks(self, handler: Arc<dyn CallbackHandler>) -> WithCallbacks<Self> {
        WithCallbacks::new(self, handler)
    }

    /// Answer repeated requests from `cache` (see [`CachedLlm`]).
    ///
    /// # Example
    ///
    /// ```rust
    /// use std::sync::Arc;
    ///
    /// use async_trait::async_trait;
    /// use rune_chain_core::{GenerateResult, InMemoryLlmCache, Llm, LlmError, LlmExt, Message};
    ///
    /// struct Fixed;
    /// #[async_trait]
    /// impl Llm for Fixed {
    ///     async fn generate(&self, _: &[Message]) -> Result<GenerateResult, LlmError> {
    ///         Ok(GenerateResult::from_text("ok"))
    ///     }
    /// }
    ///
    /// # tokio_test::block_on(async {
    /// let cache = Arc::new(InMemoryLlmCache::new(1_000));
    /// let llm = Fixed.with_cache(cache.clone()).namespace("fixed");
    /// llm.generate(&[Message::human("hi")]).await.unwrap();
    /// llm.generate(&[Message::human("hi")]).await.unwrap(); // served from the cache
    /// assert_eq!(cache.len(), 1);
    /// # });
    /// ```
    fn with_cache(self, cache: Arc<dyn LlmCache>) -> CachedLlm<Self> {
        CachedLlm::new(self, cache)
    }

    /// Fail with [`LlmError::timeout`] when a call takes longer than `limit`
    /// (see [`WithTimeout`](crate::WithTimeout)). Needs a Tokio runtime.
    #[cfg(feature = "tokio")]
    fn with_timeout(self, limit: std::time::Duration) -> crate::WithTimeout<Self> {
        crate::WithTimeout::new(self, limit)
    }

    /// Retry transient failures up to `max_retries` times with exponential
    /// backoff that honours the provider's retry-after hint (see
    /// [`WithRetry`](crate::WithRetry)). Needs a Tokio runtime.
    #[cfg(feature = "tokio")]
    fn with_retry(self, max_retries: u32) -> crate::WithRetry<Self> {
        crate::WithRetry::new(self, max_retries)
    }
}

impl<L: Llm> LlmExt for L {}

/// An [`Llm`] with a fixed tool list; built by [`LlmExt::bind_tools`].
pub struct BoundTools<L> {
    inner: L,
    tools: Arc<[FunctionDefinition]>,
    tool_choice: Option<ToolChoice>,
}

impl<L> BoundTools<L> {
    /// Also send this [`ToolChoice`] on calls that use the bound tools.
    #[must_use]
    pub fn with_tool_choice(mut self, tool_choice: ToolChoice) -> Self {
        self.tool_choice = Some(tool_choice);
        self
    }

    /// The bound tools.
    pub fn tools(&self) -> &[FunctionDefinition] {
        &self.tools
    }
}

impl<L> std::fmt::Debug for BoundTools<L> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BoundTools")
            .field(
                "tools",
                &self.tools.iter().map(|t| &t.name).collect::<Vec<_>>(),
            )
            .field("tool_choice", &self.tool_choice)
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl<L: Llm> Llm for BoundTools<L> {
    async fn generate(&self, messages: &[Message]) -> Result<GenerateResult, LlmError> {
        self.inner
            .generate_with_tools(messages, &self.tools, self.tool_choice.clone())
            .await
    }

    async fn generate_with_tools(
        &self,
        messages: &[Message],
        tools: &[FunctionDefinition],
        tool_choice: Option<ToolChoice>,
    ) -> Result<GenerateResult, LlmError> {
        if tools.is_empty() {
            let choice = tool_choice.or_else(|| self.tool_choice.clone());
            self.inner
                .generate_with_tools(messages, &self.tools, choice)
                .await
        } else {
            self.inner
                .generate_with_tools(messages, tools, tool_choice)
                .await
        }
    }

    async fn stream(&self, messages: &[Message]) -> Result<LlmStream, LlmError> {
        self.inner.stream(messages).await
    }

    /// Uses the bound tools unless `tools` is a non-empty list.
    async fn stream_events(
        &self,
        messages: &[Message],
        tools: Option<&[FunctionDefinition]>,
        tool_choice: Option<ToolChoice>,
    ) -> Result<EventStream, LlmError> {
        match tools {
            Some(tools) if !tools.is_empty() => {
                self.inner
                    .stream_events(messages, Some(tools), tool_choice)
                    .await
            }
            _ => {
                let choice = tool_choice.or_else(|| self.tool_choice.clone());
                self.inner
                    .stream_events(messages, Some(&self.tools), choice)
                    .await
            }
        }
    }

    /// Prompts for JSON (see [`ResponseFormat::apply_to`]) and calls the
    /// model with the bound tools.
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
}

/// An [`Llm`] that tries fallback models in order; built by
/// [`LlmExt::with_fallbacks`].
pub struct LlmWithFallbacks<L> {
    primary: L,
    fallbacks: Vec<Arc<dyn Llm>>,
}

impl<L> std::fmt::Debug for LlmWithFallbacks<L> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LlmWithFallbacks")
            .field("fallbacks", &self.fallbacks.len())
            .finish_non_exhaustive()
    }
}

/// Try `primary`, then each fallback, with the same async operation.
macro_rules! try_in_order {
    ($self:ident, |$llm:ident| $op:expr) => {{
        let mut last = {
            let $llm = &$self.primary;
            match $op.await {
                Ok(v) => return Ok(v),
                Err(e) => e,
            }
        };
        for fallback in &$self.fallbacks {
            let $llm = &**fallback;
            match $op.await {
                Ok(v) => return Ok(v),
                Err(e) => last = e,
            }
        }
        Err(last)
    }};
}

#[async_trait]
impl<L: Llm> Llm for LlmWithFallbacks<L> {
    async fn generate(&self, messages: &[Message]) -> Result<GenerateResult, LlmError> {
        try_in_order!(self, |llm| llm.generate(messages))
    }

    async fn generate_with_tools(
        &self,
        messages: &[Message],
        tools: &[FunctionDefinition],
        tool_choice: Option<ToolChoice>,
    ) -> Result<GenerateResult, LlmError> {
        try_in_order!(self, |llm| llm.generate_with_tools(
            messages,
            tools,
            tool_choice.clone()
        ))
    }

    async fn stream(&self, messages: &[Message]) -> Result<LlmStream, LlmError> {
        try_in_order!(self, |llm| llm.stream(messages))
    }

    /// Falls back only when opening the stream fails; an error part-way
    /// through is passed on.
    async fn stream_events(
        &self,
        messages: &[Message],
        tools: Option<&[FunctionDefinition]>,
        tool_choice: Option<ToolChoice>,
    ) -> Result<EventStream, LlmError> {
        try_in_order!(self, |llm| llm.stream_events(
            messages,
            tools,
            tool_choice.clone()
        ))
    }

    async fn generate_structured(
        &self,
        messages: &[Message],
        format: &ResponseFormat,
    ) -> Result<GenerateResult, LlmError> {
        try_in_order!(self, |llm| llm.generate_structured(messages, format))
    }
}
