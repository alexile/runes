//! Shared-ownership impls and combinators for [`Chain`] and [`Llm`].

use std::{collections::HashMap, pin::Pin, sync::Arc};

use async_trait::async_trait;
use futures::Stream;
use serde_json::Value;

use crate::{
    Chain, ChainError, FunctionDefinition, GenerateResult, Llm, LlmError, Memory, Message,
    PromptArgs, ResponseFormat, StreamData, Tool, ToolChoice, ToolError,
};

type LlmStream = Pin<Box<dyn Stream<Item = Result<StreamData, LlmError>> + Send>>;
type ChainStream = Pin<Box<dyn Stream<Item = Result<StreamData, ChainError>> + Send>>;

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

    async fn generate_structured(
        &self,
        messages: &[Message],
        format: &ResponseFormat,
    ) -> Result<GenerateResult, LlmError> {
        (**self).generate_structured(messages, format).await
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
}

impl<C: Chain> ChainExt for C {}

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
}

impl<L: Llm> LlmExt for L {}

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

    async fn generate_structured(
        &self,
        messages: &[Message],
        format: &ResponseFormat,
    ) -> Result<GenerateResult, LlmError> {
        try_in_order!(self, |llm| llm.generate_structured(messages, format))
    }
}
