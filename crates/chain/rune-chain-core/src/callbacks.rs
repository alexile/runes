//! Lifecycle hooks for [`Llm`], [`Chain`] and [`Tool`] calls.
//!
//! Implement [`CallbackHandler`] (every method has a no-op default) and wrap
//! a model, chain or tool with `.with_callbacks(handler)`. Unwrapped values
//! pay nothing; wrapped ones pass borrowed events, so no prompt, input or
//! output is copied for the handler.
//!
//! Events hold the raw prompts and outputs so a handler *can* inspect them,
//! but their `Debug` output shows only sizes, names and token counts. Logging
//! an event with `{:?}` never writes prompt text, tool input or model output.

use std::{
    collections::HashMap,
    fmt,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use async_trait::async_trait;
use serde_json::Value;

use crate::{
    Chain, ChainError, FunctionDefinition, GenerateResult, Llm, LlmError, Message, PromptArgs,
    ResponseFormat, Tool, ToolChoice, ToolError,
    ext::{ChainStream, LlmStream},
};

static NEXT_RUN_ID: AtomicU64 = AtomicU64::new(1);

fn next_run_id() -> u64 {
    NEXT_RUN_ID.fetch_add(1, Ordering::Relaxed)
}

/// Which [`Llm`] method an event belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum LlmCall {
    /// [`Llm::generate`].
    Generate,
    /// [`Llm::generate_with_tools`].
    GenerateWithTools,
    /// [`Llm::generate_structured`].
    Structured,
    /// [`Llm::stream`] (only start and error events: see [`WithCallbacks`]).
    Stream,
}

/// Fired before a model call.
#[non_exhaustive]
pub struct LlmStart<'a> {
    /// Ties this call's start event to its end or error event.
    pub run_id: u64,
    /// Which method was called.
    pub call: LlmCall,
    /// The conversation sent to the model.
    pub messages: &'a [Message],
    /// Tool definitions offered to the model (empty when none).
    pub tools: &'a [FunctionDefinition],
}

impl fmt::Debug for LlmStart<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LlmStart")
            .field("run_id", &self.run_id)
            .field("call", &self.call)
            .field("messages", &self.messages.len())
            .field("tools", &self.tools.len())
            .finish()
    }
}

/// Fired after a model call succeeds.
#[non_exhaustive]
pub struct LlmEnd<'a> {
    /// Same id as the matching [`LlmStart`].
    pub run_id: u64,
    /// Which method was called.
    pub call: LlmCall,
    /// The model's response.
    pub result: &'a GenerateResult,
    /// Wall time of the call.
    pub elapsed: Duration,
}

impl fmt::Debug for LlmEnd<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LlmEnd")
            .field("run_id", &self.run_id)
            .field("call", &self.call)
            .field("output_len", &self.result.generation.len())
            .field("tool_calls", &self.result.tool_calls.len())
            .field("tokens", &self.result.tokens)
            .field("finish_reason", &self.result.finish_reason)
            .field("elapsed", &self.elapsed)
            .finish()
    }
}

/// Fired when a model call fails.
#[non_exhaustive]
pub struct LlmFailure<'a> {
    /// Same id as the matching [`LlmStart`].
    pub run_id: u64,
    /// Which method was called.
    pub call: LlmCall,
    /// The error returned by the model.
    pub error: &'a LlmError,
    /// Wall time of the call.
    pub elapsed: Duration,
}

impl fmt::Debug for LlmFailure<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LlmFailure")
            .field("run_id", &self.run_id)
            .field("call", &self.call)
            .field("kind", &self.error.kind())
            .field("status", &self.error.status())
            .field("elapsed", &self.elapsed)
            .finish()
    }
}

/// Fired before a chain runs.
#[non_exhaustive]
pub struct ChainStart<'a> {
    /// Ties this run's start event to its end or error event.
    pub run_id: u64,
    /// The chain's input variables.
    pub inputs: &'a PromptArgs,
}

impl fmt::Debug for ChainStart<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut keys: Vec<&str> = self.inputs.keys().map(String::as_str).collect();
        keys.sort_unstable();
        f.debug_struct("ChainStart")
            .field("run_id", &self.run_id)
            .field("input_keys", &keys)
            .finish()
    }
}

/// Fired after a chain succeeds.
#[non_exhaustive]
pub struct ChainEnd<'a> {
    /// Same id as the matching [`ChainStart`].
    pub run_id: u64,
    /// The chain's final answer.
    pub output: &'a str,
    /// Wall time of the run.
    pub elapsed: Duration,
}

impl fmt::Debug for ChainEnd<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ChainEnd")
            .field("run_id", &self.run_id)
            .field("output_len", &self.output.len())
            .field("elapsed", &self.elapsed)
            .finish()
    }
}

/// Fired when a chain fails.
#[non_exhaustive]
pub struct ChainFailure<'a> {
    /// Same id as the matching [`ChainStart`].
    pub run_id: u64,
    /// The error returned by the chain.
    pub error: &'a ChainError,
    /// Wall time of the run.
    pub elapsed: Duration,
}

impl fmt::Debug for ChainFailure<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let kind = match self.error {
            ChainError::LlmError(_) => "llm",
            ChainError::MissingVariable(_) => "missing_variable",
            ChainError::MemoryError(_) => "memory",
            ChainError::ToolError(_) => "tool",
            ChainError::ParseError(_) => "parse",
            ChainError::Other(_) => "other",
        };
        f.debug_struct("ChainFailure")
            .field("run_id", &self.run_id)
            .field("kind", &kind)
            .field("elapsed", &self.elapsed)
            .finish()
    }
}

/// Fired before a tool runs.
#[non_exhaustive]
pub struct ToolStart<'a> {
    /// Ties this run's start event to its end or error event.
    pub run_id: u64,
    /// The tool's name.
    pub name: &'a str,
    /// The tool's input.
    pub input: &'a str,
}

impl fmt::Debug for ToolStart<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ToolStart")
            .field("run_id", &self.run_id)
            .field("name", &self.name)
            .field("input_len", &self.input.len())
            .finish()
    }
}

/// Fired after a tool succeeds.
#[non_exhaustive]
pub struct ToolEnd<'a> {
    /// Same id as the matching [`ToolStart`].
    pub run_id: u64,
    /// The tool's name.
    pub name: &'a str,
    /// The tool's output.
    pub output: &'a str,
    /// Wall time of the run.
    pub elapsed: Duration,
}

impl fmt::Debug for ToolEnd<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ToolEnd")
            .field("run_id", &self.run_id)
            .field("name", &self.name)
            .field("output_len", &self.output.len())
            .field("elapsed", &self.elapsed)
            .finish()
    }
}

/// Fired when a tool fails.
#[non_exhaustive]
pub struct ToolFailure<'a> {
    /// Same id as the matching [`ToolStart`].
    pub run_id: u64,
    /// The tool's name.
    pub name: &'a str,
    /// The error returned by the tool.
    pub error: &'a ToolError,
    /// Wall time of the run.
    pub elapsed: Duration,
}

impl fmt::Debug for ToolFailure<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ToolFailure")
            .field("run_id", &self.run_id)
            .field("name", &self.name)
            .field("elapsed", &self.elapsed)
            .finish_non_exhaustive()
    }
}

/// Receives lifecycle events from values wrapped with `.with_callbacks(…)`.
///
/// Every method does nothing by default; override the ones you need. Hooks
/// run inline on the calling task, so keep them quick.
///
/// # Example
///
/// ```rust
/// use std::sync::{Arc, atomic::{AtomicU32, Ordering}};
///
/// use async_trait::async_trait;
/// use rune_chain_core::{
///     CallbackHandler, GenerateResult, Llm, LlmEnd, LlmError, LlmExt, Message,
/// };
///
/// #[derive(Default)]
/// struct TokenCounter(AtomicU32);
///
/// impl CallbackHandler for TokenCounter {
///     fn on_llm_end(&self, event: &LlmEnd<'_>) {
///         let used = event.result.tokens.as_ref().map_or(0, |t| t.total_tokens);
///         self.0.fetch_add(used, Ordering::Relaxed);
///     }
/// }
///
/// struct Fixed;
/// #[async_trait]
/// impl Llm for Fixed {
///     async fn generate(&self, _: &[Message]) -> Result<GenerateResult, LlmError> {
///         Ok(GenerateResult::from_text("ok")
///             .with_tokens(rune_chain_core::TokenUsage::new(3, 1)))
///     }
/// }
///
/// # tokio_test::block_on(async {
/// let counter = Arc::new(TokenCounter::default());
/// let llm = Fixed.with_callbacks(counter.clone());
/// llm.generate(&[Message::human("hi")]).await.unwrap();
/// assert_eq!(counter.0.load(Ordering::Relaxed), 4);
/// # });
/// ```
pub trait CallbackHandler: Send + Sync {
    /// Before a model call.
    fn on_llm_start(&self, _event: &LlmStart<'_>) {}
    /// After a model call succeeds.
    fn on_llm_end(&self, _event: &LlmEnd<'_>) {}
    /// After a model call fails.
    fn on_llm_error(&self, _event: &LlmFailure<'_>) {}
    /// Before a chain runs.
    fn on_chain_start(&self, _event: &ChainStart<'_>) {}
    /// After a chain succeeds.
    fn on_chain_end(&self, _event: &ChainEnd<'_>) {}
    /// After a chain fails.
    fn on_chain_error(&self, _event: &ChainFailure<'_>) {}
    /// Before a tool runs.
    fn on_tool_start(&self, _event: &ToolStart<'_>) {}
    /// After a tool succeeds.
    fn on_tool_end(&self, _event: &ToolEnd<'_>) {}
    /// After a tool fails.
    fn on_tool_error(&self, _event: &ToolFailure<'_>) {}
}

/// Sends every event to each handler in turn.
impl CallbackHandler for Vec<Arc<dyn CallbackHandler>> {
    fn on_llm_start(&self, event: &LlmStart<'_>) {
        for h in self {
            h.on_llm_start(event);
        }
    }
    fn on_llm_end(&self, event: &LlmEnd<'_>) {
        for h in self {
            h.on_llm_end(event);
        }
    }
    fn on_llm_error(&self, event: &LlmFailure<'_>) {
        for h in self {
            h.on_llm_error(event);
        }
    }
    fn on_chain_start(&self, event: &ChainStart<'_>) {
        for h in self {
            h.on_chain_start(event);
        }
    }
    fn on_chain_end(&self, event: &ChainEnd<'_>) {
        for h in self {
            h.on_chain_end(event);
        }
    }
    fn on_chain_error(&self, event: &ChainFailure<'_>) {
        for h in self {
            h.on_chain_error(event);
        }
    }
    fn on_tool_start(&self, event: &ToolStart<'_>) {
        for h in self {
            h.on_tool_start(event);
        }
    }
    fn on_tool_end(&self, event: &ToolEnd<'_>) {
        for h in self {
            h.on_tool_end(event);
        }
    }
    fn on_tool_error(&self, event: &ToolFailure<'_>) {
        for h in self {
            h.on_tool_error(event);
        }
    }
}

/// A model, chain or tool that reports to a [`CallbackHandler`]; built by
/// `.with_callbacks(…)` on [`LlmExt`](crate::LlmExt),
/// [`ChainExt`](crate::ChainExt) or [`ToolExt`].
///
/// Streams fire the start event, and the error event when the stream cannot
/// be opened; chunks and the end of the stream are not reported.
pub struct WithCallbacks<T> {
    inner: T,
    handler: Arc<dyn CallbackHandler>,
}

impl<T> WithCallbacks<T> {
    pub(crate) fn new(inner: T, handler: Arc<dyn CallbackHandler>) -> Self {
        Self { inner, handler }
    }

    /// The wrapped value.
    pub const fn inner(&self) -> &T {
        &self.inner
    }
}

impl<T> fmt::Debug for WithCallbacks<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WithCallbacks").finish_non_exhaustive()
    }
}

impl<T> WithCallbacks<T> {
    async fn observe_llm<F>(
        &self,
        call: LlmCall,
        messages: &[Message],
        tools: &[FunctionDefinition],
        fut: F,
    ) -> Result<GenerateResult, LlmError>
    where
        F: Future<Output = Result<GenerateResult, LlmError>> + Send,
        T: Sync,
    {
        let run_id = next_run_id();
        self.handler.on_llm_start(&LlmStart {
            run_id,
            call,
            messages,
            tools,
        });
        let started = Instant::now();
        let out = fut.await;
        let elapsed = started.elapsed();
        match &out {
            Ok(result) => self.handler.on_llm_end(&LlmEnd {
                run_id,
                call,
                result,
                elapsed,
            }),
            Err(error) => self.handler.on_llm_error(&LlmFailure {
                run_id,
                call,
                error,
                elapsed,
            }),
        }
        out
    }

    async fn observe_chain<R, F>(
        &self,
        inputs: PromptArgs,
        run: impl FnOnce(PromptArgs) -> F + Send,
        output: impl Fn(&R) -> Option<&str> + Send,
    ) -> Result<R, ChainError>
    where
        F: Future<Output = Result<R, ChainError>> + Send,
        R: Send,
        T: Sync,
    {
        let run_id = next_run_id();
        self.handler.on_chain_start(&ChainStart {
            run_id,
            inputs: &inputs,
        });
        let started = Instant::now();
        let out = run(inputs).await;
        let elapsed = started.elapsed();
        match &out {
            Ok(r) => self.handler.on_chain_end(&ChainEnd {
                run_id,
                output: output(r).unwrap_or_default(),
                elapsed,
            }),
            Err(error) => self.handler.on_chain_error(&ChainFailure {
                run_id,
                error,
                elapsed,
            }),
        }
        out
    }
}

#[async_trait]
impl<L: Llm> Llm for WithCallbacks<L> {
    async fn generate(&self, messages: &[Message]) -> Result<GenerateResult, LlmError> {
        self.observe_llm(
            LlmCall::Generate,
            messages,
            &[],
            self.inner.generate(messages),
        )
        .await
    }

    async fn generate_with_tools(
        &self,
        messages: &[Message],
        tools: &[FunctionDefinition],
        tool_choice: Option<ToolChoice>,
    ) -> Result<GenerateResult, LlmError> {
        self.observe_llm(
            LlmCall::GenerateWithTools,
            messages,
            tools,
            self.inner.generate_with_tools(messages, tools, tool_choice),
        )
        .await
    }

    async fn stream(&self, messages: &[Message]) -> Result<LlmStream, LlmError> {
        let run_id = next_run_id();
        let call = LlmCall::Stream;
        self.handler.on_llm_start(&LlmStart {
            run_id,
            call,
            messages,
            tools: &[],
        });
        let started = Instant::now();
        let out = self.inner.stream(messages).await;
        if let Err(error) = &out {
            self.handler.on_llm_error(&LlmFailure {
                run_id,
                call,
                error,
                elapsed: started.elapsed(),
            });
        }
        out
    }

    async fn generate_structured(
        &self,
        messages: &[Message],
        format: &ResponseFormat,
    ) -> Result<GenerateResult, LlmError> {
        self.observe_llm(
            LlmCall::Structured,
            messages,
            &[],
            self.inner.generate_structured(messages, format),
        )
        .await
    }
}

#[async_trait]
impl<C: Chain> Chain for WithCallbacks<C> {
    async fn call(&self, input_variables: PromptArgs) -> Result<GenerateResult, ChainError> {
        self.observe_chain(
            input_variables,
            |input| self.inner.call(input),
            |r: &GenerateResult| Some(r.generation.as_str()),
        )
        .await
    }

    async fn execute(
        &self,
        input_variables: PromptArgs,
    ) -> Result<HashMap<String, Value>, ChainError> {
        let key = self.inner.primary_output_key();
        self.observe_chain(
            input_variables,
            |input| self.inner.execute(input),
            |map: &HashMap<String, Value>| map.get(&key).and_then(Value::as_str),
        )
        .await
    }

    async fn stream(&self, input_variables: PromptArgs) -> Result<ChainStream, ChainError> {
        let run_id = next_run_id();
        self.handler.on_chain_start(&ChainStart {
            run_id,
            inputs: &input_variables,
        });
        let started = Instant::now();
        let out = self.inner.stream(input_variables).await;
        if let Err(error) = &out {
            self.handler.on_chain_error(&ChainFailure {
                run_id,
                error,
                elapsed: started.elapsed(),
            });
        }
        out
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

#[async_trait]
impl<T: Tool> Tool for WithCallbacks<T> {
    fn name(&self) -> &str {
        self.inner.name()
    }

    fn description(&self) -> &str {
        self.inner.description()
    }

    async fn run(&self, input: &str) -> Result<String, ToolError> {
        let run_id = next_run_id();
        let name = self.inner.name();
        self.handler.on_tool_start(&ToolStart {
            run_id,
            name,
            input,
        });
        let started = Instant::now();
        let out = self.inner.run(input).await;
        let elapsed = started.elapsed();
        match &out {
            Ok(output) => self.handler.on_tool_end(&ToolEnd {
                run_id,
                name,
                output,
                elapsed,
            }),
            Err(error) => self.handler.on_tool_error(&ToolFailure {
                run_id,
                name,
                error,
                elapsed,
            }),
        }
        out
    }

    fn schema(&self) -> Value {
        self.inner.schema()
    }

    fn function_definition(&self) -> FunctionDefinition {
        self.inner.function_definition()
    }
}

/// Combinators available on every [`Tool`].
pub trait ToolExt: Tool + Sized {
    /// Report every run of this tool to `handler`.
    fn with_callbacks(self, handler: Arc<dyn CallbackHandler>) -> WithCallbacks<Self> {
        WithCallbacks::new(self, handler)
    }
}

impl<T: Tool> ToolExt for T {}
