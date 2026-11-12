//! [`TracedTool`]: a [`Tool`] wrapper that emits an `execute_tool` span.

use async_trait::async_trait;
use rune_chain_core::{Tool, ToolCall, ToolError};
use tracing::{Instrument, Span};

use crate::ContentPolicy;
use crate::span::{record_error, tool_error_type, tool_span};

/// Wraps a [`Tool`] so every run is an `execute_tool {name}` span with
/// `gen_ai.tool.name`, `gen_ai.tool.description` and `gen_ai.tool.type`,
/// plus `error.type` and an `ERROR` status when the tool fails.
///
/// [`TracedTool::run_call`] also records the model's call identifier
/// (`gen_ai.tool.call.id`). With content capture on, the arguments and the
/// result are recorded too, redacted and capped by the [`ContentPolicy`].
///
/// # Examples
///
/// ```
/// use async_trait::async_trait;
/// use rune_chain_core::{Tool, ToolCall, ToolError};
/// use rune_otel_genai::TracedTool;
///
/// struct Upper;
/// #[async_trait]
/// impl Tool for Upper {
///     fn name(&self) -> &str { "upper" }
///     fn description(&self) -> &str { "Upper-cases text." }
///     async fn run(&self, input: &str) -> Result<String, ToolError> {
///         Ok(input.to_uppercase())
///     }
/// }
///
/// let tool = TracedTool::new(Upper);
/// let call = ToolCall::new("call_1", "upper", "abc");
/// assert_eq!(tokio_test::block_on(tool.run_call(&call))?, "ABC");
/// # Ok::<(), ToolError>(())
/// ```
#[derive(Debug, Clone)]
pub struct TracedTool<T> {
    inner: T,
    content: ContentPolicy,
}

impl<T: Tool> TracedTool<T> {
    /// Traces `inner`'s runs, without recording arguments or results.
    pub const fn new(inner: T) -> Self {
        Self {
            inner,
            content: ContentPolicy::off(),
        }
    }

    /// Records tool arguments and results (`gen_ai.tool.call.arguments`,
    /// `gen_ai.tool.call.result`) with the current policy's caps and
    /// redaction. Off by default.
    #[must_use]
    pub fn with_capture_content(mut self, capture: bool) -> Self {
        self.content = self.content.with_enabled(capture);
        self
    }

    /// Sets the full content policy: capture, size cap and redaction.
    #[must_use]
    pub fn with_content_policy(mut self, policy: ContentPolicy) -> Self {
        self.content = policy;
        self
    }

    /// The wrapped tool.
    #[must_use]
    pub const fn inner(&self) -> &T {
        &self.inner
    }

    /// Unwraps, returning the inner tool.
    pub fn into_inner(self) -> T {
        self.inner
    }

    /// Runs the tool for a model-issued `call`, recording its identifier.
    pub async fn run_call(&self, call: &ToolCall) -> Result<String, ToolError> {
        self.traced(Some(&call.id), &call.arguments).await
    }

    async fn traced(&self, call_id: Option<&str>, input: &str) -> Result<String, ToolError> {
        let span = tool_span(self.inner.name(), self.inner.description(), call_id);
        if self.content.is_enabled() {
            span.record(
                "gen_ai.tool.call.arguments",
                self.content.apply(input).as_str(),
            );
        }
        let result = self.inner.run(input).instrument(span.clone()).await;
        self.settle(&span, &result);
        result
    }

    fn settle(&self, span: &Span, result: &Result<String, ToolError>) {
        match result {
            Ok(output) if self.content.is_enabled() => {
                span.record(
                    "gen_ai.tool.call.result",
                    self.content.apply(output).as_str(),
                );
            }
            Ok(_) => {}
            Err(e) => record_error(span, tool_error_type(e), &e.to_string()),
        }
    }
}

#[async_trait]
impl<T: Tool> Tool for TracedTool<T> {
    fn name(&self) -> &str {
        self.inner.name()
    }

    fn description(&self) -> &str {
        self.inner.description()
    }

    async fn run(&self, input: &str) -> Result<String, ToolError> {
        self.traced(None, input).await
    }

    fn schema(&self) -> serde_json::Value {
        self.inner.schema()
    }
}
