//! What gets evaluated: any [`Chain`], an async closure, or (feature
//! `retrieval`) a retriever plus a chain.

use std::future::Future;

use async_trait::async_trait;
use rune_chain_core::{Chain, ChainError, GenerateResult, TokenUsage, ToolCall};
use serde_json::{Map, Value};

use crate::Example;

/// What a target produced for one example.
///
/// Besides the answer text it carries what metrics beyond text need: the
/// token usage (for cost), the tool calls made (for trajectory metrics) and
/// the retrieved contexts (for RAG metrics).
#[derive(Debug, Clone, Default, PartialEq)]
#[non_exhaustive]
pub struct TargetOutput {
    /// The answer.
    pub output: String,
    /// Token usage, if reported.
    pub usage: Option<TokenUsage>,
    /// Tool calls made while answering, in order.
    pub tool_calls: Vec<ToolCall>,
    /// Retrieved context passages, best first.
    pub contexts: Vec<String>,
    /// Anything else worth keeping.
    pub metadata: Map<String, Value>,
}

impl TargetOutput {
    /// An output with just text.
    pub fn text(output: impl Into<String>) -> Self {
        Self {
            output: output.into(),
            ..Self::default()
        }
    }

    /// Set the token usage (builder style).
    #[must_use]
    pub const fn with_usage(mut self, usage: TokenUsage) -> Self {
        self.usage = Some(usage);
        self
    }

    /// Set the tool calls (builder style).
    #[must_use]
    pub fn with_tool_calls(mut self, calls: impl IntoIterator<Item = ToolCall>) -> Self {
        self.tool_calls = calls.into_iter().collect();
        self
    }

    /// Set the retrieved contexts (builder style).
    #[must_use]
    pub fn with_contexts(mut self, contexts: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.contexts = contexts.into_iter().map(Into::into).collect();
        self
    }

    /// Add a metadata entry (builder style).
    #[must_use]
    pub fn with_metadata(mut self, key: impl Into<String>, value: Value) -> Self {
        self.metadata.insert(key.into(), value);
        self
    }
}

impl From<GenerateResult> for TargetOutput {
    fn from(r: GenerateResult) -> Self {
        Self {
            output: r.generation,
            usage: r.tokens,
            tool_calls: r.tool_calls,
            ..Self::default()
        }
    }
}

impl From<String> for TargetOutput {
    fn from(s: String) -> Self {
        Self::text(s)
    }
}

impl From<&str> for TargetOutput {
    fn from(s: &str) -> Self {
        Self::text(s)
    }
}

/// The system under test.
#[async_trait]
pub trait Target: Send + Sync {
    /// Produce an output for one example.
    async fn run(&self, example: &Example) -> Result<TargetOutput, ChainError>;
}

#[async_trait]
impl<T: Target + ?Sized> Target for std::sync::Arc<T> {
    async fn run(&self, example: &Example) -> Result<TargetOutput, ChainError> {
        (**self).run(example).await
    }
}

#[async_trait]
impl<T: Target + ?Sized> Target for Box<T> {
    async fn run(&self, example: &Example) -> Result<TargetOutput, ChainError> {
        (**self).run(example).await
    }
}

/// Runs a [`Chain`] on each example's inputs.
#[derive(Debug, Clone)]
pub struct ChainTarget<C>(pub C);

#[async_trait]
impl<C: Chain> Target for ChainTarget<C> {
    async fn run(&self, example: &Example) -> Result<TargetOutput, ChainError> {
        self.0.call(example.prompt_args()).await.map(Into::into)
    }
}

/// Evaluate a [`Chain`].
pub const fn chain_target<C: Chain>(chain: C) -> ChainTarget<C> {
    ChainTarget(chain)
}

/// Runs an async closure on each example (it gets its own clone).
#[derive(Clone)]
pub struct FnTarget<F>(F);

impl<F> std::fmt::Debug for FnTarget<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("FnTarget")
    }
}

#[async_trait]
impl<F, Fut, O> Target for FnTarget<F>
where
    F: Fn(Example) -> Fut + Send + Sync,
    Fut: Future<Output = Result<O, ChainError>> + Send,
    O: Into<TargetOutput>,
{
    async fn run(&self, example: &Example) -> Result<TargetOutput, ChainError> {
        (self.0)(example.clone()).await.map(Into::into)
    }
}

/// Evaluate an async closure. It may return anything that converts into
/// a [`TargetOutput`]: a `String`, a [`GenerateResult`], or a
/// `TargetOutput` with usage, tool calls and contexts.
///
/// ```rust
/// use rune_chain_eval::{TargetOutput, target_fn};
///
/// let target = target_fn(|ex| async move {
///     let q = ex.question().unwrap_or_default().to_owned();
///     Ok::<_, rune_chain_core::ChainError>(TargetOutput::text(q.to_uppercase()))
/// });
/// # let _ = target;
/// ```
pub const fn target_fn<F, Fut, O>(f: F) -> FnTarget<F>
where
    F: Fn(Example) -> Fut + Send + Sync,
    Fut: Future<Output = Result<O, ChainError>> + Send,
    O: Into<TargetOutput>,
{
    FnTarget(f)
}

#[cfg(feature = "retrieval")]
pub use rag_target::RagTarget;

#[cfg(feature = "retrieval")]
mod rag_target {
    use std::fmt::Write as _;

    use async_trait::async_trait;
    use rune_chain_core::{Chain, ChainError};
    use rune_chain_retrieval::Retriever;
    use serde_json::Value;

    use super::{Target, TargetOutput};
    use crate::Example;

    /// Retrieves contexts for the example's question, passes them to a
    /// chain under `context_key`, and records them for RAG metrics.
    #[derive(Debug, Clone)]
    pub struct RagTarget<R, C> {
        retriever: R,
        chain: C,
        top_k: usize,
        context_key: String,
    }

    impl<R: Retriever, C: Chain> RagTarget<R, C> {
        /// Retrieve the top 4 passages and pass them as `"context"`.
        pub fn new(retriever: R, chain: C) -> Self {
            Self {
                retriever,
                chain,
                top_k: 4,
                context_key: "context".into(),
            }
        }

        /// How many passages to retrieve (builder style).
        #[must_use]
        pub const fn top_k(mut self, k: usize) -> Self {
            self.top_k = k;
            self
        }

        /// The chain input that receives the joined passages (builder style).
        #[must_use]
        pub fn context_key(mut self, key: impl Into<String>) -> Self {
            self.context_key = key.into();
            self
        }
    }

    #[async_trait]
    impl<R: Retriever, C: Chain> Target for RagTarget<R, C> {
        async fn run(&self, example: &Example) -> Result<TargetOutput, ChainError> {
            let question = example
                .question()
                .ok_or_else(|| ChainError::MissingVariable("question".into()))?;
            let docs = self
                .retriever
                .retrieve(question, self.top_k)
                .await
                .map_err(|e| ChainError::Other(format!("retrieval failed: {e}")))?;
            let contexts: Vec<String> = docs.into_iter().map(|d| d.document.content).collect();
            let mut joined = String::new();
            for (i, c) in contexts.iter().enumerate() {
                let _ = write!(joined, "[{}] {c}\n\n", i + 1);
            }
            let mut args = example.prompt_args();
            args.insert(self.context_key.clone(), Value::String(joined));
            let out: TargetOutput = self.chain.call(args).await?.into();
            Ok(out.with_contexts(contexts))
        }
    }
}
