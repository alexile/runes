use std::{collections::HashMap, pin::Pin};

use async_trait::async_trait;
use futures::{Stream, StreamExt, stream};
use serde_json::Value;

use crate::{ChainError, GenerateResult, PromptArgs, StreamData};

const DEFAULT_OUTPUT_KEY: &str = "output";
const DEFAULT_RESULT_KEY: &str = "generate_result";

/// How many requests [`Chain::batch`] and [`Llm::batch`](crate::Llm::batch)
/// run at once.
pub const DEFAULT_BATCH_CONCURRENCY: usize = 8;

/// A composable unit of LLM work that maps [`PromptArgs`] to a [`GenerateResult`].
///
/// Chains are the core abstraction of the `rune-chain` ecosystem. A chain may wrap
/// a single LLM call, a retrieval step, a sequence of sub-chains, or any other
/// unit of work that accepts named variables and produces generated text.
///
/// Implementors must provide [`Chain::call`]; all other methods have default
/// implementations built on top of it.
///
/// # Example
///
/// ```rust
/// use rune_chain_core::{Chain, ChainError, GenerateResult, PromptArgs, prompt_args};
/// use async_trait::async_trait;
///
/// struct EchoChain;
///
/// #[async_trait]
/// impl Chain for EchoChain {
///     async fn call(&self, input: PromptArgs) -> Result<GenerateResult, ChainError> {
///         let text = input.get("input").and_then(|v| v.as_str()).unwrap_or("").to_string();
///         Ok(GenerateResult::from_text(text))
///     }
/// }
///
/// # tokio_test::block_on(async {
/// let chain = EchoChain;
/// let result = chain.invoke(prompt_args! { "input" => "hello" }).await.unwrap();
/// assert_eq!(result, "hello");
/// # });
/// ```
#[async_trait]
pub trait Chain: Sync + Send {
    /// Run the chain and return the full [`GenerateResult`] including token usage.
    async fn call(&self, input_variables: PromptArgs) -> Result<GenerateResult, ChainError>;

    /// Run the chain and return the generated text string only.
    ///
    /// Convenience wrapper around [`Chain::call`] that discards token usage.
    async fn invoke(&self, input_variables: PromptArgs) -> Result<String, ChainError> {
        self.call(input_variables).await.map(|r| r.generation)
    }

    /// Run the chain and return a named-output map ready to pipe into the next step.
    ///
    /// # Contract
    ///
    /// [`Chain::call`]'s `generation` is the chain's final answer. The map
    /// returned here must agree with it:
    ///
    /// - every key listed by [`Chain::output_keys`] is present;
    /// - the [primary output key](Chain::primary_output_key) holds the final
    ///   answer as a JSON string (multi-step chains may store intermediate
    ///   outputs under their other keys);
    /// - `"generate_result"` holds the full serialised [`GenerateResult`],
    ///   whose `generation` is that same final answer.
    ///
    /// The default implementation writes exactly the primary output key and
    /// `"generate_result"`.
    async fn execute(
        &self,
        input_variables: PromptArgs,
    ) -> Result<HashMap<String, Value>, ChainError> {
        let result = self.call(input_variables).await?;
        let mut map = HashMap::new();
        map.insert(
            self.primary_output_key(),
            Value::String(result.generation.clone()),
        );
        map.insert(
            DEFAULT_RESULT_KEY.to_string(),
            serde_json::to_value(&result).unwrap_or(Value::Null),
        );
        Ok(map)
    }

    /// Run the chain on many inputs, at most [`DEFAULT_BATCH_CONCURRENCY`]
    /// at a time.
    ///
    /// Results come back in input order, one per input; a failed input does
    /// not stop the others. Collect into `Result<Vec<_>, _>` for
    /// all-or-nothing behaviour.
    ///
    /// # Example
    ///
    /// ```rust
    /// use async_trait::async_trait;
    /// use rune_chain_core::{Chain, ChainError, GenerateResult, PromptArgs, prompt_args};
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
    /// # tokio_test::block_on(async {
    /// let inputs = vec![prompt_args! { "input" => "a" }, prompt_args! { "input" => "b" }];
    /// let out: Vec<_> = Upper.batch(inputs).await.into_iter().map(|r| r.unwrap().generation).collect();
    /// assert_eq!(out, ["A", "B"]);
    /// # });
    /// ```
    async fn batch(&self, inputs: Vec<PromptArgs>) -> Vec<Result<GenerateResult, ChainError>> {
        self.batch_with_concurrency(inputs, DEFAULT_BATCH_CONCURRENCY)
            .await
    }

    /// Like [`Chain::batch`] with an explicit concurrency limit (`0` is
    /// treated as `1`).
    async fn batch_with_concurrency(
        &self,
        inputs: Vec<PromptArgs>,
        max_concurrency: usize,
    ) -> Vec<Result<GenerateResult, ChainError>> {
        stream::iter(inputs.into_iter().map(|input| self.call(input)))
            .buffered(max_concurrency.max(1))
            .collect()
            .await
    }

    /// Stream tokens as they are produced rather than waiting for the full completion.
    ///
    /// Returns a [`Stream`] of [`StreamData`] chunks. Chains that do not support
    /// streaming return [`ChainError::Other`] by default.
    ///
    /// > [!NOTE]
    /// > Memory layers cannot be updated automatically during a stream because the
    /// > complete output is only known when the stream ends. Callers are responsible
    /// > for persisting the accumulated output after draining the stream.
    async fn stream(
        &self,
        _input_variables: PromptArgs,
    ) -> Result<Pin<Box<dyn Stream<Item = Result<StreamData, ChainError>> + Send>>, ChainError>
    {
        Err(ChainError::Other(
            "streaming is not implemented for this chain".into(),
        ))
    }

    /// The variable names this chain reads from its [`PromptArgs`] input.
    fn input_keys(&self) -> Vec<String> {
        vec![]
    }

    /// The keys this chain writes into the map returned by [`Chain::execute`].
    fn output_keys(&self) -> Vec<String> {
        vec![
            DEFAULT_OUTPUT_KEY.to_string(),
            DEFAULT_RESULT_KEY.to_string(),
        ]
    }

    /// The key under which [`Chain::execute`] stores the final answer
    /// (`call().generation`).
    ///
    /// Defaults to the **last** entry of [`Chain::output_keys`] other than
    /// `"generate_result"`, or `"output"` when there is none. For a
    /// single-output chain that is its only text key; for a multi-step chain
    /// that lists one key per step (sequential pipelines, fan-outs) it is the
    /// final step's key, whose output is the chain's answer.
    ///
    /// # Example
    ///
    /// ```rust
    /// use async_trait::async_trait;
    /// use rune_chain_core::{Chain, ChainError, GenerateResult, PromptArgs};
    ///
    /// struct TwoStep;
    ///
    /// #[async_trait]
    /// impl Chain for TwoStep {
    ///     async fn call(&self, _: PromptArgs) -> Result<GenerateResult, ChainError> {
    ///         Ok(GenerateResult::from_text("final"))
    ///     }
    ///     fn output_keys(&self) -> Vec<String> {
    ///         vec!["draft".into(), "answer".into(), "generate_result".into()]
    ///     }
    /// }
    ///
    /// assert_eq!(TwoStep.primary_output_key(), "answer");
    /// ```
    fn primary_output_key(&self) -> String {
        self.output_keys()
            .into_iter()
            .rfind(|k| k != DEFAULT_RESULT_KEY)
            .unwrap_or_else(|| DEFAULT_OUTPUT_KEY.to_string())
    }
}

impl<C: Chain + 'static> From<C> for Box<dyn Chain> {
    fn from(chain: C) -> Self {
        Box::new(chain)
    }
}
