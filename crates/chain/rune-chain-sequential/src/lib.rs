//! `SequentialChain` — run [`Chain`]s in order, piping each output as input to the next.
//!
//! Each step declares an output key. After it runs, that key and the generated
//! text are merged into the running variable map so subsequent steps can
//! reference them as template variables.
//!
//! # Features
//!
//! - [`SequentialChain`] — ordered pipeline of heterogeneous chains
//! - Fluent `chain(chain, output_key)` builder — no separate builder type needed
//! - Implements the full [`Chain`] trait: `call`, `invoke`, `execute`, `stream` (errors)
//! - Token usage is summed across all steps
//!
//! # Quick Start
//!
//! ```rust
//! use rune_chain_sequential::SequentialChain;
//! use rune_chain_core::{Chain, ChainError, GenerateResult, PromptArgs, prompt_args};
//! use async_trait::async_trait;
//!
//! struct UpperCase;
//!
//! #[async_trait]
//! impl Chain for UpperCase {
//!     async fn call(&self, input: PromptArgs) -> Result<GenerateResult, ChainError> {
//!         let text = input.get("input")
//!             .and_then(|v| v.as_str())
//!             .unwrap_or("")
//!             .to_uppercase();
//!         Ok(GenerateResult::from_text(text))
//!     }
//! }
//!
//! struct Exclaim;
//!
//! #[async_trait]
//! impl Chain for Exclaim {
//!     async fn call(&self, input: PromptArgs) -> Result<GenerateResult, ChainError> {
//!         let text = input.get("shouted")
//!             .and_then(|v| v.as_str())
//!             .unwrap_or("");
//!         Ok(GenerateResult::from_text(format!("{text}!!!")))
//!     }
//! }
//!
//! # tokio_test::block_on(async {
//! let seq = SequentialChain::new()
//!     .chain(UpperCase, "shouted")
//!     .chain(Exclaim, "final");
//!
//! let result = seq.invoke(prompt_args! { "input" => "hello" }).await.unwrap();
//! assert_eq!(result, "HELLO!!!");
//! # });
//! ```

use std::collections::HashMap;

use async_trait::async_trait;
use rune_chain_core::{Chain, ChainError, GenerateResult, PromptArgs, TokenUsage};
use serde_json::{Value, json};

struct Step {
    chain: Box<dyn Chain>,
    output_key: String,
}

/// An ordered pipeline of [`Chain`]s where each step's text output is injected
/// into the variable map for all subsequent steps.
///
/// Build with [`SequentialChain::new`] and add steps via [`chain`](SequentialChain::chain).
///
/// # Example
///
/// ```rust,no_run
/// use rune_chain_sequential::SequentialChain;
/// use rune_chain_core::{Chain, ChainError, GenerateResult, PromptArgs, prompt_args};
/// use async_trait::async_trait;
///
/// struct Echo;
///
/// #[async_trait]
/// impl Chain for Echo {
///     async fn call(&self, input: PromptArgs) -> Result<GenerateResult, ChainError> {
///         let text = input.get("input")
///             .and_then(|v| v.as_str())
///             .unwrap_or("")
///             .to_string();
///         Ok(GenerateResult::from_text(text))
///     }
/// }
///
/// # tokio_test::block_on(async {
/// let seq = SequentialChain::new().chain(Echo, "result");
/// let out = seq.invoke(prompt_args! { "input" => "hi" }).await.unwrap();
/// assert_eq!(out, "hi");
/// # });
/// ```
pub struct SequentialChain {
    steps: Vec<Step>,
}

impl SequentialChain {
    /// Create an empty sequential chain with no steps yet.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_chain_sequential::SequentialChain;
    /// use rune_chain_core::Chain;
    ///
    /// let seq = SequentialChain::new();
    /// assert_eq!(seq.output_keys(), vec!["generate_result"]);
    /// ```
    #[must_use]
    pub const fn new() -> Self {
        Self { steps: Vec::new() }
    }

    /// Append a step: run `chain` and store its text output under `output_key`.
    ///
    /// The `output_key` becomes a variable available to all later steps, and is
    /// included in the map returned by [`Chain::execute`].
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_chain_sequential::SequentialChain;
    /// use rune_chain_core::{Chain, ChainError, GenerateResult, PromptArgs};
    /// use async_trait::async_trait;
    ///
    /// struct Noop;
    ///
    /// #[async_trait]
    /// impl Chain for Noop {
    ///     async fn call(&self, _: PromptArgs) -> Result<GenerateResult, ChainError> {
    ///         Ok(GenerateResult::from_text(""))
    ///     }
    /// }
    ///
    /// let seq = SequentialChain::new()
    ///     .chain(Noop, "step1")
    ///     .chain(Noop, "step2");
    ///
    /// assert_eq!(seq.output_keys(), vec!["step1", "step2", "generate_result"]);
    /// ```
    #[must_use]
    pub fn chain(mut self, chain: impl Chain + 'static, output_key: impl Into<String>) -> Self {
        self.steps.push(Step {
            chain: Box::new(chain),
            output_key: output_key.into(),
        });
        self
    }
}

impl Default for SequentialChain {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Chain for SequentialChain {
    async fn call(&self, input: PromptArgs) -> Result<GenerateResult, ChainError> {
        let output = self.execute(input).await?;
        let result_value = output
            .get("generate_result")
            .cloned()
            .unwrap_or_else(|| json!(GenerateResult::default()));
        serde_json::from_value(result_value)
            .map_err(|e| ChainError::Other(format!("result deserialisation failed: {e}")))
    }

    async fn execute(&self, input: PromptArgs) -> Result<HashMap<String, Value>, ChainError> {
        let mut vars = input;
        let mut accumulated: HashMap<String, Value> = HashMap::new();
        let mut total_tokens: Option<TokenUsage> = None;
        let mut last_generation = String::new();

        for step in &self.steps {
            let result = step.chain.call(vars.clone()).await?;

            last_generation.clone_from(&result.generation);

            if let Some(usage) = &result.tokens {
                total_tokens = Some(
                    total_tokens
                        .take()
                        .map_or_else(|| usage.clone(), |prev| prev.combine(usage)),
                );
            }

            vars.insert(step.output_key.clone(), json!(result.generation));
            accumulated.insert(step.output_key.clone(), json!(result.generation));
        }

        let final_result = GenerateResult::from_text(last_generation).with_tokens(total_tokens);

        // The final answer lives under the primary key (the last step's key,
        // or `"output"` when there are no steps), per the `Chain::execute`
        // contract.
        accumulated
            .entry(self.primary_output_key())
            .or_insert_with(|| json!(final_result.generation));
        accumulated.insert(
            "generate_result".to_string(),
            serde_json::to_value(&final_result).unwrap_or(Value::Null),
        );

        Ok(accumulated)
    }

    fn output_keys(&self) -> Vec<String> {
        let mut keys: Vec<String> = self.steps.iter().map(|s| s.output_key.clone()).collect();
        keys.push("generate_result".to_string());
        keys
    }

    fn input_keys(&self) -> Vec<String> {
        self.steps
            .first()
            .map(|s| s.chain.input_keys())
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use rune_chain_core::{ChainError, GenerateResult, PromptArgs, prompt_args};

    struct Echo {
        key: String,
    }

    #[async_trait]
    impl Chain for Echo {
        async fn call(&self, input: PromptArgs) -> Result<GenerateResult, ChainError> {
            let text = input
                .get(&self.key)
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            Ok(GenerateResult::from_text(text))
        }
    }

    struct UpperCase {
        key: String,
    }

    #[async_trait]
    impl Chain for UpperCase {
        async fn call(&self, input: PromptArgs) -> Result<GenerateResult, ChainError> {
            let text = input
                .get(&self.key)
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_uppercase();
            Ok(GenerateResult::from_text(text))
        }
    }

    #[tokio::test]
    async fn single_step_passes_through() {
        let seq = SequentialChain::new().chain(
            Echo {
                key: "input".into(),
            },
            "out",
        );
        let result = seq
            .invoke(prompt_args! { "input" => "hello" })
            .await
            .unwrap();
        assert_eq!(result, "hello");
    }

    #[tokio::test]
    async fn two_steps_pipe_output() {
        let seq = SequentialChain::new()
            .chain(
                Echo {
                    key: "input".into(),
                },
                "echoed",
            )
            .chain(
                UpperCase {
                    key: "echoed".into(),
                },
                "upper",
            );

        let result = seq
            .invoke(prompt_args! { "input" => "hello" })
            .await
            .unwrap();
        assert_eq!(result, "HELLO");
    }

    #[tokio::test]
    async fn execute_contains_all_step_outputs() {
        let seq = SequentialChain::new()
            .chain(
                Echo {
                    key: "input".into(),
                },
                "step1",
            )
            .chain(
                UpperCase {
                    key: "step1".into(),
                },
                "step2",
            );

        let map = seq
            .execute(prompt_args! { "input" => "world" })
            .await
            .unwrap();
        assert_eq!(map["step1"].as_str().unwrap(), "world");
        assert_eq!(map["step2"].as_str().unwrap(), "WORLD");
    }

    #[tokio::test]
    async fn empty_chain_returns_default_result() {
        let seq = SequentialChain::new();
        let result = seq.call(prompt_args! {}).await.unwrap();
        assert_eq!(result.generation, "");
    }

    #[tokio::test]
    async fn output_keys_lists_all_steps_plus_result() {
        let seq = SequentialChain::new()
            .chain(
                Echo {
                    key: "input".into(),
                },
                "a",
            )
            .chain(Echo { key: "a".into() }, "b");
        assert_eq!(seq.output_keys(), vec!["a", "b", "generate_result"]);
    }
}
