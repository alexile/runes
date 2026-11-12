//! `ParallelChain` — run multiple chains concurrently and merge their outputs.
//!
//! All branches run concurrently on the calling task (polled together with
//! `join_all`; nothing is spawned), each with the same input. Their text
//! outputs are merged into the shared variable map keyed by the branch's
//! `output_key`, making them available to downstream chains.
//!
//! Token usage across all branches is summed, and [`Chain::call`] returns the
//! last branch's generation. The first branch error fails the whole chain.
//!
//! # Quick Start
//!
//! ```rust
//! use rune_chain_parallel::ParallelChain;
//! use rune_chain_core::{Chain, ChainError, GenerateResult, PromptArgs, prompt_args};
//! use async_trait::async_trait;
//!
//! struct UpperCase;
//! #[async_trait]
//! impl Chain for UpperCase {
//!     async fn call(&self, input: PromptArgs) -> Result<GenerateResult, ChainError> {
//!         let text = input.get("input").and_then(|v| v.as_str()).unwrap_or("").to_uppercase();
//!         Ok(GenerateResult::from_text(text))
//!     }
//! }
//!
//! struct LowerCase;
//! #[async_trait]
//! impl Chain for LowerCase {
//!     async fn call(&self, input: PromptArgs) -> Result<GenerateResult, ChainError> {
//!         let text = input.get("input").and_then(|v| v.as_str()).unwrap_or("").to_lowercase();
//!         Ok(GenerateResult::from_text(text))
//!     }
//! }
//!
//! async fn run() {
//!     let par = ParallelChain::new()
//!         .branch(UpperCase, "upper")
//!         .branch(LowerCase, "lower");
//!
//!     let out = par.execute(prompt_args! { "input" => "Hello" }).await.unwrap();
//!     assert_eq!(out["upper"].as_str().unwrap(), "HELLO");
//!     assert_eq!(out["lower"].as_str().unwrap(), "hello");
//! }
//! # tokio::runtime::Builder::new_current_thread().build().unwrap().block_on(run());
//! ```

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use futures::future::join_all;
use rune_chain_core::{Chain, ChainError, GenerateResult, PromptArgs, TokenUsage};
use serde_json::{Value, json};

struct Branch {
    chain: Arc<dyn Chain>,
    output_key: String,
}

/// A fan-out chain that runs multiple sub-chains concurrently and merges outputs.
///
/// Each branch receives the same input and runs concurrently. Their
/// outputs are stored under distinct keys in the result map.
pub struct ParallelChain {
    branches: Vec<Branch>,
}

impl ParallelChain {
    /// Create an empty parallel chain.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            branches: Vec::new(),
        }
    }

    /// Add a branch: run `chain` in parallel and store its output under `output_key`.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_chain_parallel::ParallelChain;
    /// use rune_chain_core::{Chain, ChainError, GenerateResult, PromptArgs};
    /// use async_trait::async_trait;
    ///
    /// struct Noop;
    /// #[async_trait]
    /// impl Chain for Noop {
    ///     async fn call(&self, _: PromptArgs) -> Result<GenerateResult, ChainError> {
    ///         Ok(GenerateResult::from_text(""))
    ///     }
    /// }
    ///
    /// let par = ParallelChain::new().branch(Noop, "a").branch(Noop, "b");
    /// assert_eq!(par.output_keys(), vec!["a", "b", "generate_result"]);
    /// ```
    #[must_use]
    pub fn branch(mut self, chain: impl Chain + 'static, output_key: impl Into<String>) -> Self {
        self.branches.push(Branch {
            chain: Arc::new(chain),
            output_key: output_key.into(),
        });
        self
    }
}

impl Default for ParallelChain {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Chain for ParallelChain {
    async fn call(&self, input: PromptArgs) -> Result<GenerateResult, ChainError> {
        let map = self.execute(input).await?;
        let result_value = map
            .get("generate_result")
            .cloned()
            .unwrap_or_else(|| json!(GenerateResult::default()));
        serde_json::from_value(result_value)
            .map_err(|e| ChainError::Other(format!("result deserialisation failed: {e}")))
    }

    async fn execute(&self, input: PromptArgs) -> Result<HashMap<String, Value>, ChainError> {
        let futures: Vec<_> = self
            .branches
            .iter()
            .map(|b| {
                let chain = Arc::clone(&b.chain);
                let input_clone = input.clone();
                let key = b.output_key.clone();
                async move {
                    let result = chain.call(input_clone).await;
                    (key, result)
                }
            })
            .collect();

        let results = join_all(futures).await;

        let mut accumulated: HashMap<String, Value> = HashMap::new();
        let mut total_tokens: Option<TokenUsage> = None;
        let mut last_generation = String::new();

        for (key, result) in results {
            let r = result?;
            last_generation.clone_from(&r.generation);
            if let Some(usage) = &r.tokens {
                total_tokens = Some(
                    total_tokens
                        .take()
                        .map_or_else(|| usage.clone(), |prev| prev.combine(usage)),
                );
            }
            accumulated.insert(key, json!(r.generation));
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
        let mut keys: Vec<String> = self.branches.iter().map(|b| b.output_key.clone()).collect();
        keys.push("generate_result".to_string());
        keys
    }

    fn input_keys(&self) -> Vec<String> {
        self.branches
            .first()
            .map(|b| b.chain.input_keys())
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use rune_chain_core::prompt_args;

    struct Echo(String);

    #[async_trait]
    impl Chain for Echo {
        async fn call(&self, input: PromptArgs) -> Result<GenerateResult, ChainError> {
            let text = input
                .get(&self.0)
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            Ok(GenerateResult::from_text(text))
        }
    }

    struct Upper(String);

    #[async_trait]
    impl Chain for Upper {
        async fn call(&self, input: PromptArgs) -> Result<GenerateResult, ChainError> {
            let text = input
                .get(&self.0)
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_uppercase();
            Ok(GenerateResult::from_text(text))
        }
    }

    #[tokio::test]
    async fn runs_branches_and_merges_output() {
        let par = ParallelChain::new()
            .branch(Echo("input".into()), "echo")
            .branch(Upper("input".into()), "upper");

        let map = par
            .execute(prompt_args! { "input" => "hello" })
            .await
            .unwrap();
        assert_eq!(map["echo"].as_str().unwrap(), "hello");
        assert_eq!(map["upper"].as_str().unwrap(), "HELLO");
    }

    #[tokio::test]
    async fn output_keys_includes_all_branches() {
        let par = ParallelChain::new()
            .branch(Echo("input".into()), "a")
            .branch(Echo("input".into()), "b");
        assert_eq!(par.output_keys(), vec!["a", "b", "generate_result"]);
    }

    #[tokio::test]
    async fn empty_parallel_chain_returns_default() {
        let par = ParallelChain::new();
        let result = par.call(prompt_args! {}).await.unwrap();
        assert_eq!(result.generation, "");
    }
}
