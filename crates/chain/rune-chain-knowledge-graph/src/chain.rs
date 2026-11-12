use async_trait::async_trait;
use rune_chain_core::{Chain, ChainError, GenerateResult, Llm, PromptArgs};

use crate::knowledge_graph::KnowledgeGraph;

const INPUT_KEY: &str = "input";

/// Runs triple extraction and returns the results as formatted text.
///
/// Accepts `"input"` in the [`PromptArgs`] map. The extracted triples are
/// written to the `generation` field of the [`GenerateResult`], one per line,
/// in `Subject --[relation]--> Object` format.
///
/// This lets `KnowledgeGraph` participate in `SequentialChain` pipelines (`rune-chain-sequential`):
/// the formatted triple list can be passed as input to the next chain step
/// (e.g. a summarisation `LlmChain`).
///
/// # Example
///
/// ```rust,no_run
/// use rune_chain_core::{Chain, prompt_args};
/// use rune_chain_knowledge_graph::KnowledgeGraph;
/// # use rune_chain_core::{Llm, Message, GenerateResult, LlmError};
/// # use async_trait::async_trait;
/// # struct FakeLlm;
/// # #[async_trait] impl Llm for FakeLlm {
/// #   async fn generate(&self, _: &[Message]) -> Result<GenerateResult, LlmError> {
/// #     Ok(GenerateResult::from_text(r#"[{"subject":"Alice","relation":"knows","object":"Bob"}]"#))
/// #   }
/// # }
/// # tokio_test::block_on(async {
/// let kg = KnowledgeGraph::new(FakeLlm);
/// let result = kg.invoke(prompt_args! { "input" => "Alice knows Bob." }).await.unwrap();
/// assert!(result.contains("Alice"));
/// # });
/// ```
#[async_trait]
impl<L: Llm + 'static> Chain for KnowledgeGraph<L> {
    async fn call(&self, input: PromptArgs) -> Result<GenerateResult, ChainError> {
        let text = input
            .get(INPUT_KEY)
            .and_then(|v| v.as_str())
            .ok_or_else(|| ChainError::MissingVariable(INPUT_KEY.to_string()))?
            .to_string();

        let triples = self.extract(&text).await.map_err(ChainError::from)?;

        let output = if triples.is_empty() {
            "No relationships extracted.".to_string()
        } else {
            triples
                .iter()
                .map(std::string::ToString::to_string)
                .collect::<Vec<_>>()
                .join("\n")
        };

        Ok(GenerateResult::from_text(output))
    }

    fn input_keys(&self) -> Vec<String> {
        vec![INPUT_KEY.to_string()]
    }

    fn output_keys(&self) -> Vec<String> {
        vec!["output".to_string(), "generate_result".to_string()]
    }
}
