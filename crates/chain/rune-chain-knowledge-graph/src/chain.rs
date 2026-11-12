use async_trait::async_trait;
use rune_chain_core::{Chain, ChainError, GenerateResult, Llm, PromptArgs};

use crate::knowledge_graph::{DEFAULT_DOCUMENT_ID, KnowledgeGraph};

const INPUT_KEY: &str = "input";
const DOCUMENT_KEY: &str = "document_id";

/// Runs extraction and returns the accepted facts as formatted text.
///
/// Reads the text from `"input"` and, optionally, a document id from
/// `"document_id"` (default [`DEFAULT_DOCUMENT_ID`]). The facts accepted in
/// this call are written to the `generation` field of the
/// [`GenerateResult`], one per line, in `Subject --[relation]--> Object`
/// format, and the summed token usage to `tokens`.
///
/// This lets `KnowledgeGraph` participate in `SequentialChain` pipelines (`rune-chain-sequential`):
/// the formatted triple list can be passed as input to the next chain step
/// (e.g. a summarisation `LlmChain`).
///
/// # Example
///
/// ```rust
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
/// let result = kg
///     .invoke(prompt_args! { "input" => "Alice knows Bob.", "document_id" => "chat-42" })
///     .await
///     .unwrap();
/// assert_eq!(result, "Alice --[knows]--> Bob");
/// assert_eq!(kg.relations_of("Alice").await[0].provenance[0].document_id, "chat-42");
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
        let document_id = match input.get(DOCUMENT_KEY) {
            None => DEFAULT_DOCUMENT_ID.to_string(),
            Some(v) => v
                .as_str()
                .ok_or_else(|| ChainError::Other(format!("`{DOCUMENT_KEY}` must be a string")))?
                .to_string(),
        };

        let report = self
            .extract_document(&document_id, &text)
            .await
            .map_err(ChainError::from)?;

        let output = if report.facts.is_empty() {
            "No relationships extracted.".to_string()
        } else {
            report
                .facts
                .iter()
                .map(|f| f.triple.to_string())
                .collect::<Vec<_>>()
                .join("\n")
        };

        Ok(GenerateResult::from_text(output).with_tokens(report.usage))
    }

    fn input_keys(&self) -> Vec<String> {
        vec![INPUT_KEY.to_string()]
    }

    fn output_keys(&self) -> Vec<String> {
        vec!["output".to_string(), "generate_result".to_string()]
    }
}
