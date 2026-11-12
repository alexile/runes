use std::sync::Arc;

use async_trait::async_trait;
use rune_chain_core::{Chain, ChainError, GenerateResult, Llm, Message, PromptArgs};
use rune_chain_embed::Embedder;

use crate::retriever::Retriever;
use crate::scored::filter_min_score;
use crate::store::VectorStore;

/// Where [`RetrievalQaChain`] gets its documents.
enum Source {
    Vector {
        embedder: Arc<dyn Embedder>,
        store: Arc<dyn VectorStore>,
    },
    Retriever(Arc<dyn Retriever>),
}

const DEFAULT_INPUT_KEY: &str = "input";
const DEFAULT_TOP_K: usize = 4;
const DEFAULT_SYSTEM: &str = "You are a helpful assistant. Answer the question using only the provided context. \
     If the context does not contain enough information to answer, say so clearly.";

/// RAG chain: embed a query, retrieve relevant documents, and answer with an LLM.
///
/// `RetrievalQaChain` implements the Retrieval-Augmented Generation pattern:
///
/// 1. Embeds the user's question with an [`Embedder`]
/// 2. Retrieves the top-`k` most similar [`Document`](crate::Document)s from a
///    [`VectorStore`]
/// 3. Formats the retrieved context and question into a prompt
/// 4. Calls the [`Llm`] and returns the answer
///
/// # Examples
///
/// ```rust,no_run
/// use std::sync::Arc;
/// use rune_chain_core::{Chain, prompt_args};
/// use rune_chain_embed::{Embedder, OpenAiEmbedder};
/// use rune_chain_retrieval::{InMemoryVectorStore, RetrievalQaChain};
///
/// # struct FakeLlm;
/// # use async_trait::async_trait;
/// # use rune_chain_core::{Llm, Message, GenerateResult, LlmError};
/// # #[async_trait] impl Llm for FakeLlm {
/// #     async fn generate(&self, _: &[Message]) -> Result<GenerateResult, LlmError> {
/// #         Ok(GenerateResult::from_text("Paris"))
/// #     }
/// # }
/// # tokio_test::block_on(async {
/// let embedder: Arc<dyn Embedder> = Arc::new(OpenAiEmbedder::from_env().unwrap());
/// let store = Arc::new(InMemoryVectorStore::new(Arc::clone(&embedder)));
///
/// store.add_texts(&[
///     "The capital of France is Paris.",
///     "The capital of Germany is Berlin.",
/// ]).await.unwrap();
///
/// let chain = RetrievalQaChain::new(FakeLlm, Arc::clone(&embedder), store);
/// let answer = chain.invoke(prompt_args! { "input" => "What is the capital of France?" })
///     .await
///     .unwrap();
/// println!("{answer}");
/// # });
/// ```
pub struct RetrievalQaChain<L: Llm> {
    llm: L,
    source: Source,
    top_k: usize,
    min_score: Option<f32>,
    system_prompt: Option<String>,
}

impl<L: Llm + 'static> RetrievalQaChain<L> {
    /// Create a chain with default settings (`top_k = 4`, default system prompt).
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use std::sync::Arc;
    /// use rune_chain_embed::{Embedder, OpenAiEmbedder};
    /// use rune_chain_retrieval::{InMemoryVectorStore, RetrievalQaChain};
    ///
    /// # struct FakeLlm;
    /// # use async_trait::async_trait;
    /// # use rune_chain_core::{Llm, Message, GenerateResult, LlmError};
    /// # #[async_trait] impl Llm for FakeLlm {
    /// #     async fn generate(&self, _: &[Message]) -> Result<GenerateResult, LlmError> {
    /// #         Ok(GenerateResult::from_text("ok"))
    /// #     }
    /// # }
    /// let embedder: Arc<dyn Embedder> = Arc::new(OpenAiEmbedder::from_env().unwrap());
    /// let store = Arc::new(InMemoryVectorStore::new(Arc::clone(&embedder)));
    /// let chain = RetrievalQaChain::new(FakeLlm, embedder, store);
    /// ```
    pub fn new(llm: L, embedder: Arc<dyn Embedder>, store: Arc<dyn VectorStore>) -> Self {
        Self {
            llm,
            source: Source::Vector { embedder, store },
            top_k: DEFAULT_TOP_K,
            min_score: None,
            system_prompt: None,
        }
    }

    /// Create a chain that gets its context from any [`Retriever`] — BM25,
    /// hybrid, reranked, multi-query, … — with `top_k = 4`.
    ///
    /// ```rust
    /// use std::sync::Arc;
    /// use rune_chain_core::{Chain, prompt_args};
    /// use rune_chain_retrieval::{Bm25Retriever, Document, RetrievalQaChain};
    /// # use async_trait::async_trait;
    /// # use rune_chain_core::{Llm, Message, GenerateResult, LlmError};
    /// # struct FakeLlm;
    /// # #[async_trait] impl Llm for FakeLlm {
    /// #     async fn generate(&self, _: &[Message]) -> Result<GenerateResult, LlmError> {
    /// #         Ok(GenerateResult::from_text("Paris"))
    /// #     }
    /// # }
    ///
    /// # tokio_test::block_on(async {
    /// let retriever = Arc::new(Bm25Retriever::from_documents(vec![
    ///     Document::new("The capital of France is Paris."),
    /// ]));
    /// let chain = RetrievalQaChain::with_retriever(FakeLlm, retriever);
    /// let answer = chain.invoke(prompt_args! { "input" => "capital of France?" }).await?;
    /// assert_eq!(answer, "Paris");
    /// # Ok::<(), rune_chain_core::ChainError>(())
    /// # }).unwrap();
    /// ```
    pub fn with_retriever(llm: L, retriever: Arc<dyn Retriever>) -> Self {
        Self {
            llm,
            source: Source::Retriever(retriever),
            top_k: DEFAULT_TOP_K,
            min_score: None,
            system_prompt: None,
        }
    }

    /// Drop retrieved documents scoring below `min_score` before they reach
    /// the prompt. Only applies to chains built with
    /// [`with_retriever`](Self::with_retriever) (a plain [`VectorStore`]
    /// reports no scores). `NaN` disables the threshold.
    #[must_use]
    pub const fn min_score(mut self, min_score: f32) -> Self {
        self.min_score = if min_score.is_nan() {
            None
        } else {
            Some(min_score)
        };
        self
    }

    /// Set the number of documents to retrieve per query. Defaults to `4`.
    /// `0` retrieves nothing; the LLM is then told no context was found.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use std::sync::Arc;
    /// # use rune_chain_embed::OpenAiEmbedder;
    /// # use rune_chain_retrieval::{InMemoryVectorStore, RetrievalQaChain};
    /// # struct FakeLlm;
    /// # use async_trait::async_trait;
    /// # use rune_chain_core::{Llm, Message, GenerateResult, LlmError};
    /// # #[async_trait] impl Llm for FakeLlm {
    /// #     async fn generate(&self, _: &[Message]) -> Result<GenerateResult, LlmError> {
    /// #         Ok(GenerateResult::from_text("ok"))
    /// #     }
    /// # }
    /// # use rune_chain_embed::Embedder;
    /// # let embedder: Arc<dyn Embedder> = Arc::new(OpenAiEmbedder::from_env().unwrap());
    /// # let store = Arc::new(InMemoryVectorStore::new(Arc::clone(&embedder)));
    /// let chain = RetrievalQaChain::new(FakeLlm, embedder, store).top_k(8);
    /// ```
    #[must_use]
    pub const fn top_k(mut self, top_k: usize) -> Self {
        self.top_k = top_k;
        self
    }

    /// Override the system prompt injected before the context and question.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use std::sync::Arc;
    /// # use rune_chain_embed::OpenAiEmbedder;
    /// # use rune_chain_retrieval::{InMemoryVectorStore, RetrievalQaChain};
    /// # struct FakeLlm;
    /// # use async_trait::async_trait;
    /// # use rune_chain_core::{Llm, Message, GenerateResult, LlmError};
    /// # #[async_trait] impl Llm for FakeLlm {
    /// #     async fn generate(&self, _: &[Message]) -> Result<GenerateResult, LlmError> {
    /// #         Ok(GenerateResult::from_text("ok"))
    /// #     }
    /// # }
    /// # use rune_chain_embed::Embedder;
    /// # let embedder: Arc<dyn Embedder> = Arc::new(OpenAiEmbedder::from_env().unwrap());
    /// # let store = Arc::new(InMemoryVectorStore::new(Arc::clone(&embedder)));
    /// let chain = RetrievalQaChain::new(FakeLlm, embedder, store)
    ///     .with_system("Answer in bullet points only.");
    /// ```
    #[must_use]
    pub fn with_system(mut self, prompt: impl Into<String>) -> Self {
        self.system_prompt = Some(prompt.into());
        self
    }
}

fn build_context(docs: &[crate::document::Document]) -> String {
    if docs.is_empty() {
        return "No relevant context was found.".to_string();
    }
    docs.iter()
        .enumerate()
        .map(|(i, doc)| format!("[{}] {}", i + 1, doc.content))
        .collect::<Vec<_>>()
        .join("\n\n")
}

fn build_messages(question: &str, context: &str, system_prompt: Option<&str>) -> Vec<Message> {
    let system = system_prompt.unwrap_or(DEFAULT_SYSTEM);
    let human = format!("Context:\n{context}\n\nQuestion: {question}");
    vec![Message::system(system), Message::human(&human)]
}

#[async_trait]
impl<L: Llm + 'static> Chain for RetrievalQaChain<L> {
    async fn call(&self, input: PromptArgs) -> Result<GenerateResult, ChainError> {
        let question = input
            .get(DEFAULT_INPUT_KEY)
            .and_then(|v| v.as_str())
            .ok_or_else(|| ChainError::MissingVariable(DEFAULT_INPUT_KEY.to_string()))?
            .to_string();

        let docs = match &self.source {
            _ if self.top_k == 0 => Vec::new(),
            Source::Vector { embedder, store } => {
                let query_embedding = embedder
                    .embed(&question)
                    .await
                    .map_err(|e| ChainError::Other(e.to_string()))?;
                store.search(&query_embedding, self.top_k).await?
            }
            Source::Retriever(retriever) => {
                let mut scored = retriever.retrieve(&question, self.top_k).await?;
                if let Some(min) = self.min_score {
                    scored = filter_min_score(scored, min);
                }
                scored.truncate(self.top_k);
                scored.into_iter().map(|s| s.document).collect()
            }
        };

        let context = build_context(&docs);
        let messages = build_messages(&question, &context, self.system_prompt.as_deref());

        Ok(self.llm.generate(&messages).await?)
    }

    fn input_keys(&self) -> Vec<String> {
        vec![DEFAULT_INPUT_KEY.to_string()]
    }

    fn output_keys(&self) -> Vec<String> {
        vec!["output".to_string(), "generate_result".to_string()]
    }
}

#[cfg(test)]
#[allow(clippy::assert_is_empty, reason = "emptiness is the expectation")]
mod tests {
    use std::sync::Arc;

    use async_trait::async_trait;
    use rune_chain_core::{GenerateResult, LlmError, Message, prompt_args};
    use rune_chain_embed::{EmbedError, Embedder};

    use super::*;
    use crate::InMemoryVectorStore;

    // Embedder that encodes text as a normalised byte-frequency vector (256 dims).
    // Texts that share the same characters will have high cosine similarity.
    struct ByteFreqEmbedder;

    #[async_trait]
    impl Embedder for ByteFreqEmbedder {
        async fn embed_batch(&self, texts: &[&str]) -> Result<Vec<Vec<f32>>, EmbedError> {
            Ok(texts
                .iter()
                .map(|text| {
                    let mut freq = vec![0.0f32; 256];
                    for byte in text.bytes() {
                        freq[usize::from(byte)] += 1.0;
                    }
                    let mag: f32 = freq.iter().map(|x| x * x).sum::<f32>().sqrt();
                    if mag > 0.0 {
                        for x in &mut freq {
                            *x /= mag;
                        }
                    }
                    freq
                })
                .collect())
        }
    }

    struct ContextCaptureLlm {
        captured: Arc<tokio::sync::Mutex<Vec<Vec<Message>>>>,
    }

    #[async_trait]
    impl Llm for ContextCaptureLlm {
        async fn generate(&self, messages: &[Message]) -> Result<GenerateResult, LlmError> {
            self.captured.lock().await.push(messages.to_vec());
            Ok(GenerateResult::from_text("answer"))
        }
    }

    async fn make_store() -> Arc<InMemoryVectorStore> {
        let store = Arc::new(InMemoryVectorStore::new(Arc::new(ByteFreqEmbedder)));
        store
            .add_texts(&[
                "aaaaaa bbbbbb cccccc",
                "dddddd eeeeee ffffff",
                "gggggg hhhhhh iiiiii",
            ])
            .await
            .unwrap();
        store
    }

    #[tokio::test]
    async fn returns_answer_from_llm() {
        let store = make_store().await;
        let embedder = Arc::new(ByteFreqEmbedder);
        let captured = Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let llm = ContextCaptureLlm {
            captured: Arc::clone(&captured),
        };
        let chain = RetrievalQaChain::new(llm, embedder, store);
        let result = chain
            .invoke(prompt_args! { "input" => "aaaaaa" })
            .await
            .unwrap();
        assert_eq!(result, "answer");
    }

    #[allow(
        clippy::significant_drop_tightening,
        reason = "the guard must outlive the values borrowed from it"
    )]
    #[tokio::test]
    async fn context_contains_retrieved_docs() {
        let store = make_store().await;
        let embedder = Arc::new(ByteFreqEmbedder);
        let captured = Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let llm = ContextCaptureLlm {
            captured: Arc::clone(&captured),
        };
        let chain = RetrievalQaChain::new(llm, embedder, store).top_k(1);

        chain
            .invoke(prompt_args! { "input" => "aaaaaa bbbbbb cccccc" })
            .await
            .unwrap();

        let calls = captured.lock().await;
        let human = calls[0]
            .iter()
            .find(|m| m.role == rune_chain_core::Role::Human)
            .unwrap();
        assert!(
            human.content.text_content().contains("aaaaaa"),
            "context should include the most similar document"
        );
    }

    #[allow(
        clippy::significant_drop_tightening,
        reason = "the guard must outlive the values borrowed from it"
    )]
    #[tokio::test]
    async fn custom_system_prompt_is_used() {
        let store = make_store().await;
        let embedder = Arc::new(ByteFreqEmbedder);
        let captured = Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let llm = ContextCaptureLlm {
            captured: Arc::clone(&captured),
        };
        let chain = RetrievalQaChain::new(llm, embedder, store).with_system("Custom instructions.");

        chain
            .invoke(prompt_args! { "input" => "query" })
            .await
            .unwrap();

        let calls = captured.lock().await;
        let system = calls[0]
            .iter()
            .find(|m| m.role == rune_chain_core::Role::System)
            .unwrap();
        assert_eq!(system.content, "Custom instructions.");
    }

    #[tokio::test]
    async fn missing_input_key_returns_error() {
        let store = make_store().await;
        let embedder = Arc::new(ByteFreqEmbedder);
        let captured = Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let llm = ContextCaptureLlm { captured };
        let chain = RetrievalQaChain::new(llm, embedder, store);
        let err = chain.invoke(prompt_args! { "wrong" => "q" }).await;
        assert!(err.is_err());
    }

    #[allow(
        clippy::significant_drop_tightening,
        reason = "the guard must outlive the values borrowed from it"
    )]
    #[tokio::test]
    async fn empty_store_produces_no_context_message() {
        let empty_store = Arc::new(InMemoryVectorStore::new(Arc::new(ByteFreqEmbedder)));
        let embedder = Arc::new(ByteFreqEmbedder);
        let captured = Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let llm = ContextCaptureLlm {
            captured: Arc::clone(&captured),
        };
        let chain = RetrievalQaChain::new(llm, embedder, empty_store);

        chain
            .invoke(prompt_args! { "input" => "anything" })
            .await
            .unwrap();

        let calls = captured.lock().await;
        let human = calls[0]
            .iter()
            .find(|m| m.role == rune_chain_core::Role::Human)
            .unwrap();
        assert!(human.content.text_content().contains("No relevant context"));
    }
}
