//! `LlmChain` — wire a prompt template, an LLM, and optional memory into a single [`Chain`].
//!
//! # Message order
//!
//! ```text
//! System messages (from template, always first)
//! ↓ prior Human / Ai turns (from memory)
//! ↓ current Human input (from template)
//! ```
//!
//! Only `Human` turns and `Ai` responses are persisted to memory; `System`
//! messages are re-applied fresh from the template on every call.
//!
//! # Streaming
//!
//! [`LlmChain::stream`](Chain::stream) is fully implemented: it forwards the
//! prompt to [`Llm::stream`] and yields chunks
//! directly. Memory is **not** updated automatically during a stream because
//! the complete output is only known once the stream ends — drain the stream
//! and persist the result manually if needed.
//!
//! # Quick Start
//!
//! ```rust
//! use std::sync::Arc;
//! use rune_chain_llm::LlmChain;
//! use rune_chain_prompt::{ChatTemplate, MessageTemplate};
//! use rune_chain_core::{Chain, prompt_args};
//!
//! # async fn run() -> Result<(), Box<dyn std::error::Error>> {
//! # struct FakeLlm;
//! # use async_trait::async_trait;
//! # use rune_chain_core::{Llm, Message, GenerateResult, LlmError};
//! # #[async_trait] impl Llm for FakeLlm {
//! #     async fn generate(&self, _: &[Message]) -> Result<GenerateResult, LlmError> {
//! #         Ok(GenerateResult::from_text("42"))
//! #     }
//! # }
//! let chain = LlmChain::new(FakeLlm, ChatTemplate::new(vec![
//!     MessageTemplate::system("You are helpful."),
//!     MessageTemplate::human("{question}"),
//! ]));
//!
//! let answer = chain.invoke(prompt_args! { "question" => "What is 2 + 2?" }).await?;
//! println!("{answer}");
//! # Ok(()) }
//! # tokio_test::block_on(run()).unwrap();
//! ```

use std::pin::Pin;
use std::sync::Arc;

use async_trait::async_trait;
use futures::Stream;
use rune_chain_core::{
    Chain, ChainError, GenerateResult, Llm, Memory, Message, PromptArgs, Role, StreamData,
};
use rune_chain_prompt::ChatTemplate;

/// A chain that renders a prompt template and sends it to an [`Llm`].
pub struct LlmChain<L: Llm> {
    llm: L,
    prompt: ChatTemplate,
    memory: Option<Arc<dyn Memory>>,
    max_context_tokens: Option<usize>,
}

impl<L: Llm> LlmChain<L> {
    /// Create a chain from an LLM and a prompt template, with no memory and no token limit.
    pub fn new(llm: L, prompt: ChatTemplate) -> Self {
        Self {
            llm,
            prompt,
            memory: None,
            max_context_tokens: None,
        }
    }

    /// Attach a [`Memory`] store for multi-turn conversation history.
    #[must_use]
    pub fn with_memory(mut self, memory: Arc<dyn Memory>) -> Self {
        self.memory = Some(memory);
        self
    }

    /// Reject calls whose combined context exceeds `max_tokens` (approximate, 4 chars ≈ 1 token).
    #[must_use]
    pub const fn with_max_context_tokens(mut self, max_tokens: usize) -> Self {
        self.max_context_tokens = Some(max_tokens);
        self
    }

    async fn build_messages(
        &self,
        input: &PromptArgs,
    ) -> Result<(Vec<Message>, Vec<Message>), ChainError> {
        let new_messages = self.prompt.format_messages(input)?;

        let (system_msgs, input_msgs): (Vec<_>, Vec<_>) = new_messages
            .into_iter()
            .partition(|m| m.role == Role::System);

        let history = match &self.memory {
            Some(mem) => mem.messages().await?,
            None => Vec::new(),
        };

        Ok((
            assemble_messages(system_msgs, history, input_msgs.clone()),
            input_msgs,
        ))
    }
}

fn assemble_messages(
    system_msgs: Vec<Message>,
    history: Vec<Message>,
    input_msgs: Vec<Message>,
) -> Vec<Message> {
    system_msgs
        .into_iter()
        .chain(history)
        .chain(input_msgs)
        .collect()
}

fn check_budget(messages: &[Message], max_tokens: usize) -> Result<(), ChainError> {
    let combined: String = messages
        .iter()
        .map(|m| m.content.text_content())
        .collect::<Vec<_>>()
        .join("\n");
    let tokens = rune_tokenize::estimate(&combined);
    if tokens > max_tokens {
        Err(ChainError::Other(format!(
            "context too large: ~{tokens} tokens exceeds limit of {max_tokens}"
        )))
    } else {
        Ok(())
    }
}

#[async_trait]
impl<L: Llm + 'static> Chain for LlmChain<L> {
    async fn call(&self, input: PromptArgs) -> Result<GenerateResult, ChainError> {
        let (combined, input_msgs) = self.build_messages(&input).await?;

        if let Some(max) = self.max_context_tokens {
            check_budget(&combined, max)?;
        }

        let result = self.llm.generate(&combined).await?;

        if let Some(mem) = &self.memory {
            for msg in &input_msgs {
                if msg.role == Role::Human {
                    mem.add(msg.clone()).await?;
                }
            }
            mem.add(Message::ai(&result.generation)).await?;
        }

        Ok(result)
    }

    async fn stream(
        &self,
        input: PromptArgs,
    ) -> Result<Pin<Box<dyn Stream<Item = Result<StreamData, ChainError>> + Send>>, ChainError>
    {
        let (combined, _input_msgs) = self.build_messages(&input).await?;

        if let Some(max) = self.max_context_tokens {
            check_budget(&combined, max)?;
        }

        let raw = self.llm.stream(&combined).await?;
        let mapped = futures::StreamExt::map(raw, |item| item.map_err(ChainError::from));
        Ok(Box::pin(mapped))
    }

    fn input_keys(&self) -> Vec<String> {
        self.prompt.input_variables()
    }

    fn output_keys(&self) -> Vec<String> {
        vec!["output".to_string(), "generate_result".to_string()]
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use async_trait::async_trait;
    use rune_chain_core::{GenerateResult, LlmError, Memory, Message, Role, prompt_args};
    use rune_chain_memory::SimpleMemory;
    use rune_chain_prompt::{ChatTemplate, MessageTemplate};

    use super::*;

    struct EchoLlm;

    #[async_trait]
    impl Llm for EchoLlm {
        async fn generate(&self, messages: &[Message]) -> Result<GenerateResult, LlmError> {
            let last = messages
                .iter()
                .rfind(|m| m.role == Role::Human)
                .map(|m| m.content.text_content())
                .unwrap_or_default();
            Ok(GenerateResult::from_text(last))
        }
    }

    struct RecordingLlm {
        calls: Arc<Mutex<Vec<Vec<Message>>>>,
    }

    #[async_trait]
    impl Llm for RecordingLlm {
        async fn generate(&self, messages: &[Message]) -> Result<GenerateResult, LlmError> {
            self.calls.lock().unwrap().push(messages.to_vec());
            Ok(GenerateResult::from_text("recorded"))
        }
    }

    fn simple_prompt() -> ChatTemplate {
        ChatTemplate::new(vec![
            MessageTemplate::system("You are helpful."),
            MessageTemplate::human("{input}"),
        ])
    }

    #[tokio::test]
    async fn echoes_human_input() {
        let chain = LlmChain::new(EchoLlm, simple_prompt());
        let answer = chain
            .invoke(prompt_args! { "input" => "hello" })
            .await
            .unwrap();
        assert_eq!(answer, "hello");
    }

    #[tokio::test]
    async fn memory_accumulates_across_calls() {
        let mem = Arc::new(SimpleMemory::new());
        let chain = LlmChain::new(EchoLlm, simple_prompt()).with_memory(Arc::clone(&mem) as _);

        chain
            .invoke(prompt_args! { "input" => "first" })
            .await
            .unwrap();
        chain
            .invoke(prompt_args! { "input" => "second" })
            .await
            .unwrap();

        let history = mem.messages().await.unwrap();
        assert_eq!(history.len(), 4);
        assert_eq!(history[0].content.as_text(), "first");
        assert_eq!(history[2].content.as_text(), "second");
    }

    #[tokio::test]
    async fn system_message_is_always_first() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let llm = RecordingLlm {
            calls: Arc::clone(&calls),
        };
        let mem = Arc::new(SimpleMemory::new());
        mem.add(Message::human("prior")).await.unwrap();
        mem.add(Message::ai("reply")).await.unwrap();

        let chain = LlmChain::new(llm, simple_prompt()).with_memory(Arc::clone(&mem) as _);
        chain
            .invoke(prompt_args! { "input" => "now" })
            .await
            .unwrap();

        let sent = calls.lock().unwrap();
        assert_eq!(sent[0][0].role, Role::System);
        assert_eq!(sent[0][1].role, Role::Human);
        assert_eq!(sent[0][2].role, Role::Ai);
        assert_eq!(sent[0][3].role, Role::Human);
    }

    #[tokio::test]
    async fn system_message_not_saved_to_memory() {
        let mem = Arc::new(SimpleMemory::new());
        let chain = LlmChain::new(EchoLlm, simple_prompt()).with_memory(Arc::clone(&mem) as _);
        chain
            .invoke(prompt_args! { "input" => "hi" })
            .await
            .unwrap();

        let history = mem.messages().await.unwrap();
        assert!(history.iter().all(|m| m.role != Role::System));
    }

    #[tokio::test]
    async fn rejects_oversized_context() {
        let big_input = "word ".repeat(10_000);
        let chain = LlmChain::new(EchoLlm, simple_prompt()).with_max_context_tokens(100);
        let err = chain
            .invoke(prompt_args! { "input" => big_input })
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("context too large"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn input_keys_come_from_template() {
        let chain = LlmChain::new(EchoLlm, simple_prompt());
        assert_eq!(chain.input_keys(), vec!["input"]);
    }
}
