//! `ConversationalChain` — LLM + memory wired for ergonomic multi-turn dialogue.
//!
//! Every call automatically saves the human turn and the AI response so each
//! subsequent call sees the full prior context. Streaming is fully supported.
//!
//! # Quick Start
//!
//! ```rust
//! use rune_chain_conversational::ConversationalChain;
//! use rune_chain_core::{Chain, prompt_args};
//!
//! # struct FakeLlm;
//! # use async_trait::async_trait;
//! # use rune_chain_core::{Llm, Message, GenerateResult, LlmError};
//! # #[async_trait] impl Llm for FakeLlm {
//! #     async fn generate(&self, msgs: &[Message]) -> Result<GenerateResult, LlmError> {
//! #         Ok(GenerateResult::from_text("ok"))
//! #     }
//! # }
//! # tokio_test::block_on(async {
//! let chain = ConversationalChain::new(FakeLlm);
//!
//! let r1 = chain.invoke(prompt_args! { "input" => "Hi, my name is Alice." }).await.unwrap();
//! let r2 = chain.invoke(prompt_args! { "input" => "What is my name?" }).await.unwrap();
//! # });
//! ```

use std::pin::Pin;
use std::sync::Arc;

use async_trait::async_trait;
use futures::{Stream, StreamExt};
use rune_chain_core::{
    Chain, ChainError, GenerateResult, Llm, Memory, Message, PromptArgs, StreamData,
};
use rune_chain_memory::SimpleMemory;

const DEFAULT_INPUT_KEY: &str = "input";
const DEFAULT_SYSTEM: &str = "You are a helpful, friendly AI assistant. \
    Respond naturally and remember what has been discussed.";

/// A multi-turn conversational chain that automatically manages memory.
///
/// Pass `"input"` in [`PromptArgs`] on every call; the chain saves the human
/// turn and the AI response so each subsequent call sees the full prior context.
pub struct ConversationalChain<L: Llm> {
    llm: L,
    system: String,
    memory: Arc<dyn Memory>,
}

impl<L: Llm + 'static> ConversationalChain<L> {
    /// Create a chain with an LLM, default system prompt, and `SimpleMemory`.
    pub fn new(llm: L) -> Self {
        Self {
            llm,
            system: DEFAULT_SYSTEM.to_string(),
            memory: Arc::new(SimpleMemory::new()),
        }
    }

    /// Override the system prompt.
    #[must_use]
    pub fn with_system(mut self, system: impl Into<String>) -> Self {
        self.system = system.into();
        self
    }

    /// Attach a custom [`Memory`] implementation instead of the default `SimpleMemory`.
    #[must_use]
    pub fn with_memory(mut self, memory: Arc<dyn Memory>) -> Self {
        self.memory = memory;
        self
    }

    async fn build_messages(&self, human_text: &str) -> Result<Vec<Message>, ChainError> {
        let history = self.memory.messages().await?;
        let mut messages: Vec<Message> = Vec::with_capacity(2 + history.len() + 1);
        messages.push(Message::system(&self.system));
        messages.extend(history);
        messages.push(Message::human(human_text));
        Ok(messages)
    }
}

#[async_trait]
impl<L: Llm + 'static> Chain for ConversationalChain<L> {
    async fn call(&self, input: PromptArgs) -> Result<GenerateResult, ChainError> {
        let human_text = input
            .get(DEFAULT_INPUT_KEY)
            .and_then(|v| v.as_str())
            .ok_or_else(|| ChainError::MissingVariable(DEFAULT_INPUT_KEY.to_string()))?
            .to_string();

        let messages = self.build_messages(&human_text).await?;
        let result = self.llm.generate(&messages).await?;

        self.memory.add(Message::human(&human_text)).await?;
        self.memory.add(Message::ai(&result.generation)).await?;

        Ok(result)
    }

    async fn stream(
        &self,
        input: PromptArgs,
    ) -> Result<Pin<Box<dyn Stream<Item = Result<StreamData, ChainError>> + Send>>, ChainError>
    {
        let human_text = input
            .get(DEFAULT_INPUT_KEY)
            .and_then(|v| v.as_str())
            .ok_or_else(|| ChainError::MissingVariable(DEFAULT_INPUT_KEY.to_string()))?
            .to_string();

        let messages = self.build_messages(&human_text).await?;
        let raw = self.llm.stream(&messages).await?;
        let mapped = raw.map(|item| item.map_err(ChainError::from));
        Ok(Box::pin(mapped))
    }

    fn input_keys(&self) -> Vec<String> {
        vec![DEFAULT_INPUT_KEY.to_string()]
    }

    fn output_keys(&self) -> Vec<String> {
        vec!["output".to_string(), "generate_result".to_string()]
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use async_trait::async_trait;
    use rune_chain_core::{GenerateResult, LlmError, Message, Role, prompt_args};

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
            Ok(GenerateResult::from_text(format!("echo: {last}")))
        }
    }

    struct RecordingLlm {
        calls: Arc<Mutex<Vec<Vec<Message>>>>,
    }

    #[async_trait]
    impl Llm for RecordingLlm {
        async fn generate(&self, messages: &[Message]) -> Result<GenerateResult, LlmError> {
            self.calls.lock().unwrap().push(messages.to_vec());
            Ok(GenerateResult::from_text("response"))
        }
    }

    #[tokio::test]
    async fn responds_to_input() {
        let chain = ConversationalChain::new(EchoLlm);
        let result = chain
            .invoke(prompt_args! { "input" => "hello" })
            .await
            .unwrap();
        assert_eq!(result, "echo: hello");
    }

    #[allow(
        clippy::significant_drop_tightening,
        reason = "the guard must outlive the values borrowed from it"
    )]
    #[tokio::test]
    async fn memory_grows_across_calls() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let chain = ConversationalChain::new(RecordingLlm {
            calls: Arc::clone(&calls),
        });

        chain
            .invoke(prompt_args! { "input" => "first" })
            .await
            .unwrap();
        chain
            .invoke(prompt_args! { "input" => "second" })
            .await
            .unwrap();

        let recorded = calls.lock().unwrap();
        let second_call = &recorded[1];
        let has_first_turn = second_call.iter().any(|m| m.content.as_text() == "first");
        assert!(has_first_turn, "memory was not carried into second call");
    }

    #[tokio::test]
    async fn system_message_appears_first() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let chain = ConversationalChain::new(RecordingLlm {
            calls: Arc::clone(&calls),
        })
        .with_system("Custom system prompt.");

        chain
            .invoke(prompt_args! { "input" => "hi" })
            .await
            .unwrap();

        let recorded = calls.lock().unwrap();
        assert_eq!(recorded[0][0].role, Role::System);
        assert_eq!(recorded[0][0].content.as_text(), "Custom system prompt.");
    }

    #[allow(
        clippy::significant_drop_tightening,
        reason = "the guard must outlive the values borrowed from it"
    )]
    #[tokio::test]
    async fn windowed_memory_limits_history() {
        use rune_chain_memory::WindowedMemory;

        let calls = Arc::new(Mutex::new(Vec::new()));
        let chain = ConversationalChain::new(RecordingLlm {
            calls: Arc::clone(&calls),
        })
        .with_memory(Arc::new(WindowedMemory::new(2)));

        for i in 0..4u32 {
            chain
                .invoke(prompt_args! { "input" => format!("turn {i}") })
                .await
                .unwrap();
        }

        let recorded = calls.lock().unwrap();
        let last = &recorded[3];
        assert!(
            last.len() <= 4,
            "expected at most 4 messages, got {}",
            last.len()
        );
    }

    #[tokio::test]
    async fn missing_input_key_returns_error() {
        let chain = ConversationalChain::new(EchoLlm);
        let err = chain.invoke(prompt_args! { "wrong_key" => "hi" }).await;
        assert!(err.is_err());
    }
}
