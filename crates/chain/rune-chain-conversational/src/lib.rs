//! `ConversationalChain` — an LLM plus bounded conversation memory, wired for
//! multi-turn dialogue.
//!
//! Every call sends the pinned system prompt, the remembered history and the
//! new input, then records the human turn and the answer. Streams record the
//! full answer too, once they have been read to the end.
//!
//! # Features
//!
//! - The system prompt is kept out of memory and sent first on every call,
//!   so no history policy can evict or reorder it.
//! - History is bounded by default: a [`TokenBufferMemory`] holding about
//!   [`DEFAULT_HISTORY_TOKENS`] tokens. Swap in a window, a summarizing
//!   memory or any [`Memory`] with the `with_*` methods.
//! - [`Chain::call`] returns the model's [`GenerateResult`] unchanged, so
//!   token usage and the finish reason reach the caller.
//! - A failed call or an interrupted stream leaves memory untouched.
//!
//! # Quick Start
//!
//! ```rust
//! use rune_chain_conversational::ConversationalChain;
//! use rune_chain_core::{Chain, Memory, prompt_args};
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
//! let chain = ConversationalChain::new(FakeLlm).with_system("You are terse.");
//!
//! chain.invoke(prompt_args! { "input" => "Hi, my name is Alice." }).await.unwrap();
//! chain.invoke(prompt_args! { "input" => "What is my name?" }).await.unwrap();
//! assert_eq!(chain.history().await.unwrap().len(), 4);
//! # });
//! ```

use std::sync::Arc;

use async_trait::async_trait;
use futures::StreamExt;
use rune_chain_core::{Chain, ChainError, GenerateResult, Llm, Memory, Message, PromptArgs};
use rune_chain_llm::{ChainStream, with_stream_completion};
use rune_chain_memory::{
    SimpleMemory, Summarizer, SummaryBufferMemory, TokenBufferMemory, WindowedMemory,
};

/// The default input key.
pub const DEFAULT_INPUT_KEY: &str = "input";

/// The default system prompt.
pub const DEFAULT_SYSTEM_PROMPT: &str = "You are a helpful, friendly AI assistant. \
    Respond naturally and remember what has been discussed.";

/// Token budget of the default history (a [`TokenBufferMemory`] with the
/// character estimate, about four characters per token).
pub const DEFAULT_HISTORY_TOKENS: usize = 4_000;

/// A multi-turn conversational chain that manages its own memory.
///
/// Pass the user's message under `"input"` (see
/// [`with_input_key`](Self::with_input_key)). The model sees:
///
/// ```text
/// System prompt (pinned, never stored in memory)
/// ↓ history from memory (a summary message first, for summarizing memories)
/// ↓ the new human message
/// ```
///
/// After a successful call the human message and the answer are added to
/// memory. Concurrent calls on one chain share the memory; their turns may
/// interleave.
pub struct ConversationalChain<L: Llm> {
    llm: L,
    system: Option<String>,
    memory: Arc<dyn Memory>,
    input_key: String,
}

impl<L: Llm> std::fmt::Debug for ConversationalChain<L> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConversationalChain")
            .field("has_system", &self.system.is_some())
            .field("input_key", &self.input_key)
            .finish_non_exhaustive()
    }
}

impl<L: Llm + 'static> ConversationalChain<L> {
    /// Create a chain with the [default system prompt](DEFAULT_SYSTEM_PROMPT)
    /// and a [`TokenBufferMemory`] of [`DEFAULT_HISTORY_TOKENS`].
    pub fn new(llm: L) -> Self {
        Self {
            llm,
            system: Some(DEFAULT_SYSTEM_PROMPT.to_string()),
            memory: Arc::new(TokenBufferMemory::with_char_estimate(
                DEFAULT_HISTORY_TOKENS,
            )),
            input_key: DEFAULT_INPUT_KEY.to_string(),
        }
    }

    /// Replace the system prompt. It is sent verbatim (no template
    /// substitution) at the start of every request.
    #[must_use]
    pub fn with_system(mut self, system: impl Into<String>) -> Self {
        self.system = Some(system.into());
        self
    }

    /// Send no system prompt at all.
    #[must_use]
    pub fn without_system(mut self) -> Self {
        self.system = None;
        self
    }

    /// Read the user's message from `key` instead of `"input"`.
    #[must_use]
    pub fn with_input_key(mut self, key: impl Into<String>) -> Self {
        self.input_key = key.into();
        self
    }

    /// Use any [`Memory`], for example one shared with other chains or
    /// backed by a database.
    #[must_use]
    pub fn with_memory(mut self, memory: Arc<dyn Memory>) -> Self {
        self.memory = memory;
        self
    }

    /// Keep the newest turns that fit `max_tokens`, estimated at about four
    /// characters per token (a [`TokenBufferMemory`]). For a real
    /// tokenizer, build a [`TokenBufferMemory`] yourself and pass it to
    /// [`with_memory`](Self::with_memory).
    ///
    /// # Example
    ///
    /// ```rust
    /// # use rune_chain_core::{GenerateResult, Llm, LlmError, Message};
    /// # struct Mock;
    /// # #[async_trait::async_trait]
    /// # impl Llm for Mock {
    /// #     async fn generate(&self, _: &[Message]) -> Result<GenerateResult, LlmError> {
    /// #         Ok(GenerateResult::from_text("a fairly long answer to fill the budget"))
    /// #     }
    /// # }
    /// use rune_chain_conversational::ConversationalChain;
    /// use rune_chain_core::{Chain, prompt_args};
    ///
    /// # tokio_test::block_on(async {
    /// let chain = ConversationalChain::new(Mock).with_token_budget(40);
    /// for i in 0..10 {
    ///     chain.invoke(prompt_args! { "input" => format!("question {i}") }).await.unwrap();
    /// }
    /// assert!(chain.history().await.unwrap().len() < 20);
    /// # });
    /// ```
    #[must_use]
    pub fn with_token_budget(self, max_tokens: usize) -> Self {
        self.with_memory(Arc::new(TokenBufferMemory::with_char_estimate(max_tokens)))
    }

    /// Keep the last `messages` messages (a [`WindowedMemory`]).
    #[must_use]
    pub fn with_window(self, messages: usize) -> Self {
        self.with_memory(Arc::new(WindowedMemory::new(messages)))
    }

    /// Keep recent turns within `max_tokens` and fold older ones into a
    /// running summary written by `summarizer` (a [`SummaryBufferMemory`];
    /// use [`LlmSummarizer`](rune_chain_memory::LlmSummarizer) to have an
    /// LLM write it).
    ///
    /// # Example
    ///
    /// ```rust
    /// # use rune_chain_core::{GenerateResult, Llm, LlmError};
    /// # struct Mock;
    /// # #[async_trait::async_trait]
    /// # impl Llm for Mock {
    /// #     async fn generate(&self, _: &[Message]) -> Result<GenerateResult, LlmError> {
    /// #         Ok(GenerateResult::from_text("noted"))
    /// #     }
    /// # }
    /// use rune_chain_conversational::ConversationalChain;
    /// use rune_chain_core::{Chain, ChainError, Message, Role, prompt_args};
    ///
    /// let count = |prev: Option<&str>, turns: &[Message]| -> Result<String, ChainError> {
    ///     let before: usize = prev.and_then(|p| p.rsplit(' ').next()?.parse().ok()).unwrap_or(0);
    ///     Ok(format!("turns folded: {}", before + turns.len()))
    /// };
    /// # tokio_test::block_on(async {
    /// let chain = ConversationalChain::new(Mock).with_summary(count, 20);
    /// for i in 0..6 {
    ///     chain.invoke(prompt_args! { "input" => format!("fact number {i}") }).await.unwrap();
    /// }
    /// let history = chain.history().await.unwrap();
    /// assert_eq!(history[0].role, Role::System);
    /// assert!(history[0].content.text_content().contains("turns folded"));
    /// # });
    /// ```
    #[must_use]
    pub fn with_summary(self, summarizer: impl Summarizer + 'static, max_tokens: usize) -> Self {
        self.with_memory(Arc::new(SummaryBufferMemory::new(summarizer, max_tokens)))
    }

    /// Keep every turn (a [`SimpleMemory`]). Long conversations will
    /// eventually overflow the model's context window; prefer a bounded
    /// memory.
    #[must_use]
    pub fn with_unbounded_history(self) -> Self {
        self.with_memory(Arc::new(SimpleMemory::new()))
    }

    /// The LLM this chain calls.
    pub const fn llm(&self) -> &L {
        &self.llm
    }

    /// The memory holding the conversation.
    #[must_use]
    pub const fn memory(&self) -> &Arc<dyn Memory> {
        &self.memory
    }

    /// The system prompt, if any.
    #[must_use]
    pub fn system(&self) -> Option<&str> {
        self.system.as_deref()
    }

    /// The history the next call will see (without the system prompt).
    ///
    /// # Errors
    ///
    /// The memory's error.
    pub async fn history(&self) -> Result<Vec<Message>, ChainError> {
        self.memory.messages().await
    }

    /// Forget the conversation. The system prompt is kept.
    ///
    /// # Errors
    ///
    /// The memory's error.
    pub async fn clear_history(&self) -> Result<(), ChainError> {
        self.memory.clear().await
    }

    fn human_text(&self, input: &PromptArgs) -> Result<String, ChainError> {
        input
            .get(&self.input_key)
            .and_then(|v| v.as_str())
            .map(str::to_string)
            .ok_or_else(|| ChainError::MissingVariable(self.input_key.clone()))
    }

    async fn build_messages(&self, human_text: &str) -> Result<Vec<Message>, ChainError> {
        let history = self.memory.messages().await?;
        let mut messages = Vec::with_capacity(history.len() + 2);
        messages.extend(self.system.as_deref().map(Message::system));
        messages.extend(history);
        messages.push(Message::human(human_text));
        Ok(messages)
    }
}

async fn record(memory: &dyn Memory, human: String, answer: &str) -> Result<(), ChainError> {
    memory.add(Message::human(human)).await?;
    memory.add(Message::ai(answer)).await
}

#[async_trait]
impl<L: Llm + 'static> Chain for ConversationalChain<L> {
    async fn call(&self, input: PromptArgs) -> Result<GenerateResult, ChainError> {
        let human = self.human_text(&input)?;
        let messages = self.build_messages(&human).await?;
        let result = self.llm.generate(&messages).await?;
        record(self.memory.as_ref(), human, &result.generation).await?;
        Ok(result)
    }

    /// Stream the answer. Once the stream has been read to the end, the
    /// human message and the full answer are recorded in memory; a stream
    /// that fails or is dropped early records nothing.
    async fn stream(&self, input: PromptArgs) -> Result<ChainStream, ChainError> {
        let human = self.human_text(&input)?;
        let messages = self.build_messages(&human).await?;
        let raw = self.llm.stream(&messages).await?;
        let mapped: ChainStream = Box::pin(raw.map(|item| item.map_err(ChainError::from)));
        let memory = Arc::clone(&self.memory);
        Ok(with_stream_completion(mapped, move |answer| async move {
            record(memory.as_ref(), human, &answer).await
        }))
    }

    fn input_keys(&self) -> Vec<String> {
        vec![self.input_key.clone()]
    }

    fn output_keys(&self) -> Vec<String> {
        vec!["output".to_string(), "generate_result".to_string()]
    }
}
