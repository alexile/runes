//! `ConversationalChain` against the shared `Chain` contract, plus memory
//! handling across turns and streams.

#![allow(clippy::unwrap_used, reason = "test assertions")]

use std::pin::Pin;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use futures::{Stream, StreamExt, stream};
use rune_chain_conversational::ConversationalChain;
use rune_chain_core::testing::{check_chain, check_chain_rejects};
use rune_chain_core::{
    Chain, ChainError, GenerateResult, Llm, LlmError, Memory, Message, Role, StreamData,
    prompt_args,
};
use rune_chain_memory::{SimpleMemory, WindowedMemory};

/// Replies with the last human message, streams it word by word, and records
/// every conversation it was sent.
#[derive(Default)]
struct EchoLlm {
    seen: Mutex<Vec<Vec<Message>>>,
}

impl EchoLlm {
    fn reply(&self, messages: &[Message]) -> String {
        self.seen.lock().unwrap().push(messages.to_vec());
        messages
            .iter()
            .rev()
            .find(|m| m.role == Role::Human)
            .map(|m| m.content.text_content())
            .unwrap_or_default()
    }
}

#[async_trait]
impl Llm for EchoLlm {
    async fn generate(&self, messages: &[Message]) -> Result<GenerateResult, LlmError> {
        Ok(GenerateResult::from_text(self.reply(messages)))
    }

    async fn stream(&self, messages: &[Message]) -> Result<BoxStream, LlmError> {
        let reply = self.reply(messages);
        let mut chunks: Vec<Result<StreamData, LlmError>> = reply
            .split_inclusive(' ')
            .map(|w| Ok(StreamData::chunk(w)))
            .collect();
        chunks.push(Ok(StreamData::done()));
        Ok(Box::pin(stream::iter(chunks)))
    }
}

type BoxStream = Pin<Box<dyn Stream<Item = Result<StreamData, LlmError>> + Send>>;

/// Lets a test keep a handle on the [`EchoLlm`] a chain owns.
struct Shared(Arc<EchoLlm>);

#[async_trait]
impl Llm for Shared {
    async fn generate(&self, m: &[Message]) -> Result<GenerateResult, LlmError> {
        self.0.generate(m).await
    }

    async fn stream(&self, m: &[Message]) -> Result<BoxStream, LlmError> {
        self.0.stream(m).await
    }
}

struct Down;

#[async_trait]
impl Llm for Down {
    async fn generate(&self, _: &[Message]) -> Result<GenerateResult, LlmError> {
        Err(LlmError::request_failed("connection refused"))
    }
}

#[tokio::test]
async fn meets_the_chain_contract() {
    let chain = ConversationalChain::new(EchoLlm::default());
    check_chain(&chain, &prompt_args! { "input" => "hello there" })
        .await
        .unwrap();
}

#[tokio::test]
async fn meets_the_chain_contract_with_windowed_memory() {
    let chain = ConversationalChain::new(EchoLlm::default())
        .with_memory(Arc::new(WindowedMemory::new(2)))
        .with_system("Be brief.");
    check_chain(&chain, &prompt_args! { "input" => "hi" })
        .await
        .unwrap();
}

#[tokio::test]
async fn rejects_input_without_the_input_key() {
    let chain = ConversationalChain::new(EchoLlm::default());
    check_chain_rejects(&chain, &prompt_args! { "question" => "hi" })
        .await
        .unwrap();
    check_chain_rejects(&chain, &prompt_args! { "input" => 42 })
        .await
        .unwrap();
    assert!(matches!(
        chain.stream(prompt_args! {}).await.err(),
        Some(ChainError::MissingVariable(_))
    ));
}

#[tokio::test]
async fn failed_generation_leaves_memory_untouched() {
    let memory = Arc::new(SimpleMemory::new());
    let chain = ConversationalChain::new(Down).with_memory(memory.clone());
    let err = chain
        .call(prompt_args! { "input" => "hi" })
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        ChainError::LlmError(ref e) if e.kind() == rune_chain_core::LlmErrorKind::Network
    ));
    assert_eq!(memory.messages().await.unwrap(), []);
}

#[tokio::test]
async fn stream_sees_history_but_does_not_record() {
    let memory = Arc::new(SimpleMemory::new());
    memory.add(Message::human("earlier")).await.unwrap();
    memory.add(Message::ai("reply")).await.unwrap();
    let llm = Arc::new(EchoLlm::default());
    let chain = ConversationalChain::new(Shared(Arc::clone(&llm)))
        .with_system("S")
        .with_memory(memory.clone());
    let s = chain
        .stream(prompt_args! { "input" => "now then" })
        .await
        .unwrap();
    let text: String = s
        .map(|c| c.unwrap().content)
        .collect::<Vec<_>>()
        .await
        .concat();
    assert_eq!(text, "now then");
    assert_eq!(memory.messages().await.unwrap().len(), 2);
    let roles: Vec<Role> = llm.seen.lock().unwrap()[0]
        .iter()
        .map(|m| m.role.clone())
        .collect();
    assert_eq!(roles, [Role::System, Role::Human, Role::Ai, Role::Human]);
    assert_eq!(chain.input_keys(), ["input"]);
}
