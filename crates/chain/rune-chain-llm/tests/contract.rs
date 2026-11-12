//! `LlmChain` against the shared `Chain` contract: templating, memory,
//! streaming and the context budget.

#![allow(clippy::unwrap_used, reason = "test assertions")]

use std::pin::Pin;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use futures::{Stream, StreamExt, stream};
use rune_chain_core::testing::{check_chain, check_chain_rejects};
use rune_chain_core::{
    Chain, GenerateResult, Llm, LlmError, Memory, Message, Role, StreamData, prompt_args,
};
use rune_chain_llm::LlmChain;
use rune_chain_memory::{SimpleMemory, WindowedMemory};
use rune_chain_prompt::{ChatTemplate, MessageTemplate};

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
}

fn template() -> ChatTemplate {
    ChatTemplate::new(vec![
        MessageTemplate::system("You are {persona}."),
        MessageTemplate::human("{question}"),
    ])
}

fn args() -> rune_chain_core::PromptArgs {
    prompt_args! { "persona" => "terse", "question" => "what is two plus two" }
}

#[tokio::test]
async fn meets_the_chain_contract() {
    check_chain(&LlmChain::new(EchoLlm::default(), template()), &args())
        .await
        .unwrap();
}

#[tokio::test]
async fn meets_the_chain_contract_with_memory_and_a_budget() {
    let chain = LlmChain::new(EchoLlm::default(), template())
        .with_memory(Arc::new(WindowedMemory::new(4)))
        .with_max_context_tokens(10_000);
    check_chain(&chain, &args()).await.unwrap();
}

#[tokio::test]
async fn rejects_missing_template_variables() {
    let chain = LlmChain::new(EchoLlm::default(), template());
    check_chain_rejects(&chain, &prompt_args! { "persona" => "terse" })
        .await
        .unwrap();
}

#[tokio::test]
async fn rejects_context_over_budget_without_calling_the_llm() {
    let llm = Arc::new(EchoLlm::default());
    let chain = LlmChain::new(Shared(Arc::clone(&llm)), template()).with_max_context_tokens(3);
    check_chain_rejects(&chain, &args()).await.unwrap();
    assert!(chain.stream(args()).await.is_err());
    assert_eq!(llm.seen.lock().unwrap().len(), 0);
}

#[tokio::test]
async fn stream_yields_the_reply_and_leaves_memory_alone() {
    let memory = Arc::new(SimpleMemory::new());
    let chain = LlmChain::new(EchoLlm::default(), template()).with_memory(memory.clone());
    let s = chain.stream(args()).await.unwrap();
    let text: String = s
        .map(|c| c.unwrap().content)
        .collect::<Vec<_>>()
        .await
        .concat();
    assert_eq!(text, "what is two plus two");
    // Only `call` records turns; a stream's reply is not known up front.
    assert_eq!(memory.messages().await.unwrap(), []);
}

#[tokio::test]
async fn history_sits_between_system_and_new_input() {
    let memory = Arc::new(SimpleMemory::new());
    let llm = Arc::new(EchoLlm::default());
    let chain = LlmChain::new(Shared(Arc::clone(&llm)), template()).with_memory(memory.clone());
    chain.call(args()).await.unwrap();
    chain
        .call(prompt_args! { "persona" => "terse", "question" => "and three" })
        .await
        .unwrap();
    assert_eq!(memory.messages().await.unwrap().len(), 4);
    let second = llm.seen.lock().unwrap()[1].clone();
    let roles: Vec<Role> = second.iter().map(|m| m.role.clone()).collect();
    assert_eq!(roles, [Role::System, Role::Human, Role::Ai, Role::Human]);
    assert_eq!(second[3].content.text_content(), "and three");
}
