//! `ConversationalChain` against the shared `Chain` contract, plus memory
//! handling across turns and streams. Every LLM here is a local mock.

#![allow(clippy::unwrap_used, reason = "test assertions")]

use std::pin::Pin;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use futures::{Stream, StreamExt, stream};
use rune_chain_conversational::{ConversationalChain, DEFAULT_SYSTEM_PROMPT};
use rune_chain_core::testing::{check_chain, check_chain_rejects};
use rune_chain_core::{
    Chain, ChainError, FinishReason, GenerateResult, Llm, LlmError, LlmErrorKind, Memory, Message,
    Role, StreamData, TokenUsage, prompt_args,
};
use rune_chain_memory::{SimpleMemory, WindowedMemory};

type BoxStream = Pin<Box<dyn Stream<Item = Result<StreamData, LlmError>> + Send>>;

/// Replies with the last human message, streams it word by word, and records
/// every conversation it was sent.
#[derive(Default)]
struct EchoLlm {
    seen: Mutex<Vec<Vec<Message>>>,
    cut_stream: bool,
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

    fn last_seen(&self) -> Vec<Message> {
        self.seen.lock().unwrap().last().cloned().unwrap()
    }
}

#[async_trait]
impl Llm for EchoLlm {
    async fn generate(&self, messages: &[Message]) -> Result<GenerateResult, LlmError> {
        Ok(GenerateResult::from_text(self.reply(messages))
            .with_tokens(TokenUsage::new(5, 2))
            .with_finish_reason(FinishReason::Stop))
    }

    async fn stream(&self, messages: &[Message]) -> Result<BoxStream, LlmError> {
        let reply = self.reply(messages);
        let mut chunks: Vec<Result<StreamData, LlmError>> = reply
            .split_inclusive(' ')
            .map(|w| Ok(StreamData::chunk(w)))
            .collect();
        if self.cut_stream {
            chunks.push(Err(LlmError::request_failed("connection reset")));
        }
        chunks.push(Ok(StreamData::done()));
        Ok(Box::pin(stream::iter(chunks)))
    }
}

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

fn texts(messages: &[Message]) -> Vec<String> {
    messages.iter().map(|m| m.content.text_content()).collect()
}

#[tokio::test]
async fn meets_the_chain_contract() {
    let chain = ConversationalChain::new(EchoLlm::default());
    check_chain(&chain, &prompt_args! { "input" => "hello there" })
        .await
        .unwrap();
}

#[tokio::test]
async fn meets_the_chain_contract_with_other_memories() {
    let windowed = ConversationalChain::new(EchoLlm::default())
        .with_window(2)
        .with_system("Be brief.");
    check_chain(&windowed, &prompt_args! { "input" => "hi" })
        .await
        .unwrap();
    let unbounded = ConversationalChain::new(EchoLlm::default())
        .with_unbounded_history()
        .without_system();
    check_chain(&unbounded, &prompt_args! { "input" => "hi" })
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
async fn custom_input_key() {
    let chain = ConversationalChain::new(EchoLlm::default()).with_input_key("question");
    assert_eq!(chain.input_keys(), ["question"]);
    assert_eq!(
        chain
            .invoke(prompt_args! { "question" => "why" })
            .await
            .unwrap(),
        "why"
    );
}

#[tokio::test]
async fn usage_and_finish_reason_are_returned() {
    let chain = ConversationalChain::new(EchoLlm::default());
    let r = chain.call(prompt_args! { "input" => "hi" }).await.unwrap();
    assert_eq!(r.tokens.unwrap().total_tokens, 7);
    assert_eq!(r.finish_reason, Some(FinishReason::Stop));
}

#[tokio::test]
async fn system_prompt_stays_pinned_while_history_is_trimmed() {
    let llm = Arc::new(EchoLlm::default());
    // ~ (20 chars / 4 + 4) = 9 tokens per message: three fit in 30.
    let chain = ConversationalChain::new(Shared(Arc::clone(&llm)))
        .with_system("Pinned {not a template}")
        .with_token_budget(30);
    for i in 0..8 {
        chain
            .invoke(prompt_args! { "input" => format!("message number {i:06}") })
            .await
            .unwrap();
    }
    let sent = llm.last_seen();
    assert_eq!(sent[0], Message::system("Pinned {not a template}"));
    assert!(sent[1..].iter().all(|m| m.role != Role::System));
    assert!(
        sent.len() <= 5,
        "history not bounded: {} messages",
        sent.len()
    );
    assert_eq!(
        sent.last().unwrap().content.text_content(),
        "message number 000007"
    );
    // The system prompt is never written to memory.
    assert!(
        chain
            .history()
            .await
            .unwrap()
            .iter()
            .all(|m| m.role != Role::System)
    );
    assert_eq!(chain.system(), Some("Pinned {not a template}"));
}

#[tokio::test]
async fn history_is_bounded_by_default() {
    let chain = ConversationalChain::new(EchoLlm::default());
    let long = "x".repeat(4_000);
    for _ in 0..20 {
        chain
            .invoke(prompt_args! { "input" => long.clone() })
            .await
            .unwrap();
    }
    let history = chain.history().await.unwrap();
    assert!(
        history.len() < 40,
        "default history kept {} messages",
        history.len()
    );
    assert_eq!(
        chain.llm().last_seen()[0],
        Message::system(DEFAULT_SYSTEM_PROMPT)
    );
}

#[tokio::test]
async fn summary_memory_folds_old_turns() {
    let llm = Arc::new(EchoLlm::default());
    let folded = |prev: Option<&str>, turns: &[Message]| -> Result<String, ChainError> {
        let mut parts: Vec<String> = prev.into_iter().map(str::to_owned).collect();
        parts.extend(turns.iter().map(|m| m.content.text_content()));
        Ok(parts.join("|"))
    };
    let chain = ConversationalChain::new(Shared(Arc::clone(&llm)))
        .with_system("S")
        .with_summary(folded, 30);
    for i in 0..6 {
        chain
            .invoke(prompt_args! { "input" => format!("fact {i}") })
            .await
            .unwrap();
    }
    let sent = llm.last_seen();
    // Pinned system prompt, then the summary, then recent turns.
    assert_eq!(sent[0], Message::system("S"));
    assert_eq!(sent[1].role, Role::System);
    assert!(sent[1].content.text_content().contains("fact 0"));
    assert_eq!(sent.last().unwrap().content.text_content(), "fact 5");
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
        ChainError::LlmError(ref e) if e.kind() == LlmErrorKind::Network
    ));
    assert_eq!(memory.messages().await.unwrap(), []);
}

#[tokio::test]
async fn stream_sees_history_and_records_the_full_answer() {
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
    assert_eq!(
        texts(&memory.messages().await.unwrap()),
        ["earlier", "reply", "now then", "now then"]
    );
    let roles: Vec<Role> = llm.seen.lock().unwrap()[0]
        .iter()
        .map(|m| m.role.clone())
        .collect();
    assert_eq!(roles, [Role::System, Role::Human, Role::Ai, Role::Human]);
}

#[tokio::test]
async fn interrupted_streams_record_nothing() {
    let memory = Arc::new(SimpleMemory::new());
    let chain = ConversationalChain::new(EchoLlm {
        cut_stream: true,
        ..EchoLlm::default()
    })
    .with_memory(memory.clone());
    let items: Vec<_> = chain
        .stream(prompt_args! { "input" => "a b c" })
        .await
        .unwrap()
        .collect()
        .await;
    assert!(items.last().unwrap().is_err());
    assert_eq!(memory.messages().await.unwrap(), []);

    let chain = ConversationalChain::new(EchoLlm::default()).with_memory(memory.clone());
    let mut s = chain
        .stream(prompt_args! { "input" => "a b c" })
        .await
        .unwrap();
    s.next().await.unwrap().unwrap();
    drop(s);
    assert_eq!(memory.messages().await.unwrap(), []);
}

#[tokio::test]
async fn clear_history_keeps_the_system_prompt() {
    let chain = ConversationalChain::new(EchoLlm::default())
        .with_memory(Arc::new(WindowedMemory::new(10)))
        .with_system("S");
    chain
        .invoke(prompt_args! { "input" => "one" })
        .await
        .unwrap();
    assert_eq!(chain.history().await.unwrap().len(), 2);
    chain.clear_history().await.unwrap();
    assert_eq!(chain.history().await.unwrap().len(), 0);
    chain
        .invoke(prompt_args! { "input" => "two" })
        .await
        .unwrap();
    assert_eq!(texts(&chain.llm().last_seen()), ["S", "two"]);
    assert!(format!("{chain:?}").contains("ConversationalChain"));
}
