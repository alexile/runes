//! Batching, piping, tool binding, callbacks, caching, timeouts and retries.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::items_after_statements,
    clippy::missing_const_for_fn,
    clippy::unnecessary_literal_bound,
    reason = "test fixtures"
)]

use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use futures::{Stream, StreamExt, stream};
use rune_chain_core::{
    CacheKey, CallbackHandler, Chain, ChainEnd, ChainError, ChainExt, ChainFailure, ChainStart,
    FunctionDefinition, GenerateResult, InMemoryLlmCache, Llm, LlmCache, LlmEnd, LlmError, LlmExt,
    LlmFailure, LlmStart, Message, PromptArgs, StreamData, TokenUsage, Tool, ToolChoice, ToolEnd,
    ToolError, ToolExt, ToolFailure, ToolStart, prompt_args,
};
use serde_json::Value;

type ChainStream = Pin<Box<dyn Stream<Item = Result<StreamData, ChainError>> + Send>>;

// ── fixtures ────────────────────────────────────────────────────────────────

/// Tracks how many calls are in flight at once.
#[derive(Default)]
struct Gauge {
    now: AtomicUsize,
    peak: AtomicUsize,
    calls: AtomicUsize,
}

impl Gauge {
    async fn enter(&self, delay_ms: u64) {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let n = self.now.fetch_add(1, Ordering::SeqCst) + 1;
        self.peak.fetch_max(n, Ordering::SeqCst);
        tokio::time::sleep(Duration::from_millis(delay_ms)).await;
        self.now.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Uppercases `input`; fails on "fail"; later inputs finish first.
struct Upper(Arc<Gauge>);

#[async_trait]
impl Chain for Upper {
    async fn call(&self, input: PromptArgs) -> Result<GenerateResult, ChainError> {
        let text = input["input"].as_str().unwrap_or_default().to_owned();
        self.0.enter(50 - text.len().min(50) as u64).await;
        if text == "fail" {
            return Err(ChainError::Other("boom".into()));
        }
        Ok(GenerateResult::from_text(text.to_uppercase()).with_tokens(TokenUsage::new(2, 1)))
    }
}

/// Echoes the last message; fails on "fail".
struct EchoLlm(Arc<Gauge>);

#[async_trait]
impl Llm for EchoLlm {
    async fn generate(&self, messages: &[Message]) -> Result<GenerateResult, LlmError> {
        let text = messages.last().map(Message::text).unwrap_or_default();
        self.0.enter(10).await;
        if text == "fail" {
            return Err(LlmError::invalid_response("bad"));
        }
        Ok(GenerateResult::from_text(text))
    }

    async fn generate_with_tools(
        &self,
        messages: &[Message],
        tools: &[FunctionDefinition],
        tool_choice: Option<ToolChoice>,
    ) -> Result<GenerateResult, LlmError> {
        self.0.calls.fetch_add(1, Ordering::SeqCst);
        let names: Vec<&str> = tools.iter().map(|t| t.name.as_str()).collect();
        Ok(GenerateResult::from_text(format!(
            "{}|{}|{:?}",
            messages.len(),
            names.join(","),
            tool_choice
        )))
    }
}

/// Reads `key` from its input and appends "!".
struct Suffix {
    key: &'static str,
    out: &'static str,
}

#[async_trait]
impl Chain for Suffix {
    async fn call(&self, input: PromptArgs) -> Result<GenerateResult, ChainError> {
        let text = input
            .get(self.key)
            .and_then(Value::as_str)
            .ok_or_else(|| ChainError::MissingVariable(self.key.into()))?;
        Ok(GenerateResult::from_text(format!("{text}!")).with_tokens(TokenUsage::new(10, 5)))
    }

    async fn stream(&self, input: PromptArgs) -> Result<ChainStream, ChainError> {
        let text = self.invoke(input).await?;
        Ok(Box::pin(stream::iter([
            Ok(StreamData::chunk(text)),
            Ok(StreamData::done()),
        ])))
    }

    fn input_keys(&self) -> Vec<String> {
        vec![self.key.into()]
    }

    fn output_keys(&self) -> Vec<String> {
        vec![self.out.into(), "generate_result".into()]
    }
}

fn gauge() -> Arc<Gauge> {
    Arc::new(Gauge::default())
}

// ── batch ───────────────────────────────────────────────────────────────────

#[tokio::test(start_paused = true)]
async fn chain_batch_keeps_order_and_collects_errors() {
    let g = gauge();
    let inputs = ["a", "fail", "ccc", "dd"]
        .iter()
        .map(|s| prompt_args! { "input" => s })
        .collect();
    let out = Upper(g.clone()).batch(inputs).await;
    assert_eq!(out.len(), 4);
    assert_eq!(out[0].as_ref().unwrap().generation, "A");
    assert!(out[1].is_err());
    assert_eq!(out[2].as_ref().unwrap().generation, "CCC");
    assert_eq!(out[3].as_ref().unwrap().generation, "DD");
    assert_eq!(g.calls.load(Ordering::SeqCst), 4);
}

#[tokio::test(start_paused = true)]
async fn chain_batch_bounds_concurrency() {
    let g = gauge();
    let inputs: Vec<_> = (0..40)
        .map(|i| prompt_args! { "input" => i.to_string() })
        .collect();
    let out = Upper(g.clone()).batch(inputs.clone()).await;
    assert!(out.iter().all(Result::is_ok));
    assert_eq!(
        g.peak.load(Ordering::SeqCst),
        rune_chain_core::DEFAULT_BATCH_CONCURRENCY
    );

    let g = gauge();
    Upper(g.clone())
        .batch_with_concurrency(inputs.clone(), 3)
        .await;
    assert_eq!(g.peak.load(Ordering::SeqCst), 3);

    // Zero means one at a time, not a hang.
    let g = gauge();
    let out = Upper(g.clone()).batch_with_concurrency(inputs, 0).await;
    assert_eq!(out.len(), 40);
    assert_eq!(g.peak.load(Ordering::SeqCst), 1);
}

#[tokio::test(start_paused = true)]
async fn chain_batch_of_nothing_is_empty() {
    assert!(Upper(gauge()).batch(Vec::new()).await.is_empty());
}

#[tokio::test(start_paused = true)]
async fn llm_batch_keeps_order_and_bounds_concurrency() {
    let g = gauge();
    let inputs: Vec<Vec<Message>> = ["x", "fail", "z"]
        .iter()
        .map(|s| vec![Message::human(*s)])
        .collect();
    let llm = Arc::new(EchoLlm(g.clone()));
    let out = llm.batch_with_concurrency(&inputs, 2).await;
    assert_eq!(out[0].as_ref().unwrap().generation, "x");
    assert!(out[1].is_err());
    assert_eq!(out[2].as_ref().unwrap().generation, "z");
    assert_eq!(g.peak.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn arc_forwards_overridden_batch() {
    struct Native;
    #[async_trait]
    impl Llm for Native {
        async fn generate(&self, _: &[Message]) -> Result<GenerateResult, LlmError> {
            Ok(GenerateResult::from_text("single"))
        }
        async fn batch(&self, inputs: &[Vec<Message>]) -> Vec<Result<GenerateResult, LlmError>> {
            inputs
                .iter()
                .map(|_| Ok(GenerateResult::from_text("native")))
                .collect()
        }
    }
    let llm: Arc<dyn Llm> = Arc::new(Native);
    let out = llm.batch(&[vec![Message::human("a")]]).await;
    assert_eq!(out[0].as_ref().unwrap().generation, "native");
}

// ── pipe ────────────────────────────────────────────────────────────────────

#[tokio::test(start_paused = true)]
async fn pipe_feeds_primary_output_and_sums_usage() {
    let chain = Upper(gauge()).pipe(Suffix {
        key: "output",
        out: "final",
    });
    let out = chain.call(prompt_args! { "input" => "hi" }).await.unwrap();
    assert_eq!(out.generation, "HI!");
    assert_eq!(out.tokens.unwrap().total_tokens, 18);
    assert_eq!(chain.primary_output_key(), "final");
    assert_eq!(chain.output_keys(), ["output", "final", "generate_result"]);
    assert_eq!(chain.input_keys(), Vec::<String>::new());

    let map = chain
        .execute(prompt_args! { "input" => "hi" })
        .await
        .unwrap();
    assert_eq!(map["output"], "HI");
    assert_eq!(map["final"], "HI!");
    assert_eq!(map["generate_result"]["generation"], "HI!");
    assert_eq!(map["generate_result"]["tokens"]["total_tokens"], 18);
}

#[tokio::test(start_paused = true)]
async fn pipe_as_renames_and_streams_second_step() {
    let chain = Upper(gauge()).pipe_as(
        Suffix {
            key: "question",
            out: "answer",
        },
        "question",
    );
    assert_eq!(
        chain.invoke(prompt_args! { "input" => "q" }).await.unwrap(),
        "Q!"
    );
    assert!(!chain.input_keys().contains(&"question".to_string()));

    let chunks: Vec<_> = chain
        .stream(prompt_args! { "input" => "q" })
        .await
        .unwrap()
        .collect()
        .await;
    assert_eq!(chunks[0].as_ref().unwrap().content, "Q!");
}

#[tokio::test(start_paused = true)]
async fn pipe_stops_on_first_error() {
    let g = gauge();
    let chain = Upper(g.clone()).pipe(Upper(g.clone()));
    assert!(
        chain
            .call(prompt_args! { "input" => "fail" })
            .await
            .is_err()
    );
    assert_eq!(g.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test(start_paused = true)]
async fn pipe_keeps_unrelated_inputs_and_missing_key_errors() {
    // The second step reads a key nobody wrote.
    let chain = Upper(gauge()).pipe(Suffix {
        key: "nope",
        out: "x",
    });
    let err = chain
        .call(prompt_args! { "input" => "a" })
        .await
        .unwrap_err();
    assert!(matches!(err, ChainError::MissingVariable(k) if k == "nope"));
    assert_eq!(chain.input_keys(), ["nope"]);

    // Original input survives into the second step.
    let chain = Upper(gauge()).pipe(Suffix {
        key: "input",
        out: "x",
    });
    assert_eq!(
        chain.invoke(prompt_args! { "input" => "a" }).await.unwrap(),
        "a!"
    );
}

// ── bind_tools ──────────────────────────────────────────────────────────────

#[tokio::test]
async fn bind_tools_routes_generate_through_tools() {
    let llm = EchoLlm(gauge())
        .bind_tools([
            FunctionDefinition::single_input("search", "s"),
            FunctionDefinition::single_input("calc", "c"),
        ])
        .with_tool_choice(ToolChoice::Required);
    assert_eq!(llm.tools().len(), 2);
    let msgs = [Message::human("hi")];

    let out = llm.generate(&msgs).await.unwrap();
    assert_eq!(out.generation, "1|search,calc|Some(Required)");

    // Explicit tools win.
    let out = llm
        .generate_with_tools(
            &msgs,
            &[FunctionDefinition::single_input("other", "o")],
            None,
        )
        .await
        .unwrap();
    assert_eq!(out.generation, "1|other|None");

    // No explicit tools: bound ones, caller's choice first.
    let out = llm
        .generate_with_tools(&msgs, &[], Some(ToolChoice::Auto))
        .await
        .unwrap();
    assert_eq!(out.generation, "1|search,calc|Some(Auto)");

    // Structured output adds a system prompt and still sends the tools.
    let out = llm
        .generate_structured(&msgs, &rune_chain_core::ResponseFormat::JsonObject)
        .await
        .unwrap();
    assert_eq!(out.generation, "2|search,calc|Some(Required)");
}

// ── callbacks ───────────────────────────────────────────────────────────────

#[derive(Default)]
struct Recorder(Mutex<Vec<String>>);

impl Recorder {
    fn push(&self, s: String) {
        self.0.lock().unwrap().push(s);
    }
    fn take(&self) -> Vec<String> {
        std::mem::take(&mut *self.0.lock().unwrap())
    }
}

impl CallbackHandler for Recorder {
    fn on_llm_start(&self, e: &LlmStart<'_>) {
        self.push(format!("llm_start {} {:?}", e.run_id, e));
    }
    fn on_llm_end(&self, e: &LlmEnd<'_>) {
        self.push(format!("llm_end {} {:?}", e.run_id, e));
    }
    fn on_llm_error(&self, e: &LlmFailure<'_>) {
        self.push(format!("llm_error {} {:?}", e.run_id, e));
    }
    fn on_chain_start(&self, e: &ChainStart<'_>) {
        self.push(format!("chain_start {} {:?}", e.run_id, e));
    }
    fn on_chain_end(&self, e: &ChainEnd<'_>) {
        self.push(format!("chain_end {} {} {:?}", e.run_id, e.output, e));
    }
    fn on_chain_error(&self, e: &ChainFailure<'_>) {
        self.push(format!("chain_error {} {:?}", e.run_id, e));
    }
    fn on_tool_start(&self, e: &ToolStart<'_>) {
        self.push(format!("tool_start {} {:?}", e.run_id, e));
    }
    fn on_tool_end(&self, e: &ToolEnd<'_>) {
        self.push(format!("tool_end {} {:?}", e.run_id, e));
    }
    fn on_tool_error(&self, e: &ToolFailure<'_>) {
        self.push(format!("tool_error {} {:?}", e.run_id, e));
    }
}

fn run_id(event: &str) -> &str {
    event.split(' ').nth(1).unwrap()
}

const SECRET: &str = "s3cret-prompt";

#[tokio::test(start_paused = true)]
async fn llm_callbacks_fire_without_leaking_prompts() {
    let rec = Arc::new(Recorder::default());
    let llm = EchoLlm(gauge()).with_callbacks(rec.clone());

    llm.generate(&[Message::human(SECRET)]).await.unwrap();
    llm.generate(&[Message::human("fail")]).await.unwrap_err();
    let events = rec.take();
    assert_eq!(events.len(), 4, "{events:?}");
    assert!(events[0].starts_with("llm_start") && events[1].starts_with("llm_end"));
    assert!(events[2].starts_with("llm_start") && events[3].starts_with("llm_error"));
    assert_eq!(run_id(&events[0]), run_id(&events[1]));
    assert_ne!(run_id(&events[0]), run_id(&events[2]));
    assert!(events.iter().all(|e| !e.contains(SECRET)), "{events:?}");
    assert!(events[3].contains("InvalidResponse"));

    // Streaming isn't supported by this model: start + error.
    assert!(llm.stream(&[Message::human("x")]).await.is_err());
    let events = rec.take();
    assert!(events[0].contains("Stream") && events[1].starts_with("llm_error"));
}

#[tokio::test(start_paused = true)]
async fn chain_callbacks_report_final_answer() {
    let rec = Arc::new(Recorder::default());
    let chain = Upper(gauge()).with_callbacks(rec.clone());

    chain
        .invoke(prompt_args! { "input" => SECRET })
        .await
        .unwrap();
    chain
        .execute(prompt_args! { "input" => "ab" })
        .await
        .unwrap();
    chain
        .call(prompt_args! { "input" => "fail" })
        .await
        .unwrap_err();
    let events = rec.take();
    assert_eq!(events.len(), 6, "{events:?}");
    assert!(events[1].starts_with(&format!("chain_end {} S3CRET-PROMPT", run_id(&events[0]))));
    assert!(events[3].contains(" AB "));
    assert!(events[5].starts_with("chain_error") && events[5].contains("other"));
    // Only the explicit `e.output` above may show the answer; Debug doesn't.
    assert!(events[0].contains("input_keys: [\"input\"]"));
    assert!(!events[0].contains(SECRET));
}

struct Shout;

#[async_trait]
impl Tool for Shout {
    fn name(&self) -> &str {
        "shout"
    }
    fn description(&self) -> &str {
        "Uppercases"
    }
    async fn run(&self, input: &str) -> Result<String, ToolError> {
        if input.is_empty() {
            return Err(ToolError::InvalidInput(SECRET.into()));
        }
        Ok(input.to_uppercase())
    }
}

#[tokio::test]
async fn tool_callbacks_fire() {
    let rec = Arc::new(Recorder::default());
    let tool = Shout.with_callbacks(rec.clone());
    assert_eq!(tool.name(), "shout");
    assert_eq!(tool.run(SECRET).await.unwrap(), SECRET.to_uppercase());
    tool.run("").await.unwrap_err();
    let events = rec.take();
    assert_eq!(events.len(), 4);
    assert!(events[0].starts_with("tool_start") && events[0].contains("\"shout\""));
    assert!(events[1].starts_with("tool_end"));
    assert!(events[3].starts_with("tool_error"));
    let all = events.join(" ").to_lowercase();
    assert!(!all.contains(SECRET), "{all}");
}

#[tokio::test]
async fn several_handlers_all_fire() {
    let a = Arc::new(Recorder::default());
    let b = Arc::new(Recorder::default());
    let both: Vec<Arc<dyn CallbackHandler>> = vec![a.clone(), b.clone()];
    let tool = Shout.with_callbacks(Arc::new(both));
    tool.run("x").await.unwrap();
    assert_eq!(a.take().len(), 2);
    assert_eq!(b.take().len(), 2);
}

// ── cache ───────────────────────────────────────────────────────────────────

#[tokio::test(start_paused = true)]
async fn cache_serves_repeats_and_skips_errors() {
    let g = gauge();
    let cache = Arc::new(InMemoryLlmCache::new(10));
    let llm = EchoLlm(g.clone()).with_cache(cache.clone());

    let hi = [Message::human("hi")];
    assert_eq!(llm.generate(&hi).await.unwrap().generation, "hi");
    assert_eq!(llm.generate(&hi).await.unwrap().generation, "hi");
    assert_eq!(g.calls.load(Ordering::SeqCst), 1);

    llm.generate(&[Message::human("ho")]).await.unwrap();
    assert_eq!(g.calls.load(Ordering::SeqCst), 2);

    llm.generate(&[Message::human("fail")]).await.unwrap_err();
    llm.generate(&[Message::human("fail")]).await.unwrap_err();
    assert_eq!(g.calls.load(Ordering::SeqCst), 4);
    assert_eq!(cache.len(), 2);

    // Tool calls and structured output get their own entries.
    let tools = [FunctionDefinition::single_input("t", "d")];
    llm.generate_with_tools(&hi, &tools, None).await.unwrap();
    llm.generate_with_tools(&hi, &tools, None).await.unwrap();
    llm.generate_with_tools(&hi, &[], None).await.unwrap();
    assert_eq!(g.calls.load(Ordering::SeqCst), 6);
    assert_eq!(cache.len(), 4);

    cache.clear();
    assert!(cache.is_empty());
}

#[tokio::test(start_paused = true)]
async fn cache_namespaces_keep_models_apart() {
    let g = gauge();
    let cache: Arc<dyn LlmCache> = Arc::new(InMemoryLlmCache::new(10));
    let a = EchoLlm(g.clone()).with_cache(cache.clone()).namespace("a");
    let b = EchoLlm(g.clone()).with_cache(cache).namespace("b");
    let hi = [Message::human("hi")];
    a.generate(&hi).await.unwrap();
    b.generate(&hi).await.unwrap();
    a.generate(&hi).await.unwrap();
    assert_eq!(g.calls.load(Ordering::SeqCst), 2);
}

fn key(text: &str) -> CacheKey {
    CacheKey::new("", &[Message::human(text)], &[], None, None)
}

#[test]
fn lru_evicts_least_recently_used() {
    let cache = InMemoryLlmCache::new(2);
    cache.put(key("a"), GenerateResult::from_text("A"));
    cache.put(key("b"), GenerateResult::from_text("B"));
    assert!(cache.get(&key("a")).is_some()); // a is now newer than b
    cache.put(key("c"), GenerateResult::from_text("C"));
    assert_eq!(cache.len(), 2);
    assert!(cache.get(&key("b")).is_none());
    assert!(cache.get(&key("a")).is_some());
    assert!(cache.get(&key("c")).is_some());

    // Overwriting keeps the size.
    cache.put(key("c"), GenerateResult::from_text("C2"));
    assert_eq!(cache.len(), 2);
    assert_eq!(cache.get(&key("c")).unwrap().generation, "C2");
}

#[test]
fn lru_respects_zero_capacity_and_entry_limit() {
    let cache = InMemoryLlmCache::new(0);
    cache.put(key("a"), GenerateResult::from_text("A"));
    assert!(cache.is_empty());

    let cache = InMemoryLlmCache::new(10).max_entry_bytes(200);
    cache.put(key("a"), GenerateResult::from_text("x".repeat(150)));
    cache.put(key(&"y".repeat(150)), GenerateResult::from_text("A"));
    assert!(cache.is_empty());
    cache.put(key("a"), GenerateResult::from_text("ok"));
    assert_eq!(cache.len(), 1);
}

#[test]
fn lru_stays_consistent_under_churn() {
    let cache = InMemoryLlmCache::new(16);
    for i in 0..1_000 {
        let k = key(&(i % 37).to_string());
        if cache.get(&k).is_none() {
            cache.put(k, GenerateResult::from_text(i.to_string()));
        }
        assert!(cache.len() <= 16);
    }
}

#[test]
fn cache_key_is_stable_and_private() {
    let k = key(SECRET);
    assert_eq!(k.stable_hash(), key(SECRET).stable_hash());
    assert_ne!(k.stable_hash(), key("other").stable_hash());
    assert!(!format!("{k:?}").contains(SECRET));
    // Pinned so a serialisation change that would invalidate external
    // caches is noticed.
    assert_eq!(
        std::str::from_utf8(key("hi").as_bytes()).unwrap(),
        r#"{"ns":"","messages":[{"role":"human","content":"hi"}],"tools":[],"tool_choice":null,"format":null}"#
    );

    let tools = [FunctionDefinition::single_input("t", "d")];
    let with_tools = CacheKey::new("", &[Message::human("hi")], &tools, None, None);
    assert_ne!(with_tools, key("hi"));
}

// ── timeout and retry ───────────────────────────────────────────────────────

#[cfg(feature = "tokio")]
mod resilience {
    use super::*;
    use rune_chain_core::{LlmErrorKind, MAX_RETRY_AFTER};
    use tokio::time::Instant;

    /// Fails with the scripted errors, then answers "ok".
    struct Flaky {
        errors: Mutex<Vec<LlmError>>,
        calls: AtomicUsize,
        delay: Duration,
    }

    impl Flaky {
        fn new(errors: Vec<LlmError>) -> Self {
            Self {
                errors: Mutex::new(errors),
                calls: AtomicUsize::new(0),
                delay: Duration::ZERO,
            }
        }

        fn next(&self) -> Result<GenerateResult, LlmError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let mut errors = self.errors.lock().unwrap();
            if errors.is_empty() {
                Ok(GenerateResult::from_text("ok"))
            } else {
                Err(errors.remove(0))
            }
        }
    }

    #[async_trait]
    impl Llm for Flaky {
        async fn generate(&self, _: &[Message]) -> Result<GenerateResult, LlmError> {
            tokio::time::sleep(self.delay).await;
            self.next()
        }
    }

    struct FlakyChain(Arc<Flaky>);

    #[async_trait]
    impl Chain for FlakyChain {
        async fn call(&self, _: PromptArgs) -> Result<GenerateResult, ChainError> {
            Ok(self.0.next()?)
        }
    }

    fn rate_limited() -> LlmError {
        LlmError::from_status(429, "slow down")
    }

    #[tokio::test(start_paused = true)]
    async fn timeout_fires_only_when_slow() {
        let mut slow = Flaky::new(vec![]);
        slow.delay = Duration::from_secs(5);
        let llm = slow.with_timeout(Duration::from_secs(1));
        let err = llm.generate(&[]).await.unwrap_err();
        assert_eq!(err.kind(), LlmErrorKind::Timeout);

        let mut fast = Flaky::new(vec![]);
        fast.delay = Duration::from_millis(10);
        let llm = fast.with_timeout(Duration::from_secs(1));
        assert_eq!(llm.generate(&[]).await.unwrap().generation, "ok");
    }

    #[tokio::test(start_paused = true)]
    async fn chain_timeout_is_an_llm_timeout() {
        struct Slow;
        #[async_trait]
        impl Chain for Slow {
            async fn call(&self, _: PromptArgs) -> Result<GenerateResult, ChainError> {
                tokio::time::sleep(Duration::from_secs(5)).await;
                Ok(GenerateResult::from_text("late"))
            }
        }
        let err = Slow
            .with_timeout(Duration::from_millis(100))
            .call(PromptArgs::new())
            .await
            .unwrap_err();
        assert!(matches!(err, ChainError::LlmError(e) if e.kind() == LlmErrorKind::Timeout));
    }

    #[tokio::test(start_paused = true)]
    async fn retry_recovers_with_backoff() {
        let llm = Flaky::new(vec![rate_limited(), LlmError::timeout("t")])
            .with_retry(3)
            .initial_delay(Duration::from_millis(100));
        let start = Instant::now();
        assert_eq!(llm.generate(&[]).await.unwrap().generation, "ok");
        // 100 ms then 200 ms.
        assert_eq!(start.elapsed(), Duration::from_millis(300));
    }

    #[tokio::test(start_paused = true)]
    async fn retry_gives_up() {
        // Not retryable.
        let inner = Arc::new(Flaky::new(vec![LlmError::invalid_response("x")]));
        let err = inner.clone().with_retry(5).generate(&[]).await.unwrap_err();
        assert_eq!(err.kind(), LlmErrorKind::InvalidResponse);
        assert_eq!(inner.calls.load(Ordering::SeqCst), 1);

        // Out of retries: the last error comes back.
        let inner = Arc::new(Flaky::new(vec![rate_limited(); 5]));
        let err = inner.clone().with_retry(2).generate(&[]).await.unwrap_err();
        assert!(err.is_rate_limit());
        assert_eq!(inner.calls.load(Ordering::SeqCst), 3);

        // A retry-after hint beyond the cap ends it at once.
        let long = rate_limited().with_retry_after(MAX_RETRY_AFTER + Duration::from_secs(1));
        let inner = Arc::new(Flaky::new(vec![long]));
        let start = Instant::now();
        inner.clone().with_retry(5).generate(&[]).await.unwrap_err();
        assert_eq!(inner.calls.load(Ordering::SeqCst), 1);
        assert_eq!(start.elapsed(), Duration::ZERO);
    }

    #[tokio::test(start_paused = true)]
    async fn retry_honours_retry_after_and_caps_backoff() {
        let hint = rate_limited().with_retry_after(Duration::from_secs(3));
        let llm = Flaky::new(vec![hint])
            .with_retry(1)
            .initial_delay(Duration::from_millis(10));
        let start = Instant::now();
        llm.generate(&[]).await.unwrap();
        assert_eq!(start.elapsed(), Duration::from_secs(3));

        // Huge retry counts don't overflow the backoff.
        let llm = Flaky::new(vec![rate_limited(); 40])
            .with_retry(u32::MAX)
            .initial_delay(Duration::from_secs(1))
            .max_delay(Duration::from_secs(2));
        let start = Instant::now();
        llm.generate(&[]).await.unwrap();
        assert_eq!(start.elapsed(), Duration::from_secs(1 + 39 * 2));
    }

    #[tokio::test(start_paused = true)]
    async fn chain_retry_only_retries_llm_errors() {
        let inner = Arc::new(Flaky::new(vec![rate_limited()]));
        let out = FlakyChain(inner.clone())
            .with_retry(2)
            .invoke(PromptArgs::new())
            .await;
        assert_eq!(out.unwrap(), "ok");
        assert_eq!(inner.calls.load(Ordering::SeqCst), 2);

        struct Missing(AtomicUsize);
        #[async_trait]
        impl Chain for Missing {
            async fn call(&self, _: PromptArgs) -> Result<GenerateResult, ChainError> {
                self.0.fetch_add(1, Ordering::SeqCst);
                Err(ChainError::MissingVariable("x".into()))
            }
        }
        let m = Arc::new(Missing(AtomicUsize::new(0)));
        m.clone()
            .with_retry(3)
            .call(PromptArgs::new())
            .await
            .unwrap_err();
        assert_eq!(m.0.load(Ordering::SeqCst), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn combinators_stack() {
        let rec = Arc::new(Recorder::default());
        let cache = Arc::new(InMemoryLlmCache::new(4));
        let inner = Arc::new(Flaky::new(vec![rate_limited()]));
        let llm = inner
            .clone()
            .with_retry(2)
            .with_timeout(Duration::from_secs(30))
            .with_cache(cache)
            .with_callbacks(rec.clone());
        llm.generate(&[Message::human("q")]).await.unwrap();
        llm.generate(&[Message::human("q")]).await.unwrap();
        assert_eq!(inner.calls.load(Ordering::SeqCst), 2);
        assert_eq!(rec.take().len(), 4);
    }

    #[allow(dead_code)]
    fn assert_send_sync() {
        fn check<T: Send + Sync>() {}
        check::<rune_chain_core::WithRetry<Flaky>>();
        check::<rune_chain_core::WithTimeout<Flaky>>();
    }
}
