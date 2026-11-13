//! End to end: rune-chain calls traced by this crate and exported through
//! `tracing-opentelemetry` into an in-memory exporter. No network.

#![allow(clippy::unwrap_used, clippy::panic, reason = "test helpers")]

use std::pin::Pin;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use futures::{Stream, StreamExt, stream};
use opentelemetry::trace::{SpanKind, Status, TracerProvider as _};
use opentelemetry_sdk::trace::{InMemorySpanExporter, SdkTracerProvider, SpanData};
use rune_chain_core::{
    FinishReason, FunctionDefinition, GenerateResult, Llm, LlmError, Message, Pricing, StreamData,
    TokenUsage, Tool, ToolCall, ToolChoice, ToolError,
};
use rune_otel_genai::{
    ContentPolicy, GenAiConfig, OperationMetrics, TracedLlm, TracedTool, agent_span, attr,
};
use tracing::Instrument;
use tracing_subscriber::layer::SubscriberExt;

/// A scripted model: asks for a tool on the first tool-enabled call,
/// reports no usage on plain calls, and streams two chunks.
struct Scripted;

#[async_trait]
impl Llm for Scripted {
    async fn generate(&self, _: &[Message]) -> Result<GenerateResult, LlmError> {
        Ok(GenerateResult::from_text("The answer is 4."))
    }

    async fn generate_with_tools(
        &self,
        _: &[Message],
        _: &[FunctionDefinition],
        _: Option<ToolChoice>,
    ) -> Result<GenerateResult, LlmError> {
        Ok(GenerateResult::from_text("")
            .with_tool_calls(vec![ToolCall::new("call_1", "add", r#"{"a":2,"b":2}"#)])
            .with_tokens(
                TokenUsage::new(1_000, 200)
                    .with_cache_read_tokens(400)
                    .with_reasoning_tokens(50),
            )
            .with_finish_reason(FinishReason::ToolCalls))
    }

    async fn stream(
        &self,
        _: &[Message],
    ) -> Result<Pin<Box<dyn Stream<Item = Result<StreamData, LlmError>> + Send>>, LlmError> {
        Ok(Box::pin(stream::iter(vec![
            Ok(StreamData::chunk("Hello ")),
            Ok(StreamData::chunk("world")),
            Ok(StreamData::done()),
        ])))
    }
}

struct Failing;

#[async_trait]
impl Llm for Failing {
    async fn generate(&self, _: &[Message]) -> Result<GenerateResult, LlmError> {
        Err(LlmError::provider("overloaded"))
    }
}

struct Add;

#[async_trait]
impl Tool for Add {
    fn name(&self) -> &'static str {
        "add"
    }
    fn description(&self) -> &'static str {
        "Adds two integers."
    }
    async fn run(&self, input: &str) -> Result<String, ToolError> {
        let v: serde_json::Value =
            serde_json::from_str(input).map_err(|e| ToolError::InvalidInput(e.to_string()))?;
        Ok((v["a"].as_i64().unwrap_or(0) + v["b"].as_i64().unwrap_or(0)).to_string())
    }
}

fn get(span: &SpanData, key: &str) -> Option<String> {
    span.attributes
        .iter()
        .find(|kv| kv.key.as_str() == key)
        .map(|kv| kv.value.as_str().into_owned())
}

/// Runs `scenario` (created inside the subscriber, so its spans are
/// recorded) and returns the exported spans.
fn run_and_export<F: std::future::Future<Output = ()>>(
    scenario: impl FnOnce() -> F,
) -> Vec<SpanData> {
    let exporter = InMemorySpanExporter::default();
    let provider = SdkTracerProvider::builder()
        .with_simple_exporter(exporter.clone())
        .build();
    let subscriber = tracing_subscriber::registry()
        .with(tracing_opentelemetry::layer().with_tracer(provider.tracer("test")));
    tracing::subscriber::with_default(subscriber, || tokio_test::block_on(scenario()));
    provider.force_flush().unwrap();
    let spans = exporter.get_finished_spans().unwrap();
    provider.shutdown().unwrap();
    spans
}

fn find<'a>(spans: &'a [SpanData], name: &str) -> &'a SpanData {
    spans.iter().find(|s| s.name == name).unwrap_or_else(|| {
        panic!(
            "no span {name:?} in {:?}",
            spans.iter().map(|s| &s.name).collect::<Vec<_>>()
        )
    })
}

#[test]
fn agent_loop_exports_genai_spans() {
    let pricing = Pricing::per_mtok(3_000_000, 15_000_000);
    let llm = TracedLlm::new(
        Scripted,
        GenAiConfig::new("anthropic", "claude-sonnet-4-6")
            .with_pricing(pricing)
            .with_max_tokens(512)
            .with_temperature(0.5)
            .with_conversation_id("conv-9")
            .with_server("api.anthropic.com", 443),
    );
    let tool = TracedTool::new(Add);

    let spans = run_and_export(|| {
        async {
            let messages = [Message::human("What is 2 + 2?")];
            let first = llm
                .generate_with_tools(&messages, &[tool.function_definition()], None)
                .await
                .unwrap();
            let output = tool.run_call(&first.tool_calls[0]).await.unwrap();
            assert_eq!(output, "4");
            llm.generate(&messages).await.unwrap();
        }
        .instrument(agent_span("calculator", Some("agent-1"), None))
    });

    let agent = find(&spans, "invoke_agent calculator");
    assert_eq!(
        get(agent, attr::GEN_AI_OPERATION_NAME).as_deref(),
        Some("invoke_agent")
    );
    assert_eq!(
        get(agent, attr::GEN_AI_AGENT_ID).as_deref(),
        Some("agent-1")
    );
    assert_eq!(agent.span_kind, SpanKind::Internal);

    let chats: Vec<&SpanData> = spans
        .iter()
        .filter(|s| s.name == "chat claude-sonnet-4-6")
        .collect();
    assert_eq!(chats.len(), 2);
    for chat in &chats {
        assert_eq!(chat.span_kind, SpanKind::Client);
        assert_eq!(chat.parent_span_id, agent.span_context.span_id());
        assert_eq!(
            get(chat, attr::GEN_AI_OPERATION_NAME).as_deref(),
            Some("chat")
        );
        assert_eq!(
            get(chat, attr::GEN_AI_PROVIDER_NAME).as_deref(),
            Some("anthropic")
        );
        assert_eq!(
            get(chat, attr::GEN_AI_REQUEST_MODEL).as_deref(),
            Some("claude-sonnet-4-6")
        );
        assert_eq!(
            get(chat, attr::GEN_AI_REQUEST_MAX_TOKENS).as_deref(),
            Some("512")
        );
        assert_eq!(
            get(chat, attr::GEN_AI_REQUEST_TEMPERATURE).as_deref(),
            Some("0.5")
        );
        assert_eq!(
            get(chat, attr::GEN_AI_CONVERSATION_ID).as_deref(),
            Some("conv-9")
        );
        assert_eq!(
            get(chat, attr::SERVER_ADDRESS).as_deref(),
            Some("api.anthropic.com")
        );
        assert_eq!(get(chat, attr::SERVER_PORT).as_deref(), Some("443"));
        // Content capture is off by default.
        assert_eq!(get(chat, attr::GEN_AI_INPUT_MESSAGES), None);
    }

    // First call: provider-reported usage, cost and one requested tool call.
    let with_tools = chats
        .iter()
        .find(|s| get(s, attr::RUNE_RESPONSE_TOOL_CALLS).as_deref() == Some("1"))
        .unwrap();
    assert_eq!(
        get(with_tools, attr::GEN_AI_USAGE_INPUT_TOKENS).as_deref(),
        Some("1000")
    );
    assert_eq!(
        get(with_tools, attr::GEN_AI_USAGE_OUTPUT_TOKENS).as_deref(),
        Some("200")
    );
    assert_eq!(
        get(with_tools, attr::RUNE_USAGE_ESTIMATED).as_deref(),
        Some("false")
    );
    assert_eq!(
        get(with_tools, attr::GEN_AI_USAGE_CACHE_READ_INPUT_TOKENS).as_deref(),
        Some("400")
    );
    assert_eq!(
        get(with_tools, attr::GEN_AI_USAGE_CACHE_CREATION_INPUT_TOKENS),
        None
    );
    assert_eq!(
        get(with_tools, attr::GEN_AI_USAGE_REASONING_OUTPUT_TOKENS).as_deref(),
        Some("50")
    );
    assert_eq!(
        get(with_tools, attr::GEN_AI_RESPONSE_FINISH_REASONS).as_deref(),
        Some("tool_call")
    );
    // Cache reads cost the input price unless set: 1000 × $3/MTok + 200 × $15/MTok = $0.006.
    let cost: f64 = get(with_tools, attr::RUNE_USAGE_COST_USD)
        .unwrap()
        .parse()
        .unwrap();
    assert!((cost - 0.006).abs() < 1e-12, "{cost}");
    assert_eq!(with_tools.events.len(), 1);
    let event = &with_tools.events[0];
    assert!(
        event
            .attributes
            .iter()
            .any(|kv| kv.key.as_str() == attr::GEN_AI_TOOL_NAME && kv.value.as_str() == "add")
    );
    assert!(event.attributes.iter().any(|kv| kv.key.as_str() == attr::GEN_AI_TOOL_CALL_ID
        && kv.value.as_str() == "call_1"));

    // Second call: no provider usage, so estimated.
    let plain = chats
        .iter()
        .find(|s| get(s, attr::RUNE_RESPONSE_TOOL_CALLS).as_deref() == Some("0"))
        .unwrap();
    assert_eq!(
        get(plain, attr::RUNE_USAGE_ESTIMATED).as_deref(),
        Some("true")
    );
    assert_eq!(get(plain, attr::GEN_AI_RESPONSE_FINISH_REASONS), None);
    assert_eq!(get(plain, attr::GEN_AI_USAGE_CACHE_READ_INPUT_TOKENS), None);
    let input: u64 = get(plain, attr::GEN_AI_USAGE_INPUT_TOKENS)
        .unwrap()
        .parse()
        .unwrap();
    assert!(input > 0);

    let tool_span = find(&spans, "execute_tool add");
    assert_eq!(tool_span.parent_span_id, agent.span_context.span_id());
    assert_eq!(
        get(tool_span, attr::GEN_AI_OPERATION_NAME).as_deref(),
        Some("execute_tool")
    );
    assert_eq!(
        get(tool_span, attr::GEN_AI_TOOL_NAME).as_deref(),
        Some("add")
    );
    assert_eq!(
        get(tool_span, attr::GEN_AI_TOOL_TYPE).as_deref(),
        Some("function")
    );
    assert_eq!(
        get(tool_span, attr::GEN_AI_TOOL_CALL_ID).as_deref(),
        Some("call_1")
    );
    assert_eq!(get(tool_span, attr::GEN_AI_TOOL_CALL_ARGUMENTS), None);
    assert_eq!(tool_span.status, Status::Unset);
}

#[test]
fn failures_set_error_type_and_status() {
    let llm = TracedLlm::new(Failing, GenAiConfig::new("openai", "gpt-x"));
    let tool = TracedTool::new(Add);
    let spans = run_and_export(|| async {
        assert!(llm.generate(&[Message::human("hi")]).await.is_err());
        assert!(tool.run("not json").await.is_err());
    });

    let chat = find(&spans, "chat gpt-x");
    assert_eq!(
        get(chat, attr::ERROR_TYPE).as_deref(),
        Some("provider_error")
    );
    assert!(
        matches!(&chat.status, Status::Error { description } if description.contains("overloaded"))
    );
    assert_eq!(get(chat, attr::GEN_AI_USAGE_INPUT_TOKENS), None);

    let tool_span = find(&spans, "execute_tool add");
    assert_eq!(
        get(tool_span, attr::ERROR_TYPE).as_deref(),
        Some("invalid_input")
    );
    assert!(matches!(tool_span.status, Status::Error { .. }));
}

#[test]
fn streams_and_content_capture() {
    let llm = TracedLlm::new(
        Scripted,
        GenAiConfig::new("ollama", "llama3")
            .with_capture_content(true)
            .with_pricing(Pricing::per_mtok(1_000_000, 1_000_000)),
    );
    let tool = TracedTool::new(Add).with_capture_content(true);
    let spans = run_and_export(|| async {
        let chunks: Vec<_> = llm
            .stream(&[Message::system("be brief"), Message::human("greet")])
            .await
            .unwrap()
            .collect()
            .await;
        assert_eq!(chunks.len(), 3);
        let call = ToolCall::new("c7", "add", r#"{"a":1,"b":2}"#);
        assert_eq!(tool.run_call(&call).await.unwrap(), "3");
    });

    let chat = find(&spans, "chat llama3");
    assert_eq!(
        get(chat, attr::RUNE_USAGE_ESTIMATED).as_deref(),
        Some("true")
    );
    assert!(
        get(chat, attr::GEN_AI_USAGE_OUTPUT_TOKENS)
            .unwrap()
            .parse::<u64>()
            .unwrap()
            > 0
    );
    assert!(get(chat, attr::RUNE_USAGE_COST_USD).is_some());
    let input: serde_json::Value =
        serde_json::from_str(&get(chat, attr::GEN_AI_INPUT_MESSAGES).unwrap()).unwrap();
    assert_eq!(input[0]["role"], "system");
    assert_eq!(input[1]["parts"][0]["content"], "greet");
    let output: serde_json::Value =
        serde_json::from_str(&get(chat, attr::GEN_AI_OUTPUT_MESSAGES).unwrap()).unwrap();
    assert_eq!(output[0]["parts"][0]["content"], "Hello world");

    let tool_span = find(&spans, "execute_tool add");
    assert_eq!(
        get(tool_span, attr::GEN_AI_TOOL_CALL_ARGUMENTS).as_deref(),
        Some(r#"{"a":1,"b":2}"#)
    );
    assert_eq!(
        get(tool_span, attr::GEN_AI_TOOL_CALL_RESULT).as_deref(),
        Some("3")
    );
}

/// What the metrics sink saw: error type, input tokens, estimated flag.
type Seen = (Option<String>, Option<u64>, bool);

struct RateLimited;

#[async_trait]
impl Llm for RateLimited {
    async fn generate(&self, _: &[Message]) -> Result<GenerateResult, LlmError> {
        Err(LlmError::from_status(429, "slow down"))
    }
}

#[test]
fn http_errors_record_status_and_kind_and_metrics() {
    let seen: Arc<Mutex<Vec<Seen>>> = Arc::default();
    let sink = Arc::clone(&seen);
    let metrics = move |m: &OperationMetrics<'_>| {
        sink.lock().unwrap().push((
            m.error_type.map(str::to_owned),
            m.input_tokens,
            m.usage_estimated,
        ));
    };
    let failing = TracedLlm::new(
        RateLimited,
        GenAiConfig::new("openai", "gpt-x")
            .with_legacy_system(true)
            .with_metrics(Arc::new(metrics.clone())),
    );
    let ok = TracedLlm::new(
        Scripted,
        GenAiConfig::new("openai", "gpt-y").with_metrics(Arc::new(metrics)),
    );
    let spans = run_and_export(|| async {
        assert!(failing.generate(&[Message::human("hi")]).await.is_err());
        ok.generate_with_tools(&[Message::human("hi")], &[], None)
            .await
            .unwrap();
    });
    let chat = find(&spans, "chat gpt-x");
    assert_eq!(get(chat, attr::ERROR_TYPE).as_deref(), Some("rate_limit"));
    assert_eq!(
        get(chat, attr::HTTP_RESPONSE_STATUS_CODE).as_deref(),
        Some("429")
    );
    assert_eq!(get(chat, attr::GEN_AI_SYSTEM).as_deref(), Some("openai"));
    assert_eq!(get(find(&spans, "chat gpt-y"), attr::GEN_AI_SYSTEM), None);
    assert_eq!(
        *seen.lock().unwrap(),
        [
            (Some("rate_limit".to_owned()), None, false),
            (None, Some(1_000), false)
        ]
    );
}

#[test]
fn captured_content_is_redacted_and_capped() {
    let policy = ContentPolicy::capture()
        .with_max_chars(12)
        .with_max_messages(2)
        .with_redactor(|t| t.replace("sk-secret", "[KEY]"));
    let llm = TracedLlm::new(
        Scripted,
        GenAiConfig::new("ollama", "llama3").with_content_policy(policy.clone()),
    );
    let tool = TracedTool::new(Add).with_content_policy(policy);
    let spans = run_and_export(|| async {
        let messages = [
            Message::system("dropped: only the last two messages are kept"),
            Message::human("my key is sk-secret"),
            Message::human("and a very long question that gets cut"),
        ];
        llm.generate(&messages).await.unwrap();
        let call = ToolCall::new("c1", "add", r#"{"a":40,"b":2, "k":"sk-secret"}"#);
        tool.run_call(&call).await.unwrap();
    });
    let chat = find(&spans, "chat llama3");
    let input: serde_json::Value =
        serde_json::from_str(&get(chat, attr::GEN_AI_INPUT_MESSAGES).unwrap()).unwrap();
    assert_eq!(input.as_array().map(Vec::len), Some(2));
    assert_eq!(input[0]["parts"][0]["content"], "my key is [K…[truncated]");
    assert_eq!(input[1]["parts"][0]["content"], "and a very l…[truncated]");
    let output: serde_json::Value =
        serde_json::from_str(&get(chat, attr::GEN_AI_OUTPUT_MESSAGES).unwrap()).unwrap();
    assert_eq!(output[0]["parts"][0]["content"], "The answer i…[truncated]");

    let tool_span = find(&spans, "execute_tool add");
    let args = get(tool_span, attr::GEN_AI_TOOL_CALL_ARGUMENTS).unwrap();
    assert!(!args.contains("sk-secret"), "{args}");
    assert_eq!(args.chars().count(), 12 + "…[truncated]".chars().count());
}

#[test]
fn long_streams_capture_a_bounded_prefix() {
    struct Long;
    #[async_trait]
    impl Llm for Long {
        async fn generate(&self, _: &[Message]) -> Result<GenerateResult, LlmError> {
            Ok(GenerateResult::from_text(""))
        }
        async fn stream(
            &self,
            _: &[Message],
        ) -> Result<Pin<Box<dyn Stream<Item = Result<StreamData, LlmError>> + Send>>, LlmError>
        {
            let chunks = (0..1_000).map(|_| Ok(StreamData::chunk("abcdefgh")));
            Ok(Box::pin(stream::iter(chunks)))
        }
    }
    let llm = TracedLlm::new(
        Long,
        GenAiConfig::new("ollama", "long")
            .with_content_policy(ContentPolicy::capture().with_max_chars(16)),
    );
    let spans = run_and_export(|| async {
        let n = llm.stream(&[]).await.unwrap().count().await;
        assert_eq!(n, 1_000);
    });
    let chat = find(&spans, "chat long");
    // 8000 characters streamed, estimated at 2000 tokens; 16 recorded.
    assert_eq!(
        get(chat, attr::GEN_AI_USAGE_OUTPUT_TOKENS).as_deref(),
        Some("2000")
    );
    let output: serde_json::Value =
        serde_json::from_str(&get(chat, attr::GEN_AI_OUTPUT_MESSAGES).unwrap()).unwrap();
    assert_eq!(
        output[0]["parts"][0]["content"],
        "abcdefghabcdefgh…[truncated]"
    );
}

#[cfg(feature = "opentelemetry")]
#[test]
fn otel_metrics_follow_the_conventions() {
    use opentelemetry::metrics::MeterProvider as _;
    use opentelemetry_sdk::metrics::data::{AggregatedMetrics, MetricData};
    use opentelemetry_sdk::metrics::{InMemoryMetricExporter, PeriodicReader, SdkMeterProvider};
    use rune_otel_genai::OtelMetrics;

    let exporter = InMemoryMetricExporter::default();
    let provider = SdkMeterProvider::builder()
        .with_reader(PeriodicReader::builder(exporter.clone()).build())
        .build();
    let llm = TracedLlm::new(
        Scripted,
        GenAiConfig::new("anthropic", "claude")
            .with_metrics(Arc::new(OtelMetrics::new(&provider.meter("test")))),
    );
    tokio_test::block_on(llm.generate_with_tools(&[Message::human("hi")], &[], None)).unwrap();
    // Estimated usage (no provider counts) records duration only.
    tokio_test::block_on(llm.generate(&[Message::human("hi")])).unwrap();
    provider.force_flush().unwrap();

    let finished = exporter.get_finished_metrics().unwrap();
    let metrics: Vec<_> = finished
        .iter()
        .flat_map(opentelemetry_sdk::metrics::data::ResourceMetrics::scope_metrics)
        .flat_map(opentelemetry_sdk::metrics::data::ScopeMetrics::metrics)
        .collect();
    let duration = metrics
        .iter()
        .find(|m| m.name() == attr::METRIC_OPERATION_DURATION)
        .unwrap();
    assert_eq!(duration.unit(), "s");
    let tokens = metrics
        .iter()
        .find(|m| m.name() == attr::METRIC_TOKEN_USAGE)
        .unwrap();
    assert_eq!(tokens.unit(), "{token}");
    let AggregatedMetrics::U64(MetricData::Histogram(hist)) = tokens.data() else {
        panic!("token usage is not a u64 histogram");
    };
    let mut sums: Vec<(String, u64, u64)> = hist
        .data_points()
        .map(|dp| {
            let kind = dp
                .attributes()
                .find(|kv| kv.key.as_str() == attr::GEN_AI_TOKEN_TYPE)
                .map(|kv| kv.value.as_str().into_owned())
                .unwrap();
            (kind, dp.count(), dp.sum())
        })
        .collect();
    sums.sort();
    assert_eq!(
        sums,
        [
            ("input".to_owned(), 1, 1_000),
            ("output".to_owned(), 1, 200)
        ]
    );
    let AggregatedMetrics::F64(MetricData::Histogram(hist)) = duration.data() else {
        panic!("duration is not an f64 histogram");
    };
    assert_eq!(
        hist.data_points()
            .map(opentelemetry_sdk::metrics::data::HistogramDataPoint::count)
            .sum::<u64>(),
        2
    );
}

#[test]
fn error_descriptions_are_redacted_and_capped() {
    struct Echo;

    #[async_trait]
    impl Tool for Echo {
        fn name(&self) -> &'static str {
            "echo"
        }
        fn description(&self) -> &'static str {
            "Rejects its input, quoting it back."
        }
        async fn run(&self, input: &str) -> Result<String, ToolError> {
            Err(ToolError::InvalidInput(format!("cannot use {input}")))
        }
    }

    struct Leaky;

    #[async_trait]
    impl Llm for Leaky {
        async fn generate(&self, _: &[Message]) -> Result<GenerateResult, LlmError> {
            Err(LlmError::provider(format!(
                "echoed sk-secret {}",
                "x".repeat(100_000)
            )))
        }
    }

    // Capture stays off: the redactor and the size cap still apply to
    // error text, which often quotes the input it choked on.
    let policy = ContentPolicy::off()
        .with_max_chars(64)
        .with_redactor(|t| t.replace("sk-secret", "[KEY]"));
    let tool = TracedTool::new(Echo).with_content_policy(policy.clone());
    let llm = TracedLlm::new(
        Leaky,
        GenAiConfig::new("openai", "gpt-x").with_content_policy(policy),
    );
    let spans = run_and_export(|| async {
        assert!(tool.run("key sk-secret").await.is_err());
        assert!(llm.generate(&[Message::human("hi")]).await.is_err());
    });
    for name in ["execute_tool echo", "chat gpt-x"] {
        let Status::Error { description } = &find(&spans, name).status else {
            panic!("{name} did not fail");
        };
        assert!(!description.contains("sk-secret"), "{description}");
        assert!(description.contains("[KEY]"), "{description}");
        assert!(description.chars().count() <= 64 + "…[truncated]".chars().count());
    }
}
