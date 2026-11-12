# rune-otel-genai

> OpenTelemetry GenAI semantic-convention spans for rune-chain LLM calls, tool executions and agents — model, tokens, cost and errors

[![crates.io](https://img.shields.io/crates/v/rune-otel-genai)](https://crates.io/crates/rune-otel-genai)
[![docs.rs](https://img.shields.io/docsrs/rune-otel-genai)](https://docs.rs/rune-otel-genai)
[![license](https://img.shields.io/crates/l/rune-otel-genai)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

Wrap a `rune-chain` model or tool and every call becomes a span that
follows the [OpenTelemetry GenAI semantic conventions] (semconv v1.40.0; the
GenAI conventions moved to their own repository in v1.41.0 with the same
names).

| Span                  | Kind     | Attributes |
| --------------------- | -------- | ---------- |
| `chat {model}`        | client   | `gen_ai.operation.name`, `gen_ai.provider.name`, `gen_ai.request.model`, `gen_ai.request.{max_tokens,temperature,top_p}`, `gen_ai.conversation.id`, `gen_ai.usage.{input,output}_tokens`, `gen_ai.usage.cache_read.input_tokens`, `gen_ai.usage.cache_creation.input_tokens`, `gen_ai.usage.reasoning.output_tokens`, `gen_ai.response.finish_reasons`, `server.{address,port}`, `error.type`, `http.response.status_code` |
| `execute_tool {name}` | internal | `gen_ai.tool.{name,description,type}`, `gen_ai.tool.call.id`, `error.type` |
| `invoke_agent {name}` | internal | `gen_ai.agent.{name,id,description}` |

Notes on the conventions:

- The provider goes in `gen_ai.provider.name`. The deprecated
  `gen_ai.system` is only written if you ask for it
  (`GenAiConfig::with_legacy_system(true)`).
- `gen_ai.response.finish_reasons` is a string array in the spec. `tracing`
  fields can't hold arrays, so the single reason is written as a string.
- `error.type` comes from `LlmError::kind()` (`rate_limit`, `overloaded`,
  `context_length_exceeded`, ...); the HTTP status, when there was one, goes
  in `http.response.status_code`.

Things the conventions don't cover use `rune.gen_ai.*`:
`rune.gen_ai.usage.cost_usd` (from `rune_chain_core::Pricing`, cache reads
and writes at their own rates), `rune.gen_ai.usage.estimated` (counts were
estimated locally because the provider sent none, e.g. streams) and
`rune.gen_ai.response.tool_calls`. Each tool call the model asks for is also
a `gen_ai.tool.call` span event.

The spans are plain `tracing` spans with `otel.name` / `otel.kind` /
`otel.status_code` fields, so the crate itself doesn't depend on
OpenTelemetry. Export them with a `tracing-opentelemetry` layer.

## Metrics

Set a sink with `GenAiConfig::with_metrics` to get one measurement per call.
With the `opentelemetry` feature, `OtelMetrics` records the two histograms
the conventions define, with their units and advised buckets:

- `gen_ai.client.operation.duration` (`s`)
- `gen_ai.client.token.usage` (`{token}`, split by `gen_ai.token.type`)

Token usage is only recorded when the provider reported it. Any closure
`Fn(&OperationMetrics)` works as a sink too.

## Prompt and completion content

Content capture is **off** by default. Prompts and completions often hold
personal data or secrets, so turn it on only where your tracing backend may
store them, and use a `ContentPolicy`:

```rust
use rune_otel_genai::{ContentPolicy, GenAiConfig};

let policy = ContentPolicy::capture()
    .with_max_chars(2_000)  // per text value; longer ones get "…[truncated]"
    .with_max_messages(10)  // only the last 10 input messages
    .with_redactor(|text| text.replace("internal-host", "[HOST]"));
let config = GenAiConfig::new("openai", "gpt-4o").with_content_policy(policy);
```

Redaction runs before truncation, so a secret that straddles the cap is
never half-recorded. With the `redact` feature,
`ContentPolicy::with_default_redaction()` uses `rune-redact` (emails, phone
and card numbers, API keys and other credentials). `TracedTool` takes the
same policy for tool arguments and results.

## Installation

```toml
[dependencies]
rune-otel-genai = { version = "0.1", features = ["opentelemetry"] }
```

## Usage

```rust,ignore
use std::sync::Arc;

use opentelemetry::metrics::MeterProvider as _;
use opentelemetry::trace::TracerProvider as _;
use rune_chain_core::{Llm, Message, Pricing, Tool};
use rune_otel_genai::{GenAiConfig, OtelMetrics, TracedLlm, TracedTool, agent_span};
use tracing::Instrument;
use tracing_subscriber::layer::SubscriberExt;

async fn run(model: impl Llm, tool: impl Tool) -> Result<(), Box<dyn std::error::Error>> {
    // Once, at startup: any OpenTelemetry tracer and meter provider.
    let tracer_provider = opentelemetry_sdk::trace::SdkTracerProvider::builder().build();
    let meter_provider = opentelemetry_sdk::metrics::SdkMeterProvider::default();
    tracing::subscriber::set_global_default(
        tracing_subscriber::registry()
            .with(tracing_opentelemetry::layer().with_tracer(tracer_provider.tracer("app"))),
    )?;

    let llm = TracedLlm::new(
        model,
        GenAiConfig::new("anthropic", "claude-sonnet-4-6")
            .with_pricing(Pricing::per_mtok(3_000_000, 15_000_000))
            .with_max_tokens(1024)
            .with_metrics(Arc::new(OtelMetrics::new(&meter_provider.meter("app")))),
    );
    let tool = TracedTool::new(tool);

    // Spans: invoke_agent calculator > chat claude-sonnet-4-6, execute_tool ...
    async {
        let reply = llm
            .generate_with_tools(&[Message::human("2 + 2?")], &[tool.function_definition()], None)
            .await?;
        for call in &reply.tool_calls {
            tool.run_call(call).await?;
        }
        Ok::<_, Box<dyn std::error::Error>>(())
    }
    .instrument(agent_span("calculator", None, None))
    .await
}
```

`TracedLlm` and `TracedTool` can be stacked with other wrappers, for example
`rune-chain-usage`'s `MeteredLlm` for budgets.

## License

MIT
