//! Accounting against recorded provider responses, served by a loopback mock
//! of each API: metered usage must equal what the provider reported, local
//! estimates must land within tolerance of it, and a budget must stop a run.
//! No test touches the network.

#![allow(clippy::unwrap_used, reason = "test helpers")]

use futures::StreamExt;
use rune_chain_anthropic::{Anthropic, models as claude};
use rune_chain_core::testing::http::{MockResponse, MockServer};
use rune_chain_core::{Cost, Llm, Message};
use rune_chain_openai::{OpenAi, models as gpt};
use rune_chain_usage::{
    Budget, MeteredLlm, Totals, UsageMeter, estimate::estimate_reply, estimate_messages,
};

macro_rules! fixture {
    ($name:literal) => {
        include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/fixtures/", $name))
    };
}

fn http() -> reqwest::Client {
    reqwest::Client::builder().no_proxy().build().unwrap()
}

/// The fixture's model, as recorded in `anthropic_messages_text.json`.
const CLAUDE_MODEL: &str = claude::CLAUDE_SONNET_4_6;

fn anthropic(server: &MockServer, meter: &UsageMeter) -> MeteredLlm<Anthropic> {
    let llm = Anthropic::new("sk-ant-test")
        .model(CLAUDE_MODEL)
        .base_url(format!("{}/", server.base_url()))
        .http_client(http());
    let pricing = claude::lookup(CLAUDE_MODEL).unwrap().pricing;
    MeteredLlm::new(llm, meter.clone(), "anthropic", CLAUDE_MODEL, pricing)
}

fn openai(server: &MockServer, meter: &UsageMeter) -> MeteredLlm<OpenAi> {
    let llm = OpenAi::new("sk-test")
        .model(gpt::GPT_4O)
        .base_url(format!("{}/v1", server.base_url()))
        .http_client(http());
    let pricing = gpt::lookup(gpt::GPT_4O).unwrap().pricing;
    MeteredLlm::new(llm, meter.clone(), "openai", gpt::GPT_4O, pricing)
}

/// Estimates are a guard rail: within 6 tokens or 30 % of the reported
/// count, whichever is looser.
fn assert_within_tolerance(what: &str, estimate: u64, reported: u64) {
    let allowed = (reported * 3 / 10).max(6);
    assert!(
        estimate.abs_diff(reported) <= allowed,
        "{what}: estimate {estimate} vs reported {reported} (allowed ±{allowed})"
    );
}

fn anthropic_prompt() -> Vec<Message> {
    vec![
        Message::system("Be terse."),
        Message::human("Capital of France?"),
    ]
}

#[test]
fn anthropic_usage_matches_reported_and_estimates_are_close() {
    let server = MockServer::start([MockResponse::json(
        200,
        fixture!("anthropic_messages_text.json"),
    )])
    .unwrap();
    let meter = UsageMeter::unlimited();
    let llm = anthropic(&server, &meter);
    let prompt = anthropic_prompt();
    let result = tokio_test::block_on(llm.generate(&prompt)).unwrap();
    server.finish().unwrap();

    // Recorded exactly as reported: 21 in, 9 out.
    let t = meter.totals();
    assert_eq!((t.calls, t.estimated_calls), (1, 0));
    assert_eq!((t.input_tokens, t.output_tokens), (21, 9));
    // Sonnet 4.6 lists $3 / $15 per MTok: 21·3 + 9·15 = 198 µ$.
    assert_eq!(t.cost, Cost::from_micros(198));
    assert_eq!(t.cost.to_string(), "$0.000198");

    assert_within_tolerance("anthropic input", estimate_messages(&prompt), 21);
    assert_within_tolerance(
        "anthropic output",
        estimate_reply(&result.generation, &result.tool_calls),
        9,
    );
}

#[test]
fn openai_usage_matches_reported_and_estimates_are_close() {
    let server =
        MockServer::start([MockResponse::json(200, fixture!("openai_chat_text.json"))]).unwrap();
    let meter = UsageMeter::unlimited();
    let llm = openai(&server, &meter);
    let prompt = [
        Message::system("You are a helpful assistant."),
        Message::human("What is 2 + 2?"),
    ];
    let result = tokio_test::block_on(llm.generate(&prompt)).unwrap();
    server.finish().unwrap();

    let t = meter.totals();
    assert_eq!((t.input_tokens, t.output_tokens), (19, 8));
    // GPT-4o lists $2.50 / $10 per MTok: 19·2.5 + 8·10 = 127.5 µ$.
    assert_eq!(t.cost.picodollars(), 127_500_000);

    assert_within_tolerance("openai input", estimate_messages(&prompt), 19);
    assert_within_tolerance(
        "openai output",
        estimate_reply(&result.generation, &result.tool_calls),
        8,
    );
}

#[test]
fn streams_are_recorded_as_estimates_once() {
    let server =
        MockServer::start([MockResponse::event_stream(fixture!("openai_stream.sse")).chunked(7)])
            .unwrap();
    let meter = UsageMeter::unlimited();
    let llm = openai(&server, &meter);
    let prompt = [Message::human("Say hello")];
    let text: String = tokio_test::block_on(async {
        let stream = llm.stream(&prompt).await.unwrap();
        stream
            .map(|c| c.unwrap().content)
            .collect::<Vec<_>>()
            .await
            .concat()
    });
    server.finish().unwrap();

    let t = meter.totals();
    assert_eq!((t.calls, t.estimated_calls), (1, 1));
    assert_eq!(t.input_tokens, estimate_messages(&prompt));
    assert_eq!(t.output_tokens, estimate_reply(&text, &[]));
    assert!(t.output_tokens > 0);
}

#[test]
fn a_dropped_stream_is_still_recorded() {
    let server =
        MockServer::start([MockResponse::event_stream(fixture!("openai_stream.sse"))]).unwrap();
    let meter = UsageMeter::unlimited();
    let llm = openai(&server, &meter);
    tokio_test::block_on(async {
        let mut stream = llm.stream(&[Message::human("Say hello")]).await.unwrap();
        let _first = stream.next().await;
    });
    drop(llm);
    let _ = server.finish();
    assert_eq!(meter.totals().calls, 1);
}

#[test]
fn budget_stops_a_run_before_the_next_request() {
    // Room for two fixture calls (2 × 198 µ$) but not a third.
    let budget = Budget::default().with_max_cost(Cost::from_micros(300));
    let meter = UsageMeter::new(budget);
    let server = MockServer::start([
        MockResponse::json(200, fixture!("anthropic_messages_text.json")),
        MockResponse::json(200, fixture!("anthropic_messages_text.json")),
    ])
    .unwrap();
    let llm = anthropic(&server, &meter);
    let prompt = anthropic_prompt();

    let mut completed = 0;
    let stop = tokio_test::block_on(async {
        loop {
            match llm.generate(&prompt).await {
                Ok(_) => completed += 1,
                Err(e) => break e,
            }
            assert!(completed <= 3, "budget did not stop the run");
        }
    });
    assert_eq!(completed, 2);
    assert!(stop.to_string().contains("budget exhausted"), "{stop}");
    // The refused call never reached the provider.
    assert_eq!(server.finish().unwrap().len(), 2);
    assert!(meter.is_exhausted());
    assert_eq!(meter.totals().cost, Cost::from_micros(396));
}

#[test]
fn preflight_refuses_a_call_that_would_overshoot() {
    let server = MockServer::start(Vec::<MockResponse>::new()).unwrap();
    let meter = UsageMeter::new(Budget::default().with_max_tokens(1_000));
    // Assume the reply may use all of max_tokens: 4096 > 1000, so refuse.
    let llm = anthropic(&server, &meter).expected_output_tokens(4_096);
    let err = tokio_test::block_on(llm.generate(&anthropic_prompt())).unwrap_err();
    assert!(err.to_string().contains("would be exceeded"), "{err}");
    assert_eq!(server.finish().unwrap().len(), 0);
    assert_eq!(meter.totals(), Totals::default());
}

#[test]
fn provider_errors_are_not_billed() {
    let server = MockServer::start([MockResponse::json(
        400,
        fixture!("anthropic_error_overloaded.json"),
    )])
    .unwrap();
    let meter = UsageMeter::unlimited();
    let llm = anthropic(&server, &meter);
    assert!(tokio_test::block_on(llm.generate(&anthropic_prompt())).is_err());
    server.finish().unwrap();
    assert_eq!(meter.totals().calls, 0);
}

#[test]
fn one_budget_spans_providers() {
    let a_server = MockServer::start([MockResponse::json(
        200,
        fixture!("anthropic_messages_text.json"),
    )])
    .unwrap();
    let o_server =
        MockServer::start([MockResponse::json(200, fixture!("openai_chat_text.json"))]).unwrap();
    let meter = UsageMeter::new(Budget::default().with_max_tokens(55));
    let a = anthropic(&a_server, &meter);
    let o = openai(&o_server, &meter);
    tokio_test::block_on(async {
        a.generate(&anthropic_prompt()).await.unwrap(); // 30 tokens
        o.generate(&[Message::human("2+2?")]).await.unwrap(); // 27 → 57 ≥ 55
        assert!(a.generate(&anthropic_prompt()).await.is_err());
    });
    a_server.finish().unwrap();
    o_server.finish().unwrap();

    let providers = meter.by_provider();
    let names: Vec<_> = providers.iter().map(|(p, _)| p.as_str()).collect();
    assert_eq!(names, ["anthropic", "openai"]);
    assert_eq!(providers[0].1.total_tokens(), 30);
    assert_eq!(providers[1].1.total_tokens(), 27);
    let by_model = meter.by_model();
    assert_eq!(by_model[1].0.model, gpt::GPT_4O);
    assert_eq!(meter.totals().total_tokens(), 57);
    assert_eq!(meter.remaining_tokens(), Some(0));
}
