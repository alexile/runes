# rune-chain-usage

> Per-provider token and cost accounting with budget caps for rune-chain LLMs

[![crates.io](https://img.shields.io/crates/v/rune-chain-usage)](https://crates.io/crates/rune-chain-usage)
[![docs.rs](https://img.shields.io/docsrs/rune-chain-usage)](https://docs.rs/rune-chain-usage)
[![license](https://img.shields.io/crates/l/rune-chain-usage)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

Meter what your agents spend, per provider and model, and stop a run when it
hits a budget.

- **`UsageMeter`** — a cloneable, thread-safe ledger of calls, tokens and cost,
  with totals per provider/model and per tag. Cache reads, cache writes and
  reasoning tokens are counted separately. Share one meter between several
  LLMs to enforce a single budget.
- **Bounded memory** — the meter keeps aggregates, not a log of every request.
  Breakdowns are capped (256 keys by default, extra keys go under `_other`)
  and the history of recent calls is an optional fixed-size ring buffer.
- **`Budget`** — cost and/or token caps, a warning threshold and an alert
  callback. Caps are hard stops by default: a call is refused *before* it is
  sent when the budget is spent or the call's estimate would pass a cap.
  `with_warn_only(true)` turns them into alerts only.
- **Export** — `UsageMeter::report()` returns a `UsageReport` that serialises
  with serde (costs as integer picodollars, so it round-trips exactly).
- **`MeteredLlm`** — wraps any `rune_chain_core::Llm`. It checks the budget
  before each call from a local token estimate (via `rune-tokenize`), and
  records the provider-reported usage afterwards, falling back to an estimate
  when the provider reports none (plain `stream`; `stream_events` uses the
  provider's `StreamEvent::Usage` when it sends one).
- Prices are `rune_chain_core::Pricing` values. `rune-chain-anthropic` and
  `rune-chain-openai` attach list prices to every model in their registries;
  costs are exact integer picodollars.

## Installation

```toml
[dependencies]
rune-chain-usage = "0.1"
```

## Usage

```rust
use rune_chain_anthropic::{Anthropic, models};
use rune_chain_core::{Cost, Llm, Message};
use rune_chain_usage::{Budget, MeteredLlm, UsageMeter};

async fn run() -> Result<(), rune_chain_core::LlmError> {
    let meter = UsageMeter::new(
        Budget::default()
            .with_max_cost(Cost::from_cents(200)) // $2.00
            .with_warn_at_percent(80)
            .on_alert(|alert| eprintln!("budget: {alert:?}")),
    );

    let model = models::CLAUDE_OPUS_5_5;
    let pricing = models::lookup(model).map(|m| m.pricing).unwrap_or_default();
    let llm = MeteredLlm::new(
        Anthropic::new("sk-ant-...").model(model),
        meter.clone(),
        "anthropic",
        model,
        pricing,
    );

    // Each call is checked first and recorded after; once $2 is spent the next
    // call fails with "budget exhausted" without reaching the API.
    llm.generate(&[Message::human("Summarise RFC 9110 in one line.")]).await?;

    for (key, totals) in meter.by_model() {
        println!("{}/{}: {} calls, {} tokens, {}", key.provider, key.model,
            totals.calls, totals.total_tokens(), totals.cost);
    }
    Ok(())
}
```

Tag calls to see who spends what, and keep the last few calls around:

```rust
use rune_chain_core::Pricing;
use rune_chain_usage::{Usage, UsageMeter};

let meter = UsageMeter::unlimited().with_history(100);
let price = Pricing::per_mtok(3_000_000, 15_000_000).with_cache(300_000, 3_750_000);
let usage = Usage::reported(10_000, 2_000).with_cache(6_000, 1_000);
meter.record_tagged("anthropic", "claude-sonnet-4-6", Some("search"), &price, usage).unwrap();

let report = meter.report();
assert_eq!(report.by_tag[0].name, "search");
println!("{}", serde_json::to_string_pretty(&report).unwrap());
```

`MeteredLlm::with_tag("search")` does the same for every call through a
wrapper.

Recording usage by hand works without any wrapper:

```rust
use rune_chain_core::{Cost, Pricing};
use rune_chain_usage::{Usage, UsageMeter};

let meter = UsageMeter::unlimited();
let price = Pricing::per_mtok(3_000_000, 15_000_000); // $3 / $15 per MTok
meter.record("anthropic", "claude-sonnet-4-6", &price, Usage::reported(21, 9)).unwrap();
assert_eq!(meter.totals().cost, Cost::from_micros(198));
```

## Accuracy

Costs are integer picodollars (`rune_chain_core::Cost`), so adding up a
million tiny calls gives the exact total with no float drift.
Provider-reported usage is recorded exactly. Local estimates (about four
characters per token, plus a few framing tokens per message) are a guard rail
for pre-flight checks and streams; the tests hold them within ±30 % (or six
tokens) of recorded Anthropic and OpenAI responses.

## License

MIT
