# rune-chain-retry

> Resilience and routing for rune-chain `Llm`: retries with jittered backoff, and a multi-provider router with circuit breakers.

[![crates.io](https://img.shields.io/crates/v/rune-chain-retry)](https://crates.io/crates/rune-chain-retry)
[![docs.rs](https://img.shields.io/docsrs/rune-chain-retry)](https://docs.rs/rune-chain-retry)
[![license](https://img.shields.io/crates/l/rune-chain-retry)](LICENSE)

A small, composable take on litellm's router for the `rune-chain` family:
every piece is just another `Llm`, so it stacks with `LlmExt::with_fallbacks`,
`Arc<dyn Llm>` and the other wrappers.

- **`RetryLlm`**: retries one model on transient failures, using exponential
  backoff with full jitter, a cap per delay, a total time budget
  (`max_elapsed`) and a per-attempt timeout. It honours provider retry-after
  hints such as `try again in 2s`.
- **Error classification** (`classify`): rate limits, overload, 5xx,
  timeouts and network errors are retried. Authentication or billing
  failures, invalid requests, context-length errors, undecodable responses
  and `LlmError::other` are never retried.
- **`Router`**: one `Llm` in front of N providers, with these strategies:
  - `Ordered`: fallback in the order the providers were added.
  - `WeightedRandom`.
  - `RoundRobin`.
  - `LowestLatency`: by an EWMA of each provider's latency.
  - `CheapestFirst`: uses `rune_chain_core::Pricing`.

  Each provider also gets:
  - a circuit breaker (closed, open or half-open);
  - a cooldown after a rate limit;
  - context-window filtering, which uses a token estimate you can replace.
- **Streaming**: retry and fallback happen only before the first chunk. The
  outputs of two providers are never spliced together.
- **Observability**: `on_event` callbacks receive an `Event` for attempts,
  retries, fallbacks, skipped providers, cooldowns and breaker state changes.

No network in tests: everything runs on mock models with tokio's paused clock.

## Installation

```toml
[dependencies]
rune-chain-retry = "0.3"
```

## Usage

```rust,ignore
use std::time::Duration;
use rune_chain_core::Pricing;
use rune_chain_retry::{
    BreakerConfig, Event, Provider, RetryLlm, RetryPolicy, Router, Strategy,
};

// One model, retried.
let llm = RetryLlm::new(my_llm)
    .max_retries(3)
    .initial_delay_ms(500)
    .max_elapsed(Duration::from_secs(30))
    .attempt_timeout(Duration::from_secs(60));

// Several providers behind one Llm.
let router = Router::new(Strategy::CheapestFirst)
    .provider(Provider::new("haiku", haiku)
        .pricing(Pricing::per_mtok(1_000_000, 5_000_000))
        .max_context_tokens(200_000))
    .provider(Provider::new("gpt", gpt)
        .pricing(Pricing::per_mtok(2_500_000, 10_000_000))
        .max_context_tokens(128_000))
    .retry_policy(RetryPolicy::default().with_max_retries(1))
    .breaker(BreakerConfig::default().with_failure_threshold(3))
    .on_event(|e| if let Event::Fallback { from, to, class } = e {
        tracing::warn!(%from, %to, ?class, "llm fallback");
    });
```

See [docs.rs](https://docs.rs/rune-chain-retry) for runnable examples.

## Migrating from 0.2

- Uses `rune-chain-core` 0.2, whose `LlmError`, `GenerateResult`, `TokenUsage` and `Message` changed; see its [migration notes](https://crates.io/crates/rune-chain-core).
- `classify` reads `LlmError::kind()` first; message matching is only a fallback for unclassified (`Provider`, or status-less `Network`) errors.
- `retry_after` prefers `LlmError::retry_after()` (the provider's `Retry-After` header) over hints in the message.
- Attempt timeouts are `LlmErrorKind::Timeout`; a router with no usable provider fails with `Overloaded` or `ContextLengthExceeded`.

## Migrating from 0.1

The API from 0.1 still compiles unchanged, but some default behaviour is
different:

- **Jitter is on by default** (`Jitter::Full`): each delay is random in
  `[0, initial × multiplier^n]`. Call `.jitter(Jitter::None)` to get the old
  deterministic delays back.
- **Delays are capped at 30 s** (`max_delay`). Before 0.2 they grew without
  limit.
- **`ProviderError`s are classified.** Errors that read as authentication,
  billing or quota failures, invalid requests or context-length problems
  are no longer retried. Unrecognised provider errors are still retried.
  To change this, pass your own function to `.classifier(…)`.
- **Retry-after hints are honoured.** A message such as `try again in 20s`
  makes the next wait at least 20 s. Turn this off with
  `RetryPolicy::with_honor_retry_after(false)`.
- **`stream()` waits for the first chunk** before it returns, so that a
  stream that fails before producing any output is retried. Errors after
  the first chunk are passed through as before.
- **`generate_structured` is forwarded** to the inner model, with retries,
  so its native JSON mode is used. Before 0.2 the trait default ran on top
  of the retried `generate`.

## License

MIT
