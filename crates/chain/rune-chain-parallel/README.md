# rune-chain-parallel

> ParallelChain for rune-chain: fan-out to multiple chains concurrently and merge outputs.

[![crates.io](https://img.shields.io/crates/v/rune-chain-parallel)](https://crates.io/crates/rune-chain-parallel)
[![docs.rs](https://img.shields.io/docsrs/rune-chain-parallel)](https://docs.rs/rune-chain-parallel)
[![license](https://img.shields.io/crates/l/rune-chain-parallel)](LICENSE)

All branches run concurrently on the calling task (polled together;
nothing is spawned), each with the same input. Their text outputs are
merged into the shared variable map keyed by each branch's `output_key`, making them available to downstream chains. Token
usage across all branches is summed, and `call` returns the last branch's
generation. The first branch error fails the whole chain.

## Installation

```toml
[dependencies]
rune-chain-parallel = "0.2"
```

## Usage

```rust,no_run
use rune_chain_parallel::ParallelChain;
use rune_chain_core::{Chain, ChainError, GenerateResult, PromptArgs, prompt_args};
use async_trait::async_trait;

struct UpperCase;
#[async_trait]
impl Chain for UpperCase {
    async fn call(&self, input: PromptArgs) -> Result<GenerateResult, ChainError> {
        let text = input.get("input").and_then(|v| v.as_str()).unwrap_or("").to_uppercase();
        Ok(GenerateResult::from_text(text))
    }
}

async fn run() {
    let chain = ParallelChain::new().branch(UpperCase, "upper");
    let out = chain.execute(prompt_args! { "input" => "hi" }).await.unwrap();
    assert_eq!(out["upper"], "HI");
}
```

## Migrating from 0.1

- Uses `rune-chain-core` 0.2, whose `LlmError`, `GenerateResult`, `TokenUsage` and `Message` changed; see its [migration notes](https://crates.io/crates/rune-chain-core).
- No behaviour change.

## License

MIT
