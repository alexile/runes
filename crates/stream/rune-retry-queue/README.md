# rune-retry-queue

> Dead-letter queue with configurable backoff retry for failed sink writes.

[![crates.io](https://img.shields.io/crates/v/rune-retry-queue)](https://crates.io/crates/rune-retry-queue)
[![docs.rs](https://img.shields.io/docsrs/rune-retry-queue)](https://docs.rs/rune-retry-queue)
[![license](https://img.shields.io/crates/l/rune-retry-queue)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

## What it does

Schedules failed items for retry after a delay from a `Fixed` or capped
`Exponential` backoff policy, up to a configurable max attempt count. Items
that exhaust their attempts are routed to a dead-letter list instead. Time is
always passed in explicitly (`std::time::Instant`), so the queue never calls
the clock itself and is fully deterministic to test. Pure Rust, no
dependencies.

## Installation

```toml
[dependencies]
rune-retry-queue = "0.1"
```

The `rune-retry-queue` command-line tool is behind the opt-in `cli` feature:

```bash
cargo install rune-retry-queue --features cli
```

## Usage

```rust
use rune_retry_queue::{BackoffPolicy, RetryQueue};
use std::time::{Duration, Instant};

let mut queue = RetryQueue::new(BackoffPolicy::Fixed(Duration::from_secs(1)), 3);
let t0 = Instant::now();

queue.push("payload", 0, t0);
assert!(queue.ready(t0).is_empty());

let due = queue.ready(t0 + Duration::from_secs(1));
assert_eq!(due, vec![("payload", 0)]);
```

## CLI

Prints the delay schedule a policy would produce, without running a real queue:

```bash
rune-retry-queue --policy exponential --delay-ms 500 --factor 2 --max-delay-ms 10000 --max-attempts 6
```

## Output

```
attempt 0: 500ms
attempt 1: 1s
attempt 2: 2s
attempt 3: 4s
attempt 4: 8s
attempt 5: 10s
```

## License

MIT
