# rune-bp-channel

> Bounded channel wrapper with configurable backpressure policy: drop-oldest, drop-newest, block.

[![crates.io](https://img.shields.io/crates/v/rune-bp-channel)](https://crates.io/crates/rune-bp-channel)
[![docs.rs](https://img.shields.io/docsrs/rune-bp-channel)](https://docs.rs/rune-bp-channel)
[![license](https://img.shields.io/crates/l/rune-bp-channel)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

## What it does

Wraps a bounded queue behind a `Mutex`/`Condvar` pair with a choice of three
behaviors once the buffer fills up: evict the oldest item, reject the new
item, or block the producer until a consumer catches up. Multi-producer via a
cloneable `Sender`. Pure Rust, `std`-only, no async runtime required.

## Installation

```toml
[dependencies]
rune-bp-channel = "0.1"
```

The `rune-bp-channel` command-line tool is behind the opt-in `cli` feature:

```bash
cargo install rune-bp-channel --features cli
```

## Usage

```rust
use rune_bp_channel::{channel, BackpressurePolicy, PushOutcome};

let (tx, rx) = channel::<i32>(2, BackpressurePolicy::DropOldest);
assert!(matches!(tx.send(1), PushOutcome::Accepted));
assert!(matches!(tx.send(2), PushOutcome::Accepted));
assert!(matches!(tx.send(3), PushOutcome::DroppedOldest(1)));

assert_eq!(rx.recv(), Some(2));
assert_eq!(rx.recv(), Some(3));
```

## CLI

Feeds stdin lines through a bounded channel and reports what happened:

```bash
printf 'a\nb\nc\n' | rune-bp-channel --capacity 2 --policy drop-oldest
```

## Output

```
b
c
2 accepted, 1 dropped, 2 received
```

## License

MIT
