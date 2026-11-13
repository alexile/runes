# rune-dedupe

> Idempotency/dedup filter over a keyed, windowed stream.

[![crates.io](https://img.shields.io/crates/v/rune-dedupe)](https://crates.io/crates/rune-dedupe)
[![docs.rs](https://img.shields.io/docsrs/rune-dedupe)](https://docs.rs/rune-dedupe)
[![license](https://img.shields.io/crates/l/rune-dedupe)](LICENSE)

## What it does

Remembers which keys were accepted recently and drops repeats: the building
block for turning at-least-once delivery (retried webhooks, redelivered queue
messages, flaky uplinks) into at-most-once processing.

- **Exact mode**: TTL window plus an optional hard `max_keys` cap. At the cap
  the oldest accepted key is evicted first. `O(log n)` per check.
- **Approximate mode**: no keys stored, just a few rotating Bloom filter
  generations of fixed size, with a configurable false-positive rate and no
  false negatives within the window.
- **Event time**: `EventTimeDedupe` matches occurrences whose event times are
  within the window of each other, in any arrival order, and forgets state
  only as the watermark moves past it. Timestamps default to `i64`
  milliseconds, the same as `rune-watermark`.
- **Checkpointing**: snapshot and restore the full state (seen set or
  filters, hash key, counters). A restored deduplicator makes the same
  decisions as the original. With the `serde` feature, snapshots serialize, so
  the seen set and the input offset can be committed in one atomic write.
- **HashDoS-resistant**: keys are hashed with SipHash-2-4 under a secret
  random key.
- **Metrics**: built-in counters (seen, fresh, duplicates, late, evictions by
  reason) and an optional per-event callback.

Time is always passed in explicitly, so runs are deterministic. Use
`Instant`, `SystemTime`, or `i64`/`u64` milliseconds.

## Installation

```toml
[dependencies]
rune-dedupe = "0.1"
# For serializable snapshots:
# rune-dedupe = { version = "0.1", features = ["serde"] }
```

The `rune-dedupe` command-line tool is behind the opt-in `cli` feature:

```bash
cargo install rune-dedupe --features cli
```

## Usage

```rust
use rune_dedupe::Dedupe;
use std::time::{Duration, Instant};

let start = Instant::now();
let mut dedupe = Dedupe::new(Duration::from_secs(60));

assert!(dedupe.check("msg-1", start));
assert!(!dedupe.check("msg-1", start + Duration::from_secs(1)));
assert!(dedupe.check("msg-1", start + Duration::from_secs(61)));
```

### Bounded memory

```rust
use rune_dedupe::{ApproxConfig, Dedupe};
use std::time::Duration;

let window = Duration::from_secs(600);

// Exact, at most 250k keys; the oldest accepted key goes first when full.
let exact: Dedupe<String, u64> = Dedupe::builder(window).max_keys(250_000).build()?;

// Fixed memory: sized for 5M keys per window, at most 0.01% false positives.
let approx: Dedupe<String, u64> = Dedupe::builder(window)
    .approximate(ApproxConfig::new(5_000_000, 0.0001))
    .build()?;
```

Approximate mode splits the window into `generations - 1` spans (default 4
generations), each with its own Bloom filter sized for its share of the keys
at `fpr / (generations + 1)`, so the union bound keeps the overall rate at or
below `fpr`. Keys may be remembered up to one span past the window. If traffic
exceeds `expected_keys`, generations roll early and the oldest one can be
dropped before its time; those drops are counted as capacity evictions.

### Event time

```rust
use rune_dedupe::{EventTimeDedupe, Verdict};
use std::time::Duration;

let mut d: EventTimeDedupe<&str> = EventTimeDedupe::new(Duration::from_millis(100));
assert_eq!(d.check("order-7", 1_000), Verdict::Fresh);
assert_eq!(d.check("order-7", 950), Verdict::Duplicate);

d.advance_watermark(1_150); // e.g. from rune-watermark's tracker
assert_eq!(d.check("order-7", 1_050), Verdict::Late);
```

`Verdict::Late` means the event is behind the watermark and no match is still
held, so it can't be called fresh safely. Drop it or send it to a side output.

### Exactly-once checkpoints

Commit the dedupe state and the input offset together, after the outputs up
to that offset are durable (or in the same transaction as them):

```rust
use rune_dedupe::{Checkpoint, Dedupe, Snapshot};

// Save: one atomic write (temp file + rename, or a DB transaction).
let cp = Checkpoint { offset: next_offset, state: dedupe.snapshot() };
std::fs::write("state.json.tmp", serde_json::to_vec(&cp)?)?;
std::fs::rename("state.json.tmp", "state.json")?;

// Restart: restore, then resume reading at `cp.offset`.
let cp: Checkpoint<Snapshot<String, u64>> =
    serde_json::from_slice(&std::fs::read("state.json")?)?;
let mut dedupe = Dedupe::restore(cp.state)?;
```

Replayed events hit the restored seen set and are dropped. `rune-checkpoint`
stores offsets only (a `source -> u64` map), so it can't hold the seen set;
keeping the two in separate stores would let them drift apart on a crash.
Snapshots include the secret hash key, so store them accordingly.

## CLI

Filters duplicate keys (one per line) within a trailing window:

```bash
rune-dedupe --window-secs 60 keys.txt
cat keys.txt | rune-dedupe --window-secs 60 --max-keys 100000 -
cat keys.txt | rune-dedupe --window-secs 60 --fpr 0.001 --expected-keys 1000000 -
```

```
msg-1
msg-2
2 kept, 1 duplicate(s) dropped
```

## License

MIT
