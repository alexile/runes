# rune-checkpoint

> Resumable-cursor/offset persistence for restartable stream consumers.

[![crates.io](https://img.shields.io/crates/v/rune-checkpoint)](https://crates.io/crates/rune-checkpoint)
[![docs.rs](https://img.shields.io/docsrs/rune-checkpoint)](https://docs.rs/rune-checkpoint)
[![license](https://img.shields.io/crates/l/rune-checkpoint)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

## What it does

Persists a flat `source_id -> offset` map to a single JSON file, so a stream
consumer can restart and resume from its last saved position instead of
replaying from the beginning. Every save is atomic — written to a temp file
and renamed into place — so a crash mid-write can never corrupt the store.
Pure Rust, no dependencies beyond serde.

## Installation

```toml
[dependencies]
rune-checkpoint = "0.1"
```

The `rune-checkpoint` command-line tool is behind the opt-in `cli` feature:

```bash
cargo install rune-checkpoint --features cli
```

## Usage

```rust
use rune_checkpoint::CheckpointStore;

let store = CheckpointStore::new("checkpoints.json");
store.save("sensor-1", 1024).unwrap();

assert_eq!(store.load("sensor-1").unwrap(), Some(1024));
assert_eq!(store.load("sensor-2").unwrap(), None);
```

## CLI

```bash
rune-checkpoint --store state.json save sensor-1 1024
rune-checkpoint --store state.json load sensor-1
rune-checkpoint --store state.json list
```

## Output

```
saved sensor-1 = 1024
1024
sensor-1	1024
```

## License

MIT
