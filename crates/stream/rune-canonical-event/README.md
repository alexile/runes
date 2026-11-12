# rune-canonical-event

> Typed event envelope for streaming pipelines — source, timestamp, sequence, kind, payload, and metadata, with a validating builder.

[![crates.io](https://img.shields.io/crates/v/rune-canonical-event)](https://crates.io/crates/rune-canonical-event)
[![docs.rs](https://img.shields.io/docsrs/rune-canonical-event)](https://docs.rs/rune-canonical-event)
[![license](https://img.shields.io/crates/l/rune-canonical-event)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

## What it does

Gives heterogeneous event sources one normalized shape to produce, and every
downstream consumer one shape to read: `source_id`, `ts`, `seq`, `kind`,
`payload`, an optional `geo` position, and a free-form `meta` map. Ships a
validating builder plus a standalone `validate` for events deserialized
directly from JSON. Pure Rust, serde-based.

## Installation

```toml
[dependencies]
rune-canonical-event = "0.1"
```

The `rune-canonical-event` command-line tool is behind the opt-in `cli` feature:

```bash
cargo install rune-canonical-event --features cli
```

## Usage

```rust
use rune_canonical_event::CanonicalEvent;
use serde_json::json;

let event = CanonicalEvent::builder("sensor-42", 1_700_000_000_000, 1, "temperature")
    .payload(json!({ "celsius": 21.5 }))
    .geo(60.17, 24.94)
    .meta("unit", "pump-3")
    .build()
    .unwrap();

assert_eq!(event.source_id, "sensor-42");
```

## CLI

Validates an NDJSON file of events against the schema, one JSON object per line:

```bash
rune-canonical-event events.ndjson
cat events.ndjson | rune-canonical-event -
```

## Output

```
3 valid, 1 invalid
```

Validation errors are printed to stderr with their line number.

## License

MIT
