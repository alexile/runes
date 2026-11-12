# rune-ingest-mqtt

> Minimal MQTT subscriber normalizing messages into a typed event channel.

[![crates.io](https://img.shields.io/crates/v/rune-ingest-mqtt)](https://crates.io/crates/rune-ingest-mqtt)
[![docs.rs](https://img.shields.io/docsrs/rune-ingest-mqtt)](https://docs.rs/rune-ingest-mqtt)
[![license](https://img.shields.io/crates/l/rune-ingest-mqtt)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

## What it does

A blocking, QoS-0-only MQTT 3.1.1 subscriber: a pure byte-level packet codec
(`CONNECT`/`CONNACK`/`SUBSCRIBE`/`SUBACK`/`PUBLISH`), MQTT topic-filter wildcard
matching (`+`/`#`), and a normalizer that turns a raw topic + payload into a typed
`NormalizedMessage` — JSON payloads decode as JSON, everything else falls back to a
string. No MQTT client library, no async runtime, pure Rust.

## Installation

```toml
[dependencies]
rune-ingest-mqtt = "0.1"
```

The `rune-ingest-mqtt` command-line tool is behind the opt-in `cli` feature:

```bash
cargo install rune-ingest-mqtt --features cli
```

## Usage

```rust
use rune_ingest_mqtt::{normalize, topic_matches};

let msg = normalize("sensors/42/temperature", br#"{"celsius":21.5}"#, 1_700_000_000_000);
assert_eq!(msg.payload["celsius"], 21.5);

assert!(topic_matches("sensors/+/temperature", "sensors/42/temperature"));
```

```rust,no_run
use rune_ingest_mqtt::subscribe_qos0;

subscribe_qos0("broker.local:1883", "my-client", "sensors/#", |msg| {
    println!("{} -> {}", msg.topic, msg.payload);
}).unwrap();
```

## CLI

```bash
rune-ingest-mqtt broker.local:1883 "sensors/#"
```

## Output

```
{"topic":"sensors/42/temperature","payload":{"celsius":21.5},"received_at_ms":1700000000000}
```

## License

MIT
