# rune-ingest-ndjson

> Streaming NDJSON reader with a time-compression replay clock (Nx speed).

[![crates.io](https://img.shields.io/crates/v/rune-ingest-ndjson)](https://crates.io/crates/rune-ingest-ndjson)
[![docs.rs](https://img.shields.io/docsrs/rune-ingest-ndjson)](https://docs.rs/rune-ingest-ndjson)
[![license](https://img.shields.io/crates/l/rune-ingest-ndjson)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

## What it does

Reads NDJSON (one JSON object per line) and replays it as an iterator, sleeping
the real-time-compressed delay between records based on the gap between their
timestamps — so a recorded log can be replayed as if it were arriving live, at
any speed multiplier. Malformed lines report an error instead of panicking or
silently vanishing. Pure Rust, no async runtime required.

## Installation

```toml
[dependencies]
rune-ingest-ndjson = "0.1"
```

The `rune-ingest-ndjson` command-line tool is behind the opt-in `cli` feature:

```bash
cargo install rune-ingest-ndjson --features cli
```

## Usage

```rust
use rune_ingest_ndjson::NdjsonReplay;
use std::io::Cursor;

let data = "{\"ts\":0,\"v\":1}\n{\"ts\":1000,\"v\":2}\n";
let replay = NdjsonReplay::new(Cursor::new(data.as_bytes()), "ts", 10.0);

for record in replay {
    let record = record.unwrap();
    println!("{record}");
}
```

## CLI

```bash
rune-ingest-ndjson --speed 10 --ts-field ts events.ndjson
cat events.ndjson | rune-ingest-ndjson --speed 10 -
```

## Output

```
{"ts":0,"v":1}
{"ts":1000,"v":2}
```

## License

MIT
