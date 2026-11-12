# rune-ws

> Sans-I/O WebSocket (RFC 6455) framing, handshake and connection state machine, with optional permessage-deflate and tokio adapter

[![crates.io](https://img.shields.io/crates/v/rune-ws)](https://crates.io/crates/rune-ws)
[![docs.rs](https://img.shields.io/docsrs/rune-ws)](https://docs.rs/rune-ws)
[![license](https://img.shields.io/crates/l/rune-ws)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

## Installation

```toml
[dependencies]
rune-ws = "0.1"
```

The `rune-ws` command-line tool is behind the opt-in `cli` feature:

```bash
cargo install rune-ws --features cli
```

## Usage

### Library

```rust
use rune_ws::{Options, run};

let report = run("hello rune", &Options::default()).unwrap();
assert_eq!(report.words, 2);
```

### CLI

```bash
rune-ws "hello rune"
# 2

rune-ws --max-len 4 "hello rune"
# error: input is 10 bytes, more than the limit of 4 bytes
```

## License

MIT
