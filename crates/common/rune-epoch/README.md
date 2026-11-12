# rune-epoch

> Unix timestamp conversions — epoch to human-readable and back.

[![crates.io](https://img.shields.io/crates/v/rune-epoch)](https://crates.io/crates/rune-epoch)
[![docs.rs](https://img.shields.io/docsrs/rune-epoch)](https://docs.rs/rune-epoch)
[![license](https://img.shields.io/crates/l/rune-epoch)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

## What it does

Converts Unix epoch values (seconds or milliseconds) to ISO 8601 UTC strings and
back, using pure Rust standard library arithmetic — no external time crates required.
Security researchers and log analysts use it to quickly translate raw timestamps
found in binary files, database dumps, and network captures into readable dates.

## Installation

```toml
[dependencies]
rune-epoch = "0.2"
```

The `rune-epoch` command-line tool is behind the opt-in `cli` feature:

```bash
cargo install rune-epoch --features cli
```

## Usage

### Library

```rust
use rune_epoch::{to_utc_string, from_utc_string, now_secs};

// Current time
println!("{}", now_secs());

// Epoch to string
assert_eq!(to_utc_string(0),          "1970-01-01T00:00:00Z");
assert_eq!(to_utc_string(1704067200), "2024-01-01T00:00:00Z");
assert_eq!(to_utc_string(-86400),     "1969-12-31T00:00:00Z");

// String to epoch
assert_eq!(from_utc_string("2024-01-01T00:00:00Z").unwrap(), 1704067200);
assert_eq!(from_utc_string("2024-01-01 00:00:00").unwrap(),  1704067200);
```

### CLI

```bash
rune-epoch                          # print current epoch seconds
rune-epoch --millis                 # print current epoch in milliseconds
rune-epoch 1704067200               # convert epoch to UTC string
rune-epoch "2024-01-15T14:30:00Z"   # convert UTC string to epoch
rune-epoch "2024-01-15 14:30:00"    # space separator also accepted
```

## Output

```
$ rune-epoch
1704067200

$ rune-epoch 1704067200
2024-01-01T00:00:00Z

$ rune-epoch "2024-01-15T14:30:00Z"
1705329000

$ rune-epoch --millis
1704067200000
```

## License

MIT
