# rune-schema-sniff

> Heuristic column/field-type detector for arbitrary CSV/JSON: guesses timestamp/id/value/lat-lon columns, emits a normalized preview with confidence scores.

[![crates.io](https://img.shields.io/crates/v/rune-schema-sniff)](https://crates.io/crates/rune-schema-sniff)
[![docs.rs](https://img.shields.io/docsrs/rune-schema-sniff)](https://docs.rs/rune-schema-sniff)
[![license](https://img.shields.io/crates/l/rune-schema-sniff)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

## What it does

Looks at a column's name and its sampled values together and guesses what kind
of field it is — identifier, timestamp, coordinate, flag, plain number, or
free text — with a confidence score. Works over both CSV rows and JSON
objects. Coordinates are only guessed when the column name hints at them and
the values fall in the matching range, so a column of small numbers with no
geo-sounding name (a percentage, a temperature) stays `Numeric` instead of
being mistaken for a coordinate. Pure Rust, no external heuristics library.

## Installation

```toml
[dependencies]
rune-schema-sniff = "0.1"
```

The `rune-schema-sniff` command-line tool is behind the opt-in `cli` feature:

```bash
cargo install rune-schema-sniff --features cli
```

## Usage

```rust
use rune_schema_sniff::{sniff_csv, FieldType};

let headers = vec!["id".to_string(), "lat".to_string(), "lon".to_string()];
let rows = vec![
    vec!["u1".to_string(), "60.17".to_string(), "24.94".to_string()],
    vec!["u2".to_string(), "60.20".to_string(), "24.90".to_string()],
];

let guesses = sniff_csv(&headers, &rows);
assert_eq!(guesses[0].guessed_type, FieldType::Id);
assert_eq!(guesses[1].guessed_type, FieldType::Latitude);
```

## CLI

```bash
rune-schema-sniff data.csv
rune-schema-sniff data.json
```

## Output

```
id                   id         confidence=0.75
lat                  latitude   confidence=0.95
lon                  longitude  confidence=0.90
```

## License

MIT
