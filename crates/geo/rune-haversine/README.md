# rune-haversine

> Great-circle distance and bearing between coordinates.

[![crates.io](https://img.shields.io/crates/v/rune-haversine)](https://crates.io/crates/rune-haversine)
[![docs.rs](https://img.shields.io/docsrs/rune-haversine)](https://docs.rs/rune-haversine)
[![license](https://img.shields.io/crates/l/rune-haversine)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

## What it does

Computes great-circle distance (haversine formula) and initial compass
bearing between two latitude/longitude coordinates. Pure Rust, no
dependencies beyond the optional CLI parser.

## Installation

```toml
[dependencies]
rune-haversine = "0.1"
```

The `rune-haversine` command-line tool is behind the opt-in `cli` feature:

```bash
cargo install rune-haversine --features cli
```

## Usage

```rust
use rune_haversine::{distance_m, bearing_deg};

let d = distance_m(60.1699, 24.9384, 60.4518, 22.2666);
let b = bearing_deg(60.1699, 24.9384, 60.4518, 22.2666);
```

## CLI

```bash
rune-haversine 60.1699 24.9384 60.4518 22.2666
```

## Output

```
distance_m=149613.25 bearing_deg=294.83
```

## License

MIT
