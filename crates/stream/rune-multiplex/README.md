# rune-multiplex

> Fan-in merge of N ordered sources into one interleaved, time-ordered stream.

[![crates.io](https://img.shields.io/crates/v/rune-multiplex)](https://crates.io/crates/rune-multiplex)
[![docs.rs](https://img.shields.io/docsrs/rune-multiplex)](https://docs.rs/rune-multiplex)
[![license](https://img.shields.io/crates/l/rune-multiplex)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

## What it does

Merges several sequences, each already sorted by a key, into one globally
sorted sequence — a k-way merge over a binary heap, `O(n log k)`. Ties between
sources are broken deterministically by source index. Pure Rust, no
dependencies.

## Installation

```toml
[dependencies]
rune-multiplex = "0.1"
```

The `rune-multiplex` command-line tool is behind the opt-in `cli` feature:

```bash
cargo install rune-multiplex --features cli
```

## Usage

```rust
use rune_multiplex::multiplex;

let sensor_a = vec![1, 4, 7];
let sensor_b = vec![2, 5, 8];
let sensor_c = vec![3, 6, 9];

let merged = multiplex(vec![sensor_a, sensor_b, sensor_c], |v| *v);
assert_eq!(merged, vec![1, 2, 3, 4, 5, 6, 7, 8, 9]);
```

## CLI

Merges N files of newline-separated, ascending integers:

```bash
rune-multiplex source_a.txt source_b.txt source_c.txt
```

## Output

```
1
2
3
4
5
6
```

## License

MIT
