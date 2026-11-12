# rune-tsne

> t-SNE dimensionality reduction — map high-dimensional data into 2D or 3D for visualisation.

[![crates.io](https://img.shields.io/crates/v/rune-tsne)](https://crates.io/crates/rune-tsne)
[![docs.rs](https://img.shields.io/docsrs/rune-tsne)](https://docs.rs/rune-tsne)
[![license](https://img.shields.io/crates/l/rune-tsne)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

## What it does

Implements exact O(n²) t-SNE (van der Maaten & Hinton 2008) in pure Rust.
t-SNE is the standard algorithm for visualising clusters in high-dimensional data —
used by data scientists, ML researchers, and security analysts to explore embeddings,
malware feature vectors, and network traffic fingerprints.

## Installation

```toml
[dependencies]
rune-tsne = "0.1"
```

The `rune-tsne` command-line tool is behind the opt-in `cli` feature:

```bash
cargo install rune-tsne --features cli
```

## Usage

```rust
use rune_tsne::Tsne;

let points: Vec<Vec<f64>> = (0..50)
    .map(|i| vec![i as f64, (i as f64).sin(), (i as f64).cos()])
    .collect();

let result = Tsne::new()
    .perplexity(15.0)
    .n_iter(1000)
    .random_seed(42) // same seed + same input => bit-identical output
    .fit(&points)?;

for row in &result.embedding {
    println!("{:.4}\t{:.4}", row[0], row[1]);
}
println!("KL divergence: {:.4}", result.kl_divergence);
```

`fit` returns a `TsneError` instead of panicking when it is given fewer than three
points, a perplexity at or above `n_points / 3`, rows of different lengths or
NaN/infinite coordinates.

The learning rate defaults to `max(n_points / 48, 50)` (scikit-learn's `"auto"`);
set it explicitly with `.learning_rate(…)`. Results do not depend on the units of
the input: the bandwidth search starts at each point's own distance scale.

3D output:

```rust
use rune_tsne::Tsne;

let points: Vec<Vec<f64>> = (0..30)
    .map(|i| vec![i as f64, (i as f64 * 0.3).sin()])
    .collect();

let result = Tsne::new()
    .n_components(3)
    .perplexity(9.0)
    .n_iter(200)
    .fit(&points)?;

assert_eq!(result.embedding[0].len(), 3);
```

## CLI

```bash
rune-tsne data.csv --perplexity 30 --n-iter 1000
rune-tsne data.csv --n-components 3 --perplexity 10 --learning-rate 150
cat data.csv | rune-tsne - --perplexity 10
```

## Output

```
0.342156    -1.204873
-0.891234    0.673421
1.203847    0.094812
...
# 150 points → 2D embedding
```

Each line is one embedded point with coordinates tab-separated. The summary line is
written to stderr.

## License

MIT
