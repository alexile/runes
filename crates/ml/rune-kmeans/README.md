# rune-kmeans

> K-Means++ clustering — partition points into k clusters with smart initialisation.

[![crates.io](https://img.shields.io/crates/v/rune-kmeans)](https://crates.io/crates/rune-kmeans)
[![docs.rs](https://img.shields.io/docsrs/rune-kmeans)](https://docs.rs/rune-kmeans)
[![license](https://img.shields.io/crates/l/rune-kmeans)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

## What it does

Clusters a set of numeric vectors into `k` groups using the K-Means algorithm with
K-Means++ initialisation. K-Means++ spreads the initial centroids across the data,
reducing the chance of a poor local minimum compared to random initialisation.
Multiple independent restarts (`n_init`) are run and the result with the lowest
inertia is returned.

## Installation

```toml
[dependencies]
rune-kmeans = "0.1"
```

The `rune-kmeans` command-line tool is behind the opt-in `cli` feature:

```bash
cargo install rune-kmeans --features cli
```

## Usage

```rust
use rune_kmeans::{KMeans, Metric};

let points = vec![
    vec![1.0, 1.0], vec![1.2, 0.9], vec![0.9, 1.1],
    vec![9.0, 9.0], vec![9.1, 8.9], vec![8.8, 9.2],
];

let result = KMeans::new(2)
    .max_iter(300)
    .tol(1e-4)
    .n_init(10)
    .metric(Metric::Euclidean)
    .random_seed(42)
    .fit(&points);

println!("inertia: {:.4}", result.inertia);
for (i, label) in result.labels.iter().enumerate() {
    println!("point {i} → cluster {label}");
}
```

## CLI

```bash
rune-kmeans data.csv --k 3
rune-kmeans data.csv --k 5 --metric manhattan --n-init 20 --seed 7
cat data.csv | rune-kmeans - --k 3
```

## Output

One label per line (0-indexed cluster index), followed by a summary on stderr:

```
0
0
0
1
1
1
# 6 points → 2 clusters, inertia=0.042
```

## License

MIT
