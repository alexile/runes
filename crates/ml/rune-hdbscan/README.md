# rune-hdbscan

> HDBSCAN clustering — hierarchical density-based clustering with automatic noise detection.

[![crates.io](https://img.shields.io/crates/v/rune-hdbscan)](https://crates.io/crates/rune-hdbscan)
[![docs.rs](https://img.shields.io/docsrs/rune-hdbscan)](https://docs.rs/rune-hdbscan)
[![license](https://img.shields.io/crates/l/rune-hdbscan)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

## What it does

HDBSCAN (Hierarchical Density-Based Spatial Clustering of Applications with Noise) finds
clusters of arbitrary shape in numeric data without requiring a fixed density threshold.
Unlike DBSCAN, it handles clusters of varying density and labels outliers as noise (`-1`).
Each point also receives a soft membership probability — how strongly it belongs to its cluster.

## Installation

```toml
[dependencies]
rune-hdbscan = "0.1"
```

The `rune-hdbscan` command-line tool is behind the opt-in `cli` feature:

```bash
cargo install rune-hdbscan --features cli
```

## Usage

```rust
use rune_hdbscan::{Hdbscan, Metric};

let points = vec![
    vec![1.0, 2.0], vec![1.5, 1.8], vec![1.2, 1.9], vec![1.3, 2.1], vec![1.1, 1.7],
    vec![8.0, 8.0], vec![8.5, 8.2], vec![8.1, 8.3], vec![8.3, 7.9], vec![8.2, 8.1],
];

let result = Hdbscan::new(3)           // min_cluster_size
    .min_samples(2)                    // core distance neighbourhood
    .metric(Metric::Euclidean)
    .fit(&points);

println!("{} cluster(s) found", result.num_clusters);
for (i, (&label, &prob)) in result.labels.iter().zip(&result.probabilities).enumerate() {
    println!("point {i:>3}: cluster {label:>2}  prob {prob:.3}");
}
```

## Key parameters

| Parameter | Default | Effect |
|---|---|---|
| `min_cluster_size` | required | Minimum points to form a cluster. Lower = more clusters. |
| `min_samples` | = `min_cluster_size` | Core distance neighbourhood. Higher = more noise. |
| `metric` | `Euclidean` | `Euclidean`, `Manhattan`, or `Cosine`. |

## CLI

```bash
rune-hdbscan data.csv --min-cluster-size 5
rune-hdbscan data.csv --min-cluster-size 5 --metric cosine --probs
cat data.csv | rune-hdbscan - --min-cluster-size 3
```

Input: one point per line, space or comma separated:

```
1.0 2.0
1.5 1.8
8.0 8.0
8.5 8.2
```

## Output

Default output: one label per line (`-1` = noise). With `--probs`: label and probability tab-separated.

```
$ rune-hdbscan data.csv --min-cluster-size 3 --probs
0       1.000000
0       0.874475
1       1.000000
1       0.874475
# 4 points → 2 cluster(s), 0 noise
```

The summary line goes to stderr so stdout is pipeline-safe.

## Algorithm

HDBSCAN builds a minimum spanning tree on the *mutual reachability graph*
(`max(core_dist(a), core_dist(b), dist(a, b))`), converts it into a cluster
hierarchy, then selects flat clusters by maximising stability bottom-up.
Runtime is O(n²) — suitable for up to ~10 000 points.

## License

MIT
