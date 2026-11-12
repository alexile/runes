# rune-pagerank

> Score graph nodes by importance via random-walk convergence.

[![crates.io](https://img.shields.io/crates/v/rune-pagerank)](https://crates.io/crates/rune-pagerank)
[![docs.rs](https://img.shields.io/docsrs/rune-pagerank)](https://docs.rs/rune-pagerank)
[![license](https://img.shields.io/crates/l/rune-pagerank)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

## What it does

Computes PageRank (Brin & Page, 1998) on any weighted directed graph. A virtual random
surfer follows outgoing edges with probability `d` (the damping factor) and teleports
uniformly to any node with probability `1 − d`. The stationary distribution of that
walk assigns each node a score proportional to the importance of the nodes pointing to
it. Used by search engines, citation networks, social graphs, and dependency analysis
tools to rank nodes without requiring labelled data.

## Installation

```toml
[dependencies]
rune-pagerank = "0.1"
```

The `rune-pagerank` command-line tool is behind the opt-in `cli` feature:

```bash
cargo install rune-pagerank --features cli
```

## Usage

```rust
use rune_pagerank::PageRank;

// Star graph: nodes 1, 2, 3 all point to hub node 0
let edges = [(1, 0, 1.0), (2, 0, 1.0), (3, 0, 1.0)];
let result = PageRank::new().rank(4, &edges);

assert!(result.converged);
println!("hub score: {:.4}", result.scores[0]);
```

Tune the algorithm:

```rust
use rune_pagerank::PageRank;

let edges = [(0, 1, 2.0), (1, 2, 1.0), (2, 0, 1.0)];
let result = PageRank::new()
    .damping(0.90)
    .max_iter(200)
    .tol(1e-9)
    .rank(3, &edges);

println!("converged in {} iterations", result.iterations);
for (i, score) in result.scores.iter().enumerate() {
    println!("node {i}: {score:.6}");
}
```

## CLI

Edge list format: one edge per line — `from to [weight]` — space or comma separated.
Node indices start at zero. The weight field is optional and defaults to `1.0`.

```bash
rune-pagerank graph.txt                    # default damping 0.85
rune-pagerank graph.txt --damping 0.90     # custom damping factor
rune-pagerank graph.txt --max-iter 200     # raise iteration cap
cat edges.csv | rune-pagerank -            # read from stdin
```

## Output

One scored node per line on stdout (`node_index<TAB>score`). Summary to stderr.

```
0       0.368293
1       0.213952
2       0.213952
3       0.203803
# 4 nodes → converged in 42 iterations
```

## License

MIT
