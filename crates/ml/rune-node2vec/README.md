# rune-node2vec

> Graph node embeddings via biased random walks and skip-gram.

[![crates.io](https://img.shields.io/crates/v/rune-node2vec)](https://crates.io/crates/rune-node2vec)
[![docs.rs](https://img.shields.io/docsrs/rune-node2vec)](https://docs.rs/rune-node2vec)
[![license](https://img.shields.io/crates/l/rune-node2vec)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

## What it does

`rune-node2vec` implements the Node2Vec algorithm (Grover & Leskovec, 2016) to learn
continuous vector representations for every node in an undirected graph. The two
hyperparameters `p` and `q` bias the random walk between local-neighbourhood (BFS) and
global-exploration (DFS) strategies, making the embeddings useful for link prediction,
node classification, and community detection.

## Installation

```toml
[dependencies]
rune-node2vec = "0.1"
```

The `rune-node2vec` command-line tool is behind the opt-in `cli` feature:

```bash
cargo install rune-node2vec --features cli
```

## Usage

```rust
use rune_node2vec::Node2Vec;

// Two triangles with no edges between them.
let edges = vec![(0,1),(1,2),(2,0), (3,4),(4,5),(5,3)];

let result = Node2Vec::new()
    .embedding_dim(32)
    .num_walks(10)
    .walk_length(20)
    .n_epochs(5)
    .random_seed(42)
    .fit(6, &edges);

assert_eq!(result.embeddings.len(), 6);
assert_eq!(result.embeddings[0].len(), 32);
```

## CLI

```bash
# basic use — one edge `u v` per line
rune-node2vec graph.edgelist

# stdin, custom parameters
cat graph.edgelist | rune-node2vec - --dim 64 --epochs 5 --p 0.5 --q 2.0

# all options
rune-node2vec graph.edgelist \
  --dim 128 --walk-length 80 --num-walks 10 \
  --window 10 --p 1.0 --q 1.0 --epochs 1 --lr 0.025 --neg-samples 5 --seed 42
```

## Output

Each line is one node's embedding — tab-separated floats, one line per node in ascending
index order. A summary is written to stderr.

```
0.012345	-0.034567	0.056789	...
-0.023456	0.045678	-0.012345	...
# 6 nodes → 128-dim embeddings
```

## License

MIT
