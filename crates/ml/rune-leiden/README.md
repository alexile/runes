# rune-leiden

> Leiden community detection — find densely-connected clusters in weighted graphs.

[![crates.io](https://img.shields.io/crates/v/rune-leiden)](https://crates.io/crates/rune-leiden)
[![docs.rs](https://img.shields.io/docsrs/rune-leiden)](https://docs.rs/rune-leiden)
[![license](https://img.shields.io/crates/l/rune-leiden)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

## What it does

`rune-leiden` partitions the nodes of a weighted undirected graph into communities that
maximise the Newman–Girvan modularity Q. It implements the Leiden algorithm (Traag,
Waltman & van Eck, 2019), which improves on Louvain by adding a per-community refinement
phase that prevents poorly-connected nodes from being trapped in the wrong community.
Security researchers and data scientists use it to detect cohesive subgroups in network
data, call graphs, trust graphs, and social networks.

## Installation

```toml
[dependencies]
rune-leiden = "0.1"
```

The `rune-leiden` command-line tool is behind the opt-in `cli` feature:

```bash
cargo install rune-leiden --features cli
```

## Usage

```rust
use rune_leiden::Leiden;

// Two fully-connected triangles joined by a weak bridge
let edges = vec![
    (0, 1, 1.0), (1, 2, 1.0), (0, 2, 1.0),
    (3, 4, 1.0), (4, 5, 1.0), (3, 5, 1.0),
    (2, 3, 0.01),
];

let result = Leiden::new().fit(6, &edges);
assert_eq!(result.n_communities, 2);
println!("modularity: {:.4}", result.modularity);

for (node, community) in result.communities.iter().enumerate() {
    println!("node {node} → community {community}");
}
```

### Tuning the resolution

The resolution parameter `γ` controls granularity. Higher values split into more,
smaller communities; lower values merge into fewer, larger ones.

```rust
use rune_leiden::Leiden;

let edges = vec![(0, 1, 1.0), (1, 2, 1.0), (2, 3, 1.0), (3, 0, 1.0)];

// Fine-grained
let fine = Leiden::new().resolution(2.0).fit(4, &edges);

// Coarse
let coarse = Leiden::new().resolution(0.5).fit(4, &edges);
```

## CLI

```bash
rune-leiden edges.txt                          # default resolution 1.0
rune-leiden edges.txt --resolution 0.5        # coarser communities
rune-leiden edges.txt --seed 123              # deterministic
cat edges.txt | rune-leiden -                 # stdin
```

Edge list format — one edge per line, whitespace or comma separated:

```
# u  v  [weight]   — weight defaults to 1.0 if omitted
0 1 1.0
1 2 1.0
0 2 1.0
```

## Output

Each line of stdout is the community id (0-indexed) for the corresponding input node
(node 0, node 1, …). Community ids are contiguous integers starting at 0.

```
$ echo -e "0 1\n1 2\n0 2\n3 4\n4 5\n3 5\n2 3 0.01" | rune-leiden -
0
0
0
1
1
1
# 6 nodes → 2 communities  modularity 0.498336
```

## License

MIT
