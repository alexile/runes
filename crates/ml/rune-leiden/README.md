# rune-leiden

> Leiden and Louvain community detection — find densely-connected clusters in weighted graphs.

[![crates.io](https://img.shields.io/crates/v/rune-leiden)](https://crates.io/crates/rune-leiden)
[![docs.rs](https://img.shields.io/docsrs/rune-leiden)](https://docs.rs/rune-leiden)
[![license](https://img.shields.io/crates/l/rune-leiden)](LICENSE)

## What it does

`rune-leiden` partitions the nodes of a weighted undirected graph into communities. Two
algorithms are included:

- **Leiden** (Traag, Waltman & van Eck, 2019) adds a refinement step to Louvain, so every
  community it returns is connected.
- **Louvain** (Blondel, Guillaume, Lambiotte & Lefebvre, 2008) is the classic multi-level
  method. It is slightly cheaper, but it can occasionally return a community that is
  internally disconnected.

Both maximise either Newman–Girvan **modularity** with a resolution parameter `γ`, or the
**Constant Potts Model** (CPM), which avoids modularity's resolution limit. Both are
deterministic for a given seed, can return the partition at every aggregation level, and
have no dependencies.

Typical uses include finding cohesive subgroups in social networks, call graphs, trust
graphs and similarity graphs.

## Installation

```toml
[dependencies]
rune-leiden = "0.2"
```

The `rune-leiden` command-line tool is behind the opt-in `cli` feature:

```bash
cargo install rune-leiden --features cli
```

## Usage

```rust
use rune_leiden::{Leiden, Louvain};

// Two fully-connected triangles joined by a weak bridge
let edges = vec![
    (0, 1, 1.0), (1, 2, 1.0), (0, 2, 1.0),
    (3, 4, 1.0), (4, 5, 1.0), (3, 5, 1.0),
    (2, 3, 0.01),
];

let result = Leiden::new().random_seed(7).try_fit(6, &edges)?;
assert_eq!(result.n_communities, 2);
assert_eq!(result.communities(), vec![vec![0, 1, 2], vec![3, 4, 5]]);
println!("modularity: {:.4}", result.modularity);

let result = Louvain::new().random_seed(7).try_fit(6, &edges)?;
assert_eq!(result.n_communities, 2);
```

`result.communities` holds one community id per node (contiguous from 0) and
`result.communities()` returns the members of each community.

### Scoring a partition

```rust
use rune_leiden::{cpm, modularity};

let edges = [
    (0, 1, 1.0), (1, 2, 1.0), (0, 2, 1.0),
    (3, 4, 1.0), (4, 5, 1.0), (3, 5, 1.0),
];
let q = modularity(6, &edges, &[0, 0, 0, 1, 1, 1], 1.0)?; // γ = 1
assert!((q - 0.5).abs() < 1e-12);

let h = cpm(6, &edges, &[0, 0, 0, 1, 1, 1], 0.5)?;        // 2 × (3 − 0.5 × 3)
assert!((h - 3.0).abs() < 1e-12);
```

### Resolution and quality

`γ` controls granularity. With modularity, higher values give more, smaller communities.
With CPM, `γ` is a density threshold: communities end up denser than `γ` inside and
sparser than `γ` between them.

```rust
use rune_leiden::{Leiden, Quality};

let edges = vec![(0, 1, 1.0), (1, 2, 1.0), (2, 3, 1.0), (3, 0, 1.0)];

let fine = Leiden::new().resolution(2.0).try_fit(4, &edges)?;
let coarse = Leiden::new().resolution(0.5).try_fit(4, &edges)?;
let dense = Leiden::new().quality(Quality::Cpm).resolution(0.3).try_fit(4, &edges)?;
```

### Hierarchy

`fit_hierarchy` returns the partition after every aggregation level, finest first. For
Louvain each level merges whole communities of the previous one (a dendrogram). Leiden
aggregates refined sub-communities, so its levels are not always strictly nested.

```rust
use rune_leiden::Louvain;

let edges = [(0, 1, 1.0), (1, 2, 1.0), (2, 3, 1.0), (3, 0, 1.0), (3, 4, 1.0)];
let hierarchy = Louvain::new().fit_hierarchy(5, &edges)?;
for level in &hierarchy.levels {
    println!("{} communities, Q = {:.3}", level.n_communities, level.quality);
}
let best = hierarchy.best();
```

### Input rules

`try_fit`, `fit_hierarchy`, `modularity` and `cpm` return an `Error` for an empty graph
(no nodes), out-of-range node indices, negative or non-finite weights, and a negative or
non-finite resolution. Parallel edges are summed, zero-weight edges are allowed, and
self-loops are ignored everywhere. `Leiden::fit` keeps its original contract: it panics
on out-of-range indices and does not check weights.

## CLI

```bash
rune-leiden edges.txt                          # Leiden, modularity, γ = 1
rune-leiden edges.txt --resolution 0.5         # coarser communities
rune-leiden edges.txt --algorithm louvain      # Louvain instead of Leiden
rune-leiden edges.txt --quality cpm --resolution 0.1
rune-leiden edges.txt --seed 123               # deterministic
cat edges.txt | rune-leiden -                  # stdin
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
(node 0, node 1, …). Community ids are contiguous integers starting at 0. A summary line
with the modularity goes to stderr.

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
