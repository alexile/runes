# rune-leiden

> Leiden and Louvain community detection — find densely-connected clusters in weighted graphs.

[![crates.io](https://img.shields.io/crates/v/rune-leiden)](https://crates.io/crates/rune-leiden)
[![docs.rs](https://img.shields.io/docsrs/rune-leiden)](https://docs.rs/rune-leiden)
[![license](https://img.shields.io/crates/l/rune-leiden)](LICENSE)

## What it does

`rune-leiden` partitions the nodes of a weighted undirected graph into communities. Two
algorithms are included:

- **Leiden** (Traag, Waltman & van Eck, 2019) follows the paper's algorithm: fast local
  moving with a node queue, a randomised refinement step that only merges well-connected
  nodes and sub-communities, and aggregation of the refined partition starting from the
  unrefined one. Every community it returns is connected (in fact γ-connected), and it
  usually reaches higher quality than Louvain.
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
rune-leiden = "0.3"
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

### Leiden's randomness

During refinement a node joins one of the eligible neighbouring sub-communities (or stays
alone) with probability proportional to `exp(ΔH / θ)`, where `ΔH` is the quality gain in
edge-weight units. `θ` defaults to `0.01`, the value used in the paper; `0` makes the
choice greedy, larger values explore more. Draws come from the seeded PRNG, so a given
seed and `θ` always give the same result.

```rust
use rune_leiden::Leiden;

let edges = [(0, 1, 1.0), (1, 2, 1.0), (0, 2, 1.0), (2, 3, 1.0)];
let result = Leiden::new().randomness(0.05).random_seed(3).try_fit(4, &edges)?;
```

### Hierarchy

`fit_hierarchy` returns the partition after every aggregation level, finest first. For
Louvain each level merges whole communities of the previous one (a dendrogram). Leiden
aggregates refined sub-communities and repeats whole iterations, so its levels are not
always strictly nested; its last level is the best one and the only one guaranteed to have
connected communities.

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
non-finite resolution or Leiden randomness. Parallel edges are summed, zero-weight edges are allowed, and
self-loops are ignored everywhere. `Leiden::fit` keeps its original contract: it panics
on out-of-range indices and does not check weights.

## CLI

```bash
rune-leiden edges.txt                          # Leiden, modularity, γ = 1
rune-leiden edges.txt --resolution 0.5         # coarser communities
rune-leiden edges.txt --algorithm louvain      # Louvain instead of Leiden
rune-leiden edges.txt --quality cpm --resolution 0.1
rune-leiden edges.txt --seed 123               # deterministic
rune-leiden edges.txt --randomness 0           # greedy Leiden refinement
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

## Migrating from 0.2

The API is unchanged apart from the new `Leiden::randomness` option and
`Error::InvalidRandomness`, but **Leiden returns different partitions for the same seed**.
0.2 started every aggregation level from singletons and refined greedily. 0.3 implements
the algorithm as published: fast local moving with a queue, refinement restricted to
well-connected nodes and sub-communities with randomised merges (`θ = 0.01`), the next
level initialised from the unrefined partition, and iterations repeated until the
partition stops changing. Quality is higher as a result (on random test graphs Leiden now
beats Louvain on average, where 0.2 fell slightly behind), and communities are still
always connected. `max_iter` now caps local-moving passes over all levels and iterations.
Louvain's output is unchanged. If you stored partitions or tuned seeds against 0.2, rerun
them.

## References

- V. A. Traag, L. Waltman & N. J. van Eck, "From Louvain to Leiden: guaranteeing
  well-connected communities", *Scientific Reports* 9, 5233 (2019).
  doi:10.1038/s41598-019-41695-z
- V. D. Blondel, J.-L. Guillaume, R. Lambiotte & E. Lefebvre, "Fast unfolding of
  communities in large networks", *J. Stat. Mech.* P10008 (2008).
- U. Brandes et al., "On Modularity Clustering", *IEEE TKDE* 20(2), 172–188 (2008).

## License

MIT
