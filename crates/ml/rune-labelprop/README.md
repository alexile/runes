# rune-labelprop

> Semi-supervised node classification via iterative neighbourhood smoothing.

[![crates.io](https://img.shields.io/crates/v/rune-labelprop)](https://crates.io/crates/rune-labelprop)
[![docs.rs](https://img.shields.io/docsrs/rune-labelprop)](https://docs.rs/rune-labelprop)
[![license](https://img.shields.io/crates/l/rune-labelprop)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

## What it does

Label propagation (Zhu & Ghahramani, 2002) classifies unlabelled graph nodes by spreading
known labels through edges. Each unknown node takes the weighted average of its neighbours'
label distributions each iteration; seed nodes are clamped to their original one-hot
distributions throughout. Useful for citation networks, social graphs, fraud detection, and
any domain where a small fraction of nodes are labelled and the rest should be inferred from
connectivity.

## Installation

```toml
[dependencies]
rune-labelprop = "0.1"
```

The `rune-labelprop` command-line tool is behind the opt-in `cli` feature:

```bash
cargo install rune-labelprop --features cli
```

## Usage

```rust
use rune_labelprop::LabelProp;

// Line graph: 0 -- 1 -- 2 -- 3
// Nodes 0 and 3 are seeds; 1 and 2 are unknown.
let edges = vec![(0, 1, 1.0), (1, 2, 1.0), (2, 3, 1.0)];
let seed_labels = vec![0, -1, -1, 1];

let result = LabelProp::new().propagate(4, &edges, &seed_labels);
println!("{:?}", result.labels); // [0, 0, 1, 1]
println!("converged: {} in {} iters", result.converged, result.iterations);
```

Tuning convergence:

```rust
use rune_labelprop::LabelProp;

let result = LabelProp::new()
    .max_iter(500)
    .tol(1e-6)
    .propagate(4, &[(0, 1, 1.0), (1, 2, 1.0), (2, 3, 1.0)], &[0, -1, -1, 1]);
assert!(result.converged);
```

## CLI

Prepare two plain-text files:

**edges.txt** — one edge per line: `u v [weight]`
```
0 1 1.0
1 2 1.0
2 3 1.0
```

**labels.txt** — one label per line (0-indexed nodes, -1 for unknown)
```
0
-1
-1
1
```

Run:

```bash
rune-labelprop --edges edges.txt --labels labels.txt
rune-labelprop --edges edges.txt --labels labels.txt --max-iter 500 --tol 1e-6
```

## Output

```
0
0
1
1
# 4 nodes → 2 classes labelled 4, unknown 0 (iters=3, converged=true)
```

Each line of stdout is the predicted label for node N. Nodes unreachable from any seed
print `-1`. The summary line goes to stderr.

## License

MIT
