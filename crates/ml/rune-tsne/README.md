# rune-tsne

> t-SNE dimensionality reduction — exact and Barnes-Hut t-SNE mapping high-dimensional data into 2D or 3D for visualisation.

[![crates.io](https://img.shields.io/crates/v/rune-tsne)](https://crates.io/crates/rune-tsne)
[![docs.rs](https://img.shields.io/docsrs/rune-tsne)](https://docs.rs/rune-tsne)
[![license](https://img.shields.io/crates/l/rune-tsne)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

## What it does

t-SNE (van der Maaten & Hinton 2008) is the standard way to look at clusters in
high-dimensional data: embeddings, feature vectors, fingerprints. This crate
implements it in pure Rust:

- **Exact** O(n²) t-SNE and **Barnes-Hut** t-SNE (van der Maaten 2014): sparse
  affinities over `⌊3·perplexity⌋` nearest neighbours and quadtree/octree
  repulsion in O(n log n) per iteration, tuned by `theta`. `Method::Auto` picks
  exact for up to 1000 points.
- Robust perplexity calibration: bounded bisection (200 steps) on
  minimum-shifted distances, starting at each point's own scale, so it never
  produces NaN and results do not depend on the units of the data.
- The optimisation schedule of van der Maaten (2014): early exaggeration (12×
  for 250 iterations) with momentum 0.5, then momentum 0.8, adaptive gains.
- PCA initialisation (default, via `rune-pca`) or seeded random initialisation.
- A per-iteration callback with the KL divergence and gradient norm, which can
  also stop the run.
- `trustworthiness` to score how well neighbourhoods were preserved (shared
  with `rune-umap` through `rune-ml-core`).
- Errors, not panics: too few points for the perplexity (`n ≤ 3·perplexity`),
  ragged rows, NaN/infinite values and out-of-range parameters return a
  `TsneError`.
- Deterministic for a given seed, independent of the rayon thread count.

## Installation

```toml
[dependencies]
rune-tsne = "0.3"
```

The `rune-tsne` command-line tool is behind the opt-in `cli` feature:

```bash
cargo install rune-tsne --features cli
```

## Usage

```rust
use rune_tsne::{trustworthiness, Init, Method, Metric, Tsne};

// Two well separated blobs.
let points: Vec<Vec<f64>> = (0..60)
    .map(|i| {
        let c = if i < 30 { 0.0 } else { 20.0 };
        let t = i as f64;
        vec![c + (t * 1.7).sin(), c + (t * 2.3).cos(), (t * 0.9).sin()]
    })
    .collect();

let result = Tsne::new()
    .perplexity(10.0)
    .method(Method::BarnesHut)
    .theta(0.5)
    .init(Init::Pca)
    .n_iter(500)
    .random_seed(42) // same seed + same input => bit-identical output
    .try_fit(&points)?;

let t = trustworthiness(&points, &result.embedding, 5, Metric::Euclidean)?;
assert!(t > 0.9);
println!("KL divergence: {:.4}", result.kl_divergence);
# Ok::<(), rune_tsne::TsneError>(())
```

Watching the optimisation, and stopping early:

```rust
use std::ops::ControlFlow;
use rune_tsne::Tsne;

let points: Vec<Vec<f64>> = (0..40).map(|i| vec![i as f64, (i % 4) as f64]).collect();
let result = Tsne::new().perplexity(8.0).try_fit_with(&points, |it| {
    if it.iteration % 100 == 0 {
        eprintln!("{:>4}: KL {:.4}", it.iteration, it.kl_divergence);
    }
    if it.iteration >= 400 { ControlFlow::Break(()) } else { ControlFlow::Continue(()) }
})?;
assert_eq!(result.n_iter, 401);
# Ok::<(), rune_tsne::TsneError>(())
```

Defaults: 2 components, perplexity 30, 1000 iterations, `Method::Auto`,
`theta` 0.5, `Init::Pca`, early exaggeration 12 for 250 iterations, seed 42 and
a learning rate of `n_points / (4 · early_exaggeration)` (Belkina et al. 2019).

Barnes-Hut supports at most 3 output dimensions; its nearest-neighbour search
is a parallel brute-force scan (O(n²·d) once, O(n·k) memory), and the per-
iteration cost is O(n log n). The exact method needs O(n²) memory.

## CLI

```bash
rune-tsne data.csv --perplexity 30 --n-iter 1000
rune-tsne data.csv --method barnes-hut --theta 0.5 --report-every 50
rune-tsne data.csv --n-components 3 --perplexity 10 --init random --seed 7
cat data.csv | rune-tsne - --perplexity 10
```

Each output line is one embedded point with tab-separated coordinates. The
summary (and progress, with `--report-every`) goes to stderr.

## Migrating from 0.2

- `fit` is now `try_fit` (the old name remains as an alias). New
  `try_fit_with` takes a progress callback; `TsneResult` gains `n_iter` and
  `method`.
- Setters no longer clamp: zero components or iterations, a perplexity below
  1 or NaN, and a non-positive or non-finite learning rate are rejected by
  `try_fit` as `TsneError::InvalidParameter` (which replaces
  `InvalidLearningRate`).
- `NonFiniteInput { index }` is now `NonFinite { row, col, value }`, points
  with no coordinates are `NoFeatures`, and at least 4 points are required.
- The default initialisation is PCA rather than random (`.init(Init::Random)`
  restores it); random initialisation now uses the `rune-ml-core` generator,
  so embeddings for a given seed differ from 0.2.
- The automatic learning rate is `n / (4 · early_exaggeration)` without the
  floor of 50, which made small data sets unstable.
- Inputs above 1000 points use Barnes-Hut by default; set
  `.method(Method::Exact)` for the old behaviour.

## References

- L. van der Maaten, G. Hinton, *Visualizing data using t-SNE*, JMLR 9, 2008.
- L. van der Maaten, *Accelerating t-SNE using tree-based algorithms*, JMLR 15, 2014.
- A. C. Belkina et al., *Automated optimized parameters for t-SNE improve
  visualization and analysis of large datasets*, Nature Communications 10, 2019.
- D. Kobak, G. C. Linderman, *Initialization is critical for preserving global
  data structure in both t-SNE and UMAP*, Nature Biotechnology 39, 2021.
- J. Venna, S. Kaski, *Neighborhood preservation in nonlinear projection
  methods: an experimental study*, ICANN 2001.

## License

MIT
