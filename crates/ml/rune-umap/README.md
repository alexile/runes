# rune-umap

> UMAP dimensionality reduction — project high-dimensional data into 2D or nD embeddings.

[![crates.io](https://img.shields.io/crates/v/rune-umap)](https://crates.io/crates/rune-umap)
[![docs.rs](https://img.shields.io/docsrs/rune-umap)](https://docs.rs/rune-umap)
[![license](https://img.shields.io/crates/l/rune-umap)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

## What it does

UMAP (Uniform Manifold Approximation and Projection) maps high-dimensional points into a
lower-dimensional space while preserving both local neighbourhood structure and global
topology. It is widely used for visualising embeddings, finding clusters, and as a
preprocessing step before classification. Unlike t-SNE, UMAP preserves more global
structure and runs faster.

## Installation

```toml
[dependencies]
rune-umap = "0.2"
```

The `rune-umap` command-line tool is behind the opt-in `cli` feature:

```bash
cargo install rune-umap --features cli
```

## Usage

```rust
use rune_umap::{Metric, Umap, UmapError};

fn embed(points: &[Vec<f64>]) -> Result<(), UmapError> {
    let fitted = Umap::new()
        .n_neighbors(15)     // neighbourhood size — controls local vs global structure
        .min_dist(0.1)       // minimum distance between output points
        .n_epochs(500)       // SGD iterations
        .metric(Metric::Euclidean)
        .random_seed(42)     // identical seeds give identical embeddings
        .try_fit(points)?;   // validates input instead of panicking

    for (i, coords) in fitted.embedding.iter().enumerate() {
        println!("point {i}: {:.3} {:.3}", coords[0], coords[1]);
    }

    // Embed unseen points into the same space.
    let new = fitted.try_transform(&points[..2])?;
    assert_eq!(new.len(), 2);
    Ok(())
}
```

### Validation

The `try_*` methods (`try_fit`, `try_fit_supervised`, `fit_semi_supervised`,
`try_transform`) return a `UmapError` for empty input, rows without features,
ragged rows, `NaN`/infinite values, `n_neighbors ≥ n_samples`, mismatched label
counts and non-finite parameters. The original `fit`, `fit_supervised` and
`transform` are kept for compatibility and panic on the same conditions.

### Supervised and semi-supervised

```rust
use rune_umap::Umap;

let points = vec![
    vec![0.0, 0.0], vec![0.1, 0.1], vec![0.0, 0.1],
    vec![5.0, 5.0], vec![5.1, 5.0], vec![5.0, 5.1],
];
let labels = [0i64, 0, 0, 1, 1, 1];
let sup = Umap::new().n_neighbors(2).try_fit_supervised(&points, &labels)?;

// `None` marks an unlabelled point.
let partial = [Some(0), None, Some(0), Some(1), None, None];
let semi = Umap::new().n_neighbors(2).fit_semi_supervised(&points, &partial)?;
```

### Measuring quality

`trustworthiness(high, low, k, metric)` scores how faithfully the embedding
keeps each point's `k` nearest neighbours (1.0 = perfect), matching
`sklearn.manifold.trustworthiness`. It wraps the shared implementation in
`rune-ml-core`, so scores line up with `rune-tsne` and `rune-pca`.

### Standalone kNN graphs

The neighbour search UMAP uses is public in the `knn` module, for code that
needs a k-nearest-neighbour graph without an embedding (density clustering,
neighbour lists for t-SNE, label propagation):

```rust
use rune_umap::{knn, Metric};

let points: Vec<Vec<f64>> = (0..1000)
    .map(|i| vec![f64::from(i % 40), f64::from(i / 40)])
    .collect();

// Exact search up to 4096 points, NN-Descent above; seeded and deterministic.
let graph = knn::knn_graph(&points, 10, Metric::Euclidean, 42)?;
assert_eq!(graph[0].len(), 10); // (index, distance) pairs, nearest first

// Force NN-Descent and check it against the exact answer.
let approx = knn::nn_descent(&points, 10, Metric::Euclidean, 10, 42)?;
let truth = knn::exact(&points, 10, Metric::Euclidean)?;
assert!(knn::recall(&approx, &truth) > 0.9);
```

`knn_graph_with` takes an explicit `KnnMethod` and iteration cap. Inputs are
validated the same way as `try_fit` (empty, ragged, non-finite, `k = 0`,
`k ≥ n`).

## Key parameters

| Parameter | Default | Effect |
|---|---|---|
| `n_neighbors` | 15 | Neighbourhood size. Lower = finer local detail; higher = more global structure. |
| `min_dist` | 0.1 | Packing of output points. `0.0` = dense clusters; `1.0` = spread out. |
| `n_components` | 2 | Output dimensions. |
| `spread` | 1.0 | Scale of the embedded space; works with `min_dist`. |
| `n_epochs` | 500 / 200 | SGD iterations. More = better quality, slower. |
| `metric` | `Euclidean` | `Euclidean`, `Manhattan`, `Cosine` or `Correlation`. |
| `knn_method` | `Auto` | `Exact` (brute force), `NnDescent` (approximate), or `Auto` (exact up to 4096 points). |
| `target_weight` | 0.5 | Weight of the label graph in (semi-)supervised mode. |
| `spectral_init` | true | Spectral initialisation; falls back to random on disconnected graphs. |
| `random_seed` | 42 | Controls initialisation, NN-Descent and negative sampling. |

## CLI

```bash
rune-umap data.csv --n-neighbors 15
rune-umap data.csv --n-neighbors 15 --n-components 3 --metric correlation
cat data.csv | rune-umap - --n-neighbors 10 --min-dist 0.05
```

Input: one point per line, space or comma separated:

```
0.42 1.37 2.91
0.51 1.22 2.88
9.14 0.03 7.56
```

## Output

One embedded point per line, tab-separated coordinates. Summary goes to stderr.

```
$ rune-umap blobs.csv --n-neighbors 5 --n-epochs 500
-3.241156   2.874012
-3.109438   2.651034
...
7.443021   -4.220811
# 30 points → 2D embedding
```

## Algorithm

1. **k-NN graph** — exact brute-force search for small inputs, NN-Descent
   (forward and reverse neighbour exploration) for large ones, parallelised with
   rayon and deterministic regardless of thread count. Available on its own as
   `rune_umap::knn`.
2. **Fuzzy simplicial set** — per point, `ρ` is the distance to the nearest
   non-duplicate neighbour and `σ` is binary-searched so membership strengths
   sum to `log₂(k)`; the directed graph is symmetrised via fuzzy union
   (optionally merged with a label graph).
3. **Parameter fitting** — fit curve parameters `a` and `b` from `min_dist` and
   `spread` using Adam over 300 sample points.
4. **Layout** — spectral initialisation from the normalised graph Laplacian (or
   random), then SGD with attractive forces along graph edges and repulsive
   forces to sampled negative pairs; the learning rate decays linearly to 0.

## License

MIT
