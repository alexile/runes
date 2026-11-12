# rune-ml-core

> Shared ML core: row-major matrices, distance metrics, deterministic RNG and estimator traits

[![crates.io](https://img.shields.io/crates/v/rune-ml-core)](https://crates.io/crates/rune-ml-core)
[![docs.rs](https://img.shields.io/docsrs/rune-ml-core)](https://docs.rs/rune-ml-core)
[![license](https://img.shields.io/crates/l/rune-ml-core)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

The common foundation for the runes ML crates (k-means, HDBSCAN, t-SNE,
UMAP, …), so each algorithm stops re-implementing its own distance
functions, PRNG and `Vec<Vec<f64>>` plumbing.

| Item | What it is |
|------|------------|
| `Float` | Sealed scalar trait for `f32` / `f64` |
| `Matrix<F>`, `MatrixView<'a, F>` | Owned / borrowed row-major dense matrix over one flat buffer |
| `Metric` | `Euclidean`, `SqEuclidean`, `Manhattan`, `Cosine`, `Chebyshev`, with `distance`, `pairwise`, `cdist`, `nearest` |
| `kernels` | Unrolled 8-lane slice kernels (`dot`, `sq_euclidean`, `manhattan`, `cosine`, …) that LLVM auto-vectorises |
| `Rng`, `SplitMix64` | Reproducible xoshiro256++ seeded by SplitMix64; `uniform`, `below`, `normal`, `shuffle`, `sample_indices`, `weighted_index`, `jump`, `fork` |
| `Fit`, `Predict`, `Transform`, `FitPredict`, `FitTransform` | Estimator traits: configuration → `fit` → model |
| `MlError` | Shared error enum, meant to be wrapped by each crate's own error |

## Installation

```toml
[dependencies]
rune-ml-core = "0.1"
```

Optional features:

- `serde` — serialize `Matrix` (shape validated on load), `Metric`, `Rng`.
- `rayon` — parallel `Metric::pairwise` / `Metric::cdist` and `par_rows()`.

## Usage

```rust
use rune_ml_core::{Matrix, Metric, Rng};

// Migrate from nested vectors in one call (f64 -> f32 with `from_rows_cast`).
let points = vec![vec![0.0, 0.0], vec![3.0, 4.0], vec![1.0, 1.0]];
let x = Matrix::from_rows(&points)?;

let d = Metric::Euclidean.pairwise(x.view())?;
assert_eq!(d[(0, 1)], 5.0);

let mut rng = Rng::new(42);
let sample = x.select_rows(&rng.sample_indices(x.nrows(), 2))?;
assert_eq!(sample.shape(), (2, 2));
# Ok::<(), rune_ml_core::MlError>(())
```

### Writing an estimator

```rust
use rune_ml_core::{Fit, MatrixView, MlError, Predict, Metric};

struct Centroid;
struct Model(Vec<f64>);

impl Fit<MatrixView<'_, f64>> for Centroid {
    type Model = Model;
    type Error = MlError;
    fn fit(&self, x: &MatrixView<'_, f64>) -> Result<Model, MlError> {
        Ok(Model(x.column_means()))
    }
}

impl Predict<MatrixView<'_, f64>> for Model {
    type Output = Vec<f64>;
    type Error = MlError;
    fn predict(&self, x: &MatrixView<'_, f64>) -> Result<Vec<f64>, MlError> {
        Ok(x.rows().map(|r| Metric::Euclidean.distance(r, &self.0)).collect())
    }
}
```

Guidelines for algorithm crates:

- Take input as `MatrixView<'_, F>` (callers pass `matrix.view()` or wrap a
  slice with `MatrixView::new`), return `Matrix<F>` for dense output.
- Store a `Metric` in options; validate with `view.check_finite()`.
- Take a `u64` seed in options and build `Rng::new(seed)`; use
  `rng.fork()` / `rng.jump()` per thread to stay deterministic under `rayon`.
- Keep your crate's own `thiserror` enum and add
  `#[error(transparent)] Core(#[from] rune_ml_core::MlError)`.

## Benchmarks

```bash
cargo bench -p rune-ml-core            # kernels vs naive loops, pairwise
cargo bench -p rune-ml-core --features rayon
```

## License

MIT
