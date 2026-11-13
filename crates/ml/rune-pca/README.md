# rune-pca

> Principal component analysis — exact, randomized and incremental (batched) PCA, whitening, inverse transform

[![crates.io](https://img.shields.io/crates/v/rune-pca)](https://crates.io/crates/rune-pca)
[![docs.rs](https://img.shields.io/docsrs/rune-pca)](https://docs.rs/rune-pca)
[![license](https://img.shields.io/crates/l/rune-pca)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

Pure-Rust PCA with no BLAS/LAPACK dependency:

- **Exact solvers**: eigendecomposition of the covariance matrix (Householder
  tridiagonalisation + implicit QL) or a one-sided Jacobi SVD of the centred
  data, which never forms `XᵀX` and is accurate for ill-conditioned data.
- **Randomized SVD**: the randomized range finder with power iterations of
  Halko, Martinsson & Tropp (2011). Computes only the leading `k` components, in
  `O(n·d·k)` time.
- **Incremental PCA**: `IncrementalPca` merges one batch at a time (Ross et
  al. 2008, as scikit-learn's `IncrementalPCA`), in `O((k + b)·d)` memory, for
  data that does not fit in memory. Exact when every component is kept.
- `fit`, `transform`, `fit_transform` and `inverse_transform`.
- Explained variance, explained-variance ratio, singular values and the noise
  variance of probabilistic PCA.
- Component selection by count or by cumulative explained-variance ratio.
- Whitening (unit-variance outputs).
- Deterministic: component signs are fixed (largest loading positive), and
  results do not depend on the number of rayon threads.
- Errors, not panics, for invalid input (`PcaError`).
- Optional `serde` support for storing fitted models.

## Installation

```toml
[dependencies]
rune-pca = "0.2"
# or, to serialize fitted models:
rune-pca = { version = "0.2", features = ["serde"] }
```

The `rune-pca` command-line tool is behind the opt-in `cli` feature:

```bash
cargo install rune-pca --features cli
```

## Usage

### Library

```rust
use rune_pca::{Pca, Solver};

let x = vec![
    vec![-1.0, -1.0], vec![-2.0, -1.0], vec![-3.0, -2.0],
    vec![1.0, 1.0], vec![2.0, 1.0], vec![3.0, 2.0],
];

let (model, projected) = Pca::new(1).fit_transform(&x)?;
assert!((model.explained_variance_ratio()[0] - 0.9924).abs() < 1e-4);
assert_eq!(projected[0].len(), 1);

// Map back to the original space (the best rank-1 approximation).
let approx = model.inverse_transform(&projected)?;
assert_eq!(approx[0].len(), 2);

// Randomized SVD with whitening, for large data sets.
let model = Pca::new(1)
    .with_solver(Solver::Randomized)
    .with_whiten(true)
    .with_seed(7)
    .fit(&x)?;
assert_eq!(model.n_components(), 1);
# Ok::<(), rune_pca::PcaError>(())
```

Incremental fitting, batch by batch:

```rust
use rune_pca::IncrementalPca;

let x: Vec<Vec<f64>> = (0..100)
    .map(|i| {
        let t = f64::from(i);
        vec![t, 2.0 * t + (t * 0.3).sin(), (t * 0.7).cos()]
    })
    .collect();

let mut ipca = IncrementalPca::new(2);
for batch in x.chunks(25) {
    ipca.partial_fit(batch)?;
}
let model = ipca.model()?;
assert_eq!(model.n_samples(), 100);
assert!(model.explained_variance_ratio()[0] > 0.99);
# Ok::<(), rune_pca::PcaError>(())
```

`Solver::Auto` (the default) uses randomized SVD when `max(n, d) > 500` and
fewer than 80% of the components are requested, and an exact solver otherwise.

### CLI

```bash
# Project onto the first two principal components
rune-pca data.csv -k 2

# Keep enough components for 95% of the variance, whitened
cat data.csv | rune-pca - --variance 0.95 --whiten
```

Input is one sample per line, values separated by commas or whitespace. The
projected rows go to stdout and a summary with the explained-variance ratios
goes to stderr.

## Migrating from 0.1

- The randomized solver draws its test matrix from the `rune-ml-core`
  generator, so `Solver::Randomized` results for a given seed differ slightly
  from 0.1 (exact solvers are unchanged).
- `PcaError` gains `InvalidBatchSize` and `BatchTooSmall` (it is
  `#[non_exhaustive]`, so matches need no change).

## References

- N. Halko, P.-G. Martinsson, J. A. Tropp, *Finding structure with randomness:
  Probabilistic algorithms for constructing approximate matrix decompositions*,
  SIAM Review 53(2), 2011.
- D. A. Ross, J. Lim, R.-S. Lin, M.-H. Yang, *Incremental learning for robust
  visual tracking*, IJCV 77, 2008.
- J. Demmel, K. Veselić, *Jacobi's method is more accurate than QR*, SIAM J.
  Matrix Anal. Appl. 13(4), 1992.

## License

MIT
