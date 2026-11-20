# rune-ml-metrics

> Model evaluation metrics — classification, ranking (ROC/PR), regression and clustering scores matching scikit-learn

[![crates.io](https://img.shields.io/crates/v/rune-ml-metrics)](https://crates.io/crates/rune-ml-metrics)
[![docs.rs](https://img.shields.io/docsrs/rune-ml-metrics)](https://docs.rs/rune-ml-metrics)
[![license](https://img.shields.io/crates/l/rune-ml-metrics)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

## What it does

The `sklearn.metrics` toolbox for Rust. Every function returns the same
number as scikit-learn (the tests pin values computed with scikit-learn 1.9),
validates its input, and returns a `Result` instead of panicking or quietly
producing `NaN`.

| Group | Functions |
|-------|-----------|
| Classification | `accuracy_score`, `balanced_accuracy_score`, `precision_score`, `recall_score`, `f1_score`, `fbeta_score`, `precision_recall_fscore_support`, `confusion_matrix`, `classification_report`, `matthews_corrcoef`, `cohen_kappa_score` |
| Probabilities | `log_loss`, `brier_score_loss` |
| Ranking | `roc_curve`, `roc_auc_score`, `precision_recall_curve`, `average_precision_score` |
| Regression | `mean_absolute_error`, `mean_squared_error`, `root_mean_squared_error`, `r2_score`, `explained_variance_score`, `mean_absolute_percentage_error`, `median_absolute_error`, `max_error` |
| Clustering | `silhouette_score`, `silhouette_samples`, `adjusted_rand_score`, `mutual_info_score`, `normalized_mutual_info_score`, `adjusted_mutual_info_score`, `davies_bouldin_score`, `calinski_harabasz_score` |

## Installation

```toml
[dependencies]
rune-ml-metrics = "0.1"
```

Optional features:

- `rayon` — parallel silhouette (rows in parallel, same result).

## Usage

```rust
use rune_ml_metrics::{
    classification_report, f1_score, roc_auc_score, r2_score, Average, ZeroDivision,
};

let y_true = ["cat", "dog", "dog", "bird", "cat"];
let y_pred = ["cat", "dog", "cat", "bird", "cat"];
let f1 = f1_score(&y_true, &y_pred, &Average::Macro, ZeroDivision::Zero)?;
assert!((f1 - 0.8222).abs() < 1e-4);

// Same table as sklearn; `{:.4}` for four digits.
println!("{}", classification_report(&y_true, &y_pred, ZeroDivision::Zero)?);

// Ranking metrics take bool targets; ties count one half.
let auc = roc_auc_score(&[false, false, true, true], &[0.1, 0.4, 0.35, 0.8])?;
assert_eq!(auc, 0.75);

// f32 or f64.
let r2 = r2_score(&[3.0_f32, -0.5, 2.0, 7.0], &[2.5, 0.0, 2.0, 8.0])?;
assert!((r2 - 0.9486).abs() < 1e-4);
# Ok::<(), rune_ml_metrics::MetricsError>(())
```

Clustering metrics take a `rune_ml_core` matrix view:

```rust
use rune_ml_core::{Matrix, Metric};
use rune_ml_metrics::{adjusted_rand_score, silhouette_score};

let x = Matrix::from_rows(&[[0.0, 0.0], [0.0, 1.0], [10.0, 0.0], [10.0, 1.0]])?;
let labels = [0, 0, 1, 1];
assert!(silhouette_score(x.view(), &labels, Metric::Euclidean)? > 0.9);
assert_eq!(adjusted_rand_score(&labels, &["a", "a", "b", "b"])?, 1.0);
# Ok::<(), Box<dyn std::error::Error>>(())
```

## Conventions

- **Labels.** Classification labels are any `Ord + Clone` type; classes are
  sorted, as in scikit-learn. Clustering labels need only `Eq + Hash`, and the
  two labelings may differ in type. Ranking metrics take `&[bool]`.
- **Zero division.** `ZeroDivision::{Zero, One, Nan}` mirrors scikit-learn's
  `zero_division`. `Zero` is the default (sklearn's `"warn"` without the
  warning). With `Nan`, undefined classes are left out of the averages.
- **Errors.** Empty input, length mismatch, `NaN`/`inf`, probabilities outside
  `[0, 1]` and bad parameters are errors. Where scikit-learn only warns (ROC
  with a single class, average precision without positives, R² of one sample)
  this crate returns an error too.
- **Accuracy.** Sums use compensated (Neumaier) summation in `f64`; ROC AUC
  and MCC use exact integer arithmetic.
- **Cost.** Silhouette is `O(n²·d)` time and `O(n + k)` memory. Adjusted mutual
  information is `O(Σ min(aᵢ, bⱼ))` over cluster sizes. Everything else is
  `O(n log n)` or better; `confusion_matrix` allocates `k²` counters.

## License

MIT
