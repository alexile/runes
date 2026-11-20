//! Model evaluation metrics, the runes counterpart of `sklearn.metrics`.
//!
//! | Group | Functions |
//! |-------|-----------|
//! | Classification | [`accuracy_score`], [`balanced_accuracy_score`], [`precision_score`], [`recall_score`], [`f1_score`], [`fbeta_score`], [`precision_recall_fscore_support`], [`confusion_matrix`], [`classification_report`], [`matthews_corrcoef`], [`cohen_kappa_score`] |
//! | Probabilities | [`log_loss`], [`brier_score_loss`] |
//! | Ranking | [`roc_curve`], [`roc_auc_score`], [`precision_recall_curve`], [`average_precision_score`] |
//! | Regression | [`mean_absolute_error`], [`mean_squared_error`], [`root_mean_squared_error`], [`r2_score`], [`explained_variance_score`], [`mean_absolute_percentage_error`], [`median_absolute_error`], [`max_error`] |
//! | Clustering | [`silhouette_score`], [`silhouette_samples`], [`adjusted_rand_score`], [`mutual_info_score`], [`normalized_mutual_info_score`], [`adjusted_mutual_info_score`], [`davies_bouldin_score`], [`calinski_harabasz_score`] |
//!
//! Results match scikit-learn (the tests pin values computed with it), with
//! these conventions:
//!
//! - **Labels.** Classification labels are any `Ord + Clone` type (integers,
//!   strings, enums, `bool`); classes are ordered by sorting, as scikit-learn
//!   does. Clustering labels only need `Eq + Hash`, and the two labelings may
//!   use different types. Ranking metrics take `y_true: &[bool]` (map your
//!   labels with `l == pos_label`).
//! - **Floats.** Scores, targets and features are `f32` or `f64`
//!   ([`rune_ml_core::Float`]); results are `f64`, accumulated with
//!   compensated (Neumaier) summation.
//! - **Errors.** Empty input, length mismatch, `NaN`/`inf` values and invalid
//!   parameters return a [`MetricsError`] instead of panicking or producing
//!   `NaN`. Where scikit-learn only warns and returns a placeholder (ROC with
//!   one class, average precision without positives, R² of one sample) this
//!   crate returns an error.
//! - **Zero division.** [`ZeroDivision`] mirrors scikit-learn's
//!   `zero_division`: precision of a never-predicted class, recall of an
//!   absent class, and so on are `0.0` by default, or `1.0` / `NaN`.
//!
//! # Example
//!
//! ```
//! use rune_ml_metrics::{f1_score, roc_auc_score, r2_score, Average, ZeroDivision};
//!
//! let y_true = ["cat", "dog", "dog", "bird", "cat"];
//! let y_pred = ["cat", "dog", "cat", "bird", "cat"];
//! let f1 = f1_score(&y_true, &y_pred, &Average::Macro, ZeroDivision::Zero)?;
//! assert!((f1 - 0.822_222_222_222_222_3).abs() < 1e-12);
//!
//! let auc = roc_auc_score(&[false, false, true, true], &[0.1, 0.4, 0.35, 0.8])?;
//! assert_eq!(auc, 0.75);
//!
//! let r2 = r2_score(&[3.0_f32, -0.5, 2.0, 7.0], &[2.5, 0.0, 2.0, 8.0])?;
//! assert!((r2 - 0.9486).abs() < 1e-4);
//! # Ok::<(), rune_ml_metrics::MetricsError>(())
//! ```
//!
//! # Features
//!
//! * `rayon` — parallel [`silhouette_samples`] / [`silhouette_score`].

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![allow(
    clippy::many_single_char_names,
    clippy::similar_names,
    clippy::suboptimal_flops,
    reason = "formulas follow the usual math notation (tp, fp, p, r, ...)"
)]

mod classification;
mod clustering;
mod error;
mod probability;
mod ranking;
mod regression;
mod util;

pub use classification::{
    Average, AverageReport, ClassReport, ClassScores, ClassificationReport, ConfusionMatrix,
    KappaWeights, ZeroDivision, accuracy_score, balanced_accuracy_score, classification_report,
    cohen_kappa_score, confusion_matrix, confusion_matrix_with_labels, f1_score, fbeta_score,
    matthews_corrcoef, precision_recall_fscore_support, precision_score, recall_score,
};
pub use clustering::{
    AverageMethod, adjusted_mutual_info_score, adjusted_rand_score, calinski_harabasz_score,
    davies_bouldin_score, mutual_info_score, normalized_mutual_info_score, silhouette_samples,
    silhouette_score,
};
pub use error::{MetricsError, Result};
pub use probability::{brier_score_loss, log_loss};
pub use ranking::{
    PrecisionRecallCurve, RocCurve, average_precision_score, precision_recall_curve, roc_auc_score,
    roc_curve,
};
pub use regression::{
    explained_variance_score, max_error, mean_absolute_error, mean_absolute_percentage_error,
    mean_squared_error, median_absolute_error, r2_score, root_mean_squared_error,
};
pub use rune_ml_core::{Float, MatrixView, Metric};
