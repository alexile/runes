//! Clustering metrics: external (compare two labelings) and internal (score
//! a labeling against the data).

use std::hash::Hash;

use rune_ml_core::{Float, MatrixView, Metric};

use crate::util::{Sum, bincount, check_pair, encode_hashed, to_f64};
use crate::{MetricsError, Result};

/// Sparse contingency table of two labelings.
struct Contingency {
    n: usize,
    /// Row sums (sizes of the `labels_true` classes).
    a: Vec<usize>,
    /// Column sums (sizes of the `labels_pred` clusters).
    b: Vec<usize>,
    /// Non-zero cells `(row, col, count)`.
    cells: Vec<(usize, usize, usize)>,
}

impl Contingency {
    fn new<A: Eq + Hash, B: Eq + Hash>(labels_true: &[A], labels_pred: &[B]) -> Result<Self> {
        check_pair(labels_true, labels_pred)?;
        let (ca, ka) = encode_hashed(labels_true);
        let (cb, kb) = encode_hashed(labels_pred);
        let mut pairs: Vec<(usize, usize)> = ca.iter().copied().zip(cb.iter().copied()).collect();
        pairs.sort_unstable();
        let mut cells: Vec<(usize, usize, usize)> = Vec::new();
        for (i, j) in pairs {
            match cells.last_mut() {
                Some(c) if c.0 == i && c.1 == j => c.2 += 1,
                _ => cells.push((i, j, 1)),
            }
        }
        Ok(Self {
            n: ca.len(),
            a: bincount(&ca, ka),
            b: bincount(&cb, kb),
            cells,
        })
    }

    /// Mutual information in nats, as `sklearn.metrics.mutual_info_score`.
    fn mutual_info(&self) -> f64 {
        if self.a.len() == 1 || self.b.len() == 1 {
            return 0.0;
        }
        let n = to_f64(self.n);
        let ln_n = n.ln();
        let mut s = Sum::default();
        for &(i, j, c) in &self.cells {
            let c = to_f64(c);
            let outer = to_f64(self.a[i]) * to_f64(self.b[j]);
            // (c/n)·ln(c·n / (aᵢ·bⱼ)), with logs taken separately to avoid
            // overflow and keep precision.
            let term = c / n * (c.ln() - ln_n) + c / n * (2.0f64.mul_add(ln_n, -outer.ln()));
            if term.abs() >= f64::EPSILON {
                s.add(term);
            }
        }
        s.value().max(0.0)
    }
}

/// Entropy (nats) of a labeling given its class sizes.
fn entropy(sizes: &[usize], n: usize) -> f64 {
    if sizes.len() <= 1 {
        return 0.0;
    }
    let (n, ln_n) = (to_f64(n), to_f64(n).ln());
    let mut s = Sum::default();
    for &c in sizes {
        let c = to_f64(c);
        s.add(c / n * (c.ln() - ln_n));
    }
    -s.value()
}

/// Adjusted Rand index: pair-counting agreement between two labelings,
/// corrected for chance. `1.0` for identical partitions (up to renaming),
/// about `0.0` for random ones, and possibly negative.
///
/// The two labelings may use different label types. Pair counts are exact
/// 128-bit integers.
///
/// ```
/// use rune_ml_metrics::adjusted_rand_score;
/// assert_eq!(adjusted_rand_score(&[0, 0, 1, 1], &["b", "b", "a", "a"])?, 1.0);
/// let ari = adjusted_rand_score(&[0, 0, 1, 2], &[0, 0, 1, 1])?;
/// assert!((ari - 0.571_428_571_428_571_4).abs() < 1e-15);
/// # Ok::<(), rune_ml_metrics::MetricsError>(())
/// ```
///
/// # Errors
///
/// [`MetricsError::Empty`] or [`MetricsError::LengthMismatch`].
pub fn adjusted_rand_score<A: Eq + Hash, B: Eq + Hash>(
    labels_true: &[A],
    labels_pred: &[B],
) -> Result<f64> {
    let c = Contingency::new(labels_true, labels_pred)?;
    let sq = |v: &mut dyn Iterator<Item = usize>| -> i128 {
        v.map(|x| {
            let x = i128::try_from(x).unwrap_or(i128::MAX);
            x * x
        })
        .sum()
    };
    let n = i128::try_from(c.n).unwrap_or(i128::MAX);
    let sum_sq = sq(&mut c.cells.iter().map(|x| x.2));
    // Ordered pair counts (each unordered pair counted twice), as sklearn's
    // pair_confusion_matrix.
    let tp = sum_sq - n;
    let fp = sq(&mut c.b.iter().copied()) - sum_sq;
    let fn_ = sq(&mut c.a.iter().copied()) - sum_sq;
    let tn = n * n - fp - fn_ - sum_sq;
    if fn_ == 0 && fp == 0 {
        return Ok(1.0);
    }
    let f = crate::classification::i128_f64;
    // The products reach n⁴, beyond i128 for n > 2^31; f64 keeps ~16 digits.
    let num = f(tp).mul_add(f(tn), -(f(fn_) * f(fp)));
    let den = f(tp + fn_).mul_add(f(fn_ + tn), f(tp + fp) * f(fp + tn));
    Ok(2.0 * num / den)
}

/// Mutual information between two labelings, in nats.
///
/// # Errors
///
/// [`MetricsError::Empty`] or [`MetricsError::LengthMismatch`].
pub fn mutual_info_score<A: Eq + Hash, B: Eq + Hash>(
    labels_true: &[A],
    labels_pred: &[B],
) -> Result<f64> {
    Ok(Contingency::new(labels_true, labels_pred)?.mutual_info())
}

/// How [`normalized_mutual_info_score`] and [`adjusted_mutual_info_score`]
/// combine the two entropies into a normaliser.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AverageMethod {
    /// `min(H(U), H(V))`.
    Min,
    /// `sqrt(H(U)·H(V))`.
    Geometric,
    /// `(H(U) + H(V)) / 2`, scikit-learn's default (equal to the V-measure for NMI).
    #[default]
    Arithmetic,
    /// `max(H(U), H(V))`.
    Max,
}

impl AverageMethod {
    fn apply(self, u: f64, v: f64) -> f64 {
        match self {
            Self::Min => u.min(v),
            Self::Geometric => (u * v).sqrt(),
            Self::Arithmetic => u.midpoint(v),
            Self::Max => u.max(v),
        }
    }
}

/// Normalized mutual information, `MI / avg(H(U), H(V))`, in `[0, 1]`.
///
/// Two single-cluster labelings score `1.0`; when the mutual information is
/// zero the score is `0.0`. Not corrected for chance; see
/// [`adjusted_mutual_info_score`].
///
/// ```
/// use rune_ml_metrics::{normalized_mutual_info_score, AverageMethod};
/// let nmi = normalized_mutual_info_score(&[0, 0, 1, 1], &[0, 0, 1, 2], AverageMethod::Arithmetic)?;
/// assert!((nmi - 0.8).abs() < 1e-12);
/// # Ok::<(), rune_ml_metrics::MetricsError>(())
/// ```
///
/// # Errors
///
/// [`MetricsError::Empty`] or [`MetricsError::LengthMismatch`].
pub fn normalized_mutual_info_score<A: Eq + Hash, B: Eq + Hash>(
    labels_true: &[A],
    labels_pred: &[B],
    average_method: AverageMethod,
) -> Result<f64> {
    let c = Contingency::new(labels_true, labels_pred)?;
    if c.a.len() == 1 && c.b.len() == 1 {
        return Ok(1.0);
    }
    let mi = c.mutual_info();
    if mi == 0.0 {
        return Ok(0.0);
    }
    let norm = average_method.apply(entropy(&c.a, c.n), entropy(&c.b, c.n));
    Ok(mi / norm)
}

/// `ln(k!)`: exact table below 256, Stirling series above (error < 1e-17).
struct LnFactorial {
    table: Vec<f64>,
}

impl LnFactorial {
    const TABLE: usize = 256;

    fn new() -> Self {
        let mut table = Vec::with_capacity(Self::TABLE);
        let mut s = Sum::default();
        table.push(0.0);
        for k in 1..Self::TABLE {
            s.add(to_f64(k).ln());
            table.push(s.value());
        }
        Self { table }
    }

    fn get(&self, k: usize) -> f64 {
        if let Some(&v) = self.table.get(k) {
            return v;
        }
        let x = to_f64(k);
        let inv = 1.0 / x;
        let inv2 = inv * inv;
        let series = inv * (1.0 / 12.0 - inv2 * (1.0 / 360.0 - inv2 / 1260.0));
        x.mul_add(x.ln(), -x) + 0.5 * (core::f64::consts::TAU * x).ln() + series
    }
}

/// Expected mutual information of two random labelings with the same class
/// sizes (hypergeometric model), as scikit-learn's
/// `expected_mutual_information`. Costs `O(Σᵢⱼ min(aᵢ, bⱼ))`.
fn expected_mutual_info(c: &Contingency) -> f64 {
    if c.a.len() == 1 || c.b.len() == 1 {
        return 0.0;
    }
    let lf = LnFactorial::new();
    let n = c.n;
    let nf = to_f64(n);
    let ln_n = nf.ln();
    let gln_n = lf.get(n);
    let mut emi = Sum::default();
    for &ai in &c.a {
        let ln_a = to_f64(ai).ln();
        let gln_a = lf.get(ai) + lf.get(n - ai);
        for &bj in &c.b {
            let ln_b = to_f64(bj).ln();
            let gln_ab = gln_a + lf.get(bj) + lf.get(n - bj) - gln_n;
            let start = (ai + bj).saturating_sub(n).max(1);
            let end = ai.min(bj);
            for nij in start..=end {
                let nijf = to_f64(nij);
                let term2 = ln_n + nijf.ln() - ln_a - ln_b;
                let gln = gln_ab
                    - lf.get(nij)
                    - lf.get(ai - nij)
                    - lf.get(bj - nij)
                    - lf.get(n + nij - ai - bj);
                emi.add(nijf / nf * term2 * gln.exp());
            }
        }
    }
    emi.value()
}

/// Adjusted mutual information, `(MI − E[MI]) / (avg(H(U), H(V)) − E[MI])`:
/// mutual information corrected for chance, `1.0` for identical partitions
/// and about `0.0` for random ones.
///
/// The expected MI costs `O(Σᵢⱼ min(aᵢ, bⱼ))` over class sizes `a` and
/// cluster sizes `b`, at most `O(n·min(k_true, k_pred))`. Two single-cluster
/// labelings score `1.0`; one single-cluster labeling scores `0.0`.
///
/// ```
/// use rune_ml_metrics::{adjusted_mutual_info_score, AverageMethod};
/// let ami = adjusted_mutual_info_score(&[0, 0, 1, 1], &[1, 1, 0, 0], AverageMethod::Arithmetic)?;
/// assert!((ami - 1.0).abs() < 1e-12);
/// # Ok::<(), rune_ml_metrics::MetricsError>(())
/// ```
///
/// # Errors
///
/// [`MetricsError::Empty`] or [`MetricsError::LengthMismatch`].
pub fn adjusted_mutual_info_score<A: Eq + Hash, B: Eq + Hash>(
    labels_true: &[A],
    labels_pred: &[B],
    average_method: AverageMethod,
) -> Result<f64> {
    let c = Contingency::new(labels_true, labels_pred)?;
    match (c.a.len(), c.b.len()) {
        (1, 1) => return Ok(1.0),
        (1, _) | (_, 1) => return Ok(0.0),
        _ => {}
    }
    let mi = c.mutual_info();
    let emi = expected_mutual_info(&c);
    let norm = average_method.apply(entropy(&c.a, c.n), entropy(&c.b, c.n));
    // Keep both terms away from zero with their sign, as scikit-learn does.
    let away = |x: f64| {
        if x < 0.0 {
            x.min(-f64::EPSILON)
        } else {
            x.max(f64::EPSILON)
        }
    };
    Ok(away(mi - emi) / away(norm - emi))
}

/// Encodes cluster labels and checks `2 <= k <= n - 1`.
fn cluster_codes<F: Float, L: Eq + Hash>(
    x: MatrixView<'_, F>,
    labels: &[L],
) -> Result<(Vec<usize>, usize)> {
    if x.nrows() != labels.len() {
        return Err(MetricsError::LengthMismatch {
            expected: x.nrows(),
            found: labels.len(),
        });
    }
    if labels.is_empty() {
        return Err(MetricsError::Empty);
    }
    x.check_finite()?;
    let (codes, k) = encode_hashed(labels);
    let n = labels.len();
    if k < 2 || k >= n {
        return Err(MetricsError::label_count(format!(
            "need 2 <= n_labels <= n_samples - 1, got {k} labels for {n} samples"
        )));
    }
    Ok((codes, k))
}

/// Silhouette coefficient of every sample.
///
/// Each sample scores `(b − a) / max(a, b)`, where `a`
/// is the mean distance to the other members of its cluster and `b` the
/// mean distance to the nearest other cluster. Samples in singleton clusters
/// score `0`.
///
/// **Cost:** `O(n²·d)` time (every pair of rows is measured, twice, so rows
/// are independent) and `O(n + k)` extra memory. With the `rayon` feature
/// rows are processed in parallel; the result does not depend on the thread
/// count. For very large data, score a random subsample.
///
/// # Errors
///
/// [`MetricsError::Empty`], [`MetricsError::LengthMismatch`] (rows vs labels),
/// [`MetricsError::Core`] for a non-finite feature, or
/// [`MetricsError::InvalidLabelCount`] unless `2 <= n_labels <= n - 1`.
pub fn silhouette_samples<F: Float, L: Eq + Hash>(
    x: MatrixView<'_, F>,
    labels: &[L],
    metric: Metric,
) -> Result<Vec<f64>> {
    let (codes, k) = cluster_codes(x, labels)?;
    let sizes = bincount(&codes, k);
    let n = codes.len();
    let row = |i: usize| -> f64 {
        let own = codes[i];
        if sizes[own] == 1 {
            return 0.0;
        }
        let xi = x.row(i);
        let mut sums = vec![0.0f64; k];
        for (j, &cj) in codes.iter().enumerate() {
            if j != i {
                sums[cj] += metric.distance(xi, x.row(j)).to_f64();
            }
        }
        let a = sums[own] / to_f64(sizes[own] - 1);
        let b = sums
            .iter()
            .zip(&sizes)
            .enumerate()
            .filter(|&(c, _)| c != own)
            .map(|(_, (&s, &m))| s / to_f64(m))
            .fold(f64::INFINITY, f64::min);
        let den = a.max(b);
        if den == 0.0 { 0.0 } else { (b - a) / den }
    };
    #[cfg(feature = "rayon")]
    {
        use rayon::prelude::*;
        Ok((0..n).into_par_iter().map(row).collect())
    }
    #[cfg(not(feature = "rayon"))]
    Ok((0..n).map(row).collect())
}

/// Mean silhouette coefficient over all samples, in `[-1, 1]`; higher means
/// denser, better separated clusters. `O(n²)`: see [`silhouette_samples`].
///
/// ```
/// use rune_ml_core::{Matrix, Metric};
/// use rune_ml_metrics::silhouette_score;
///
/// let x = Matrix::from_rows(&[[0.0, 0.0], [0.0, 1.0], [10.0, 0.0], [10.0, 1.0]])?;
/// let s = silhouette_score(x.view(), &[0, 0, 1, 1], Metric::Euclidean)?;
/// assert!(s > 0.9);
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
///
/// # Errors
///
/// As [`silhouette_samples`].
pub fn silhouette_score<F: Float, L: Eq + Hash>(
    x: MatrixView<'_, F>,
    labels: &[L],
    metric: Metric,
) -> Result<f64> {
    let s = silhouette_samples(x, labels, metric)?;
    let mut sum = Sum::default();
    for &v in &s {
        sum.add(v);
    }
    Ok(sum.value() / to_f64(s.len()))
}

/// Per-cluster centroids (row-major `k × d`) and sizes.
fn centroids<F: Float>(x: MatrixView<'_, F>, codes: &[usize], k: usize) -> (Vec<f64>, Vec<usize>) {
    let d = x.ncols();
    let mut acc = vec![Sum::default(); k * d];
    for (row, &c) in x.rows().zip(codes) {
        for (s, &v) in acc[c * d..(c + 1) * d].iter_mut().zip(row) {
            s.add(v.to_f64());
        }
    }
    let sizes = bincount(codes, k);
    let cent = acc
        .iter()
        .enumerate()
        .map(|(i, s)| s.value() / to_f64(sizes[i / d.max(1)]))
        .collect();
    (cent, sizes)
}

fn sq_dist<F: Float>(a: &[F], b: &[f64]) -> f64 {
    a.iter()
        .zip(b)
        .map(|(&x, &y)| {
            let t = x.to_f64() - y;
            t * t
        })
        .sum()
}

/// Davies-Bouldin index; lower is better.
///
/// The mean, over clusters, of the worst ratio `(sᵢ + sⱼ) / d(cᵢ, cⱼ)` of
/// within-cluster scatter to centroid separation. `0` is the minimum. Euclidean distance, `O(n·d + k²·d)`.
///
/// ```
/// use rune_ml_core::Matrix;
/// use rune_ml_metrics::davies_bouldin_score;
///
/// let x = Matrix::from_rows(&[[0.0, 0.0], [0.0, 2.0], [10.0, 0.0], [10.0, 2.0]])?;
/// assert!((davies_bouldin_score(x.view(), &[0, 0, 1, 1])? - 0.2).abs() < 1e-12);
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
///
/// # Errors
///
/// As [`silhouette_samples`].
pub fn davies_bouldin_score<F: Float, L: Eq + Hash>(
    x: MatrixView<'_, F>,
    labels: &[L],
) -> Result<f64> {
    let (codes, k) = cluster_codes(x, labels)?;
    let d = x.ncols();
    let (cent, sizes) = centroids(x, &codes, k);
    let c = |i: usize| &cent[i * d..(i + 1) * d];
    let mut intra = vec![Sum::default(); k];
    for (row, &ci) in x.rows().zip(&codes) {
        intra[ci].add(sq_dist(row, c(ci)).sqrt());
    }
    let intra: Vec<f64> = intra
        .iter()
        .zip(&sizes)
        .map(|(s, &m)| s.value() / to_f64(m))
        .collect();
    let dist = |i: usize, j: usize| {
        c(i).iter()
            .zip(c(j))
            .map(|(a, b)| (a - b) * (a - b))
            .sum::<f64>()
            .sqrt()
    };
    // numpy's allclose(.., 0): every value within 1e-8.
    let all_intra_zero = intra.iter().all(|v| v.abs() <= 1e-8);
    let all_cent_zero = (0..k).all(|i| (i + 1..k).all(|j| dist(i, j) <= 1e-8));
    if all_intra_zero || all_cent_zero {
        return Ok(0.0);
    }
    let mut total = Sum::default();
    for i in 0..k {
        let worst = (0..k)
            .filter(|&j| j != i)
            .map(|j| {
                let dij = dist(i, j);
                // Coincident centroids count as infinitely far apart, as sklearn.
                if dij == 0.0 {
                    0.0
                } else {
                    (intra[i] + intra[j]) / dij
                }
            })
            .fold(0.0, f64::max);
        total.add(worst);
    }
    Ok(total.value() / to_f64(k))
}

/// Calinski-Harabasz index (variance ratio criterion); higher is better.
///
/// Between-cluster dispersion over within-cluster dispersion, scaled by
/// `(n − k) / (k − 1)`. Returns `1.0` when every cluster is a single point
/// repeated (zero within-cluster dispersion), as scikit-learn.
///
/// ```
/// use rune_ml_core::Matrix;
/// use rune_ml_metrics::calinski_harabasz_score;
///
/// let x = Matrix::from_rows(&[[0.0, 0.0], [0.0, 2.0], [10.0, 0.0], [10.0, 2.0]])?;
/// assert!((calinski_harabasz_score(x.view(), &[0, 0, 1, 1])? - 50.0).abs() < 1e-9);
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
///
/// # Errors
///
/// As [`silhouette_samples`].
pub fn calinski_harabasz_score<F: Float, L: Eq + Hash>(
    x: MatrixView<'_, F>,
    labels: &[L],
) -> Result<f64> {
    let (codes, k) = cluster_codes(x, labels)?;
    let n = codes.len();
    let d = x.ncols();
    let (cent, sizes) = centroids(x, &codes, k);
    let mut mean = vec![Sum::default(); d];
    for row in x.rows() {
        for (s, &v) in mean.iter_mut().zip(row) {
            s.add(v.to_f64());
        }
    }
    let mean: Vec<f64> = mean.iter().map(|s| s.value() / to_f64(n)).collect();
    let mut extra = Sum::default();
    for (ci, &m) in sizes.iter().enumerate() {
        let c = &cent[ci * d..(ci + 1) * d];
        let sq: f64 = c.iter().zip(&mean).map(|(a, b)| (a - b) * (a - b)).sum();
        extra.add(to_f64(m) * sq);
    }
    let mut intra = Sum::default();
    for (row, &ci) in x.rows().zip(&codes) {
        intra.add(sq_dist(row, &cent[ci * d..(ci + 1) * d]));
    }
    let intra = intra.value();
    if intra == 0.0 {
        return Ok(1.0);
    }
    Ok(extra.value() * to_f64(n - k) / (intra * to_f64(k - 1)))
}
