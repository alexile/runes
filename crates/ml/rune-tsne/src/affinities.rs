//! High-dimensional affinities: per-point bandwidth calibration and the
//! symmetrised joint probabilities P, dense (exact t-SNE) or sparse over the
//! nearest neighbours (Barnes-Hut t-SNE).

use rayon::prelude::*;

/// Maximum bisection steps of the bandwidth search.
pub const MAX_SEARCH_STEPS: usize = 200;
/// Stop once the entropy is this close to `ln(perplexity)` (in nats).
const ENTROPY_TOL: f64 = 1e-5;

/// Sparse symmetric matrix in compressed-row form.
pub struct Sparse {
    /// `row_start[i]..row_start[i + 1]` indexes the entries of row `i`.
    pub row_start: Vec<usize>,
    pub cols: Vec<usize>,
    pub vals: Vec<f64>,
}

fn sq_dist(a: &[f64], b: &[f64]) -> f64 {
    a.iter().zip(b).map(|(x, y)| (x - y) * (x - y)).sum()
}

/// Conditional probabilities `p_{j|i} ∝ exp(−β·d_j)` over the squared
/// distances `sq` whose entropy is `target` nats (`ln(perplexity)`).
///
/// The precision `β` is found by bisection, starting from the inverse mean
/// distance so the search begins at the data's own scale and the result does
/// not depend on its units. Distances are shifted by their minimum first,
/// so the normaliser is at least 1: nothing underflows to 0/0, and the output
/// is always a finite probability vector. The search is bounded by
/// [`MAX_SEARCH_STEPS`] steps and stops early if `β` overflows.
pub fn calibrate(sq: &[f64], target: f64) -> Vec<f64> {
    let k = sq.len();
    if k == 0 {
        return Vec::new();
    }
    let min = sq.iter().copied().fold(f64::INFINITY, f64::min);
    let shifted: Vec<f64> = sq.iter().map(|d| d - min).collect();
    #[allow(
        clippy::cast_precision_loss,
        reason = "neighbour counts stay far below 2^52, so the f64 conversion is exact"
    )]
    let mean = shifted.iter().sum::<f64>() / k as f64;
    let mut w = vec![0.0; k];
    if !(mean > 0.0 && mean.is_finite()) {
        // All neighbours equidistant: the only answer is uniform.
        #[allow(clippy::cast_precision_loss, reason = "see above")]
        w.fill(1.0 / k as f64);
        return w;
    }

    let mut beta = 1.0 / mean;
    let (mut lo, mut hi) = (0.0f64, f64::INFINITY);
    let mut sum = 1.0;
    for _ in 0..MAX_SEARCH_STEPS {
        let entropy = weights(&shifted, beta, &mut w, &mut sum);
        if (entropy - target).abs() < ENTROPY_TOL {
            break;
        }
        let next = if entropy > target {
            // Too flat: sharpen.
            lo = beta;
            if hi.is_finite() {
                f64::midpoint(lo, hi)
            } else {
                beta * 2.0
            }
        } else {
            hi = beta;
            f64::midpoint(lo, hi)
        };
        #[allow(
            clippy::float_cmp,
            reason = "bisection has stalled when the midpoint stops moving"
        )]
        let stalled = next == beta;
        if !next.is_finite() || stalled {
            break;
        }
        beta = next;
    }
    // `w` holds the weights of the last evaluated `beta`.
    weights(&shifted, beta, &mut w, &mut sum);
    for x in &mut w {
        *x /= sum;
    }
    w
}

/// Fills `w` with `exp(−β·d)` and returns the entropy (nats) of the
/// normalised distribution; `sum` receives the normaliser (≥ 1).
fn weights(shifted: &[f64], beta: f64, w: &mut [f64], sum: &mut f64) -> f64 {
    let mut s = 0.0;
    let mut weighted = 0.0;
    for (x, &d) in w.iter_mut().zip(shifted) {
        *x = (-beta * d).exp();
        s += *x;
        weighted = (*x * d).mul_add(beta, weighted);
    }
    *sum = s;
    // H = ln Σw + β Σ w·d / Σw
    s.ln() + weighted / s
}

/// Dense symmetric P (row-major `n × n`, zero diagonal, summing to 1) using
/// every other point as a neighbour.
#[allow(
    clippy::cast_precision_loss,
    reason = "counts and indices stay far below 2^52, so the f64 conversion is exact"
)]
pub fn dense_p(points: &[Vec<f64>], perplexity: f64) -> Vec<f64> {
    let n = points.len();
    let target = perplexity.ln();
    let conditional: Vec<Vec<f64>> = (0..n)
        .into_par_iter()
        .map(|i| {
            let sq: Vec<f64> = (0..n)
                .filter(|&j| j != i)
                .map(|j| sq_dist(&points[i], &points[j]))
                .collect();
            let mut row = calibrate(&sq, target);
            row.insert(i, 0.0);
            row
        })
        .collect();
    let denom = 2.0 * n as f64;
    let mut p = vec![0.0; n * n];
    for i in 0..n {
        for j in 0..n {
            p[i * n + j] = (conditional[i][j] + conditional[j][i]) / denom;
        }
    }
    p
}

/// The `k` nearest neighbours of point `i` (excluding itself) and their
/// squared distances, nearest first, ties broken by index. Brute force:
/// `O(n·d)` time and `O(n)` memory per point.
fn knn(points: &[Vec<f64>], i: usize, k: usize) -> Vec<(usize, f64)> {
    let mut all: Vec<(usize, f64)> = (0..points.len())
        .filter(|&j| j != i)
        .map(|j| (j, sq_dist(&points[i], &points[j])))
        .collect();
    let by = |a: &(usize, f64), b: &(usize, f64)| a.1.total_cmp(&b.1).then(a.0.cmp(&b.0));
    if k < all.len() {
        all.select_nth_unstable_by(k, by);
        all.truncate(k);
    }
    all.sort_unstable_by(by);
    all
}

/// Sparse symmetric P over each point's `k = min(n − 1, ⌊3·perplexity⌋)`
/// nearest neighbours (van der Maaten 2014, section 4.1).
#[allow(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    reason = "perplexity is validated finite and below n / 3, so 3·perplexity fits in usize"
)]
pub fn sparse_p(points: &[Vec<f64>], perplexity: f64) -> Sparse {
    let n = points.len();
    let k = ((3.0 * perplexity).floor() as usize).clamp(1, n.saturating_sub(1));
    let target = perplexity.ln();
    let conditional: Vec<Vec<(usize, f64)>> = (0..n)
        .into_par_iter()
        .map(|i| {
            let nn = knn(points, i, k);
            let sq: Vec<f64> = nn.iter().map(|&(_, d)| d).collect();
            let p = calibrate(&sq, target);
            nn.iter().map(|&(j, _)| j).zip(p).collect()
        })
        .collect();

    // P = (P_{j|i} + P_{i|j}) / 2n over the union of both neighbourhoods.
    let mut rows: Vec<Vec<(usize, f64)>> = vec![Vec::new(); n];
    for (i, row) in conditional.iter().enumerate() {
        for &(j, v) in row {
            rows[i].push((j, v));
            rows[j].push((i, v));
        }
    }
    let denom = 2.0 * n as f64;
    let mut out = Sparse {
        row_start: Vec::with_capacity(n + 1),
        cols: Vec::new(),
        vals: Vec::new(),
    };
    out.row_start.push(0);
    for row in &mut rows {
        row.sort_unstable_by(|a, b| a.0.cmp(&b.0).then(a.1.total_cmp(&b.1)));
        let mut idx = 0;
        while idx < row.len() {
            let j = row[idx].0;
            let mut v = 0.0;
            while idx < row.len() && row[idx].0 == j {
                v += row[idx].1;
                idx += 1;
            }
            out.cols.push(j);
            out.vals.push(v / denom);
        }
        out.row_start.push(out.cols.len());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[allow(
        clippy::cast_precision_loss,
        reason = "test sizes are tiny, so the f64 conversions are exact"
    )]
    fn spiral(n: usize, scale: f64) -> Vec<Vec<f64>> {
        (0..n)
            .map(|i| {
                let t = i as f64 * 0.37;
                vec![t * t.cos() * scale, t * t.sin() * scale, t * 0.1 * scale]
            })
            .collect()
    }

    fn entropy(p: &[f64]) -> f64 {
        p.iter().filter(|&&x| x > 0.0).map(|&x| -x * x.ln()).sum()
    }

    #[test]
    fn calibration_hits_the_target_perplexity_at_any_scale() {
        for scale in [1e-40, 1e-8, 1.0, 1e8, 1e40] {
            let pts = spiral(40, scale);
            for perplexity in [2.0, 5.0, 12.0] {
                for i in 0..pts.len() {
                    let sq: Vec<f64> = (0..pts.len())
                        .filter(|&j| j != i)
                        .map(|j| sq_dist(&pts[i], &pts[j]))
                        .collect();
                    let p = calibrate(&sq, f64::ln(perplexity));
                    let h = entropy(&p);
                    assert!(
                        (h - perplexity.ln()).abs() < 1e-4,
                        "scale {scale:e}, perplexity {perplexity}, point {i}: {h}"
                    );
                    assert!((p.iter().sum::<f64>() - 1.0).abs() < 1e-12);
                }
            }
        }
    }

    #[test]
    fn calibration_never_produces_nan() {
        // Unreachable targets (above ln k, or below the entropy of the tied
        // nearest neighbours) and degenerate distances.
        let cases: [(&[f64], f64); 5] = [
            (&[1.0, 2.0, 3.0], 10.0),
            (&[0.0, 0.0, 5.0, 1e300], 0.01),
            (&[0.0, 0.0, 0.0], 1.0),
            (&[1e-300, 2e-300, 1e300], 0.5),
            (&[7.0], 0.0),
        ];
        for (sq, target) in cases {
            let p = calibrate(sq, target);
            assert_eq!(p.len(), sq.len());
            assert!(
                p.iter().all(|x| x.is_finite() && *x >= 0.0),
                "{sq:?}: {p:?}"
            );
            assert!((p.iter().sum::<f64>() - 1.0).abs() < 1e-12);
        }
        assert_eq!(calibrate(&[], 1.0), Vec::<f64>::new());
    }

    #[test]
    fn dense_p_is_symmetric_and_normalised() {
        let pts = spiral(25, 1.0);
        let n = pts.len();
        let p = dense_p(&pts, 5.0);
        assert!((p.iter().sum::<f64>() - 1.0).abs() < 1e-12);
        for i in 0..n {
            assert_eq!(p[i * n + i], 0.0);
            for j in 0..n {
                assert!((p[i * n + j] - p[j * n + i]).abs() < 1e-15);
            }
        }
    }

    #[test]
    fn sparse_p_is_symmetric_and_normalised() {
        let pts = spiral(40, 1.0);
        let p = sparse_p(&pts, 4.0);
        assert!((p.vals.iter().sum::<f64>() - 1.0).abs() < 1e-12);
        let get = |i: usize, j: usize| {
            (p.row_start[i]..p.row_start[i + 1])
                .find(|&e| p.cols[e] == j)
                .map_or(0.0, |e| p.vals[e])
        };
        for i in 0..40 {
            let row = &p.cols[p.row_start[i]..p.row_start[i + 1]];
            assert!(row.windows(2).all(|w| w[0] < w[1]) && !row.contains(&i));
            // Each point keeps at least its own 12 neighbours.
            assert!(row.len() >= 12);
            for &j in row {
                assert!((get(i, j) - get(j, i)).abs() < 1e-15);
            }
        }
    }

    #[test]
    fn affinities_are_scale_invariant() {
        let reference = dense_p(&spiral(20, 1.0), 4.0);
        for scale in [1e-30, 1e30] {
            let scaled = dense_p(&spiral(20, scale), 4.0);
            for (a, b) in reference.iter().zip(&scaled) {
                assert!((a - b).abs() < 1e-6, "scale {scale:e}: {a} vs {b}");
            }
        }
    }

    #[test]
    fn duplicates_get_uniform_affinities() {
        let p = dense_p(&vec![vec![3.0, 3.0]; 5], 2.0);
        for i in 0..5 {
            for j in (0..5).filter(|&j| j != i) {
                assert!((p[i * 5 + j] - 1.0 / 20.0).abs() < 1e-12);
            }
        }
    }
}
