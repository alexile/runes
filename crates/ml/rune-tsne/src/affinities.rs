/// Compute the symmetrised joint probability matrix P for t-SNE.
///
/// Returns a flat upper-triangular-style matrix stored as a full `n × n` array
/// (row-major, index `i * n + j`) containing `p_ij` values.
#[allow(
    clippy::cast_precision_loss,
    reason = "counts and indices stay far below 2^52, so the f64 conversion is exact"
)]
pub fn compute_p(points: &[Vec<f64>], perplexity: f64) -> Vec<f64> {
    let n = points.len();
    let target_entropy = perplexity.log2();

    let mut conditional = vec![0.0f64; n * n];

    for i in 0..n {
        let sigma = binary_search_sigma(&points[i], points, i, target_entropy);
        let two_sigma_sq = 2.0 * sigma * sigma;

        let mut row_sum = 0.0f64;
        for j in 0..n {
            if i == j {
                continue;
            }
            let dist_sq = squared_distance(&points[i], &points[j]);
            let value = (-dist_sq / two_sigma_sq).exp();
            conditional[i * n + j] = value;
            row_sum += value;
        }
        if row_sum > 0.0 {
            for j in 0..n {
                conditional[i * n + j] /= row_sum;
            }
        }
    }

    let n_f64 = n as f64;
    let mut p = vec![0.0f64; n * n];
    for i in 0..n {
        for j in 0..n {
            let symmetrized = (conditional[i * n + j] + conditional[j * n + i]) / (2.0 * n_f64);
            p[i * n + j] = symmetrized.max(1e-12);
        }
    }

    p
}

/// Maximum bisection steps when searching for each point's bandwidth.
const SEARCH_STEPS: usize = 100;

fn squared_distance(a: &[f64], b: &[f64]) -> f64 {
    a.iter().zip(b.iter()).map(|(x, y)| (x - y).powi(2)).sum()
}

fn binary_search_sigma(
    point: &[f64],
    points: &[Vec<f64>],
    skip: usize,
    target_entropy: f64,
) -> f64 {
    let mut lo = 0.0f64;
    let mut hi = f64::INFINITY;
    // Start from the root-mean-square distance to the other points rather than a
    // fixed `1.0`: the search then begins at the data's own scale, so data measured
    // in nanometres or light years gets the same affinities as data in metres. A
    // fixed start could not double/halve its way to such scales in time and fell
    // back to (near-)uniform affinities, erasing all cluster structure.
    let mut sigma = initial_sigma(point, points, skip);

    for _ in 0..SEARCH_STEPS {
        let entropy = conditional_entropy(point, points, skip, sigma);

        if (entropy - target_entropy).abs() < 1e-5 {
            break;
        }

        if entropy < target_entropy {
            lo = sigma;
            if hi.is_infinite() {
                sigma *= 2.0;
            } else {
                sigma = f64::midpoint(sigma, hi);
            }
        } else {
            hi = sigma;
            sigma = f64::midpoint(lo, sigma);
        }
    }

    sigma
}

/// Root-mean-square distance from `point` to every other point, or `1.0` when that
/// is zero (all duplicates) or not finite.
#[allow(
    clippy::cast_precision_loss,
    reason = "counts and indices stay far below 2^52, so the f64 conversion is exact"
)]
fn initial_sigma(point: &[f64], points: &[Vec<f64>], skip: usize) -> f64 {
    let others = points.len().saturating_sub(1).max(1) as f64;
    let mean_sq = points
        .iter()
        .enumerate()
        .filter(|&(j, _)| j != skip)
        .map(|(_, q)| squared_distance(point, q))
        .sum::<f64>()
        / others;
    let sigma = mean_sq.sqrt();
    if sigma.is_finite() && sigma > 0.0 {
        sigma
    } else {
        1.0
    }
}

fn conditional_entropy(point: &[f64], points: &[Vec<f64>], skip: usize, sigma: f64) -> f64 {
    let two_sigma_sq = 2.0 * sigma * sigma;
    let mut weights: Vec<f64> = points
        .iter()
        .enumerate()
        .map(|(j, q)| {
            if j == skip {
                0.0
            } else {
                (-squared_distance(point, q) / two_sigma_sq).exp()
            }
        })
        .collect();

    let total: f64 = weights.iter().sum();
    if total == 0.0 {
        return 0.0;
    }
    for w in &mut weights {
        *w /= total;
    }

    weights
        .iter()
        .filter(|&&w| w > 0.0)
        .map(|&w| -w * w.log2())
        .sum()
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

    #[test]
    fn bandwidth_search_hits_the_target_perplexity() {
        for scale in [1e-40, 1e-8, 1.0, 1e8, 1e40] {
            let pts = spiral(40, scale);
            for perplexity in [2.0, 5.0, 12.0] {
                let target = f64::log2(perplexity);
                for i in 0..pts.len() {
                    let sigma = binary_search_sigma(&pts[i], &pts, i, target);
                    let h = conditional_entropy(&pts[i], &pts, i, sigma);
                    assert!(
                        (h - target).abs() < 1e-4,
                        "scale {scale:e}, perplexity {perplexity}, point {i}: entropy {h} vs {target}"
                    );
                }
            }
        }
    }

    #[test]
    fn joint_probabilities_are_symmetric_and_normalised() {
        let pts = spiral(25, 1.0);
        let n = pts.len();
        let p = compute_p(&pts, 5.0);
        let off_diagonal: f64 = (0..n)
            .flat_map(|i| (0..n).filter(move |&j| j != i).map(move |j| (i, j)))
            .map(|(i, j)| p[i * n + j])
            .sum();
        assert!((off_diagonal - 1.0).abs() < 1e-6, "sum = {off_diagonal}");
        for i in 0..n {
            for j in 0..n {
                assert!(p[i * n + j] > 0.0);
                assert!((p[i * n + j] - p[j * n + i]).abs() < 1e-15);
            }
        }
    }

    #[test]
    fn affinities_are_scale_invariant() {
        let reference = compute_p(&spiral(20, 1.0), 4.0);
        for scale in [1e-30, 1e30] {
            let scaled = compute_p(&spiral(20, scale), 4.0);
            for (a, b) in reference.iter().zip(&scaled) {
                assert!((a - b).abs() < 1e-6, "scale {scale:e}: {a} vs {b}");
            }
        }
    }

    #[test]
    fn duplicates_get_uniform_affinities() {
        let pts = vec![vec![3.0, 3.0]; 5];
        let p = compute_p(&pts, 2.0);
        for i in 0..5 {
            for j in 0..5 {
                if i != j {
                    assert!((p[i * 5 + j] - 1.0 / 20.0).abs() < 1e-12);
                }
            }
        }
    }
}
