use rayon::prelude::*;

/// Lower bound on the per-coordinate adaptive gain.
const MIN_GAIN: f64 = 0.01;

pub struct OptimizeParams {
    pub(crate) n: usize,
    pub(crate) nc: usize,
    pub(crate) learning_rate: f64,
    pub(crate) n_iter: usize,
    pub(crate) early_exag_iter: usize,
    pub(crate) exag_factor: f64,
}

struct GradientCtx<'a> {
    n: usize,
    nc: usize,
    p: &'a [f64],
    numerators: &'a [f64],
    normalizer: f64,
    exaggeration: f64,
    embedding: &'a [Vec<f64>],
}

pub fn optimize(embedding: &mut Vec<Vec<f64>>, p: &[f64], params: &OptimizeParams) {
    let n = params.n;
    let nc = params.nc;
    let mut velocities = vec![vec![0.0f64; nc]; n];
    // Per-coordinate adaptive gains (Jacobs 1988 "delta-bar-delta"), as in the
    // reference implementation by van der Maaten. Without them a fixed learning
    // rate of a few hundred makes small data sets oscillate and tear clusters apart.
    let mut gains = vec![vec![1.0f64; nc]; n];

    for iteration in 0..params.n_iter {
        let exaggeration = if iteration < params.early_exag_iter {
            params.exag_factor
        } else {
            1.0
        };

        let (numerators, normalizer) = compute_numerators(embedding, n, nc);

        let ctx = GradientCtx {
            n,
            nc,
            p,
            numerators: &numerators,
            normalizer,
            exaggeration,
            embedding,
        };

        let gradients: Vec<Vec<f64>> = (0..n)
            .into_par_iter()
            .map(|i| compute_gradient(i, &ctx))
            .collect();

        let momentum = if iteration < 250 { 0.5 } else { 0.8 };

        for i in 0..n {
            for d in 0..nc {
                let grad = gradients[i][d];
                let gain = &mut gains[i][d];
                // Grow the gain while the gradient keeps opposing the current
                // velocity (steady descent); shrink it when they agree in sign
                // (overshoot / oscillation).
                *gain = if (grad > 0.0) == (velocities[i][d] > 0.0) {
                    (*gain * 0.8).max(MIN_GAIN)
                } else {
                    *gain + 0.2
                };
                velocities[i][d] =
                    (params.learning_rate * *gain).mul_add(-grad, momentum * velocities[i][d]);
                embedding[i][d] += velocities[i][d];
            }
        }

        center(embedding, nc);
    }
}

fn compute_numerators(embedding: &[Vec<f64>], n: usize, nc: usize) -> (Vec<f64>, f64) {
    let mut numerators = vec![0.0f64; n * n];
    let mut normalizer = 0.0f64;

    for i in 0..n {
        for j in (i + 1)..n {
            let dist_sq: f64 = (0..nc)
                .map(|d| (embedding[i][d] - embedding[j][d]).powi(2))
                .sum();
            let num = 1.0 / (1.0 + dist_sq);
            numerators[i * n + j] = num;
            numerators[j * n + i] = num;
            normalizer = 2.0f64.mul_add(num, normalizer);
        }
    }

    (numerators, normalizer)
}

/// `KL(P ‖ Q) = Σ_{i≠j} p_ij · ln(p_ij / q_ij)` for the given embedding.
pub fn kl_divergence(embedding: &[Vec<f64>], p: &[f64], n: usize, nc: usize) -> f64 {
    let (numerators, normalizer) = compute_numerators(embedding, n, nc);
    let z = normalizer.max(1e-12);
    let mut kl = 0.0f64;
    for i in 0..n {
        for j in 0..n {
            if i == j {
                continue;
            }
            let p_ij = p[i * n + j];
            let q_ij = (numerators[i * n + j] / z).max(1e-12);
            kl = p_ij.mul_add((p_ij / q_ij).ln(), kl);
        }
    }
    kl
}

fn compute_gradient(i: usize, ctx: &GradientCtx<'_>) -> Vec<f64> {
    let mut gradient = vec![0.0f64; ctx.nc];
    let z = ctx.normalizer.max(1e-12);

    for j in 0..ctx.n {
        if i == j {
            continue;
        }
        let p_ij = ctx.p[i * ctx.n + j] * ctx.exaggeration;
        let num_ij = ctx.numerators[i * ctx.n + j];
        let q_ij = (num_ij / z).max(1e-12);
        let factor = 4.0 * (p_ij - q_ij) * num_ij;
        for (d, g) in gradient.iter_mut().enumerate() {
            *g = factor.mul_add(ctx.embedding[i][d] - ctx.embedding[j][d], *g);
        }
    }

    gradient
}

#[allow(
    clippy::cast_precision_loss,
    reason = "counts and indices stay far below 2^52, so the f64 conversion is exact"
)]
fn center(embedding: &mut [Vec<f64>], nc: usize) {
    let n = embedding.len();
    for d in 0..nc {
        let mean = embedding.iter().map(|row| row[d]).sum::<f64>() / n as f64;
        for row in embedding.iter_mut() {
            row[d] -= mean;
        }
    }
}
