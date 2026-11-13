use crate::rng::Rng;

pub struct OptimizeParams {
    pub n: usize,
    pub nc: usize,
    pub a: f64,
    pub b: f64,
    pub initial_lr: f64,
    pub n_epochs: usize,
    pub negative_sample_rate: usize,
}

/// Initialises the embedding uniformly in `[−10, 10]^n_components`.
pub fn init_random(n: usize, n_components: usize, rng: &mut Rng) -> Vec<f64> {
    (0..n * n_components)
        .map(|_| (rng.next_f64() - 0.5) * 20.0)
        .collect()
}

/// Spectral initialisation using the normalised graph Laplacian eigenvectors.
///
/// Finds the eigenvectors of `A = D^(-1/2) W D^(-1/2)` for the `nc` largest
/// eigenvalues after the trivial one (the smallest non-trivial eigenvectors of
/// the normalised Laplacian), scaled to `[−10, 10]`.
///
/// Power iteration runs on `(I + A) / 2` rather than on `A`. The spectrum of
/// `A` lies in `[−1, 1]`, and plain power iteration picks the eigenvalue with
/// the largest magnitude, so on a bipartite graph (a ring, a grid) it would
/// lock onto `−1` and give a coordinate that just alternates between
/// neighbours. The shift maps the spectrum to `[0, 1]` in the same order.
/// Falls back to random initialisation when the graph is disconnected.
pub fn spectral_init(
    edges: &[(usize, usize, f64)],
    n: usize,
    nc: usize,
    rng: &mut Rng,
) -> Vec<f64> {
    // Need nc + 1 eigenvectors of an n×n operator; tiny inputs or a
    // disconnected graph fall back to random initialisation.
    if nc + 1 >= n || !is_connected(edges, n) {
        return init_random(n, nc, rng);
    }

    // Build degree vector and symmetrically-normalised adjacency
    let mut degree = vec![0.0f64; n];
    for &(i, j, w) in edges {
        degree[i] += w;
        degree[j] += w;
    }
    let d_inv_sqrt: Vec<f64> = degree
        .iter()
        .map(|&d| if d > 0.0 { 1.0 / d.sqrt() } else { 0.0 })
        .collect();

    // The trivial eigenvector (eigenvalue 1) of a connected graph is
    // sqrt(degree), so start from it and deflate it out of every other vector.
    let mut trivial: Vec<f64> = degree.iter().map(|d| d.sqrt()).collect();
    normalize(&mut trivial);

    // Power iteration with Gram-Schmidt deflation for the next nc eigenvectors.
    let iters = 300;
    let mut found: Vec<Vec<f64>> = Vec::with_capacity(nc + 1);
    found.push(trivial);

    for _ in 0..nc {
        // Random start
        let mut v: Vec<f64> = (0..n).map(|_| rng.next_f64() - 0.5).collect();
        orthogonalize(&mut v, &found);
        normalize(&mut v);

        for _ in 0..iters {
            // v ← (v + A·v) / 2  (sparse matvec on the shifted operator)
            let mut w_vec = v.clone();
            for &(i, j, w) in edges {
                let wi = d_inv_sqrt[i] * w * d_inv_sqrt[j];
                w_vec[i] = wi.mul_add(v[j], w_vec[i]);
                w_vec[j] = wi.mul_add(v[i], w_vec[j]);
            }
            for x in &mut w_vec {
                *x *= 0.5;
            }
            orthogonalize(&mut w_vec, &found);
            normalize(&mut w_vec);
            v = w_vec;
        }

        found.push(v);
    }

    // Skip eigenvector 0 (trivial constant); use indices 1..=nc
    let mut flat = vec![0.0f64; n * nc];
    for (dim, eigvec) in found[1..].iter().enumerate() {
        let max_abs = eigvec
            .iter()
            .map(|x| x.abs())
            .fold(0.0_f64, f64::max)
            .max(1e-10);
        let scale = 10.0 / max_abs;
        for i in 0..n {
            flat[i * nc + dim] = eigvec[i] * scale;
        }
    }

    flat
}

fn orthogonalize(v: &mut [f64], basis: &[Vec<f64>]) {
    for b in basis {
        let dot: f64 = v.iter().zip(b.iter()).map(|(x, y)| x * y).sum();
        for (x, y) in v.iter_mut().zip(b.iter()) {
            *x -= dot * y;
        }
    }
}

fn normalize(v: &mut [f64]) {
    let norm: f64 = v.iter().map(|x| x * x).sum::<f64>().sqrt();
    if norm > 1e-12 {
        for x in v.iter_mut() {
            *x /= norm;
        }
    }
}

/// Returns true if the graph on `n` nodes is connected (BFS).
pub fn is_connected(edges: &[(usize, usize, f64)], n: usize) -> bool {
    if n == 0 {
        return true;
    }
    let mut adj = vec![vec![]; n];
    for &(i, j, _) in edges {
        adj[i].push(j);
        adj[j].push(i);
    }
    let mut visited = vec![false; n];
    let mut queue = std::collections::VecDeque::new();
    visited[0] = true;
    queue.push_back(0usize);
    let mut count = 1;
    while let Some(node) = queue.pop_front() {
        for &nb in &adj[node] {
            if !visited[nb] {
                visited[nb] = true;
                count += 1;
                queue.push_back(nb);
            }
        }
    }
    count == n
}

/// Runs the UMAP SGD optimisation on the flat embedding buffer.
///
/// For each epoch, iterates over all edges and samples those whose scheduling
/// counter has elapsed. Each sampled edge generates one attractive (positive)
/// gradient step and `negative_sample_rate` repulsive (negative) steps.
#[allow(
    clippy::cast_precision_loss,
    reason = "counts and indices stay far below 2^52, so the f64 conversion is exact"
)]
#[allow(
    clippy::many_single_char_names,
    reason = "short names follow the textbook notation"
)]
pub fn optimize(
    embedding: &mut [f64],
    edges: &[(usize, usize, f64)],
    p: &OptimizeParams,
    rng: &mut Rng,
) {
    let (n, nc, a, b, initial_lr, n_epochs, negative_sample_rate) = (
        p.n,
        p.nc,
        p.a,
        p.b,
        p.initial_lr,
        p.n_epochs,
        p.negative_sample_rate,
    );
    if edges.is_empty() {
        return;
    }

    let max_w = edges.iter().map(|(_, _, w)| *w).fold(0.0_f64, f64::max);
    let eps_per: Vec<f64> = edges.iter().map(|(_, _, w)| max_w / w).collect();
    let mut next_sample_at: Vec<f64> = eps_per.clone();

    for epoch in 0..n_epochs {
        let lr = initial_lr * (1.0 - epoch as f64 / n_epochs as f64).max(0.0);
        let epoch_f = epoch as f64;

        for k in 0..edges.len() {
            if next_sample_at[k] > epoch_f {
                continue;
            }
            next_sample_at[k] += eps_per[k];

            let (i, j, _) = edges[k];
            attractive_step(embedding, i, j, nc, a, b, lr);

            for _ in 0..negative_sample_rate {
                let neg_j = sample_negative(rng, n, i);
                repulsive_step(embedding, i, neg_j, nc, a, b, lr);
            }
        }
    }
}

/// Parameters for [`optimize_transform`].
pub struct TransformParams {
    pub n_train: usize,
    pub nc: usize,
    pub a: f64,
    pub b: f64,
    pub initial_lr: f64,
    pub n_epochs: usize,
    pub negative_sample_rate: usize,
}

/// Optimises new-point embeddings with training points held fixed.
///
/// `new_flat`: mutable flat buffer for new points (`n_new × nc`).
/// `train_flat`: immutable flat buffer for training points (`n_train × nc`).
/// `nn_edges`: directed edges `(i_new, j_train, weight)`.
#[allow(
    clippy::cast_precision_loss,
    reason = "counts and indices stay far below 2^52, so the f64 conversion is exact"
)]
pub fn optimize_transform(
    new_flat: &mut [f64],
    train_flat: &[f64],
    nn_edges: &[(usize, usize, f64)],
    p: &TransformParams,
    rng: &mut Rng,
) {
    let (n_train, nc, a, b, initial_lr, n_epochs, neg_rate) = (
        p.n_train,
        p.nc,
        p.a,
        p.b,
        p.initial_lr,
        p.n_epochs,
        p.negative_sample_rate,
    );
    if nn_edges.is_empty() {
        return;
    }

    let max_w = nn_edges.iter().map(|(_, _, w)| *w).fold(0.0_f64, f64::max);
    let eps_per: Vec<f64> = nn_edges.iter().map(|(_, _, w)| max_w / w).collect();
    let mut next_sample_at: Vec<f64> = eps_per.clone();

    for epoch in 0..n_epochs {
        let lr = initial_lr * (1.0 - epoch as f64 / n_epochs as f64).max(0.0);
        let epoch_f = epoch as f64;

        for k in 0..nn_edges.len() {
            if next_sample_at[k] > epoch_f {
                continue;
            }
            next_sample_at[k] += eps_per[k];

            let (i_new, j_train, _) = nn_edges[k];
            attractive_step_fixed(new_flat, train_flat, i_new, j_train, nc, a, b, lr);

            for _ in 0..neg_rate {
                let neg_j = sample_negative(rng, n_train, usize::MAX);
                repulsive_step_fixed(new_flat, train_flat, i_new, neg_j, nc, a, b, lr);
            }
        }
    }
}

const fn sample_negative(rng: &mut Rng, n: usize, exclude: usize) -> usize {
    loop {
        let candidate = rng.next_usize(n);
        if candidate != exclude {
            return candidate;
        }
    }
}

/// Attractive step: moves `y_i` toward `y_j`, and `y_j` toward `y_i`.
#[allow(
    clippy::too_many_arguments,
    reason = "hot inner-loop helper; a parameter struct would only add indirection"
)]
fn attractive_step(embedding: &mut [f64], i: usize, j: usize, nc: usize, a: f64, b: f64, lr: f64) {
    let d_sq = sq_dist_same(embedding, i, j, nc);

    let grad_coeff = if d_sq > 0.0 {
        -2.0 * a * b * d_sq.powf(b - 1.0) / a.mul_add(d_sq.powf(b), 1.0)
    } else {
        0.0
    };

    // Each coordinate's gradient depends only on that coordinate's difference,
    // so updating in place (no scratch buffer) is equivalent.
    for d in 0..nc {
        let diff = embedding[i * nc + d] - embedding[j * nc + d];
        let grad = (grad_coeff * diff).clamp(-4.0, 4.0);
        embedding[i * nc + d] = lr.mul_add(grad, embedding[i * nc + d]);
        embedding[j * nc + d] = lr.mul_add(-grad, embedding[j * nc + d]);
    }
}

/// Attractive step for transform: moves `y_i` (new) toward fixed `y_j` (train).
#[allow(clippy::too_many_arguments)]
fn attractive_step_fixed(
    new_flat: &mut [f64],
    train_flat: &[f64],
    i: usize,
    j: usize,
    nc: usize,
    a: f64,
    b: f64,
    lr: f64,
) {
    let d_sq = sq_dist_cross(new_flat, train_flat, i, j, nc);

    let grad_coeff = if d_sq > 0.0 {
        -2.0 * a * b * d_sq.powf(b - 1.0) / a.mul_add(d_sq.powf(b), 1.0)
    } else {
        0.0
    };

    for d in 0..nc {
        let diff = new_flat[i * nc + d] - train_flat[j * nc + d];
        let grad = (grad_coeff * diff).clamp(-4.0, 4.0);
        new_flat[i * nc + d] = lr.mul_add(grad, new_flat[i * nc + d]);
    }
}

/// Repulsive step: moves `y_i` away from `y_j` (only `y_i` updated).
#[allow(
    clippy::too_many_arguments,
    reason = "hot inner-loop helper; a parameter struct would only add indirection"
)]
fn repulsive_step(embedding: &mut [f64], i: usize, j: usize, nc: usize, a: f64, b: f64, lr: f64) {
    let d_sq = sq_dist_same(embedding, i, j, nc).max(1e-12);

    let grad_coeff = 2.0 * b / ((0.001 + d_sq) * a.mul_add(d_sq.powf(b), 1.0));

    for d in 0..nc {
        let diff = embedding[i * nc + d] - embedding[j * nc + d];
        let grad = (grad_coeff * diff).clamp(-4.0, 4.0);
        embedding[i * nc + d] = lr.mul_add(grad, embedding[i * nc + d]);
    }
}

/// Repulsive step for transform: moves new-point `y_i` away from fixed train `y_j`.
#[allow(clippy::too_many_arguments)]
fn repulsive_step_fixed(
    new_flat: &mut [f64],
    train_flat: &[f64],
    i: usize,
    j: usize,
    nc: usize,
    a: f64,
    b: f64,
    lr: f64,
) {
    let d_sq = sq_dist_cross(new_flat, train_flat, i, j, nc).max(1e-12);

    let grad_coeff = 2.0 * b / ((0.001 + d_sq) * a.mul_add(d_sq.powf(b), 1.0));

    for d in 0..nc {
        let diff = new_flat[i * nc + d] - train_flat[j * nc + d];
        let grad = (grad_coeff * diff).clamp(-4.0, 4.0);
        new_flat[i * nc + d] = lr.mul_add(grad, new_flat[i * nc + d]);
    }
}

fn sq_dist_same(embedding: &[f64], i: usize, j: usize, nc: usize) -> f64 {
    (0..nc)
        .map(|d| {
            let diff = embedding[i * nc + d] - embedding[j * nc + d];
            diff * diff
        })
        .sum()
}

fn sq_dist_cross(a: &[f64], b: &[f64], i: usize, j: usize, nc: usize) -> f64 {
    (0..nc)
        .map(|d| {
            let diff = a[i * nc + d] - b[j * nc + d];
            diff * diff
        })
        .sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Rayleigh quotient of `x` on `D^-1/2 W D^-1/2`.
    fn rayleigh(edges: &[(usize, usize, f64)], n: usize, x: &[f64]) -> f64 {
        let mut deg = vec![0.0; n];
        for &(i, j, w) in edges {
            deg[i] += w;
            deg[j] += w;
        }
        let num: f64 = edges
            .iter()
            .map(|&(i, j, w)| 2.0 * w * x[i] * x[j] / (deg[i] * deg[j]).sqrt())
            .sum();
        num / x.iter().map(|v| v * v).sum::<f64>()
    }

    fn check_leading(edges: &[(usize, usize, f64)], n: usize, nc: usize) {
        let flat = spectral_init(edges, n, nc, &mut Rng::new(7));
        for dim in 0..nc {
            let col: Vec<f64> = (0..n).map(|i| flat[i * nc + dim]).collect();
            let r = rayleigh(edges, n, &col);
            assert!(r > 0.0, "dim {dim} has Rayleigh quotient {r}");
        }
    }

    #[test]
    fn spectral_init_picks_positive_eigenvalues_on_ring() {
        let n = 8;
        let edges: Vec<_> = (0..n).map(|i| (i, (i + 1) % n, 1.0)).collect();
        check_leading(&edges, n, 2);
    }

    #[test]
    fn spectral_init_picks_positive_eigenvalues_on_grid() {
        let side = 4;
        let mut edges = Vec::new();
        for r in 0..side {
            for c in 0..side {
                let i = r * side + c;
                if c + 1 < side {
                    edges.push((i, i + 1, 1.0));
                }
                if r + 1 < side {
                    edges.push((i, i + side, 1.0));
                }
            }
        }
        check_leading(&edges, side * side, 2);
    }
}
