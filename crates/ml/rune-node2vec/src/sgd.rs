use crate::alias::AliasTable;
use crate::rng::Rng;

/// Parameters passed to the skip-gram trainer.
pub struct TrainParams<'a> {
    pub(crate) n_nodes: usize,
    pub(crate) dim: usize,
    pub(crate) walks: &'a [Vec<usize>],
    pub(crate) window_size: usize,
    pub(crate) neg_samples: usize,
    pub(crate) n_epochs: usize,
    pub(crate) initial_lr: f64,
    /// Negative-sampling distribution (`degree^0.75`); `None` when no node
    /// has an edge, in which case negative sampling is skipped.
    pub(crate) noise: Option<&'a AliasTable>,
}

/// Trains embeddings with skip-gram negative sampling over all walks.
///
/// `embeddings` is the flat row-major input-vector matrix of shape
/// `[n_nodes × dim]` and is what the caller gets back. As in word2vec, the
/// context ("output") vectors live in a separate matrix that starts at zero
/// and is discarded after training; tying the two matrices together blurs
/// community structure, because a node then has to be close to itself in both
/// roles at once.
///
/// The learning rate decays linearly towards `min_lr` across epochs.
#[allow(
    clippy::cast_precision_loss,
    reason = "counts and indices stay far below 2^52, so the f64 conversion is exact"
)]
pub fn train(embeddings: &mut [f64], params: &TrainParams<'_>, rng: &mut Rng) {
    let min_lr = params.initial_lr * 0.0001;
    let mut model = Model {
        input: embeddings,
        context: vec![0.0; params.n_nodes * params.dim],
        grad: vec![0.0; params.dim],
        dim: params.dim,
    };

    for epoch in 0..params.n_epochs {
        let progress = epoch as f64 / params.n_epochs.max(1) as f64;
        let lr = (params.initial_lr - min_lr).mul_add(-progress, params.initial_lr);

        for walk in params.walks {
            process_walk(&mut model, params, walk, lr, rng);
        }
    }
}

/// Input vectors (being trained, returned), context vectors (scratch), and a
/// reusable gradient buffer for the centre node.
struct Model<'a> {
    input: &'a mut [f64],
    context: Vec<f64>,
    grad: Vec<f64>,
    dim: usize,
}

/// Processes one walk: for each centre node, updates embeddings with all context pairs.
fn process_walk(
    model: &mut Model<'_>,
    params: &TrainParams<'_>,
    walk: &[usize],
    lr: f64,
    rng: &mut Rng,
) {
    let walk_len = walk.len();

    for (center_pos, &center_node) in walk.iter().enumerate() {
        let context_start = center_pos.saturating_sub(params.window_size);
        let context_end = (center_pos + params.window_size + 1).min(walk_len);

        for (offset, &context_node) in walk[context_start..context_end].iter().enumerate() {
            if context_start + offset == center_pos {
                continue;
            }
            run_pair_update(model, params, center_node, context_node, lr, rng);
        }
    }
}

/// One skip-gram step: the true `(center, context)` pair plus `neg_samples`
/// negatives drawn from the noise distribution.
#[allow(
    clippy::cast_precision_loss,
    reason = "node counts stay far below 2^52, so the f64 conversion is exact"
)]
fn run_pair_update(
    model: &mut Model<'_>,
    params: &TrainParams<'_>,
    center: usize,
    context: usize,
    lr: f64,
    rng: &mut Rng,
) {
    let dim = model.dim;
    let center_range = center * dim..(center + 1) * dim;
    model.grad.fill(0.0);

    let step = |model: &mut Model<'_>, target: usize, label: f64| {
        let target_range = target * dim..(target + 1) * dim;
        let input = &model.input[center_range.clone()];
        let output = &mut model.context[target_range];
        let dot: f64 = input.iter().zip(output.iter()).map(|(a, b)| a * b).sum();
        let factor = (label - sigmoid(dot)) * lr;
        for ((g, o), &i) in model.grad.iter_mut().zip(output.iter_mut()).zip(input) {
            *g = factor.mul_add(*o, *g);
            *o = factor.mul_add(i, *o);
        }
    };

    step(model, context, 1.0);
    if let Some(noise) = params.noise {
        for _ in 0..params.neg_samples {
            let noise_node = noise.sample(rng.next_f64() * noise.len() as f64);
            // As in word2vec: the true context is never its own negative.
            if noise_node != context {
                step(model, noise_node, 0.0);
            }
        }
    }

    for (i, g) in model.input[center_range].iter_mut().zip(&model.grad) {
        *i += g;
    }
}

fn sigmoid(x: f64) -> f64 {
    1.0 / (1.0 + (-x).exp())
}

/// Builds the negative-sampling distribution: node `v` is drawn with
/// probability proportional to `degree(v)^0.75`, as in word2vec.
///
/// Returns `None` when every node is isolated.
#[allow(
    clippy::cast_precision_loss,
    reason = "counts and indices stay far below 2^52, so the f64 conversion is exact"
)]
pub fn build_noise_distribution(degrees: &[usize]) -> Option<AliasTable> {
    let weights: Vec<f64> = degrees.iter().map(|&d| (d as f64).powf(0.75)).collect();
    AliasTable::new(&weights)
}

#[cfg(test)]
#[allow(clippy::cast_precision_loss, reason = "test counts are small")]
mod tests {
    use super::*;

    /// Regression: the old fixed-size noise table re-added the current node's
    /// weight for every slot, so it held nothing but node 0 — every negative
    /// sample was node 0 — and it allocated 10^8 entries per `fit`.
    #[test]
    fn noise_distribution_follows_degree_power() {
        let degrees = [1usize, 2, 3, 4, 5, 0];
        let noise = build_noise_distribution(&degrees).unwrap();
        let mut rng = Rng::new(7);
        let draws = 200_000;
        let mut counts = [0usize; 6];
        for _ in 0..draws {
            counts[noise.sample(rng.next_f64() * noise.len() as f64)] += 1;
        }
        let weights: Vec<f64> = degrees.iter().map(|&d| (d as f64).powf(0.75)).collect();
        let total: f64 = weights.iter().sum();
        for (node, (&count, w)) in counts.iter().zip(&weights).enumerate() {
            let observed = count as f64 / f64::from(draws);
            let expected = w / total;
            assert!(
                (observed - expected).abs() < 0.01,
                "node {node}: observed {observed:.4}, expected {expected:.4}"
            );
        }
        assert_eq!(counts[5], 0, "isolated nodes are never drawn");
    }

    #[test]
    fn all_isolated_has_no_noise_distribution() {
        assert!(build_noise_distribution(&[0, 0, 0]).is_none());
        assert!(build_noise_distribution(&[]).is_none());
    }
}
