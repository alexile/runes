use crate::alias::AliasTable;
use crate::rng::Rng;

/// Generates biased random walks from every node.
///
/// Returns a flat list of walks; each walk is a `Vec<usize>` of node indices
/// with length at most `walk_length` (shorter only for isolated nodes, which
/// produce a walk of length 1).
pub fn generate_walks(
    adjacency: &[Vec<usize>],
    walk_length: usize,
    num_walks: usize,
    p: f64,
    q: f64,
    rng: &mut Rng,
) -> Vec<Vec<usize>> {
    let n_nodes = adjacency.len();
    let mut all_walks: Vec<Vec<usize>> = Vec::with_capacity(n_nodes * num_walks);

    for _ in 0..num_walks {
        for start in 0..n_nodes {
            all_walks.push(single_walk(adjacency, start, walk_length, p, q, rng));
        }
    }

    all_walks
}

/// Produces one biased walk starting at `start`.
fn single_walk(
    adjacency: &[Vec<usize>],
    start: usize,
    walk_length: usize,
    p: f64,
    q: f64,
    rng: &mut Rng,
) -> Vec<usize> {
    let mut walk = Vec::with_capacity(walk_length);
    walk.push(start);

    if adjacency[start].is_empty() {
        return walk;
    }

    // First step: uniform over neighbours of start.
    let first = adjacency[start][rng.next_usize(adjacency[start].len())];
    walk.push(first);

    while walk.len() < walk_length {
        let [.., previous, current] = walk[..] else {
            break;
        };
        let neighbours = &adjacency[current];
        if neighbours.is_empty() {
            break;
        }

        let next = biased_sample(adjacency, previous, current, neighbours, p, q, rng);
        walk.push(next);
    }

    walk
}

/// Samples the next node in a walk using the node2vec transition probabilities.
///
/// Weights are proportional to:
/// - `1/p` for the previous node (return)
/// - `1.0` for common neighbours of previous and current (stay close)
/// - `1/q` for all other nodes (explore)
#[allow(
    clippy::cast_precision_loss,
    reason = "counts and indices stay far below 2^52, so the f64 conversion is exact"
)]
#[allow(
    clippy::too_many_arguments,
    reason = "hot inner-loop helper; a parameter struct would only add indirection"
)]
fn biased_sample(
    adjacency: &[Vec<usize>],
    previous: usize,
    _current: usize,
    neighbours: &[usize],
    p: f64,
    q: f64,
    rng: &mut Rng,
) -> usize {
    let prev_neighbours = &adjacency[previous];

    let weights: Vec<f64> = neighbours
        .iter()
        .map(|&x| transition_weight(x, previous, prev_neighbours, p, q))
        .collect();

    match AliasTable::new(&weights) {
        Some(table) => {
            let uniform = rng.next_f64() * neighbours.len() as f64;
            neighbours[table.sample(uniform)]
        }
        None => {
            // All weights zero — fall back to uniform (should not happen with valid p, q > 0).
            neighbours[rng.next_usize(neighbours.len())]
        }
    }
}

/// Returns the unnormalised transition weight for moving from `current` to `x`.
fn transition_weight(x: usize, previous: usize, prev_neighbours: &[usize], p: f64, q: f64) -> f64 {
    if x == previous {
        1.0 / p
    } else if prev_neighbours.binary_search(&x).is_ok() {
        1.0
    } else {
        1.0 / q
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn chain_adjacency(n: usize) -> Vec<Vec<usize>> {
        (0..n)
            .map(|i| {
                let mut nb = Vec::new();
                if i > 0 {
                    nb.push(i - 1);
                }
                if i + 1 < n {
                    nb.push(i + 1);
                }
                nb
            })
            .collect()
    }

    #[test]
    fn walk_length_respected() {
        let adj = chain_adjacency(10);
        let mut rng = Rng::new(42);
        let walks = generate_walks(&adj, 5, 3, 1.0, 1.0, &mut rng);
        for walk in &walks {
            assert!(walk.len() <= 5, "walk length {} exceeds 5", walk.len());
        }
    }

    #[test]
    fn isolated_node_produces_length_one_walk() {
        let adj = vec![vec![], vec![0usize], vec![1usize]];
        let mut rng = Rng::new(1);
        let walks = generate_walks(&adj, 10, 1, 1.0, 1.0, &mut rng);
        let isolated_walks: Vec<_> = walks.iter().filter(|w| w[0] == 0).collect();
        assert_ne!(isolated_walks, [] as [&Vec<usize>; 0]);
        for walk in isolated_walks {
            assert_eq!(walk.len(), 1, "isolated node must produce walk of length 1");
        }
    }

    #[test]
    fn total_walk_count_matches() {
        let adj = chain_adjacency(6);
        let mut rng = Rng::new(7);
        let walks = generate_walks(&adj, 5, 3, 1.0, 1.0, &mut rng);
        assert_eq!(walks.len(), 6 * 3);
    }

    #[test]
    fn all_nodes_in_walks_are_valid() {
        let adj = chain_adjacency(8);
        let mut rng = Rng::new(99);
        let walks = generate_walks(&adj, 10, 2, 1.0, 1.0, &mut rng);
        for walk in &walks {
            for &node in walk {
                assert!(node < 8, "node index {node} out of range");
            }
        }
    }
}
