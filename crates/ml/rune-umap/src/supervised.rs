use std::collections::HashMap;

use rayon::prelude::*;

use crate::distance::{Metric, point_distance};

/// Builds a label-graph: for each labelled point, connect it to its `k` nearest
/// same-class neighbours with weight `target_weight`. Unlabelled points (`None`)
/// get no label edges, so they are placed by the structure graph alone
/// (semi-supervised mode).
///
/// Returns undirected edges `(i, j, weight)` with `i < j`.
pub fn label_edges(
    points: &[Vec<f64>],
    metric: Metric,
    labels: &[Option<i64>],
    k: usize,
    target_weight: f64,
) -> Vec<(usize, usize, f64)> {
    let n = labels.len();

    // For each point, find k nearest same-class neighbours (parallel).
    let per_point: Vec<Vec<usize>> = (0..n)
        .into_par_iter()
        .map(|i| {
            let Some(li) = labels[i] else {
                return Vec::new();
            };
            let mut same_class: Vec<(usize, f64)> = (0..n)
                .filter(|&j| j != i && labels[j] == Some(li))
                .map(|j| (j, point_distance(metric, &points[i], &points[j])))
                .collect();
            if same_class.len() > k && k > 0 {
                same_class.select_nth_unstable_by(k - 1, crate::nnd::by_dist);
            }
            same_class.truncate(k);
            same_class.into_iter().map(|(j, _)| j).collect()
        })
        .collect();

    // Deduplicate undirected edges.
    let mut edge_map: HashMap<(usize, usize), f64> = HashMap::new();
    for (i, neighbors) in per_point.into_iter().enumerate() {
        for j in neighbors {
            let key = if i < j { (i, j) } else { (j, i) };
            edge_map.entry(key).or_insert(target_weight);
        }
    }

    edge_map.into_iter().map(|((i, j), w)| (i, j, w)).collect()
}

/// Merges two fuzzy simplicial sets via fuzzy union:
/// `w_combined = w_a + w_b − w_a · w_b`.
///
/// Both inputs must have edges with `i < j`. Edges present in only one set are
/// included as-is (with the other weight being 0, so union = that weight).
pub fn merge_fuzzy(
    edges_a: &[(usize, usize, f64)],
    edges_b: &[(usize, usize, f64)],
) -> Vec<(usize, usize, f64)> {
    let mut map: HashMap<(usize, usize), (f64, f64)> = HashMap::new();

    for &(i, j, w) in edges_a {
        map.entry((i, j)).or_insert((0.0, 0.0)).0 = w;
    }
    for &(i, j, w) in edges_b {
        map.entry((i, j)).or_insert((0.0, 0.0)).1 = w;
    }

    map.into_iter()
        .filter_map(|((i, j), (wa, wb))| {
            let combined = f64::mul_add(wa, -wb, wa + wb);
            if combined > 0.0 {
                Some((i, j, combined))
            } else {
                None
            }
        })
        .collect()
}
