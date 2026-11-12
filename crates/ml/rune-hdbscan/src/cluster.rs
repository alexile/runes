use std::collections::{HashMap, HashSet, VecDeque};

use crate::tree::CondensedEdge;

struct ClusterIndex {
    parent: HashMap<usize, usize>,
    children: HashMap<usize, Vec<usize>>,
    birth: HashMap<usize, f64>,
    point_info: Vec<Option<(usize, f64)>>,
}

/// Extracts flat clusters and soft membership probabilities from the condensed tree.
///
/// Returns `(labels, probabilities)` where `labels[i] == -1` means noise.
pub fn extract(condensed: &[CondensedEdge], n: usize) -> (Vec<i32>, Vec<f64>) {
    if condensed.is_empty() {
        return (vec![-1; n], vec![0.0; n]);
    }

    let idx = build_cluster_index(condensed, n);

    let root = find_root(condensed, &idx.parent);
    let stabilities = compute_stabilities(condensed, &idx.birth);
    let topo = bfs_order(root, &idx.children);
    let selected = select_clusters(&topo, &idx.children, &stabilities);

    let cluster_id = assign_ids(&selected);
    let max_lambda = compute_max_lambda(condensed, &idx.parent, &selected);

    assign_labels_and_probs(
        n,
        &idx.point_info,
        &idx.parent,
        &selected,
        &cluster_id,
        &max_lambda,
    )
}

fn build_cluster_index(condensed: &[CondensedEdge], n: usize) -> ClusterIndex {
    let mut parent: HashMap<usize, usize> = HashMap::new();
    let mut children: HashMap<usize, Vec<usize>> = HashMap::new();
    let mut birth: HashMap<usize, f64> = HashMap::new();
    let mut point_info: Vec<Option<(usize, f64)>> = vec![None; n];

    for edge in condensed {
        if edge.child_size > 1 {
            parent.insert(edge.child, edge.parent);
            children.entry(edge.parent).or_default().push(edge.child);
            birth.entry(edge.child).or_insert(edge.lambda);
        } else if edge.child < n {
            point_info[edge.child].get_or_insert((edge.parent, edge.lambda));
        }
    }

    ClusterIndex {
        parent,
        children,
        birth,
        point_info,
    }
}

fn find_root(condensed: &[CondensedEdge], cluster_parent: &HashMap<usize, usize>) -> usize {
    condensed
        .iter()
        .map(|e| e.parent)
        .find(|c| !cluster_parent.contains_key(c))
        .unwrap_or(0)
}

/// `stability(C) = Σ child_size × (child_lambda − birth_lambda(C))` for all edges from C.
#[allow(
    clippy::cast_precision_loss,
    reason = "counts and indices stay far below 2^52, so the f64 conversion is exact"
)]
fn compute_stabilities(
    condensed: &[CondensedEdge],
    birth: &HashMap<usize, f64>,
) -> HashMap<usize, f64> {
    let mut stability: HashMap<usize, f64> = HashMap::new();
    for edge in condensed {
        let lambda_birth = *birth.get(&edge.parent).unwrap_or(&0.0);
        let contrib = edge.child_size as f64 * (edge.lambda - lambda_birth).max(0.0);
        *stability.entry(edge.parent).or_insert(0.0) += contrib;
    }
    stability
}

fn bfs_order(root: usize, children: &HashMap<usize, Vec<usize>>) -> Vec<usize> {
    let mut order = Vec::new();
    let mut queue = VecDeque::new();
    queue.push_back(root);
    while let Some(node) = queue.pop_front() {
        order.push(node);
        if let Some(ch) = children.get(&node) {
            for &child in ch {
                queue.push_back(child);
            }
        }
    }
    order
}

/// Greedily selects clusters bottom-up: a cluster is chosen over its children when its
/// own stability exceeds the sum of its children's effective stabilities.
fn select_clusters(
    topo: &[usize],
    children: &HashMap<usize, Vec<usize>>,
    stabilities: &HashMap<usize, f64>,
) -> HashSet<usize> {
    let mut effective: HashMap<usize, f64> = HashMap::new();
    let mut selected: HashSet<usize> = HashSet::new();

    for &cluster in topo.iter().rev() {
        let self_stab = *stabilities.get(&cluster).unwrap_or(&0.0);
        let child_clusters = children.get(&cluster).map_or(&[][..], Vec::as_slice);

        if child_clusters.is_empty() {
            selected.insert(cluster);
            effective.insert(cluster, self_stab);
        } else {
            let child_stab: f64 = child_clusters
                .iter()
                .map(|c| *effective.get(c).unwrap_or(&0.0))
                .sum();

            if self_stab >= child_stab {
                deselect_subtree(child_clusters, children, &mut selected);
                selected.insert(cluster);
                effective.insert(cluster, self_stab);
            } else {
                effective.insert(cluster, child_stab);
            }
        }
    }

    selected
}

fn deselect_subtree(
    clusters: &[usize],
    children: &HashMap<usize, Vec<usize>>,
    selected: &mut HashSet<usize>,
) {
    for &c in clusters {
        selected.remove(&c);
        if let Some(ch) = children.get(&c) {
            deselect_subtree(ch, children, selected);
        }
    }
}

#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    reason = "the value is non-negative and bounded by the input size; float-to-int `as` saturates"
)]
fn assign_ids(selected: &HashSet<usize>) -> HashMap<usize, i32> {
    let mut sorted: Vec<usize> = selected.iter().copied().collect();
    sorted.sort_unstable();
    sorted
        .iter()
        .enumerate()
        .map(|(i, &c)| (c, i as i32))
        .collect()
}

/// Maximum lambda seen in each selected cluster — used to normalize probabilities.
fn compute_max_lambda(
    condensed: &[CondensedEdge],
    cluster_parent: &HashMap<usize, usize>,
    selected: &HashSet<usize>,
) -> HashMap<usize, f64> {
    let mut max_lambda: HashMap<usize, f64> = HashMap::new();
    for edge in condensed {
        if let Some(c) = find_selected_ancestor(edge.parent, cluster_parent, selected) {
            let entry = max_lambda.entry(c).or_insert(0.0);
            *entry = entry.max(edge.lambda);
        }
    }
    max_lambda
}

fn assign_labels_and_probs(
    n: usize,
    point_info: &[Option<(usize, f64)>],
    cluster_parent: &HashMap<usize, usize>,
    selected: &HashSet<usize>,
    cluster_id: &HashMap<usize, i32>,
    max_lambda: &HashMap<usize, f64>,
) -> (Vec<i32>, Vec<f64>) {
    let mut labels = vec![-1i32; n];
    let mut probs = vec![0.0f64; n];

    for point in 0..n {
        let Some((home, point_lambda)) = point_info[point] else {
            continue;
        };
        let Some(cluster) = find_selected_ancestor(home, cluster_parent, selected) else {
            continue;
        };
        let Some(&int_label) = cluster_id.get(&cluster) else {
            continue;
        };

        labels[point] = int_label;
        let ml = max_lambda.get(&cluster).copied().unwrap_or(1.0);
        probs[point] = if ml > 0.0 {
            (point_lambda / ml).min(1.0)
        } else {
            1.0
        };
    }

    (labels, probs)
}

fn find_selected_ancestor(
    mut cluster: usize,
    parent: &HashMap<usize, usize>,
    selected: &HashSet<usize>,
) -> Option<usize> {
    loop {
        if selected.contains(&cluster) {
            return Some(cluster);
        }
        cluster = *parent.get(&cluster)?;
    }
}
