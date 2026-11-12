use crate::mst::MstEdge;

/// One merge step in the HDBSCAN dendrogram.
///
/// `left` and `right` are component labels (point index `0..n` for leaves,
/// `n..2n-2` for previously-merged components). `merges[k]` creates node `n+k`.
pub struct Merge {
    pub left: usize,
    pub right: usize,
    pub distance: f64,
    pub size: usize,
}

/// One edge in the condensed cluster tree.
///
/// - `parent` is always a cluster label.
/// - If `child_size == 1`, `child` is a point index falling out as noise.
/// - If `child_size > 1`, `child` is a cluster label splitting off from `parent`.
/// - `lambda` is `1 / distance` at which the event occurs.
pub struct CondensedEdge {
    pub parent: usize,
    pub child: usize,
    pub lambda: f64,
    pub child_size: usize,
}

struct UnionFind {
    parent: Vec<usize>,
    size: Vec<usize>,
}

impl UnionFind {
    fn new(n: usize) -> Self {
        let parent = (0..2 * n).collect();
        let mut size = vec![0usize; 2 * n];
        for s in size.iter_mut().take(n) {
            *s = 1;
        }
        Self { parent, size }
    }

    fn find(&mut self, x: usize) -> usize {
        let mut root = x;
        while self.parent[root] != root {
            root = self.parent[root];
        }
        let mut current = x;
        while self.parent[current] != root {
            let next = self.parent[current];
            self.parent[current] = root;
            current = next;
        }
        root
    }
}

/// Converts sorted MST edges into a dendrogram using Union-Find.
///
/// Processes edges in ascending weight order. Each merge creates a new component
/// labelled `n + step`, so leaves are `0..n` and internal nodes are `n..2n-2`.
pub fn build_dendrogram(n: usize, mst: &[MstEdge]) -> Vec<Merge> {
    let mut sorted: Vec<&MstEdge> = mst.iter().collect();
    sorted.sort_by(|a, b| {
        a.weight
            .partial_cmp(&b.weight)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    let mut uf = UnionFind::new(n);
    let mut merges = Vec::with_capacity(n - 1);

    for (step, edge) in sorted.iter().enumerate() {
        let left_root = uf.find(edge.u);
        let right_root = uf.find(edge.v);
        let left_size = uf.size[left_root];
        let right_size = uf.size[right_root];
        let new_label = n + step;

        uf.parent[left_root] = new_label;
        uf.parent[right_root] = new_label;
        uf.parent[new_label] = new_label;
        uf.size[new_label] = left_size + right_size;

        merges.push(Merge {
            left: left_root,
            right: right_root,
            distance: edge.weight,
            size: left_size + right_size,
        });
    }

    merges
}

/// Prunes the dendrogram into the condensed cluster tree.
///
/// At each split, components with `size < min_cluster_size` are not new clusters —
/// their points "fall out" at the split's lambda. The surviving component inherits
/// the parent cluster label and continues.
pub fn condense(merges: &[Merge], n: usize, min_cluster_size: usize) -> Vec<CondensedEdge> {
    let mut result: Vec<CondensedEdge> = Vec::new();

    if merges.is_empty() {
        return result;
    }

    let root = n + merges.len() - 1;

    // Stack: (dendrogram_node, owning_cluster_label)
    let mut stack: Vec<(usize, usize)> = vec![(root, root)];

    while let Some((node, cluster_label)) = stack.pop() {
        if node < n {
            continue;
        }

        let merge = &merges[node - n];
        let lambda = safe_lambda(merge.distance);

        let left = merge.left;
        let right = merge.right;
        let left_size = component_size(left, merges, n);
        let right_size = component_size(right, merges, n);

        match (
            left_size >= min_cluster_size,
            right_size >= min_cluster_size,
        ) {
            (true, true) => {
                result.push(CondensedEdge {
                    parent: cluster_label,
                    child: left,
                    lambda,
                    child_size: left_size,
                });
                result.push(CondensedEdge {
                    parent: cluster_label,
                    child: right,
                    lambda,
                    child_size: right_size,
                });
                stack.push((left, left));
                stack.push((right, right));
            }
            (true, false) => {
                emit_points(right, merges, n, cluster_label, lambda, &mut result);
                stack.push((left, cluster_label));
            }
            (false, true) => {
                emit_points(left, merges, n, cluster_label, lambda, &mut result);
                stack.push((right, cluster_label));
            }
            (false, false) => {
                emit_points(left, merges, n, cluster_label, lambda, &mut result);
                emit_points(right, merges, n, cluster_label, lambda, &mut result);
            }
        }
    }

    result
}

const fn component_size(node: usize, merges: &[Merge], n: usize) -> usize {
    if node < n { 1 } else { merges[node - n].size }
}

fn safe_lambda(distance: f64) -> f64 {
    if distance > 1e-10 {
        1.0 / distance
    } else {
        1e10
    }
}

/// Recursively emits all leaf points in `node`'s subtree as falling out of `cluster` at `lambda`.
fn emit_points(
    node: usize,
    merges: &[Merge],
    n: usize,
    cluster: usize,
    lambda: f64,
    result: &mut Vec<CondensedEdge>,
) {
    let mut stack = vec![node];
    while let Some(curr) = stack.pop() {
        if curr < n {
            result.push(CondensedEdge {
                parent: cluster,
                child: curr,
                lambda,
                child_size: 1,
            });
        } else {
            let m = &merges[curr - n];
            stack.push(m.left);
            stack.push(m.right);
        }
    }
}
