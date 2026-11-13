//! Space-partitioning tree (binary tree / quadtree / octree for 1, 2 and 3
//! output dimensions) used by the Barnes-Hut approximation of the repulsive
//! forces (van der Maaten 2014, section 4.2).

/// Largest supported output dimensionality.
pub const MAX_DIM: usize = 3;

/// Cells are not split beyond this depth; deeper points (duplicates or
/// near-duplicates) share a leaf and are handled one by one.
const MAX_DEPTH: usize = 48;

struct Node {
    /// Centre of the cell.
    center: [f64; MAX_DIM],
    /// Half the side length of the (cubic) cell.
    half: f64,
    /// Centre of mass of the points in the cell.
    com: [f64; MAX_DIM],
    count: usize,
    /// Children are stored contiguously at `first_child..first_child + n_children`.
    first_child: usize,
    n_children: usize,
    /// For leaves: the points at `order[start..end]`.
    start: usize,
    end: usize,
}

/// A Barnes-Hut tree over an embedding stored as `n × dim` row-major values.
pub struct Tree<'a> {
    nodes: Vec<Node>,
    order: Vec<usize>,
    y: &'a [f64],
    dim: usize,
}

/// Repulsive-force contribution to one point: `z` is its share of the
/// normaliser `Z = Σ_{k≠l} (1 + ‖y_k − y_l‖²)⁻¹`, `force` is
/// `Σ_j (1 + ‖y_i − y_j‖²)⁻² (y_i − y_j)` (unnormalised).
pub struct Repulsion {
    pub z: f64,
    pub force: [f64; MAX_DIM],
}

impl<'a> Tree<'a> {
    /// Builds the tree over `y` (`n × dim`, `1 ≤ dim ≤ 3`).
    pub fn build(y: &'a [f64], dim: usize) -> Self {
        let n = y.len().checked_div(dim).unwrap_or(0);
        let mut lo = [f64::INFINITY; MAX_DIM];
        let mut hi = [f64::NEG_INFINITY; MAX_DIM];
        for p in y.chunks_exact(dim) {
            for d in 0..dim {
                lo[d] = lo[d].min(p[d]);
                hi[d] = hi[d].max(p[d]);
            }
        }
        let mut center = [0.0; MAX_DIM];
        let mut half = 0.0f64;
        for d in 0..dim {
            center[d] = f64::midpoint(lo[d], hi[d]);
            half = half.max((hi[d] - lo[d]) / 2.0);
        }
        // A little slack so points on the boundary sit strictly inside.
        let half = half.mul_add(1e-6, half).max(f64::MIN_POSITIVE);
        let mut tree = Self {
            nodes: Vec::with_capacity(2 * n.max(1)),
            order: (0..n).collect(),
            y,
            dim,
        };
        tree.nodes.push(Node {
            center,
            half,
            com: [0.0; MAX_DIM],
            count: 0,
            first_child: 0,
            n_children: 0,
            start: 0,
            end: n,
        });
        tree.split(0, 0);
        tree
    }

    fn point(&self, i: usize) -> &[f64] {
        &self.y[i * self.dim..(i + 1) * self.dim]
    }

    /// Fills in node `id` (whose `start..end` range is set) and splits it.
    #[allow(
        clippy::cast_precision_loss,
        reason = "point counts stay far below 2^52, so the f64 conversion is exact"
    )]
    fn split(&mut self, id: usize, depth: usize) {
        let (start, end) = (self.nodes[id].start, self.nodes[id].end);
        let dim = self.dim;
        let mut com = [0.0; MAX_DIM];
        for &i in &self.order[start..end] {
            let p = &self.y[i * dim..(i + 1) * dim];
            for d in 0..dim {
                com[d] += p[d];
            }
        }
        let count = end - start;
        for c in com.iter_mut().take(dim) {
            *c /= count as f64;
        }
        self.nodes[id].com = com;
        self.nodes[id].count = count;
        if count <= 1 || depth >= MAX_DEPTH {
            return;
        }

        // Counting sort of the points into the 2^dim orthants.
        let center = self.nodes[id].center;
        let orthant = |p: &[f64]| -> usize {
            (0..dim).fold(0, |acc, d| acc | (usize::from(p[d] > center[d]) << d))
        };
        let n_orthants = 1usize << dim;
        let mut counts = [0usize; 1 << MAX_DIM];
        for &i in &self.order[start..end] {
            counts[orthant(self.point(i))] += 1;
        }
        let mut offsets = [0usize; 1 << MAX_DIM];
        let mut acc = start;
        for o in 0..n_orthants {
            offsets[o] = acc;
            acc += counts[o];
        }
        let mut sorted = vec![0usize; count];
        let mut cursor = offsets;
        for &i in &self.order[start..end] {
            let o = orthant(self.point(i));
            sorted[cursor[o] - start] = i;
            cursor[o] += 1;
        }
        self.order[start..end].copy_from_slice(&sorted);

        let half = self.nodes[id].half / 2.0;
        let first_child = self.nodes.len();
        let mut children = Vec::new();
        for o in (0..n_orthants).filter(|&o| counts[o] > 0) {
            let mut c = center;
            for (d, cd) in c.iter_mut().enumerate().take(dim) {
                *cd += if o >> d & 1 == 1 { half } else { -half };
            }
            children.push(self.nodes.len());
            self.nodes.push(Node {
                center: c,
                half,
                com: [0.0; MAX_DIM],
                count: 0,
                first_child: 0,
                n_children: 0,
                start: offsets[o],
                end: offsets[o] + counts[o],
            });
        }
        self.nodes[id].first_child = first_child;
        self.nodes[id].n_children = children.len();
        for child in children {
            self.split(child, depth + 1);
        }
    }

    /// Barnes-Hut estimate of the repulsion on point `i`. A cell is
    /// summarised by its centre of mass when it does not contain `y_i` and
    /// `side / distance < theta`.
    pub fn repulsion(&self, i: usize, theta: f64) -> Repulsion {
        let dim = self.dim;
        let yi = self.point(i);
        let mut out = Repulsion {
            z: 0.0,
            force: [0.0; MAX_DIM],
        };
        let theta_sq = theta * theta;
        let mut stack = vec![0usize];
        while let Some(id) = stack.pop() {
            let node = &self.nodes[id];
            if node.count == 0 {
                continue;
            }
            if node.n_children == 0 {
                for &j in &self.order[node.start..node.end] {
                    if j != i {
                        add(&mut out, yi, self.point(j), 1.0, dim);
                    }
                }
                continue;
            }
            let side_sq = 4.0 * node.half * node.half;
            let dist_sq: f64 = (0..dim).map(|d| (yi[d] - node.com[d]).powi(2)).sum();
            let inside = (0..dim).all(|d| (yi[d] - node.center[d]).abs() <= node.half);
            #[allow(
                clippy::cast_precision_loss,
                reason = "point counts stay far below 2^52, so the f64 conversion is exact"
            )]
            if !inside && side_sq < theta_sq * dist_sq {
                add(&mut out, yi, &node.com, node.count as f64, dim);
            } else {
                stack.extend((node.first_child..node.first_child + node.n_children).rev());
            }
        }
        out
    }
}

fn add(out: &mut Repulsion, yi: &[f64], other: &[f64], weight: f64, dim: usize) {
    let dist_sq: f64 = (0..dim).map(|d| (yi[d] - other[d]).powi(2)).sum();
    let q = 1.0 / (1.0 + dist_sq);
    out.z = weight.mul_add(q, out.z);
    let w = weight * q * q;
    for d in 0..dim {
        out.force[d] = w.mul_add(yi[d] - other[d], out.force[d]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn exact(y: &[f64], dim: usize, i: usize) -> Repulsion {
        let mut out = Repulsion {
            z: 0.0,
            force: [0.0; MAX_DIM],
        };
        let n = y.len() / dim;
        for j in (0..n).filter(|&j| j != i) {
            add(
                &mut out,
                &y[i * dim..(i + 1) * dim],
                &y[j * dim..(j + 1) * dim],
                1.0,
                dim,
            );
        }
        out
    }

    #[allow(clippy::cast_precision_loss, reason = "tiny test sizes")]
    fn cloud(n: usize, dim: usize) -> Vec<f64> {
        (0..n * dim)
            .map(|k| ((k as f64) * 0.618_033_988_7).fract().mul_add(10.0, -5.0))
            .collect()
    }

    #[test]
    fn theta_zero_is_exact() {
        for dim in 1..=3 {
            let y = cloud(40, dim);
            let tree = Tree::build(&y, dim);
            for i in 0..40 {
                let (a, b) = (tree.repulsion(i, 0.0), exact(&y, dim, i));
                assert!((a.z - b.z).abs() < 1e-12);
                for d in 0..dim {
                    assert!((a.force[d] - b.force[d]).abs() < 1e-12);
                }
            }
        }
    }

    #[test]
    fn approximation_is_close_for_moderate_theta() {
        let y = cloud(200, 2);
        let tree = Tree::build(&y, 2);
        for i in (0..200).step_by(17) {
            let (a, b) = (tree.repulsion(i, 0.5), exact(&y, 2, i));
            assert!((a.z - b.z).abs() < 0.02 * b.z, "{} vs {}", a.z, b.z);
        }
    }

    #[test]
    fn duplicates_do_not_recurse_forever() {
        let y = vec![1.0; 2 * 50];
        let tree = Tree::build(&y, 2);
        let r = tree.repulsion(3, 0.5);
        assert!((r.z - 49.0).abs() < 1e-12);
        assert!(r.force.iter().all(|f| *f == 0.0));
    }
}
