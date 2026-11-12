//! Quality functions: modularity and the Constant Potts Model.

use crate::Error;
use crate::engine::renumber;
use crate::error::{validate_graph, validate_resolution};
use crate::graph::{self, Graph};

/// The objective a community-detection run maximises.
///
/// # Example
///
/// ```rust
/// use rune_leiden::{Leiden, Quality};
///
/// // CPM with γ = 0.5: a community is worth keeping only if its edge density
/// // is above one half.
/// let edges = [(0, 1, 1.0), (1, 2, 1.0), (0, 2, 1.0), (2, 3, 1.0)];
/// let result = Leiden::new().quality(Quality::Cpm).resolution(0.5).try_fit(4, &edges)?;
/// assert_eq!(result.communities[0], result.communities[1]);
/// # Ok::<(), rune_leiden::Error>(())
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum Quality {
    /// Newman–Girvan modularity with resolution `γ` (see [`modularity`]).
    /// Comparable across graphs, but subject to the resolution limit.
    #[default]
    Modularity,
    /// Constant Potts Model (Traag, Van Dooren & Nesterov, 2011; see [`cpm`]).
    /// `γ` acts as a density threshold: communities end up with internal edge
    /// density above `γ` and inter-community density below it. Free of the
    /// resolution limit. With CPM, `γ` should be on the scale of edge weights,
    /// typically between `0` and the largest weight.
    Cpm,
}

/// Weighted Newman–Girvan modularity of `partition` with resolution `γ`.
///
/// ```text
/// Q = (1/2m) × Σ_{ij} [A_ij − γ × k_i × k_j / (2m)] × δ(c_i, c_j)
/// ```
///
/// `partition[v]` is the community of node `v`; ids can be any `usize` values
/// and need not be contiguous. Parallel edges are summed and self-loops are
/// ignored, exactly as in fitting. A graph with no edge weight has
/// modularity `0`. At `γ = 1`, `Q` always lies in `[-1/2, 1)`.
///
/// # Errors
///
/// [`Error::EmptyGraph`], [`Error::NodeOutOfRange`], [`Error::InvalidWeight`]
/// (negative or non-finite), [`Error::InvalidResolution`] and
/// [`Error::PartitionLength`].
///
/// # Example
///
/// ```rust
/// // Two disjoint triangles, each its own community: Q = 2 × (3/6 − (6/12)²).
/// let edges = [
///     (0, 1, 1.0), (1, 2, 1.0), (0, 2, 1.0),
///     (3, 4, 1.0), (4, 5, 1.0), (3, 5, 1.0),
/// ];
/// let q = rune_leiden::modularity(6, &edges, &[7, 7, 7, 9, 9, 9], 1.0)?;
/// assert!((q - 0.5).abs() < 1e-12);
/// # Ok::<(), rune_leiden::Error>(())
/// ```
pub fn modularity(
    n_nodes: usize,
    edges: &[(usize, usize, f64)],
    partition: &[usize],
    resolution: f64,
) -> Result<f64, Error> {
    let (graph, partition) = prepare(n_nodes, edges, partition, resolution)?;
    Ok(graph::modularity(&graph, &partition, resolution))
}

/// Constant Potts Model quality of `partition` with resolution `γ`.
///
/// ```text
/// H = Σ_c [e_c − γ × n_c (n_c − 1) / 2]
/// ```
///
/// where `e_c` is the total edge weight inside community `c` and `n_c` its
/// node count. The value is not normalised; it grows with the graph. Parallel
/// edges are summed and self-loops are ignored.
///
/// # Errors
///
/// Same as [`modularity`].
///
/// # Example
///
/// ```rust
/// // A triangle plus a pendant node. Keeping the triangle together earns
/// // 3 − 0.5 × 3 = 1.5; the pendant node alone adds nothing.
/// let edges = [(0, 1, 1.0), (1, 2, 1.0), (0, 2, 1.0), (2, 3, 1.0)];
/// let h = rune_leiden::cpm(4, &edges, &[0, 0, 0, 1], 0.5)?;
/// assert!((h - 1.5).abs() < 1e-12);
/// # Ok::<(), rune_leiden::Error>(())
/// ```
pub fn cpm(
    n_nodes: usize,
    edges: &[(usize, usize, f64)],
    partition: &[usize],
    resolution: f64,
) -> Result<f64, Error> {
    let (graph, partition) = prepare(n_nodes, edges, partition, resolution)?;
    Ok(graph::cpm(&graph, &partition, resolution))
}

fn prepare(
    n_nodes: usize,
    edges: &[(usize, usize, f64)],
    partition: &[usize],
    resolution: f64,
) -> Result<(Graph, Vec<usize>), Error> {
    validate_graph(n_nodes, edges)?;
    validate_resolution(resolution)?;
    if partition.len() != n_nodes {
        return Err(Error::PartitionLength {
            expected: n_nodes,
            found: partition.len(),
        });
    }
    Ok((Graph::new(n_nodes, edges), renumber(partition)))
}
