//! Error type for validated entry points.

use std::fmt;

/// Reasons a graph, partition or parameter was rejected.
///
/// Returned by [`Leiden::try_fit`](crate::Leiden::try_fit),
/// [`Louvain::try_fit`](crate::Louvain::try_fit), the `fit_hierarchy` methods
/// and the free functions [`modularity`](crate::modularity) and
/// [`cpm`](crate::cpm).
///
/// # Example
///
/// ```rust
/// use rune_leiden::{Error, Leiden};
///
/// let err = Leiden::new().try_fit(2, &[(0, 1, -1.0)]).unwrap_err();
/// assert!(matches!(err, Error::InvalidWeight { edge: 0, .. }));
/// ```
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum Error {
    /// The graph has no nodes (`n_nodes == 0`).
    EmptyGraph,
    /// An edge refers to a node index `≥ n_nodes`.
    NodeOutOfRange {
        /// Position of the offending edge in the edge list.
        edge: usize,
        /// The out-of-range node index.
        node: usize,
        /// The declared node count.
        n_nodes: usize,
    },
    /// An edge weight is negative, NaN or infinite.
    InvalidWeight {
        /// Position of the offending edge in the edge list.
        edge: usize,
        /// The rejected weight.
        weight: f64,
    },
    /// The resolution parameter is negative, NaN or infinite.
    InvalidResolution(f64),
    /// A partition does not have exactly one entry per node.
    PartitionLength {
        /// The node count of the graph.
        expected: usize,
        /// The length of the supplied partition.
        found: usize,
    },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyGraph => f.write_str("graph has no nodes"),
            Self::NodeOutOfRange {
                edge,
                node,
                n_nodes,
            } => write!(
                f,
                "edge {edge}: node index {node} out of range (n_nodes = {n_nodes})"
            ),
            Self::InvalidWeight { edge, weight } => write!(
                f,
                "edge {edge}: weight {weight} is not a finite non-negative number"
            ),
            Self::InvalidResolution(r) => {
                write!(f, "resolution {r} is not a finite non-negative number")
            }
            Self::PartitionLength { expected, found } => write!(
                f,
                "partition has {found} entries but the graph has {expected} nodes"
            ),
        }
    }
}

impl std::error::Error for Error {}

/// Checks the node count and every edge.
pub fn validate_graph(n_nodes: usize, edges: &[(usize, usize, f64)]) -> Result<(), Error> {
    if n_nodes == 0 {
        return Err(Error::EmptyGraph);
    }
    for (edge, &(u, v, weight)) in edges.iter().enumerate() {
        for node in [u, v] {
            if node >= n_nodes {
                return Err(Error::NodeOutOfRange {
                    edge,
                    node,
                    n_nodes,
                });
            }
        }
        if !weight.is_finite() || weight < 0.0 {
            return Err(Error::InvalidWeight { edge, weight });
        }
    }
    Ok(())
}

/// Checks the resolution parameter.
pub fn validate_resolution(resolution: f64) -> Result<(), Error> {
    if resolution.is_finite() && resolution >= 0.0 {
        Ok(())
    } else {
        Err(Error::InvalidResolution(resolution))
    }
}
