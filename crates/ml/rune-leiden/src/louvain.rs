//! The Louvain method.

use crate::engine::{Algorithm, Settings};
use crate::{CommunityResult, Error, Hierarchy, Quality};

/// Builder for the multi-level Louvain method (Blondel, Guillaume, Lambiotte
/// & Lefebvre, 2008).
///
/// Louvain alternates two steps: move nodes one at a time to the neighbouring
/// community with the best gain until nothing improves, then collapse every
/// community into a single node and repeat on the smaller graph. Each level is
/// a coarsening of the previous one, so the output is a true dendrogram (see
/// [`Louvain::fit_hierarchy`]).
///
/// Louvain is a little cheaper than [`Leiden`](crate::Leiden) but can return
/// communities that are internally disconnected; Leiden's refinement step
/// rules that out. Node visiting order is shuffled with a seeded PRNG, so
/// results are reproducible for a given seed.
///
/// # Example
///
/// ```rust
/// use rune_leiden::Louvain;
///
/// let edges = [
///     (0, 1, 1.0), (1, 2, 1.0), (0, 2, 1.0),
///     (3, 4, 1.0), (4, 5, 1.0), (3, 5, 1.0),
///     (2, 3, 0.01),
/// ];
/// let result = Louvain::new().random_seed(7).try_fit(6, &edges)?;
/// assert_eq!(result.n_communities, 2);
/// # Ok::<(), rune_leiden::Error>(())
/// ```
#[derive(Debug, Clone)]
pub struct Louvain {
    resolution: f64,
    max_levels: usize,
    random_seed: u64,
    quality: Quality,
}

impl Default for Louvain {
    fn default() -> Self {
        Self::new()
    }
}

impl Louvain {
    /// Creates a `Louvain` instance with default parameters.
    ///
    /// | Parameter | Default |
    /// |---|---|
    /// | `resolution` | `1.0` |
    /// | `max_levels` | `100` |
    /// | `random_seed` | `42` |
    /// | `quality` | [`Quality::Modularity`] |
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_leiden::Louvain;
    ///
    /// let louvain = Louvain::new();
    /// ```
    #[must_use]
    pub const fn new() -> Self {
        Self {
            resolution: 1.0,
            max_levels: 100,
            random_seed: 42,
            quality: Quality::Modularity,
        }
    }

    /// Sets the resolution parameter `γ`. Higher values give more, smaller
    /// communities.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_leiden::Louvain;
    ///
    /// let louvain = Louvain::new().resolution(1.5);
    /// ```
    #[must_use]
    pub const fn resolution(mut self, r: f64) -> Self {
        self.resolution = r;
        self
    }

    /// Sets the maximum number of levels (move-then-collapse rounds). The run
    /// stops earlier once a level makes no move.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_leiden::Louvain;
    ///
    /// // A single level of local moving, no aggregation.
    /// let louvain = Louvain::new().max_levels(1);
    /// ```
    #[must_use]
    pub const fn max_levels(mut self, n: usize) -> Self {
        self.max_levels = n;
        self
    }

    /// Sets the seed for the node-order shuffle. Identical seeds give
    /// identical partitions.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_leiden::Louvain;
    ///
    /// let louvain = Louvain::new().random_seed(123);
    /// ```
    #[must_use]
    pub const fn random_seed(mut self, s: u64) -> Self {
        self.random_seed = s;
        self
    }

    /// Sets the objective to maximise. Defaults to [`Quality::Modularity`].
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_leiden::{Louvain, Quality};
    ///
    /// let louvain = Louvain::new().quality(Quality::Cpm).resolution(0.2);
    /// ```
    #[must_use]
    pub const fn quality(mut self, quality: Quality) -> Self {
        self.quality = quality;
        self
    }

    /// Partitions the graph and returns the best level.
    ///
    /// `edges` holds undirected weighted edges `(u, v, weight)` with
    /// `u, v < n_nodes`. Parallel edges are summed; self-loops are ignored.
    /// Weights must be finite and non-negative.
    ///
    /// # Errors
    ///
    /// [`Error::EmptyGraph`], [`Error::NodeOutOfRange`],
    /// [`Error::InvalidWeight`] or [`Error::InvalidResolution`].
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_leiden::Louvain;
    ///
    /// let edges = [(0, 1, 1.0), (2, 3, 1.0)];
    /// let result = Louvain::new().try_fit(4, &edges)?;
    /// assert_eq!(result.n_communities, 2);
    /// # Ok::<(), rune_leiden::Error>(())
    /// ```
    pub fn try_fit(
        &self,
        n_nodes: usize,
        edges: &[(usize, usize, f64)],
    ) -> Result<CommunityResult, Error> {
        crate::validate(n_nodes, edges, self.resolution)?;
        if n_nodes == 1 {
            return Ok(crate::trivial_result(1));
        }
        Ok(crate::fit_unchecked(&self.settings(), n_nodes, edges))
    }

    /// Runs Louvain and returns the partition after every level, finest
    /// first. Each level merges whole communities of the one before, so the
    /// levels form a dendrogram; the last level is normally the best.
    ///
    /// # Errors
    ///
    /// Same as [`Louvain::try_fit`].
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_leiden::Louvain;
    ///
    /// let edges = [(0, 1, 1.0), (1, 2, 1.0), (2, 3, 1.0), (3, 0, 1.0)];
    /// let hierarchy = Louvain::new().fit_hierarchy(4, &edges)?;
    /// for level in &hierarchy.levels {
    ///     println!("{} communities, Q = {:.3}", level.n_communities, level.quality);
    /// }
    /// # Ok::<(), rune_leiden::Error>(())
    /// ```
    pub fn fit_hierarchy(
        &self,
        n_nodes: usize,
        edges: &[(usize, usize, f64)],
    ) -> Result<Hierarchy, Error> {
        crate::validate(n_nodes, edges, self.resolution)?;
        Ok(crate::hierarchy_unchecked(&self.settings(), n_nodes, edges))
    }

    const fn settings(&self) -> Settings {
        Settings {
            algorithm: Algorithm::Louvain,
            quality: self.quality,
            resolution: self.resolution,
            max_iter: self.max_levels,
            seed: self.random_seed,
            randomness: 0.0,
        }
    }
}
