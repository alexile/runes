//! Online leader clustering over signatures.
//!
//! Items arrive one at a time. Each joins the most similar existing
//! cluster whose *leader* (first member) is at least
//! [`ClusterOptions::threshold`] similar, or else founds a new cluster.
//! One pass, no rebalancing: cheap, deterministic, order-dependent.

use std::collections::HashMap;

use crate::Error;
use crate::hash::mix64;
use crate::minhash::MinHashSignature;
use crate::simhash::SimHash;

/// A signature the [`Clusterer`] can compare and index.
pub trait Signature {
    /// Similarity in `[0, 1]`, 1 meaning identical.
    fn similarity(&self, other: &Self) -> f64;

    /// Locality-sensitive bucket keys for banded candidate lookup: the
    /// signature split into `bands` contiguous bands, each hashed together
    /// with its band index. Two signatures that agree on any whole band
    /// share a key. `bands` is clamped to `1..=` the signature's length.
    fn band_keys(&self, bands: usize) -> Vec<u64>;
}

impl Signature for SimHash {
    fn similarity(&self, other: &Self) -> f64 {
        Self::similarity(*self, *other)
    }

    /// Splits the 64 bits into `bands` near-equal bit ranges. By the
    /// pigeonhole principle, fingerprints within Hamming distance
    /// `bands − 1` always share a key.
    fn band_keys(&self, bands: usize) -> Vec<u64> {
        let bands = bands.clamp(1, 64);
        let mut keys = Vec::with_capacity(bands);
        let mut start = 0;
        for i in 0..bands {
            let end = (i + 1) * 64 / bands;
            let width = end - start;
            let mask = if width == 64 {
                u64::MAX
            } else {
                (1u64 << width) - 1
            };
            let part = (self.0 >> start) & mask;
            keys.push(mix64(part ^ mix64(i as u64)));
            start = end;
        }
        keys
    }
}

impl Signature for MinHashSignature {
    /// The Jaccard estimate; signatures of different lengths score 0.
    fn similarity(&self, other: &Self) -> f64 {
        self.jaccard(other).unwrap_or(0.0)
    }

    /// Classic MinHash LSH banding: with `b` bands of `r` rows, a pair with
    /// Jaccard `J` becomes a candidate with probability `1 − (1 − J^r)^b`.
    fn band_keys(&self, bands: usize) -> Vec<u64> {
        let n = self.len();
        if n == 0 {
            return vec![0];
        }
        let bands = bands.clamp(1, n);
        let mut keys = Vec::with_capacity(bands);
        let mut start = 0;
        for i in 0..bands {
            let end = (i + 1) * n / bands;
            let key = self.values()[start..end]
                .iter()
                .fold(mix64(i as u64), |acc, &v| mix64(acc ^ v));
            keys.push(key);
            start = end;
        }
        keys
    }
}

/// Settings for a [`Clusterer`].
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct ClusterOptions {
    /// Minimum similarity to join a cluster, in `[0, 1]`.
    ///
    /// For [`SimHash`], similarity is `1 − hamming/64`. Two unrelated
    /// fingerprints differ in 32 ± 4 bits (similarity ≈ 0.5), while
    /// changing a fraction `f` of a document's shingles moves about
    /// `64·acos(1 − f)/π` bits: 2 % of shingles ≈ 4 bits, 10 % ≈ 9 bits.
    /// The default 0.8 (distance ≤ 12) collapses templated pages with a
    /// few changed words and puts unrelated texts more than 4.5 standard
    /// deviations away. Raise it toward 0.95 (distance ≤ 3, the setting
    /// of Manku et al. for large web pages) for long documents.
    ///
    /// For MinHash it is the estimated Jaccard similarity of the shingle
    /// sets; 0.7–0.8 is a usual near-duplicate setting.
    pub threshold: f64,
    /// Compare only against clusters sharing a band key (see
    /// [`Signature::band_keys`]) instead of every cluster. `None` (the
    /// default) scans all leaders and never misses a match; `Some(b)`
    /// trades a miss rate for sub-linear lookups.
    ///
    /// For [`SimHash`], `b` bands guarantee every pair within Hamming
    /// distance `b − 1` is compared; farther pairs that still pass the
    /// threshold may be missed. Fewer, wider bands mean fewer candidates.
    /// For MinHash, `b` bands of `r = n/b` rows catch a pair of Jaccard
    /// `J` with probability `1 − (1 − J^r)^b`: 32 bands of 4 rows (128
    /// hashes) catch `J = 0.7` pairs 99.9 % of the time.
    pub bands: Option<usize>,
}

impl Default for ClusterOptions {
    /// Threshold 0.8, exhaustive scan.
    fn default() -> Self {
        Self {
            threshold: 0.8,
            bands: None,
        }
    }
}

impl ClusterOptions {
    /// Sets [`ClusterOptions::threshold`].
    #[must_use]
    pub const fn with_threshold(mut self, threshold: f64) -> Self {
        self.threshold = threshold;
        self
    }

    /// Sets [`ClusterOptions::bands`].
    #[must_use]
    pub const fn with_bands(mut self, bands: Option<usize>) -> Self {
        self.bands = bands;
        self
    }
}

/// One cluster: its leader and how many items joined it.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct Cluster<S> {
    /// Index of the cluster in [`Clusterer::clusters`].
    pub id: usize,
    /// The signature of the first item, against which newcomers compare.
    pub leader: S,
    /// Number of items in the cluster, leader included.
    pub size: usize,
}

/// Where [`Clusterer::assign`] put an item.
#[derive(Debug, Clone, Copy, PartialEq)]
#[non_exhaustive]
pub struct Assignment {
    /// The cluster the item joined or founded.
    pub cluster: usize,
    /// Whether the item founded a new cluster.
    pub created: bool,
    /// Similarity to the leader (1 for a new cluster).
    pub similarity: f64,
}

/// Online leader clusterer.
///
/// ```
/// use rune_simhash::{ClusterOptions, Clusterer, ShingleOptions, SimHash};
///
/// let o = ShingleOptions::default().with_strip_html(true);
/// let page = |path: &str| {
///     format!("<html><body><h1>Oops</h1><p>The page {path} could not be found on this \
///              server. Please check the address or go back to the home page and try \
///              searching for what you need.</p></body></html>")
/// };
/// let mut c = Clusterer::new(ClusterOptions::default())?;
/// let a = c.assign(SimHash::from_text(&page("/admin"), &o)?);
/// let b = c.assign(SimHash::from_text(&page("/backup.zip"), &o)?);
/// let d = c.assign(SimHash::from_text("<h1>Dashboard</h1><p>Welcome back, alice</p>", &o)?);
/// assert_eq!(a.cluster, b.cluster); // soft-404s collapse
/// assert!(d.created);
/// assert_eq!(c.clusters().len(), 2);
/// # Ok::<(), rune_simhash::Error>(())
/// ```
#[derive(Debug, Clone)]
pub struct Clusterer<S> {
    options: ClusterOptions,
    clusters: Vec<Cluster<S>>,
    index: HashMap<u64, Vec<usize>>,
}

impl<S: Signature> Clusterer<S> {
    /// An empty clusterer.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidParameter`] if the threshold is not in `[0, 1]` or
    /// `bands` is `Some(0)`.
    pub fn new(options: ClusterOptions) -> Result<Self, Error> {
        if !(0.0..=1.0).contains(&options.threshold) {
            return Err(Error::InvalidParameter {
                name: "threshold",
                reason: "must be in [0, 1]",
            });
        }
        if options.bands == Some(0) {
            return Err(Error::InvalidParameter {
                name: "bands",
                reason: "must be at least 1",
            });
        }
        Ok(Self {
            options,
            clusters: Vec::new(),
            index: HashMap::new(),
        })
    }

    /// The options this clusterer was built with.
    #[must_use]
    pub const fn options(&self) -> &ClusterOptions {
        &self.options
    }

    /// The clusters so far, indexed by id.
    #[must_use]
    pub fn clusters(&self) -> &[Cluster<S>] {
        &self.clusters
    }

    /// The best existing cluster for `signature` at or above the
    /// threshold, without inserting it. Ties go to the older cluster.
    #[must_use]
    pub fn find(&self, signature: &S) -> Option<(usize, f64)> {
        let mut best: Option<(usize, f64)> = None;
        let mut consider = |id: usize| {
            let s = self.clusters[id].leader.similarity(signature);
            if s >= self.options.threshold
                && best.is_none_or(|(bid, bs)| s > bs || (s.total_cmp(&bs).is_eq() && id < bid))
            {
                best = Some((id, s));
            }
        };
        match self.options.bands {
            None => (0..self.clusters.len()).for_each(&mut consider),
            Some(b) => {
                let mut seen = Vec::new();
                for key in signature.band_keys(b) {
                    for &id in self.index.get(&key).map_or(&[][..], Vec::as_slice) {
                        if !seen.contains(&id) {
                            seen.push(id);
                            consider(id);
                        }
                    }
                }
            }
        }
        best
    }

    /// Adds an item: joins the best matching cluster or founds a new one.
    pub fn assign(&mut self, signature: S) -> Assignment {
        if let Some((id, similarity)) = self.find(&signature) {
            self.clusters[id].size += 1;
            return Assignment {
                cluster: id,
                created: false,
                similarity,
            };
        }
        let id = self.clusters.len();
        if let Some(b) = self.options.bands {
            for key in signature.band_keys(b) {
                self.index.entry(key).or_default().push(id);
            }
        }
        self.clusters.push(Cluster {
            id,
            leader: signature,
            size: 1,
        });
        Assignment {
            cluster: id,
            created: true,
            similarity: 1.0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MinHasher;

    #[test]
    fn rejects_bad_options() {
        let bad = |o| Clusterer::<SimHash>::new(o).is_err();
        assert!(bad(ClusterOptions::default().with_threshold(1.5)));
        assert!(bad(ClusterOptions::default().with_threshold(f64::NAN)));
        assert!(bad(ClusterOptions::default().with_bands(Some(0))));
        assert!(!bad(ClusterOptions::default().with_bands(Some(8))));
    }

    #[test]
    fn simhash_bands_cover_all_bits() {
        for b in [1, 3, 7, 8, 64, 1000] {
            let keys = SimHash(0x0123_4567_89ab_cdef).band_keys(b);
            assert_eq!(keys.len(), b.min(64));
        }
    }

    #[test]
    fn pigeonhole_guarantee() {
        // Flip 7 bits spread over the word: with 8 bands one band is intact.
        let a = SimHash(0xdead_beef_cafe_f00d);
        let b = SimHash(a.0 ^ (1 | 1 << 9 | 1 << 18 | 1 << 27 | 1 << 36 | 1 << 45 | 1 << 54));
        let ka = a.band_keys(8);
        assert!(b.band_keys(8).iter().any(|k| ka.contains(k)));
    }

    #[test]
    fn banded_and_exhaustive_agree_for_simhash() {
        let base = 0x5555_aaaa_1234_5678u64;
        let items: Vec<SimHash> = (0..200u64)
            .map(|i| {
                SimHash(if i % 2 == 0 {
                    base ^ (1 << (i % 64))
                } else {
                    mix64(i)
                })
            })
            .collect();
        let opts = ClusterOptions::default().with_threshold(0.9);
        let mut full = Clusterer::new(opts.clone()).unwrap();
        let mut banded = Clusterer::new(opts.with_bands(Some(8))).unwrap();
        for s in items {
            assert_eq!(full.assign(s).cluster, banded.assign(s).cluster);
        }
        assert_eq!(full.clusters().len(), banded.clusters().len());
    }

    #[test]
    fn best_match_wins() {
        let mut c = Clusterer::new(ClusterOptions::default().with_threshold(0.8)).unwrap();
        c.assign(SimHash(0));
        c.assign(SimHash(0xFFFF)); // distance 16 → similarity 0.75: new cluster
        assert_eq!(c.clusters().len(), 2);
        let a = c.assign(SimHash(0xFFF0)); // 12 from #0, 4 from #1
        assert_eq!(a.cluster, 1);
        assert!(!a.created);
        assert_eq!(c.clusters()[1].size, 2);
    }

    #[test]
    fn minhash_clusters_with_lsh() {
        let hasher = MinHasher::new(64, 1).unwrap();
        let mut clusters = Clusterer::new(
            ClusterOptions::default()
                .with_threshold(0.7)
                .with_bands(Some(16)),
        )
        .unwrap();
        let first = clusters.assign(hasher.signature(0..200));
        let near = clusters.assign(hasher.signature(5..205));
        let far = clusters.assign(hasher.signature(1000..1200));
        assert_eq!(first.cluster, near.cluster);
        assert!(far.created);
        assert!(clusters.find(&hasher.signature(1000..1199)).is_some());
        assert_eq!(MinHashSignature(vec![]).band_keys(4).len(), 1);
    }
}
