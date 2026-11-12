//! Louvain, CPM, hierarchy and validation tests.

#![allow(
    clippy::cast_precision_loss,
    reason = "fixture sizes are tiny, so usize to f64 is exact"
)]

use proptest::prelude::*;
use rune_leiden::{Error, Leiden, Louvain, Quality, cpm, modularity};

/// Zachary's karate club (34 nodes, 78 undirected edges), 0-indexed.
#[rustfmt::skip]
const KARATE: [(usize, usize); 78] = [
    (0, 1), (0, 2), (0, 3), (0, 4), (0, 5), (0, 6), (0, 7), (0, 8), (0, 10), (0, 11),
    (0, 12), (0, 13), (0, 17), (0, 19), (0, 21), (0, 31), (1, 2), (1, 3), (1, 7), (1, 13),
    (1, 17), (1, 19), (1, 21), (1, 30), (2, 3), (2, 7), (2, 8), (2, 9), (2, 13), (2, 27),
    (2, 28), (2, 32), (3, 7), (3, 12), (3, 13), (4, 6), (4, 10), (5, 6), (5, 10), (5, 16),
    (6, 16), (8, 30), (8, 32), (8, 33), (9, 33), (13, 33), (14, 32), (14, 33), (15, 32), (15, 33),
    (18, 32), (18, 33), (19, 33), (20, 32), (20, 33), (22, 32), (22, 33), (23, 25), (23, 27), (23, 29),
    (23, 32), (23, 33), (24, 25), (24, 27), (24, 31), (25, 31), (26, 29), (26, 33), (27, 33), (28, 31),
    (28, 33), (29, 32), (29, 33), (30, 32), (30, 33), (31, 32), (31, 33), (32, 33),
];

/// Proven maximum modularity of the karate club, 0.4197896 with four
/// communities (Brandes et al., "On Modularity Clustering", IEEE TKDE 2008).
const KARATE_OPTIMUM: f64 = 0.419_790;

fn karate() -> Vec<(usize, usize, f64)> {
    KARATE.iter().map(|&(u, v)| (u, v, 1.0)).collect()
}

/// `k` cliques of size `s` joined in a ring by single edges.
fn ring_of_cliques(k: usize, s: usize) -> Vec<(usize, usize, f64)> {
    let mut edges = Vec::new();
    for c in 0..k {
        let base = c * s;
        for i in 0..s {
            for j in (i + 1)..s {
                edges.push((base + i, base + j, 1.0));
            }
        }
        edges.push((base, ((c + 1) % k) * s + 1, 1.0));
    }
    edges
}

fn assert_cliques_recovered(communities: &[usize], k: usize, s: usize) {
    for c in 0..k {
        let id = communities[c * s];
        assert!(communities[c * s..(c + 1) * s].iter().all(|&x| x == id));
        for other in 0..c {
            assert_ne!(communities[other * s], id, "cliques {other} and {c} merged");
        }
    }
}

/// Small deterministic generator for random test graphs.
struct Lcg(u64);

impl Lcg {
    const fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        self.0 >> 33
    }

    fn unit(&mut self) -> f64 {
        self.next() as f64 / f64::from(1u32 << 31)
    }
}

/// Planted-partition graph: `groups` blocks of `size` nodes, intra-block edge
/// probability `p_in`, inter-block `p_out`, random weights in `[0.5, 1.5)`.
fn planted(
    seed: u64,
    groups: usize,
    size: usize,
    p_in: f64,
    p_out: f64,
) -> Vec<(usize, usize, f64)> {
    let mut rng = Lcg(seed);
    let n = groups * size;
    let mut edges = Vec::new();
    for u in 0..n {
        for v in (u + 1)..n {
            let p = if u / size == v / size { p_in } else { p_out };
            if rng.unit() < p {
                edges.push((u, v, 0.5 + rng.unit()));
            }
        }
    }
    edges
}

#[test]
fn louvain_karate_reaches_known_modularity() {
    let edges = karate();
    let mut best = f64::NEG_INFINITY;
    for seed in 0..20 {
        let result = Louvain::new()
            .random_seed(seed)
            .try_fit(34, &edges)
            .unwrap();
        // Louvain lands in the 0.40–0.42 band reported by Blondel et al. (2008)
        // and never above the proven optimum.
        assert!(
            (0.39..=KARATE_OPTIMUM + 1e-6).contains(&result.modularity),
            "seed {seed}: {}",
            result.modularity
        );
        let check = modularity(34, &edges, &result.communities, 1.0).unwrap();
        assert!((check - result.modularity).abs() < 1e-12);
        assert_ne!(result.communities[0], result.communities[33]);
        best = best.max(result.modularity);
    }
    assert!(
        (best - KARATE_OPTIMUM).abs() < 1e-5,
        "best Louvain modularity {best} is not the known optimum"
    );
}

#[test]
fn louvain_is_deterministic_per_seed() {
    let edges = karate();
    for seed in [0, 3, 42, u64::MAX] {
        let a = Louvain::new()
            .random_seed(seed)
            .try_fit(34, &edges)
            .unwrap();
        let b = Louvain::new()
            .random_seed(seed)
            .try_fit(34, &edges)
            .unwrap();
        assert_eq!(a, b);
    }
}

#[test]
fn louvain_ring_of_cliques_recovers_every_clique() {
    let (k, s) = (8, 5);
    let edges = ring_of_cliques(k, s);
    for seed in 0..10 {
        let result = Louvain::new()
            .random_seed(seed)
            .try_fit(k * s, &edges)
            .unwrap();
        assert_eq!(result.n_communities, k, "seed {seed}");
        assert_cliques_recovered(&result.communities, k, s);
        // Closed form for one clique per community.
        let m = (k * (s * (s - 1) / 2 + 1)) as f64;
        let internal = (s * (s - 1) / 2) as f64;
        let total = (s * (s - 1) + 2) as f64;
        let want = (k as f64).mul_add(internal / m, -(k as f64) * (total / (2.0 * m)).powi(2));
        assert!((result.modularity - want).abs() < 1e-12);
    }
}

/// The resolution limit (Fortunato & Barthélemy, 2007): on a ring of 30
/// five-cliques, modularity prefers merging neighbouring cliques, while CPM
/// with γ between the inter- and intra-clique densities keeps every clique.
#[test]
fn cpm_escapes_the_resolution_limit_on_a_ring_of_cliques() {
    let (k, s) = (30, 5);
    let edges = ring_of_cliques(k, s);
    let merged = Leiden::new().fit(k * s, &edges);
    assert!(merged.n_communities < k);

    for result in [
        Leiden::new()
            .quality(Quality::Cpm)
            .resolution(0.5)
            .try_fit(k * s, &edges),
        Louvain::new()
            .quality(Quality::Cpm)
            .resolution(0.5)
            .try_fit(k * s, &edges),
    ] {
        let result = result.unwrap();
        assert_eq!(result.n_communities, k);
        assert_cliques_recovered(&result.communities, k, s);
        // H = k × (C(s, 2) − γ × C(s, 2)).
        let h = cpm(k * s, &edges, &result.communities, 0.5).unwrap();
        assert!((h - 150.0).abs() < 1e-9, "{h}");
    }
}

#[test]
fn cpm_extremes() {
    // γ = 0: every connected component becomes one community.
    let edges = [(0, 1, 1.0), (1, 2, 1.0), (3, 4, 1.0)];
    let r = Leiden::new()
        .quality(Quality::Cpm)
        .resolution(0.0)
        .try_fit(6, &edges)
        .unwrap();
    assert_eq!(r.communities(), vec![vec![0, 1, 2], vec![3, 4], vec![5]]);
    // γ above every edge weight: no merge ever pays off.
    let r = Louvain::new()
        .quality(Quality::Cpm)
        .resolution(1.5)
        .try_fit(6, &edges)
        .unwrap();
    assert_eq!(r.n_communities, 6);
}

/// Number of communities that induce a disconnected subgraph.
fn disconnected_communities(
    n: usize,
    edges: &[(usize, usize, f64)],
    communities: &[usize],
) -> usize {
    let mut adj = vec![Vec::new(); n];
    for &(u, v, _) in edges {
        if u != v && communities[u] == communities[v] {
            adj[u].push(v);
            adj[v].push(u);
        }
    }
    let n_comm = communities.iter().max().map_or(0, |m| m + 1);
    let mut seen = vec![false; n];
    let mut components = vec![0usize; n_comm];
    for start in 0..n {
        if seen[start] {
            continue;
        }
        components[communities[start]] += 1;
        let mut stack = vec![start];
        seen[start] = true;
        while let Some(x) = stack.pop() {
            for &y in &adj[x] {
                if !seen[y] {
                    seen[y] = true;
                    stack.push(y);
                }
            }
        }
    }
    components.iter().filter(|&&c| c > 1).count()
}

/// Leiden guarantees that every community is connected; Louvain does not
/// (Traag, Waltman & van Eck, 2019). On random planted-partition graphs Leiden
/// must never return a disconnected community, and its modularity must stay
/// on par with Louvain's.
#[test]
fn leiden_vs_louvain_on_random_graphs() {
    let runs = 60;
    let (mut leiden_q, mut louvain_q) = (0.0, 0.0);
    let mut louvain_broken = 0;
    for seed in 0..runs {
        let (groups, size, p_in, p_out) = if seed % 2 == 0 {
            (6, 12, 0.35, 0.04)
        } else {
            (8, 10, 0.25, 0.06)
        };
        let n = groups * size;
        let edges = planted(seed, groups, size, p_in, p_out);
        let leiden = Leiden::new().random_seed(seed).try_fit(n, &edges).unwrap();
        let louvain = Louvain::new().random_seed(seed).try_fit(n, &edges).unwrap();
        assert_eq!(
            disconnected_communities(n, &edges, &leiden.communities),
            0,
            "seed {seed}"
        );
        louvain_broken += disconnected_communities(n, &edges, &louvain.communities);
        for (q, part) in [
            (leiden.modularity, &leiden.communities),
            (louvain.modularity, &louvain.communities),
        ] {
            assert!((0.0..1.0).contains(&q));
            assert!((modularity(n, &edges, part, 1.0).unwrap() - q).abs() < 1e-12);
        }
        leiden_q += leiden.modularity;
        louvain_q += louvain.modularity;
    }
    let (leiden_q, louvain_q) = (leiden_q / runs as f64, louvain_q / runs as f64);
    eprintln!(
        "mean Q: Leiden {leiden_q:.5}, Louvain {louvain_q:.5}; Louvain disconnected communities: {louvain_broken}"
    );
    assert!(
        leiden_q >= louvain_q - 0.005,
        "Leiden mean {leiden_q} falls behind Louvain mean {louvain_q}"
    );
}

#[test]
fn louvain_hierarchy_is_a_dendrogram() {
    let edges = planted(7, 5, 10, 0.4, 0.05);
    let h = Louvain::new().fit_hierarchy(50, &edges).unwrap();
    assert!(h.levels.len() >= 2, "expected several levels");
    for pair in h.levels.windows(2) {
        let (fine, coarse) = (&pair[0], &pair[1]);
        assert!(coarse.n_communities < fine.n_communities);
        assert!(coarse.quality >= fine.quality - 1e-12);
        // Every fine community sits inside a single coarse community.
        for group in fine.communities() {
            let id = coarse.communities[group[0]];
            assert!(group.iter().all(|&v| coarse.communities[v] == id));
        }
    }
    let fit = Louvain::new().try_fit(50, &edges).unwrap();
    assert_eq!(h.best().communities, fit.communities);
    assert!((h.best().quality - fit.modularity).abs() < 1e-12);
}

#[test]
fn leiden_hierarchy_best_matches_fit() {
    let edges = karate();
    for seed in 0..10 {
        let h = Leiden::new()
            .random_seed(seed)
            .fit_hierarchy(34, &edges)
            .unwrap();
        let fit = Leiden::new().random_seed(seed).fit(34, &edges);
        assert_eq!(h.best().communities, fit.communities);
        for level in &h.levels {
            let q = modularity(34, &edges, &level.communities, 1.0).unwrap();
            assert!((q - level.quality).abs() < 1e-12);
        }
    }
}

#[test]
fn communities_helper_groups_members() {
    let result = Leiden::new().fit(34, &karate());
    let groups = result.communities();
    assert_eq!(groups.len(), result.n_communities);
    let mut all: Vec<usize> = groups.iter().flatten().copied().collect();
    all.sort_unstable();
    assert_eq!(all, (0..34).collect::<Vec<_>>());
    for (c, members) in groups.iter().enumerate() {
        assert!(members.windows(2).all(|w| w[0] < w[1]));
        assert!(members.iter().all(|&v| result.communities[v] == c));
    }
}

#[test]
fn validation_errors() {
    let leiden = Leiden::new();
    let louvain = Louvain::new();
    assert_eq!(leiden.try_fit(0, &[]), Err(Error::EmptyGraph));
    assert_eq!(louvain.try_fit(0, &[]).unwrap_err(), Error::EmptyGraph);
    assert_eq!(
        louvain.try_fit(2, &[(0, 1, 1.0), (1, 2, 1.0)]).unwrap_err(),
        Error::NodeOutOfRange {
            edge: 1,
            node: 2,
            n_nodes: 2
        }
    );
    assert_eq!(
        leiden.try_fit(2, &[(0, 1, -0.5)]).unwrap_err(),
        Error::InvalidWeight {
            edge: 0,
            weight: -0.5
        }
    );
    assert!(matches!(
        louvain.try_fit(2, &[(0, 1, f64::NAN)]),
        Err(Error::InvalidWeight { edge: 0, .. })
    ));
    assert!(matches!(
        leiden.try_fit(2, &[(0, 1, f64::INFINITY)]),
        Err(Error::InvalidWeight { .. })
    ));
    assert_eq!(
        leiden.resolution(-1.0).try_fit(2, &[]).unwrap_err(),
        Error::InvalidResolution(-1.0)
    );
    assert!(louvain.resolution(f64::NAN).fit_hierarchy(2, &[]).is_err());
    assert_eq!(
        modularity(3, &[(0, 1, 1.0)], &[0, 0], 1.0).unwrap_err(),
        Error::PartitionLength {
            expected: 3,
            found: 2
        }
    );
    assert_eq!(cpm(0, &[], &[], 1.0).unwrap_err(), Error::EmptyGraph);
    assert_eq!(Error::EmptyGraph.to_string(), "graph has no nodes");
}

#[test]
fn self_loops_are_ignored_everywhere() {
    let edges = [(0, 1, 1.0), (1, 2, 1.0), (0, 2, 1.0), (3, 4, 1.0)];
    let mut looped = edges.to_vec();
    looped.extend([(0, 0, 5.0), (3, 3, 2.0)]);
    let part = [0, 0, 0, 1, 1];
    assert_eq!(
        modularity(5, &edges, &part, 1.0).unwrap(),
        modularity(5, &looped, &part, 1.0).unwrap()
    );
    assert_eq!(
        Louvain::new().try_fit(5, &edges).unwrap(),
        Louvain::new().try_fit(5, &looped).unwrap()
    );
    assert_eq!(
        Leiden::new().try_fit(5, &edges).unwrap(),
        Leiden::new().try_fit(5, &looped).unwrap()
    );
}

#[test]
fn edge_cases() {
    // Single node, edgeless graphs, zero-weight edges.
    assert_eq!(Louvain::new().try_fit(1, &[]).unwrap().communities, vec![0]);
    let r = Louvain::new().try_fit(3, &[]).unwrap();
    assert_eq!((r.n_communities, r.modularity), (3, 0.0));
    let r = Louvain::new().try_fit(3, &[(0, 1, 0.0)]).unwrap();
    assert_eq!(r.n_communities, 3);
    assert_eq!(modularity(3, &[], &[0, 0, 0], 1.0).unwrap(), 0.0);
    // Arbitrary, non-contiguous partition ids are fine.
    let edges = [(0, 1, 1.0), (2, 3, 1.0)];
    let a = modularity(4, &edges, &[0, 0, 1, 1], 1.0).unwrap();
    let b = modularity(4, &edges, &[usize::MAX, usize::MAX, 5, 5], 1.0).unwrap();
    assert_eq!(a, b);
    assert!((a - 0.5).abs() < 1e-12);
}

fn graph_and_partition() -> impl Strategy<Value = (usize, Vec<(usize, usize, f64)>, Vec<usize>)> {
    (1usize..30).prop_flat_map(|n| {
        (
            Just(n),
            prop::collection::vec((0..n, 0..n, 0.0f64..10.0), 0..80),
            prop::collection::vec(0..n, n),
        )
    })
}

proptest! {
    /// At γ = 1 modularity is bounded: −1/2 ≤ Q < 1 (Brandes et al., 2008).
    #[test]
    fn modularity_is_bounded((n, edges, partition) in graph_and_partition()) {
        let q = modularity(n, &edges, &partition, 1.0).unwrap();
        prop_assert!((-0.5 - 1e-12..=1.0).contains(&q), "Q = {q}");
    }

    /// Both algorithms return a valid partition whose reported modularity
    /// matches the standalone function and beats the all-singletons start.
    #[test]
    fn fits_are_consistent((n, edges, _) in graph_and_partition(), seed in any::<u64>()) {
        let singletons: Vec<usize> = (0..n).collect();
        let floor = modularity(n, &edges, &singletons, 1.0).unwrap();
        for result in [
            Leiden::new().random_seed(seed).try_fit(n, &edges).unwrap(),
            Louvain::new().random_seed(seed).try_fit(n, &edges).unwrap(),
        ] {
            prop_assert_eq!(result.communities.len(), n);
            let q = modularity(n, &edges, &result.communities, 1.0).unwrap();
            prop_assert!((q.max(0.0) - result.modularity).abs() < 1e-9);
            prop_assert!(q >= floor - 1e-12);
            prop_assert!((-0.5 - 1e-12..=1.0).contains(&q));
        }
    }
}

/// A sparse random graph (G(40, 0.07) from generator seed 793) on which
/// Louvain with seed 3 returns a community that falls apart into two pieces.
/// Leiden never does, whatever the seed.
#[test]
fn louvain_can_disconnect_where_leiden_cannot() {
    let n = 40;
    let mut rng = Lcg(793);
    let mut edges = Vec::new();
    for u in 0..n {
        for v in (u + 1)..n {
            if rng.unit() < 0.07 {
                edges.push((u, v, 1.0));
            }
        }
    }
    let louvain = Louvain::new().random_seed(3).try_fit(n, &edges).unwrap();
    assert_eq!(disconnected_communities(n, &edges, &louvain.communities), 1);
    for seed in 0..20 {
        let leiden = Leiden::new().random_seed(seed).fit(n, &edges);
        assert_eq!(
            disconnected_communities(n, &edges, &leiden.communities),
            0,
            "seed {seed}"
        );
    }
}
