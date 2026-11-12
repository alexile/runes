//! Known-dataset and seeded-determinism tests for `rune-leiden`.

#![allow(
    clippy::cast_precision_loss,
    reason = "fixture sizes are tiny, so usize to f64 is exact"
)]

use rune_leiden::Leiden;

/// Zachary's karate club (34 nodes, 78 undirected edges), 0-indexed as in networkx.
const KARATE: [(usize, usize); 78] = [
    (0, 1),
    (0, 2),
    (0, 3),
    (0, 4),
    (0, 5),
    (0, 6),
    (0, 7),
    (0, 8),
    (0, 10),
    (0, 11),
    (0, 12),
    (0, 13),
    (0, 17),
    (0, 19),
    (0, 21),
    (0, 31),
    (1, 2),
    (1, 3),
    (1, 7),
    (1, 13),
    (1, 17),
    (1, 19),
    (1, 21),
    (1, 30),
    (2, 3),
    (2, 7),
    (2, 8),
    (2, 9),
    (2, 13),
    (2, 27),
    (2, 28),
    (2, 32),
    (3, 7),
    (3, 12),
    (3, 13),
    (4, 6),
    (4, 10),
    (5, 6),
    (5, 10),
    (5, 16),
    (6, 16),
    (8, 30),
    (8, 32),
    (8, 33),
    (9, 33),
    (13, 33),
    (14, 32),
    (14, 33),
    (15, 32),
    (15, 33),
    (18, 32),
    (18, 33),
    (19, 33),
    (20, 32),
    (20, 33),
    (22, 32),
    (22, 33),
    (23, 25),
    (23, 27),
    (23, 29),
    (23, 32),
    (23, 33),
    (24, 25),
    (24, 27),
    (24, 31),
    (25, 31),
    (26, 29),
    (26, 33),
    (27, 33),
    (28, 31),
    (28, 33),
    (29, 32),
    (29, 33),
    (30, 32),
    (30, 33),
    (31, 32),
    (31, 33),
    (32, 33),
];

fn karate() -> Vec<(usize, usize, f64)> {
    KARATE.iter().map(|&(u, v)| (u, v, 1.0)).collect()
}

/// Independent Newman–Girvan modularity (γ = 1) of `partition`.
fn modularity(n: usize, edges: &[(usize, usize, f64)], partition: &[usize]) -> f64 {
    let m: f64 = edges.iter().map(|e| e.2).sum();
    let mut degree = vec![0.0; n];
    let mut internal = vec![0.0; n];
    let mut total = vec![0.0; n];
    for &(u, v, w) in edges {
        degree[u] += w;
        degree[v] += w;
        if partition[u] == partition[v] {
            internal[partition[u]] += w;
        }
    }
    for (node, &d) in degree.iter().enumerate() {
        total[partition[node]] += d;
    }
    (0..n)
        .map(|c| (total[c] / (2.0 * m)).mul_add(-(total[c] / (2.0 * m)), internal[c] / m))
        .sum()
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

#[test]
fn karate_club_reaches_known_modularity() {
    let edges = karate();
    // The proven optimum modularity of the karate club is 0.419_79 with 4
    // communities (Brandes et al., 2008); seed 2 reaches it exactly.
    let result = Leiden::new().random_seed(2).fit(34, &edges);
    assert!(
        (result.modularity - 0.419_790).abs() < 1e-5,
        "modularity {} is not the known optimum",
        result.modularity
    );
    assert_eq!(result.n_communities, 4);
    let independent = modularity(34, &edges, &result.communities);
    assert!(
        (independent - result.modularity).abs() < 1e-12,
        "reported {} vs recomputed {independent}",
        result.modularity
    );
    // The two faction leaders never share a community.
    assert_ne!(result.communities[0], result.communities[33]);
}

/// Regression: modularity's null-model term was doubled and aggregation
/// dropped the weight collapsed inside each supernode, so karate-club runs
/// stalled near Q = 0.12. Every seed must now land in the known 0.39–0.42 band.
#[test]
fn karate_club_every_seed_is_near_optimal() {
    let edges = karate();
    for seed in 0..20 {
        let result = Leiden::new().random_seed(seed).fit(34, &edges);
        assert!(
            (0.39..=0.419_8).contains(&result.modularity),
            "seed {seed}: modularity {}",
            result.modularity
        );
        let independent = modularity(34, &edges, &result.communities);
        assert!((independent - result.modularity).abs() < 1e-12);
    }
}

/// Regression for the doubled null-model term: two disjoint triangles split
/// into their triangles have Q = 2·(3/6 − (6/12)²) = 0.5 exactly.
#[test]
fn two_disjoint_triangles_have_modularity_one_half() {
    let edges = [
        (0, 1, 1.0),
        (1, 2, 1.0),
        (0, 2, 1.0),
        (3, 4, 1.0),
        (4, 5, 1.0),
        (3, 5, 1.0),
    ];
    let result = Leiden::new().fit(6, &edges);
    assert_eq!(result.n_communities, 2);
    assert!(
        (result.modularity - 0.5).abs() < 1e-12,
        "{}",
        result.modularity
    );
}

#[test]
fn ring_of_cliques_recovers_every_clique() {
    let (k, s) = (8, 5);
    let edges = ring_of_cliques(k, s);
    let result = Leiden::new().random_seed(1).fit(k * s, &edges);
    assert_eq!(result.n_communities, k);
    for c in 0..k {
        let id = result.communities[c * s];
        assert!(
            result.communities[c * s..(c + 1) * s]
                .iter()
                .all(|&x| x == id)
        );
    }
    // Closed form: m = k(C(s,2) + 1), each community has internal C(s,2) and
    // degree sum s(s−1) + 2, so Q = (s(s−1)/2)/(m) − k((s(s−1)+2)/(2m))².
    let m = (k * (s * (s - 1) / 2 + 1)) as f64;
    let internal = (s * (s - 1) / 2) as f64;
    let total = (s * (s - 1) + 2) as f64;
    let want = (k as f64).mul_add(internal / m, -(k as f64) * (total / (2.0 * m)).powi(2));
    assert!((result.modularity - want).abs() < 1e-12);
}

#[test]
fn same_seed_is_identical_across_seeds() {
    let edges = karate();
    for seed in [0, 1, 7, 42, u64::MAX] {
        let a = Leiden::new().random_seed(seed).fit(34, &edges);
        let b = Leiden::new().random_seed(seed).fit(34, &edges);
        assert_eq!(a.communities, b.communities, "seed {seed}");
        assert_eq!(a.n_communities, b.n_communities);
        assert_eq!(a.modularity.to_bits(), b.modularity.to_bits());
    }
}

#[test]
fn community_ids_are_contiguous() {
    let result = Leiden::new().fit(34, &karate());
    let mut ids = result.communities.clone();
    ids.sort_unstable();
    ids.dedup();
    assert_eq!(ids, (0..result.n_communities).collect::<Vec<_>>());
}

#[test]
fn edgeless_graph_has_zero_modularity() {
    let result = Leiden::new().fit(4, &[]);
    assert_eq!(result.communities.len(), 4);
    assert!(result.modularity.abs() < 1e-15);
}
