//! Known-dataset and determinism tests for `rune-pagerank`.
//!
//! Reference scores were obtained by solving the `PageRank` linear system
//! `(I − d·Mᵀ − d·D/n) r = (1 − d)/n` exactly in rational arithmetic (d = 0.85,
//! dangling mass spread uniformly), which is the fixed point power iteration
//! converges to. For Zachary's karate club the values agree with
//! `networkx.pagerank(nx.karate_club_graph(), weight=None)`.

use rune_pagerank::PageRank;

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

const KARATE_PAGERANK: [f64; 34] = [
    0.096_997_285_388_294_76,
    0.052_876_924_061_145_73,
    0.057_078_509_488_462_03,
    0.035_859_857_786_411_375,
    0.021_977_952_364_589_538,
    0.029_111_154_678_370_14,
    0.029_111_154_678_370_14,
    0.024_490_497_035_282_38,
    0.029_766_056_081_016_96,
    0.014_309_397_129_032_914,
    0.021_977_952_364_589_538,
    0.009_564_745_492_135_512,
    0.014_644_892_011_877_124,
    0.029_536_456_151_913_672,
    0.014_535_993_997_921_251,
    0.014_535_993_997_921_251,
    0.016_784_005_444_189_665,
    0.014_558_677_209_021_497,
    0.014_535_993_997_921_251,
    0.019_604_636_325_652_788,
    0.014_535_993_997_921_251,
    0.014_558_677_209_021_497,
    0.014_535_993_997_921_251,
    0.031_522_514_776_678_04,
    0.021_076_033_559_222_82,
    0.021_006_197_394_493,
    0.015_044_038_082_725_555,
    0.025_639_767_482_847_98,
    0.019_573_459_463_828_498,
    0.026_288_537_695_114_88,
    0.024_590_155_248_580_12,
    0.037_158_087_069_145_3,
    0.071_693_226_005_754_49,
    0.100_919_182_332_625_78,
];

fn karate_directed() -> Vec<(usize, usize, f64)> {
    KARATE
        .iter()
        .flat_map(|&(u, v)| [(u, v, 1.0), (v, u, 1.0)])
        .collect()
}

#[test]
fn karate_club_matches_reference() {
    let result = PageRank::new()
        .tol(1e-14)
        .max_iter(1000)
        .rank(34, &karate_directed());
    assert!(result.converged);
    for (i, (got, want)) in result.scores.iter().zip(KARATE_PAGERANK).enumerate() {
        assert!(
            (got - want).abs() < 1e-10,
            "node {i}: got {got}, want {want}"
        );
    }
    let sum: f64 = result.scores.iter().sum();
    assert!((sum - 1.0).abs() < 1e-12);
}

#[test]
fn karate_club_top_nodes_are_the_two_leaders() {
    let result = PageRank::new().rank(34, &karate_directed());
    let mut order: Vec<usize> = (0..34).collect();
    order.sort_by(|&a, &b| result.scores[b].total_cmp(&result.scores[a]));
    assert_eq!(&order[..3], &[33, 0, 32]);
}

/// Weighted directed graph with a dangling node (3):
/// 0→1 (1), 0→2 (2), 1→2 (1), 2→0 (1), 1→3 (1).
/// Exact solution: 17690/49799, 8340/49799, 50690/149397, 20617/149397.
#[test]
fn weighted_graph_with_dangling_node_matches_exact_solution() {
    let edges = [
        (0, 1, 1.0),
        (0, 2, 2.0),
        (1, 2, 1.0),
        (2, 0, 1.0),
        (1, 3, 1.0),
    ];
    let want = [
        17_690.0 / 49_799.0,
        8_340.0 / 49_799.0,
        50_690.0 / 149_397.0,
        20_617.0 / 149_397.0,
    ];
    let result = PageRank::new().tol(1e-15).max_iter(1000).rank(4, &edges);
    assert!(result.converged);
    for (got, want) in result.scores.iter().zip(want) {
        assert!((got - want).abs() < 1e-12, "got {got}, want {want}");
    }
}

#[test]
fn parallel_edges_equal_summed_weight() {
    let split = [(0, 1, 1.0), (0, 1, 2.0), (1, 0, 1.0), (0, 2, 1.0)];
    let merged = [(0, 1, 3.0), (1, 0, 1.0), (0, 2, 1.0)];
    let a = PageRank::new().rank(3, &split);
    let b = PageRank::new().rank(3, &merged);
    for (x, y) in a.scores.iter().zip(&b.scores) {
        assert!((x - y).abs() < 1e-15);
    }
}

#[test]
fn edge_order_does_not_change_scores() {
    let edges = karate_directed();
    let mut reversed = edges.clone();
    reversed.reverse();
    let a = PageRank::new().tol(1e-14).max_iter(1000).rank(34, &edges);
    let b = PageRank::new()
        .tol(1e-14)
        .max_iter(1000)
        .rank(34, &reversed);
    for (x, y) in a.scores.iter().zip(&b.scores) {
        assert!((x - y).abs() < 1e-12);
    }
}

#[test]
fn repeated_runs_are_bit_identical() {
    let edges = karate_directed();
    let a = PageRank::new().rank(34, &edges);
    let b = PageRank::new().rank(34, &edges);
    assert_eq!(a.iterations, b.iterations);
    for (x, y) in a.scores.iter().zip(&b.scores) {
        assert_eq!(x.to_bits(), y.to_bits());
    }
}

#[test]
fn edgeless_graph_is_uniform() {
    let result = PageRank::new().rank(4, &[]);
    assert!(result.converged);
    for s in &result.scores {
        assert!((s - 0.25).abs() < 1e-15);
    }
}

#[test]
fn single_node_has_all_rank() {
    let result = PageRank::new().rank(1, &[]);
    assert_eq!(result.scores.len(), 1);
    assert!((result.scores[0] - 1.0).abs() < 1e-15);
}

/// Regression: a non-positive or `NaN` weight used to leak rank (scores no
/// longer summed to 1) or turn every score `NaN`.
#[test]
fn invalid_weights_are_ignored() {
    let clean = [(0, 1, 1.0), (1, 2, 1.0), (2, 0, 1.0)];
    let mut dirty = clean.to_vec();
    dirty.extend([
        (0, 2, f64::NAN),
        (1, 0, -3.0),
        (2, 1, 0.0),
        (0, 1, f64::INFINITY),
    ]);
    let a = PageRank::new().rank(3, &clean);
    let b = PageRank::new().rank(3, &dirty);
    for (x, y) in a.scores.iter().zip(&b.scores) {
        assert!((x - y).abs() < 1e-15, "{x} vs {y}");
    }
    let sum: f64 = b.scores.iter().sum();
    assert!((sum - 1.0).abs() < 1e-12);
}

/// Regression: `damping(NaN)` used to make every score `NaN`.
#[test]
fn nan_damping_keeps_default() {
    let edges = karate_directed();
    let a = PageRank::new().rank(34, &edges);
    let b = PageRank::new().damping(f64::NAN).rank(34, &edges);
    assert_eq!(a.scores, b.scores);
}
