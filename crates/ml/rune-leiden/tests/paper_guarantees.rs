//! Guarantees from Traag, Waltman & van Eck (2019), "From Louvain to Leiden:
//! guaranteeing well-connected communities", checked on random graphs.

#![allow(
    clippy::cast_precision_loss,
    reason = "fixture sizes are tiny, so usize to f64 is exact"
)]
#![allow(
    clippy::many_single_char_names,
    clippy::suboptimal_flops,
    reason = "the checks mirror the paper's notation (E, s, A, B)"
)]

use proptest::prelude::*;
use rune_leiden::{Error, Leiden, Louvain, Quality, modularity};

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

/// Erdős–Rényi `G(n, p)` with unit weights.
fn gnp(seed: u64, n: usize, p: f64) -> Vec<(usize, usize, f64)> {
    let mut rng = Lcg(seed);
    let mut edges = Vec::new();
    for u in 0..n {
        for v in (u + 1)..n {
            if rng.unit() < p {
                edges.push((u, v, 1.0));
            }
        }
    }
    edges
}

/// Symmetric weight matrix of a graph, self-loops dropped.
fn weight_matrix(n: usize, edges: &[(usize, usize, f64)]) -> Vec<Vec<f64>> {
    let mut w = vec![vec![0.0; n]; n];
    for &(u, v, x) in edges {
        if u != v {
            w[u][v] += x;
            w[v][u] += x;
        }
    }
    w
}

/// Node masses and the penalty scale `s` such that merging masses `a` and
/// `b` costs `s·a·b` in edge-weight units: degrees and `γ/2m` for
/// modularity, unit sizes and `γ` for CPM.
fn masses_and_scale(w: &[Vec<f64>], quality: Quality, gamma: f64) -> (Vec<f64>, f64) {
    match quality {
        Quality::Modularity => {
            let degree: Vec<f64> = w.iter().map(|row| row.iter().sum()).collect();
            let two_m: f64 = degree.iter().sum();
            let scale = if two_m > 0.0 { gamma / two_m } else { 0.0 };
            (degree, scale)
        }
        _ => (vec![1.0; w.len()], gamma),
    }
}

fn groups(communities: &[usize]) -> Vec<Vec<usize>> {
    let k = communities.iter().max().map_or(0, |m| m + 1);
    let mut g = vec![Vec::new(); k];
    for (v, &c) in communities.iter().enumerate() {
        g[c].push(v);
    }
    g
}

fn between(w: &[Vec<f64>], a: &[usize], b: &[usize]) -> f64 {
    a.iter()
        .map(|&u| b.iter().map(|&v| w[u][v]).sum::<f64>())
        .sum()
}

/// γ-separation: merging any two communities does not improve the quality,
/// i.e. `E(C, D) ≤ s·‖C‖·‖D‖`.
fn is_gamma_separated(w: &[Vec<f64>], communities: &[usize], masses: &[f64], s: f64) -> bool {
    let g = groups(communities);
    let mass = |c: &[usize]| c.iter().map(|&v| masses[v]).sum::<f64>();
    for i in 0..g.len() {
        for j in (i + 1)..g.len() {
            if between(w, &g[i], &g[j]) - s * mass(&g[i]) * mass(&g[j]) > 1e-9 {
                return false;
            }
        }
    }
    true
}

/// γ-connectivity (Traag et al., 2019): a set is γ-connected if it is a
/// single node, or splits into two γ-connected parts `A`, `B` with
/// `E(A, B) ≥ s·‖A‖·‖B‖`. We also require `E(A, B) > 0`, so γ-connected
/// sets are connected even at `γ = 0`. Exact check by dynamic programming
/// over subsets, so `community` must be small.
fn is_gamma_connected(w: &[Vec<f64>], community: &[usize], masses: &[f64], s: f64) -> bool {
    let k = community.len();
    assert!(k <= 16, "community too large for the exact check");
    let full = (1usize << k) - 1;
    // Internal weight and mass of every subset.
    let mut internal = vec![0.0f64; full + 1];
    let mut mass = vec![0.0f64; full + 1];
    for mask in 1..=full {
        let low = mask.trailing_zeros() as usize;
        let rest = mask & (mask - 1);
        let to_rest: f64 = (0..k)
            .filter(|&j| rest & (1 << j) != 0)
            .map(|j| w[community[low]][community[j]])
            .sum();
        internal[mask] = internal[rest] + to_rest;
        mass[mask] = mass[rest] + masses[community[low]];
    }
    let mut ok = vec![false; full + 1];
    for mask in 1..=full {
        if mask.is_power_of_two() {
            ok[mask] = true;
            continue;
        }
        // Enumerate splits with the lowest node in `a`.
        let low = mask & mask.wrapping_neg();
        let others = mask ^ low;
        let mut sub = others;
        loop {
            let a = sub | low;
            let b = mask ^ a;
            if b != 0 && ok[a] && ok[b] {
                let e = internal[mask] - internal[a] - internal[b];
                if e > 0.0 && e - s * mass[a] * mass[b] >= -1e-9 {
                    ok[mask] = true;
                    break;
                }
            }
            if sub == 0 {
                break;
            }
            sub = (sub - 1) & others;
        }
    }
    ok[full]
}

/// Leiden keeps improving where Louvain stops: over 20 seeded random graphs
/// its mean modularity is strictly higher.
#[test]
fn leiden_beats_louvain_on_seeded_random_graphs() {
    let runs = 20;
    let n = 120;
    let (mut leiden_q, mut louvain_q) = (0.0, 0.0);
    for seed in 0..runs {
        let edges = gnp(1000 + seed, n, 0.05);
        let leiden = Leiden::new().random_seed(seed).try_fit(n, &edges).unwrap();
        let louvain = Louvain::new().random_seed(seed).try_fit(n, &edges).unwrap();
        let q = modularity(n, &edges, &leiden.communities, 1.0).unwrap();
        assert!((q - leiden.modularity).abs() < 1e-12);
        leiden_q += leiden.modularity;
        louvain_q += louvain.modularity;
    }
    let (leiden_q, louvain_q) = (leiden_q / runs as f64, louvain_q / runs as f64);
    assert!(
        leiden_q > louvain_q,
        "mean Q: Leiden {leiden_q:.5} vs Louvain {louvain_q:.5}"
    );
}

/// The same seed and θ always give the same partition; θ is part of the
/// result.
#[test]
fn deterministic_per_seed_and_randomness() {
    let n = 80;
    let edges = gnp(5, n, 0.06);
    for seed in [0, 1, 42, u64::MAX] {
        for theta in [0.0, 0.01, 0.5] {
            let run = || {
                Leiden::new()
                    .random_seed(seed)
                    .randomness(theta)
                    .try_fit(n, &edges)
                    .unwrap()
            };
            let (a, b) = (run(), run());
            assert_eq!(a, b, "seed {seed}, θ {theta}");
            let h = Leiden::new()
                .random_seed(seed)
                .randomness(theta)
                .fit_hierarchy(n, &edges)
                .unwrap();
            assert_eq!(h.best().communities, a.communities);
            assert_eq!(h.last().communities, a.communities);
            for pair in h.levels.windows(2) {
                assert!(pair[1].quality >= pair[0].quality - 1e-12);
            }
        }
    }
}

#[test]
fn randomness_is_validated() {
    let edges = [(0, 1, 1.0)];
    for theta in [-0.1, f64::NAN, f64::INFINITY] {
        let err = Leiden::new()
            .randomness(theta)
            .try_fit(2, &edges)
            .unwrap_err();
        assert!(matches!(err, Error::InvalidRandomness(_)), "{err:?}");
        assert!(
            Leiden::new()
                .randomness(theta)
                .fit_hierarchy(2, &edges)
                .is_err()
        );
    }
    assert_eq!(
        Error::InvalidRandomness(-1.0).to_string(),
        "randomness -1 is not a finite non-negative number"
    );
    // `fit` does not validate; a bad θ behaves like 0 (greedy refinement).
    assert_eq!(
        Leiden::new().randomness(-1.0).fit(2, &edges),
        Leiden::new().randomness(0.0).fit(2, &edges)
    );
}

fn weighted_graph() -> impl Strategy<Value = (usize, Vec<(usize, usize, f64)>)> {
    (2usize..14).prop_flat_map(|n| {
        (
            Just(n),
            prop::collection::vec((0..n, 0..n, 0.1f64..5.0), 0..50),
        )
    })
}

fn quality_setting() -> impl Strategy<Value = (Quality, f64)> {
    prop_oneof![
        (0.2f64..2.5).prop_map(|g| (Quality::Modularity, g)),
        (0.0f64..1.5).prop_map(|g| (Quality::Cpm, g)),
    ]
}

proptest! {
    /// Every community Leiden returns is γ-connected (so in particular
    /// connected), and no two communities are worth merging (γ-separation).
    #[test]
    fn communities_are_gamma_connected_and_separated(
        (n, edges) in weighted_graph(),
        (quality, gamma) in quality_setting(),
        theta in prop_oneof![Just(0.0), Just(0.01), 0.0f64..1.0],
        seed in any::<u64>(),
    ) {
        let result = Leiden::new()
            .quality(quality)
            .resolution(gamma)
            .randomness(theta)
            .random_seed(seed)
            .try_fit(n, &edges)
            .unwrap();
        let w = weight_matrix(n, &edges);
        let (masses, s) = masses_and_scale(&w, quality, gamma);
        for community in groups(&result.communities) {
            prop_assert!(
                is_gamma_connected(&w, &community, &masses, s),
                "community {community:?} is not γ-connected"
            );
        }
        prop_assert!(is_gamma_separated(&w, &result.communities, &masses, s));
    }
}
