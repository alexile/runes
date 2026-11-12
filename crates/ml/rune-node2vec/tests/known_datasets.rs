//! Known-dataset and seeded-determinism tests for `rune-node2vec`.

use rune_node2vec::Node2Vec;

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

/// Members of Mr. Hi's faction after the split (networkx `club == "Mr. Hi"`);
/// every other node followed the officer.
const MR_HI: [usize; 17] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 10, 11, 12, 13, 16, 17, 19, 21];

fn cosine(a: &[f64], b: &[f64]) -> f64 {
    let dot: f64 = a.iter().zip(b).map(|(x, y)| x * y).sum();
    let na = a.iter().map(|x| x * x).sum::<f64>().sqrt();
    let nb = b.iter().map(|x| x * x).sum::<f64>().sqrt();
    dot / (na * nb)
}

fn model(seed: u64) -> Node2Vec {
    Node2Vec::new()
        .embedding_dim(16)
        .num_walks(10)
        .walk_length(20)
        .n_epochs(3)
        .random_seed(seed)
}

fn mean(values: &[f64]) -> f64 {
    values.iter().sum::<f64>() / f64::from(u32::try_from(values.len()).unwrap_or(u32::MAX))
}

/// Regression: the negative-sampling table held only node 0 and input and
/// context vectors were tied, so within- and across-faction similarity were
/// nearly equal (0.85 vs 0.84). Now the factions separate clearly.
#[test]
fn karate_club_embeddings_separate_the_two_factions() {
    let embeddings = model(42).fit(34, &KARATE).embeddings;
    let faction = |v: usize| MR_HI.contains(&v);
    let (mut same, mut across) = (Vec::new(), Vec::new());
    for u in 0..34 {
        for v in (u + 1)..34 {
            let s = cosine(&embeddings[u], &embeddings[v]);
            if faction(u) == faction(v) {
                same.push(s);
            } else {
                across.push(s);
            }
        }
    }
    let (same, across) = (mean(&same), mean(&across));
    assert!(
        same > across + 0.25,
        "within-faction {same:.3} should clearly exceed across-faction {across:.3}"
    );

    // The two leaders are each closer to their own faction's centroid.
    let centroid = |members: &dyn Fn(usize) -> bool| -> Vec<f64> {
        let rows: Vec<&Vec<f64>> = (0..34)
            .filter(|&v| members(v))
            .map(|v| &embeddings[v])
            .collect();
        (0..16)
            .map(|d| mean(&rows.iter().map(|r| r[d]).collect::<Vec<_>>()))
            .collect()
    };
    let hi = centroid(&faction);
    let officer = centroid(&|v| !faction(v));
    assert!(cosine(&embeddings[0], &hi) > cosine(&embeddings[0], &officer));
    assert!(cosine(&embeddings[33], &officer) > cosine(&embeddings[33], &hi));
}

#[test]
fn same_seed_is_bit_identical() {
    for seed in [0, u64::MAX] {
        let a = model(seed).fit(34, &KARATE).embeddings;
        let b = model(seed).fit(34, &KARATE).embeddings;
        for (x, y) in a.iter().flatten().zip(b.iter().flatten()) {
            assert_eq!(x.to_bits(), y.to_bits(), "seed {seed}");
        }
    }
}

#[test]
fn different_seeds_give_different_embeddings() {
    let a = model(1).fit(34, &KARATE).embeddings;
    let b = model(2).fit(34, &KARATE).embeddings;
    assert_ne!(a, b);
}

#[test]
fn biased_walks_are_deterministic_too() {
    let m = || model(9).p(0.25).q(4.0);
    let a = m().fit(34, &KARATE).embeddings;
    let b = m().fit(34, &KARATE).embeddings;
    assert_eq!(a, b);
    assert!(a.iter().flatten().all(|x| x.is_finite()));
}

#[test]
fn empty_graph_yields_no_embeddings() {
    assert_eq!(model(1).fit(0, &[]).embeddings, Vec::<Vec<f64>>::new());
}

#[test]
fn edgeless_graph_keeps_finite_initial_embeddings() {
    let result = model(1).fit(3, &[]);
    assert_eq!(result.embeddings.len(), 3);
    assert!(result.embeddings.iter().flatten().all(|x| x.is_finite()));
}
