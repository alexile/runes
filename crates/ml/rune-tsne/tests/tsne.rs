//! Behavioural tests for `rune-tsne`: determinism, embedding shape, cluster
//! preservation (exact and Barnes-Hut), progress reporting, scale invariance and
//! input validation. Inputs are kept to a few dozen points.

#![allow(
    clippy::cast_precision_loss,
    reason = "test sizes are tiny, so the f64 conversions are exact"
)]

use std::ops::ControlFlow;

use rune_tsne::{Init, Method, Metric, Tsne, TsneError, TsneResult, trustworthiness};

/// `k` well separated isotropic Gaussian clusters (σ = 1, centres ≥ 20 apart) of
/// `per` points each in `dim ≥ 2` dimensions, scaled by `scale`. Cluster `c` occupies
/// indices `c * per .. (c + 1) * per`. Deterministic: a fixed LCG drives Box-Muller.
fn clusters(k: usize, per: usize, dim: usize, scale: f64) -> Vec<Vec<f64>> {
    let mut state: u64 = 0x2545_f491_4f6c_dd1d;
    let mut uniform = move || {
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        ((state >> 11) as f64 + 0.5) / (1u64 << 53) as f64
    };
    let mut pts = Vec::with_capacity(k * per);
    for c in 0..k {
        // Centres on a circle of radius 20 in the first two dimensions.
        let angle = std::f64::consts::TAU * c as f64 / k as f64;
        for _ in 0..per {
            let row = (0..dim)
                .map(|d| {
                    let centre = match d {
                        0 => 20.0 * angle.cos(),
                        1 => 20.0 * angle.sin(),
                        _ => 0.0,
                    };
                    let (u1, u2) = (uniform(), uniform());
                    let gauss = (-2.0 * u1.ln()).sqrt() * (std::f64::consts::TAU * u2).cos();
                    (centre + gauss) * scale
                })
                .collect();
            pts.push(row);
        }
    }
    pts
}

fn sq_dist(a: &[f64], b: &[f64]) -> f64 {
    a.iter().zip(b).map(|(x, y)| (x - y).powi(2)).sum()
}

/// Single-linkage margin of the embedding with respect to the true labels: the
/// smallest distance between two points of *different* clusters divided by the
/// largest distance from any point to its nearest neighbour in its *own* cluster.
/// Above 1 means every point is closer to its own cluster than to any other, i.e.
/// the clusters are recovered exactly by single-linkage clustering.
fn linkage_margin(emb: &[Vec<f64>], per: usize) -> f64 {
    let mut inter = f64::INFINITY;
    let mut intra_nn = 0.0f64;
    for i in 0..emb.len() {
        let mut own = f64::INFINITY;
        for j in 0..emb.len() {
            if i == j {
                continue;
            }
            let d = sq_dist(&emb[i], &emb[j]).sqrt();
            if i / per == j / per {
                own = own.min(d);
            } else {
                inter = inter.min(d);
            }
        }
        intra_nn = intra_nn.max(own);
    }
    inter / intra_nn
}

/// Mean distance between points of the same cluster divided by the mean distance
/// between points of different clusters.
fn intra_inter_ratio(emb: &[Vec<f64>], per: usize) -> f64 {
    let (mut intra, mut n_intra, mut inter, mut n_inter) = (0.0, 0.0, 0.0, 0.0);
    for i in 0..emb.len() {
        for j in i + 1..emb.len() {
            let d = sq_dist(&emb[i], &emb[j]).sqrt();
            if i / per == j / per {
                intra += d;
                n_intra += 1.0;
            } else {
                inter += d;
                n_inter += 1.0;
            }
        }
    }
    (intra / n_intra) / (inter / n_inter)
}

fn assert_clusters_preserved(result: &TsneResult, per: usize, label: &str) {
    assert!(
        result.embedding.iter().flatten().all(|x| x.is_finite()),
        "{label}: non-finite embedding"
    );
    let margin = linkage_margin(&result.embedding, per);
    assert!(
        margin > 1.5,
        "{label}: clusters not separated (margin {margin:.3})"
    );
}

// ---------------------------------------------------------------- determinism

#[test]
fn same_seed_is_bit_for_bit_reproducible() {
    let pts = clusters(3, 8, 4, 1.0);
    for init in [Init::Pca, Init::Random] {
        for method in [Method::Exact, Method::BarnesHut] {
            let tsne = Tsne::new()
                .perplexity(5.0)
                .n_iter(300)
                .init(init)
                .method(method)
                .random_seed(1234);
            let a = tsne.try_fit(&pts).unwrap();
            let b = tsne.try_fit(&pts).unwrap();
            assert_eq!(a, b, "{init:?} {method:?}");
            // The old name still works.
            assert_eq!(tsne.fit(&pts).unwrap(), a);
        }
    }
}

#[test]
fn reproducible_regardless_of_thread_count() {
    let pts = clusters(3, 8, 4, 1.0);
    for method in [Method::Exact, Method::BarnesHut] {
        let tsne = Tsne::new()
            .perplexity(5.0)
            .n_iter(300)
            .method(method)
            .random_seed(9);
        let run = |threads: usize| {
            rayon::ThreadPoolBuilder::new()
                .num_threads(threads)
                .build()
                .unwrap()
                .install(|| tsne.try_fit(&pts).unwrap())
        };
        let one = run(1);
        assert_eq!(one, run(2));
        assert_eq!(one, run(7));
    }
}

#[test]
fn different_seeds_give_different_embeddings() {
    let pts = clusters(2, 10, 3, 1.0);
    let a = Tsne::new()
        .perplexity(5.0)
        .n_iter(100)
        .init(Init::Random)
        .random_seed(1)
        .try_fit(&pts)
        .unwrap();
    let b = Tsne::new()
        .perplexity(5.0)
        .n_iter(100)
        .init(Init::Random)
        .random_seed(2)
        .try_fit(&pts)
        .unwrap();
    assert_ne!(a.embedding, b.embedding);
}

#[test]
fn seed_zero_is_usable() {
    // Seed 0 must not produce a degenerate (all-zero) random initialisation.
    let pts = clusters(2, 10, 3, 1.0);
    let zero = Tsne::new()
        .init(Init::Random)
        .perplexity(5.0)
        .n_iter(500)
        .random_seed(0)
        .try_fit(&pts)
        .unwrap();
    assert_clusters_preserved(&zero, 10, "seed 0");
}

#[test]
fn builder_default_matches_new() {
    let pts = clusters(2, 10, 3, 1.0);
    let a = Tsne::default()
        .perplexity(5.0)
        .n_iter(20)
        .try_fit(&pts)
        .unwrap();
    let b = Tsne::new()
        .perplexity(5.0)
        .n_iter(20)
        .try_fit(&pts)
        .unwrap();
    assert_eq!(a, b);
}

// ------------------------------------------------------------------- shape

#[test]
fn output_shape_follows_n_components() {
    let pts = clusters(2, 8, 5, 1.0);
    for nc in 1..=4 {
        let r = Tsne::new()
            .n_components(nc)
            .perplexity(4.0)
            .n_iter(30)
            .try_fit(&pts)
            .unwrap();
        assert_eq!(r.embedding.len(), pts.len());
        assert!(r.embedding.iter().all(|row| row.len() == nc), "nc={nc}");
    }
}

#[test]
fn zero_components_and_zero_iterations_are_rejected() {
    let pts = clusters(2, 8, 2, 1.0);
    let base = Tsne::new().perplexity(4.0);
    for (tsne, name) in [
        (base.clone().n_components(0), "n_components"),
        (base.n_iter(0), "n_iter"),
    ] {
        assert!(matches!(
            tsne.try_fit(&pts),
            Err(TsneError::InvalidParameter { name: n, .. }) if n == name
        ));
    }
}

#[test]
fn embedding_is_centred() {
    let pts = clusters(3, 7, 3, 1.0);
    let r = Tsne::new()
        .n_components(3)
        .perplexity(5.0)
        .n_iter(200)
        .try_fit(&pts)
        .unwrap();
    for d in 0..3 {
        let mean = r.embedding.iter().map(|row| row[d]).sum::<f64>() / pts.len() as f64;
        assert!(mean.abs() < 1e-9, "dimension {d} mean {mean}");
    }
}

#[test]
fn regular_simplex_embeds_as_regular_simplex() {
    // Four mutually equidistant points (the standard basis of R^4) have uniform
    // affinities. In 3D a regular tetrahedron reproduces them exactly, so the
    // optimum has equal pairwise distances and zero KL divergence.
    let pts: Vec<Vec<f64>> = (0..4)
        .map(|i| (0..4).map(|d| if d == i { 1.0 } else { 0.0 }).collect())
        .collect();
    let r = Tsne::new()
        .n_components(3)
        .perplexity(1.2)
        .learning_rate(10.0)
        .n_iter(1000)
        .try_fit(&pts)
        .unwrap();
    let mut dists = Vec::new();
    for i in 0..4 {
        for j in i + 1..4 {
            dists.push(sq_dist(&r.embedding[i], &r.embedding[j]).sqrt());
        }
    }
    let (min, max) = dists.iter().fold((f64::INFINITY, 0.0f64), |(lo, hi), &d| {
        (lo.min(d), hi.max(d))
    });
    assert!(min > 0.0);
    assert!(max / min < 1.05, "pairwise distances not equal: {dists:?}");
    assert!(r.kl_divergence < 1e-3, "kl = {}", r.kl_divergence);
}

// ------------------------------------------------------------- correctness

#[test]
fn separable_clusters_stay_separated_in_2d_and_3d() {
    let pts = clusters(3, 10, 6, 1.0);
    for nc in [2, 3] {
        let r = Tsne::new()
            .n_components(nc)
            .perplexity(5.0)
            .n_iter(1000)
            .try_fit(&pts)
            .unwrap();
        assert_clusters_preserved(&r, 10, &format!("{nc}D"));
    }
}

#[test]
fn clusters_survive_across_seeds() {
    let pts = clusters(4, 8, 5, 1.0);
    for seed in [1, 2, 3, 42, u64::MAX] {
        let r = Tsne::new()
            .init(Init::Random)
            .perplexity(4.0)
            .n_iter(800)
            .random_seed(seed)
            .try_fit(&pts)
            .unwrap();
        assert_clusters_preserved(&r, 8, &format!("seed {seed}"));
    }
}

#[test]
fn default_learning_rate_suits_small_data_sets() {
    // Regression: the fixed default learning rate of 200 tore 30-point data sets
    // apart for most seeds. The automatic rate (n / 48 = 0.625 here) separates them
    // every time.
    let pts = clusters(3, 10, 3, 1.0);
    for seed in 1..=8 {
        let r = Tsne::new()
            .init(Init::Random)
            .perplexity(5.0)
            .random_seed(seed)
            .try_fit(&pts)
            .unwrap();
        assert_clusters_preserved(&r, 10, &format!("seed {seed}"));
    }
}

#[test]
fn adaptive_gains_tame_a_high_learning_rate() {
    // Regression: without per-coordinate adaptive gains a learning rate of 200 on
    // 30 points separated the clusters for only ~3 seeds in 20. With gains most
    // seeds succeed; require a clear majority so the test is robust to libm
    // differences between platforms.
    let pts = clusters(3, 10, 3, 1.0);
    let ok = (1..=10)
        .filter(|&seed| {
            let r = Tsne::new()
                .init(Init::Random)
                .perplexity(5.0)
                .learning_rate(200.0)
                .random_seed(seed)
                .try_fit(&pts)
                .unwrap();
            linkage_margin(&r.embedding, 10) > 1.5
        })
        .count();
    assert!(ok >= 6, "only {ok}/10 seeds separated the clusters");
}

#[test]
fn result_does_not_depend_on_data_units() {
    // Regression: the bandwidth search started at sigma = 1 and could only
    // double/halve 50 times, so data at very small or very large scale got almost
    // uniform affinities and lost all cluster structure.
    let tsne = Tsne::new().perplexity(5.0).n_iter(600);
    for scale in [1e-30, 1e-9, 1.0, 1e9, 1e30] {
        let pts = clusters(3, 10, 3, scale);
        let r = tsne.try_fit(&pts).unwrap();
        assert_clusters_preserved(&r, 10, &format!("scale {scale:e}"));
    }
}

#[test]
fn kl_divergence_is_non_negative_and_drops_with_optimisation() {
    let pts = clusters(3, 8, 4, 1.0);
    let tsne = Tsne::new().perplexity(5.0);
    let short = tsne.clone().n_iter(1).try_fit(&pts).unwrap();
    let long = tsne.n_iter(1000).try_fit(&pts).unwrap();
    assert!(short.kl_divergence.is_finite() && long.kl_divergence.is_finite());
    assert!(long.kl_divergence >= -1e-9, "kl = {}", long.kl_divergence);
    assert!(
        long.kl_divergence < short.kl_divergence / 2.0,
        "kl did not drop: {} -> {}",
        short.kl_divergence,
        long.kl_divergence
    );
}

#[test]
fn duplicate_points_give_a_finite_embedding() {
    let pts = vec![vec![1.0, -2.0, 3.0]; 12];
    let r = Tsne::new()
        .perplexity(3.0)
        .n_iter(300)
        .try_fit(&pts)
        .unwrap();
    assert!(r.embedding.iter().flatten().all(|x| x.is_finite()));
    assert!(r.kl_divergence.is_finite());
}

#[test]
fn zero_dimensional_points_are_rejected() {
    let pts = vec![Vec::new(); 9];
    assert_eq!(
        Tsne::new().perplexity(2.0).try_fit(&pts),
        Err(TsneError::NoFeatures)
    );
}

#[test]
fn larger_perplexity_spreads_affinities() {
    // A larger perplexity widens each neighbourhood. Points inside one cluster then
    // end up relatively closer than at a small perplexity, where the embedding
    // resolves finer intra-cluster structure.
    let pts = clusters(2, 15, 3, 1.0);
    let spread = |perp: f64| {
        let r = Tsne::new()
            .perplexity(perp)
            .n_iter(800)
            .try_fit(&pts)
            .unwrap();
        intra_inter_ratio(&r.embedding, 15)
    };
    let (small, large) = (spread(2.0), spread(9.0));
    assert!(small.is_finite() && large.is_finite());
    assert!(
        large < small,
        "intra/inter ratio small={small:.3} large={large:.3}"
    );
}

// --------------------------------------------------------------- validation

#[test]
fn too_few_points_is_an_error() {
    for n in 0..4 {
        let pts = vec![vec![0.0, 1.0]; n];
        assert_eq!(
            Tsne::new().perplexity(1.0).try_fit(&pts),
            Err(TsneError::TooFewPoints { n })
        );
    }
}

#[test]
fn perplexity_bound_is_exclusive() {
    let pts = clusters(2, 6, 2, 1.0); // n = 12, limit = 4
    let err = Tsne::new().perplexity(4.0).try_fit(&pts).unwrap_err();
    assert_eq!(
        err,
        TsneError::PerplexityTooLarge {
            perplexity: 4.0,
            limit: 4.0
        }
    );
    assert!(Tsne::new().perplexity(3.99).n_iter(5).try_fit(&pts).is_ok());
    // The default perplexity of 30 needs at least 91 points.
    assert!(matches!(
        Tsne::new().try_fit(&pts),
        Err(TsneError::PerplexityTooLarge { .. })
    ));
}

#[test]
fn out_of_range_parameters_are_rejected() {
    let pts = clusters(2, 3, 2, 1.0);
    let base = Tsne::new().perplexity(1.5).n_iter(5);
    let cases = [
        (base.clone().perplexity(0.5), "perplexity"),
        (base.clone().perplexity(f64::NAN), "perplexity"),
        (base.clone().perplexity(f64::INFINITY), "perplexity"),
        (base.clone().learning_rate(f64::INFINITY), "learning_rate"),
        (base.clone().learning_rate(f64::NAN), "learning_rate"),
        (base.clone().learning_rate(0.0), "learning_rate"),
        (base.clone().learning_rate(-3.0), "learning_rate"),
        (base.clone().theta(-0.1), "theta"),
        (base.clone().theta(1.5), "theta"),
        (base.clone().theta(f64::NAN), "theta"),
        (base.clone().early_exaggeration(0.5), "early_exaggeration"),
        (
            base.clone().early_exaggeration(f64::NAN),
            "early_exaggeration",
        ),
        (
            base.clone().method(Method::BarnesHut).n_components(4),
            "n_components",
        ),
    ];
    for (tsne, name) in cases {
        let r = tsne.try_fit(&pts);
        assert!(
            matches!(r, Err(TsneError::InvalidParameter { name: n, .. }) if n == name),
            "{name}: {r:?}"
        );
    }
    // More than 3 output dimensions is fine for the exact method.
    assert!(base.n_components(4).try_fit(&pts).is_ok());
}

#[test]
fn ragged_input_is_an_error() {
    let pts = vec![
        vec![0.0, 0.0],
        vec![1.0, 1.0],
        vec![2.0],
        vec![3.0, 3.0],
        vec![4.0, 4.0],
    ];
    assert_eq!(
        Tsne::new().perplexity(1.1).try_fit(&pts),
        Err(TsneError::DimensionMismatch {
            index: 2,
            expected: 2,
            found: 1
        })
    );
}

#[test]
fn non_finite_input_is_an_error() {
    for bad in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
        let mut pts = clusters(2, 3, 2, 1.0);
        pts[4][1] = bad;
        let r = Tsne::new().perplexity(1.5).try_fit(&pts);
        assert!(
            matches!(r, Err(TsneError::NonFinite { row: 4, col: 1, value }) if value.is_nan() == bad.is_nan()),
            "{r:?}"
        );
    }
}

#[test]
fn errors_have_readable_messages() {
    assert_eq!(
        TsneError::TooFewPoints { n: 2 }.to_string(),
        "t-SNE requires at least 4 points, got 2"
    );
    assert_eq!(
        TsneError::PerplexityTooLarge {
            perplexity: 30.0,
            limit: 4.0
        }
        .to_string(),
        "perplexity (30) must be less than n_points / 3 (4.000)"
    );
    assert_eq!(
        TsneError::DimensionMismatch {
            index: 3,
            expected: 2,
            found: 5
        }
        .to_string(),
        "row 3 has 5 values, expected 2"
    );
}

// ----------------------------------------------- trustworthiness, Barnes-Hut

#[test]
fn well_separated_blobs_are_trustworthy() {
    // 3 blobs × 12 points in 5D: every method and initialisation keeps the
    // neighbourhoods (trustworthiness > 0.9) and the blobs apart.
    let pts = clusters(3, 12, 5, 1.0);
    for method in [Method::Exact, Method::BarnesHut] {
        for init in [Init::Pca, Init::Random] {
            let r = Tsne::new()
                .perplexity(5.0)
                .n_iter(600)
                .method(method)
                .init(init)
                .random_seed(3)
                .try_fit(&pts)
                .unwrap();
            assert_eq!(r.method, method);
            let label = format!("{method:?} {init:?}");
            assert_clusters_preserved(&r, 12, &label);
            let t = trustworthiness(&pts, &r.embedding, 5, Metric::Euclidean).unwrap();
            assert!(t > 0.9, "{label}: trustworthiness {t:.3}");
        }
    }
}

#[test]
fn one_and_three_dimensional_embeddings() {
    // Regression for 1D: a learning rate floored at 50 made the exaggeration phase
    // overshoot and scrambled the two clusters (margin ~0.2) with either method.
    let pts = clusters(2, 12, 4, 1.0);
    for method in [Method::Exact, Method::BarnesHut] {
        for nc in [1, 3] {
            let r = Tsne::new()
                .n_components(nc)
                .perplexity(4.0)
                .n_iter(500)
                .method(method)
                .try_fit(&pts)
                .unwrap();
            assert!(r.embedding.iter().all(|row| row.len() == nc));
            assert_clusters_preserved(&r, 12, &format!("{method:?} {nc}D"));
        }
    }
}

#[test]
fn barnes_hut_kl_is_close_to_exact() {
    // Same data, both methods: the final divergences are of the same size.
    let pts = clusters(3, 10, 4, 1.0);
    let fit = |m| {
        Tsne::new()
            .perplexity(5.0)
            .n_iter(500)
            .method(m)
            .try_fit(&pts)
            .unwrap()
            .kl_divergence
    };
    let (exact, bh) = (fit(Method::Exact), fit(Method::BarnesHut));
    assert!(exact > 0.0 && bh > 0.0);
    assert!((exact - bh).abs() < 0.5 * exact.max(bh), "{exact} vs {bh}");
}

#[test]
fn auto_method_is_exact_for_small_inputs() {
    let pts = clusters(2, 8, 3, 1.0);
    let r = Tsne::new().perplexity(4.0).n_iter(5).try_fit(&pts).unwrap();
    assert_eq!(r.method, Method::Exact);
}

// ------------------------------------------------------------------ progress

#[test]
fn callback_reports_every_iteration() {
    let pts = clusters(3, 8, 4, 1.0);
    for method in [Method::Exact, Method::BarnesHut] {
        let mut reports = Vec::new();
        let tsne = Tsne::new().perplexity(5.0).n_iter(400).method(method);
        let r = tsne
            .try_fit_with(&pts, |it| {
                reports.push(*it);
                ControlFlow::Continue(())
            })
            .unwrap();
        assert_eq!(r.n_iter, 400);
        assert_eq!(reports.len(), 400);
        for (i, it) in reports.iter().enumerate() {
            assert_eq!(it.iteration, i);
            assert_eq!(it.exaggerated, i < 250);
            assert!(it.kl_divergence.is_finite() && it.kl_divergence > -1e-9);
            assert!(it.gradient_norm.is_finite());
        }
        assert!(reports[399].kl_divergence < reports[0].kl_divergence);
        // Reporting does not change the result.
        assert_eq!(tsne.try_fit(&pts).unwrap(), r);
    }
}

#[test]
fn callback_can_stop_early() {
    let pts = clusters(2, 8, 3, 1.0);
    let mut calls = 0;
    let r = Tsne::new()
        .perplexity(4.0)
        .try_fit_with(&pts, |it| {
            calls += 1;
            if it.iteration == 9 {
                ControlFlow::Break(())
            } else {
                ControlFlow::Continue(())
            }
        })
        .unwrap();
    assert_eq!((calls, r.n_iter), (10, 10));
    assert_eq!(
        r,
        Tsne::new()
            .perplexity(4.0)
            .n_iter(10)
            .try_fit(&pts)
            .unwrap()
    );
}

#[test]
fn exaggeration_schedule_is_configurable() {
    let pts = clusters(2, 8, 3, 1.0);
    let mut flags = Vec::new();
    Tsne::new()
        .perplexity(4.0)
        .n_iter(20)
        .exaggeration_iters(5)
        .early_exaggeration(4.0)
        .try_fit_with(&pts, |it| {
            flags.push(it.exaggerated);
            ControlFlow::Continue(())
        })
        .unwrap();
    assert_eq!(flags.iter().filter(|&&f| f).count(), 5);
    assert!(flags[..5].iter().all(|&f| f));
}
