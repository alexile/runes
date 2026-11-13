//! Property tests: `try_fit` never panics, and valid input always yields a finite,
//! correctly shaped, reproducible embedding.

use proptest::prelude::*;
use rune_tsne::{Init, Method, Tsne};

/// 4..=16 points of 1..=4 finite coordinates each.
fn finite_points() -> impl Strategy<Value = Vec<Vec<f64>>> {
    (1usize..=4).prop_flat_map(|dim| {
        prop::collection::vec(prop::collection::vec(-1e6f64..1e6, dim), 4..=16)
    })
}

/// Arbitrary (possibly ragged, possibly non-finite) input.
fn any_points() -> impl Strategy<Value = Vec<Vec<f64>>> {
    prop::collection::vec(prop::collection::vec(any::<f64>(), 0..4), 0..10)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn never_panics_on_arbitrary_input(
        pts in any_points(),
        perp in any::<f64>(),
        lr in any::<f64>(),
        nc in 0usize..5,
        theta in any::<f64>(),
        bh in any::<bool>(),
    ) {
        let _ = Tsne::new()
            .theta(theta)
            .method(if bh { Method::BarnesHut } else { Method::Auto })
            .perplexity(perp)
            .learning_rate(lr)
            .n_components(nc)
            .n_iter(5)
            .try_fit(&pts);
    }

    #[test]
    fn valid_input_gives_finite_reproducible_embedding(
        pts in finite_points(),
        frac in 0.0f64..1.0,
        nc in 1usize..4,
        seed in any::<u64>(),
        bh in any::<bool>(),
        random in any::<bool>(),
    ) {
        #[allow(clippy::cast_precision_loss, reason = "n is tiny")]
        let limit = pts.len() as f64 / 3.0;
        // Strictly inside (1, n/3).
        let perp = (limit - 1.0).mul_add(frac * 0.99, 1.0 + 1e-6);
        let tsne = Tsne::new()
            .perplexity(perp)
            .n_components(nc)
            .n_iter(40)
            .method(if bh { Method::BarnesHut } else { Method::Exact })
            .init(if random { Init::Random } else { Init::Pca })
            .random_seed(seed);
        let r = tsne.try_fit(&pts).unwrap();
        prop_assert_eq!(r.embedding.len(), pts.len());
        prop_assert!(r.embedding.iter().all(|row| row.len() == nc));
        prop_assert!(r.embedding.iter().flatten().all(|x| x.is_finite()));
        prop_assert!(r.kl_divergence.is_finite());
        prop_assert_eq!(tsne.try_fit(&pts).unwrap(), r);
    }
}
