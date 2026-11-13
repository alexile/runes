//! Behavioural and known-answer tests for `rune-pca`.

#![allow(
    clippy::suboptimal_flops,
    clippy::cast_precision_loss,
    reason = "test sizes are tiny, so the f64 conversions are exact"
)]

use rune_pca::{Components, IncrementalPca, Pca, PcaError, PcaModel, Solver};

const EXACT: [Solver; 2] = [Solver::Covariance, Solver::Svd];
const ALL: [Solver; 3] = [Solver::Covariance, Solver::Svd, Solver::Randomized];

fn dot(a: &[f64], b: &[f64]) -> f64 {
    a.iter().zip(b).map(|(x, y)| x * y).sum()
}

fn close(a: f64, b: f64, tol: f64) -> bool {
    (a - b).abs() <= tol * (1.0 + b.abs())
}

/// The data set of scikit-learn's `PCA` docstring.
fn sklearn_example() -> Vec<Vec<f64>> {
    vec![
        vec![-1.0, -1.0],
        vec![-2.0, -1.0],
        vec![-3.0, -2.0],
        vec![1.0, 1.0],
        vec![2.0, 1.0],
        vec![3.0, 2.0],
    ]
}

/// Deterministic standard-normal samples (LCG + Box-Muller).
fn gaussians(seed: u64) -> impl FnMut() -> f64 {
    let mut state = seed;
    move || {
        let mut u = || {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            ((state >> 11) as f64 + 0.5) / (1u64 << 53) as f64
        };
        let (u1, u2) = (u(), u());
        (-2.0 * u1.ln()).sqrt() * (std::f64::consts::TAU * u2).cos()
    }
}

/// `n × d` data of rank `rank` with decaying spectrum, plus small noise.
fn low_rank(n: usize, d: usize, rank: usize, noise: f64) -> Vec<Vec<f64>> {
    let mut g = gaussians(0x5eed);
    let basis: Vec<Vec<f64>> = (0..rank).map(|_| (0..d).map(|_| g()).collect()).collect();
    (0..n)
        .map(|_| {
            let coeffs: Vec<f64> = (0..rank).map(|r| g() * 10.0 / (r as f64 + 1.0)).collect();
            (0..d)
                .map(|j| {
                    let signal: f64 = coeffs.iter().zip(&basis).map(|(c, b)| c * b[j]).sum();
                    signal + noise * g() + 3.0
                })
                .collect()
        })
        .collect()
}

fn assert_orthonormal(m: &PcaModel) {
    let c = m.components();
    for i in 0..c.len() {
        assert_eq!(c[i].len(), m.n_features());
        for j in 0..c.len() {
            let want = if i == j { 1.0 } else { 0.0 };
            let got = dot(&c[i], &c[j]);
            assert!((got - want).abs() < 1e-9, "<c{i}, c{j}> = {got}");
        }
    }
}

// ------------------------------------------------------------ known answers

#[test]
fn sklearn_docstring_example() {
    // XᵀX = [[28, 18], [18, 12]] → eigenvalues 20 ± √388.
    let s388 = 388f64.sqrt();
    let (l1, l2) = (20.0 + s388, 20.0 - s388);
    let norm = 18f64.hypot(l1 - 28.0);
    let axis = [18.0 / norm, (l1 - 28.0) / norm];
    for solver in ALL {
        let m = Pca::new(2)
            .with_solver(solver)
            .fit(&sklearn_example())
            .unwrap();
        let tol = 1e-12;
        assert!(close(m.singular_values()[0], l1.sqrt(), tol), "{solver:?}");
        assert!(close(m.singular_values()[1], l2.sqrt(), tol), "{solver:?}");
        assert!(close(m.explained_variance()[0], l1 / 5.0, tol));
        assert!(close(m.explained_variance()[1], l2 / 5.0, tol));
        assert!(close(m.explained_variance_ratio()[0], l1 / 40.0, tol));
        assert!(close(m.explained_variance_ratio()[1], l2 / 40.0, tol));
        // Published (rounded) values from the scikit-learn documentation.
        assert!((m.explained_variance_ratio()[0] - 0.992_442_9).abs() < 1e-6);
        assert!((m.explained_variance_ratio()[1] - 0.007_557_1).abs() < 1e-6);
        assert!((m.singular_values()[0] - 6.300_612_32).abs() < 1e-7);
        assert!((m.singular_values()[1] - 0.549_803_96).abs() < 1e-7);
        assert!(close(m.components()[0][0], axis[0], tol));
        assert!(close(m.components()[0][1], axis[1], tol));
        assert!(
            close(m.components()[1][0], -axis[1], 1e-10)
                || close(m.components()[1][0], axis[1], 1e-10)
        );
        assert!(m.mean().iter().all(|v| v.abs() < 1e-15));
        assert_eq!(m.noise_variance(), 0.0);
        assert_orthonormal(&m);
    }
}

/// Hand-computed: the rows (2, 2), (−2, −2), (1, −1), (−1, 1) have mean 0 and
/// `XᵀX = [[10, 6], [6, 10]]`, with eigenvalues 16 along (1, 1)/√2 and 4 along
/// (1, −1)/√2. So σ = (4, 2), explained variance = σ²/(n − 1) = (16/3, 4/3),
/// ratio = (0.8, 0.2), and (2, 2) projects to (2√2, 0). The same numbers come
/// out of `sklearn.decomposition.PCA(2).fit(X)` (up to the component signs,
/// which scikit-learn fixes from U rather than V).
fn hand_example() -> Vec<Vec<f64>> {
    vec![
        vec![2.0, 2.0],
        vec![-2.0, -2.0],
        vec![1.0, -1.0],
        vec![-1.0, 1.0],
    ]
}

fn assert_hand_model(m: &PcaModel, y: &[Vec<f64>], tol: f64) {
    let h = std::f64::consts::FRAC_1_SQRT_2;
    let sigma = [4.0, 2.0];
    let variance = [16.0 / 3.0, 4.0 / 3.0];
    let ratio = [0.8, 0.2];
    for i in 0..2 {
        assert!(close(m.singular_values()[i], sigma[i], tol), "{m:?}");
        assert!(close(m.explained_variance()[i], variance[i], tol), "{m:?}");
        assert!(
            close(m.explained_variance_ratio()[i], ratio[i], tol),
            "{m:?}"
        );
    }
    // The second axis has loadings of equal magnitude, so which of them
    // counts as "largest" (and hence its sign) is down to rounding.
    let c = m.components();
    assert!(close(c[0][0], h, tol) && close(c[0][1], h, tol));
    assert!(close(c[1][0].abs(), h, tol) && close(c[1][0], -c[1][1], tol));
    assert!(close(y[0][0], 8f64.sqrt(), tol) && y[0][1].abs() < tol);
    assert!(close(y[2][1].abs(), 2f64.sqrt(), tol) && y[2][0].abs() < tol);
}

#[test]
fn hand_computed_decomposition() {
    for solver in ALL {
        let m = Pca::new(2)
            .with_solver(solver)
            .fit(&hand_example())
            .unwrap();
        assert_hand_model(&m, &m.transform(&hand_example()).unwrap(), 1e-12);
    }
    let m = IncrementalPca::new(2)
        .fit_batches(&hand_example(), 2)
        .unwrap();
    assert_hand_model(&m, &m.transform(&hand_example()).unwrap(), 1e-12);
    // Whitening divides by √(16/3) and √(4/3).
    let w = Pca::new(2).with_whiten(true).fit(&hand_example()).unwrap();
    let y = w.transform(&hand_example()).unwrap();
    assert!(close(y[0][0], 8f64.sqrt() / (16.0f64 / 3.0).sqrt(), 1e-12));
    let back = w.inverse_transform(&y).unwrap();
    for (r, s) in back.iter().zip(hand_example()) {
        for (a, b) in r.iter().zip(&s) {
            assert!((a - b).abs() < 1e-12);
        }
    }
}

// ------------------------------------------------------- incremental PCA

#[test]
fn incremental_matches_batch_with_all_components() {
    let x = low_rank(60, 5, 3, 0.5);
    let batch = Pca::new(5).with_solver(Solver::Svd).fit(&x).unwrap();
    for size in [5, 7, 13, 60] {
        let inc = IncrementalPca::new(5).fit_batches(&x, size).unwrap();
        assert_eq!(inc.n_samples(), 60);
        for i in 0..5 {
            assert!(close(
                inc.explained_variance()[i],
                batch.explained_variance()[i],
                1e-9
            ));
            assert!(close(
                inc.explained_variance_ratio()[i],
                batch.explained_variance_ratio()[i],
                1e-9
            ));
            assert!(close(inc.mean()[i], batch.mean()[i], 1e-12));
            let d = dot(&inc.components()[i], &batch.components()[i]);
            assert!(
                (d.abs() - 1.0).abs() < 1e-8,
                "batch size {size}, component {i}: {d}"
            );
        }
    }
}

#[test]
fn incremental_truncated_tracks_the_leading_subspace() {
    // Rank-2 signal plus small noise: two components from batches of 10
    // should span the same plane as batch PCA.
    let x = low_rank(80, 6, 2, 0.01);
    let batch = Pca::new(2).fit(&x).unwrap();
    let inc = IncrementalPca::new(2).fit_batches(&x, 10).unwrap();
    for c in inc.components() {
        let in_plane: f64 = batch.components().iter().map(|b| dot(b, c).powi(2)).sum();
        assert!(in_plane > 1.0 - 1e-6, "{in_plane}");
    }
    for i in 0..2 {
        assert!(close(
            inc.explained_variance()[i],
            batch.explained_variance()[i],
            1e-4
        ));
    }
    let total: f64 = inc.explained_variance_ratio().iter().sum();
    assert!(total < 1.0 && total > 0.99);
    assert!(inc.noise_variance() > 0.0);
}

#[test]
fn incremental_validation() {
    assert_eq!(
        IncrementalPca::new(1).fit_batches(&hand_example(), 0),
        Err(PcaError::InvalidBatchSize)
    );
    assert_eq!(
        IncrementalPca::new(3).fit_batches(&hand_example(), 2),
        Err(PcaError::InvalidComponents {
            requested: 3,
            max: 2
        })
    );
    assert_eq!(
        IncrementalPca::new(2).partial_fit(&[vec![1.0, 2.0]]),
        Err(PcaError::BatchTooSmall {
            rows: 1,
            n_components: 2
        })
    );
    let mut one = IncrementalPca::new(1);
    one.partial_fit(&[vec![1.0, 2.0]]).unwrap();
    assert_eq!(one.model(), Err(PcaError::TooFewSamples { n: 1 }));
    assert_eq!(
        one.partial_fit(&[vec![1.0, 2.0, 3.0]]),
        Err(PcaError::DimensionMismatch {
            index: 0,
            expected: 2,
            found: 3
        })
    );
    assert_eq!(
        one.partial_fit(&[vec![1.0, f64::NAN]]),
        Err(PcaError::NonFiniteInput { index: 0 })
    );
    assert_eq!(
        IncrementalPca::new(1).partial_fit(&[vec![], vec![]]),
        Err(PcaError::NoFeatures)
    );
}

#[test]
fn rotated_axis_aligned_design() {
    // ±a·e_i for a = 6, 3, 1: covariance diag(2a²/5) in the frame `r`.
    let r = [
        [2.0 / 3.0, 2.0 / 3.0, 1.0 / 3.0],
        [-2.0 / 3.0, 1.0 / 3.0, 2.0 / 3.0],
        [1.0 / 3.0, -2.0 / 3.0, 2.0 / 3.0],
    ];
    let offset = [10.0, -5.0, 2.5];
    let mut x = Vec::new();
    for (axis, a) in r.iter().zip([6.0, 3.0, 1.0]) {
        for sign in [1.0, -1.0] {
            x.push(
                (0..3)
                    .map(|j| sign * a * axis[j] + offset[j])
                    .collect::<Vec<_>>(),
            );
        }
    }
    for solver in ALL {
        let m = Pca::default().with_solver(solver).fit(&x).unwrap();
        for (i, a) in [6.0f64, 3.0, 1.0].into_iter().enumerate() {
            assert!(
                close(m.explained_variance()[i], 2.0 * a * a / 5.0, 1e-12),
                "{solver:?}"
            );
            let d = dot(&m.components()[i], &r[i]).abs();
            assert!((d - 1.0).abs() < 1e-12, "{solver:?} axis {i}: {d}");
        }
        assert!(close(m.explained_variance_ratio()[0], 36.0 / 46.0, 1e-12));
        for (got, want) in m.mean().iter().zip(offset) {
            assert!(close(*got, want, 1e-14));
        }
    }
}

#[test]
fn component_signs_put_the_largest_loading_positive() {
    let m = Pca::default().fit(&low_rank(50, 6, 3, 0.1)).unwrap();
    for c in m.components() {
        let pivot = c
            .iter()
            .copied()
            .max_by(|a, b| a.abs().total_cmp(&b.abs()))
            .unwrap();
        assert!(pivot > 0.0);
    }
}

// ------------------------------------------------------- solver agreement

#[test]
fn exact_solvers_agree() {
    for (n, d) in [(40, 7), (7, 40), (12, 12)] {
        let x = low_rank(n, d, 5, 0.5);
        let a = Pca::default()
            .with_solver(Solver::Covariance)
            .fit(&x)
            .unwrap();
        let b = Pca::default().with_solver(Solver::Svd).fit(&x).unwrap();
        assert_eq!(a.n_components(), n.min(d));
        assert_eq!(b.n_components(), n.min(d));
        assert_orthonormal(&a);
        assert_orthonormal(&b);
        for i in 0..a.n_components() {
            assert!(
                close(a.explained_variance()[i], b.explained_variance()[i], 1e-8)
                    || a.explained_variance()[i] < 1e-10
            );
        }
        // Components of well-separated eigenvalues match exactly (signs fixed).
        for i in 0..5 {
            for (p, q) in a.components()[i].iter().zip(&b.components()[i]) {
                assert!((p - q).abs() < 1e-7, "{n}x{d} comp {i}: {p} vs {q}");
            }
        }
    }
}

#[test]
fn randomized_matches_exact_on_low_rank_data() {
    let x = low_rank(600, 80, 6, 0.01);
    let exact = Pca::new(6).with_solver(Solver::Svd).fit(&x).unwrap();
    let rand = Pca::new(6)
        .with_solver(Solver::Randomized)
        .with_seed(3)
        .fit(&x)
        .unwrap();
    assert_orthonormal(&rand);
    for i in 0..6 {
        assert!(close(
            rand.explained_variance()[i],
            exact.explained_variance()[i],
            1e-8
        ));
        let align = dot(&rand.components()[i], &exact.components()[i]);
        assert!((align - 1.0).abs() < 1e-8, "component {i}: {align}");
    }
    assert!(close(rand.noise_variance(), exact.noise_variance(), 1e-6));
}

#[test]
fn auto_picks_randomized_for_large_inputs() {
    let x = low_rank(600, 20, 3, 0.1);
    assert_eq!(Pca::new(3).fit(&x).unwrap().solver(), Solver::Randomized);
    assert_eq!(Pca::new(19).fit(&x).unwrap().solver(), Solver::Covariance);
    assert_eq!(
        Pca::with_variance_ratio(0.9).fit(&x).unwrap().solver(),
        Solver::Covariance
    );
}

// ------------------------------------------------------------ properties

#[test]
fn full_reconstruction_is_exact() {
    let x = low_rank(30, 8, 8, 1.0);
    for solver in ALL {
        for whiten in [false, true] {
            let (m, y) = Pca::default()
                .with_solver(solver)
                .with_whiten(whiten)
                .fit_transform(&x)
                .unwrap();
            let back = m.inverse_transform(&y).unwrap();
            for (r, s) in x.iter().zip(&back) {
                for (a, b) in r.iter().zip(s) {
                    assert!(
                        (a - b).abs() < 1e-9,
                        "{solver:?} whiten={whiten}: {a} vs {b}"
                    );
                }
            }
        }
    }
}

#[test]
fn truncated_reconstruction_error_is_the_discarded_spectrum() {
    // Eckart–Young: ‖X − X_k‖²_F = Σ_{j>k} σ_j².
    let x = low_rank(40, 10, 10, 1.0);
    let full = Pca::default().with_solver(Solver::Svd).fit(&x).unwrap();
    for solver in EXACT {
        let (m, y) = Pca::new(4).with_solver(solver).fit_transform(&x).unwrap();
        let back = m.inverse_transform(&y).unwrap();
        let err: f64 = x
            .iter()
            .zip(&back)
            .flat_map(|(r, s)| r.iter().zip(s).map(|(a, b)| (a - b).powi(2)))
            .sum();
        let tail: f64 = full.singular_values()[4..].iter().map(|s| s * s).sum();
        assert!(close(err, tail, 1e-9), "{solver:?}: {err} vs {tail}");
        let noise = tail / 39.0 / 6.0;
        assert!(close(m.noise_variance(), noise, 1e-9));
    }
}

#[test]
fn projection_variances_equal_explained_variance() {
    let x = low_rank(60, 5, 5, 0.3);
    let (m, y) = Pca::new(3).fit_transform(&x).unwrap();
    for c in 0..3 {
        let mean = y.iter().map(|r| r[c]).sum::<f64>() / 60.0;
        let var = y.iter().map(|r| (r[c] - mean).powi(2)).sum::<f64>() / 59.0;
        assert!(mean.abs() < 1e-9);
        assert!(close(var, m.explained_variance()[c], 1e-10));
    }
    let total: f64 = m.explained_variance_ratio().iter().sum();
    assert!(total < 1.0);
}

#[test]
fn whitening_gives_unit_uncorrelated_outputs() {
    let x = low_rank(80, 6, 6, 0.5);
    for solver in ALL {
        let (m, y) = Pca::new(4)
            .with_solver(solver)
            .with_whiten(true)
            .fit_transform(&x)
            .unwrap();
        assert!(m.whiten());
        for a in 0..4 {
            for b in 0..4 {
                let cov = y.iter().map(|r| r[a] * r[b]).sum::<f64>() / 79.0;
                let want = if a == b { 1.0 } else { 0.0 };
                assert!(
                    (cov - want).abs() < 1e-8,
                    "{solver:?} cov[{a}][{b}] = {cov}"
                );
            }
        }
    }
}

#[test]
fn variance_ratio_picks_the_fewest_components() {
    let x = low_rank(50, 6, 6, 0.1);
    let full = Pca::default().fit(&x).unwrap();
    let ratios = full.explained_variance_ratio();
    let target = ratios[0] + ratios[1] * 0.5;
    let m = Pca::with_variance_ratio(target).fit(&x).unwrap();
    assert_eq!(m.n_components(), 2);
    let m = Pca::with_variance_ratio(ratios[0]).fit(&x).unwrap();
    assert_eq!(m.n_components(), 1);
    let m = Pca::with_variance_ratio(1.0).fit(&x).unwrap();
    assert_eq!(m.n_components(), 6);
}

#[test]
fn results_scale_with_the_data() {
    let x = low_rank(20, 4, 4, 1.0);
    let reference = Pca::default().fit(&x).unwrap();
    for scale in [1e-150, 1e150] {
        let xs: Vec<Vec<f64>> = x
            .iter()
            .map(|r| r.iter().map(|v| v * scale).collect())
            .collect();
        let m = Pca::default().fit(&xs).unwrap();
        for i in 0..4 {
            assert!(close(
                m.singular_values()[i],
                reference.singular_values()[i] * scale,
                1e-10
            ));
            assert!(close(
                m.explained_variance_ratio()[i],
                reference.explained_variance_ratio()[i],
                1e-10
            ));
            for (a, b) in m.components()[i].iter().zip(&reference.components()[i]) {
                assert!((a - b).abs() < 1e-9);
            }
        }
    }
}

#[test]
fn deterministic_across_runs_and_thread_counts() {
    let x = low_rank(700, 30, 4, 0.2);
    let pca = Pca::new(4).with_solver(Solver::Randomized).with_seed(11);
    let run = |threads: usize| {
        rayon::ThreadPoolBuilder::new()
            .num_threads(threads)
            .build()
            .unwrap()
            .install(|| pca.fit(&x).unwrap())
    };
    let one = run(1);
    assert_eq!(one, run(3));
    assert_eq!(one, pca.fit(&x).unwrap());
    let exact = Pca::default().with_solver(Solver::Svd);
    assert_eq!(exact.fit(&x).unwrap(), exact.fit(&x).unwrap());
}

#[test]
fn single_feature_and_two_samples() {
    let m = Pca::default()
        .fit(&[vec![1.0], vec![3.0], vec![5.0]])
        .unwrap();
    assert_eq!(m.components(), &[vec![1.0]]);
    assert!(close(m.explained_variance()[0], 4.0, 1e-14));
    let m = Pca::default()
        .fit(&[vec![0.0, 0.0], vec![2.0, 2.0]])
        .unwrap();
    assert_eq!(m.n_components(), 2);
    assert!(close(m.explained_variance_ratio()[0], 1.0, 1e-14));
    assert!(m.explained_variance()[1].abs() < 1e-14);
    assert_orthonormal(&m);
}

// ----------------------------------------------------------------- errors

#[test]
fn invalid_input_is_rejected() {
    let pca = Pca::default();
    assert_eq!(pca.fit(&[]), Err(PcaError::TooFewSamples { n: 0 }));
    assert_eq!(pca.fit(&[vec![1.0]]), Err(PcaError::TooFewSamples { n: 1 }));
    assert_eq!(pca.fit(&[vec![], vec![]]), Err(PcaError::NoFeatures));
    assert_eq!(
        pca.fit(&[vec![1.0, 2.0], vec![1.0]]),
        Err(PcaError::DimensionMismatch {
            index: 1,
            expected: 2,
            found: 1
        })
    );
    assert_eq!(
        pca.fit(&[vec![1.0], vec![f64::NAN]]),
        Err(PcaError::NonFiniteInput { index: 1 })
    );
    assert_eq!(
        pca.fit(&[vec![1e308], vec![-1e308]]),
        Err(PcaError::NumericalOverflow)
    );
}

#[test]
fn invalid_configuration_is_rejected() {
    let x = sklearn_example();
    assert_eq!(
        Pca::new(0).fit(&x),
        Err(PcaError::InvalidComponents {
            requested: 0,
            max: 2
        })
    );
    assert_eq!(
        Pca::new(3).fit(&x),
        Err(PcaError::InvalidComponents {
            requested: 3,
            max: 2
        })
    );
    for r in [0.0, -0.5, 1.5] {
        assert_eq!(
            Pca::with_variance_ratio(r).fit(&x),
            Err(PcaError::InvalidVarianceRatio(r))
        );
    }
    assert!(matches!(
        Pca::with_variance_ratio(f64::NAN).fit(&x),
        Err(PcaError::InvalidVarianceRatio(_))
    ));
    assert_eq!(
        Pca::with_variance_ratio(0.5)
            .with_solver(Solver::Randomized)
            .fit(&x),
        Err(PcaError::RandomizedNeedsCount)
    );
}

#[test]
fn transform_validates_shapes() {
    let m = Pca::new(1).fit(&sklearn_example()).unwrap();
    assert_eq!(
        m.transform(&[vec![1.0, 2.0, 3.0]]),
        Err(PcaError::DimensionMismatch {
            index: 0,
            expected: 2,
            found: 3
        })
    );
    assert_eq!(
        m.inverse_transform(&[vec![1.0, 2.0]]),
        Err(PcaError::DimensionMismatch {
            index: 0,
            expected: 1,
            found: 2
        })
    );
    assert_eq!(
        m.transform(&[vec![f64::INFINITY, 0.0]]),
        Err(PcaError::NonFiniteInput { index: 0 })
    );
    assert_eq!(m.transform(&[]), Ok(vec![]));
}

#[test]
fn errors_have_readable_messages() {
    let msg = PcaError::InvalidComponents {
        requested: 5,
        max: 2,
    }
    .to_string();
    assert_eq!(msg, "n_components must be in 1..=2, got 5");
    assert!(PcaError::NoConvergence("SVD").to_string().contains("SVD"));
}

#[test]
fn builder_and_defaults() {
    let p = Pca::default();
    assert_eq!(p.components, Components::All);
    assert_eq!(p.solver, Solver::Auto);
    assert!(!p.whiten);
    let p = Pca::new(3)
        .with_oversamples(4)
        .with_power_iterations(2)
        .with_seed(9)
        .with_whiten(true);
    assert_eq!(p.components, Components::Count(3));
    assert_eq!(
        (p.n_oversamples, p.n_power_iter, p.random_seed),
        (4, Some(2), 9)
    );
    let m = p
        .with_solver(Solver::Randomized)
        .fit(&low_rank(30, 5, 5, 1.0))
        .unwrap();
    assert_eq!(m.n_components(), 3);
}

#[cfg(feature = "serde")]
#[test]
fn serde_round_trip_and_validation() {
    let x = low_rank(20, 4, 4, 1.0);
    let m = Pca::new(2).with_whiten(true).fit(&x).unwrap();
    let json = serde_json::to_string(&m).unwrap();
    let back: PcaModel = serde_json::from_str(&json).unwrap();
    assert_eq!(back.n_components(), 2);
    assert_eq!(back.solver(), m.solver());
    let (a, b) = (back.transform(&x).unwrap(), m.transform(&x).unwrap());
    for (r, s) in a.iter().zip(&b) {
        for (p, q) in r.iter().zip(s) {
            assert!((p - q).abs() < 1e-12);
        }
    }

    let cfg = Pca::with_variance_ratio(0.9).with_solver(Solver::Svd);
    let cfg_back: Pca = serde_json::from_str(&serde_json::to_string(&cfg).unwrap()).unwrap();
    assert_eq!(cfg_back, cfg);

    let mut value: serde_json::Value = serde_json::from_str(&json).unwrap();
    value["mean"] = serde_json::json!([0.0]);
    let broken: PcaModel = serde_json::from_value(value).unwrap();
    assert!(matches!(
        broken.transform(&x),
        Err(PcaError::InvalidModel(_))
    ));
}
