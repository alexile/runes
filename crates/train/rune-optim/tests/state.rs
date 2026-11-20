//! State save/resume, thread-count determinism, flat layouts and input
//! validation.

#![allow(
    clippy::unwrap_used,
    clippy::missing_const_for_fn,
    clippy::while_float,
    clippy::float_cmp,
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::similar_names,
    clippy::many_single_char_names,
    clippy::doc_markdown,
    clippy::suboptimal_flops,
    clippy::too_many_lines,
    clippy::type_complexity,
    clippy::unreadable_literal
)]

mod common;

use common::{Rng, bits};
use proptest::prelude::*;
use rune_optim::{
    Adafactor, AdafactorConfig, AdamW, AdamWConfig, FlatLayout, GroupOptions, Lion, LionConfig,
    Muon, MuonConfig, OptimError, Optimizer, PARALLEL_MIN_LEN, ParamSet, ParamSpec,
};

/// Large enough to take the parallel path (> PARALLEL_MIN_LEN elements).
fn big_specs() -> Vec<ParamSpec> {
    vec![
        ParamSpec::matrix(256, 160),
        ParamSpec::vector(40_000).in_group(1),
        ParamSpec::matrix(96, 128),
        ParamSpec::vector(33),
    ]
}

fn small_specs() -> Vec<ParamSpec> {
    vec![
        ParamSpec::matrix(12, 7),
        ParamSpec::vector(9).in_group(1),
        ParamSpec::matrix(5, 16),
    ]
}

fn groups() -> Vec<GroupOptions> {
    vec![GroupOptions::new(), GroupOptions::no_decay().with_lr(2e-3)]
}

fn make_all(specs: &[ParamSpec]) -> Vec<(&'static str, Box<dyn Optimizer + Send>)> {
    let set = || ParamSet::new(specs.to_vec(), groups()).unwrap();
    vec![
        (
            "adamw",
            Box::new(
                AdamW::new(
                    set(),
                    AdamWConfig {
                        amsgrad: true,
                        ..Default::default()
                    },
                )
                .unwrap(),
            ),
        ),
        (
            "lion",
            Box::new(
                Lion::new(
                    set(),
                    LionConfig {
                        weight_decay: 0.1,
                        ..Default::default()
                    },
                )
                .unwrap(),
            ),
        ),
        (
            "adafactor",
            Box::new(
                Adafactor::new(
                    set(),
                    AdafactorConfig {
                        beta1: Some(0.9),
                        ..Default::default()
                    },
                )
                .unwrap(),
            ),
        ),
        (
            "muon",
            Box::new(
                Muon::new(
                    set(),
                    MuonConfig {
                        weight_decay: 0.1,
                        ..Default::default()
                    },
                )
                .unwrap(),
            ),
        ),
    ]
}

fn run_steps(opt: &mut dyn Optimizer, params: &mut [Vec<f32>], seed: u64, steps: usize) {
    let mut rng = Rng::new(seed);
    for _ in 0..steps {
        let grads: Vec<Vec<f32>> = params.iter().map(|p| rng.vec_f32(p.len())).collect();
        let mut p: Vec<&mut [f32]> = params.iter_mut().map(Vec::as_mut_slice).collect();
        let g: Vec<&[f32]> = grads.iter().map(Vec::as_slice).collect();
        opt.step(&mut p, &g).unwrap();
    }
}

fn init(specs: &[ParamSpec]) -> Vec<Vec<f32>> {
    let mut rng = Rng::new(99);
    specs.iter().map(|s| rng.vec_f32(s.len)).collect()
}

#[test]
fn bitwise_identical_across_thread_counts() {
    assert!(big_specs()[0].len > PARALLEL_MIN_LEN);
    let results: Vec<Vec<Vec<Vec<u32>>>> = [1, 3, 8]
        .iter()
        .map(|&threads| {
            let pool = rayon::ThreadPoolBuilder::new()
                .num_threads(threads)
                .build()
                .unwrap();
            pool.install(|| {
                make_all(&big_specs())
                    .into_iter()
                    .map(|(_, mut opt)| {
                        let mut params = init(&big_specs());
                        run_steps(opt.as_mut(), &mut params, 5, 2);
                        params.iter().map(|p| bits(p)).collect()
                    })
                    .collect()
            })
        })
        .collect();
    for r in &results[1..] {
        assert!(r == &results[0], "results differ between thread counts");
    }
}

#[test]
fn flat_step_equals_list_step() {
    for align in [1usize, 16] {
        let specs = small_specs();
        let set = ParamSet::new(specs.clone(), groups()).unwrap();
        let layout = FlatLayout::aligned(&set, align);
        for ((name, mut a), (_, mut b)) in make_all(&specs).into_iter().zip(make_all(&specs)) {
            let mut params = init(&specs);
            let mut flat = vec![-7.0f32; layout.total()];
            for (p, &o) in params.iter().zip(layout.offsets()) {
                flat[o..o + p.len()].copy_from_slice(p);
            }
            let mut rng = Rng::new(17);
            for _ in 0..3 {
                let grads: Vec<Vec<f32>> = params.iter().map(|p| rng.vec_f32(p.len())).collect();
                let mut gflat = vec![f32::NAN; layout.total()];
                for (g, &o) in grads.iter().zip(layout.offsets()) {
                    gflat[o..o + g.len()].copy_from_slice(g);
                }
                let mut p: Vec<&mut [f32]> = params.iter_mut().map(Vec::as_mut_slice).collect();
                let g: Vec<&[f32]> = grads.iter().map(Vec::as_slice).collect();
                a.step(&mut p, &g).unwrap();
                b.step_flat(&layout, &mut flat, &gflat).unwrap();
            }
            for (p, &o) in params.iter().zip(layout.offsets()) {
                assert_eq!(bits(p), bits(&flat[o..o + p.len()]), "{name}");
            }
            // Padding is never touched.
            let used: usize = specs.iter().map(|s| s.len).sum();
            let pad = flat.iter().filter(|&&v| v == -7.0).count();
            assert_eq!(pad, layout.total() - used, "{name}");
        }
    }
}

#[test]
fn flat_layout_validation() {
    let set = ParamSet::single_group(vec![ParamSpec::vector(4), ParamSpec::vector(4)]).unwrap();
    assert!(FlatLayout::new(&set, vec![4, 0], 8).is_ok());
    assert!(matches!(
        FlatLayout::new(&set, vec![0, 2], 8),
        Err(OptimError::BadLayout { .. })
    ));
    assert!(matches!(
        FlatLayout::new(&set, vec![0, 5], 8),
        Err(OptimError::BadLayout { .. })
    ));
    assert!(FlatLayout::new(&set, vec![0], 8).is_err());
    assert!(FlatLayout::new(&set, vec![usize::MAX, 0], 8).is_err());
    let layout = FlatLayout::new(&set, vec![4, 0], 8).unwrap();
    let mut opt = AdamW::new(set, AdamWConfig::default()).unwrap();
    assert!(opt.step_flat(&layout, &mut [0.0; 7], &[0.0; 8]).is_err());
    assert!(opt.step_flat(&layout, &mut [0.0; 8], &[0.0; 9]).is_err());
    assert_eq!(opt.steps(), 0);
}

#[test]
fn bad_inputs_are_rejected_without_side_effects() {
    let specs = small_specs();
    for (name, mut opt) in make_all(&specs) {
        let mut params = init(&specs);
        let before = params.clone();
        let grads: Vec<Vec<f32>> = specs.iter().map(|s| vec![1.0; s.len]).collect();
        {
            let mut p: Vec<&mut [f32]> = params.iter_mut().map(Vec::as_mut_slice).collect();
            let g: Vec<&[f32]> = grads.iter().map(Vec::as_slice).collect();
            assert!(
                matches!(
                    opt.step(&mut p[..2], &g[..2]),
                    Err(OptimError::TensorCount { .. })
                ),
                "{name}"
            );
            let short = vec![1.0f32; 3];
            let mut g2 = g.clone();
            g2[2] = &short;
            assert!(
                matches!(
                    opt.step(&mut p, &g2),
                    Err(OptimError::LengthMismatch { .. })
                ),
                "{name}"
            );
            opt.set_lr_scale(f64::NAN);
            assert!(opt.step(&mut p, &g).is_err(), "{name}");
            opt.set_lr_scale(-1.0);
            assert!(opt.step(&mut p, &g).is_err(), "{name}");
            opt.set_lr_scale(1.0);
            opt.groups_mut()[1].lr = Some(f32::INFINITY);
            assert!(opt.step(&mut p, &g).is_err(), "{name}");
        }
        assert_eq!(params, before, "{name}");
        assert_eq!(opt.steps(), 0, "{name}");
    }
}

#[test]
fn config_and_set_validation() {
    assert!(matches!(
        ParamSet::single_group(vec![ParamSpec::vector(1).in_group(1)]),
        Err(OptimError::UnknownGroup { .. })
    ));
    let mut bad = ParamSpec::matrix(2, 3);
    bad.len = 5;
    assert!(matches!(
        ParamSet::single_group(vec![bad]),
        Err(OptimError::BadShape { .. })
    ));
    assert!(ParamSet::single_group(vec![ParamSpec::matrix(0, 3)]).is_err());
    let set = || ParamSet::single_group(vec![ParamSpec::vector(1)]).unwrap();
    assert!(
        AdamW::new(
            set(),
            AdamWConfig {
                betas: (1.0, 0.9),
                ..Default::default()
            }
        )
        .is_err()
    );
    assert!(
        AdamW::new(
            set(),
            AdamWConfig {
                eps: 0.0,
                ..Default::default()
            }
        )
        .is_err()
    );
    assert!(
        AdamW::new(
            set(),
            AdamWConfig {
                lr: -1.0,
                ..Default::default()
            }
        )
        .is_err()
    );
    assert!(
        Lion::new(
            set(),
            LionConfig {
                betas: (0.9, -0.1),
                ..Default::default()
            }
        )
        .is_err()
    );
    assert!(
        Adafactor::new(
            set(),
            AdafactorConfig {
                decay_rate: 0.5,
                ..Default::default()
            }
        )
        .is_err()
    );
    assert!(
        Adafactor::new(
            set(),
            AdafactorConfig {
                eps: (0.0, 1e-3),
                ..Default::default()
            }
        )
        .is_err()
    );
    assert!(
        Muon::new(
            set(),
            MuonConfig {
                momentum: 1.0,
                ..Default::default()
            }
        )
        .is_err()
    );
    let set = ParamSet::new(
        vec![ParamSpec::vector(1)],
        vec![GroupOptions::new().with_betas(0.9, 1.5)],
    );
    assert!(set.is_err());
}

#[test]
fn empty_and_zero_length_tensors() {
    let set = ParamSet::single_group(vec![]).unwrap();
    let mut opt = AdamW::new(set, AdamWConfig::default()).unwrap();
    opt.step(&mut [], &[]).unwrap();
    assert_eq!(opt.steps(), 1);
    let set = ParamSet::single_group(vec![ParamSpec::vector(0), ParamSpec::vector(2)]).unwrap();
    let mut opt = Adafactor::new(set, AdafactorConfig::default()).unwrap();
    let mut w = vec![1.0f32, 2.0];
    opt.step(&mut [&mut [], &mut w], &[&[], &[0.1, 0.1]])
        .unwrap();
    assert!(w.iter().all(|v| v.is_finite()));
}

#[test]
fn zero_gradients_are_safe() {
    let specs = small_specs();
    for (name, mut opt) in make_all(&specs) {
        let mut params = init(&specs);
        let grads: Vec<Vec<f32>> = specs.iter().map(|s| vec![0.0; s.len]).collect();
        let mut p: Vec<&mut [f32]> = params.iter_mut().map(Vec::as_mut_slice).collect();
        let g: Vec<&[f32]> = grads.iter().map(Vec::as_slice).collect();
        opt.step(&mut p, &g).unwrap();
        assert!(params.iter().flatten().all(|v| v.is_finite()), "{name}");
    }
}

#[cfg(feature = "serde")]
mod resume {
    use super::*;

    fn check<O>(make: impl Fn() -> O)
    where
        O: Optimizer + serde::Serialize + serde::de::DeserializeOwned + PartialEq + std::fmt::Debug,
    {
        let specs = small_specs();
        let mut a = make();
        let mut params_a = init(&specs);
        run_steps(&mut a, &mut params_a, 1, 3);
        let json = serde_json::to_string(&a).unwrap();
        let mut b: O = serde_json::from_str(&json).unwrap();
        assert_eq!(a, b);
        let mut params_b = params_a.clone();
        run_steps(&mut a, &mut params_a, 2, 4);
        run_steps(&mut b, &mut params_b, 2, 4);
        for (x, y) in params_a.iter().zip(&params_b) {
            assert_eq!(bits(x), bits(y));
        }
        assert_eq!(
            serde_json::to_string(&a).unwrap(),
            serde_json::to_string(&b).unwrap()
        );
        assert_eq!(b.steps(), 7);
    }

    fn set() -> ParamSet {
        ParamSet::new(small_specs(), groups()).unwrap()
    }

    #[test]
    fn resume_is_bitwise() {
        check(|| {
            AdamW::new(
                set(),
                AdamWConfig {
                    amsgrad: true,
                    ..Default::default()
                },
            )
            .unwrap()
        });
        check(|| Lion::new(set(), LionConfig::default()).unwrap());
        check(|| {
            Adafactor::new(
                set(),
                AdafactorConfig {
                    beta1: Some(0.9),
                    ..Default::default()
                },
            )
            .unwrap()
        });
        check(|| Muon::new(set(), MuonConfig::default()).unwrap());
    }

    #[test]
    fn corrupt_state_is_rejected() {
        let opt = AdamW::new(set(), AdamWConfig::default()).unwrap();
        let mut v: serde_json::Value = serde_json::to_value(&opt).unwrap();
        v["state"][0]["m"] = serde_json::json!([1.0]);
        let mut bad: AdamW = serde_json::from_value(v).unwrap();
        let mut params = init(&small_specs());
        let grads = init(&small_specs());
        let mut p: Vec<&mut [f32]> = params.iter_mut().map(Vec::as_mut_slice).collect();
        let g: Vec<&[f32]> = grads.iter().map(Vec::as_slice).collect();
        assert!(matches!(
            bad.step(&mut p, &g),
            Err(OptimError::CorruptState { index: 0, .. })
        ));

        let opt = Muon::new(set(), MuonConfig::default()).unwrap();
        let mut v: serde_json::Value = serde_json::to_value(&opt).unwrap();
        v["state"].as_array_mut().unwrap().pop();
        let mut bad: Muon = serde_json::from_value(v).unwrap();
        assert!(matches!(
            bad.step(&mut p, &g),
            Err(OptimError::CorruptState { .. })
        ));
    }

    #[test]
    fn schedules_and_helpers_round_trip() {
        use rune_optim::{DecayShape, LossScaler, LossScalerConfig, Schedule};
        let s = Schedule::concat(
            vec![(5, Schedule::linear_warmup(1.0, 5).unwrap())],
            Schedule::warmup_stable_decay(1.0, 0, 50, 10, 0.1, DecayShape::OneMinusSqrt).unwrap(),
        );
        let back: Schedule = serde_json::from_str(&serde_json::to_string(&s).unwrap()).unwrap();
        assert_eq!(s, back);
        let l = LossScaler::new(LossScalerConfig::default()).unwrap();
        let back: LossScaler = serde_json::from_str(&serde_json::to_string(&l).unwrap()).unwrap();
        assert_eq!(l, back);
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn first_adamw_step_is_bounded_by_lr(
        g in proptest::collection::vec(-1e4f32..1e4, 1..64), lr in 1e-5f32..1e-1,
    ) {
        let set = ParamSet::single_group(vec![ParamSpec::vector(g.len())]).unwrap();
        let mut opt = AdamW::new(set, AdamWConfig { lr, weight_decay: 0.0, ..Default::default() }).unwrap();
        let mut w = vec![0.0f32; g.len()];
        opt.step(&mut [&mut w], &[&g]).unwrap();
        for (&w, &g) in w.iter().zip(&g) {
            prop_assert!(w.abs() <= lr * 1.000_001);
            prop_assert!(w == 0.0 || w.signum() == -g.signum());
        }
    }

    #[test]
    fn flat_matches_list_for_random_shapes(
        shapes in proptest::collection::vec((1usize..9, 1usize..9, any::<bool>()), 1..5),
        seed in any::<u64>(),
    ) {
        let specs: Vec<ParamSpec> = shapes
            .iter()
            .map(|&(r, c, m)| if m { ParamSpec::matrix(r, c) } else { ParamSpec::vector(r * c) })
            .collect();
        let set = ParamSet::single_group(specs.clone()).unwrap();
        let layout = FlatLayout::contiguous(&set);
        let mut a = Muon::new(set.clone(), MuonConfig::default()).unwrap();
        let mut b = Muon::new(set, MuonConfig::default()).unwrap();
        let mut rng = Rng::new(seed);
        let mut params: Vec<Vec<f32>> = specs.iter().map(|s| rng.vec_f32(s.len)).collect();
        let mut flat: Vec<f32> = params.concat();
        for _ in 0..2 {
            let grads: Vec<Vec<f32>> = specs.iter().map(|s| rng.vec_f32(s.len)).collect();
            let gflat = grads.concat();
            let mut p: Vec<&mut [f32]> = params.iter_mut().map(Vec::as_mut_slice).collect();
            let g: Vec<&[f32]> = grads.iter().map(Vec::as_slice).collect();
            a.step(&mut p, &g).unwrap();
            b.step_flat(&layout, &mut flat, &gflat).unwrap();
        }
        prop_assert_eq!(bits(&params.concat()), bits(&flat));
    }

    #[test]
    fn lion_update_magnitude_is_exactly_lr(
        g in proptest::collection::vec(-10f32..10.0, 1..32),
    ) {
        let set = ParamSet::single_group(vec![ParamSpec::vector(g.len())]).unwrap();
        let mut opt = Lion::new(set, LionConfig { lr: 0.25, ..Default::default() }).unwrap();
        let mut w = vec![1.0f32; g.len()];
        opt.step(&mut [&mut w], &[&g]).unwrap();
        for (&w, &g) in w.iter().zip(&g) {
            let want = if g > 0.0 { 0.75 } else if g < 0.0 { 1.25 } else { 1.0 };
            prop_assert_eq!(w, want);
        }
    }
}
