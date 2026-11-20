//! Every optimizer reduces the loss of simple convex problems.

#![allow(
    clippy::unwrap_used,
    clippy::missing_const_for_fn,
    clippy::while_float,
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::similar_names,
    clippy::many_single_char_names,
    clippy::doc_markdown,
    clippy::float_cmp,
    clippy::suboptimal_flops,
    clippy::too_many_lines,
    clippy::type_complexity,
    clippy::unreadable_literal
)]

mod common;

use common::Rng;
use rune_optim::{
    Adafactor, AdafactorConfig, AdamW, AdamWConfig, Lion, LionConfig, Muon, MuonConfig, Optimizer,
    ParamSet, ParamSpec, Schedule,
};

const STEPS: u64 = 300;

/// Something that maps parameters to (loss, gradients).
trait Problem {
    fn specs(&self) -> Vec<ParamSpec>;
    fn loss_grad(&self, params: &[Vec<f32>]) -> (f64, Vec<Vec<f32>>);
}

/// `0.5 * sum a_i (x_i - c_i)^2` over a 6 × 8 matrix and an 8-vector.
struct Quadratic {
    a: Vec<Vec<f32>>,
    c: Vec<Vec<f32>>,
}

impl Quadratic {
    fn new() -> Self {
        let mut rng = Rng::new(21);
        let lens = [48, 8];
        Self {
            a: lens
                .iter()
                .map(|&n| {
                    (0..n)
                        .map(|_| (1.25 + 0.75 * rng.uniform()) as f32)
                        .collect()
                })
                .collect(),
            c: lens.iter().map(|&n| rng.vec_f32(n)).collect(),
        }
    }
}

impl Problem for Quadratic {
    fn specs(&self) -> Vec<ParamSpec> {
        vec![ParamSpec::matrix(6, 8), ParamSpec::vector(8)]
    }

    fn loss_grad(&self, params: &[Vec<f32>]) -> (f64, Vec<Vec<f32>>) {
        let mut loss = 0.0;
        let mut grads = Vec::new();
        for ((p, a), c) in params.iter().zip(&self.a).zip(&self.c) {
            let mut g = Vec::with_capacity(p.len());
            for ((&x, &a), &c) in p.iter().zip(a).zip(c) {
                let d = f64::from(x) - f64::from(c);
                loss += 0.5 * f64::from(a) * d * d;
                g.push((f64::from(a) * d) as f32);
            }
            grads.push(g);
        }
        (loss, grads)
    }
}

/// Binary logistic regression with a `1 × d` weight and a bias.
struct Logistic {
    x: Vec<Vec<f64>>,
    y: Vec<f64>,
}

const D: usize = 8;

impl Logistic {
    fn new() -> Self {
        let mut rng = Rng::new(22);
        let w: Vec<f64> = (0..D).map(|_| rng.normal()).collect();
        let mut x = Vec::new();
        let mut y = Vec::new();
        for _ in 0..128 {
            let xi: Vec<f64> = (0..D).map(|_| rng.normal()).collect();
            let z: f64 = xi.iter().zip(&w).map(|(a, b)| a * b).sum::<f64>() + 0.5;
            y.push(if z + 0.3 * rng.normal() > 0.0 {
                1.0
            } else {
                0.0
            });
            x.push(xi);
        }
        Self { x, y }
    }
}

impl Problem for Logistic {
    fn specs(&self) -> Vec<ParamSpec> {
        vec![ParamSpec::matrix(1, D), ParamSpec::vector(1).in_group(0)]
    }

    fn loss_grad(&self, params: &[Vec<f32>]) -> (f64, Vec<Vec<f32>>) {
        let n = self.x.len() as f64;
        let (mut loss, mut gw, mut gb) = (0.0, vec![0.0f64; D], 0.0f64);
        for (xi, &yi) in self.x.iter().zip(&self.y) {
            let z: f64 = xi
                .iter()
                .zip(&params[0])
                .map(|(a, &w)| a * f64::from(w))
                .sum::<f64>()
                + f64::from(params[1][0]);
            let p = 1.0 / (1.0 + (-z).exp());
            loss += -(yi * p.max(1e-12).ln() + (1.0 - yi) * (1.0 - p).max(1e-12).ln());
            for (g, a) in gw.iter_mut().zip(xi) {
                *g += (p - yi) * a / n;
            }
            gb += (p - yi) / n;
        }
        (
            loss / n,
            vec![gw.iter().map(|&g| g as f32).collect(), vec![gb as f32]],
        )
    }
}

fn train<O: Optimizer>(mut opt: O, problem: &dyn Problem, schedule: &Schedule) -> (f64, f64) {
    let mut params: Vec<Vec<f32>> = problem.specs().iter().map(|s| vec![0.0; s.len]).collect();
    let (initial, _) = problem.loss_grad(&params);
    for t in 0..STEPS {
        let (_, grads) = problem.loss_grad(&params);
        opt.set_lr_scale(schedule.value(t + 1));
        let mut p: Vec<&mut [f32]> = params.iter_mut().map(Vec::as_mut_slice).collect();
        let g: Vec<&[f32]> = grads.iter().map(Vec::as_slice).collect();
        opt.step(&mut p, &g).unwrap();
    }
    (initial, problem.loss_grad(&params).0)
}

fn optimizers(
    problem: &dyn Problem,
) -> Vec<(&'static str, Box<dyn FnOnce(&Schedule) -> (f64, f64) + '_>)> {
    let set = || ParamSet::single_group(problem.specs()).unwrap();
    vec![
        (
            "adamw",
            Box::new(move |s: &Schedule| {
                let cfg = AdamWConfig {
                    lr: 0.05,
                    weight_decay: 0.0,
                    ..Default::default()
                };
                train(AdamW::new(set(), cfg).unwrap(), problem, s)
            }),
        ),
        (
            "adamw-amsgrad",
            Box::new(move |s: &Schedule| {
                let cfg = AdamWConfig {
                    lr: 0.05,
                    weight_decay: 0.0,
                    amsgrad: true,
                    ..Default::default()
                };
                train(AdamW::new(set(), cfg).unwrap(), problem, s)
            }),
        ),
        (
            "lion",
            Box::new(move |s: &Schedule| {
                let cfg = LionConfig {
                    lr: 0.05,
                    ..Default::default()
                };
                train(Lion::new(set(), cfg).unwrap(), problem, s)
            }),
        ),
        (
            "adafactor",
            Box::new(move |s: &Schedule| {
                let cfg = AdafactorConfig {
                    lr: Some(0.05),
                    scale_parameter: false,
                    ..Default::default()
                };
                train(Adafactor::new(set(), cfg).unwrap(), problem, s)
            }),
        ),
        (
            "muon",
            Box::new(move |s: &Schedule| {
                let mut cfg = MuonConfig {
                    lr: 0.1,
                    ..Default::default()
                };
                cfg.fallback.lr = 0.05;
                train(Muon::new(set(), cfg).unwrap(), problem, s)
            }),
        ),
    ]
}

#[test]
fn quadratic_loss_falls() {
    let problem = Quadratic::new();
    let schedule = Schedule::warmup_cosine(1.0, 10, STEPS, 0.0).unwrap();
    for (name, run) in optimizers(&problem) {
        let (initial, last) = run(&schedule);
        assert!(last < 1e-2 * initial, "{name}: {initial} -> {last}");
    }
}

#[test]
fn logistic_loss_falls() {
    let problem = Logistic::new();
    let schedule = Schedule::warmup_cosine(1.0, 10, STEPS, 0.0).unwrap();
    for (name, run) in optimizers(&problem) {
        let (initial, last) = run(&schedule);
        assert!(last < 0.5 * initial, "{name}: {initial} -> {last}");
    }
}
