//! Each optimizer against a hand-written f64 reference, and pinned values
//! from closed-form cases.

#![allow(
    clippy::too_many_arguments,
    clippy::cast_possible_wrap,
    clippy::unwrap_used,
    clippy::missing_const_for_fn,
    clippy::while_float,
    clippy::float_cmp,
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::many_single_char_names,
    clippy::suboptimal_flops,
    clippy::too_many_lines,
    clippy::similar_names,
    clippy::doc_markdown,
    clippy::type_complexity,
    clippy::unreadable_literal
)]

mod common;

use common::{Rng, assert_close, matmul, to_f64, transpose};
use rune_optim::{
    Adafactor, AdafactorConfig, AdamW, AdamWConfig, GroupOptions, Lion, LionConfig, Muon,
    MuonConfig, MuonScale, NewtonSchulz, Optimizer, ParamSet, ParamSpec,
};

const STEPS: usize = 8;

fn grads_for(rng: &mut Rng, specs: &[ParamSpec]) -> Vec<Vec<f32>> {
    specs.iter().map(|s| rng.vec_f32(s.len)).collect()
}

fn run<O: Optimizer>(opt: &mut O, params: &mut [Vec<f32>], grads: &[Vec<f32>]) {
    let mut p: Vec<&mut [f32]> = params.iter_mut().map(Vec::as_mut_slice).collect();
    let g: Vec<&[f32]> = grads.iter().map(Vec::as_slice).collect();
    opt.step(&mut p, &g).unwrap();
}

// ---------- AdamW ----------

struct RefAdam {
    m: Vec<f64>,
    v: Vec<f64>,
    vmax: Vec<f64>,
}

fn ref_adamw(
    p: &mut [f64],
    g: &[f64],
    st: &mut RefAdam,
    t: usize,
    (lr, b1, b2, eps, wd): (f64, f64, f64, f64, f64),
    amsgrad: bool,
    inside: bool,
) {
    let bc1 = 1.0 - b1.powi(t as i32);
    let bc2 = 1.0 - b2.powi(t as i32);
    for i in 0..p.len() {
        p[i] *= 1.0 - lr * wd;
        st.m[i] = b1 * st.m[i] + (1.0 - b1) * g[i];
        st.v[i] = b2 * st.v[i] + (1.0 - b2) * g[i] * g[i];
        let mut v = st.v[i];
        if amsgrad {
            st.vmax[i] = st.vmax[i].max(v);
            v = st.vmax[i];
        }
        let mhat = st.m[i] / bc1;
        let vhat = v / bc2;
        let denom = if inside {
            (vhat + eps).sqrt()
        } else {
            vhat.sqrt() + eps
        };
        p[i] -= lr * mhat / denom;
    }
}

fn check_adamw(amsgrad: bool, inside: bool) {
    let specs = vec![
        ParamSpec::matrix(3, 5),
        ParamSpec::vector(7).in_group(1),
        ParamSpec::vector(4).in_group(2),
    ];
    let groups = vec![
        GroupOptions::new(),
        GroupOptions::no_decay(),
        GroupOptions::new()
            .with_lr(3e-3)
            .with_betas(0.8, 0.99)
            .with_weight_decay(0.3),
    ];
    let cfg = AdamWConfig {
        lr: 1e-2,
        betas: (0.9, 0.999),
        eps: if inside { 1e-6 } else { 1e-8 },
        weight_decay: 0.1,
        amsgrad,
        eps_inside_sqrt: inside,
    };
    let set = ParamSet::new(specs.clone(), groups).unwrap();
    let mut opt = AdamW::new(set, cfg).unwrap();
    let mut rng = Rng::new(7);
    let mut params: Vec<Vec<f32>> = specs.iter().map(|s| rng.vec_f32(s.len)).collect();
    let mut refp: Vec<Vec<f64>> = params.iter().map(|p| to_f64(p)).collect();
    let mut refs: Vec<RefAdam> = specs
        .iter()
        .map(|s| RefAdam {
            m: vec![0.0; s.len],
            v: vec![0.0; s.len],
            vmax: vec![0.0; s.len],
        })
        .collect();
    let hyper = [
        (1e-2, 0.9, 0.999, f64::from(cfg.eps), 0.1),
        (1e-2, 0.9, 0.999, f64::from(cfg.eps), 0.0),
        (
            f64::from(3e-3f32),
            f64::from(0.8f32),
            f64::from(0.99f32),
            f64::from(cfg.eps),
            f64::from(0.3f32),
        ),
    ];
    for t in 1..=STEPS {
        // Shrinking gradients exercise AMSGrad's running max.
        let mut grads = grads_for(&mut rng, &specs);
        for g in &mut grads {
            for v in g.iter_mut() {
                *v /= t as f32;
            }
        }
        run(&mut opt, &mut params, &grads);
        for i in 0..specs.len() {
            let h = hyper[i];
            let h = (
                f64::from(h.0 as f32),
                f64::from(h.1 as f32),
                f64::from(h.2 as f32),
                h.3,
                h.4,
            );
            ref_adamw(
                &mut refp[i],
                &to_f64(&grads[i]),
                &mut refs[i],
                t,
                h,
                amsgrad,
                inside,
            );
        }
    }
    for i in 0..specs.len() {
        assert_close(&params[i], &refp[i], 2e-5, "adamw");
    }
}

#[test]
fn adamw_matches_reference() {
    check_adamw(false, false);
}

#[test]
fn adamw_amsgrad_matches_reference() {
    check_adamw(true, false);
}

#[test]
fn adamw_eps_inside_sqrt_matches_reference() {
    check_adamw(false, true);
    check_adamw(true, true);
}

#[test]
fn adamw_constant_gradient_closed_form() {
    // With a constant gradient the bias-corrected moments are exactly g and
    // g^2, so each step moves lr * g / (|g| + eps) after the decay.
    let set = ParamSet::single_group(vec![ParamSpec::vector(2)]).unwrap();
    let cfg = AdamWConfig {
        lr: 0.1,
        weight_decay: 0.5,
        ..Default::default()
    };
    let mut opt = AdamW::new(set, cfg).unwrap();
    let mut w = vec![1.0f32, -2.0];
    let g = [2.0f32, -0.25];
    let mut expect = [1.0f64, -2.0];
    for _ in 0..5 {
        opt.step(&mut [&mut w], &[&g]).unwrap();
        for (e, &g) in expect.iter_mut().zip(&g) {
            let g = f64::from(g);
            *e = *e * (1.0 - 0.05) - 0.1 * g / (g.abs() + 1e-8);
        }
    }
    assert_close(&w, &expect, 1e-6, "adamw closed form");
    // p1 = 1 * 0.95 - 0.1 = 0.85 exactly in f64; pin the first value of a fresh run.
    let set = ParamSet::single_group(vec![ParamSpec::vector(1)]).unwrap();
    let mut opt = AdamW::new(set, cfg).unwrap();
    let mut w = vec![1.0f32];
    opt.step(&mut [&mut w], &[&[2.0]]).unwrap();
    assert!((w[0] - 0.85).abs() < 1e-7, "{}", w[0]);
}

// ---------- Lion ----------

#[test]
fn lion_matches_reference() {
    let specs = vec![ParamSpec::vector(33), ParamSpec::matrix(4, 4).in_group(1)];
    let groups = vec![GroupOptions::new(), GroupOptions::no_decay().with_lr(5e-3)];
    let cfg = LionConfig {
        lr: 1e-2,
        betas: (0.9, 0.99),
        weight_decay: 0.2,
    };
    let mut opt = Lion::new(ParamSet::new(specs.clone(), groups).unwrap(), cfg).unwrap();
    let mut rng = Rng::new(11);
    let mut params: Vec<Vec<f32>> = specs.iter().map(|s| rng.vec_f32(s.len)).collect();
    let mut refp: Vec<Vec<f64>> = params.iter().map(|p| to_f64(p)).collect();
    let mut refm: Vec<Vec<f64>> = specs.iter().map(|s| vec![0.0; s.len]).collect();
    let (b1, b2) = (f64::from(0.9f32), f64::from(0.99f32));
    for _ in 0..STEPS {
        let grads = grads_for(&mut rng, &specs);
        run(&mut opt, &mut params, &grads);
        for i in 0..specs.len() {
            let (lr, wd) = if i == 0 {
                (f64::from(1e-2f32), f64::from(0.2f32))
            } else {
                (f64::from(5e-3f32), 0.0)
            };
            for j in 0..specs[i].len {
                let g = f64::from(grads[i][j]);
                refp[i][j] *= 1.0 - lr * wd;
                let c = b1 * refm[i][j] + (1.0 - b1) * g;
                refp[i][j] -= lr * c.signum() * f64::from(u8::from(c != 0.0));
                refm[i][j] = b2 * refm[i][j] + (1.0 - b2) * g;
            }
        }
    }
    for i in 0..specs.len() {
        assert_close(&params[i], &refp[i], 1e-5, "lion");
    }
}

#[test]
fn lion_moves_by_exactly_lr() {
    let set = ParamSet::single_group(vec![ParamSpec::vector(3)]).unwrap();
    let cfg = LionConfig {
        lr: 0.125,
        ..Default::default()
    };
    let mut opt = Lion::new(set, cfg).unwrap();
    let mut w = vec![0.0f32; 3];
    for _ in 0..4 {
        opt.step(&mut [&mut w], &[&[1.0, -7.0, 0.0]]).unwrap();
    }
    assert_eq!(w, [-0.5, 0.5, 0.0]);
}

// ---------- Adafactor ----------

#[derive(Clone)]
struct RefFactor {
    row: Vec<f64>,
    col: Vec<f64>,
    full: Vec<f64>,
    m: Vec<f64>,
}

fn rms(x: &[f64]) -> f64 {
    (x.iter().map(|v| v * v).sum::<f64>() / x.len() as f64).sqrt()
}

#[allow(clippy::too_many_arguments)]
fn ref_adafactor(
    p: &mut [f64],
    g: &[f64],
    shape: Option<(usize, usize)>,
    st: &mut RefFactor,
    t: usize,
    cfg: &AdafactorConfig,
    lr_fixed: Option<f64>,
) {
    let tf = t as f64;
    let (eps1, eps2) = (f64::from(cfg.eps.0), f64::from(cfg.eps.1));
    let base = lr_fixed.unwrap_or_else(|| 1e-2f64.min(1.0 / tf.sqrt()));
    let lr = base
        * if cfg.scale_parameter {
            eps2.max(rms(p))
        } else {
            1.0
        };
    let b2 = 1.0 - tf.powf(f64::from(cfg.decay_rate));
    let mut u: Vec<f64> = vec![0.0; p.len()];
    match shape {
        Some((r, c)) => {
            for i in 0..r {
                let mean = (0..c).map(|j| g[i * c + j].powi(2) + eps1).sum::<f64>() / c as f64;
                st.row[i] = b2 * st.row[i] + (1.0 - b2) * mean;
            }
            for j in 0..c {
                let mean = (0..r).map(|i| g[i * c + j].powi(2) + eps1).sum::<f64>() / r as f64;
                st.col[j] = b2 * st.col[j] + (1.0 - b2) * mean;
            }
            let rm = st.row.iter().sum::<f64>() / r as f64;
            for i in 0..r {
                for j in 0..c {
                    u[i * c + j] = g[i * c + j] / ((st.row[i] / rm).sqrt() * st.col[j].sqrt());
                }
            }
        }
        None => {
            for i in 0..p.len() {
                st.full[i] = b2 * st.full[i] + (1.0 - b2) * (g[i] * g[i] + eps1);
                u[i] = g[i] / st.full[i].sqrt();
            }
        }
    }
    let d = (rms(&u) / f64::from(cfg.clip_threshold)).max(1.0);
    for v in &mut u {
        *v = *v / d * lr;
    }
    if let Some(b1) = cfg.beta1 {
        let b1 = f64::from(b1);
        for (m, v) in st.m.iter_mut().zip(&mut u) {
            *m = b1 * *m + (1.0 - b1) * *v;
            *v = *m;
        }
    }
    let wd = f64::from(cfg.weight_decay);
    for (p, v) in p.iter_mut().zip(&u) {
        *p = *p - wd * lr * *p - v;
    }
}

fn check_adafactor(cfg: AdafactorConfig) {
    let specs = vec![
        ParamSpec::matrix(6, 9),
        ParamSpec::vector(10),
        ParamSpec::matrix(1, 5),
    ];
    let mut opt = Adafactor::new(ParamSet::single_group(specs.clone()).unwrap(), cfg).unwrap();
    let mut rng = Rng::new(3);
    let mut params: Vec<Vec<f32>> = specs.iter().map(|s| rng.vec_f32(s.len)).collect();
    let mut refp: Vec<Vec<f64>> = params.iter().map(|p| to_f64(p)).collect();
    let mut refs: Vec<RefFactor> = specs
        .iter()
        .map(|s| {
            let (r, c) = s.matrix.unwrap_or((0, 0));
            RefFactor {
                row: vec![0.0; r],
                col: vec![0.0; c],
                full: vec![0.0; s.len],
                m: vec![0.0; s.len],
            }
        })
        .collect();
    for t in 1..=STEPS {
        let grads = grads_for(&mut rng, &specs);
        run(&mut opt, &mut params, &grads);
        for i in 0..specs.len() {
            let g = to_f64(&grads[i]);
            ref_adafactor(
                &mut refp[i],
                &g,
                specs[i].matrix,
                &mut refs[i],
                t,
                &cfg,
                cfg.lr.map(f64::from),
            );
        }
    }
    for i in 0..specs.len() {
        assert_close(&params[i], &refp[i], 2e-5, "adafactor");
    }
}

#[test]
fn adafactor_matches_reference() {
    check_adafactor(AdafactorConfig::default());
}

#[test]
fn adafactor_variants_match_reference() {
    check_adafactor(AdafactorConfig {
        lr: Some(1e-2),
        beta1: Some(0.9),
        weight_decay: 0.1,
        scale_parameter: false,
        clip_threshold: 0.5,
        ..Default::default()
    });
}

#[test]
fn adafactor_factored_state_is_sublinear() {
    let specs = vec![ParamSpec::matrix(100, 200), ParamSpec::vector(50)];
    let opt = Adafactor::new(
        ParamSet::single_group(specs).unwrap(),
        AdafactorConfig::default(),
    )
    .unwrap();
    assert_eq!(opt.state_len(), 100 + 200 + 50);
}

// ---------- Muon ----------

fn ref_newton_schulz(g: &[f64], rows: usize, cols: usize, steps: usize) -> Vec<f64> {
    let (a, b, c) = (
        f64::from(3.4445f32),
        f64::from(-4.7750f32),
        f64::from(2.0315f32),
    );
    let tr = rows > cols;
    let (m, n) = if tr { (cols, rows) } else { (rows, cols) };
    let mut x = if tr {
        transpose(g, rows, cols)
    } else {
        g.to_vec()
    };
    let norm = x.iter().map(|v| v * v).sum::<f64>().sqrt() + f64::from(1e-7f32);
    for v in &mut x {
        *v /= norm;
    }
    for _ in 0..steps {
        let gram = matmul(&x, &transpose(&x, m, n), m, n, m);
        let gram2 = matmul(&gram, &gram, m, m, m);
        let poly: Vec<f64> = gram
            .iter()
            .zip(&gram2)
            .map(|(a1, a2)| b * a1 + c * a2)
            .collect();
        let px = matmul(&poly, &x, m, m, n);
        x = x.iter().zip(&px).map(|(x, px)| a * x + px).collect();
    }
    if tr { transpose(&x, m, n) } else { x }
}

#[test]
fn newton_schulz_matches_reference() {
    let mut rng = Rng::new(5);
    for (r, c) in [(8, 8), (5, 12), (12, 5), (1, 7), (7, 1)] {
        let g = rng.vec_f32(r * c);
        let mut o = vec![0.0f32; r * c];
        NewtonSchulz::default()
            .orthogonalize(&g, r, c, &mut o)
            .unwrap();
        let reference = ref_newton_schulz(&to_f64(&g), r, c, 5);
        assert_close(&o, &reference, 1e-4, "newton-schulz");
    }
}

#[test]
fn newton_schulz_on_scaled_orthogonal_is_the_scalar_polynomial() {
    // G = 3 I (4 × 4): X0 = I / 2, every singular value follows
    // s <- a s + b s^3 + c s^5 from s = 0.5.
    let mut g = vec![0.0f32; 16];
    for i in 0..4 {
        g[i * 5] = 3.0;
    }
    let mut o = vec![0.0f32; 16];
    NewtonSchulz::default()
        .orthogonalize(&g, 4, 4, &mut o)
        .unwrap();
    let (a, b, c) = (3.4445f64, -4.7750, 2.0315);
    let mut s = 3.0 / (6.0 + 1e-7);
    for _ in 0..5 {
        s = a * s + b * s.powi(3) + c * s.powi(5);
    }
    for i in 0..4 {
        for j in 0..4 {
            let want = if i == j { s } else { 0.0 };
            assert!(
                (f64::from(o[i * 4 + j]) - want).abs() < 1e-5,
                "{i},{j}: {}",
                o[i * 4 + j]
            );
        }
    }
}

fn check_muon(nesterov: bool, scale: MuonScale) {
    let specs = vec![
        ParamSpec::matrix(6, 4),
        ParamSpec::matrix(3, 8).in_group(1),
        ParamSpec::vector(5).in_group(2),
        ParamSpec::matrix(4, 4).in_group(3),
    ];
    let groups = vec![
        GroupOptions::new(),
        GroupOptions::new()
            .with_lr(0.01)
            .with_betas(0.9, 0.99)
            .with_weight_decay(0.2),
        GroupOptions::no_decay(),
        GroupOptions::new().elementwise(),
    ];
    let cfg = MuonConfig {
        lr: 0.02,
        momentum: 0.95,
        nesterov,
        weight_decay: 0.1,
        scale,
        fallback: AdamWConfig {
            lr: 1e-3,
            weight_decay: 0.05,
            ..Default::default()
        },
        ..Default::default()
    };
    let mut opt = Muon::new(ParamSet::new(specs.clone(), groups).unwrap(), cfg).unwrap();
    assert!(opt.is_matrix(0) && opt.is_matrix(1) && !opt.is_matrix(2) && !opt.is_matrix(3));
    let mut rng = Rng::new(9);
    let mut params: Vec<Vec<f32>> = specs.iter().map(|s| rng.vec_f32(s.len)).collect();
    let mut refp: Vec<Vec<f64>> = params.iter().map(|p| to_f64(p)).collect();
    let mut mom: Vec<Vec<f64>> = specs.iter().map(|s| vec![0.0; s.len]).collect();
    let mut adam: Vec<RefAdam> = specs
        .iter()
        .map(|s| RefAdam {
            m: vec![0.0; s.len],
            v: vec![0.0; s.len],
            vmax: vec![],
        })
        .collect();
    for t in 1..=STEPS {
        let grads = grads_for(&mut rng, &specs);
        run(&mut opt, &mut params, &grads);
        for i in 0..specs.len() {
            let g = to_f64(&grads[i]);
            if i >= 2 {
                let wd = if i == 2 { 0.0 } else { f64::from(0.05f32) };
                let h = (
                    f64::from(1e-3f32),
                    f64::from(0.9f32),
                    f64::from(0.999f32),
                    f64::from(1e-8f32),
                    wd,
                );
                ref_adamw(&mut refp[i], &g, &mut adam[i], t, h, false, false);
                continue;
            }
            let (r, c) = specs[i].matrix.unwrap();
            let (lr, mu, wd) = if i == 0 {
                (f64::from(0.02f32), f64::from(0.95f32), f64::from(0.1f32))
            } else {
                (f64::from(0.01f32), f64::from(0.9f32), f64::from(0.2f32))
            };
            for (m, g) in mom[i].iter_mut().zip(&g) {
                *m = mu * *m + (1.0 - mu) * g;
            }
            let u: Vec<f64> = if nesterov {
                g.iter()
                    .zip(&mom[i])
                    .map(|(g, m)| (1.0 - mu) * g + mu * m)
                    .collect()
            } else {
                mom[i].clone()
            };
            let o = ref_newton_schulz(&u, r, c, 5);
            let factor = scale.factor(r, c);
            for (p, o) in refp[i].iter_mut().zip(&o) {
                *p = *p * (1.0 - lr * wd) - lr * factor * o;
            }
        }
    }
    for i in 0..specs.len() {
        assert_close(&params[i], &refp[i], 5e-5, "muon");
    }
}

#[test]
fn muon_matches_reference() {
    check_muon(true, MuonScale::Shape);
    check_muon(false, MuonScale::Unit);
    check_muon(true, MuonScale::MatchAdamW { coefficient: 0.2 });
}

#[test]
fn muon_scale_rules() {
    assert_eq!(MuonScale::Shape.factor(16, 4), 2.0);
    assert_eq!(MuonScale::Shape.factor(4, 16), 1.0);
    assert_eq!(MuonScale::Unit.factor(9, 1), 1.0);
    let f = MuonScale::MatchAdamW { coefficient: 0.2 }.factor(100, 25);
    assert!((f - 2.0).abs() < 1e-7);
}
