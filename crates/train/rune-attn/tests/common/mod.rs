//! Naive f64 reference attention and problem generators shared by the tests.
#![allow(
    clippy::unused_self,
    clippy::too_many_arguments,
    clippy::unwrap_used,
    clippy::cast_possible_truncation,
    clippy::missing_const_for_fn,
    clippy::suboptimal_flops,
    clippy::type_complexity,
    dead_code,
    clippy::cast_precision_loss,
    clippy::cast_possible_wrap,
    clippy::many_single_char_names,
    clippy::too_many_lines
)]

use rune_attn::{Attention, AttnGrads, AttnInputs, AttnLayout, AttnOutput, Bias, HeadDims};

/// Which bias a problem carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BiasKind {
    None,
    Alibi,
    Dense,
}

/// Mask and score options.
#[derive(Debug, Clone, Copy)]
pub struct Spec {
    pub causal: bool,
    pub left: Option<usize>,
    pub right: Option<usize>,
    pub softcap: Option<f64>,
    pub scale: Option<f64>,
    pub bias: BiasKind,
}

impl Spec {
    pub const PLAIN: Self = Self {
        causal: false,
        left: None,
        right: None,
        softcap: None,
        scale: None,
        bias: BiasKind::None,
    };

    pub fn attention(&self, blocks: (usize, usize)) -> Attention {
        let mut a = Attention::new()
            .causal(self.causal)
            .window(self.left, self.right)
            .blocks(blocks.0, blocks.1);
        if let Some(c) = self.softcap {
            a = a.softcap(c as f32);
        }
        if let Some(s) = self.scale {
            a = a.scale(s as f32);
        }
        a
    }
}

/// Deterministic pseudo-random numbers in `[-1, 1)`.
pub struct Rng(u64);

impl Rng {
    pub const fn new(seed: u64) -> Self {
        Self(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1)
    }

    pub fn next(&mut self) -> f64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        ((self.0 >> 11) as f64 / (1u64 << 53) as f64).mul_add(2.0, -1.0)
    }

    pub fn vec(&mut self, n: usize, amp: f64) -> Vec<f64> {
        // Round through f32 so the f32 kernel and the f64 reference see the
        // same numbers.
        (0..n)
            .map(|_| f64::from((self.next() * amp) as f32))
            .collect()
    }
}

/// One attention problem in f64.
#[derive(Debug, Clone)]
pub struct Problem {
    pub cu_q: Vec<usize>,
    pub cu_k: Vec<usize>,
    pub hd: HeadDims,
    pub q: Vec<f64>,
    pub k: Vec<f64>,
    pub v: Vec<f64>,
    pub slopes: Vec<f64>,
    pub bias: Vec<f64>,
}

pub fn f32s(x: &[f64]) -> Vec<f32> {
    x.iter().map(|&v| v as f32).collect()
}

impl Problem {
    pub fn new(cu_q: Vec<usize>, cu_k: Vec<usize>, hd: HeadDims, rng: &mut Rng, amp: f64) -> Self {
        let tq = *cu_q.last().unwrap_or(&0);
        let tk = *cu_k.last().unwrap_or(&0);
        let nb: usize = (0..cu_q.len() - 1)
            .map(|b| hd.heads_q * (cu_q[b + 1] - cu_q[b]) * (cu_k[b + 1] - cu_k[b]))
            .sum();
        Self {
            q: rng.vec(tq * hd.heads_q * hd.dim_qk, amp),
            k: rng.vec(tk * hd.heads_kv * hd.dim_qk, amp),
            v: rng.vec(tk * hd.heads_kv * hd.dim_v, 1.0),
            slopes: (0..hd.heads_q)
                .map(|h| f64::from(0.5f32.powi(h as i32 + 1)))
                .collect(),
            bias: rng.vec(nb, 1.0),
            cu_q,
            cu_k,
            hd,
        }
    }

    pub fn dense(batch: usize, sq: usize, sk: usize, hd: HeadDims, rng: &mut Rng) -> Self {
        Self::new(
            (0..=batch).map(|b| b * sq).collect(),
            (0..=batch).map(|b| b * sk).collect(),
            hd,
            rng,
            1.0,
        )
    }

    pub fn layout(&self) -> AttnLayout {
        AttnLayout::varlen(&self.cu_q, &self.cu_k, self.hd).unwrap()
    }

    /// Run the crate's forward pass on the f32 copy.
    pub fn forward(&self, spec: &Spec, attn: &Attention) -> AttnOutput {
        let (q, k, v, s, b) = self.f32_parts();
        let inputs = self.inputs(spec, &q, &k, &v, &s, &b);
        attn.forward(&self.layout(), &inputs).unwrap()
    }

    pub fn backward(
        &self,
        spec: &Spec,
        attn: &Attention,
        d_out: &[f32],
    ) -> (AttnOutput, AttnGrads) {
        let (q, k, v, s, b) = self.f32_parts();
        let inputs = self.inputs(spec, &q, &k, &v, &s, &b);
        let layout = self.layout();
        let fwd = attn.forward(&layout, &inputs).unwrap();
        let g = attn
            .backward(&layout, &inputs, &fwd.out, &fwd.lse, d_out)
            .unwrap();
        (fwd, g)
    }

    pub fn f32_parts(&self) -> (Vec<f32>, Vec<f32>, Vec<f32>, Vec<f32>, Vec<f32>) {
        (
            f32s(&self.q),
            f32s(&self.k),
            f32s(&self.v),
            f32s(&self.slopes),
            f32s(&self.bias),
        )
    }

    pub fn inputs<'a>(
        &self,
        spec: &Spec,
        q: &'a [f32],
        k: &'a [f32],
        v: &'a [f32],
        slopes: &'a [f32],
        bias: &'a [f32],
    ) -> AttnInputs<'a> {
        let b = match spec.bias {
            BiasKind::None => Bias::None,
            BiasKind::Alibi => Bias::Alibi(slopes),
            BiasKind::Dense => Bias::Dense(bias),
        };
        AttnInputs::new(q, k, v).with_bias(b)
    }

    /// Materialize every softmax row in f64. Returns `(out, lse)`.
    pub fn reference(&self, spec: &Spec) -> (Vec<f64>, Vec<f64>) {
        let HeadDims {
            heads_q: hq,
            heads_kv: hkv,
            dim_qk: dqk,
            dim_v: dv,
        } = self.hd;
        let group = hq / hkv;
        let tq = *self.cu_q.last().unwrap_or(&0);
        let mut out = vec![0.0; tq * hq * dv];
        let mut lse = vec![f64::NEG_INFINITY; tq * hq];
        let scale = spec.scale.unwrap_or_else(|| 1.0 / (dqk as f64).sqrt());
        let mut bias_off = 0;
        for b in 0..self.cu_q.len() - 1 {
            let (q0, k0) = (self.cu_q[b], self.cu_k[b]);
            let sq = self.cu_q[b + 1] - q0;
            let sk = self.cu_k[b + 1] - k0;
            for h in 0..hq {
                let g = h / group;
                for i in 0..sq {
                    let p = i as i64 + sk as i64 - sq as i64;
                    let mut logits = vec![f64::NEG_INFINITY; sk];
                    for (j, l) in logits.iter_mut().enumerate() {
                        let jj = j as i64;
                        let visible = (!spec.causal || jj <= p)
                            && spec.left.is_none_or(|w| jj >= p - w as i64)
                            && spec.right.is_none_or(|w| jj <= p + w as i64);
                        if !visible {
                            continue;
                        }
                        let qi = &self.q[((q0 + i) * hq + h) * dqk..][..dqk];
                        let kj = &self.k[((k0 + j) * hkv + g) * dqk..][..dqk];
                        let mut s = scale * qi.iter().zip(kj).map(|(a, b)| a * b).sum::<f64>();
                        if let Some(c) = spec.softcap {
                            s = c * (s / c).tanh();
                        }
                        match spec.bias {
                            BiasKind::None => {}
                            BiasKind::Alibi => s -= self.slopes[h] * (p - jj).abs() as f64,
                            BiasKind::Dense => s += self.bias[bias_off + (h * sq + i) * sk + j],
                        }
                        *l = s;
                    }
                    let m = logits.iter().copied().fold(f64::NEG_INFINITY, f64::max);
                    if m == f64::NEG_INFINITY {
                        continue;
                    }
                    let w: Vec<f64> = logits.iter().map(|&l| (l - m).exp()).collect();
                    let sum: f64 = w.iter().sum();
                    let row = (q0 + i) * hq + h;
                    lse[row] = m + sum.ln();
                    for (j, &wj) in w.iter().enumerate() {
                        let vj = &self.v[((k0 + j) * hkv + g) * dv..][..dv];
                        for (o, &x) in out[row * dv..][..dv].iter_mut().zip(vj) {
                            *o += wj / sum * x;
                        }
                    }
                }
            }
            bias_off += hq * sq * sk;
        }
        (out, lse)
    }

    /// Central finite differences of `sum(out · w)` on the f64 reference.
    pub fn fd_grads(&self, spec: &Spec, w: &[f64]) -> [Vec<f64>; 4] {
        let loss =
            |p: &Self| -> f64 { p.reference(spec).0.iter().zip(w).map(|(a, b)| a * b).sum() };
        let eps = 1e-5;
        let mut res: [Vec<f64>; 4] = Default::default();
        for (slot, which) in res.iter_mut().zip(0..4) {
            let n = match which {
                0 => self.q.len(),
                1 => self.k.len(),
                2 => self.v.len(),
                _ => {
                    if spec.bias == BiasKind::Dense {
                        self.bias.len()
                    } else {
                        0
                    }
                }
            };
            let mut p = self.clone();
            for idx in 0..n {
                let x0 = match which {
                    0 => p.q[idx],
                    1 => p.k[idx],
                    2 => p.v[idx],
                    _ => p.bias[idx],
                };
                set(&mut p, which, idx, x0 + eps);
                let lp = loss(&p);
                set(&mut p, which, idx, x0 - eps);
                let lm = loss(&p);
                set(&mut p, which, idx, x0);
                slot.push((lp - lm) / (2.0 * eps));
            }
        }
        res
    }
}

fn set(p: &mut Problem, which: usize, idx: usize, x: f64) {
    match which {
        0 => p.q[idx] = x,
        1 => p.k[idx] = x,
        2 => p.v[idx] = x,
        _ => p.bias[idx] = x,
    }
}

/// Assert `got` (f32) matches `want` (f64) elementwise.
pub fn assert_close(what: &str, got: &[f32], want: &[f64], atol: f64, rtol: f64) {
    assert_eq!(got.len(), want.len(), "{what}: length");
    for (i, (&g, &w)) in got.iter().zip(want).enumerate() {
        let g = f64::from(g);
        if w == f64::NEG_INFINITY {
            assert!(g == f64::NEG_INFINITY, "{what}[{i}]: got {g}, want -inf");
            continue;
        }
        assert!(g.is_finite(), "{what}[{i}]: got {g}, want {w}");
        assert!(
            (g - w).abs() <= atol + rtol * w.abs(),
            "{what}[{i}]: got {g}, want {w}"
        );
    }
}
