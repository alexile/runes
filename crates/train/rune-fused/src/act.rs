//! Activations and gated MLP units (Shazeer, "GLU Variants Improve
//! Transformer"; So et al., "Primer: Searching for Efficient Transformers
//! for Language Modeling" for squared ReLU).

use crate::error::{FusedError, check_len, invalid, mul, rows_of};
use crate::reduce::{rows_per_task, run_tasks, worth_parallel};

/// Element-wise nonlinearity used alone or as the gate of a gated unit.
///
/// | Variant | `f(x)` | Gated unit |
/// |---------|--------|------------|
/// | `Silu` | `x · σ(x)` | SwiGLU |
/// | `GeluTanh` | `x/2 · (1 + tanh(√(2/π) (x + 0.044715 x³)))` | GeGLU (tanh) |
/// | `GeluErf` | `x · Φ(x) = x/2 · (1 + erf(x / √2))` | GeGLU (exact) |
/// | `ReluSquared` | `max(x, 0)²` | gated squared ReLU |
///
/// `Silu`, `GeluTanh` and `ReluSquared` are evaluated in `f32`. `GeluErf`
/// is evaluated in `f64` (with `Φ` computed from `erfc`, so the far
/// negative tail keeps its relative accuracy) and rounded once.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Activation {
    /// Sigmoid-weighted linear unit (swish with β = 1).
    Silu,
    /// GELU, tanh approximation.
    GeluTanh,
    /// GELU, exact (error function).
    GeluErf,
    /// Squared ReLU.
    ReluSquared,
}

const SQRT_2_OVER_PI: f32 = 0.797_884_6;
const GELU_C: f32 = 0.044_715;
const FRAC_1_SQRT_2PI: f64 = 0.398_942_280_401_432_7;

#[allow(clippy::cast_possible_truncation)]
impl Activation {
    /// `f(x)`.
    #[must_use]
    pub fn apply(self, x: f32) -> f32 {
        match self {
            Self::Silu => x * sigmoid(x),
            Self::GeluTanh => {
                let t = (SQRT_2_OVER_PI * (x + GELU_C * x * x * x)).tanh();
                0.5 * x * (1.0 + t)
            }
            Self::GeluErf => {
                let x = f64::from(x);
                (x * norm_cdf(x)) as f32
            }
            Self::ReluSquared => {
                let r = relu(x);
                r * r
            }
        }
    }

    /// `f'(x)`.
    #[must_use]
    pub fn derivative(self, x: f32) -> f32 {
        self.value_and_derivative(x).1
    }

    /// `(f(x), f'(x))` in one evaluation.
    #[must_use]
    pub fn value_and_derivative(self, x: f32) -> (f32, f32) {
        match self {
            Self::Silu => {
                let s = sigmoid(x);
                (x * s, s * (1.0 + x * (1.0 - s)))
            }
            Self::GeluTanh => {
                let x2 = x * x;
                let t = (SQRT_2_OVER_PI * (x + GELU_C * x2 * x)).tanh();
                let d = 0.5
                    + 0.5 * t
                    + 0.5 * x * (1.0 - t * t) * SQRT_2_OVER_PI * (1.0 + 3.0 * GELU_C * x2);
                (0.5 * x * (1.0 + t), d)
            }
            Self::GeluErf => {
                let x = f64::from(x);
                let cdf = norm_cdf(x);
                let pdf = FRAC_1_SQRT_2PI * (-0.5 * x * x).exp();
                ((x * cdf) as f32, (cdf + x * pdf) as f32)
            }
            Self::ReluSquared => {
                let r = relu(x);
                (r * r, 2.0 * r)
            }
        }
    }
}

fn sigmoid(x: f32) -> f32 {
    1.0 / (1.0 + (-x).exp())
}

/// `max(x, 0)` that propagates NaN.
fn relu(x: f32) -> f32 {
    if x <= 0.0 { 0.0 } else { x }
}

/// Standard normal CDF `Φ(x) = erfc(-x / √2) / 2`.
fn norm_cdf(x: f64) -> f64 {
    0.5 * erfc(-x * std::f64::consts::FRAC_1_SQRT_2)
}

/// `erf(x)` to about `f64` precision.
#[must_use]
pub fn erf(x: f64) -> f64 {
    if x.is_nan() {
        return x;
    }
    let a = x.abs();
    let r = if a < 2.0 {
        erf_series(a)
    } else {
        1.0 - erfc_cf(a)
    };
    r.copysign(x)
}

/// `erfc(x) = 1 - erf(x)`, accurate in the tail where `erf` rounds to 1.
#[must_use]
pub fn erfc(x: f64) -> f64 {
    if x.is_nan() {
        return x;
    }
    if x < 0.0 {
        2.0 - erfc(-x)
    } else if x < 2.0 {
        1.0 - erf_series(x)
    } else {
        erfc_cf(x)
    }
}

/// `erf(z) = 2/√π · e^{-z²} · Σ_n 2ⁿ z^{2n+1} / (1·3·…·(2n+1))`, for
/// `0 <= z < 2`. All terms are positive, so there is no cancellation.
fn erf_series(z: f64) -> f64 {
    let z2 = 2.0 * z * z;
    let mut term = z;
    let mut sum = z;
    let mut n = 0.0f64;
    for _ in 0..200 {
        term *= z2 / (2.0 * n + 3.0);
        sum += term;
        n += 1.0;
        if term <= sum * 1e-17 {
            break;
        }
    }
    std::f64::consts::FRAC_2_SQRT_PI * (-z * z).exp() * sum
}

/// `erfc(z) = e^{-z²}/√π · 1/(z + (1/2)/(z + 1/(z + (3/2)/(z + …))))` by
/// the modified Lentz method, for `z >= 2`.
fn erfc_cf(z: f64) -> f64 {
    const TINY: f64 = 1e-300;
    if z > 27.3 {
        // erfc(27.3) is below the smallest subnormal f64.
        return 0.0;
    }
    let mut f = z;
    let mut c = f;
    let mut d = 0.0f64;
    let mut k = 1.0f64;
    for _ in 0..500 {
        let a = 0.5 * k;
        d = z + a * d;
        if d.abs() < TINY {
            d = TINY;
        }
        c = z + a / c;
        if c.abs() < TINY {
            c = TINY;
        }
        d = 1.0 / d;
        let delta = c * d;
        f *= delta;
        k += 1.0;
        if (delta - 1.0).abs() < 1e-16 {
            break;
        }
    }
    (-z * z).exp() / (std::f64::consts::PI.sqrt() * f)
}

const ELEM_TASK: usize = 1 << 13;

/// `out = f(x)` element-wise.
pub fn activation_forward(act: Activation, x: &[f32], out: &mut [f32]) -> Result<(), FusedError> {
    check_len("out", x.len(), out.len())?;
    let tasks: Vec<_> = x.chunks(ELEM_TASK).zip(out.chunks_mut(ELEM_TASK)).collect();
    run_tasks(worth_parallel(x.len()), tasks, |(x, out)| {
        for (o, &v) in out.iter_mut().zip(x) {
            *o = act.apply(v);
        }
    });
    Ok(())
}

/// `dx = dy · f'(x)` element-wise.
pub fn activation_backward(
    act: Activation,
    dy: &[f32],
    x: &[f32],
    dx: &mut [f32],
) -> Result<(), FusedError> {
    check_len("dy", x.len(), dy.len())?;
    check_len("dx", x.len(), dx.len())?;
    let tasks: Vec<_> = dy
        .chunks(ELEM_TASK)
        .zip(x.chunks(ELEM_TASK))
        .zip(dx.chunks_mut(ELEM_TASK))
        .collect();
    run_tasks(worth_parallel(x.len()), tasks, |((dy, x), dx)| {
        for ((g, &d), &v) in dx.iter_mut().zip(dy).zip(x) {
            *g = d * act.derivative(v);
        }
    });
    Ok(())
}

/// Gated unit with separate inputs: `out = f(gate) · up`, all the same
/// length (`[rows, inter]`).
///
/// ```
/// use rune_fused::{glu_forward, Activation};
///
/// let gate = [0.0f32, 2.0];
/// let up = [5.0f32, 3.0];
/// let mut out = [0.0f32; 2];
/// glu_forward(Activation::ReluSquared, &gate, &up, &mut out)?;
/// assert_eq!(out, [0.0, 12.0]);
/// # Ok::<(), rune_fused::FusedError>(())
/// ```
pub fn glu_forward(
    act: Activation,
    gate: &[f32],
    up: &[f32],
    out: &mut [f32],
) -> Result<(), FusedError> {
    check_len("up", gate.len(), up.len())?;
    check_len("out", gate.len(), out.len())?;
    let tasks: Vec<_> = gate
        .chunks(ELEM_TASK)
        .zip(up.chunks(ELEM_TASK))
        .zip(out.chunks_mut(ELEM_TASK))
        .collect();
    run_tasks(worth_parallel(gate.len()), tasks, |((g, u), out)| {
        glu_slice(act, g, u, out);
    });
    Ok(())
}

/// Backward of [`glu_forward`]: `dgate = dy · up · f'(gate)`,
/// `dup = dy · f(gate)`.
pub fn glu_backward(
    act: Activation,
    dy: &[f32],
    gate: &[f32],
    up: &[f32],
    dgate: &mut [f32],
    dup: &mut [f32],
) -> Result<(), FusedError> {
    let n = gate.len();
    check_len("up", n, up.len())?;
    check_len("dy", n, dy.len())?;
    check_len("dgate", n, dgate.len())?;
    check_len("dup", n, dup.len())?;
    let tasks: Vec<_> = dy
        .chunks(ELEM_TASK)
        .zip(gate.chunks(ELEM_TASK))
        .zip(up.chunks(ELEM_TASK))
        .zip(dgate.chunks_mut(ELEM_TASK).zip(dup.chunks_mut(ELEM_TASK)))
        .collect();
    run_tasks(worth_parallel(n), tasks, |(((dy, g), u), (dg, du))| {
        glu_backward_slice(act, dy, g, u, dg, du);
    });
    Ok(())
}

fn fused_rows(gate_up: &[f32], inter: usize) -> Result<usize, FusedError> {
    if inter == 0 {
        return Err(invalid("inter", "must be positive"));
    }
    rows_of("gate_up", gate_up.len(), mul(inter, 2)?)
}

/// Gated unit on the fused layout: each row of `gate_up: [rows, 2·inter]`
/// holds the gate in its first `inter` values and the up projection in the
/// second; `out: [rows, inter] = f(gate) · up`.
///
/// ```
/// use rune_fused::{glu_forward_fused, Activation};
///
/// let gate_up = [0.0f32, 2.0, 5.0, 3.0]; // one row: gate [0, 2], up [5, 3]
/// let mut out = [0.0f32; 2];
/// glu_forward_fused(Activation::Silu, &gate_up, 2, &mut out)?;
/// assert_eq!(out[0], 0.0);
/// assert!((out[1] - 3.0 * 2.0 / (1.0 + (-2.0f32).exp())).abs() < 1e-6);
/// # Ok::<(), rune_fused::FusedError>(())
/// ```
pub fn glu_forward_fused(
    act: Activation,
    gate_up: &[f32],
    inter: usize,
    out: &mut [f32],
) -> Result<(), FusedError> {
    let rows = fused_rows(gate_up, inter)?;
    check_len("out", mul(rows, inter)?, out.len())?;
    let rpt = rows_per_task(2 * inter);
    let tasks: Vec<_> = gate_up
        .chunks(rpt * 2 * inter)
        .zip(out.chunks_mut(rpt * inter))
        .collect();
    run_tasks(worth_parallel(gate_up.len()), tasks, |(gu, out)| {
        for (gu, out) in gu.chunks_exact(2 * inter).zip(out.chunks_exact_mut(inter)) {
            let (g, u) = gu.split_at(inter);
            glu_slice(act, g, u, out);
        }
    });
    Ok(())
}

/// Backward of [`glu_forward_fused`]: `dgate_up: [rows, 2·inter]` gets
/// `dgate` in the first half of each row and `dup` in the second.
pub fn glu_backward_fused(
    act: Activation,
    dy: &[f32],
    gate_up: &[f32],
    inter: usize,
    dgate_up: &mut [f32],
) -> Result<(), FusedError> {
    let rows = fused_rows(gate_up, inter)?;
    check_len("dy", mul(rows, inter)?, dy.len())?;
    check_len("dgate_up", gate_up.len(), dgate_up.len())?;
    let rpt = rows_per_task(2 * inter);
    let tasks: Vec<_> = dy
        .chunks(rpt * inter)
        .zip(gate_up.chunks(rpt * 2 * inter))
        .zip(dgate_up.chunks_mut(rpt * 2 * inter))
        .collect();
    run_tasks(worth_parallel(gate_up.len()), tasks, |((dy, gu), dgu)| {
        let rows = dy
            .chunks_exact(inter)
            .zip(gu.chunks_exact(2 * inter))
            .zip(dgu.chunks_exact_mut(2 * inter));
        for ((dy, gu), dgu) in rows {
            let (g, u) = gu.split_at(inter);
            let (dg, du) = dgu.split_at_mut(inter);
            glu_backward_slice(act, dy, g, u, dg, du);
        }
    });
    Ok(())
}

fn glu_slice(act: Activation, g: &[f32], u: &[f32], out: &mut [f32]) {
    for ((o, &g), &u) in out.iter_mut().zip(g).zip(u) {
        *o = act.apply(g) * u;
    }
}

fn glu_backward_slice(
    act: Activation,
    dy: &[f32],
    g: &[f32],
    u: &[f32],
    dg: &mut [f32],
    du: &mut [f32],
) {
    let it = dy
        .iter()
        .zip(g)
        .zip(u)
        .zip(dg.iter_mut().zip(du.iter_mut()));
    for (((&d, &g), &u), (dg, du)) in it {
        let (f, df) = act.value_and_derivative(g);
        *dg = d * u * df;
        *du = d * f;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn erf_matches_reference_values() {
        // Values from a correctly rounded erf/erfc.
        let cases = [
            (0.1, 0.112_462_916_018_284_9),
            (0.5, 0.520_499_877_813_046_5),
            (1.0, 0.842_700_792_949_714_9),
            (1.5, 0.966_105_146_475_310_8),
            (1.999, 0.995_301_556_651_370_5),
            (2.0, 0.995_322_265_018_952_7),
            (3.0, 0.999_977_909_503_001_4),
        ];
        for (x, e) in cases {
            assert!((erf(x) - e).abs() < 2e-15, "erf({x}) = {} vs {e}", erf(x));
            assert!((erf(-x) + e).abs() < 2e-15);
        }
        let tails = [
            (2.0, 4.677_734_981_047_266e-3),
            (3.0, 2.209_049_699_858_544e-5),
            (5.0, 1.537_459_794_428_034_8e-12),
            (10.0, 2.088_487_583_762_545e-45),
        ];
        for (x, e) in tails {
            assert!(
                ((erfc(x) - e) / e).abs() < 1e-13,
                "erfc({x}) = {} vs {e}",
                erfc(x)
            );
        }
        assert_eq!(erf(0.0), 0.0);
        assert!(erf(f64::NAN).is_nan());
        assert_eq!(erf(f64::INFINITY), 1.0);
    }

    #[test]
    fn relu_squared_propagates_nan() {
        assert!(Activation::ReluSquared.apply(f32::NAN).is_nan());
        assert_eq!(Activation::ReluSquared.apply(-3.0), 0.0);
    }
}
