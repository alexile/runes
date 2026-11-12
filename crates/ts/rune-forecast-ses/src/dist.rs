//! Normal quantiles and a small deterministic random source for simulated
//! prediction intervals.

/// Inverse of the standard normal CDF (Acklam's rational approximation,
/// relative error below 1.2e-9). `p` must lie in `(0, 1)`.
pub fn normal_quantile(p: f64) -> f64 {
    const A: [f64; 6] = [
        -3.969_683_028_665_376e1,
        2.209_460_984_245_205e2,
        -2.759_285_104_469_687e2,
        1.383_577_518_672_69e2,
        -3.066_479_806_614_716e1,
        2.506_628_277_459_239,
    ];
    const B: [f64; 5] = [
        -5.447_609_879_822_406e1,
        1.615_858_368_580_409e2,
        -1.556_989_798_598_866e2,
        6.680_131_188_771_972e1,
        -1.328_068_155_288_572e1,
    ];
    const C: [f64; 6] = [
        -7.784_894_002_430_293e-3,
        -3.223_964_580_411_365e-1,
        -2.400_758_277_161_838,
        -2.549_732_539_343_734,
        4.374_664_141_464_968,
        2.938_163_982_698_783,
    ];
    const D: [f64; 4] = [
        7.784_695_709_041_462e-3,
        3.224_671_290_700_398e-1,
        2.445_134_137_142_996,
        3.754_408_661_907_416,
    ];
    const P_LOW: f64 = 0.024_25;

    let poly = |coef: &[f64], x: f64| coef.iter().fold(0.0_f64, |acc, c| acc.mul_add(x, *c));
    if p < P_LOW {
        let q = (-2.0 * p.ln()).sqrt();
        poly(&C, q) / poly(&[D[0], D[1], D[2], D[3], 1.0], q)
    } else if p <= 1.0 - P_LOW {
        let q = p - 0.5;
        let r = q * q;
        poly(&A, r) * q / poly(&[B[0], B[1], B[2], B[3], B[4], 1.0], r)
    } else {
        let q = (-2.0 * (1.0 - p).ln()).sqrt();
        -poly(&C, q) / poly(&[D[0], D[1], D[2], D[3], 1.0], q)
    }
}

/// `SplitMix64` generator with Box-Muller normals. Seeded with a constant so
/// simulated intervals are reproducible.
pub struct Rng {
    state: u64,
    spare: Option<f64>,
}

impl Rng {
    pub const fn new(seed: u64) -> Self {
        Self {
            state: seed,
            spare: None,
        }
    }

    const fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    /// Uniform draw in the open interval `(0, 1)`.
    #[allow(
        clippy::cast_precision_loss,
        reason = "a 53-bit integer converts to f64 exactly"
    )]
    fn uniform(&mut self) -> f64 {
        ((self.next_u64() >> 11) as f64 + 0.5) / (1u64 << 53) as f64
    }

    /// Standard normal draw.
    pub fn normal(&mut self) -> f64 {
        if let Some(z) = self.spare.take() {
            return z;
        }
        let r = (-2.0 * self.uniform().ln()).sqrt();
        let theta = core::f64::consts::TAU * self.uniform();
        self.spare = Some(r * theta.sin());
        r * theta.cos()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_quantiles() {
        assert!((normal_quantile(0.975) - 1.959_963_985).abs() < 1e-8);
        assert!((normal_quantile(0.9) - 1.281_551_566).abs() < 1e-8);
        assert!(normal_quantile(0.5).abs() < 1e-12);
        assert!((normal_quantile(0.001) + 3.090_232_306).abs() < 1e-7);
    }

    #[test]
    fn normals_have_unit_variance() {
        let mut rng = Rng::new(7);
        let draws: Vec<f64> = (0..20_000).map(|_| rng.normal()).collect();
        let mean = draws.iter().sum::<f64>() / 20_000.0;
        let var = draws.iter().map(|z| (z - mean).powi(2)).sum::<f64>() / 20_000.0;
        assert!(
            mean.abs() < 0.03 && (var - 1.0).abs() < 0.05,
            "{mean} {var}"
        );
    }
}
