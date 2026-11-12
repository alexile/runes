/// Xorshift64 PRNG — deterministic, no external dependencies.
pub struct Rng(u64);

impl Rng {
    pub(crate) const fn new(seed: u64) -> Self {
        let seed = if seed == 0 {
            0x6c62_272e_07bb_0142
        } else {
            seed
        };
        Self(seed)
    }

    const fn next_u64(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    #[allow(
        clippy::cast_precision_loss,
        reason = "counts and indices stay far below 2^52, so the f64 conversion is exact"
    )]
    pub(crate) fn next_f64(&mut self) -> f64 {
        (self.next_u64() >> 11) as f64 / (1u64 << 53) as f64
    }

    /// Draws a standard-normal sample via Box-Muller transform.
    pub(crate) fn next_gaussian(&mut self) -> f64 {
        let u1 = self.next_f64().max(1e-300);
        let u2 = self.next_f64();
        (-2.0 * u1.ln()).sqrt() * (2.0 * std::f64::consts::PI * u2).cos()
    }
}

#[cfg(test)]
mod tests {
    use super::Rng;

    #[test]
    fn seed_zero_is_remapped_away_from_the_fixed_point() {
        let mut zero = Rng::new(0);
        assert_ne!(zero.next_u64(), 0);
    }

    #[test]
    fn uniform_samples_lie_in_the_unit_interval() {
        let mut rng = Rng::new(7);
        assert!(
            (0..10_000)
                .map(|_| rng.next_f64())
                .all(|u| (0.0..1.0).contains(&u))
        );
    }

    #[test]
    fn gaussian_samples_have_unit_moments() {
        let mut rng = Rng::new(42);
        let xs: Vec<f64> = (0..20_000).map(|_| rng.next_gaussian()).collect();
        let nf = 20_000.0;
        let mean = xs.iter().sum::<f64>() / nf;
        let var = xs.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / nf;
        assert!(mean.abs() < 0.03, "mean {mean}");
        assert!((var - 1.0).abs() < 0.05, "variance {var}");
        assert!(xs.iter().all(|x| x.is_finite()));
    }
}
