//! Shared helpers: a seeded generator, closeness checks, finite differences.

#![allow(
    clippy::unwrap_used,
    clippy::doc_markdown,
    clippy::missing_const_for_fn,
    clippy::excessive_precision,
    clippy::too_many_arguments,
    clippy::needless_range_loop,
    clippy::redundant_clone,
    clippy::many_single_char_names,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    dead_code
)]

/// SplitMix64: small, seeded, reproducible.
pub struct Rng(u64);

impl Rng {
    pub fn new(seed: u64) -> Self {
        Self(seed)
    }

    pub fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// Uniform in `[-1, 1)`.
    pub fn unit(&mut self) -> f32 {
        ((self.next_u64() >> 40) as f32 / (1u64 << 24) as f32) * 2.0 - 1.0
    }

    pub fn vec(&mut self, n: usize, scale: f32) -> Vec<f32> {
        (0..n).map(|_| self.unit() * scale).collect()
    }

    pub fn below(&mut self, n: usize) -> usize {
        (self.next_u64() % n as u64) as usize
    }
}

pub fn to64(x: &[f32]) -> Vec<f64> {
    x.iter().map(|&v| f64::from(v)).collect()
}

/// `|a - b| <= atol + rtol · |b|` elementwise, with a useful message.
pub fn assert_close(what: &str, got: &[f32], want: &[f64], atol: f64, rtol: f64) {
    assert_eq!(got.len(), want.len(), "{what}: length");
    for (i, (&g, &w)) in got.iter().zip(want).enumerate() {
        let err = (f64::from(g) - w).abs();
        assert!(
            err <= atol + rtol * w.abs(),
            "{what}[{i}]: got {g}, want {w} (err {err:e})"
        );
    }
}

pub fn dot(a: &[f32], b: &[f32]) -> f64 {
    a.iter()
        .zip(b)
        .map(|(&x, &y)| f64::from(x) * f64::from(y))
        .sum()
}

/// Central finite differences of the scalar `loss` with respect to every
/// element of `x`, compared with `analytic`.
pub fn check_fd<F: FnMut(&[f32]) -> f64>(
    what: &str,
    x: &[f32],
    analytic: &[f32],
    h: f32,
    tol: f64,
    mut loss: F,
) {
    assert_eq!(x.len(), analytic.len(), "{what}: length");
    let mut xp = x.to_vec();
    for i in 0..x.len() {
        let v = x[i];
        xp[i] = v + h;
        let lp = loss(&xp);
        xp[i] = v - h;
        let lm = loss(&xp);
        xp[i] = v;
        let step = f64::from(v + h) - f64::from(v - h);
        let fd = (lp - lm) / step;
        let an = f64::from(analytic[i]);
        assert!(
            (fd - an).abs() <= tol * (1.0 + an.abs()),
            "{what}[{i}]: finite difference {fd}, analytic {an}"
        );
    }
}

/// Runs `f` on rayon pools of several sizes and checks the outputs are
/// bitwise equal.
pub fn same_on_all_pools<T: PartialEq + std::fmt::Debug + Send, F: Fn() -> T + Sync>(f: F) {
    let mut first: Option<T> = None;
    for threads in [1, 2, 3, 8] {
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(threads)
            .build()
            .unwrap();
        let out = pool.install(&f);
        match &first {
            None => first = Some(out),
            Some(f0) => assert!(*f0 == out, "result differs on {threads} threads"),
        }
    }
}

pub fn bits(x: &[f32]) -> Vec<u32> {
    x.iter().map(|v| v.to_bits()).collect()
}
