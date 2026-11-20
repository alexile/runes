//! Shared test helpers: a small deterministic RNG and f64 linear algebra.

#![allow(
    dead_code,
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation
)]

/// SplitMix64.
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

    /// Uniform in [-1, 1).
    pub fn uniform(&mut self) -> f64 {
        (self.next_u64() >> 11) as f64 / (1u64 << 52) as f64 - 1.0
    }

    /// Approximately standard normal (sum of 12 uniforms).
    pub fn normal(&mut self) -> f64 {
        (0..6).map(|_| self.uniform()).sum::<f64>() / 2.0_f64.sqrt()
    }

    pub fn vec_f32(&mut self, n: usize) -> Vec<f32> {
        (0..n).map(|_| self.normal() as f32).collect()
    }
}

/// Row-major `m × k` times `k × n`.
pub fn matmul(a: &[f64], b: &[f64], m: usize, k: usize, n: usize) -> Vec<f64> {
    let mut c = vec![0.0; m * n];
    for i in 0..m {
        for p in 0..k {
            let aip = a[i * k + p];
            for j in 0..n {
                c[i * n + j] += aip * b[p * n + j];
            }
        }
    }
    c
}

pub fn transpose(a: &[f64], m: usize, n: usize) -> Vec<f64> {
    let mut t = vec![0.0; m * n];
    for i in 0..m {
        for j in 0..n {
            t[j * m + i] = a[i * n + j];
        }
    }
    t
}

/// Eigenvalues of a symmetric `n × n` matrix by cyclic Jacobi rotations.
pub fn sym_eigenvalues(a: &[f64], n: usize) -> Vec<f64> {
    let mut a = a.to_vec();
    for _ in 0..100 {
        let off: f64 = (0..n)
            .flat_map(|i| (0..n).filter(move |&j| j != i).map(move |j| (i, j)))
            .map(|(i, j)| a[i * n + j] * a[i * n + j])
            .sum();
        if off < 1e-22 {
            break;
        }
        for p in 0..n {
            for q in p + 1..n {
                let apq = a[p * n + q];
                if apq.abs() < 1e-300 {
                    continue;
                }
                let theta = (a[q * n + q] - a[p * n + p]) / (2.0 * apq);
                let t = theta.signum() / (theta.abs() + (theta * theta + 1.0).sqrt());
                let t = if theta == 0.0 { 1.0 } else { t };
                let c = 1.0 / (t * t + 1.0).sqrt();
                let s = t * c;
                for k in 0..n {
                    let akp = a[k * n + p];
                    let akq = a[k * n + q];
                    a[k * n + p] = c * akp - s * akq;
                    a[k * n + q] = s * akp + c * akq;
                }
                for k in 0..n {
                    let apk = a[p * n + k];
                    let aqk = a[q * n + k];
                    a[p * n + k] = c * apk - s * aqk;
                    a[q * n + k] = s * apk + c * aqk;
                }
            }
        }
    }
    (0..n).map(|i| a[i * n + i]).collect()
}

/// Singular values of a row-major `m × n` matrix via the eigenvalues of
/// its smaller Gram matrix.
pub fn singular_values(x: &[f64], m: usize, n: usize) -> Vec<f64> {
    let (gram, k) = if m <= n {
        (matmul(x, &transpose(x, m, n), m, n, m), m)
    } else {
        (matmul(&transpose(x, m, n), x, n, m, n), n)
    };
    let mut s: Vec<f64> = sym_eigenvalues(&gram, k)
        .into_iter()
        .map(|l| l.max(0.0).sqrt())
        .collect();
    s.sort_by(f64::total_cmp);
    s
}

/// Largest singular value by power iteration on `XᵀX`.
pub fn max_singular_power(x: &[f64], m: usize, n: usize) -> f64 {
    let xt = transpose(x, m, n);
    let mut v = vec![1.0; n];
    let mut lambda = 0.0;
    for _ in 0..500 {
        let xv = matmul(x, &v, m, n, 1);
        let w = matmul(&xt, &xv, n, m, 1);
        let norm = w.iter().map(|a| a * a).sum::<f64>().sqrt();
        if norm == 0.0 {
            return 0.0;
        }
        lambda = norm / v.iter().map(|a| a * a).sum::<f64>().sqrt();
        v = w.iter().map(|a| a / norm).collect();
    }
    lambda.sqrt()
}

/// A matrix `U diag(s) Vᵀ` with random orthonormal `U` (`m × r`) and `V`
/// (`n × r`), `r = s.len()`, built by Gram–Schmidt.
pub fn with_singular_values(rng: &mut Rng, m: usize, n: usize, s: &[f64]) -> Vec<f64> {
    let r = s.len();
    let orth = |rng: &mut Rng, dim: usize| {
        let mut cols: Vec<Vec<f64>> = Vec::new();
        while cols.len() < r {
            let mut v: Vec<f64> = (0..dim).map(|_| rng.normal()).collect();
            for _ in 0..2 {
                for c in &cols {
                    let d: f64 = v.iter().zip(c).map(|(a, b)| a * b).sum();
                    for (a, b) in v.iter_mut().zip(c) {
                        *a -= d * b;
                    }
                }
            }
            let norm = v.iter().map(|a| a * a).sum::<f64>().sqrt();
            cols.push(v.iter().map(|a| a / norm).collect());
        }
        cols
    };
    let u = orth(rng, m);
    let v = orth(rng, n);
    let mut x = vec![0.0; m * n];
    for k in 0..r {
        for i in 0..m {
            for j in 0..n {
                x[i * n + j] += u[k][i] * s[k] * v[k][j];
            }
        }
    }
    x
}

pub fn to_f32(x: &[f64]) -> Vec<f32> {
    x.iter().map(|&v| v as f32).collect()
}

pub fn to_f64(x: &[f32]) -> Vec<f64> {
    x.iter().map(|&v| f64::from(v)).collect()
}

pub fn bits(x: &[f32]) -> Vec<u32> {
    x.iter().map(|v| v.to_bits()).collect()
}

pub fn assert_close(a: &[f32], b: &[f64], tol: f64, what: &str) {
    assert_eq!(a.len(), b.len(), "{what}: length");
    for (i, (&x, &y)) in a.iter().zip(b).enumerate() {
        let err = (f64::from(x) - y).abs();
        assert!(
            err <= tol * (1.0 + y.abs()),
            "{what}[{i}]: {x} vs reference {y} (err {err:e})"
        );
    }
}
