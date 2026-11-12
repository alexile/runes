//! Micro-benchmarks: unrolled kernels vs naive loops, and `pairwise`.
//!
//! Dependency-free (no criterion): `cargo bench -p rune-ml-core`, optionally
//! `--features rayon`. Reports the best of several runs in ns per call.

#![allow(clippy::print_stdout, reason = "a benchmark reports to stdout")]

use std::hint::black_box;
use std::time::{Duration, Instant};

use rune_ml_core::{Float, Matrix, Metric, Rng, kernels};

fn best_of<T>(runs: usize, iters: u32, mut f: impl FnMut() -> T) -> Duration {
    let mut best = Duration::MAX;
    for _ in 0..runs {
        let start = Instant::now();
        for _ in 0..iters {
            black_box(f());
        }
        best = best.min(start.elapsed() / iters);
    }
    best
}

fn naive_sq<F: Float>(a: &[F], b: &[F]) -> F {
    a.iter()
        .zip(b)
        .fold(F::ZERO, |s, (&x, &y)| s + (x - y) * (x - y))
}

fn naive_l1<F: Float>(a: &[F], b: &[F]) -> F {
    a.iter()
        .zip(b)
        .fold(F::ZERO, |s, (&x, &y)| s + (x - y).abs())
}

fn vectors<F: Float>(rng: &mut Rng, d: usize) -> (Vec<F>, Vec<F>) {
    (
        (0..d).map(|_| rng.uniform()).collect(),
        (0..d).map(|_| rng.uniform()).collect(),
    )
}

fn kernel_suite<F: Float>(label: &str, rng: &mut Rng) {
    for d in [16, 128, 1024] {
        let (a, b) = vectors::<F>(rng, d);
        let iters = 200_000 / u32::try_from(d).unwrap_or(1) + 100;
        let naive = best_of(5, iters, || naive_sq(black_box(&a), black_box(&b)));
        let fast = best_of(5, iters, || {
            kernels::sq_euclidean(black_box(&a), black_box(&b))
        });
        let naive1 = best_of(5, iters, || naive_l1(black_box(&a), black_box(&b)));
        let fast1 = best_of(5, iters, || {
            kernels::manhattan(black_box(&a), black_box(&b))
        });
        let cos = best_of(5, iters, || kernels::cosine(black_box(&a), black_box(&b)));
        println!(
            "{label} d={d:5}  sq_euclid naive {naive:>9.1?} unrolled {fast:>9.1?} | \
             manhattan naive {naive1:>9.1?} unrolled {fast1:>9.1?} | cosine {cos:>9.1?}"
        );
    }
}

fn main() {
    let mut rng = Rng::new(0xbe9c);
    kernel_suite::<f32>("f32", &mut rng);
    kernel_suite::<f64>("f64", &mut rng);

    let (n, d) = (1_000, 32);
    let Ok(x) = Matrix::<f64>::from_fn(n, d, |_, _| rng.normal()) else {
        return;
    };
    for metric in Metric::ALL {
        let t = best_of(3, 1, || metric.pairwise(black_box(x.view())));
        println!("pairwise {metric:<11} n={n} d={d}: {t:>9.2?}");
    }
}
