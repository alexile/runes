//! Rough throughput check: `cargo run --release -p rune-gemm --example gflops [n]`.
#![allow(
    clippy::print_stdout,
    clippy::cast_precision_loss,
    clippy::many_single_char_names
)]

use std::time::Instant;

use rune_gemm::{Gemm, GemmError, Isa, MatMut, MatRef};

fn bench<T: rune_gemm::Element>(label: &str, cfg: Gemm, n: usize, x: T) -> Result<(), GemmError> {
    let a = vec![x; n * n];
    let b = vec![x; n * n];
    let mut c = vec![x; n * n];
    let mut run = || {
        cfg.gemm(
            T::ONE,
            MatRef::row_major(&a, n, n)?,
            MatRef::row_major(&b, n, n)?,
            T::ZERO,
            MatMut::row_major(&mut c, n, n)?,
        )
    };
    run()?; // warm up caches and the thread pool
    let reps = 10;
    let t = Instant::now();
    for _ in 0..reps {
        run()?;
    }
    let secs = t.elapsed().as_secs_f64() / f64::from(reps);
    let gflops = 2.0 * (n as f64).powi(3) / secs / 1e9;
    println!(
        "{label:<28} {n}^3  {:>8.3} ms  {gflops:>7.1} GFLOP/s",
        secs * 1e3
    );
    Ok(())
}

fn main() -> Result<(), GemmError> {
    let n = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(512);
    let simd = Gemm::new();
    let scalar = Gemm::new().isa(Isa::Scalar);
    println!(
        "kernel: {}, threads: {}",
        simd.kernel().name(),
        rayon::current_num_threads()
    );
    bench("f32 1 thread", simd.parallel(false), n, 0.5f32)?;
    bench("f32 all threads", simd, n, 0.5f32)?;
    bench("f32 portable, 1 thread", scalar.parallel(false), n, 0.5f32)?;
    bench("f64 1 thread", simd.parallel(false), n, 0.5f64)?;
    bench("f64 all threads", simd, n, 0.5f64)?;
    Ok(())
}
