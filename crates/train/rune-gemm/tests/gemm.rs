//! Every entry point against a naive triple loop.

#![allow(
    clippy::unwrap_used,
    clippy::use_self,
    clippy::missing_const_for_fn,
    clippy::suboptimal_flops,
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_lossless,
    clippy::too_many_arguments,
    clippy::many_single_char_names
)]

use proptest::prelude::*;
use rune_gemm::{
    BatchMut, BatchRef, Element, Gemm, GemmError, Isa, MatMut, MatRef, Transpose, dgemm, gemm,
    gemm_batched, gemm_grouped, sgemm,
};

trait Num: Element {
    const EPS: f64;
    fn from_f64(x: f64) -> Self;
    fn to_f64(self) -> f64;
}

impl Num for f32 {
    const EPS: f64 = f32::EPSILON as f64;
    fn from_f64(x: f64) -> Self {
        x as Self
    }
    fn to_f64(self) -> f64 {
        f64::from(self)
    }
}

impl Num for f64 {
    const EPS: f64 = f64::EPSILON;
    fn from_f64(x: f64) -> Self {
        x
    }
    fn to_f64(self) -> f64 {
        self
    }
}

/// Deterministic values in [-1, 1).
fn fill<T: Num>(len: usize, seed: u64) -> Vec<T> {
    let mut s = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
    (0..len)
        .map(|_| {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            T::from_f64((s >> 11) as f64 / (1u64 << 52) as f64 - 1.0)
        })
        .collect()
}

/// How an `r × c` matrix is laid out in memory.
#[derive(Debug, Clone, Copy, PartialEq)]
enum Layout {
    Row,
    Col,
    /// Row-major with this much padding per row.
    Padded(usize),
    /// Neither stride is 1.
    Strided,
}

impl Layout {
    /// `(row_stride, col_stride, len)`.
    fn strides(self, r: usize, c: usize) -> (usize, usize, usize) {
        let (rs, cs) = match self {
            Self::Row => (c, 1),
            Self::Col => (1, r),
            Self::Padded(p) => (c + p, 1),
            Self::Strided => (2 * c + 1, 2),
        };
        let len = if r == 0 || c == 0 {
            0
        } else {
            (r - 1) * rs + (c - 1) * cs + 1
        };
        (rs, cs, len)
    }
}

/// A stored operand: `op` shape `r × c`, stored transposed when `trans`.
struct Operand<T> {
    data: Vec<T>,
    r: usize,
    c: usize,
    rs: usize,
    cs: usize,
    trans: bool,
}

impl<T: Num> Operand<T> {
    fn new(r: usize, c: usize, layout: Layout, trans: bool, seed: u64) -> Self {
        let (sr, sc) = if trans { (c, r) } else { (r, c) };
        let (rs, cs, len) = layout.strides(sr, sc);
        Self {
            data: fill(len, seed),
            r,
            c,
            rs,
            cs,
            trans,
        }
    }

    fn view(&self) -> MatRef<'_, T> {
        let (sr, sc) = if self.trans {
            (self.c, self.r)
        } else {
            (self.r, self.c)
        };
        let v = MatRef::new(&self.data, sr, sc, self.rs, self.cs).unwrap();
        if self.trans { v.t() } else { v }
    }

    fn at(&self, i: usize, j: usize) -> f64 {
        let (i, j) = if self.trans { (j, i) } else { (i, j) };
        self.data[i * self.rs + j * self.cs].to_f64()
    }
}

/// Expected C and a per-element error bound.
fn reference<T: Num>(
    alpha: f64,
    a: &Operand<T>,
    b: &Operand<T>,
    beta: f64,
    c0: impl Fn(usize, usize) -> f64,
) -> Vec<(f64, f64)> {
    let (m, k, n) = (a.r, a.c, b.c);
    let mut out = Vec::with_capacity(m * n);
    for i in 0..m {
        for j in 0..n {
            let (mut s, mut mag) = (0.0, 0.0);
            for p in 0..k {
                let x = a.at(i, p) * b.at(p, j);
                s += x;
                mag += x.abs();
            }
            let (cv, cmag) = if beta == 0.0 {
                (0.0, 0.0)
            } else {
                (beta * c0(i, j), (beta * c0(i, j)).abs())
            };
            let tol = (k as f64 + 4.0) * 2.0 * T::EPS * (alpha.abs() * mag + cmag) + 1e-30;
            out.push((alpha * s + cv, tol));
        }
    }
    out
}

#[allow(clippy::too_many_arguments)]
fn check_case<T: Num>(
    cfg: Gemm,
    m: usize,
    n: usize,
    k: usize,
    (ta, tb): (bool, bool),
    (la, lb, lc): (Layout, Layout, Layout),
    alpha: f64,
    beta: f64,
) {
    let a = Operand::<T>::new(m, k, la, ta, 1 + (m * 31 + k) as u64);
    let b = Operand::<T>::new(k, n, lb, tb, 7 + (n * 17 + k) as u64);
    let (rs, cs, len) = lc.strides(m, n);
    let mut c: Vec<T> = fill(len, 99);
    let c0 = c.clone();
    let want = reference(alpha, &a, &b, beta, |i, j| c0[i * rs + j * cs].to_f64());
    cfg.gemm(
        T::from_f64(alpha),
        a.view(),
        b.view(),
        T::from_f64(beta),
        MatMut::new(&mut c, m, n, rs, cs).unwrap(),
    )
    .unwrap();
    for i in 0..m {
        for j in 0..n {
            let got = c[i * rs + j * cs].to_f64();
            let (w, tol) = want[i * n + j];
            assert!(
                (got - w).abs() <= tol,
                "m={m} n={n} k={k} ta={ta} tb={tb} {la:?}/{lb:?}/{lc:?} a={alpha} b={beta} \
                 at ({i},{j}): got {got}, want {w} (tol {tol}) on {:?}",
                cfg.kernel()
            );
        }
    }
    // Elements of C outside the view are untouched.
    let mut inside = vec![false; len];
    for i in 0..m {
        for j in 0..n {
            inside[i * rs + j * cs] = true;
        }
    }
    for (idx, &is_in) in inside.iter().enumerate() {
        if !is_in {
            assert_eq!(c[idx].to_f64().to_bits(), c0[idx].to_f64().to_bits());
        }
    }
}

const TRANS: [(bool, bool); 4] = [(false, false), (false, true), (true, false), (true, true)];

fn configs() -> Vec<Gemm> {
    let mut v = vec![
        Gemm::new(),
        Gemm::new().parallel(false),
        Gemm::new().isa(Isa::Scalar),
    ];
    v.dedup();
    v
}

#[test]
fn shape_sweep_f32() {
    for cfg in configs() {
        for &m in &[1, 5, 6, 7, 13] {
            for &n in &[1, 15, 16, 17, 33] {
                for &k in &[0, 1, 7, 31] {
                    for t in TRANS {
                        check_case::<f32>(
                            cfg,
                            m,
                            n,
                            k,
                            t,
                            (Layout::Row, Layout::Row, Layout::Row),
                            1.0,
                            0.0,
                        );
                    }
                }
            }
        }
    }
}

#[test]
fn shape_sweep_f64() {
    for cfg in configs() {
        for &m in &[1, 6, 7, 11] {
            for &n in &[1, 7, 8, 9, 23] {
                for &k in &[0, 1, 5, 19] {
                    for t in TRANS {
                        check_case::<f64>(
                            cfg,
                            m,
                            n,
                            k,
                            t,
                            (Layout::Row, Layout::Col, Layout::Row),
                            0.5,
                            -1.5,
                        );
                    }
                }
            }
        }
    }
}

#[test]
fn every_layout_and_transpose() {
    let layouts = [Layout::Row, Layout::Col, Layout::Padded(3), Layout::Strided];
    for la in layouts {
        for lb in layouts {
            for lc in layouts {
                for t in TRANS {
                    check_case::<f32>(Gemm::new(), 9, 19, 11, t, (la, lb, lc), 1.25, 0.75);
                    check_case::<f64>(Gemm::new(), 7, 10, 5, t, (la, lb, lc), -1.0, 1.0);
                }
            }
        }
    }
}

#[test]
fn primes_and_one_by_one() {
    for &(m, n, k) in &[
        (1, 1, 1),
        (2, 3, 5),
        (7, 11, 13),
        (17, 19, 23),
        (31, 37, 41),
    ] {
        for t in TRANS {
            let l = (Layout::Row, Layout::Row, Layout::Col);
            check_case::<f32>(Gemm::new(), m, n, k, t, l, 1.0, 1.0);
            check_case::<f64>(Gemm::new(), m, n, k, t, l, 2.0, 0.0);
        }
    }
}

#[test]
fn crosses_every_cache_block() {
    // f32: MC = 144, KC = 256, NC = 4080; f64: MC = 72.
    let l = (Layout::Row, Layout::Row, Layout::Row);
    for cfg in configs() {
        check_case::<f32>(cfg, 150, 37, 300, (false, false), l, 1.0, 0.5);
        check_case::<f32>(cfg, 151, 40, 520, (true, true), l, -0.5, 0.0);
        check_case::<f64>(cfg, 80, 20, 270, (false, true), l, 1.0, 1.0);
    }
    check_case::<f32>(Gemm::new(), 7, 4100, 3, (false, false), l, 1.0, 0.0);
    check_case::<f64>(Gemm::new(), 3, 4090, 260, (true, false), l, 1.0, 2.0);
}

#[test]
fn beta_zero_overwrites_nan_and_alpha_zero_skips_inputs() {
    let a = [f32::NAN; 6];
    let b = [1.0f32; 6];
    let mut c = [f32::NAN; 4];
    let av = MatRef::row_major(&[1.0f32; 6], 2, 3).unwrap();
    let bv = MatRef::row_major(&b, 3, 2).unwrap();
    gemm(1.0, av, bv, 0.0, MatMut::row_major(&mut c, 2, 2).unwrap()).unwrap();
    assert_eq!(c, [3.0; 4]);

    // alpha = 0: A is not read (NaN does not propagate), C = beta * C.
    let nan_a = MatRef::row_major(&a, 2, 3).unwrap();
    let mut c = [1.0f32, 2.0, 3.0, 4.0];
    gemm(
        0.0,
        nan_a,
        bv,
        2.0,
        MatMut::row_major(&mut c, 2, 2).unwrap(),
    )
    .unwrap();
    assert_eq!(c, [2.0, 4.0, 6.0, 8.0]);

    // alpha = 0 and beta = 0: zeros, even over NaN.
    let mut c = [f32::NAN; 4];
    gemm(
        0.0,
        nan_a,
        bv,
        0.0,
        MatMut::row_major(&mut c, 2, 2).unwrap(),
    )
    .unwrap();
    assert_eq!(c, [0.0; 4]);

    // k = 0, beta = 1: untouched.
    let mut c = [5.0f64, f64::NAN];
    let e: [f64; 0] = [];
    gemm(
        3.0,
        MatRef::row_major(&e, 1, 0).unwrap(),
        MatRef::row_major(&e, 0, 2).unwrap(),
        1.0,
        MatMut::row_major(&mut c, 1, 2).unwrap(),
    )
    .unwrap();
    assert_eq!(c[0], 5.0);
    assert!(c[1].is_nan());

    // m = 0 / n = 0: nothing to do.
    let mut none: [f32; 0] = [];
    gemm(
        1.0,
        MatRef::row_major(&[] as &[f32], 0, 4).unwrap(),
        MatRef::row_major(&[0.0f32; 12], 4, 3).unwrap(),
        0.0,
        MatMut::row_major(&mut none, 0, 3).unwrap(),
    )
    .unwrap();
}

#[test]
fn simd_matches_scalar() {
    let simd = Gemm::new();
    let scalar = Gemm::new().isa(Isa::Scalar);
    let (m, n, k) = (67, 45, 300);
    let a: Vec<f32> = fill(m * k, 3);
    let b: Vec<f32> = fill(k * n, 4);
    let mut c1 = vec![0.0f32; m * n];
    let mut c2 = vec![0.0f32; m * n];
    for (cfg, c) in [(simd, &mut c1), (scalar, &mut c2)] {
        cfg.gemm(
            1.0,
            MatRef::row_major(&a, m, k).unwrap(),
            MatRef::row_major(&b, k, n).unwrap(),
            0.0,
            MatMut::row_major(c, m, n).unwrap(),
        )
        .unwrap();
    }
    let max = c1
        .iter()
        .zip(&c2)
        .map(|(x, y)| (x - y).abs())
        .fold(0.0f32, f32::max);
    assert!(max < 1e-4, "simd vs scalar differ by {max}");

    let a: Vec<f64> = fill(m * k, 5);
    let b: Vec<f64> = fill(k * n, 6);
    let mut d1 = vec![0.0f64; m * n];
    let mut d2 = vec![0.0f64; m * n];
    for (cfg, c) in [(simd, &mut d1), (scalar, &mut d2)] {
        cfg.gemm(
            1.0,
            MatRef::row_major(&a, m, k).unwrap(),
            MatRef::col_major(&b, k, n).unwrap(),
            0.0,
            MatMut::row_major(c, m, n).unwrap(),
        )
        .unwrap();
    }
    let max = d1
        .iter()
        .zip(&d2)
        .map(|(x, y)| (x - y).abs())
        .fold(0.0f64, f64::max);
    assert!(max < 1e-12, "simd vs scalar differ by {max}");
}

#[test]
fn bitwise_identical_across_thread_counts() {
    let (m, n, k) = (301, 263, 290);
    let a: Vec<f32> = fill(m * k, 11);
    let b: Vec<f32> = fill(k * n, 12);
    let c0: Vec<f32> = fill(m * n, 13);
    let run = |cfg: Gemm| {
        let mut c = c0.clone();
        cfg.gemm(
            0.7,
            MatRef::row_major(&a, m, k).unwrap(),
            MatRef::row_major(&b, k, n).unwrap().t().t(),
            0.3,
            MatMut::row_major(&mut c, m, n).unwrap(),
        )
        .unwrap();
        c
    };
    let serial = run(Gemm::new().parallel(false));
    for threads in [1, 2, 3, 7] {
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(threads)
            .build()
            .unwrap();
        let par = pool.install(|| run(Gemm::new()));
        assert!(
            serial
                .iter()
                .zip(&par)
                .all(|(x, y)| x.to_bits() == y.to_bits()),
            "{threads} threads differ from serial"
        );
    }
}

#[test]
fn batched_dense_interleaved_and_broadcast() {
    let (batch, m, n, k) = (5, 9, 13, 7);
    let a: Vec<f32> = fill(batch * m * k, 21);
    let w: Vec<f32> = fill(k * n, 22); // one B shared by every entry
    // C laid out [m, batch, n] (heads interleaved).
    let mut c = vec![f32::NAN; m * batch * n];
    gemm_batched(
        1.0,
        BatchRef::row_major(&a, batch, m, k).unwrap(),
        BatchRef::new(&w, batch, k, n, n, 1, 0).unwrap(),
        0.0,
        BatchMut::new(&mut c, batch, m, n, batch * n, 1, n).unwrap(),
    )
    .unwrap();
    for bi in 0..batch {
        for i in 0..m {
            for j in 0..n {
                let want: f32 = (0..k)
                    .map(|p| a[bi * m * k + i * k + p] * w[p * n + j])
                    .sum();
                let got = c[i * batch * n + bi * n + j];
                assert!((got - want).abs() < 1e-5, "{bi} {i} {j}: {got} vs {want}");
            }
        }
    }

    // Transposed operands and a column-major output batch.
    let bt: Vec<f64> = fill(batch * n * k, 23);
    let a64: Vec<f64> = fill(batch * m * k, 24);
    let mut c = vec![1.0f64; batch * m * n];
    Gemm::new()
        .parallel(false)
        .gemm_batched(
            2.0,
            BatchRef::row_major(&a64, batch, m, k).unwrap(),
            BatchRef::row_major(&bt, batch, n, k).unwrap().t(),
            -1.0,
            BatchMut::new(&mut c, batch, m, n, 1, m, m * n).unwrap(),
        )
        .unwrap();
    for bi in 0..batch {
        for i in 0..m {
            for j in 0..n {
                let s: f64 = (0..k)
                    .map(|p| a64[bi * m * k + i * k + p] * bt[bi * n * k + j * k + p])
                    .sum();
                let got = c[bi * m * n + j * m + i];
                assert!((got - (2.0 * s - 1.0)).abs() < 1e-12);
            }
        }
    }
}

fn grouped_case(c_col_major: bool, cfg: Gemm) {
    let groups = [0usize, 5, 1, 0, 17, 3, 160];
    let total: usize = groups.iter().sum();
    let (k, n) = (12, 21);
    let a: Vec<f32> = fill(total * k, 31);
    let b: Vec<f32> = fill(groups.len() * k * n, 32);
    let c0: Vec<f32> = fill(total * n, 33);
    let mut c = c0.clone();
    let (rs, cs) = if c_col_major { (1, total) } else { (n, 1) };
    cfg.gemm_grouped(
        1.0,
        MatRef::row_major(&a, total, k).unwrap(),
        &groups,
        BatchRef::row_major(&b, groups.len(), k, n).unwrap(),
        0.5,
        MatMut::new(&mut c, total, n, rs, cs).unwrap(),
    )
    .unwrap();
    let mut r0 = 0;
    for (g, &mg) in groups.iter().enumerate() {
        for i in r0..r0 + mg {
            for j in 0..n {
                let s: f32 = (0..k)
                    .map(|p| a[i * k + p] * b[g * k * n + p * n + j])
                    .sum();
                let want = s + 0.5 * c0[i * rs + j * cs];
                let got = c[i * rs + j * cs];
                assert!((got - want).abs() < 1e-5, "group {g} row {i} col {j}");
            }
        }
        r0 += mg;
    }
}

#[test]
fn grouped_ragged_groups() {
    for cfg in configs() {
        grouped_case(false, cfg);
        grouped_case(true, cfg);
    }
}

#[test]
fn blas_style_calls() {
    let (m, n, k) = (5, 4, 3);
    for (ta, tb) in TRANS {
        let flag = |t| if t { Transpose::Yes } else { Transpose::No };
        let a = Operand::<f32>::new(m, k, Layout::Padded(2), ta, 41);
        let b = Operand::<f32>::new(k, n, Layout::Padded(1), tb, 42);
        let mut c = vec![f32::NAN; m * 6];
        let want = reference(1.5, &a, &b, 0.0, |_, _| 0.0);
        sgemm(
            flag(ta),
            flag(tb),
            m,
            n,
            k,
            1.5,
            &a.data,
            a.rs,
            &b.data,
            b.rs,
            0.0,
            &mut c,
            6,
        )
        .unwrap();
        for i in 0..m {
            for j in 0..n {
                let (w, tol) = want[i * n + j];
                assert!((f64::from(c[i * 6 + j]) - w).abs() <= tol);
            }
        }
    }
    let mut c = [0.0f64; 4];
    dgemm(
        Transpose::No,
        Transpose::Yes,
        2,
        2,
        1,
        1.0,
        &[1.0, 2.0],
        1,
        &[3.0, 4.0],
        1,
        0.0,
        &mut c,
        2,
    )
    .unwrap();
    assert_eq!(c, [3.0, 4.0, 6.0, 8.0]);
    assert!(matches!(
        sgemm(
            Transpose::No,
            Transpose::No,
            2,
            2,
            3,
            1.0,
            &[0.0; 6],
            2,
            &[0.0; 6],
            2,
            0.0,
            &mut [0.0; 4],
            2
        ),
        Err(GemmError::LeadingDimension { what: "lda", .. })
    ));
}

#[test]
fn errors_leave_c_untouched() {
    let a = [1.0f32; 6];
    let mut c = [7.0f32; 4];
    let r = gemm(
        1.0,
        MatRef::row_major(&a, 2, 3).unwrap(),
        MatRef::row_major(&a, 2, 3).unwrap(),
        0.0,
        MatMut::row_major(&mut c, 2, 2).unwrap(),
    );
    assert!(matches!(
        r,
        Err(GemmError::DimensionMismatch {
            what: "rows of B",
            ..
        })
    ));
    assert_eq!(c, [7.0; 4]);
    assert!(matches!(
        MatRef::row_major(&a, 3, 3),
        Err(GemmError::OutOfBounds { needed: 9, len: 6 })
    ));
    assert!(matches!(
        MatMut::new(&mut c, 2, 2, 1, 1),
        Err(GemmError::Overlapping { .. })
    ));
    let b = BatchRef::row_major(&a, 2, 1, 3).unwrap();
    let w = BatchRef::row_major(&a, 2, 3, 1).unwrap();
    let r = gemm_batched(
        1.0,
        b,
        w,
        0.0,
        BatchMut::row_major(&mut c, 3, 1, 1).unwrap(),
    );
    assert!(matches!(r, Err(GemmError::DimensionMismatch { .. })));
    let r = gemm_grouped(
        1.0,
        MatRef::row_major(&a, 2, 3).unwrap(),
        &[1, 2],
        w,
        0.0,
        MatMut::row_major(&mut c, 2, 2).unwrap(),
    );
    assert!(matches!(
        r,
        Err(GemmError::DimensionMismatch {
            what: "sum of group rows",
            ..
        })
    ));
    assert_eq!(c, [7.0; 4]);
}

fn layout() -> impl Strategy<Value = Layout> {
    prop_oneof![
        Just(Layout::Row),
        Just(Layout::Col),
        (1usize..4).prop_map(Layout::Padded),
        Just(Layout::Strided),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(96))]

    #[test]
    fn matches_naive(
        m in 0usize..40, n in 0usize..40, k in 0usize..40,
        ta: bool, tb: bool,
        la in layout(), lb in layout(), lc in layout(),
        alpha in prop_oneof![Just(0.0), Just(1.0), -2.0f64..2.0],
        beta in prop_oneof![Just(0.0), Just(1.0), -2.0f64..2.0],
        scalar: bool, parallel: bool,
    ) {
        let cfg = Gemm::new().parallel(parallel);
        let cfg = if scalar { cfg.isa(Isa::Scalar) } else { cfg };
        check_case::<f32>(cfg, m, n, k, (ta, tb), (la, lb, lc), alpha, beta);
        check_case::<f64>(cfg, n, m, k, (tb, ta), (lb, la, lc), alpha, beta);
    }
}
