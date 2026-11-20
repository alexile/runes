//! AVX2 + FMA micro-kernels: 6 × 16 for `f32`, 6 × 8 for `f64`.
//!
//! Each kernel keeps the tile in 12 YMM accumulators, loads two B vectors
//! and broadcasts six A values per step: 12 FMAs per 8 loads.

#[cfg(target_arch = "x86_64")]
mod imp {
    use core::arch::x86_64::{
        __m256, __m256d, _mm256_broadcast_sd, _mm256_broadcast_ss, _mm256_fmadd_pd,
        _mm256_fmadd_ps, _mm256_loadu_pd, _mm256_loadu_ps, _mm256_setzero_pd, _mm256_setzero_ps,
        _mm256_storeu_pd, _mm256_storeu_ps,
    };

    pub fn available() -> bool {
        std::is_x86_feature_detected!("avx2") && std::is_x86_feature_detected!("fma")
    }

    macro_rules! avx2_kernel {
        ($name:ident, $inner:ident, $t:ty, $vec:ty, $nr:literal, $lanes:literal,
         $zero:ident, $load:ident, $bcast:ident, $fma:ident, $store:ident) => {
            #[allow(unsafe_code, clippy::needless_range_loop)]
            #[target_feature(enable = "avx2,fma")]
            fn $inner(kc: usize, a: &[$t], b: &[$t], acc: &mut [$t]) {
                const MR: usize = 6;
                const V: usize = $nr / $lanes;
                let mut c: [[$vec; V]; MR] = [[$zero(); V]; MR];
                for (ak, bk) in a
                    .as_chunks::<MR>()
                    .0
                    .iter()
                    .zip(b.as_chunks::<$nr>().0)
                    .take(kc)
                {
                    let mut bv: [$vec; V] = [$zero(); V];
                    for v in 0..V {
                        // SAFETY: `bk` holds exactly NR = V * lanes elements, so
                        // the unaligned load of `lanes` values at `v * lanes` is in
                        // bounds.
                        bv[v] = unsafe { $load(bk.as_ptr().add(v * $lanes)) };
                    }
                    for i in 0..MR {
                        let ai = $bcast(&ak[i]);
                        for v in 0..V {
                            c[i][v] = $fma(ai, bv[v], c[i][v]);
                        }
                    }
                }
                for (row, ci) in acc.chunks_exact_mut($nr).zip(&c) {
                    for v in 0..V {
                        // SAFETY: `row` holds exactly NR = V * lanes elements.
                        unsafe { $store(row.as_mut_ptr().add(v * $lanes), ci[v]) };
                    }
                }
            }

            pub fn $name(kc: usize, a: &[$t], b: &[$t], acc: &mut [$t]) -> bool {
                if !available() || a.len() < kc * 6 || b.len() < kc * $nr || acc.len() < 6 * $nr {
                    return false;
                }
                #[allow(unsafe_code)]
                // SAFETY: AVX2 and FMA were detected on this CPU just above.
                unsafe {
                    $inner(kc, a, b, acc);
                }
                true
            }
        };
    }

    avx2_kernel!(
        f32_6x16,
        f32_6x16_avx2,
        f32,
        __m256,
        16,
        8,
        _mm256_setzero_ps,
        _mm256_loadu_ps,
        _mm256_broadcast_ss,
        _mm256_fmadd_ps,
        _mm256_storeu_ps
    );
    avx2_kernel!(
        f64_6x8,
        f64_6x8_avx2,
        f64,
        __m256d,
        8,
        4,
        _mm256_setzero_pd,
        _mm256_loadu_pd,
        _mm256_broadcast_sd,
        _mm256_fmadd_pd,
        _mm256_storeu_pd
    );
}

#[cfg(not(target_arch = "x86_64"))]
mod imp {
    pub const fn available() -> bool {
        false
    }
    pub const fn f32_6x16(_: usize, _: &[f32], _: &[f32], _: &mut [f32]) -> bool {
        false
    }
    pub const fn f64_6x8(_: usize, _: &[f64], _: &[f64], _: &mut [f64]) -> bool {
        false
    }
}

pub use imp::{available, f32_6x16, f64_6x8};
