//! `AArch64` NEON micro-kernels: 6 × 16 for `f32`, 6 × 8 for `f64`.
//!
//! Each kernel keeps the tile in 24 of the 32 vector registers.

#[cfg(target_arch = "aarch64")]
mod imp {
    use core::arch::aarch64::{
        float32x4_t, float64x2_t, vdupq_n_f32, vdupq_n_f64, vfmaq_f32, vfmaq_f64, vld1q_f32,
        vld1q_f64, vst1q_f32, vst1q_f64,
    };

    pub fn available() -> bool {
        std::arch::is_aarch64_feature_detected!("neon")
    }

    macro_rules! neon_kernel {
        ($name:ident, $inner:ident, $t:ty, $vec:ty, $nr:literal, $lanes:literal,
         $dup:ident, $load:ident, $fma:ident, $store:ident) => {
            #[allow(unsafe_code, clippy::needless_range_loop)]
            #[target_feature(enable = "neon")]
            fn $inner(kc: usize, a: &[$t], b: &[$t], acc: &mut [$t]) {
                const MR: usize = 6;
                const V: usize = $nr / $lanes;
                let mut c: [[$vec; V]; MR] = [[$dup(0.0); V]; MR];
                for (ak, bk) in a
                    .as_chunks::<MR>()
                    .0
                    .iter()
                    .zip(b.as_chunks::<$nr>().0)
                    .take(kc)
                {
                    let mut bv: [$vec; V] = [$dup(0.0); V];
                    for v in 0..V {
                        // SAFETY: `bk` holds exactly NR = V * lanes elements, so
                        // the load of `lanes` values at `v * lanes` is in bounds.
                        bv[v] = unsafe { $load(bk.as_ptr().add(v * $lanes)) };
                    }
                    for i in 0..MR {
                        let ai = $dup(ak[i]);
                        for v in 0..V {
                            c[i][v] = $fma(c[i][v], bv[v], ai);
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
                // SAFETY: NEON was detected on this CPU just above.
                unsafe {
                    $inner(kc, a, b, acc);
                }
                true
            }
        };
    }

    neon_kernel!(
        f32_6x16,
        f32_6x16_neon,
        f32,
        float32x4_t,
        16,
        4,
        vdupq_n_f32,
        vld1q_f32,
        vfmaq_f32,
        vst1q_f32
    );
    neon_kernel!(
        f64_6x8,
        f64_6x8_neon,
        f64,
        float64x2_t,
        8,
        2,
        vdupq_n_f64,
        vld1q_f64,
        vfmaq_f64,
        vst1q_f64
    );
}

#[cfg(not(target_arch = "aarch64"))]
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
