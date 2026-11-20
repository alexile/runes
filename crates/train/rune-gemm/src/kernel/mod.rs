//! Register-blocked micro-kernels.
//!
//! Every kernel computes one `MR × NR` tile from a packed A panel
//! (`a[p * MR + i]`) and a packed B panel (`b[p * NR + j]`), summing over `p`
//! in increasing order into register accumulators, then stores the tile.
//! SIMD kernels check the CPU at run time and report `false` when they
//! cannot run, so the caller falls back to [`scalar`].

pub mod neon;
pub mod x86;

use crate::Element;

/// Instruction set a micro-kernel is written for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Isa {
    /// Portable Rust (auto-vectorised by the compiler for the build target).
    Scalar,
    /// x86-64 AVX2 with fused multiply-add.
    Avx2Fma,
    /// `AArch64` Advanced SIMD (NEON).
    Neon,
}

impl Isa {
    /// The fastest kernel this CPU supports.
    #[must_use]
    pub fn detect() -> Self {
        if x86::available() {
            Self::Avx2Fma
        } else if neon::available() {
            Self::Neon
        } else {
            Self::Scalar
        }
    }

    /// Whether this CPU can run the kernel.
    #[must_use]
    pub fn is_available(self) -> bool {
        match self {
            Self::Scalar => true,
            Self::Avx2Fma => x86::available(),
            Self::Neon => neon::available(),
        }
    }

    /// A short name: `"scalar"`, `"avx2+fma"` or `"neon"`.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Scalar => "scalar",
            Self::Avx2Fma => "avx2+fma",
            Self::Neon => "neon",
        }
    }
}

/// Portable kernel. A fixed-size accumulator array lets the compiler keep
/// the tile in registers and vectorise the `j` loop.
pub fn scalar<T: Element, const MR: usize, const NR: usize>(
    kc: usize,
    a: &[T],
    b: &[T],
    acc: &mut [T],
) {
    let mut t = [[T::ZERO; NR]; MR];
    for (ap, bp) in a
        .as_chunks::<MR>()
        .0
        .iter()
        .zip(b.as_chunks::<NR>().0)
        .take(kc)
    {
        for (row, &ai) in t.iter_mut().zip(ap) {
            for (c, &bj) in row.iter_mut().zip(bp) {
                *c = *c + ai * bj;
            }
        }
    }
    for (dst, row) in acc.as_chunks_mut::<NR>().0.iter_mut().zip(&t) {
        dst.copy_from_slice(row);
    }
}
