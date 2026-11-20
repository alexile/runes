//! Scalar types the kernels work on.

use core::fmt::Debug;
use core::ops::{Add, Mul};

use crate::kernel::{self, Isa};

/// A floating-point element type with a tuned GEMM kernel: `f32` or `f64`.
///
/// Sealed: the blocking parameters and micro-kernels live with the type.
pub trait Element:
    sealed::Kernel
    + Copy
    + Send
    + Sync
    + PartialEq
    + Debug
    + Add<Output = Self>
    + Mul<Output = Self>
    + 'static
{
    /// Additive identity.
    const ZERO: Self;
    /// Multiplicative identity.
    const ONE: Self;
}

mod sealed {
    use crate::kernel::Isa;

    /// Blocking parameters and the register-blocked micro-kernel.
    pub trait Kernel: Sized {
        /// Micro-tile rows (rows of a packed A panel).
        const MR: usize;
        /// Micro-tile columns (columns of a packed B panel).
        const NR: usize;
        /// Rows of A per L2 block (multiple of `MR`).
        const MC: usize;
        /// Depth per block: one `KC × NR` B panel stays in L1.
        const KC: usize;
        /// Columns of B per L3 block (multiple of `NR`).
        const NC: usize;

        /// `acc[i * NR + j] = Σ_p a[p * MR + i] * b[p * NR + j]` for
        /// `p < kc`, summed in increasing `p`.
        fn micro_kernel(isa: Isa, kc: usize, a: &[Self], b: &[Self], acc: &mut [Self]);
    }
}

impl sealed::Kernel for f32 {
    const MR: usize = 6;
    const NR: usize = 16;
    const MC: usize = 144;
    const KC: usize = 256;
    const NC: usize = 4080;

    fn micro_kernel(isa: Isa, kc: usize, a: &[Self], b: &[Self], acc: &mut [Self]) {
        let done = match isa {
            Isa::Avx2Fma => kernel::x86::f32_6x16(kc, a, b, acc),
            Isa::Neon => kernel::neon::f32_6x16(kc, a, b, acc),
            Isa::Scalar => false,
        };
        if !done {
            kernel::scalar::<Self, 6, 16>(kc, a, b, acc);
        }
    }
}

impl sealed::Kernel for f64 {
    const MR: usize = 6;
    const NR: usize = 8;
    const MC: usize = 72;
    const KC: usize = 256;
    const NC: usize = 4080;

    fn micro_kernel(isa: Isa, kc: usize, a: &[Self], b: &[Self], acc: &mut [Self]) {
        let done = match isa {
            Isa::Avx2Fma => kernel::x86::f64_6x8(kc, a, b, acc),
            Isa::Neon => kernel::neon::f64_6x8(kc, a, b, acc),
            Isa::Scalar => false,
        };
        if !done {
            kernel::scalar::<Self, 6, 8>(kc, a, b, acc);
        }
    }
}

impl Element for f32 {
    const ZERO: Self = 0.0;
    const ONE: Self = 1.0;
}

impl Element for f64 {
    const ZERO: Self = 0.0;
    const ONE: Self = 1.0;
}
