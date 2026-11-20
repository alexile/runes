//! Packed, cache-blocked, SIMD, multithreaded matrix multiply on plain
//! slices.
//!
//! Computes `C = alpha * A * B + beta * C` for `f32` and `f64`, where each
//! operand is a strided view: row-major, column-major, padded, transposed
//! (free, via [`MatRef::t`]) or broadcast (stride 0).
//!
//! | Entry point | Problem |
//! |-------------|---------|
//! | [`gemm`] | one product |
//! | [`gemm_batched`] | `C[b] = alpha * A[b] * B[b] + beta * C[b]` over a strided batch |
//! | [`gemm_grouped`] | ragged groups of rows of `A`/`C`, each times its own `B[g]` (mixture-of-experts layers) |
//! | [`sgemm`], [`dgemm`] | BLAS-style row-major call with transpose flags and leading dimensions |
//! | [`Gemm`] | the same calls with explicit threading and kernel choice |
//!
//! # Algorithm
//!
//! The five-loop blocked algorithm of the Goto and BLIS papers: `B` is packed into
//! `KC × NR` micro-panels (one stays in L1), `A` into `MC × KC` blocks of
//! `MR`-row panels (L2), and a register-blocked micro-kernel computes each
//! `MR × NR` tile of `C`. Kernels:
//!
//! | Type | Tile | Kernels |
//! |------|------|---------|
//! | `f32` | 6 × 16 | AVX2 + FMA, NEON, portable |
//! | `f64` | 6 × 8 | AVX2 + FMA, NEON, portable |
//!
//! The SIMD kernel is picked at run time ([`Isa::detect`]); the portable one
//! always works. Edge tiles are zero-padded in the packed buffers, so every
//! tile goes through the same kernel.
//!
//! # Threads and determinism
//!
//! Problems with at least [`PARALLEL_MIN_MACS`] multiply-adds run on the
//! current rayon pool, split over row blocks and, when those are few, column
//! blocks. The depth (`k`) loop is never split, so every element of `C` is
//! summed in the same order whatever the thread count: results are bitwise
//! identical on 1 or 64 threads. Batched and grouped calls run their
//! problems in parallel as well.
//!
//! # Semantics
//!
//! BLAS conventions: when `alpha == 0` or `k == 0`, `A` and `B` are not read
//! and `C = beta * C`; when `beta == 0`, `C` is overwritten without being
//! read, so `NaN` in `C` does not leak into the result.
//!
//! # Example
//!
//! ```
//! use rune_gemm::{gemm, MatMut, MatRef};
//!
//! let a = [1.0f32, 2.0, 3.0, 4.0, 5.0, 6.0]; // 2 × 3, row-major
//! let b = [1.0f32, 0.0, 0.0, 1.0, 1.0, 1.0]; // 3 × 2
//! let mut c = [0.0f32; 4];
//! gemm(
//!     1.0,
//!     MatRef::row_major(&a, 2, 3)?,
//!     MatRef::row_major(&b, 3, 2)?,
//!     0.0,
//!     MatMut::row_major(&mut c, 2, 2)?,
//! )?;
//! assert_eq!(c, [4.0, 5.0, 10.0, 11.0]);
//!
//! // Aᵀ · A with no copy: transposing a view only swaps its strides.
//! let at = MatRef::row_major(&a, 2, 3)?.t();
//! let mut g = [0.0f32; 9];
//! gemm(1.0, at, MatRef::row_major(&a, 2, 3)?, 0.0, MatMut::row_major(&mut g, 3, 3)?)?;
//! assert_eq!(g[0], 17.0);
//! # Ok::<(), rune_gemm::GemmError>(())
//! ```

#![warn(missing_docs)]
#![allow(
    clippy::similar_names,
    clippy::many_single_char_names,
    clippy::too_many_arguments
)]

mod driver;
mod element;
mod error;
mod kernel;
mod pack;
mod view;

pub use driver::PARALLEL_MIN_MACS;
pub use element::Element;
pub use error::GemmError;
pub use kernel::Isa;
pub use view::{BatchMut, BatchRef, MatMut, MatRef};

use driver::{CDesc, Exec, Item};

/// Whether an operand is used as stored or transposed (BLAS `trans` flag).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum Transpose {
    /// Use the matrix as stored.
    #[default]
    No,
    /// Use its transpose.
    Yes,
}

/// GEMM settings: threading and kernel choice. [`Gemm::new`] picks the
/// fastest kernel and uses the current rayon pool.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Gemm {
    parallel: bool,
    isa: Isa,
}

impl Default for Gemm {
    fn default() -> Self {
        Self::new()
    }
}

const fn check(what: &'static str, expected: usize, found: usize) -> Result<(), GemmError> {
    if expected == found {
        Ok(())
    } else {
        Err(GemmError::DimensionMismatch {
            what,
            expected,
            found,
        })
    }
}

impl Gemm {
    /// Detected kernel, multithreaded.
    #[must_use]
    pub fn new() -> Self {
        Self {
            parallel: true,
            isa: Isa::detect(),
        }
    }

    /// Allow or forbid using more than one thread. Results do not change.
    #[must_use]
    pub const fn parallel(mut self, parallel: bool) -> Self {
        self.parallel = parallel;
        self
    }

    /// Use a specific kernel. One this CPU cannot run falls back to
    /// [`Isa::Scalar`].
    #[must_use]
    pub fn isa(mut self, isa: Isa) -> Self {
        self.isa = if isa.is_available() { isa } else { Isa::Scalar };
        self
    }

    /// The kernel calls will use.
    #[must_use]
    pub const fn kernel(&self) -> Isa {
        self.isa
    }

    const fn exec(self) -> Exec {
        Exec {
            isa: self.isa,
            parallel: self.parallel,
        }
    }

    /// `C = alpha * A * B + beta * C` with `A: m × k`, `B: k × n`,
    /// `C: m × n`.
    pub fn gemm<T: Element>(
        &self,
        alpha: T,
        a: MatRef<'_, T>,
        b: MatRef<'_, T>,
        beta: T,
        c: MatMut<'_, T>,
    ) -> Result<(), GemmError> {
        check("rows of A", c.rows, a.rows)?;
        check("rows of B", a.cols, b.rows)?;
        check("columns of B", c.cols, b.cols)?;
        let item = Item {
            a,
            b,
            c: CDesc {
                offset: 0,
                rows: c.rows,
                cols: c.cols,
                rs: c.rs,
                cs: c.cs,
            },
        };
        driver::execute(self.exec(), alpha, beta, &[item], c.into_data())
    }

    /// `C[i] = alpha * A[i] * B[i] + beta * C[i]` for every batch entry.
    /// A batch stride of 0 on `A` or `B` shares one matrix across the batch.
    pub fn gemm_batched<T: Element>(
        &self,
        alpha: T,
        a: BatchRef<'_, T>,
        b: BatchRef<'_, T>,
        beta: T,
        c: BatchMut<'_, T>,
    ) -> Result<(), GemmError> {
        check("batch of A", c.batch, a.batch)?;
        check("batch of B", c.batch, b.batch)?;
        check("rows of A", c.rows, a.rows)?;
        check("rows of B", a.cols, b.rows)?;
        check("columns of B", c.cols, b.cols)?;
        let items: Vec<_> = (0..c.batch)
            .map(|i| Item {
                a: a.item(i),
                b: b.item(i),
                c: CDesc {
                    offset: i * c.bs,
                    rows: c.rows,
                    cols: c.cols,
                    rs: c.rs,
                    cs: c.cs,
                },
            })
            .collect();
        driver::execute(self.exec(), alpha, beta, &items, c.into_data())
    }

    /// Grouped GEMM: the rows of `A` (`M × k`) and `C` (`M × n`) are cut into
    /// consecutive groups of `group_rows[g]` rows (summing to `M`, zeros
    /// allowed), and group `g` is multiplied by `B[g]` (`k × n`):
    ///
    /// `C[r_g .. r_g + m_g] = alpha * A[r_g .. r_g + m_g] * B[g] + beta * C[r_g .. r_g + m_g]`
    ///
    /// This is the expert layer of a mixture-of-experts model with tokens
    /// sorted by expert. All groups run as one parallel job.
    pub fn gemm_grouped<T: Element>(
        &self,
        alpha: T,
        a: MatRef<'_, T>,
        group_rows: &[usize],
        b: BatchRef<'_, T>,
        beta: T,
        c: MatMut<'_, T>,
    ) -> Result<(), GemmError> {
        let total = group_rows
            .iter()
            .try_fold(0usize, |s, &m| s.checked_add(m))
            .ok_or(GemmError::Overflow)?;
        check("sum of group rows", c.rows, total)?;
        check("rows of A", c.rows, a.rows)?;
        check("number of B matrices", group_rows.len(), b.batch)?;
        check("rows of B", a.cols, b.rows)?;
        check("columns of B", c.cols, b.cols)?;
        let mut r0 = 0;
        let mut items = Vec::with_capacity(group_rows.len());
        for (g, &m) in group_rows.iter().enumerate() {
            items.push(Item {
                a: a.row_range(r0, m),
                b: b.item(g),
                c: CDesc {
                    offset: r0 * c.rs,
                    rows: m,
                    cols: c.cols,
                    rs: c.rs,
                    cs: c.cs,
                },
            });
            r0 += m;
        }
        driver::execute(self.exec(), alpha, beta, &items, c.into_data())
    }
}

/// `C = alpha * A * B + beta * C` with the default [`Gemm`] settings.
pub fn gemm<T: Element>(
    alpha: T,
    a: MatRef<'_, T>,
    b: MatRef<'_, T>,
    beta: T,
    c: MatMut<'_, T>,
) -> Result<(), GemmError> {
    Gemm::new().gemm(alpha, a, b, beta, c)
}

/// Strided batched GEMM with the default settings; see
/// [`Gemm::gemm_batched`].
pub fn gemm_batched<T: Element>(
    alpha: T,
    a: BatchRef<'_, T>,
    b: BatchRef<'_, T>,
    beta: T,
    c: BatchMut<'_, T>,
) -> Result<(), GemmError> {
    Gemm::new().gemm_batched(alpha, a, b, beta, c)
}

/// Grouped (ragged) GEMM with the default settings; see
/// [`Gemm::gemm_grouped`].
pub fn gemm_grouped<T: Element>(
    alpha: T,
    a: MatRef<'_, T>,
    group_rows: &[usize],
    b: BatchRef<'_, T>,
    beta: T,
    c: MatMut<'_, T>,
) -> Result<(), GemmError> {
    Gemm::new().gemm_grouped(alpha, a, group_rows, b, beta, c)
}

/// The operand view for a BLAS-style row-major argument: stored as
/// `rows × cols` (before `trans`) with leading dimension `ld`.
fn blas_view<'a, T: Element>(
    what: &'static str,
    data: &'a [T],
    trans: Transpose,
    op_rows: usize,
    op_cols: usize,
    ld: usize,
) -> Result<MatRef<'a, T>, GemmError> {
    let (rows, cols) = match trans {
        Transpose::No => (op_rows, op_cols),
        Transpose::Yes => (op_cols, op_rows),
    };
    if ld < cols.max(1) {
        return Err(GemmError::LeadingDimension {
            what,
            found: ld,
            min: cols.max(1),
        });
    }
    let v = MatRef::new(data, rows, cols, ld, 1)?;
    Ok(match trans {
        Transpose::No => v,
        Transpose::Yes => v.t(),
    })
}

fn blas_gemm<T: Element>(
    trans_a: Transpose,
    trans_b: Transpose,
    m: usize,
    n: usize,
    k: usize,
    alpha: T,
    a: &[T],
    lda: usize,
    b: &[T],
    ldb: usize,
    beta: T,
    c: &mut [T],
    ldc: usize,
) -> Result<(), GemmError> {
    let a = blas_view("lda", a, trans_a, m, k, lda)?;
    let b = blas_view("ldb", b, trans_b, k, n, ldb)?;
    if ldc < n.max(1) {
        return Err(GemmError::LeadingDimension {
            what: "ldc",
            found: ldc,
            min: n.max(1),
        });
    }
    gemm(alpha, a, b, beta, MatMut::new(c, m, n, ldc, 1)?)
}

/// BLAS-style single-precision GEMM on row-major storage.
///
/// `C = alpha * op(A) * op(B) + beta * C` with `op(A): m × k`,
/// `op(B): k × n`, `C: m × n` and leading dimensions (row strides) `lda`,
/// `ldb`, `ldc`. `A` is stored `m × k` (or `k × m` when transposed), and
/// likewise `B`.
///
/// ```
/// use rune_gemm::{sgemm, Transpose};
///
/// // op(A) = Aᵀ where A is stored 3 × 2.
/// let a = [1.0, 4.0, 2.0, 5.0, 3.0, 6.0];
/// let b = [1.0, 0.0, 0.0, 1.0, 1.0, 1.0];
/// let mut c = [f32::NAN; 4]; // beta = 0 overwrites NaN
/// sgemm(Transpose::Yes, Transpose::No, 2, 2, 3, 1.0, &a, 2, &b, 2, 0.0, &mut c, 2)?;
/// assert_eq!(c, [4.0, 5.0, 10.0, 11.0]);
/// # Ok::<(), rune_gemm::GemmError>(())
/// ```
pub fn sgemm(
    trans_a: Transpose,
    trans_b: Transpose,
    m: usize,
    n: usize,
    k: usize,
    alpha: f32,
    a: &[f32],
    lda: usize,
    b: &[f32],
    ldb: usize,
    beta: f32,
    c: &mut [f32],
    ldc: usize,
) -> Result<(), GemmError> {
    blas_gemm(
        trans_a, trans_b, m, n, k, alpha, a, lda, b, ldb, beta, c, ldc,
    )
}

/// BLAS-style double-precision GEMM on row-major storage; see [`sgemm`].
pub fn dgemm(
    trans_a: Transpose,
    trans_b: Transpose,
    m: usize,
    n: usize,
    k: usize,
    alpha: f64,
    a: &[f64],
    lda: usize,
    b: &[f64],
    ldb: usize,
    beta: f64,
    c: &mut [f64],
    ldc: usize,
) -> Result<(), GemmError> {
    blas_gemm(
        trans_a, trans_b, m, n, k, alpha, a, lda, b, ldb, beta, c, ldc,
    )
}

/// The README examples, compiled and run as doc tests.
#[cfg(doctest)]
#[doc = include_str!("../README.md")]
struct ReadmeDoctests;
