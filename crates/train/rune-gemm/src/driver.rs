//! The blocked GEMM driver.
//!
//! Loop nest (outer to inner), after "Anatomy of High-Performance Matrix
//! Multiplication" (Goto, van de Geijn) and "BLIS: A Framework for Rapidly
//! Instantiating BLAS Functionality" (Van Zee, van de Geijn):
//!
//! 1. `jc`: columns of B and C in blocks of `NC` (L3).
//! 2. `pc`: depth in blocks of `KC`; `B[pc, jc]` is packed into `NR`-wide
//!    panels shared by all threads.
//! 3. `ic`: rows in blocks of `MC` (L2); each task packs its `A[ic, pc]`
//!    into `MR`-tall panels.
//! 4. `jr`, `ir`: one `MR × NR` micro-kernel call per tile.
//!
//! Threads split loop 3 (and, when there are few row blocks, the columns of
//! the `NC` block), never the `k` loop, so every output element is summed in
//! the same order whatever the thread count.

use rayon::prelude::*;

use crate::{Element, GemmError, Isa, MatRef, pack};

/// Below this many multiply-adds a problem runs on one thread.
pub const PARALLEL_MIN_MACS: usize = 1 << 18;

/// Largest `MR * NR` over the element types.
const MAX_TILE: usize = 96;

/// Execution settings resolved for one call.
#[derive(Debug, Clone, Copy)]
pub struct Exec {
    pub isa: Isa,
    pub parallel: bool,
}

/// Where one output matrix lives inside the shared `C` slice.
#[derive(Debug, Clone, Copy)]
pub struct CDesc {
    pub offset: usize,
    pub rows: usize,
    pub cols: usize,
    pub rs: usize,
    pub cs: usize,
}

/// One `C = alpha * A * B + beta * C` problem.
#[derive(Debug, Clone, Copy)]
pub struct Item<'a, T> {
    pub a: MatRef<'a, T>,
    pub b: MatRef<'a, T>,
    pub c: CDesc,
}

/// An item whose output rows are disjoint mutable slices.
struct Problem<'a, 'c, T> {
    a: MatRef<'a, T>,
    b: MatRef<'a, T>,
    rows: Vec<&'c mut [T]>,
}

/// Runs every item. Shapes were validated by the caller; `data` is the `C`
/// slice every `CDesc` points into, already proven in bounds and disjoint.
pub fn execute<T: Element>(
    ex: Exec,
    alpha: T,
    beta: T,
    items: &[Item<'_, T>],
    data: &mut [T],
) -> Result<(), GemmError> {
    let items: Vec<Item<'_, T>> = items
        .iter()
        .copied()
        .filter(|it| it.c.rows > 0 && it.c.cols > 0)
        .collect();
    if items.iter().any(|it| row_layout(&it.c).is_none()) {
        return execute_dense(ex, alpha, beta, &items, data);
    }

    // One (offset, len) segment per output row (or per column when C is
    // column-major and the problem is solved transposed).
    let mut segs = Vec::new();
    let mut transposed = Vec::with_capacity(items.len());
    for it in &items {
        let c = it.c;
        let t = row_layout(&c) == Some(true);
        transposed.push(t);
        if t {
            segs.extend((0..c.cols).map(|j| (c.offset + j * c.cs, c.rows)));
        } else {
            segs.extend((0..c.rows).map(|i| (c.offset + i * c.rs, c.cols)));
        }
    }
    let mut rows = split_segments(data, &segs)?.into_iter();
    let mut problems = Vec::with_capacity(items.len());
    for (it, t) in items.iter().zip(transposed) {
        let (a, b, m) = if t {
            (it.b.t(), it.a.t(), it.c.cols)
        } else {
            (it.a, it.b, it.c.rows)
        };
        problems.push(Problem {
            a,
            b,
            rows: rows.by_ref().take(m).collect(),
        });
    }

    if ex.parallel && problems.len() > 1 {
        problems
            .into_par_iter()
            .for_each(|p| run(ex, alpha, beta, p));
    } else {
        for p in problems {
            run(ex, alpha, beta, p);
        }
    }
    Ok(())
}

/// `Some(false)`: rows are contiguous. `Some(true)`: columns are. `None`:
/// neither, so `C` goes through a dense scratch copy.
const fn row_layout(c: &CDesc) -> Option<bool> {
    if c.cs == 1 || c.cols <= 1 {
        Some(false)
    } else if c.rs == 1 || c.rows <= 1 {
        Some(true)
    } else {
        None
    }
}

/// Runs items whose `C` has no unit stride through a dense row-major copy.
fn execute_dense<T: Element>(
    ex: Exec,
    alpha: T,
    beta: T,
    items: &[Item<'_, T>],
    data: &mut [T],
) -> Result<(), GemmError> {
    let total = items.iter().map(|it| it.c.rows * it.c.cols).sum();
    let mut tmp = vec![T::ZERO; total];
    let mut dense = Vec::with_capacity(items.len());
    let mut off = 0;
    for it in items {
        let c = it.c;
        if beta != T::ZERO {
            for i in 0..c.rows {
                for j in 0..c.cols {
                    tmp[off + i * c.cols + j] = data[c.offset + i * c.rs + j * c.cs];
                }
            }
        }
        dense.push(Item {
            c: CDesc {
                offset: off,
                rows: c.rows,
                cols: c.cols,
                rs: c.cols,
                cs: 1,
            },
            ..*it
        });
        off += c.rows * c.cols;
    }
    execute(ex, alpha, beta, &dense, &mut tmp)?;
    for (it, d) in items.iter().zip(&dense) {
        let c = it.c;
        for i in 0..c.rows {
            for j in 0..c.cols {
                data[c.offset + i * c.rs + j * c.cs] = tmp[d.c.offset + i * c.cols + j];
            }
        }
    }
    Ok(())
}

/// Splits `data` into the requested `(offset, len)` segments, returned in
/// request order. Fails if two segments overlap or one runs past the end.
fn split_segments<'c, T>(
    data: &'c mut [T],
    segs: &[(usize, usize)],
) -> Result<Vec<&'c mut [T]>, GemmError> {
    let mut order: Vec<usize> = (0..segs.len()).collect();
    order.sort_unstable_by_key(|&i| segs[i].0);
    let mut out: Vec<Option<&'c mut [T]>> = Vec::new();
    out.resize_with(segs.len(), || None);
    let len = data.len();
    let mut rest = data;
    let mut pos = 0usize;
    for i in order {
        let (off, n) = segs[i];
        let overlapping = || GemmError::Overlapping {
            strides: Vec::new(),
        };
        let skip = off.checked_sub(pos).ok_or_else(overlapping)?;
        let tail = core::mem::take(&mut rest);
        let (_, tail) = tail
            .split_at_mut_checked(skip)
            .ok_or(GemmError::OutOfBounds {
                needed: off + n,
                len,
            })?;
        let (seg, tail) = tail.split_at_mut_checked(n).ok_or(GemmError::OutOfBounds {
            needed: off + n,
            len,
        })?;
        out[i] = Some(seg);
        rest = tail;
        pos = off + n;
    }
    out.into_iter()
        .collect::<Option<Vec<_>>>()
        .ok_or(GemmError::Overflow)
}

/// A rectangle of output rows/columns handled by one thread.
struct Task<'t, T> {
    /// First row (relative to the problem).
    i0: usize,
    /// First column, relative to the `NC` block; a multiple of `NR`.
    j0: usize,
    /// Column count.
    nc: usize,
    rows: Vec<&'t mut [T]>,
}

const fn round_up(x: usize, to: usize) -> usize {
    x.div_ceil(to) * to
}

fn run<T: Element>(ex: Exec, alpha: T, beta: T, mut p: Problem<'_, '_, T>) {
    let m = p.rows.len();
    let n = p.b.cols;
    let k = p.a.cols;
    if m == 0 || n == 0 {
        return;
    }
    if k == 0 || alpha == T::ZERO {
        scale(&mut p.rows, beta);
        return;
    }
    let par = ex.parallel
        && rayon::current_num_threads() > 1
        && m.saturating_mul(n).saturating_mul(k) >= PARALLEL_MIN_MACS;
    let (mr, nr) = (T::MR, T::NR);

    let mut bpack = vec![T::ZERO; T::KC.min(k) * round_up(T::NC.min(n), nr)];
    for jc in (0..n).step_by(T::NC) {
        let nc = T::NC.min(n - jc);
        for pc in (0..k).step_by(T::KC) {
            let kc = T::KC.min(k - pc);
            let bp = &mut bpack[..kc * round_up(nc, nr)];
            let pack = |(panel, dst): (usize, &mut [T])| {
                pack::pack_b_panel(&p.b, pc, jc, nc, kc, panel, dst);
            };
            if par {
                bp.par_chunks_mut(kc * nr).enumerate().for_each(pack);
            } else {
                bp.chunks_mut(kc * nr).enumerate().for_each(pack);
            }
            let bp: &[T] = bp;
            let beta = if pc == 0 { beta } else { T::ONE };

            let tasks = make_tasks::<T>(&mut p.rows, jc, nc, par);
            let a = &p.a;
            let work = |abuf: &mut Vec<T>, mut t: Task<'_, T>| {
                let mc = t.rows.len();
                pack::pack_a(a, t.i0, pc, mc, kc, abuf);
                macro_kernel(ex.isa, alpha, beta, kc, abuf, bp, &mut t);
            };
            let abuf = || vec![T::ZERO; round_up(T::MC.min(m), mr) * kc];
            if par {
                tasks.into_par_iter().for_each_init(abuf, work);
            } else {
                let mut buf = abuf();
                for t in tasks {
                    work(&mut buf, t);
                }
            }
        }
    }
}

/// Splits the columns `jc .. jc + nc` of every row into tasks of `MC` rows
/// by a multiple of `NR` columns. Column splitting only kicks in when there
/// are too few row blocks to keep every thread busy.
fn make_tasks<'t, T: Element>(
    rows: &'t mut [&mut [T]],
    jc: usize,
    nc: usize,
    par: bool,
) -> Vec<Task<'t, T>> {
    let m = rows.len();
    let bands = m.div_ceil(T::MC);
    let panels = nc.div_ceil(T::NR);
    let groups = if par {
        (2 * rayon::current_num_threads())
            .div_ceil(bands)
            .clamp(1, panels)
    } else {
        1
    };
    let gw = panels.div_ceil(groups) * T::NR;
    let groups = nc.div_ceil(gw);
    let mut tasks = Vec::with_capacity(bands * groups);
    for band in 0..bands {
        let i0 = band * T::MC;
        let mc = T::MC.min(m - i0);
        for g in 0..groups {
            let j0 = g * gw;
            tasks.push(Task {
                i0,
                j0,
                nc: gw.min(nc - j0),
                rows: Vec::with_capacity(mc),
            });
        }
    }
    for (i, row) in rows.iter_mut().enumerate() {
        let band = i / T::MC;
        let mut rest: &mut [T] = &mut row[jc..jc + nc];
        for task in &mut tasks[band * groups..(band + 1) * groups] {
            let (head, tail) = core::mem::take(&mut rest).split_at_mut(task.nc);
            task.rows.push(head);
            rest = tail;
        }
    }
    tasks
}

fn macro_kernel<T: Element>(
    isa: Isa,
    alpha: T,
    beta: T,
    kc: usize,
    apack: &[T],
    bpack: &[T],
    t: &mut Task<'_, T>,
) {
    let (mr, nr) = (T::MR, T::NR);
    let mc = t.rows.len();
    let mut acc = [T::ZERO; MAX_TILE];
    let acc = &mut acc[..mr * nr];
    for jr in (0..t.nc).step_by(nr) {
        let ncols = nr.min(t.nc - jr);
        let bpanel = &bpack[(t.j0 + jr) / nr * kc * nr..][..kc * nr];
        for ir in (0..mc).step_by(mr) {
            let nrows = mr.min(mc - ir);
            let apanel = &apack[ir / mr * kc * mr..][..kc * mr];
            T::micro_kernel(isa, kc, apanel, bpanel, acc);
            for (row, tile) in t.rows[ir..ir + nrows].iter_mut().zip(acc.chunks_exact(nr)) {
                let dst = &mut row[jr..jr + ncols];
                if beta == T::ZERO {
                    for (d, &s) in dst.iter_mut().zip(tile) {
                        *d = alpha * s;
                    }
                } else {
                    for (d, &s) in dst.iter_mut().zip(tile) {
                        *d = alpha * s + beta * *d;
                    }
                }
            }
        }
    }
}

/// `C = beta * C`, with `beta = 0` overwriting (NaN in `C` does not survive).
fn scale<T: Element>(rows: &mut [&mut [T]], beta: T) {
    if beta == T::ONE {
        return;
    }
    for row in rows {
        if beta == T::ZERO {
            row.fill(T::ZERO);
        } else {
            for x in row.iter_mut() {
                *x = beta * *x;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_rejects_overlap_and_overrun() {
        let mut v = [0u8; 10];
        assert!(split_segments(&mut v, &[(0, 3), (2, 3)]).is_err());
        assert!(split_segments(&mut v, &[(8, 3)]).is_err());
        let s = split_segments(&mut v, &[(6, 2), (0, 3), (3, 3)]).unwrap();
        assert_eq!(s.iter().map(|s| s.len()).collect::<Vec<_>>(), [2, 3, 3]);
    }
}
