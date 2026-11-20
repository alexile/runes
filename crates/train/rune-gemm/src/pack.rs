//! Packing operands into contiguous, zero-padded micro-panels.

use crate::{Element, MatRef};

/// Packs `A[i0 .. i0 + mc, p0 .. p0 + kc]` into `ceil(mc / MR)` panels of
/// `kc × MR`, panel-major: `dst[panel * kc * MR + p * MR + i]`. Rows past
/// `mc` are zero.
pub fn pack_a<T: Element>(
    a: &MatRef<'_, T>,
    i0: usize,
    p0: usize,
    mc: usize,
    kc: usize,
    dst: &mut [T],
) {
    let mr = T::MR;
    for (panel, out) in dst.chunks_exact_mut(kc * mr).enumerate() {
        let r0 = panel * mr;
        if r0 >= mc {
            break;
        }
        let rows = mr.min(mc - r0);
        if rows < mr {
            out.fill(T::ZERO);
        }
        if a.cs == 1 {
            // Rows are contiguous along k: read each row once.
            for i in 0..rows {
                let base = a.offset + (i0 + r0 + i) * a.rs + p0;
                let src = &a.data[base..base + kc];
                for (o, &x) in out.iter_mut().skip(i).step_by(mr).zip(src) {
                    *o = x;
                }
            }
        } else {
            for (p, o) in out.chunks_exact_mut(mr).enumerate() {
                for (i, slot) in o.iter_mut().take(rows).enumerate() {
                    *slot = a.at(i0 + r0 + i, p0 + p);
                }
            }
        }
    }
}

/// Packs B panel number `panel` of the block `B[p0 .. p0 + kc, j0 .. j0 + nc]`
/// (columns `panel * NR ..`) into `dst[p * NR + j]`. Columns past `nc` are
/// zero.
pub fn pack_b_panel<T: Element>(
    b: &MatRef<'_, T>,
    p0: usize,
    j0: usize,
    nc: usize,
    kc: usize,
    panel: usize,
    dst: &mut [T],
) {
    let nr = T::NR;
    let c0 = panel * nr;
    let cols = nr.min(nc.saturating_sub(c0));
    if cols < nr {
        dst.fill(T::ZERO);
    }
    if b.cs == 1 {
        for (p, o) in dst.chunks_exact_mut(nr).take(kc).enumerate() {
            let base = b.offset + (p0 + p) * b.rs + j0 + c0;
            o[..cols].copy_from_slice(&b.data[base..base + cols]);
        }
    } else {
        for j in 0..cols {
            for (p, o) in dst.chunks_exact_mut(nr).take(kc).enumerate() {
                o[j] = b.at(p0 + p, j0 + c0 + j);
            }
        }
    }
}
