//! Summation and work splitting shared by every op.
//!
//! All reductions here have a fixed association order that depends only on
//! the input length, never on the thread count, so every op built on them is
//! bitwise reproducible.

use rayon::prelude::*;

/// Work (in elements) below which an op runs on the calling thread.
pub const PARALLEL_MIN_ELEMS: usize = 1 << 15;

/// Rows per partial sum for parameter gradients that reduce over rows.
/// Fixed, so the partials (and the result) do not depend on the thread
/// count.
pub const GRAD_BLOCK_ROWS: usize = 64;

/// Leaf size of the pairwise sums.
const LEAF: usize = 128;
const LANES: usize = 8;

#[inline]
fn leaf2<F: Fn(f32, f32) -> f32>(a: &[f32], b: &[f32], f: &F) -> f32 {
    let mut acc = [0.0f32; LANES];
    let (ca, ra) = a.as_chunks::<LANES>();
    let (cb, rb) = b.as_chunks::<LANES>();
    for (x, y) in ca.iter().zip(cb) {
        for k in 0..LANES {
            acc[k] += f(x[k], y[k]);
        }
    }
    for (k, (&x, &y)) in ra.iter().zip(rb).enumerate() {
        acc[k] += f(x, y);
    }
    ((acc[0] + acc[1]) + (acc[2] + acc[3])) + ((acc[4] + acc[5]) + (acc[6] + acc[7]))
}

fn pairwise2<F: Fn(f32, f32) -> f32>(a: &[f32], b: &[f32], f: &F) -> f32 {
    if a.len() <= LEAF {
        return leaf2(a, b, f);
    }
    // Split on a multiple of the leaf size so the leaves stay full.
    let mid = (a.len() / 2).div_ceil(LEAF) * LEAF;
    let (a0, a1) = a.split_at(mid);
    let (b0, b1) = b.split_at(mid);
    pairwise2(a0, b0, f) + pairwise2(a1, b1, f)
}

/// `Σ f(a[i], b[i])` by pairwise summation (8-lane leaves of 128 elements):
/// error grows like `log n`, not `n`. `a` and `b` must have equal lengths;
/// extra elements of the longer one are ignored.
#[inline]
pub fn sum2_by<F: Fn(f32, f32) -> f32>(a: &[f32], b: &[f32], f: F) -> f32 {
    let n = a.len().min(b.len());
    pairwise2(&a[..n], &b[..n], &f)
}

/// `Σ f(x[i])` by pairwise summation.
#[inline]
pub fn sum_by<F: Fn(f32) -> f32>(x: &[f32], f: F) -> f32 {
    pairwise2(x, x, &|v, _| f(v))
}

/// Runs `f` on every task, in parallel when `parallel` holds.
pub fn run_tasks<T, F>(parallel: bool, tasks: Vec<T>, f: F)
where
    T: Send,
    F: Fn(T) + Sync + Send,
{
    if parallel && tasks.len() > 1 {
        tasks.into_par_iter().for_each(f);
    } else {
        tasks.into_iter().for_each(f);
    }
}

/// Maps every task, in parallel when `parallel` holds; results keep task
/// order.
pub fn map_tasks<T, R, F>(parallel: bool, tasks: Vec<T>, f: F) -> Vec<R>
where
    T: Send,
    R: Send,
    F: Fn(T) -> R + Sync + Send,
{
    if parallel && tasks.len() > 1 {
        tasks.into_par_iter().map(f).collect()
    } else {
        tasks.into_iter().map(f).collect()
    }
}

/// Whether `elems` units of work are worth spreading over threads.
pub const fn worth_parallel(elems: usize) -> bool {
    elems >= PARALLEL_MIN_ELEMS
}

/// Rows per task so one task touches about [`PARALLEL_MIN_ELEMS`] / 8
/// elements. Depends only on the row length.
pub fn rows_per_task(row: usize) -> usize {
    (PARALLEL_MIN_ELEMS / 8).div_ceil(row.max(1)).max(1)
}

/// Combines per-block partial vectors (each of length `out.len()`) into
/// `out` by a pairwise tree in block order. Writes zeros when there are no
/// partials.
pub fn combine_partials(mut partials: Vec<Vec<f32>>, out: &mut [f32]) {
    while partials.len() > 1 {
        let mut next = Vec::with_capacity(partials.len().div_ceil(2));
        let mut it = partials.into_iter();
        while let Some(mut a) = it.next() {
            if let Some(b) = it.next() {
                for (x, y) in a.iter_mut().zip(&b) {
                    *x += *y;
                }
            }
            next.push(a);
        }
        partials = next;
    }
    match partials.pop() {
        Some(p) => out.copy_from_slice(&p),
        None => out.fill(0.0),
    }
}

#[cfg(test)]
#[allow(clippy::cast_precision_loss)]
mod tests {
    use super::*;

    #[test]
    fn pairwise_matches_exact_sum() {
        for n in [0usize, 1, 7, 8, 9, 127, 128, 129, 1000, 4097] {
            let x: Vec<f32> = (0..n).map(|i| (i % 13) as f32 * 0.25).collect();
            let exact: f64 = x.iter().map(|&v| f64::from(v)).sum();
            assert!((f64::from(sum_by(&x, |v| v)) - exact).abs() <= 1e-6 * exact.max(1.0));
        }
    }

    #[test]
    fn pairwise_beats_naive_on_long_sums() {
        let x = vec![0.1f32; 1 << 20];
        let exact = 0.1f64 * f64::from(1u32 << 20);
        let naive: f32 = x.iter().sum();
        let pw = sum_by(&x, |v| v);
        assert!((f64::from(pw) - exact).abs() < (f64::from(naive) - exact).abs() / 10.0);
    }

    #[test]
    fn combine_is_tree_ordered() {
        let parts: Vec<Vec<f32>> = (0..5).map(|i| vec![i as f32; 3]).collect();
        let mut out = [0.0; 3];
        combine_partials(parts, &mut out);
        assert_eq!(out, [10.0; 3]);
        let mut out = [1.0; 2];
        combine_partials(Vec::new(), &mut out);
        assert_eq!(out, [0.0; 2]);
    }
}
