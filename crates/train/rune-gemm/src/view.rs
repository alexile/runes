//! Validated strided views over slices.

use crate::GemmError;

/// Highest offset + 1 addressed by a strided box, or 0 if any extent is 0.
fn span(dims: &[(usize, usize)]) -> Result<usize, GemmError> {
    if dims.iter().any(|&(d, _)| d == 0) {
        return Ok(0);
    }
    let mut last = 0usize;
    for &(d, s) in dims {
        last = (d - 1)
            .checked_mul(s)
            .and_then(|x| x.checked_add(last))
            .ok_or(GemmError::Overflow)?;
    }
    last.checked_add(1).ok_or(GemmError::Overflow)
}

fn check_bounds(len: usize, offset: usize, dims: &[(usize, usize)]) -> Result<(), GemmError> {
    let s = span(dims)?;
    if s == 0 {
        return Ok(());
    }
    let needed = offset.checked_add(s).ok_or(GemmError::Overflow)?;
    if needed > len {
        return Err(GemmError::OutOfBounds { needed, len });
    }
    Ok(())
}

/// Sufficient condition for a strided box to address every element once:
/// sorted by stride, each stride exceeds the span of all smaller ones.
/// Covers every permutation of a dense (optionally padded) layout.
fn check_disjoint(dims: &[(usize, usize)]) -> Result<(), GemmError> {
    let mut live: Vec<(usize, usize)> = dims.iter().copied().filter(|&(d, _)| d > 1).collect();
    if dims.iter().any(|&(d, _)| d == 0) {
        return Ok(());
    }
    live.sort_by_key(|&(_, s)| s);
    let mut reach = 0usize; // highest offset reachable by the smaller dims
    for &(d, s) in &live {
        if s <= reach || s == 0 {
            return Err(GemmError::Overlapping {
                strides: dims.iter().map(|&(_, s)| s).collect(),
            });
        }
        reach = (d - 1)
            .checked_mul(s)
            .and_then(|x| x.checked_add(reach))
            .ok_or(GemmError::Overflow)?;
    }
    Ok(())
}

/// A read-only `rows × cols` matrix view: element `(i, j)` lives at
/// `data[i * row_stride + j * col_stride]`.
///
/// Any strides are allowed, including 0 (broadcast). Transposing is free:
/// [`MatRef::t`] swaps the dimensions and strides.
#[derive(Debug, Clone, Copy)]
pub struct MatRef<'a, T> {
    pub(crate) data: &'a [T],
    pub(crate) offset: usize,
    pub(crate) rows: usize,
    pub(crate) cols: usize,
    pub(crate) rs: usize,
    pub(crate) cs: usize,
}

impl<'a, T: Copy> MatRef<'a, T> {
    /// A strided view. Fails if any addressed element is outside `data`.
    pub fn new(
        data: &'a [T],
        rows: usize,
        cols: usize,
        row_stride: usize,
        col_stride: usize,
    ) -> Result<Self, GemmError> {
        check_bounds(data.len(), 0, &[(rows, row_stride), (cols, col_stride)])?;
        Ok(Self {
            data,
            offset: 0,
            rows,
            cols,
            rs: row_stride,
            cs: col_stride,
        })
    }

    /// A dense row-major view (`row_stride = cols`).
    pub fn row_major(data: &'a [T], rows: usize, cols: usize) -> Result<Self, GemmError> {
        Self::new(data, rows, cols, cols, 1)
    }

    /// A dense column-major view (`col_stride = rows`).
    pub fn col_major(data: &'a [T], rows: usize, cols: usize) -> Result<Self, GemmError> {
        Self::new(data, rows, cols, 1, rows)
    }

    /// The transposed view; no data moves.
    #[must_use]
    pub const fn t(self) -> Self {
        Self {
            data: self.data,
            offset: self.offset,
            rows: self.cols,
            cols: self.rows,
            rs: self.cs,
            cs: self.rs,
        }
    }

    /// Number of rows.
    #[must_use]
    pub const fn rows(&self) -> usize {
        self.rows
    }

    /// Number of columns.
    #[must_use]
    pub const fn cols(&self) -> usize {
        self.cols
    }

    /// Distance between consecutive rows.
    #[must_use]
    pub const fn row_stride(&self) -> usize {
        self.rs
    }

    /// Distance between consecutive columns.
    #[must_use]
    pub const fn col_stride(&self) -> usize {
        self.cs
    }

    /// Element `(i, j)`, or `None` outside the view.
    #[must_use]
    pub fn get(&self, i: usize, j: usize) -> Option<T> {
        (i < self.rows && j < self.cols).then(|| self.at(i, j))
    }

    /// Element `(i, j)`; the caller keeps `i < rows`, `j < cols`, which the
    /// constructor proved in bounds.
    #[inline]
    pub(crate) const fn at(&self, i: usize, j: usize) -> T {
        self.data[self.offset + i * self.rs + j * self.cs]
    }

    /// Rows `r0 .. r0 + m` (the caller keeps them in range).
    pub(crate) const fn row_range(self, r0: usize, m: usize) -> Self {
        Self {
            offset: self.offset + r0 * self.rs,
            rows: m,
            ..self
        }
    }
}

/// A mutable `rows × cols` matrix view with the same addressing as
/// [`MatRef`]. The strides must address every element at most once.
#[derive(Debug)]
pub struct MatMut<'a, T> {
    pub(crate) data: &'a mut [T],
    pub(crate) rows: usize,
    pub(crate) cols: usize,
    pub(crate) rs: usize,
    pub(crate) cs: usize,
}

impl<'a, T: Copy> MatMut<'a, T> {
    /// A strided mutable view. Fails if an element is outside `data` or two
    /// `(i, j)` could map to the same element.
    pub fn new(
        data: &'a mut [T],
        rows: usize,
        cols: usize,
        row_stride: usize,
        col_stride: usize,
    ) -> Result<Self, GemmError> {
        let dims = [(rows, row_stride), (cols, col_stride)];
        check_bounds(data.len(), 0, &dims)?;
        check_disjoint(&dims)?;
        Ok(Self {
            data,
            rows,
            cols,
            rs: row_stride,
            cs: col_stride,
        })
    }

    /// A dense row-major view.
    pub fn row_major(data: &'a mut [T], rows: usize, cols: usize) -> Result<Self, GemmError> {
        Self::new(data, rows, cols, cols, 1)
    }

    /// A dense column-major view.
    pub fn col_major(data: &'a mut [T], rows: usize, cols: usize) -> Result<Self, GemmError> {
        Self::new(data, rows, cols, 1, rows)
    }

    /// The transposed view; no data moves.
    #[must_use]
    pub const fn t(self) -> Self {
        Self {
            data: self.data,
            rows: self.cols,
            cols: self.rows,
            rs: self.cs,
            cs: self.rs,
        }
    }

    pub(crate) const fn into_data(self) -> &'a mut [T] {
        self.data
    }

    /// A read-only view of the same elements.
    #[must_use]
    pub const fn as_ref(&self) -> MatRef<'_, T> {
        MatRef {
            data: self.data,
            offset: 0,
            rows: self.rows,
            cols: self.cols,
            rs: self.rs,
            cs: self.cs,
        }
    }

    /// Number of rows.
    #[must_use]
    pub const fn rows(&self) -> usize {
        self.rows
    }

    /// Number of columns.
    #[must_use]
    pub const fn cols(&self) -> usize {
        self.cols
    }
}

/// A read-only strided batch of equally shaped matrices: element `(b, i, j)`
/// lives at `data[b * batch_stride + i * row_stride + j * col_stride]`.
///
/// `batch_stride = 0` broadcasts one matrix to every batch entry.
#[derive(Debug, Clone, Copy)]
pub struct BatchRef<'a, T> {
    pub(crate) data: &'a [T],
    pub(crate) batch: usize,
    pub(crate) rows: usize,
    pub(crate) cols: usize,
    pub(crate) rs: usize,
    pub(crate) cs: usize,
    pub(crate) bs: usize,
}

impl<'a, T: Copy> BatchRef<'a, T> {
    /// A strided batch view. Fails if any addressed element is outside `data`.
    pub fn new(
        data: &'a [T],
        batch: usize,
        rows: usize,
        cols: usize,
        row_stride: usize,
        col_stride: usize,
        batch_stride: usize,
    ) -> Result<Self, GemmError> {
        check_bounds(
            data.len(),
            0,
            &[
                (batch, batch_stride),
                (rows, row_stride),
                (cols, col_stride),
            ],
        )?;
        Ok(Self {
            data,
            batch,
            rows,
            cols,
            rs: row_stride,
            cs: col_stride,
            bs: batch_stride,
        })
    }

    /// `batch` dense row-major matrices stored back to back.
    pub fn row_major(
        data: &'a [T],
        batch: usize,
        rows: usize,
        cols: usize,
    ) -> Result<Self, GemmError> {
        let bs = rows.checked_mul(cols).ok_or(GemmError::Overflow)?;
        Self::new(data, batch, rows, cols, cols, 1, bs)
    }

    /// Every entry transposed; no data moves.
    #[must_use]
    pub const fn t(self) -> Self {
        Self {
            rows: self.cols,
            cols: self.rows,
            rs: self.cs,
            cs: self.rs,
            ..self
        }
    }

    /// Number of matrices.
    #[must_use]
    pub const fn batch(&self) -> usize {
        self.batch
    }

    /// Rows of each matrix.
    #[must_use]
    pub const fn rows(&self) -> usize {
        self.rows
    }

    /// Columns of each matrix.
    #[must_use]
    pub const fn cols(&self) -> usize {
        self.cols
    }

    /// Entry `b` as a matrix view, or `None` if `b >= batch`.
    #[must_use]
    pub const fn get(&self, b: usize) -> Option<MatRef<'a, T>> {
        if b >= self.batch {
            return None;
        }
        Some(self.item(b))
    }

    pub(crate) const fn item(&self, b: usize) -> MatRef<'a, T> {
        MatRef {
            data: self.data,
            offset: b * self.bs,
            rows: self.rows,
            cols: self.cols,
            rs: self.rs,
            cs: self.cs,
        }
    }
}

/// A mutable strided batch. All `(b, i, j)` must address distinct elements;
/// interleaved layouts such as `[rows, batch, cols]` are fine.
#[derive(Debug)]
pub struct BatchMut<'a, T> {
    pub(crate) data: &'a mut [T],
    pub(crate) batch: usize,
    pub(crate) rows: usize,
    pub(crate) cols: usize,
    pub(crate) rs: usize,
    pub(crate) cs: usize,
    pub(crate) bs: usize,
}

impl<'a, T: Copy> BatchMut<'a, T> {
    /// A strided mutable batch view. Fails if an element is outside `data`
    /// or the strides could address an element twice.
    pub fn new(
        data: &'a mut [T],
        batch: usize,
        rows: usize,
        cols: usize,
        row_stride: usize,
        col_stride: usize,
        batch_stride: usize,
    ) -> Result<Self, GemmError> {
        let dims = [
            (batch, batch_stride),
            (rows, row_stride),
            (cols, col_stride),
        ];
        check_bounds(data.len(), 0, &dims)?;
        check_disjoint(&dims)?;
        Ok(Self {
            data,
            batch,
            rows,
            cols,
            rs: row_stride,
            cs: col_stride,
            bs: batch_stride,
        })
    }

    /// `batch` dense row-major matrices stored back to back.
    pub fn row_major(
        data: &'a mut [T],
        batch: usize,
        rows: usize,
        cols: usize,
    ) -> Result<Self, GemmError> {
        let bs = rows.checked_mul(cols).ok_or(GemmError::Overflow)?;
        Self::new(data, batch, rows, cols, cols, 1, bs)
    }

    pub(crate) const fn into_data(self) -> &'a mut [T] {
        self.data
    }

    /// Number of matrices.
    #[must_use]
    pub const fn batch(&self) -> usize {
        self.batch
    }

    /// Rows of each matrix.
    #[must_use]
    pub const fn rows(&self) -> usize {
        self.rows
    }

    /// Columns of each matrix.
    #[must_use]
    pub const fn cols(&self) -> usize {
        self.cols
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounds_and_overlap() {
        let v = [0.0f32; 12];
        assert!(MatRef::row_major(&v, 3, 4).is_ok());
        assert!(MatRef::row_major(&v, 4, 4).is_err());
        assert!(MatRef::new(&v, 100, 0, 7, 7).is_ok());
        assert!(MatRef::new(&v, 3, 4, 0, 0).is_ok());
        assert_eq!(
            MatRef::new(&v, 2, 2, usize::MAX, 1).err(),
            Some(GemmError::Overflow)
        );
        let mut w = [0.0f32; 12];
        assert!(MatMut::new(&mut w, 3, 4, 4, 1).is_ok());
        assert!(matches!(
            MatMut::new(&mut w, 3, 4, 3, 1),
            Err(GemmError::Overlapping { .. })
        ));
        assert!(MatMut::new(&mut w, 3, 4, 0, 1).is_err());
        assert!(MatMut::new(&mut w, 1, 4, 0, 1).is_ok());
        // [rows=2, batch=3, cols=2] interleaved
        assert!(BatchMut::new(&mut w, 3, 2, 2, 6, 1, 2).is_ok());
        assert!(BatchMut::new(&mut w, 3, 2, 2, 6, 1, 1).is_err());
    }
}
