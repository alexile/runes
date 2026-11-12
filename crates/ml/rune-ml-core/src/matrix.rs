//! Row-major dense matrices: owned [`Matrix`] and borrowed [`MatrixView`].
//!
//! Both store `rows * cols` elements contiguously, row after row, so row
//! `i` is the slice `data[i * cols..(i + 1) * cols]`. One sample per row is
//! the convention every ML rune follows.

use core::ops::{Index, IndexMut};

use crate::{Float, MlError};

fn checked_len(rows: usize, cols: usize) -> Result<usize, MlError> {
    rows.checked_mul(cols)
        .ok_or(MlError::ShapeOverflow { rows, cols })
}

fn check_buffer(rows: usize, cols: usize, len: usize) -> Result<(), MlError> {
    if checked_len(rows, cols)? == len {
        Ok(())
    } else {
        Err(MlError::BufferLength { rows, cols, len })
    }
}

/// A borrowed, read-only row-major matrix over a flat slice.
///
/// Cheap to copy; obtain one from [`Matrix::view`] or wrap any slice with
/// [`MatrixView::new`]. Algorithms should take a `MatrixView` so callers can
/// pass either owned or borrowed data without copying.
///
/// ```
/// use rune_ml_core::MatrixView;
///
/// let buf = [1.0, 2.0, 3.0, 4.0, 5.0, 6.0];
/// let v = MatrixView::new(&buf, 3, 2)?;
/// assert_eq!(v.row(1), &[3.0, 4.0]);
/// assert_eq!(v[(2, 0)], 5.0);
/// # Ok::<(), rune_ml_core::MlError>(())
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MatrixView<'a, F> {
    data: &'a [F],
    rows: usize,
    cols: usize,
}

/// An owned row-major matrix over a flat `Vec<F>`.
///
/// ```
/// use rune_ml_core::Matrix;
///
/// // Migrate from nested vectors in one call.
/// let rows = vec![vec![1.0, 2.0], vec![3.0, 4.0]];
/// let m = Matrix::from_rows(&rows)?;
/// assert_eq!(m.shape(), (2, 2));
/// assert_eq!(m.transpose().row(0), &[1.0, 3.0]);
/// assert_eq!(m.to_rows(), rows);
/// # Ok::<(), rune_ml_core::MlError>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "serde",
    serde(
        try_from = "MatrixRepr<F>",
        bound(
            serialize = "F: serde::Serialize",
            deserialize = "F: serde::Deserialize<'de>"
        )
    )
)]
pub struct Matrix<F> {
    data: Vec<F>,
    rows: usize,
    cols: usize,
}

#[cfg(feature = "serde")]
#[derive(serde::Deserialize)]
struct MatrixRepr<F> {
    data: Vec<F>,
    rows: usize,
    cols: usize,
}

#[cfg(feature = "serde")]
impl<F> TryFrom<MatrixRepr<F>> for Matrix<F> {
    type Error = MlError;
    fn try_from(r: MatrixRepr<F>) -> Result<Self, MlError> {
        check_buffer(r.rows, r.cols, r.data.len())?;
        Ok(Self {
            data: r.data,
            rows: r.rows,
            cols: r.cols,
        })
    }
}

/// Iterator over the rows of a matrix, as slices.
#[derive(Debug, Clone)]
pub struct Rows<'a, F> {
    data: &'a [F],
    cols: usize,
    remaining: usize,
}

impl<'a, F> Iterator for Rows<'a, F> {
    type Item = &'a [F];

    #[inline]
    fn next(&mut self) -> Option<&'a [F]> {
        if self.remaining == 0 {
            return None;
        }
        self.remaining -= 1;
        let (head, tail) = self.data.split_at(self.cols);
        self.data = tail;
        Some(head)
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.remaining, Some(self.remaining))
    }
}

impl<F> DoubleEndedIterator for Rows<'_, F> {
    #[inline]
    fn next_back(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }
        self.remaining -= 1;
        let (head, tail) = self.data.split_at(self.remaining * self.cols);
        self.data = head;
        Some(tail)
    }
}

impl<F> ExactSizeIterator for Rows<'_, F> {}
impl<F> core::iter::FusedIterator for Rows<'_, F> {}

impl<'a, F: Float> MatrixView<'a, F> {
    /// Wraps a row-major slice of exactly `rows * cols` elements.
    pub fn new(data: &'a [F], rows: usize, cols: usize) -> Result<Self, MlError> {
        check_buffer(rows, cols, data.len())?;
        Ok(Self { data, rows, cols })
    }

    /// Views a single slice as a `1 x n` matrix.
    #[must_use]
    pub const fn from_row(row: &'a [F]) -> Self {
        Self {
            data: row,
            rows: 1,
            cols: row.len(),
        }
    }

    /// Number of rows (samples).
    #[must_use]
    pub const fn nrows(&self) -> usize {
        self.rows
    }

    /// Number of columns (features).
    #[must_use]
    pub const fn ncols(&self) -> usize {
        self.cols
    }

    /// `(rows, cols)`.
    #[must_use]
    pub const fn shape(&self) -> (usize, usize) {
        (self.rows, self.cols)
    }

    /// `true` when the matrix has no rows.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.rows == 0
    }

    /// The underlying row-major buffer.
    #[must_use]
    pub const fn as_slice(&self) -> &'a [F] {
        self.data
    }

    /// Row `i` as a slice.
    ///
    /// # Panics
    ///
    /// If `i >= nrows()`, like slice indexing. Use [`get_row`](Self::get_row)
    /// for a checked variant.
    #[inline]
    #[must_use]
    pub fn row(&self, i: usize) -> &'a [F] {
        &self.data[i * self.cols..(i + 1) * self.cols]
    }

    /// Row `i`, or `None` if out of bounds.
    #[inline]
    #[must_use]
    pub fn get_row(&self, i: usize) -> Option<&'a [F]> {
        (i < self.rows).then(|| self.row(i))
    }

    /// Element `(i, j)`, or `None` if out of bounds.
    #[inline]
    #[must_use]
    pub const fn get(&self, i: usize, j: usize) -> Option<F> {
        if i < self.rows && j < self.cols {
            Some(self.data[i * self.cols + j])
        } else {
            None
        }
    }

    /// Iterator over the rows.
    #[must_use]
    pub const fn rows(&self) -> Rows<'a, F> {
        Rows {
            data: self.data,
            cols: self.cols,
            remaining: self.rows,
        }
    }

    /// Parallel iterator over the rows (`rayon` feature).
    #[cfg(feature = "rayon")]
    #[must_use]
    pub fn par_rows(
        &self,
    ) -> impl rayon::iter::IndexedParallelIterator<Item = &'a [F]> + use<'a, F> {
        use rayon::iter::{IntoParallelIterator, ParallelIterator};
        let (data, cols) = (self.data, self.cols);
        (0..self.rows)
            .into_par_iter()
            .map(move |i| &data[i * cols..(i + 1) * cols])
    }

    /// Iterator over column `j` (empty if `j` is out of bounds).
    pub fn column(&self, j: usize) -> impl ExactSizeIterator<Item = F> + use<'a, F> {
        let (data, cols) = (self.data, self.cols);
        let n = if j < cols { self.rows } else { 0 };
        (0..n).map(move |i| data[i * cols + j])
    }

    /// Copies into an owned [`Matrix`].
    #[must_use]
    pub fn to_matrix(&self) -> Matrix<F> {
        Matrix {
            data: self.data.to_vec(),
            rows: self.rows,
            cols: self.cols,
        }
    }

    /// Copies into nested vectors (one `Vec` per row).
    #[must_use]
    pub fn to_rows(&self) -> Vec<Vec<F>> {
        self.rows().map(<[F]>::to_vec).collect()
    }

    /// Returns the first non-finite element as an error.
    pub fn check_finite(&self) -> Result<(), MlError> {
        self.data
            .iter()
            .position(|v| !v.is_finite())
            .map_or(Ok(()), |p| {
                Err(MlError::NonFinite {
                    row: p.checked_div(self.cols).unwrap_or(0),
                    col: p.checked_rem(self.cols).unwrap_or(0),
                })
            })
    }

    /// Per-column arithmetic mean; all zeros when there are no rows.
    #[must_use]
    pub fn column_means(&self) -> Vec<F> {
        let mut sums = vec![F::ZERO; self.cols];
        for r in self.rows() {
            for (s, &v) in sums.iter_mut().zip(r) {
                *s += v;
            }
        }
        if self.rows > 0 {
            let n = F::from_usize(self.rows);
            for s in &mut sums {
                *s /= n;
            }
        }
        sums
    }

    /// The transpose, as a new matrix.
    #[must_use]
    pub fn transpose(&self) -> Matrix<F> {
        let mut data = vec![F::ZERO; self.data.len()];
        for (i, r) in self.rows().enumerate() {
            for (j, &v) in r.iter().enumerate() {
                data[j * self.rows + i] = v;
            }
        }
        Matrix {
            data,
            rows: self.cols,
            cols: self.rows,
        }
    }

    /// Matrix product `self · rhs`.
    pub fn matmul(&self, rhs: MatrixView<'_, F>) -> Result<Matrix<F>, MlError> {
        if self.cols != rhs.rows {
            return Err(MlError::DimensionMismatch {
                expected: self.cols,
                found: rhs.rows,
            });
        }
        checked_len(self.rows, rhs.cols)?;
        let mut out = Matrix::zeros(self.rows, rhs.cols)?;
        if rhs.cols == 0 {
            return Ok(out);
        }
        // i-k-j order: streams through contiguous rows of `rhs` and `out`.
        for (a_row, o_row) in self.rows().zip(out.data.chunks_exact_mut(rhs.cols)) {
            for (&a, b_row) in a_row.iter().zip(rhs.rows()) {
                crate::kernels::axpy(a, b_row, o_row);
            }
        }
        Ok(out)
    }

    /// Gathers the given rows (in order, repeats allowed) into a new matrix.
    pub fn select_rows(&self, indices: &[usize]) -> Result<Matrix<F>, MlError> {
        let mut data = Vec::with_capacity(checked_len(indices.len(), self.cols)?);
        for &i in indices {
            let r = self.get_row(i).ok_or(MlError::IndexOutOfBounds {
                index: i,
                len: self.rows,
            })?;
            data.extend_from_slice(r);
        }
        Ok(Matrix {
            data,
            rows: indices.len(),
            cols: self.cols,
        })
    }

    /// Converts every element to another precision.
    #[must_use]
    pub fn cast<G: Float>(&self) -> Matrix<G> {
        Matrix {
            data: self.data.iter().map(|v| G::from_f64(v.to_f64())).collect(),
            rows: self.rows,
            cols: self.cols,
        }
    }
}

impl<F: Float> Index<(usize, usize)> for MatrixView<'_, F> {
    type Output = F;

    /// # Panics
    ///
    /// If `(i, j)` is out of bounds.
    #[inline]
    fn index(&self, (i, j): (usize, usize)) -> &F {
        &self.row(i)[j]
    }
}

impl<F: Float> Matrix<F> {
    /// Takes ownership of a row-major buffer of exactly `rows * cols` elements.
    pub fn from_vec(data: Vec<F>, rows: usize, cols: usize) -> Result<Self, MlError> {
        check_buffer(rows, cols, data.len())?;
        Ok(Self { data, rows, cols })
    }

    /// A `rows x cols` matrix of zeros.
    pub fn zeros(rows: usize, cols: usize) -> Result<Self, MlError> {
        Self::filled(rows, cols, F::ZERO)
    }

    /// A `rows x cols` matrix with every element set to `value`.
    pub fn filled(rows: usize, cols: usize, value: F) -> Result<Self, MlError> {
        let len = checked_len(rows, cols)?;
        Ok(Self {
            data: vec![value; len],
            rows,
            cols,
        })
    }

    /// The `n x n` identity matrix.
    pub fn identity(n: usize) -> Result<Self, MlError> {
        let mut m = Self::zeros(n, n)?;
        for i in 0..n {
            m.data[i * n + i] = F::ONE;
        }
        Ok(m)
    }

    /// Builds a matrix from `f(i, j)`.
    pub fn from_fn(
        rows: usize,
        cols: usize,
        mut f: impl FnMut(usize, usize) -> F,
    ) -> Result<Self, MlError> {
        let len = checked_len(rows, cols)?;
        let mut data = Vec::with_capacity(len);
        for i in 0..rows {
            for j in 0..cols {
                data.push(f(i, j));
            }
        }
        Ok(Self { data, rows, cols })
    }

    /// Copies nested rows (`&[Vec<F>]`, `&[[F; N]]`, `&[&[F]]`, …) into a
    /// matrix. Every row must have the same length; no rows gives `0 x 0`.
    pub fn from_rows<R: AsRef<[F]>>(rows: &[R]) -> Result<Self, MlError> {
        let cols = rows.first().map_or(0, |r| r.as_ref().len());
        let mut data = Vec::with_capacity(checked_len(rows.len(), cols)?);
        for (i, r) in rows.iter().enumerate() {
            let r = r.as_ref();
            if r.len() != cols {
                return Err(MlError::RaggedRows {
                    row: i,
                    expected: cols,
                    found: r.len(),
                });
            }
            data.extend_from_slice(r);
        }
        Ok(Self {
            data,
            rows: rows.len(),
            cols,
        })
    }

    /// Like [`from_rows`](Self::from_rows) but converting from another
    /// precision, e.g. `Matrix::<f32>::from_rows_cast(&vec_of_f64_rows)`.
    pub fn from_rows_cast<G: Float, R: AsRef<[G]>>(rows: &[R]) -> Result<Self, MlError> {
        Ok(Matrix::<G>::from_rows(rows)?.view().cast())
    }

    /// Borrows as a [`MatrixView`].
    #[inline]
    #[must_use]
    pub fn view(&self) -> MatrixView<'_, F> {
        MatrixView {
            data: &self.data,
            rows: self.rows,
            cols: self.cols,
        }
    }

    /// Number of rows (samples).
    #[must_use]
    pub const fn nrows(&self) -> usize {
        self.rows
    }

    /// Number of columns (features).
    #[must_use]
    pub const fn ncols(&self) -> usize {
        self.cols
    }

    /// `(rows, cols)`.
    #[must_use]
    pub const fn shape(&self) -> (usize, usize) {
        (self.rows, self.cols)
    }

    /// `true` when the matrix has no rows.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.rows == 0
    }

    /// The underlying row-major buffer.
    #[must_use]
    pub fn as_slice(&self) -> &[F] {
        &self.data
    }

    /// The underlying row-major buffer, mutably.
    #[must_use]
    pub fn as_mut_slice(&mut self) -> &mut [F] {
        &mut self.data
    }

    /// Consumes the matrix and returns its row-major buffer.
    #[must_use]
    pub fn into_vec(self) -> Vec<F> {
        self.data
    }

    /// Row `i` as a slice.
    ///
    /// # Panics
    ///
    /// If `i >= nrows()`. Use [`get_row`](Self::get_row) for a checked variant.
    #[inline]
    #[must_use]
    pub fn row(&self, i: usize) -> &[F] {
        &self.data[i * self.cols..(i + 1) * self.cols]
    }

    /// Row `i`, mutably.
    ///
    /// # Panics
    ///
    /// If `i >= nrows()`.
    #[inline]
    #[must_use]
    pub fn row_mut(&mut self, i: usize) -> &mut [F] {
        &mut self.data[i * self.cols..(i + 1) * self.cols]
    }

    /// Row `i`, or `None` if out of bounds.
    #[inline]
    #[must_use]
    pub fn get_row(&self, i: usize) -> Option<&[F]> {
        self.view().get_row(i)
    }

    /// Element `(i, j)`, or `None` if out of bounds.
    #[inline]
    #[must_use]
    pub fn get(&self, i: usize, j: usize) -> Option<F> {
        self.view().get(i, j)
    }

    /// Iterator over the rows.
    #[must_use]
    pub fn rows(&self) -> Rows<'_, F> {
        self.view().rows()
    }

    /// Iterator over the rows (same as [`rows`](Self::rows)).
    #[must_use]
    pub fn iter(&self) -> Rows<'_, F> {
        self.rows()
    }

    /// Iterator over mutable rows.
    pub fn rows_mut(&mut self) -> impl ExactSizeIterator<Item = &mut [F]> {
        let (rows, cols) = (self.rows, self.cols);
        let mut rest: &mut [F] = &mut self.data;
        (0..rows).map(move |_| {
            let (head, tail) = core::mem::take(&mut rest).split_at_mut(cols);
            rest = tail;
            head
        })
    }

    /// Parallel iterator over the rows (`rayon` feature).
    #[cfg(feature = "rayon")]
    #[must_use]
    pub fn par_rows(&self) -> impl rayon::iter::IndexedParallelIterator<Item = &[F]> + '_ {
        self.view().par_rows()
    }

    /// Iterator over column `j` (empty if `j` is out of bounds).
    pub fn column(&self, j: usize) -> impl ExactSizeIterator<Item = F> + '_ {
        self.view().column(j)
    }

    /// Appends a row. On an empty `0 x 0` matrix the row sets the width.
    pub fn push_row(&mut self, row: &[F]) -> Result<(), MlError> {
        if self.rows == 0 && self.cols == 0 {
            self.cols = row.len();
        } else if row.len() != self.cols {
            return Err(MlError::DimensionMismatch {
                expected: self.cols,
                found: row.len(),
            });
        }
        self.data.extend_from_slice(row);
        self.rows += 1;
        Ok(())
    }

    /// Applies `f` to every element in place.
    pub fn map_inplace(&mut self, mut f: impl FnMut(F) -> F) {
        for v in &mut self.data {
            *v = f(*v);
        }
    }

    /// Copies into nested vectors (one `Vec` per row).
    #[must_use]
    pub fn to_rows(&self) -> Vec<Vec<F>> {
        self.view().to_rows()
    }

    /// Returns the first non-finite element as an error.
    pub fn check_finite(&self) -> Result<(), MlError> {
        self.view().check_finite()
    }

    /// Per-column arithmetic mean; all zeros when there are no rows.
    #[must_use]
    pub fn column_means(&self) -> Vec<F> {
        self.view().column_means()
    }

    /// The transpose, as a new matrix.
    #[must_use]
    pub fn transpose(&self) -> Self {
        self.view().transpose()
    }

    /// Matrix product `self · rhs`.
    pub fn matmul(&self, rhs: MatrixView<'_, F>) -> Result<Self, MlError> {
        self.view().matmul(rhs)
    }

    /// Gathers the given rows (in order, repeats allowed) into a new matrix.
    pub fn select_rows(&self, indices: &[usize]) -> Result<Self, MlError> {
        self.view().select_rows(indices)
    }

    /// Converts every element to another precision.
    #[must_use]
    pub fn cast<G: Float>(&self) -> Matrix<G> {
        self.view().cast()
    }
}

impl<F: Float> Index<(usize, usize)> for Matrix<F> {
    type Output = F;

    /// # Panics
    ///
    /// If `(i, j)` is out of bounds.
    #[inline]
    fn index(&self, (i, j): (usize, usize)) -> &F {
        &self.row(i)[j]
    }
}

impl<F: Float> IndexMut<(usize, usize)> for Matrix<F> {
    /// # Panics
    ///
    /// If `(i, j)` is out of bounds.
    #[inline]
    fn index_mut(&mut self, (i, j): (usize, usize)) -> &mut F {
        &mut self.row_mut(i)[j]
    }
}

impl<'a, F: Float> From<&'a Matrix<F>> for MatrixView<'a, F> {
    fn from(m: &'a Matrix<F>) -> Self {
        m.view()
    }
}

impl<F: Float> TryFrom<&[Vec<F>]> for Matrix<F> {
    type Error = MlError;
    fn try_from(rows: &[Vec<F>]) -> Result<Self, MlError> {
        Self::from_rows(rows)
    }
}

impl<F: Float> TryFrom<&Vec<Vec<F>>> for Matrix<F> {
    type Error = MlError;
    fn try_from(rows: &Vec<Vec<F>>) -> Result<Self, MlError> {
        Self::from_rows(rows)
    }
}

impl<F: Float> TryFrom<Vec<Vec<F>>> for Matrix<F> {
    type Error = MlError;
    fn try_from(rows: Vec<Vec<F>>) -> Result<Self, MlError> {
        Self::from_rows(&rows)
    }
}

impl<F: Float> From<Matrix<F>> for Vec<Vec<F>> {
    fn from(m: Matrix<F>) -> Self {
        m.to_rows()
    }
}

impl<'a, F: Float> IntoIterator for &'a Matrix<F> {
    type Item = &'a [F];
    type IntoIter = Rows<'a, F>;
    fn into_iter(self) -> Rows<'a, F> {
        self.rows()
    }
}

impl<'a, F: Float> IntoIterator for MatrixView<'a, F> {
    type Item = &'a [F];
    type IntoIter = Rows<'a, F>;
    fn into_iter(self) -> Rows<'a, F> {
        self.rows()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shapes_and_errors() {
        assert_eq!(
            Matrix::from_vec(vec![1.0_f64; 5], 2, 3),
            Err(MlError::BufferLength {
                rows: 2,
                cols: 3,
                len: 5
            })
        );
        assert_eq!(
            Matrix::<f64>::zeros(usize::MAX, 2),
            Err(MlError::ShapeOverflow {
                rows: usize::MAX,
                cols: 2
            })
        );
        let ragged = vec![vec![1.0_f64, 2.0], vec![3.0]];
        assert_eq!(
            Matrix::from_rows(&ragged),
            Err(MlError::RaggedRows {
                row: 1,
                expected: 2,
                found: 1
            })
        );
        let empty: Vec<Vec<f64>> = vec![];
        assert_eq!(Matrix::from_rows(&empty).map(|m| m.shape()), Ok((0, 0)));
    }

    #[test]
    fn zero_width_rows() {
        let m = Matrix::<f32>::zeros(3, 0).unwrap();
        assert_eq!(m.rows().count(), 3);
        assert!(m.rows().all(<[f32]>::is_empty));
        assert_eq!(m.rows().rev().count(), 3);
        assert_eq!(m.transpose().shape(), (0, 3));
        assert_eq!(m.check_finite(), Ok(()));
    }

    #[test]
    fn accessors() {
        let mut m =
            Matrix::from_fn(3, 2, |i, j| f64::from(u32::try_from(i * 10 + j).unwrap())).unwrap();
        assert_eq!(m[(2, 1)], 21.0);
        m[(2, 1)] = -1.0;
        assert_eq!(m.get(2, 1), Some(-1.0));
        assert_eq!(m.get(3, 0), None);
        assert_eq!(m.get_row(3), None);
        assert_eq!(m.column(0).collect::<Vec<_>>(), vec![0.0, 10.0, 20.0]);
        assert_eq!(m.column(5).count(), 0);
        assert_eq!(m.rows().next_back(), Some(&[20.0, -1.0][..]));
        for r in m.rows_mut() {
            r[0] = 7.0;
        }
        assert_eq!(m.column(0).collect::<Vec<_>>(), vec![7.0; 3]);
        assert_eq!(m.column_means(), vec![7.0, (1.0 + 11.0 - 1.0) / 3.0]);
    }

    #[test]
    fn push_and_select() {
        let mut m = Matrix::<f64>::default();
        m.push_row(&[1.0, 2.0]).unwrap();
        m.push_row(&[3.0, 4.0]).unwrap();
        assert!(m.push_row(&[1.0]).is_err());
        let s = m.select_rows(&[1, 1, 0]).unwrap();
        assert_eq!(
            s.to_rows(),
            vec![vec![3.0, 4.0], vec![3.0, 4.0], vec![1.0, 2.0]]
        );
        assert_eq!(
            m.select_rows(&[2]),
            Err(MlError::IndexOutOfBounds { index: 2, len: 2 })
        );
    }

    #[test]
    fn matmul_identity_and_mismatch() {
        let a = Matrix::from_rows(&[[1.0_f64, 2.0, 3.0], [4.0, 5.0, 6.0]]).unwrap();
        let i3 = Matrix::identity(3).unwrap();
        assert_eq!(a.matmul(i3.view()).unwrap(), a);
        let p = a.matmul(a.transpose().view()).unwrap();
        assert_eq!(p.to_rows(), vec![vec![14.0, 32.0], vec![32.0, 77.0]]);
        assert!(a.matmul(a.view()).is_err());
    }

    #[test]
    fn non_finite_location() {
        let m = Matrix::from_rows(&[[1.0_f64, 2.0], [3.0, f64::NAN]]).unwrap();
        assert_eq!(m.check_finite(), Err(MlError::NonFinite { row: 1, col: 1 }));
    }

    #[test]
    fn cast_between_precisions() {
        let rows = vec![vec![0.5_f64, 1.25]];
        let m: Matrix<f32> = Matrix::from_rows_cast(&rows).unwrap();
        assert_eq!(m.row(0), &[0.5_f32, 1.25]);
        assert_eq!(m.cast::<f64>().to_rows(), rows);
    }

    #[test]
    fn conversions() {
        let rows = vec![vec![1.0_f64], vec![2.0]];
        let m = Matrix::try_from(&rows).unwrap();
        let back: Vec<Vec<f64>> = m.clone().into();
        assert_eq!(back, rows);
        let v: MatrixView<'_, f64> = (&m).into();
        assert_eq!(v.into_iter().count(), 2);
        assert_eq!((&m).into_iter().count(), 2);
    }
}
