//! Parametric effect sizes, for reporting next to the rank-based ones.

use crate::Error;
use crate::descriptive::{mean, sum_of_squares};
use crate::util::{check, count};

/// Cohen's d: the difference of means `mean(x) − mean(y)` in units of the
/// pooled sample standard deviation.
///
/// # Errors
///
/// [`Error::TooFew`] with fewer than three observations in total;
/// [`Error::Degenerate`] when both samples have zero spread.
///
/// ```
/// let d = rune_stats::cohens_d(&[2.0, 4.0, 6.0], &[1.0, 3.0, 5.0])?;
/// assert_eq!(d, 0.5);
/// # Ok::<(), rune_stats::Error>(())
/// ```
pub fn cohens_d(x: &[f64], y: &[f64]) -> Result<f64, Error> {
    check(x)?;
    check(y)?;
    let total = x.len() + y.len();
    if total < 3 {
        return Err(Error::TooFew {
            needed: 3,
            got: total,
        });
    }
    let pooled = (sum_of_squares(x)? + sum_of_squares(y)?) / count(total - 2);
    if pooled <= 0.0 {
        return Err(Error::Degenerate("both samples have zero variance"));
    }
    Ok((mean(x)? - mean(y)?) / pooled.sqrt())
}
