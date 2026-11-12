//! Ordinary least-squares line fit.

use crate::Error;
use crate::util::count;

/// Ordinary least-squares fit `y = slope·x + intercept`.
#[derive(Debug, Clone, Copy, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub struct LinearFit {
    /// Fitted slope.
    pub slope: f64,
    /// Fitted intercept.
    pub intercept: f64,
    /// Coefficient of determination in `[0, 1]`; `1` when every `y` is
    /// equal.
    pub r_squared: f64,
}

/// Least-squares regression of `(x, y)` points.
///
/// # Errors
///
/// [`Error::TooFew`] for fewer than two points, [`Error::Nan`] for a `NaN`
/// coordinate, [`Error::Degenerate`] when all `x` are equal.
///
/// ```
/// let fit = rune_stats::linear_regression(&[(0.0, 1.0), (1.0, 3.0), (2.0, 5.0)])?;
/// assert_eq!((fit.slope, fit.intercept), (2.0, 1.0));
/// assert!((fit.r_squared - 1.0).abs() < 1e-12);
/// # Ok::<(), rune_stats::Error>(())
/// ```
pub fn linear_regression(points: &[(f64, f64)]) -> Result<LinearFit, Error> {
    if points.len() < 2 {
        return Err(Error::TooFew {
            needed: 2,
            got: points.len(),
        });
    }
    if points.iter().any(|(x, y)| x.is_nan() || y.is_nan()) {
        return Err(Error::Nan);
    }
    let n = count(points.len());
    let mean_x = points.iter().map(|point| point.0).sum::<f64>() / n;
    let mean_y = points.iter().map(|point| point.1).sum::<f64>() / n;
    let (mut sxx, mut sxy, mut syy) = (0.0, 0.0, 0.0);
    for &(x, y) in points {
        let dx = x - mean_x;
        let dy = y - mean_y;
        sxx = dx.mul_add(dx, sxx);
        sxy = dx.mul_add(dy, sxy);
        syy = dy.mul_add(dy, syy);
    }
    if sxx <= f64::EPSILON {
        return Err(Error::Degenerate("all x values are equal"));
    }
    let slope = sxy / sxx;
    let intercept = slope.mul_add(-mean_x, mean_y);
    let r_squared = if syy <= f64::EPSILON {
        1.0
    } else {
        let correlation = sxy / (sxx.sqrt() * syy.sqrt());
        (correlation * correlation).clamp(0.0, 1.0)
    };
    Ok(LinearFit {
        slope,
        intercept,
        r_squared,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recovers_line() {
        let points: Vec<(f64, f64)> = (0..10)
            .map(|i| {
                let x = f64::from(i);
                (x, 2.0f64.mul_add(x, 1.0))
            })
            .collect();
        let fit = linear_regression(&points).unwrap();
        assert!((fit.slope - 2.0).abs() < 1e-9);
        assert!((fit.intercept - 1.0).abs() < 1e-9);
        assert!((fit.r_squared - 1.0).abs() < 1e-9);
        assert!(matches!(
            linear_regression(&[(1.0, 1.0), (1.0, 2.0)]),
            Err(Error::Degenerate(_))
        ));
    }
}
