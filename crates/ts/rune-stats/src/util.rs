//! Small shared helpers: lossless-enough casts and input validation.

use crate::Error;

/// Converts a count to `f64`.
#[expect(
    clippy::cast_precision_loss,
    reason = "counts above 2^53 are far beyond any sample this crate handles"
)]
pub const fn count(n: usize) -> f64 {
    n as f64
}

/// Converts an exact integer to `f64`.
#[expect(
    clippy::cast_precision_loss,
    reason = "rounding to the nearest f64 is the intended conversion"
)]
pub const fn int(n: i128) -> f64 {
    n as f64
}

/// Rejects empty samples and samples containing `NaN`.
pub fn check(values: &[f64]) -> Result<(), Error> {
    if values.is_empty() {
        return Err(Error::Empty);
    }
    if values.iter().any(|value| value.is_nan()) {
        return Err(Error::Nan);
    }
    Ok(())
}

/// Like [`check`], and additionally requires ascending order (by
/// [`f64::total_cmp`]).
pub fn check_sorted(values: &[f64]) -> Result<(), Error> {
    check(values)?;
    if values
        .windows(2)
        .any(|pair| pair[0].total_cmp(&pair[1]).is_gt())
    {
        return Err(Error::NotSorted);
    }
    Ok(())
}

/// Copies `values` and sorts the copy by [`f64::total_cmp`].
pub fn sorted_copy(values: &[f64]) -> Result<Vec<f64>, Error> {
    check(values)?;
    let mut sorted = values.to_vec();
    sorted.sort_unstable_by(f64::total_cmp);
    Ok(sorted)
}

/// Validates a confidence level strictly inside `(0, 1)`.
pub fn check_confidence(confidence: f64) -> Result<(), Error> {
    if confidence > 0.0 && confidence < 1.0 {
        Ok(())
    } else {
        Err(Error::InvalidParameter {
            name: "confidence",
            value: confidence,
        })
    }
}
