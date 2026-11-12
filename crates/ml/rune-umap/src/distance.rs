use std::fmt;
use std::str::FromStr;

/// Distance metric for measuring similarity between high-dimensional points.
///
/// Parse from a string with [`str::parse`] (case-insensitive):
///
/// ```rust
/// use rune_umap::Metric;
///
/// let m: Metric = "Correlation".parse().unwrap();
/// assert_eq!(m, Metric::Correlation);
/// assert_eq!(m.to_string(), "correlation");
/// ```
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Metric {
    /// Straight-line distance: `sqrt(Σ (aᵢ − bᵢ)²)`.
    #[default]
    Euclidean,
    /// City-block distance: `Σ |aᵢ − bᵢ|`.
    Manhattan,
    /// Angular distance: `1 − cosine_similarity(a, b)`, in `[0, 2]`.
    ///
    /// A zero vector is at distance `0` from another zero vector and `1` from
    /// everything else.
    Cosine,
    /// Correlation distance: `1 − pearson(a, b)`, in `[0, 2]`.
    ///
    /// Equivalent to cosine distance after centring each point on its own mean.
    /// A constant point is at distance `0` from another constant point and `1`
    /// from everything else.
    Correlation,
}

impl Metric {
    /// All supported metrics, in declaration order.
    pub const ALL: [Self; 4] = [
        Self::Euclidean,
        Self::Manhattan,
        Self::Cosine,
        Self::Correlation,
    ];

    /// The lowercase name of the metric, as accepted by [`str::parse`].
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Euclidean => "euclidean",
            Self::Manhattan => "manhattan",
            Self::Cosine => "cosine",
            Self::Correlation => "correlation",
        }
    }

    /// Distance between `a` and `b` under this metric.
    ///
    /// Both slices are expected to have the same length; extra trailing
    /// values in the longer slice are ignored.
    ///
    /// ```rust
    /// use rune_umap::Metric;
    ///
    /// assert_eq!(Metric::Manhattan.distance(&[0.0, 0.0], &[1.0, 2.0]), 3.0);
    /// assert!((Metric::Euclidean.distance(&[0.0, 0.0], &[3.0, 4.0]) - 5.0).abs() < 1e-12);
    /// ```
    #[must_use]
    pub fn distance(self, a: &[f64], b: &[f64]) -> f64 {
        point_distance(self, a, b)
    }
}

impl fmt::Display for Metric {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// Error returned when parsing an unknown [`Metric`] name.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("unknown metric '{0}' (expected euclidean, manhattan, cosine or correlation)")]
pub struct ParseMetricError(pub String);

impl FromStr for Metric {
    type Err = ParseMetricError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let lower = s.trim().to_ascii_lowercase();
        Self::ALL
            .into_iter()
            .find(|m| m.name() == lower)
            .ok_or_else(|| ParseMetricError(s.to_owned()))
    }
}

/// Distance between two points under the given metric.
///
/// Overflowing distances (finite inputs near `f64::MAX`) saturate to
/// `f64::MAX` so downstream arithmetic never sees `inf` or `NaN`.
pub fn point_distance(metric: Metric, a: &[f64], b: &[f64]) -> f64 {
    let d = match metric {
        Metric::Euclidean => euclidean(a, b),
        Metric::Manhattan => manhattan(a, b),
        Metric::Cosine => cosine_distance(a, b),
        Metric::Correlation => correlation_distance(a, b),
    };
    if d.is_nan() {
        f64::MAX
    } else {
        d.min(f64::MAX)
    }
}

fn euclidean(a: &[f64], b: &[f64]) -> f64 {
    a.iter()
        .zip(b.iter())
        .map(|(x, y)| (x - y).powi(2))
        .sum::<f64>()
        .sqrt()
}

fn manhattan(a: &[f64], b: &[f64]) -> f64 {
    a.iter().zip(b.iter()).map(|(x, y)| (x - y).abs()).sum()
}

fn cosine_distance(a: &[f64], b: &[f64]) -> f64 {
    let dot: f64 = a.iter().zip(b.iter()).map(|(x, y)| x * y).sum();
    let norm_a = a.iter().map(|x| x * x).sum::<f64>().sqrt();
    let norm_b = b.iter().map(|x| x * x).sum::<f64>().sqrt();
    angular(dot, norm_a, norm_b)
}

#[allow(
    clippy::cast_precision_loss,
    reason = "dimensionality stays far below 2^52, so the f64 conversion is exact"
)]
fn correlation_distance(a: &[f64], b: &[f64]) -> f64 {
    let len = a.len().min(b.len());
    if len == 0 {
        return 0.0;
    }
    let n = len as f64;
    let mean_a = a[..len].iter().sum::<f64>() / n;
    let mean_b = b[..len].iter().sum::<f64>() / n;
    let (mut dot, mut ss_a, mut ss_b) = (0.0_f64, 0.0_f64, 0.0_f64);
    for (x, y) in a.iter().zip(b.iter()) {
        let (dx, dy) = (x - mean_a, y - mean_b);
        dot = dx.mul_add(dy, dot);
        ss_a = dx.mul_add(dx, ss_a);
        ss_b = dy.mul_add(dy, ss_b);
    }
    angular(dot, ss_a.sqrt(), ss_b.sqrt())
}

/// `1 − dot / (‖a‖·‖b‖)`, with the degenerate zero-norm cases defined so
/// that identical degenerate points are at distance zero.
fn angular(dot: f64, norm_a: f64, norm_b: f64) -> f64 {
    match (norm_a == 0.0, norm_b == 0.0) {
        (true, true) => 0.0,
        (true, false) | (false, true) => 1.0,
        (false, false) => {
            let d = 1.0 - dot / (norm_a * norm_b);
            if d.is_finite() {
                d.clamp(0.0, 2.0)
            } else {
                1.0
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_values() {
        let a = [1.0, 0.0];
        let b = [0.0, 1.0];
        assert!((Metric::Cosine.distance(&a, &b) - 1.0).abs() < 1e-12);
        assert!((Metric::Cosine.distance(&a, &[-1.0, 0.0]) - 2.0).abs() < 1e-12);
        assert!(Metric::Cosine.distance(&a, &[3.0, 0.0]).abs() < 1e-12);
        // Perfectly correlated / anti-correlated.
        let x = [1.0, 2.0, 3.0];
        assert!(Metric::Correlation.distance(&x, &[2.0, 4.0, 6.0]).abs() < 1e-12);
        assert!((Metric::Correlation.distance(&x, &[3.0, 2.0, 1.0]) - 2.0).abs() < 1e-12);
    }

    #[test]
    fn degenerate_points() {
        let z = [0.0, 0.0];
        assert_eq!(Metric::Cosine.distance(&z, &z), 0.0);
        assert_eq!(Metric::Cosine.distance(&z, &[1.0, 0.0]), 1.0);
        let c = [5.0, 5.0, 5.0];
        assert_eq!(Metric::Correlation.distance(&c, &[1.0, 1.0, 1.0]), 0.0);
        assert_eq!(Metric::Correlation.distance(&c, &[1.0, 2.0, 3.0]), 1.0);
    }

    #[test]
    fn parse_roundtrip() {
        for m in Metric::ALL {
            assert_eq!(m.to_string().parse::<Metric>(), Ok(m));
            assert_eq!(m.name().to_uppercase().parse::<Metric>(), Ok(m));
        }
        assert!("chebyshev".parse::<Metric>().is_err());
    }
}
