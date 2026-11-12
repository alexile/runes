/// Distance metric used to measure similarity between points during clustering.
///
/// > [!NOTE]
/// > Cosine distance is intentionally excluded: taking the mean of unit vectors does
/// > not produce a unit vector, so the update step would be geometrically unsound.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum Metric {
    /// Straight-line distance: `sqrt(Σ (aᵢ − bᵢ)²)`.
    #[default]
    Euclidean,
    /// City-block distance: `Σ |aᵢ − bᵢ|`.
    Manhattan,
}

/// Squared Euclidean distance between two points.
///
/// Used internally for K-Means++ initialisation weights and inertia
/// computation, where the square avoids an expensive `sqrt`.
pub fn squared_euclidean(a: &[f64], b: &[f64]) -> f64 {
    a.iter().zip(b.iter()).map(|(x, y)| (x - y).powi(2)).sum()
}

/// Distance between two points under the given metric.
pub fn point_distance(metric: &Metric, a: &[f64], b: &[f64]) -> f64 {
    match metric {
        Metric::Euclidean => squared_euclidean(a, b).sqrt(),
        Metric::Manhattan => a.iter().zip(b.iter()).map(|(x, y)| (x - y).abs()).sum(),
    }
}

/// Squared distance between two points under the given metric.
///
/// For Euclidean this avoids a `sqrt`; for Manhattan the value is squared
/// after computing the L1 sum so that inertia units remain consistent.
pub fn squared_distance(metric: &Metric, a: &[f64], b: &[f64]) -> f64 {
    match metric {
        Metric::Euclidean => squared_euclidean(a, b),
        Metric::Manhattan => {
            let d = point_distance(metric, a, b);
            d * d
        }
    }
}
