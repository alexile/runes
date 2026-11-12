/// Fits `a` and `b` so that `1 / (1 + a·x^(2b))` matches the UMAP target curve
/// defined by `min_dist` and `spread`:
/// - `1.0` for `x < min_dist`
/// - `exp(-(x - min_dist) / spread)` for `x ≥ min_dist`
///
/// Uses Adam optimisation over 300 sample points on `[0, 3·spread]`.
#[allow(
    clippy::cast_precision_loss,
    reason = "counts and indices stay far below 2^52, so the f64 conversion is exact"
)]
pub fn fit_ab(min_dist: f64, spread: f64) -> (f64, f64) {
    const N: usize = 300;
    let xs: Vec<f64> = (0..N)
        .map(|i| i as f64 / (N - 1) as f64 * spread * 3.0)
        .collect();
    let ys: Vec<f64> = xs
        .iter()
        .map(|&x| {
            if x < min_dist {
                1.0
            } else {
                (-(x - min_dist) / spread).exp()
            }
        })
        .collect();

    let mut a = 1.0f64;
    let mut b = 1.0f64;

    let (beta1, beta2, eps) = (0.9_f64, 0.999_f64, 1e-8_f64);
    let (mut m_a, mut m_b) = (0.0_f64, 0.0_f64);
    let (mut v_a, mut v_b) = (0.0_f64, 0.0_f64);
    let lr = 0.05;

    for t in 1..=2000_i32 {
        let (ga, gb) = gradient(&xs, &ys, a, b);

        m_a = f64::mul_add(1.0 - beta1, ga, beta1 * m_a);
        m_b = f64::mul_add(1.0 - beta1, gb, beta1 * m_b);
        v_a = f64::mul_add((1.0 - beta2) * ga, ga, beta2 * v_a);
        v_b = f64::mul_add((1.0 - beta2) * gb, gb, beta2 * v_b);

        let m_hat_a = m_a / (1.0 - beta1.powi(t));
        let m_hat_b = m_b / (1.0 - beta1.powi(t));
        let v_hat_a = v_a / (1.0 - beta2.powi(t));
        let v_hat_b = v_b / (1.0 - beta2.powi(t));

        a -= lr * m_hat_a / (v_hat_a.sqrt() + eps);
        b -= lr * m_hat_b / (v_hat_b.sqrt() + eps);

        a = a.max(0.01);
        b = b.max(0.01);
    }

    (a, b)
}

fn gradient(xs: &[f64], ys: &[f64], a: f64, b: f64) -> (f64, f64) {
    let (mut da, mut db) = (0.0_f64, 0.0_f64);
    for (&x, &y) in xs.iter().zip(ys) {
        if x == 0.0 {
            continue;
        }
        let x2b = x.powf(2.0 * b);
        let denom_sq = a.mul_add(x2b, 1.0).powi(2);
        let pred = 1.0 / a.mul_add(x2b, 1.0);
        let err2 = 2.0 * (pred - y);
        da = err2.mul_add(-x2b / denom_sq, da);
        db = err2.mul_add(-2.0 * a * x2b * x.ln() / denom_sq, db);
    }
    (da, db)
}
