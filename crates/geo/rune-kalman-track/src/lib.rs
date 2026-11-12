//! A 2D constant-velocity Kalman filter for smoothing noisy position/velocity
//! readings — GPS fixes, radar returns, any noisy 2D position sensor.
//!
//! Tracks a 4-element state `[x, y, vx, vy]` and its 4x4 error covariance.
//! [`KalmanTrack::predict`] advances the state under a constant-velocity motion
//! model and grows uncertainty by the configured process noise;
//! [`KalmanTrack::update`] folds in a new position measurement and shrinks
//! uncertainty accordingly. The matrix math is hand-rolled for this fixed 4-state,
//! 2-observation shape — no external linear-algebra dependency.
//!
//! # Features
//!
//! - Constant-velocity motion model (position advances by velocity × dt).
//! - Full 4x4 covariance propagation, not just a diagonal approximation.
//! - Position-only measurement updates (2D fixes), velocity is inferred.
//!
//! # Quick Start
//!
//! ```rust
//! use rune_kalman_track::KalmanTrack;
//!
//! let mut track = KalmanTrack::new(0.0, 0.0, 0.01, 1.0);
//! track.predict(1.0);
//! track.update(1.0, 0.0);
//! let (x, y) = track.position();
//! assert!(x > 0.0 && x < 1.5);
//! ```
//!
//! # CLI
//!
//! ```bash
//! rune-kalman-track 0.0,0.0 1.0,0.1 2.1,-0.1 3.0,0.2
//! ```

type Mat4 = [[f64; 4]; 4];
type Vec4 = [f64; 4];

fn mat4_mult(a: &Mat4, b: &Mat4) -> Mat4 {
    let mut out = [[0.0; 4]; 4];
    for i in 0..4 {
        for j in 0..4 {
            let mut sum = 0.0;
            for k in 0..4 {
                sum = a[i][k].mul_add(b[k][j], sum);
            }
            out[i][j] = sum;
        }
    }
    out
}

fn mat4_transpose(a: &Mat4) -> Mat4 {
    let mut out = [[0.0; 4]; 4];
    for i in 0..4 {
        for j in 0..4 {
            out[j][i] = a[i][j];
        }
    }
    out
}

fn mat4_add(a: &Mat4, b: &Mat4) -> Mat4 {
    let mut out = [[0.0; 4]; 4];
    for i in 0..4 {
        for j in 0..4 {
            out[i][j] = a[i][j] + b[i][j];
        }
    }
    out
}

/// A 2D constant-velocity Kalman filter tracking `[x, y, vx, vy]`.
pub struct KalmanTrack {
    state: Vec4,
    covariance: Mat4,
    process_noise: f64,
    measurement_noise: f64,
}

impl KalmanTrack {
    /// Creates a new tracker at `(initial_x, initial_y)` with zero initial velocity.
    ///
    /// `process_noise` controls how much uncertainty [`predict`](Self::predict) adds per
    /// second of elapsed time; `measurement_noise` controls how much a single
    /// [`update`](Self::update) is trusted.
    #[must_use]
    pub const fn new(
        initial_x: f64,
        initial_y: f64,
        process_noise: f64,
        measurement_noise: f64,
    ) -> Self {
        Self {
            state: [initial_x, initial_y, 0.0, 0.0],
            covariance: [
                [1.0, 0.0, 0.0, 0.0],
                [0.0, 1.0, 0.0, 0.0],
                [0.0, 0.0, 1.0, 0.0],
                [0.0, 0.0, 0.0, 1.0],
            ],
            process_noise,
            measurement_noise,
        }
    }

    /// Advances the state by `dt_s` seconds under the constant-velocity model and
    /// grows the covariance by the configured process noise.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_kalman_track::KalmanTrack;
    ///
    /// let mut track = KalmanTrack::new(0.0, 0.0, 0.0, 1.0);
    /// track.predict(2.0);
    /// assert_eq!(track.position(), (0.0, 0.0)); // zero initial velocity, no movement yet
    /// ```
    pub fn predict(&mut self, dt_s: f64) {
        let f: Mat4 = [
            [1.0, 0.0, dt_s, 0.0],
            [0.0, 1.0, 0.0, dt_s],
            [0.0, 0.0, 1.0, 0.0],
            [0.0, 0.0, 0.0, 1.0],
        ];

        let mut new_state = [0.0; 4];
        for i in 0..4 {
            new_state[i] = (0..4).map(|j| f[i][j] * self.state[j]).sum();
        }
        self.state = new_state;

        let ft = mat4_transpose(&f);
        let fp = mat4_mult(&f, &self.covariance);
        let fpft = mat4_mult(&fp, &ft);

        let q: Mat4 = {
            let mut q = [[0.0; 4]; 4];
            for (i, row) in q.iter_mut().enumerate() {
                row[i] = self.process_noise * dt_s.max(0.0);
            }
            q
        };

        self.covariance = mat4_add(&fpft, &q);
    }

    /// Folds in a new position measurement `(measured_x, measured_y)`.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_kalman_track::KalmanTrack;
    ///
    /// let mut track = KalmanTrack::new(0.0, 0.0, 0.01, 0.5);
    /// track.update(1.0, 1.0);
    /// let (x, y) = track.position();
    /// assert!(x > 0.0 && y > 0.0);
    /// ```
    pub fn update(&mut self, measured_x: f64, measured_y: f64) {
        let innovation = [measured_x - self.state[0], measured_y - self.state[1]];

        let p = &self.covariance;
        let r = self.measurement_noise;

        // S = H P H^T + R, restricted to the position 2x2 block of P.
        let s00 = p[0][0] + r;
        let s01 = p[0][1];
        let s10 = p[1][0];
        let s11 = p[1][1] + r;

        let det = s01.mul_add(-s10, s00 * s11);
        if det.abs() < 1e-12 {
            return;
        }
        let inv00 = s11 / det;
        let inv01 = -s01 / det;
        let inv10 = -s10 / det;
        let inv11 = s00 / det;

        // K = P H^T S^-1 (4x2), where P H^T is just the first two columns of P.
        let mut k = [[0.0; 2]; 4];
        for i in 0..4 {
            let ph0 = p[i][0];
            let ph1 = p[i][1];
            k[i][0] = ph1.mul_add(inv10, ph0 * inv00);
            k[i][1] = ph1.mul_add(inv11, ph0 * inv01);
        }

        for (i, s) in self.state.iter_mut().enumerate() {
            *s += f64::mul_add(k[i][1], innovation[1], k[i][0] * innovation[0]);
        }

        // P = (I - K H) P, where (K H)[i][0] = K[i][0], (K H)[i][1] = K[i][1], else 0.
        let mut kh: Mat4 = [[0.0; 4]; 4];
        for i in 0..4 {
            kh[i][0] = k[i][0];
            kh[i][1] = k[i][1];
        }
        let mut i_minus_kh: Mat4 = [[0.0; 4]; 4];
        for i in 0..4 {
            for j in 0..4 {
                i_minus_kh[i][j] = if i == j { 1.0 } else { 0.0 } - kh[i][j];
            }
        }
        self.covariance = mat4_mult(&i_minus_kh, &self.covariance);
    }

    /// Current position estimate.
    #[must_use]
    pub const fn position(&self) -> (f64, f64) {
        (self.state[0], self.state[1])
    }

    /// Current velocity estimate, in units per second.
    #[must_use]
    pub const fn velocity(&self) -> (f64, f64) {
        (self.state[2], self.state[3])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repeated_identical_measurements_converge_to_that_point() {
        let mut track = KalmanTrack::new(0.0, 0.0, 0.001, 0.1);
        for _ in 0..50 {
            track.predict(1.0);
            track.update(5.0, 5.0);
        }
        let (x, y) = track.position();
        assert!((x - 5.0).abs() < 0.05, "x={x}");
        assert!((y - 5.0).abs() < 0.05, "y={y}");
    }

    #[allow(clippy::similar_names, reason = "parallel names for parallel fixtures")]
    #[test]
    fn constant_velocity_target_converges_velocity_estimate() {
        let mut track = KalmanTrack::new(0.0, 0.0, 0.1, 0.01);
        let true_vx = 2.0;
        let true_vy = -1.0;
        let mut true_x = 0.0;
        let mut true_y = 0.0;

        for _ in 0..100 {
            true_x += true_vx;
            true_y += true_vy;
            track.predict(1.0);
            track.update(true_x, true_y);
        }

        let (vx, vy) = track.velocity();
        assert!((vx - true_vx).abs() < 0.2, "vx={vx}");
        assert!((vy - true_vy).abs() < 0.2, "vy={vy}");
    }

    #[allow(
        clippy::cast_precision_loss,
        reason = "counts and indices stay far below 2^52, so the f64 conversion is exact"
    )]
    #[test]
    fn smooths_noisy_measurements_around_a_constant_position() {
        // Start at the true position so the comparison below measures noise
        // smoothing, not the unrelated initial-convergence transient.
        let mut track = KalmanTrack::new(10.0, 10.0, 0.001, 1.0);
        // Deterministic pseudo-noise: alternates above/below the true point.
        let offsets = [0.5, -0.5, 0.4, -0.4, 0.6, -0.6, 0.3, -0.3, 0.5, -0.5];

        let mut raw_variance_sum = 0.0;
        for &offset in &offsets {
            track.predict(1.0);
            track.update(10.0 + offset, 10.0 + offset);
            raw_variance_sum = f64::mul_add(offset, offset, raw_variance_sum);
        }

        let (x, y) = track.position();
        let smoothed_error = (y - 10.0).mul_add(y - 10.0, (x - 10.0).powi(2));
        let raw_error_avg = raw_variance_sum / offsets.len() as f64;

        assert!(
            smoothed_error < raw_error_avg,
            "smoothed_error={smoothed_error} raw_error_avg={raw_error_avg}"
        );
    }

    #[test]
    fn predict_without_update_advances_by_velocity_times_dt() {
        let mut track = KalmanTrack::new(0.0, 0.0, 0.01, 0.1);
        // Seed a known velocity via two updates a second apart.
        track.predict(1.0);
        track.update(0.0, 0.0);
        track.predict(1.0);
        track.update(1.0, 0.0);

        let (before_x, _) = track.position();
        let (vx, _) = track.velocity();
        track.predict(1.0);
        let (after_x, _) = track.position();

        assert!((after_x - (before_x + vx)).abs() < 1e-9);
    }

    #[test]
    fn new_tracker_starts_at_initial_position_with_zero_velocity() {
        let track = KalmanTrack::new(3.0, 4.0, 0.1, 0.1);
        assert_eq!(track.position(), (3.0, 4.0));
        assert_eq!(track.velocity(), (0.0, 0.0));
    }
}
