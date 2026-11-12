//! Stop/dwell-time detection from a stream of timestamped positions.
//!
//! Tracks whether recent positions stay within a radius of an anchor point long
//! enough to count as a genuine stop, as opposed to noise (briefly leaving the
//! radius before any meaningful time has passed) or continuous movement.
//!
//! # Features
//!
//! - [`DwellDetector::update`] — feed one `(ts_ms, lat, lon)` sample at a time;
//!   returns a completed [`DwellEvent`] whenever a qualifying stop just ended.
//! - [`DwellDetector::flush`] — close out a stop still in progress at stream end.
//!
//! # Quick Start
//!
//! ```rust
//! use rune_dwell::DwellDetector;
//!
//! let mut d = DwellDetector::new(50.0, 60_000); // 50m radius, 60s minimum dwell
//! assert!(d.update(0, 60.17, 24.94).is_none());
//! assert!(d.update(90_000, 60.17, 24.94).is_none()); // still within radius
//! let event = d.update(91_000, 61.0, 24.94).unwrap(); // jumped far away
//! assert_eq!(event.duration_ms, 90_000);
//! ```
//!
//! # CLI
//!
//! ```bash
//! rune-dwell 50 60000 trace.csv
//! ```

const EARTH_RADIUS_M: f64 = 6_371_000.0;

fn haversine_m(lat1: f64, lon1: f64, lat2: f64, lon2: f64) -> f64 {
    let (lat1r, lat2r) = (lat1.to_radians(), lat2.to_radians());
    let dlat = (lat2 - lat1).to_radians();
    let dlon = (lon2 - lon1).to_radians();
    let a = (dlat / 2.0).sin().mul_add(
        (dlat / 2.0).sin(),
        lat1r.cos() * lat2r.cos() * (dlon / 2.0).sin().powi(2),
    );
    2.0 * EARTH_RADIUS_M * a.sqrt().asin()
}

/// A completed stop: the anchor position and how long the stream dwelled near it.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct DwellEvent {
    /// Timestamp of the first fix in the dwell, in milliseconds.
    pub start_ms: i64,
    /// Timestamp of the last fix in the dwell, in milliseconds.
    pub end_ms: i64,
    /// Latitude of the dwell anchor.
    pub lat: f64,
    /// Longitude of the dwell anchor.
    pub lon: f64,
    /// `end_ms - start_ms`.
    pub duration_ms: i64,
}

/// Detects stops (dwell periods) in a position stream.
///
/// A stop is a run of positions all within `radius_m` of an anchor point, lasting
/// at least `min_dwell_ms`. Leaving the radius before `min_dwell_ms` has elapsed is
/// treated as noise, not a stop, and does not emit an event.
pub struct DwellDetector {
    radius_m: f64,
    min_dwell_ms: i64,
    anchor: Option<(f64, f64)>,
    start_ms: i64,
    last_ms: i64,
}

impl DwellDetector {
    /// Creates a detector requiring positions to stay within `radius_m` metres of
    /// an anchor for at least `min_dwell_ms` milliseconds to count as a stop.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_dwell::DwellDetector;
    ///
    /// let d = DwellDetector::new(25.0, 30_000);
    /// ```
    #[must_use]
    pub const fn new(radius_m: f64, min_dwell_ms: i64) -> Self {
        Self {
            radius_m,
            min_dwell_ms,
            anchor: None,
            start_ms: 0,
            last_ms: 0,
        }
    }

    /// Feeds one timestamped position into the detector.
    ///
    /// Returns a [`DwellEvent`] whenever a qualifying stop (dwelled at least
    /// `min_dwell_ms`) just ended because the position moved outside the radius.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_dwell::DwellDetector;
    ///
    /// let mut d = DwellDetector::new(10.0, 1_000);
    /// assert!(d.update(0, 0.0, 0.0).is_none());
    /// assert!(d.update(1_500, 0.0, 0.0).is_none()); // still within radius, dwell accrues
    /// assert!(d.update(2_000, 10.0, 10.0).is_some()); // now leaves; qualifying stop just ended
    /// ```
    pub fn update(&mut self, ts_ms: i64, lat: f64, lon: f64) -> Option<DwellEvent> {
        match self.anchor {
            None => {
                self.anchor = Some((lat, lon));
                self.start_ms = ts_ms;
                self.last_ms = ts_ms;
                None
            }
            Some((alat, alon)) => {
                if haversine_m(alat, alon, lat, lon) <= self.radius_m {
                    self.last_ms = ts_ms;
                    None
                } else {
                    let duration_ms = self.last_ms - self.start_ms;
                    let event = if duration_ms >= self.min_dwell_ms {
                        Some(DwellEvent {
                            start_ms: self.start_ms,
                            end_ms: self.last_ms,
                            lat: alat,
                            lon: alon,
                            duration_ms,
                        })
                    } else {
                        None
                    };
                    self.anchor = Some((lat, lon));
                    self.start_ms = ts_ms;
                    self.last_ms = ts_ms;
                    event
                }
            }
        }
    }

    /// Closes out an in-progress stop at stream end, if it already met
    /// `min_dwell_ms` as of `now_ms`. Clears the detector's state either way.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rune_dwell::DwellDetector;
    ///
    /// let mut d = DwellDetector::new(10.0, 1_000);
    /// d.update(0, 0.0, 0.0);
    /// assert!(d.flush(2_000).is_some());
    /// ```
    pub fn flush(&mut self, now_ms: i64) -> Option<DwellEvent> {
        let event = self.anchor.and_then(|(lat, lon)| {
            let duration_ms = now_ms - self.start_ms;
            if duration_ms >= self.min_dwell_ms {
                Some(DwellEvent {
                    start_ms: self.start_ms,
                    end_ms: now_ms,
                    lat,
                    lon,
                    duration_ms,
                })
            } else {
                None
            }
        });
        self.anchor = None;
        event
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn qualifying_stop_then_departure_emits_one_event() {
        let mut d = DwellDetector::new(50.0, 60_000);
        assert!(d.update(0, 60.17, 24.94).is_none());
        assert!(d.update(30_000, 60.1701, 24.94).is_none());
        assert!(d.update(90_000, 60.1701, 24.94).is_none());
        let event = d.update(91_000, 61.0, 24.94).unwrap();
        assert_eq!(event.start_ms, 0);
        assert_eq!(event.end_ms, 90_000);
        assert_eq!(event.duration_ms, 90_000);
    }

    #[test]
    fn brief_noise_before_min_dwell_emits_nothing() {
        let mut d = DwellDetector::new(10.0, 60_000);
        assert!(d.update(0, 0.0, 0.0).is_none());
        assert!(d.update(1_000, 5.0, 5.0).is_none()); // far, before min_dwell met
    }

    #[allow(
        clippy::cast_precision_loss,
        reason = "counts and indices stay far below 2^52, so the f64 conversion is exact"
    )]
    #[test]
    fn continuous_movement_emits_nothing() {
        let mut d = DwellDetector::new(1.0, 60_000);
        for i in 0..10 {
            let lat = i as f64 * 0.01;
            assert!(d.update(i * 1_000, lat, 0.0).is_none());
        }
    }

    #[test]
    fn flush_closes_qualifying_in_progress_stop() {
        let mut d = DwellDetector::new(50.0, 10_000);
        d.update(0, 60.17, 24.94);
        d.update(5_000, 60.1701, 24.94);
        let event = d.flush(20_000).unwrap();
        assert_eq!(event.start_ms, 0);
        assert_eq!(event.end_ms, 20_000);
        assert_eq!(event.duration_ms, 20_000);
    }

    #[test]
    fn flush_does_not_emit_when_min_dwell_not_met() {
        let mut d = DwellDetector::new(50.0, 60_000);
        d.update(0, 60.17, 24.94);
        assert!(d.flush(5_000).is_none());
    }

    #[test]
    fn flush_on_empty_detector_emits_nothing() {
        let mut d = DwellDetector::new(50.0, 1_000);
        assert!(d.flush(100_000).is_none());
    }
}
