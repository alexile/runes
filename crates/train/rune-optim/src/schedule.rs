//! Learning-rate (or any hyperparameter) schedules as functions of the step.

use std::f64::consts::PI;

use crate::error::{OptimError, finite};

/// Shape of the decay tail of a warmup-stable-decay schedule, as a factor
/// `f(p)` going from 1 at the start of the decay (`p = 0`) to 0 at its end
/// (`p = 1`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum DecayShape {
    /// `1 - p`.
    #[default]
    Linear,
    /// `(1 + cos(pi p)) / 2`.
    Cosine,
    /// `1 - sqrt(p)`.
    OneMinusSqrt,
}

impl DecayShape {
    fn factor(self, p: f64) -> f64 {
        match self {
            Self::Linear => 1.0 - p,
            Self::Cosine => f64::midpoint(1.0, (PI * p).cos()),
            Self::OneMinusSqrt => 1.0 - p.sqrt(),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
enum Kind {
    Constant(f64),
    Warmup {
        peak: f64,
        warmup: u64,
    },
    Cosine {
        peak: f64,
        min: f64,
        warmup: u64,
        total: u64,
    },
    Wsd {
        peak: f64,
        min: f64,
        warmup: u64,
        decay_start: u64,
        total: u64,
        shape: DecayShape,
    },
    InverseSqrt {
        peak: f64,
        warmup: u64,
        timescale: u64,
    },
    Piecewise(Vec<(u64, f64)>),
    Concat(Vec<(u64, Schedule)>, Box<Schedule>),
}

/// A schedule: a value for every step `t = 0, 1, 2, ...`.
///
/// Every constructor validates its arguments. All values are computed in
/// `f64`, and endpoints are returned exactly: a warmup reaches `peak` at
/// `t == warmup`, a decay reaches its minimum at `t == total` and stays
/// there, a piecewise-linear schedule returns each knot's value at that
/// knot.
///
/// Feed the value to an optimizer with [`crate::Optimizer::set_lr_scale`]
/// (build the schedule with `peak = 1` to get a multiplier of the group
/// learning rates), or use it directly as a learning rate.
///
/// ```
/// use rune_optim::Schedule;
///
/// let s = Schedule::warmup_cosine(3e-4, 100, 1000, 0.1)?;
/// assert_eq!(s.value(0), 0.0);
/// assert_eq!(s.value(100), 3e-4);
/// assert_eq!(s.value(1000), 3e-4 * 0.1);
/// assert_eq!(s.value(5000), 3e-4 * 0.1);
/// # Ok::<(), rune_optim::OptimError>(())
/// ```
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Schedule(Kind);

fn ratio(name: &'static str, min_ratio: f64) -> Result<(), OptimError> {
    finite(name, min_ratio)?;
    if (0.0..=1.0).contains(&min_ratio) {
        Ok(())
    } else {
        Err(OptimError::InvalidHyperparameter {
            name,
            value: min_ratio,
            reason: "must be in [0, 1]",
        })
    }
}

#[allow(clippy::cast_precision_loss, reason = "step counts are far below 2^53")]
fn frac(num: u64, den: u64) -> f64 {
    num as f64 / den as f64
}

fn warmup(peak: f64, warmup: u64, t: u64) -> f64 {
    if t >= warmup {
        peak
    } else if t == 0 {
        0.0
    } else {
        peak * frac(t, warmup)
    }
}

impl Schedule {
    /// The same value at every step.
    pub fn constant(value: f64) -> Result<Self, OptimError> {
        finite("value", value)?;
        Ok(Self(Kind::Constant(value)))
    }

    /// `peak * t / warmup` up to `warmup`, then `peak`.
    pub fn linear_warmup(peak: f64, warmup: u64) -> Result<Self, OptimError> {
        finite("peak", peak)?;
        Ok(Self(Kind::Warmup { peak, warmup }))
    }

    /// Linear warmup to `peak`, then a half cosine from `peak` down to
    /// `min_ratio * peak` at `total`, then constant.
    pub fn warmup_cosine(
        peak: f64,
        warmup: u64,
        total: u64,
        min_ratio: f64,
    ) -> Result<Self, OptimError> {
        finite("peak", peak)?;
        ratio("min_ratio", min_ratio)?;
        if warmup > total {
            return Err(OptimError::InvalidSchedule("warmup longer than total"));
        }
        Ok(Self(Kind::Cosine {
            peak,
            min: peak * min_ratio,
            warmup,
            total,
        }))
    }

    /// Warmup-stable-decay: linear warmup to `peak`, `peak` until
    /// `total - decay`, then a `shape` tail down to `min_ratio * peak` at
    /// `total`, then constant.
    pub fn warmup_stable_decay(
        peak: f64,
        warmup: u64,
        total: u64,
        decay: u64,
        min_ratio: f64,
        shape: DecayShape,
    ) -> Result<Self, OptimError> {
        finite("peak", peak)?;
        ratio("min_ratio", min_ratio)?;
        let decay_start = total
            .checked_sub(decay)
            .ok_or(OptimError::InvalidSchedule("decay longer than total"))?;
        if warmup > decay_start {
            return Err(OptimError::InvalidSchedule(
                "warmup overlaps the decay phase",
            ));
        }
        Ok(Self(Kind::Wsd {
            peak,
            min: peak * min_ratio,
            warmup,
            decay_start,
            total,
            shape,
        }))
    }

    /// Linear warmup to `peak`, then
    /// `peak * sqrt(timescale / (t - warmup + timescale))`.
    /// `timescale` (at least 1) sets how fast it falls: the value halves
    /// after `3 * timescale` further steps.
    pub fn inverse_sqrt(peak: f64, warmup: u64, timescale: u64) -> Result<Self, OptimError> {
        finite("peak", peak)?;
        if timescale == 0 {
            return Err(OptimError::InvalidSchedule("timescale must be at least 1"));
        }
        Ok(Self(Kind::InverseSqrt {
            peak,
            warmup,
            timescale,
        }))
    }

    /// Linear interpolation through `(step, value)` knots with strictly
    /// increasing steps; constant before the first and after the last knot.
    pub fn piecewise_linear(points: Vec<(u64, f64)>) -> Result<Self, OptimError> {
        if points.is_empty() {
            return Err(OptimError::InvalidSchedule("no knots"));
        }
        for w in points.windows(2) {
            if w[0].0 >= w[1].0 {
                return Err(OptimError::InvalidSchedule(
                    "knot steps must be strictly increasing",
                ));
            }
        }
        for &(_, v) in &points {
            finite("knot value", v)?;
        }
        Ok(Self(Kind::Piecewise(points)))
    }

    /// Run each `(steps, schedule)` part for `steps` steps, then `last`
    /// forever. Each part sees its own step counter starting at 0.
    #[must_use]
    pub fn concat(parts: Vec<(u64, Self)>, last: Self) -> Self {
        Self(Kind::Concat(parts, Box::new(last)))
    }

    /// The value at step `t`.
    #[must_use]
    pub fn value(&self, t: u64) -> f64 {
        match &self.0 {
            Kind::Constant(v) => *v,
            Kind::Warmup { peak, warmup: w } => warmup(*peak, *w, t),
            Kind::Cosine {
                peak,
                min,
                warmup: w,
                total,
            } => {
                if t <= *w {
                    warmup(*peak, *w, t)
                } else if t >= *total {
                    *min
                } else {
                    let p = frac(t - w, total - w);
                    min + (peak - min) * DecayShape::Cosine.factor(p)
                }
            }
            Kind::Wsd {
                peak,
                min,
                warmup: w,
                decay_start,
                total,
                shape,
            } => {
                if t < *w {
                    warmup(*peak, *w, t)
                } else if t <= *decay_start && t < *total {
                    *peak
                } else if t >= *total {
                    *min
                } else {
                    let p = frac(t - decay_start, total - decay_start);
                    min + (peak - min) * shape.factor(p)
                }
            }
            Kind::InverseSqrt {
                peak,
                warmup: w,
                timescale,
            } => match t.cmp(w) {
                std::cmp::Ordering::Less => warmup(*peak, *w, t),
                std::cmp::Ordering::Equal => *peak,
                std::cmp::Ordering::Greater => {
                    let s = *timescale;
                    peak * frac(s, (t - w).saturating_add(s)).sqrt()
                }
            },
            Kind::Piecewise(points) => piecewise(points, t),
            Kind::Concat(parts, last) => {
                let mut t = t;
                for (len, s) in parts {
                    if t < *len {
                        return s.value(t);
                    }
                    t -= len;
                }
                last.value(t)
            }
        }
    }
}

fn piecewise(points: &[(u64, f64)], t: u64) -> f64 {
    let Some(&(first_t, first_v)) = points.first() else {
        return 0.0;
    };
    if t <= first_t {
        return first_v;
    }
    for w in points.windows(2) {
        let ((a, va), (b, vb)) = (w[0], w[1]);
        if t == b {
            return vb;
        }
        if t > a && t < b {
            return va + (vb - va) * frac(t - a, b - a);
        }
    }
    points.last().map_or(first_v, |p| p.1)
}
