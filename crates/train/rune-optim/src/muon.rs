//! Muon: momentum orthogonalized by a Newton–Schulz iteration, with an
//! AdamW fallback for non-matrix parameters.

use rune_gemm::{Gemm, MatMut, MatRef};

use crate::adamw::{AdamScalars, AdamState, AdamWConfig, lerp};
use crate::error::{OptimError, finite, non_negative, positive, unit};
use crate::par;
use crate::params::{GroupOptions, ParamSet, Resolved};
use crate::{Optimizer, check_scale, check_state_count};

/// The quintic Newton–Schulz iteration that maps a matrix `G = U S Vᵀ` to
/// roughly `U Vᵀ`.
///
/// `X ← X / (‖X‖_F + eps)`, then `steps` times
/// `A = X Xᵀ;  X ← a X + (b A + c A²) X`, working on the wide orientation
/// (the matrix is transposed when `rows > cols`, so `A` is the smaller Gram
/// matrix). The default coefficients `(3.4445, -4.7750, 2.0315)` trade exact
/// convergence for speed: after 5 steps every singular value `s` of `G`
/// with `s >= 1.5e-3 · ‖G‖_F` maps into `[0.68, 1.21]` (the usual
/// "about `[0.7, 1.2]`") rather than to exactly 1. Smaller ones are not
/// lifted into the band within 5 steps; they stay small, which is the
/// intended behaviour for near-null directions. Each singular value goes
/// through the same scalar map, so singular vectors are preserved.
#[derive(Debug, Clone, Copy, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct NewtonSchulz {
    /// `(a, b, c)` of `p(x) = a x + b x³ + c x⁵`.
    pub coefficients: (f32, f32, f32),
    /// Number of iterations.
    pub steps: usize,
    /// Added to the Frobenius norm before normalizing.
    pub eps: f32,
}

impl Default for NewtonSchulz {
    fn default() -> Self {
        Self {
            coefficients: (3.4445, -4.7750, 2.0315),
            steps: 5,
            eps: 1e-7,
        }
    }
}

impl NewtonSchulz {
    fn validate(&self) -> Result<(), OptimError> {
        finite("ns coefficient a", f64::from(self.coefficients.0))?;
        finite("ns coefficient b", f64::from(self.coefficients.1))?;
        finite("ns coefficient c", f64::from(self.coefficients.2))?;
        non_negative("ns eps", f64::from(self.eps))
    }

    /// Orthogonalize the row-major `rows × cols` matrix `g` into `out`.
    ///
    /// ```
    /// use rune_optim::NewtonSchulz;
    ///
    /// // A diagonal matrix with singular values 4 and 1 maps to (about) the
    /// // identity.
    /// let g = [4.0f32, 0.0, 0.0, 1.0];
    /// let mut o = [0.0f32; 4];
    /// NewtonSchulz::default().orthogonalize(&g, 2, 2, &mut o)?;
    /// assert!(o[0] > 0.6 && o[0] < 1.25 && o[3] > 0.6 && o[3] < 1.25);
    /// assert!(o[1].abs() < 1e-6 && o[2].abs() < 1e-6);
    /// # Ok::<(), rune_optim::OptimError>(())
    /// ```
    pub fn orthogonalize(
        &self,
        g: &[f32],
        rows: usize,
        cols: usize,
        out: &mut [f32],
    ) -> Result<(), OptimError> {
        self.validate()?;
        let len = rows.checked_mul(cols).ok_or(OptimError::BadShape {
            index: 0,
            rows,
            cols,
            len: g.len(),
        })?;
        if len != g.len() {
            return Err(OptimError::BadShape {
                index: 0,
                rows,
                cols,
                len: g.len(),
            });
        }
        if out.len() != len {
            return Err(OptimError::LengthMismatch {
                what: "orthogonalize output",
                index: 0,
                expected: len,
                found: out.len(),
            });
        }
        if len == 0 {
            return Ok(());
        }
        let transpose = rows > cols;
        let (m, n) = if transpose {
            (cols, rows)
        } else {
            (rows, cols)
        };
        let mut x = vec![0.0f32; len];
        if transpose {
            for (i, row) in g.chunks(cols).enumerate() {
                for (j, &v) in row.iter().enumerate() {
                    x[j * rows + i] = v;
                }
            }
        } else {
            x.copy_from_slice(g);
        }
        self.iterate(&mut x, m, n)?;
        if transpose {
            for (j, row) in x.chunks(rows).enumerate() {
                for (i, &v) in row.iter().enumerate() {
                    out[i * cols + j] = v;
                }
            }
        } else {
            out.copy_from_slice(&x);
        }
        Ok(())
    }

    /// In place on a row-major `m × n` matrix with `m <= n`.
    #[allow(clippy::cast_possible_truncation, reason = "norm rounded to f32 once")]
    fn iterate(&self, x: &mut Vec<f32>, m: usize, n: usize) -> Result<(), OptimError> {
        let gemm = Gemm::new();
        let denom = (par::sum_sq(x).sqrt() + f64::from(self.eps)) as f32;
        par::apply1(x, |x| {
            for v in x {
                *v /= denom;
            }
        });
        let (a, b, c) = self.coefficients;
        let mut gram = vec![0.0f32; m * m];
        let mut poly = vec![0.0f32; m * m];
        let mut next = vec![0.0f32; m * n];
        for _ in 0..self.steps {
            {
                let xr = MatRef::row_major(x, m, n)?;
                gemm.gemm(1.0, xr, xr.t(), 0.0, MatMut::row_major(&mut gram, m, m)?)?;
            }
            poly.copy_from_slice(&gram);
            {
                let ar = MatRef::row_major(&gram, m, m)?;
                gemm.gemm(c, ar, ar, b, MatMut::row_major(&mut poly, m, m)?)?;
            }
            next.copy_from_slice(x);
            gemm.gemm(
                1.0,
                MatRef::row_major(&poly, m, m)?,
                MatRef::row_major(x, m, n)?,
                a,
                MatMut::row_major(&mut next, m, n)?,
            )?;
            std::mem::swap(x, &mut next);
        }
        Ok(())
    }
}

/// How Muon scales the orthogonalized update of a `rows × cols` matrix.
#[derive(Debug, Clone, Copy, PartialEq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub enum MuonScale {
    /// No scaling.
    Unit,
    /// `sqrt(max(1, rows / cols))`: keeps the per-element RMS of tall
    /// matrices comparable to square ones.
    #[default]
    Shape,
    /// `coefficient * sqrt(max(rows, cols))` (usually `0.2`): matches the
    /// update RMS of AdamW, so AdamW learning rates and weight decay carry
    /// over.
    MatchAdamW {
        /// Multiplier, `0.2` in the published recipe.
        coefficient: f32,
    },
}

impl MuonScale {
    /// The factor for a `rows × cols` matrix.
    #[must_use]
    #[allow(clippy::cast_precision_loss, reason = "dimensions fit f64")]
    pub fn factor(self, rows: usize, cols: usize) -> f64 {
        let (r, c) = (rows as f64, cols as f64);
        match self {
            Self::Unit => 1.0,
            Self::Shape => (r / c).max(1.0).sqrt(),
            Self::MatchAdamW { coefficient } => f64::from(coefficient) * r.max(c).sqrt(),
        }
    }
}

/// Muon hyperparameters (defaults: `lr = 0.02`, `momentum = 0.95`,
/// Nesterov, no weight decay, [`MuonScale::Shape`], 5 Newton–Schulz steps,
/// and an AdamW fallback with `lr = 3e-4`, `betas = (0.9, 0.95)`).
#[derive(Debug, Clone, Copy, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct MuonConfig {
    /// Learning rate of the matrix parameters.
    pub lr: f32,
    /// Momentum coefficient.
    pub momentum: f32,
    /// Use Nesterov momentum.
    pub nesterov: bool,
    /// Decoupled weight decay of the matrix parameters
    /// (`p *= 1 - lr * weight_decay`, unscaled `lr`).
    pub weight_decay: f32,
    /// Update scaling rule.
    pub scale: MuonScale,
    /// The orthogonalization.
    pub newton_schulz: NewtonSchulz,
    /// Settings for parameters that are not matrices (or whose group is
    /// marked element-wise only).
    pub fallback: AdamWConfig,
}

impl Default for MuonConfig {
    fn default() -> Self {
        Self {
            lr: 0.02,
            momentum: 0.95,
            nesterov: true,
            weight_decay: 0.0,
            scale: MuonScale::Shape,
            newton_schulz: NewtonSchulz::default(),
            fallback: AdamWConfig {
                lr: 3e-4,
                betas: (0.9, 0.95),
                eps: 1e-8,
                weight_decay: 0.0,
                amsgrad: false,
                eps_inside_sqrt: false,
            },
        }
    }
}

impl MuonConfig {
    fn validate(&self) -> Result<(), OptimError> {
        non_negative("lr", f64::from(self.lr))?;
        unit("momentum", f64::from(self.momentum))?;
        non_negative("weight_decay", f64::from(self.weight_decay))?;
        if let MuonScale::MatchAdamW { coefficient } = self.scale {
            positive("scale coefficient", f64::from(coefficient))?;
        }
        self.newton_schulz.validate()?;
        self.fallback.validate()
    }
}

#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
enum MuonState {
    Matrix { momentum: Vec<f32> },
    Elementwise(AdamState),
}

/// Muon (Jordan et al., "Muon: An optimizer for hidden layers in neural
/// networks"; scaling rules from "Muon is Scalable for LLM Training").
///
/// For each 2-D parameter (`rows × cols`, row-major, rows = output
/// features):
///
/// ```text
/// m = lerp(m, g, 1 - mu)
/// u = nesterov ? lerp(g, m, mu) : m
/// o = NewtonSchulz(u)                   ≈ U Vᵀ of u
/// p = p * (1 - lr * wd)
/// p = p - lr * scale(rows, cols) * o
/// ```
///
/// Every other tensor, and every tensor of a group marked
/// [`GroupOptions::elementwise_only`], is stepped with AdamW using
/// [`MuonConfig::fallback`]. Group overrides apply to both: `lr` and
/// `weight_decay` override the respective optimizer's value and `betas.0`
/// is the momentum of matrix tensors. Matrix products go through
/// `rune-gemm`, whose results do not depend on the thread count.
///
/// ```
/// use rune_optim::{GroupOptions, Muon, MuonConfig, Optimizer, ParamSet, ParamSpec};
///
/// let set = ParamSet::new(
///     vec![ParamSpec::matrix(4, 3), ParamSpec::vector(4).in_group(1)],
///     vec![GroupOptions::new(), GroupOptions::no_decay()],
/// )?;
/// let mut opt = Muon::new(set, MuonConfig::default())?;
/// assert!(opt.is_matrix(0) && !opt.is_matrix(1));
/// let (mut w, mut b) = (vec![0.0f32; 12], vec![0.0f32; 4]);
/// let gw: Vec<f32> = (0..12).map(|i| (i as f32 * 0.7).sin()).collect();
/// opt.step(&mut [&mut w, &mut b], &[&gw, &[1.0, -1.0, 1.0, -1.0]])?;
/// assert!(w.iter().all(|v| v.is_finite()) && (b[0] + 3e-4).abs() < 1e-9);
/// # Ok::<(), rune_optim::OptimError>(())
/// ```
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Muon {
    set: ParamSet,
    config: MuonConfig,
    step: u64,
    lr_scale: f64,
    state: Vec<MuonState>,
}

impl Muon {
    /// A fresh optimizer. Tensors with a matrix shape go to Muon unless their
    /// group is element-wise only.
    pub fn new(set: ParamSet, config: MuonConfig) -> Result<Self, OptimError> {
        set.validate()?;
        config.validate()?;
        let state = (0..set.len())
            .map(|i| {
                let s = set.specs()[i];
                if s.matrix.is_some() && !set.group_of(i).elementwise_only {
                    MuonState::Matrix {
                        momentum: vec![0.0; s.len],
                    }
                } else {
                    MuonState::Elementwise(AdamState::new(s.len, config.fallback.amsgrad))
                }
            })
            .collect();
        Ok(Self {
            set,
            config,
            step: 0,
            lr_scale: 1.0,
            state,
        })
    }

    /// The configuration.
    #[must_use]
    pub const fn config(&self) -> &MuonConfig {
        &self.config
    }

    /// Whether tensor `index` is stepped by the matrix path.
    #[must_use]
    pub fn is_matrix(&self, index: usize) -> bool {
        matches!(self.state.get(index), Some(MuonState::Matrix { .. }))
    }

    fn check_state(&self) -> Result<(), OptimError> {
        check_state_count(self.state.len(), self.set.len())?;
        for (index, (st, s)) in self.state.iter().zip(self.set.specs()).enumerate() {
            match st {
                MuonState::Matrix { momentum } => {
                    if s.matrix.is_none() || momentum.len() != s.len {
                        return Err(OptimError::CorruptState {
                            index,
                            reason: "matrix momentum does not match the tensor",
                        });
                    }
                }
                MuonState::Elementwise(a) => a.check(index, s.len, self.config.fallback.amsgrad)?,
            }
        }
        Ok(())
    }
}

impl Optimizer for Muon {
    fn param_set(&self) -> &ParamSet {
        &self.set
    }

    fn groups_mut(&mut self) -> &mut [GroupOptions] {
        self.set.groups_mut()
    }

    fn steps(&self) -> u64 {
        self.step
    }

    fn lr_scale(&self) -> f64 {
        self.lr_scale
    }

    fn set_lr_scale(&mut self, scale: f64) {
        self.lr_scale = scale;
    }

    #[allow(
        clippy::cast_possible_truncation,
        reason = "f64 scalars rounded to f32 once"
    )]
    fn step(&mut self, params: &mut [&mut [f32]], grads: &[&[f32]]) -> Result<(), OptimError> {
        self.set.check_slices(params, grads)?;
        self.config.validate()?;
        check_scale(self.lr_scale)?;
        self.check_state()?;
        let t = self.step + 1;
        let cfg = self.config;
        let max_matrix = (0..self.set.len())
            .filter(|&i| self.is_matrix(i))
            .map(|i| self.set.specs()[i].len)
            .max()
            .unwrap_or(0);
        let (mut dir, mut ortho) = (vec![0.0f32; max_matrix], vec![0.0f32; max_matrix]);
        for i in 0..self.set.len() {
            let group = self.set.group_of(i);
            let spec = self.set.specs()[i];
            let (p, g) = (&mut *params[i], grads[i]);
            match &mut self.state[i] {
                MuonState::Elementwise(st) => {
                    let f = &cfg.fallback;
                    let h = Resolved::new(&group, f.lr, f.weight_decay, f.betas, self.lr_scale);
                    AdamScalars::new(&h, f, t).apply(p, g, st);
                }
                MuonState::Matrix { momentum } => {
                    let (rows, cols) = spec.matrix.unwrap_or((spec.len, 1));
                    let beta = (cfg.momentum, cfg.momentum);
                    let h = Resolved::new(&group, cfg.lr, cfg.weight_decay, beta, self.lr_scale);
                    let mu = h.beta1 as f32;
                    let u = &mut dir[..spec.len];
                    let nesterov = cfg.nesterov;
                    par::apply3(u, g, momentum, |u, g, m| {
                        for ((u, &g), m) in u.iter_mut().zip(g).zip(m) {
                            *m = lerp(*m, g, 1.0 - mu);
                            *u = if nesterov { lerp(g, *m, mu) } else { *m };
                        }
                    });
                    let o = &mut ortho[..spec.len];
                    cfg.newton_schulz.orthogonalize(u, rows, cols, o)?;
                    let decay = (1.0 - h.lr * h.wd) as f32;
                    let step = (h.lr * cfg.scale.factor(rows, cols)) as f32;
                    par::apply2(p, o, |p, o| {
                        for (p, &o) in p.iter_mut().zip(o) {
                            *p *= decay;
                            *p -= step * o;
                        }
                    });
                }
            }
        }
        self.step = t;
        Ok(())
    }
}
