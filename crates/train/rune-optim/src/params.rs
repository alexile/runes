//! Parameter groups, tensor descriptions and flat-buffer layouts.

use crate::error::{OptimError, non_negative, unit};

/// Per-group overrides of an optimizer's defaults.
///
/// A field left at `None` takes the optimizer's value. `no_decay` turns
/// weight decay off for the group whatever `weight_decay` says; it is the
/// usual setting for norm gains, biases and often embeddings.
#[derive(Debug, Clone, Copy, PartialEq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct GroupOptions {
    /// Learning rate override.
    pub lr: Option<f32>,
    /// Weight decay override.
    pub weight_decay: Option<f32>,
    /// `(beta1, beta2)` override. Muon reads `beta1` as its momentum and
    /// Lion reads both; Adafactor ignores it.
    pub betas: Option<(f32, f32)>,
    /// Disable weight decay for this group.
    pub no_decay: bool,
    /// Keep this group off the matrix optimizer: [`crate::Muon`] steps its
    /// tensors with the element-wise fallback even when they are 2-D
    /// (embeddings and output heads are commonly kept on AdamW).
    pub elementwise_only: bool,
}

impl GroupOptions {
    /// No overrides.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            lr: None,
            weight_decay: None,
            betas: None,
            no_decay: false,
            elementwise_only: false,
        }
    }

    /// The group for norms, biases and embeddings: no weight decay.
    #[must_use]
    pub const fn no_decay() -> Self {
        let mut g = Self::new();
        g.no_decay = true;
        g
    }

    /// Set the learning-rate override.
    #[must_use]
    pub const fn with_lr(mut self, lr: f32) -> Self {
        self.lr = Some(lr);
        self
    }

    /// Set the weight-decay override.
    #[must_use]
    pub const fn with_weight_decay(mut self, wd: f32) -> Self {
        self.weight_decay = Some(wd);
        self
    }

    /// Set the betas override.
    #[must_use]
    pub const fn with_betas(mut self, beta1: f32, beta2: f32) -> Self {
        self.betas = Some((beta1, beta2));
        self
    }

    /// Mark the group element-wise only (see the field).
    #[must_use]
    pub const fn elementwise(mut self) -> Self {
        self.elementwise_only = true;
        self
    }

    fn validate(&self) -> Result<(), OptimError> {
        if let Some(lr) = self.lr {
            non_negative("group lr", f64::from(lr))?;
        }
        if let Some(wd) = self.weight_decay {
            non_negative("group weight_decay", f64::from(wd))?;
        }
        if let Some((b1, b2)) = self.betas {
            unit("group beta1", f64::from(b1))?;
            unit("group beta2", f64::from(b2))?;
        }
        Ok(())
    }
}

/// One parameter tensor: its length, an optional matrix shape and its group.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ParamSpec {
    /// Number of elements.
    pub len: usize,
    /// `(rows, cols)` for a row-major 2-D weight, `None` otherwise. For a
    /// linear layer stored as `[out_features, in_features]`, rows are the
    /// output dimension.
    pub matrix: Option<(usize, usize)>,
    /// Index of the parameter group.
    pub group: usize,
}

impl ParamSpec {
    /// A 1-D (or any non-matrix) tensor in group 0.
    #[must_use]
    pub const fn vector(len: usize) -> Self {
        Self {
            len,
            matrix: None,
            group: 0,
        }
    }

    /// A row-major `rows × cols` matrix in group 0.
    #[must_use]
    pub const fn matrix(rows: usize, cols: usize) -> Self {
        Self {
            len: rows.saturating_mul(cols),
            matrix: Some((rows, cols)),
            group: 0,
        }
    }

    /// Put the tensor in group `group`.
    #[must_use]
    pub const fn in_group(mut self, group: usize) -> Self {
        self.group = group;
        self
    }
}

/// The tensors an optimizer manages and their parameter groups.
#[derive(Debug, Clone, PartialEq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ParamSet {
    specs: Vec<ParamSpec>,
    groups: Vec<GroupOptions>,
}

impl ParamSet {
    /// Tensors with explicit groups. Every `spec.group` must index `groups`
    /// and every matrix shape must match its length.
    pub fn new(specs: Vec<ParamSpec>, groups: Vec<GroupOptions>) -> Result<Self, OptimError> {
        let set = Self { specs, groups };
        set.validate()?;
        Ok(set)
    }

    /// Tensors all in one default group (any `spec.group` must be 0).
    pub fn single_group(specs: Vec<ParamSpec>) -> Result<Self, OptimError> {
        Self::new(specs, vec![GroupOptions::new()])
    }

    /// Re-check the invariants (used after deserialization and after
    /// [`Self::groups_mut`] edits).
    pub fn validate(&self) -> Result<(), OptimError> {
        for g in &self.groups {
            g.validate()?;
        }
        for (index, s) in self.specs.iter().enumerate() {
            if s.group >= self.groups.len() {
                return Err(OptimError::UnknownGroup {
                    index,
                    group: s.group,
                    groups: self.groups.len(),
                });
            }
            if let Some((rows, cols)) = s.matrix
                && (rows.checked_mul(cols) != Some(s.len) || rows == 0 || cols == 0)
            {
                return Err(OptimError::BadShape {
                    index,
                    rows,
                    cols,
                    len: s.len,
                });
            }
        }
        Ok(())
    }

    /// The tensors.
    #[must_use]
    pub fn specs(&self) -> &[ParamSpec] {
        &self.specs
    }

    /// The groups.
    #[must_use]
    pub fn groups(&self) -> &[GroupOptions] {
        &self.groups
    }

    /// Mutable access to the group options, e.g. to change a group's
    /// learning rate mid-run. Values are re-validated on every step.
    pub fn groups_mut(&mut self) -> &mut [GroupOptions] {
        &mut self.groups
    }

    /// Number of tensors.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.specs.len()
    }

    /// Whether there are no tensors.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.specs.is_empty()
    }

    /// Total number of elements.
    #[must_use]
    pub fn numel(&self) -> usize {
        self.specs.iter().map(|s| s.len).sum()
    }

    /// The group of tensor `index`. Callers have validated the set.
    pub(crate) fn group_of(&self, index: usize) -> GroupOptions {
        self.specs
            .get(index)
            .and_then(|s| self.groups.get(s.group))
            .copied()
            .unwrap_or_default()
    }

    /// Check a list of parameter and gradient slices against the specs.
    pub(crate) fn check_slices(
        &self,
        params: &[&mut [f32]],
        grads: &[&[f32]],
    ) -> Result<(), OptimError> {
        self.validate()?;
        for (what, found) in [("params", params.len()), ("grads", grads.len())] {
            if found != self.specs.len() {
                return Err(OptimError::TensorCount {
                    what,
                    expected: self.specs.len(),
                    found,
                });
            }
        }
        for (index, ((s, p), g)) in self.specs.iter().zip(params).zip(grads).enumerate() {
            for (what, found) in [("param", p.len()), ("grad", g.len())] {
                if found != s.len {
                    return Err(OptimError::LengthMismatch {
                        what,
                        index,
                        expected: s.len,
                        found,
                    });
                }
            }
        }
        Ok(())
    }
}

/// Where each tensor of a [`ParamSet`] lives in one flat buffer.
///
/// This is the layout of sharded data parallelism: parameters, gradients
/// and optimizer state of many tensors packed (optionally with alignment
/// padding) into one contiguous allocation. Tensors must not overlap; gaps
/// are allowed and never touched.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct FlatLayout {
    offsets: Vec<usize>,
    lens: Vec<usize>,
    total: usize,
}

impl FlatLayout {
    /// Tensors packed back to back in order.
    #[must_use]
    pub fn contiguous(set: &ParamSet) -> Self {
        Self::aligned(set, 1)
    }

    /// Tensors in order, each starting at a multiple of `align` elements
    /// (`align == 0` is treated as 1).
    #[must_use]
    pub fn aligned(set: &ParamSet, align: usize) -> Self {
        let align = align.max(1);
        let mut offsets = Vec::with_capacity(set.len());
        let mut at = 0usize;
        for s in set.specs() {
            at = at.div_ceil(align).saturating_mul(align);
            offsets.push(at);
            at = at.saturating_add(s.len);
        }
        Self {
            offsets,
            lens: set.specs().iter().map(|s| s.len).collect(),
            total: at,
        }
    }

    /// Explicit offsets into a buffer of `total` elements.
    pub fn new(set: &ParamSet, offsets: Vec<usize>, total: usize) -> Result<Self, OptimError> {
        if offsets.len() != set.len() {
            return Err(OptimError::TensorCount {
                what: "offsets",
                expected: set.len(),
                found: offsets.len(),
            });
        }
        let layout = Self {
            lens: set.specs().iter().map(|s| s.len).collect(),
            offsets,
            total,
        };
        layout.validate()?;
        Ok(layout)
    }

    fn validate(&self) -> Result<(), OptimError> {
        let mut order: Vec<usize> = (0..self.offsets.len()).collect();
        order.sort_by_key(|&i| (self.offsets[i], self.lens[i]));
        let mut prev_end = 0usize;
        for &index in &order {
            let start = self.offsets[index];
            let end = start
                .checked_add(self.lens[index])
                .ok_or(OptimError::BadLayout {
                    index,
                    start,
                    end: usize::MAX,
                    reason: "overflows usize",
                })?;
            if end > self.total {
                return Err(OptimError::BadLayout {
                    index,
                    start,
                    end,
                    reason: "runs past the end of the buffer",
                });
            }
            if start < prev_end {
                return Err(OptimError::BadLayout {
                    index,
                    start,
                    end,
                    reason: "overlaps another tensor",
                });
            }
            prev_end = prev_end.max(end);
        }
        Ok(())
    }

    /// Start offset of each tensor.
    #[must_use]
    pub fn offsets(&self) -> &[usize] {
        &self.offsets
    }

    /// Length of the flat buffer.
    #[must_use]
    pub const fn total(&self) -> usize {
        self.total
    }

    fn matches(&self, set: &ParamSet) -> bool {
        self.lens.len() == set.len() && self.lens.iter().zip(set.specs()).all(|(l, s)| *l == s.len)
    }

    fn check(&self, set: &ParamSet, what: &'static str, len: usize) -> Result<(), OptimError> {
        if !self.matches(set) {
            return Err(OptimError::TensorCount {
                what: "layout tensors",
                expected: set.len(),
                found: self.lens.len(),
            });
        }
        self.validate()?;
        if len != self.total {
            return Err(OptimError::LengthMismatch {
                what,
                index: 0,
                expected: self.total,
                found: len,
            });
        }
        Ok(())
    }

    /// Views of each tensor in a flat buffer, in tensor order.
    pub fn split<'a>(&self, set: &ParamSet, buf: &'a [f32]) -> Result<Vec<&'a [f32]>, OptimError> {
        self.check(set, "flat buffer", buf.len())?;
        Ok(self
            .offsets
            .iter()
            .zip(&self.lens)
            .map(|(&o, &l)| buf.get(o..o + l).unwrap_or_default())
            .collect())
    }

    /// Mutable views of each tensor in a flat buffer, in tensor order.
    pub fn split_mut<'a>(
        &self,
        set: &ParamSet,
        buf: &'a mut [f32],
    ) -> Result<Vec<&'a mut [f32]>, OptimError> {
        self.check(set, "flat buffer", buf.len())?;
        let mut order: Vec<usize> = (0..self.offsets.len()).collect();
        order.sort_by_key(|&i| (self.offsets[i], self.lens[i]));
        let mut out: Vec<Option<&'a mut [f32]>> = (0..self.offsets.len()).map(|_| None).collect();
        let mut rest = buf;
        let mut base = 0usize;
        for &i in &order {
            let skip = self.offsets[i] - base;
            let (_, tail) = rest.split_at_mut(skip);
            let (mine, tail) = tail.split_at_mut(self.lens[i]);
            out[i] = Some(mine);
            rest = tail;
            base = self.offsets[i] + self.lens[i];
        }
        Ok(out.into_iter().map(Option::unwrap_or_default).collect())
    }
}

/// Hyperparameters of one tensor after applying its group's overrides and
/// the global learning-rate scale.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Resolved {
    pub lr: f64,
    pub wd: f64,
    pub beta1: f64,
    pub beta2: f64,
}

impl Resolved {
    pub(crate) fn new(
        group: &GroupOptions,
        lr: f32,
        weight_decay: f32,
        betas: (f32, f32),
        lr_scale: f64,
    ) -> Self {
        let (b1, b2) = group.betas.unwrap_or(betas);
        Self {
            lr: f64::from(group.lr.unwrap_or(lr)) * lr_scale,
            wd: if group.no_decay {
                0.0
            } else {
                f64::from(group.weight_decay.unwrap_or(weight_decay))
            },
            beta1: f64::from(b1),
            beta2: f64::from(b2),
        }
    }
}
