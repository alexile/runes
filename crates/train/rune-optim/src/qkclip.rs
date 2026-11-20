//! Per-head rescaling of query/key projections to cap attention logits.

use crate::error::{OptimError, positive};

/// Shapes of the query and key projection weights.
///
/// Both are row-major `[heads * head_dim, model_dim]` (output features
/// first): query head `h` owns rows `h * head_dim .. (h + 1) * head_dim` of
/// `wq`, key head `k` the same rows of `wk`. With grouped-query attention,
/// query heads `k * group .. (k + 1) * group` share key head `k`, where
/// `group = num_heads / num_kv_heads`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct QkLayout {
    /// Number of query heads.
    pub num_heads: usize,
    /// Number of key heads (divides `num_heads`).
    pub num_kv_heads: usize,
    /// Dimension of one head.
    pub head_dim: usize,
    /// Input (model) dimension.
    pub model_dim: usize,
}

/// Cap the attention logits of each head at `threshold` by shrinking the
/// query and key projection weights (the clipping step of "Kimi K2: Open
/// Agentic Intelligence").
///
/// `max_logits[h]` is the largest pre-softmax logit `q·k` (including any
/// `1/sqrt(d)` factor the model applies) of query head `h` observed in the
/// last forward pass. A head with `max_logits[h] > threshold` gets
/// `gamma_h = threshold / max_logits[h]`; others get 1. The product of the
/// query and key scales of head `h` is exactly `gamma_h`, so its logits
/// shrink by that factor and no other head's logits change:
///
/// * key head `k` is scaled by `s_k = (min_{h in k} gamma_h)^(1 - alpha)`;
/// * query head `h` is scaled by `gamma_h / s_k`.
///
/// For multi-head attention this is `gamma^alpha` on the query and
/// `gamma^(1 - alpha)` on the key; `alpha = 0.5` splits it evenly. With
/// grouped-query attention an unclipped query head sharing a clipped key
/// head is scaled up by `1 / s_k` to keep its logits unchanged.
///
/// Returns `gamma_h` per query head. Weights are untouched when no head
/// exceeds the threshold.
///
/// ```
/// use rune_optim::{QkLayout, qk_clip};
///
/// let layout = QkLayout { num_heads: 2, num_kv_heads: 2, head_dim: 1, model_dim: 2 };
/// let (mut wq, mut wk) = (vec![1.0f32; 4], vec![1.0f32; 4]);
/// let gamma = qk_clip(&mut wq, &mut wk, layout, &[400.0, 50.0], 100.0, 0.5)?;
/// assert_eq!(gamma, [0.25, 1.0]);
/// assert_eq!(wq, [0.5, 0.5, 1.0, 1.0]);
/// assert_eq!(wk, [0.5, 0.5, 1.0, 1.0]);
/// # Ok::<(), rune_optim::OptimError>(())
/// ```
#[allow(
    clippy::cast_possible_truncation,
    reason = "scales rounded to f32 once"
)]
pub fn qk_clip(
    wq: &mut [f32],
    wk: &mut [f32],
    layout: QkLayout,
    max_logits: &[f32],
    threshold: f32,
    alpha: f32,
) -> Result<Vec<f32>, OptimError> {
    positive("threshold", f64::from(threshold))?;
    let a = f64::from(alpha);
    if !(0.0..=1.0).contains(&a) {
        return Err(OptimError::InvalidHyperparameter {
            name: "alpha",
            value: a,
            reason: "must be in [0, 1]",
        });
    }
    let QkLayout {
        num_heads,
        num_kv_heads,
        head_dim,
        model_dim,
    } = layout;
    if num_kv_heads == 0 || num_heads % num_kv_heads != 0 {
        return Err(OptimError::InvalidHyperparameter {
            name: "num_kv_heads",
            #[allow(clippy::cast_precision_loss, reason = "reported value only")]
            value: num_kv_heads as f64,
            reason: "must be positive and divide num_heads",
        });
    }
    let block = head_dim
        .checked_mul(model_dim)
        .ok_or(OptimError::BadShape {
            index: 0,
            rows: head_dim,
            cols: model_dim,
            len: wq.len(),
        })?;
    for (what, buf, heads) in [("wq", wq.len(), num_heads), ("wk", wk.len(), num_kv_heads)] {
        let want = block.saturating_mul(heads);
        if buf != want {
            return Err(OptimError::LengthMismatch {
                what,
                index: 0,
                expected: want,
                found: buf,
            });
        }
    }
    if max_logits.len() != num_heads {
        return Err(OptimError::LengthMismatch {
            what: "max_logits",
            index: 0,
            expected: num_heads,
            found: max_logits.len(),
        });
    }
    if let Some(&bad) = max_logits.iter().find(|v| v.is_nan()) {
        return Err(OptimError::InvalidHyperparameter {
            name: "max_logits",
            value: f64::from(bad),
            reason: "must not be NaN",
        });
    }
    let tau = f64::from(threshold);
    let gamma: Vec<f64> = max_logits
        .iter()
        .map(|&s| {
            let s = f64::from(s);
            if s > tau { tau / s } else { 1.0 }
        })
        .collect();
    let group = num_heads / num_kv_heads;
    if block == 0 {
        return Ok(gamma.iter().map(|&g| g as f32).collect());
    }
    for (k, (gs, wk_head)) in gamma.chunks(group).zip(wk.chunks_mut(block)).enumerate() {
        let gk = gs.iter().copied().fold(1.0f64, f64::min);
        if gk >= 1.0 {
            continue;
        }
        let sk = gk.powf(1.0 - a);
        let sk32 = sk as f32;
        for w in wk_head {
            *w *= sk32;
        }
        for (j, &gh) in gs.iter().enumerate() {
            let sq = (gh / sk) as f32;
            let h = k * group + j;
            for w in &mut wq[h * block..(h + 1) * block] {
                *w *= sq;
            }
        }
    }
    Ok(gamma.iter().map(|&g| g as f32).collect())
}
