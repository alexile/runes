//! Per-tensor (current and delayed) and per-tile scaling recipes.

#![allow(
    clippy::unwrap_used,
    clippy::float_cmp,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::cast_precision_loss,
    clippy::cast_lossless,
    clippy::many_single_char_names,
    clippy::similar_names,
    clippy::suboptimal_flops,
    clippy::manual_midpoint,
    clippy::missing_const_for_fn,
    clippy::needless_range_loop,
    clippy::assert_is_empty,
    reason = "tests: exact float comparisons and bit casts are the point"
)]

mod common;

use common::Rng;
use rune_lowp::{
    AmaxReduction, BlockScaledMatrix, DelayedScaling, F8E4M3, F8E5M2, LowpError, Overflow,
    ScalePair, ScalingRecipe, amax, dequantize_scaled, quantize_scaled,
};

#[test]
fn current_scaling() {
    let r = ScalingRecipe::for_element::<F8E4M3>();
    assert_eq!(r.target_max(), 448.0);
    let s = r.current(&[0.5, -3.5, 1.0]);
    assert_eq!(s.scale, 128.0);
    assert_eq!(s.scale_inv, 1.0 / 128.0);
    // Margin divides by 2^margin.
    let s = r.with_margin(2).unwrap().current(&[0.5, -3.5]);
    assert_eq!(s.scale, 32.0);
    // Power-of-two scales round down: 448 / 3 = 149.3 → 128.
    let s = r.with_power_of_two(true).current(&[3.0]);
    assert_eq!((s.scale, s.scale_inv), (128.0, 2f32.powi(-7)));
    // Degenerate amax keeps the identity.
    assert_eq!(r.current(&[0.0, 0.0]), ScalePair::IDENTITY);
    assert_eq!(r.current(&[1.0, f32::NAN]), ScalePair::IDENTITY);
    assert_eq!(r.current(&[f32::INFINITY]), ScalePair::IDENTITY);
    assert_eq!(r.current(&[]), ScalePair::IDENTITY);
    // Tiny amax: the scale is capped instead of becoming infinite.
    let s = r.current(&[f32::from_bits(1)]);
    assert_eq!(s.scale, f32::MAX);
    assert!(s.scale_inv > 0.0);
    let s = r.with_power_of_two(true).current(&[f32::from_bits(1)]);
    assert_eq!(s.scale, 2f32.powi(127));
    // E5M2 target.
    assert_eq!(
        ScalingRecipe::for_element::<F8E5M2>()
            .current(&[57344.0])
            .scale,
        1.0
    );
}

#[test]
fn recipe_validation() {
    assert!(ScalingRecipe::new(0.0).is_err());
    assert!(ScalingRecipe::new(f32::INFINITY).is_err());
    assert!(ScalingRecipe::new(448.0).unwrap().with_margin(65).is_err());
    assert!(ScalePair::from_scale(-1.0).is_err());
    assert_eq!(ScalePair::from_scale(4.0).unwrap().scale_inv, 0.25);
    assert!(DelayedScaling::new(ScalingRecipe::new(1.0).unwrap(), 0, AmaxReduction::Max).is_err());
}

#[test]
fn delayed_scaling_window() {
    let r = ScalingRecipe::for_element::<F8E4M3>();
    let mut ds = DelayedScaling::new(r, 4, AmaxReduction::Max).unwrap();
    assert_eq!(ds.scale(), ScalePair::IDENTITY);
    assert_eq!(ds.reduced_amax(), 0.0);
    // A zero amax is recorded but cannot produce a scale.
    assert_eq!(ds.record(0.0), ScalePair::IDENTITY);
    for (amax, want_max) in [
        (2.0, 2.0),
        (8.0, 8.0),
        (1.0, 8.0),
        (4.0, 8.0),
        (1.0, 8.0),
        (0.5, 4.0),
    ] {
        let s = ds.record(amax);
        assert_eq!(ds.reduced_amax(), want_max);
        assert_eq!(s.scale, 448.0 / want_max);
        assert_eq!(ds.scale(), s);
    }
    assert_eq!(ds.history(), [1.0, 4.0, 1.0, 0.5]);
    // Non-finite amaxes are skipped and leave the scale alone.
    let before = ds.scale();
    assert_eq!(ds.record(f32::NAN), before);
    assert_eq!(ds.record(f32::INFINITY), before);
    assert_eq!(ds.record(-1.0), before);
    assert_eq!(ds.history(), [1.0, 4.0, 1.0, 0.5]);
    ds.reset();
    assert_eq!(ds.scale(), ScalePair::IDENTITY);
    assert!(ds.history().is_empty());
}

#[test]
fn delayed_scaling_most_recent() {
    let r = ScalingRecipe::for_element::<F8E4M3>()
        .with_margin(1)
        .unwrap();
    let mut ds = DelayedScaling::new(r, 16, AmaxReduction::MostRecent).unwrap();
    ds.record(7.0);
    ds.record(1.75);
    assert_eq!(ds.scale().scale, 448.0 / 1.75 / 2.0);
    ds.record_tensor(&[0.5, -3.5]);
    assert_eq!(ds.scale().scale, 64.0);
    assert_eq!(ds.history_len(), 16);
    assert_eq!(ds.history(), [7.0, 1.75, 3.5]);
}

#[test]
fn scaled_round_trip() {
    let mut rng = Rng(1);
    let x: Vec<f32> = (0..1000).map(|_| rng.uniform(-0.01, 0.01)).collect();
    let r = ScalingRecipe::for_element::<F8E4M3>();
    let s = r.current(&x);
    let mut q = vec![F8E4M3::ZERO; x.len()];
    quantize_scaled(&x, s, Overflow::Saturating, &mut q).unwrap();
    let mut y = vec![0.0f32; x.len()];
    dequantize_scaled(&q, s, &mut y).unwrap();
    let a = amax(&x);
    for (u, v) in x.iter().zip(&y) {
        // Relative error 2^-4 for normals; absolute floor from the subnormal step.
        assert!(
            (u - v).abs() <= u.abs() / 16.0 + a / 448.0 * 2f32.powi(-9),
            "{u} vs {v}"
        );
    }
    // Without scaling these values would mostly be subnormal or zero in E4M3.
    assert!(q.iter().any(|v| v.to_f32().abs() > 256.0));
    assert_eq!(
        quantize_scaled(&x, s, Overflow::Saturating, &mut q[1..]),
        Err(LowpError::LengthMismatch {
            expected: 1000,
            found: 999
        })
    );
    assert!(dequantize_scaled(&q[1..], s, &mut y).is_err());
}

#[test]
fn amax_helper() {
    assert_eq!(amax(&[]), 0.0);
    assert_eq!(amax(&[-0.0, -2.0, 1.0]), 2.0);
    assert_eq!(amax(&[f32::NEG_INFINITY, 1.0]), f32::INFINITY);
    let mut big = vec![1.0f32; 1 << 17];
    big[100_000] = -9.0;
    assert_eq!(amax(&big), 9.0);
    big[5] = f32::NAN;
    assert!(amax(&big).is_nan());
}

#[test]
fn block_scaled_tiles() {
    let (rows, cols) = (130, 260); // edge tiles in both directions
    let mut rng = Rng(2);
    let x: Vec<f32> = (0..rows * cols)
        .map(|i| {
            let (r, c) = (i / cols, i % cols);
            // Different magnitude per tile.
            rng.uniform(-1.0, 1.0) * 10f32.powi(((r / 128) * 3 + c / 128) as i32 - 2)
        })
        .collect();
    let recipe = ScalingRecipe::for_element::<F8E4M3>();
    let m = BlockScaledMatrix::<F8E4M3>::quantize(&x, rows, cols, 128, 128, recipe).unwrap();
    assert_eq!((m.grid_rows(), m.grid_cols()), (2, 3));
    assert_eq!(m.scales().len(), 6);
    assert_eq!(
        (m.rows(), m.cols(), m.block_rows(), m.block_cols()),
        (rows, cols, 128, 128)
    );
    // Each tile scale comes from that tile's amax.
    for gr in 0..2 {
        for gc in 0..3 {
            let mut t = 0.0f32;
            for r in gr * 128..((gr + 1) * 128).min(rows) {
                for c in gc * 128..((gc + 1) * 128).min(cols) {
                    t = t.max(x[r * cols + c].abs());
                }
            }
            assert_eq!(
                m.scales()[gr * 3 + gc],
                recipe.scale_from_amax(t, ScalePair::IDENTITY)
            );
        }
    }
    let y = m.dequantize();
    for i in 0..x.len() {
        let (r, c) = (i / cols, i % cols);
        let s = m.scales()[(r / 128) * 3 + c / 128];
        let tile_floor = s.scale_inv * 2f32.powi(-9);
        assert!((x[i] - y[i]).abs() <= x[i].abs() / 16.0 + tile_floor, "{i}");
        assert!(m.data()[i].to_f32().abs() <= 448.0);
    }
    // 1 × 128 activation tiles.
    let a = BlockScaledMatrix::<F8E4M3>::quantize(&x, rows, cols, 1, 128, recipe).unwrap();
    assert_eq!(a.scales().len(), rows * 3);
}

#[test]
fn block_scaled_specials_and_validation() {
    let recipe = ScalingRecipe::for_element::<F8E4M3>().with_power_of_two(true);
    let mut x = vec![1.0f32; 8];
    x[5] = f32::NAN;
    let m = BlockScaledMatrix::<F8E4M3>::quantize(&x, 2, 4, 1, 4, recipe).unwrap();
    assert_eq!(m.scales()[0].scale, 256.0);
    assert_eq!(m.scales()[1], ScalePair::IDENTITY);
    let y = m.dequantize();
    assert_eq!(&y[..4], [1.0; 4]);
    assert!(y[5].is_nan());
    assert!(BlockScaledMatrix::<F8E4M3>::quantize(&x, 2, 4, 0, 4, recipe).is_err());
    assert!(BlockScaledMatrix::<F8E4M3>::quantize(&x, 3, 4, 1, 4, recipe).is_err());
    let e = BlockScaledMatrix::<F8E4M3>::quantize(&[], 0, 0, 1, 128, recipe).unwrap();
    assert!(e.dequantize().is_empty());
}
