//! Rotary embeddings: reference rotation, inverse, relative-position
//! property and pinned scaling formulas.

#![allow(
    clippy::unwrap_used,
    clippy::doc_markdown,
    clippy::missing_const_for_fn,
    clippy::excessive_precision,
    clippy::too_many_arguments,
    clippy::needless_range_loop,
    clippy::redundant_clone,
    clippy::many_single_char_names,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    clippy::suboptimal_flops,
    clippy::float_cmp
)]

mod common;

use common::{Rng, assert_close, bits, check_fd, dot, same_on_all_pools};
use proptest::prelude::*;
use rune_fused::{
    FusedError, RopeConfig, RopeLayout, RopeScaling, RopeTable, YarnScaling, packed_positions,
};

fn rope_ref(
    x: &[f32],
    heads: usize,
    hd: usize,
    pos: &[usize],
    inv: &[f64],
    af: f64,
    layout: RopeLayout,
) -> Vec<f64> {
    let half = inv.len();
    let mut out: Vec<f64> = x.iter().map(|&v| f64::from(v)).collect();
    for (t, &p) in pos.iter().enumerate() {
        for h in 0..heads {
            let base = (t * heads + h) * hd;
            for i in 0..half {
                let (a, b) = match layout {
                    RopeLayout::HalfSplit => (base + i, base + i + half),
                    RopeLayout::Interleaved => (base + 2 * i, base + 2 * i + 1),
                };
                let th = p as f64 * inv[i];
                let (s, c) = (th.sin() * af, th.cos() * af);
                let (x0, x1) = (f64::from(x[a]), f64::from(x[b]));
                out[a] = x0 * c - x1 * s;
                out[b] = x1 * c + x0 * s;
            }
        }
    }
    out
}

const LAYOUTS: [RopeLayout; 2] = [RopeLayout::HalfSplit, RopeLayout::Interleaved];

#[test]
fn apply_matches_reference_including_partial_rotary() {
    let mut rng = Rng::new(20);
    let (tokens, heads, hd) = (6, 3, 16);
    for r in [16, 8, 2] {
        let cfg = RopeConfig::new(r, 10_000.0).unwrap();
        let table = RopeTable::new(&cfg, 64).unwrap();
        let pos: Vec<usize> = (0..tokens).map(|_| rng.below(64)).collect();
        let x = rng.vec(tokens * heads * hd, 1.0);
        for layout in LAYOUTS {
            let mut y = x.clone();
            table.apply(&mut y, heads, hd, &pos, layout).unwrap();
            let want = rope_ref(&x, heads, hd, &pos, &cfg.inv_freq(64), 1.0, layout);
            assert_close("rope", &y, &want, 1e-6, 1e-6);
            // The pass-through dimensions are untouched, bit for bit.
            for (head_y, head_x) in y.chunks(hd).zip(x.chunks(hd)) {
                assert_eq!(bits(&head_y[r..]), bits(&head_x[r..]));
            }
        }
    }
}

#[test]
fn backward_is_inverse_and_gradient() {
    let mut rng = Rng::new(21);
    let (tokens, heads, hd) = (5, 2, 12);
    let cfg = RopeConfig::new(8, 10_000.0).unwrap();
    let table = RopeTable::new(&cfg, 1000).unwrap();
    let pos = [0usize, 1, 999, 500, 3];
    let x = rng.vec(tokens * heads * hd, 1.0);
    let dy = rng.vec(tokens * heads * hd, 1.0);
    for layout in LAYOUTS {
        let mut y = x.clone();
        table.apply(&mut y, heads, hd, &pos, layout).unwrap();
        table
            .apply_backward(&mut y, heads, hd, &pos, layout)
            .unwrap();
        let x64: Vec<f64> = x.iter().map(|&v| f64::from(v)).collect();
        assert_close("inverse", &y, &x64, 1e-6, 0.0);

        let mut dx = dy.clone();
        table
            .apply_backward(&mut dx, heads, hd, &pos, layout)
            .unwrap();
        check_fd("rope dx", &x, &dx, 1e-2, 1e-4, |xp| {
            let mut y = xp.to_vec();
            table.apply(&mut y, heads, hd, &pos, layout).unwrap();
            dot(&y, &dy)
        });
    }
    // With an attention factor the backward is the transpose, still the
    // gradient.
    let yarn = cfg
        .with_scaling(RopeScaling::Yarn(YarnScaling::new(4.0, 64)))
        .unwrap();
    let table = RopeTable::new(&yarn, 1000).unwrap();
    let mut dx = dy.clone();
    table
        .apply_backward(&mut dx, heads, hd, &pos, RopeLayout::HalfSplit)
        .unwrap();
    check_fd("yarn dx", &x, &dx, 1e-2, 1e-4, |xp| {
        let mut y = xp.to_vec();
        table
            .apply(&mut y, heads, hd, &pos, RopeLayout::HalfSplit)
            .unwrap();
        dot(&y, &dy)
    });
}

#[test]
fn scores_depend_only_on_relative_position() {
    let mut rng = Rng::new(22);
    let hd = 64;
    let cfg = RopeConfig::new(hd, 10_000.0).unwrap();
    let table = RopeTable::new(&cfg, 4096).unwrap();
    let q = rng.vec(hd, 1.0);
    let k = rng.vec(hd, 1.0);
    for layout in LAYOUTS {
        let score = |m: usize, n: usize| {
            let (mut qm, mut kn) = (q.clone(), k.clone());
            table.apply(&mut qm, 1, hd, &[m], layout).unwrap();
            table.apply(&mut kn, 1, hd, &[n], layout).unwrap();
            dot(&qm, &kn)
        };
        for &(m, n) in &[(5usize, 2usize), (100, 0), (37, 37), (3, 90)] {
            let s0 = score(m, n);
            for shift in [1usize, 17, 1000, 3000] {
                let s = score(m + shift, n + shift);
                assert!((s - s0).abs() < 2e-5, "{m},{n} shift {shift}: {s} vs {s0}");
            }
        }
        // And the score actually varies with the offset.
        assert!((score(10, 0) - score(0, 0)).abs() > 1e-3);
    }
}

#[test]
fn layouts_are_permutations_of_each_other() {
    let mut rng = Rng::new(23);
    let hd = 10;
    let table = RopeTable::new(&RopeConfig::new(hd, 500.0).unwrap(), 50).unwrap();
    let x = rng.vec(hd, 1.0);
    let half = hd / 2;
    // interleaved[2i] = half[i], interleaved[2i+1] = half[i + half]
    let mut inter = vec![0.0; hd];
    for i in 0..half {
        inter[2 * i] = x[i];
        inter[2 * i + 1] = x[i + half];
    }
    let mut a = x.clone();
    table
        .apply(&mut a, 1, hd, &[7], RopeLayout::HalfSplit)
        .unwrap();
    table
        .apply(&mut inter, 1, hd, &[7], RopeLayout::Interleaved)
        .unwrap();
    for i in 0..half {
        assert_eq!(a[i], inter[2 * i]);
        assert_eq!(a[i + half], inter[2 * i + 1]);
    }
}

#[test]
fn packed_sequences_restart_positions() {
    let mut rng = Rng::new(24);
    let (heads, hd) = (2, 8);
    let table = RopeTable::new(&RopeConfig::new(hd, 10_000.0).unwrap(), 16).unwrap();
    let lens = [3usize, 5, 1];
    let pos = packed_positions(&lens);
    assert_eq!(pos, vec![0, 1, 2, 0, 1, 2, 3, 4, 0]);
    let x = rng.vec(9 * heads * hd, 1.0);
    let mut packed = x.clone();
    table
        .apply(&mut packed, heads, hd, &pos, RopeLayout::HalfSplit)
        .unwrap();
    let mut start = 0;
    for &l in &lens {
        let seq = &x[start * heads * hd..(start + l) * heads * hd];
        let mut y = seq.to_vec();
        let p: Vec<usize> = (0..l).collect();
        table
            .apply(&mut y, heads, hd, &p, RopeLayout::HalfSplit)
            .unwrap();
        assert_eq!(
            bits(&y),
            bits(&packed[start * heads * hd..(start + l) * heads * hd])
        );
        start += l;
    }
}

fn close(a: f64, b: f64, rel: f64) {
    assert!((a - b).abs() <= rel * b.abs(), "{a} vs {b}");
}

#[test]
fn plain_and_linear_frequencies() {
    let cfg = RopeConfig::new(8, 10_000.0).unwrap();
    // θ_i = 10000^(-2i/8) = 10^(-i)
    let inv = cfg.inv_freq(0);
    for (i, v) in inv.iter().enumerate() {
        close(*v, 10f64.powi(-(i as i32)), 1e-15);
    }
    let lin = cfg
        .with_scaling(RopeScaling::Linear { factor: 4.0 })
        .unwrap();
    for (a, b) in lin.inv_freq(0).iter().zip(&inv) {
        close(*a, b / 4.0, 1e-15);
    }
    // Linear interpolation: position 4p with factor 4 = position p plain.
    let t_lin = RopeTable::new(&lin, 64).unwrap();
    let t = RopeTable::new(&cfg, 64).unwrap();
    assert_eq!(t_lin.cos(40).unwrap(), t.cos(10).unwrap());
}

#[test]
fn ntk_pins() {
    // base' = 10000 · 4^(128/126) = 40889.94243248622.
    let cfg = RopeConfig::new(128, 10_000.0)
        .unwrap()
        .with_scaling(RopeScaling::Ntk { factor: 4.0 })
        .unwrap();
    let inv = cfg.inv_freq(0);
    close(inv[0], 1.0, 0.0);
    close(inv[1], 0.847_117_185_151_206_8, 1e-14);
    close(inv[63], 2.886_954_961_723_645_2e-5, 1e-13);
    // The lowest frequency is the plain one divided by exactly the factor.
    let plain = RopeConfig::new(128, 10_000.0).unwrap().inv_freq(0);
    close(inv[63], plain[63] / 4.0, 1e-13);
}

#[test]
fn dynamic_ntk_pins() {
    let cfg = RopeConfig::new(128, 10_000.0)
        .unwrap()
        .with_scaling(RopeScaling::DynamicNtk {
            factor: 2.0,
            original_max_positions: 2048,
        })
        .unwrap();
    let plain = RopeConfig::new(128, 10_000.0).unwrap().inv_freq(0);
    // Within the original context nothing changes.
    assert_eq!(cfg.inv_freq(1000), plain);
    assert_eq!(cfg.inv_freq(2048), plain);
    // L = 4096: base' = 10000 · (2 · 2 - 1)^(128/126) = 30527.7367488067.
    let inv = cfg.inv_freq(4096);
    close(inv[63], 3.849_273_282_298_194e-5, 1e-13);
    close(
        inv[63],
        1.0 / 30_527.736_748_806_7f64.powf(126.0 / 128.0),
        1e-13,
    );
}

#[test]
fn yarn_pins() {
    // r = 128, base 1e4, s = 4, original context 4096, β = (32, 1):
    // correction dims 20.944 and 45.027 → ramp over [20, 46].
    let y = YarnScaling::new(4.0, 4096);
    let cfg = RopeConfig::new(128, 10_000.0)
        .unwrap()
        .with_scaling(RopeScaling::Yarn(y))
        .unwrap();
    let inv = cfg.inv_freq(0);
    let plain = RopeConfig::new(128, 10_000.0).unwrap().inv_freq(0);
    close(inv[0], 1.0, 0.0);
    // Below the ramp: extrapolated (kept).
    assert_eq!(inv[20], plain[20]);
    close(inv[20], 0.056_234_132_519_034_905, 1e-14);
    close(inv[21], 0.047_292_038_501_684_786, 1e-14);
    close(inv[33], 0.005_412_277_021_000_408, 1e-14);
    // From the end of the ramp on: fully interpolated.
    close(inv[46], 0.000_333_380_358_040_831, 1e-14);
    close(inv[46], plain[46] / 4.0, 1e-14);
    close(inv[63], plain[63] / 4.0, 1e-14);
    // Temperature 0.1 ln 4 + 1.
    close(cfg.attention_factor(), 1.138_629_436_111_989, 1e-15);
    let table = RopeTable::new(&cfg, 8).unwrap();
    assert_eq!(table.cos(0).unwrap()[5], 1.138_629_436_111_989f64 as f32);
    assert_eq!(table.sin(0).unwrap()[5], 0.0);

    // mscale / mscale_all_dim ratio: m(40, 0.707) / m(40, 1).
    let ds = YarnScaling {
        mscale: Some(0.707),
        mscale_all_dim: Some(1.0),
        ..YarnScaling::new(40.0, 4096)
    };
    close(ds.attention_factor(), 0.921_042_355_316_339_9, 1e-14);
    // Equal coefficients cancel to 1; only one set falls back to m(s, 1).
    let eq = YarnScaling {
        mscale: Some(1.0),
        mscale_all_dim: Some(1.0),
        ..YarnScaling::new(40.0, 4096)
    };
    assert_eq!(eq.attention_factor(), 1.0);
    let one = YarnScaling {
        mscale: Some(0.707),
        ..YarnScaling::new(40.0, 4096)
    };
    close(one.attention_factor(), 0.1 * 40f64.ln() + 1.0, 1e-15);
    let fixed = YarnScaling {
        attention_factor: Some(0.5),
        ..YarnScaling::new(40.0, 4096)
    };
    assert_eq!(fixed.attention_factor(), 0.5);
    // No extension: temperature 1.
    assert_eq!(YarnScaling::new(1.0, 4096).attention_factor(), 1.0);
}

#[test]
fn wavelength_band_pins() {
    // r = 128, base 5e5, factor 8, band factors 1 and 4, original 8192.
    let cfg = RopeConfig::new(128, 500_000.0)
        .unwrap()
        .with_scaling(RopeScaling::WavelengthBands {
            factor: 8.0,
            low_freq_factor: 1.0,
            high_freq_factor: 4.0,
            original_max_positions: 8192,
        })
        .unwrap();
    let inv = cfg.inv_freq(0);
    let plain = RopeConfig::new(128, 500_000.0).unwrap().inv_freq(0);
    // High-frequency band (wavelength < 2048) kept: indices 0..29.
    for i in 0..29 {
        assert_eq!(inv[i], plain[i]);
    }
    // Smoothed band: indices 29..35.
    close(inv[29], 0.002_166_570_763_503_359, 1e-13);
    close(inv[31], 0.000_856_751_412_919_632_1, 1e-13);
    close(inv[34], 0.000_178_507_812_767_996_38, 1e-13);
    // Low-frequency band (wavelength > 8192) divided by 8.
    close(inv[40], 3.428_102_195_952_591e-5, 1e-13);
    close(inv[63], 3.068_925_988_914_511e-7, 1e-13);
    for i in 35..64 {
        close(inv[i], plain[i] / 8.0, 1e-15);
    }
}

#[test]
fn table_is_computed_in_f64() {
    // θ_0 = 1, so cos at position p is cos(p); at p = 100000 an f32 angle
    // would be off by up to 4e-3 radians.
    let table = RopeTable::new(&RopeConfig::new(2, 10_000.0).unwrap(), 100_001).unwrap();
    let c = table.cos(100_000).unwrap()[0];
    let s = table.sin(100_000).unwrap()[0];
    assert_eq!(c, 100_000f64.cos() as f32);
    assert_eq!(s, 100_000f64.sin() as f32);
    assert!(table.cos(100_001).is_none());
}

#[test]
fn errors() {
    assert!(RopeConfig::new(0, 10_000.0).is_err());
    assert!(RopeConfig::new(7, 10_000.0).is_err());
    assert!(RopeConfig::new(8, 1.0).is_err());
    assert!(RopeConfig::new(8, f64::NAN).is_err());
    let cfg = RopeConfig::new(8, 10_000.0).unwrap();
    assert!(
        cfg.with_scaling(RopeScaling::Linear { factor: 0.0 })
            .is_err()
    );
    assert!(
        RopeConfig::new(2, 10_000.0)
            .unwrap()
            .with_scaling(RopeScaling::Ntk { factor: 2.0 })
            .is_err()
    );
    assert!(
        cfg.with_scaling(RopeScaling::DynamicNtk {
            factor: 0.5,
            original_max_positions: 10
        })
        .is_err()
    );
    assert!(
        cfg.with_scaling(RopeScaling::WavelengthBands {
            factor: 8.0,
            low_freq_factor: 4.0,
            high_freq_factor: 1.0,
            original_max_positions: 8192
        })
        .is_err()
    );
    assert!(
        cfg.with_scaling(RopeScaling::Yarn(YarnScaling::new(4.0, 0)))
            .is_err()
    );
    let table = RopeTable::new(&cfg, 10).unwrap();
    let mut x = vec![1.0f32; 2 * 8];
    assert!(matches!(
        table.apply(&mut x, 1, 8, &[0, 10], RopeLayout::HalfSplit),
        Err(FusedError::PositionOutOfRange {
            index: 1,
            position: 10,
            len: 10
        })
    ));
    assert_eq!(x, vec![1.0; 16], "no partial update on error");
    assert!(
        table
            .apply(&mut x, 1, 4, &[0, 1], RopeLayout::HalfSplit)
            .is_err()
    );
    assert!(
        table
            .apply(&mut x, 1, 8, &[0], RopeLayout::HalfSplit)
            .is_err()
    );
    assert!(
        table
            .apply(&mut x, 0, 8, &[], RopeLayout::HalfSplit)
            .is_err()
    );
    assert!(RopeTable::from_inv_freq(&[], 1.0, 4).is_err());
    assert!(RopeTable::from_inv_freq(&[f64::NAN], 1.0, 4).is_err());
    table
        .apply(&mut [], 2, 8, &[], RopeLayout::Interleaved)
        .unwrap();
}

#[test]
fn deterministic_across_thread_counts() {
    let mut rng = Rng::new(25);
    let (tokens, heads, hd) = (300, 4, 64);
    let cfg = RopeConfig::new(48, 10_000.0)
        .unwrap()
        .with_scaling(RopeScaling::Yarn(YarnScaling::new(8.0, 256)))
        .unwrap();
    let pos: Vec<usize> = (0..tokens).map(|_| rng.below(2048)).collect();
    let x = rng.vec(tokens * heads * hd, 1.0);
    same_on_all_pools(|| {
        let table = RopeTable::new(&cfg, 2048).unwrap();
        let mut y = x.clone();
        table
            .apply(&mut y, heads, hd, &pos, RopeLayout::Interleaved)
            .unwrap();
        let mut g = x.clone();
        table
            .apply_backward(&mut g, heads, hd, &pos, RopeLayout::HalfSplit)
            .unwrap();
        (bits(&y), bits(&g), table)
    });
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(48))]

    #[test]
    fn prop_rope_any_shape(
        tokens in 0usize..8,
        heads in 1usize..4,
        half_hd in 1usize..20,
        rfrac in 0.0f64..=1.0,
        interleaved in any::<bool>(),
        seed in any::<u64>(),
    ) {
        let hd = 2 * half_hd;
        let r = (2 * ((half_hd as f64 * rfrac).round() as usize)).max(2);
        let mut rng = Rng::new(seed);
        let cfg = RopeConfig::new(r, 10_000.0).unwrap();
        let table = RopeTable::new(&cfg, 128).unwrap();
        let pos: Vec<usize> = (0..tokens).map(|_| rng.below(128)).collect();
        let x = rng.vec(tokens * heads * hd, 1.0);
        let layout = if interleaved { RopeLayout::Interleaved } else { RopeLayout::HalfSplit };
        let mut y = x.clone();
        table.apply(&mut y, heads, hd, &pos, layout).unwrap();
        let want = rope_ref(&x, heads, hd, &pos, &cfg.inv_freq(128), 1.0, layout);
        assert_close("rope", &y, &want, 1e-6, 1e-6);
        table.apply_backward(&mut y, heads, hd, &pos, layout).unwrap();
        let x64: Vec<f64> = x.iter().map(|&v| f64::from(v)).collect();
        assert_close("inverse", &y, &x64, 1e-6, 0.0);
    }
}
