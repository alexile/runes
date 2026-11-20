//! Microscaling formats: hand-computed spec examples, a naive reference
//! implementation of the OCP MX algorithm, packing, and the 16-element FP4
//! variant.

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

use common::{RefRound, Rng, positive_table, ref_decode, ref_encode};
use rune_lowp::pack::{pack_fp4, pack_fp6, packed_len, unpack_fp4, unpack_fp6};
use rune_lowp::{
    E8M0, F8E4M3, Fp4x16Tensor, LowpError, MX_BLOCK_SIZE, MxElement, MxTensor, mx_block_scale,
};

#[test]
fn spec_example_fp4() {
    // amax 1.75 → floor(log2) = 0, emax(E2M1) = 2 → X = 2^-2.
    let mut x = vec![0.0f32; 32];
    x[0] = 1.0; // 4 → code 0b0110
    x[1] = 0.3; // 1.2 → 1.0 → code 0b0010
    x[2] = -1.75; // -7 → saturates to -6 → code 0b1111
    x[3] = 0.125; // 0.5 → code 0b0001
    x[4] = 0.0625; // 0.25 → tie between 0 and 0.5 → 0
    x[5] = 0.625; // 2.5 → tie between 2 and 3 → 2 → code 0b0100
    let q = MxTensor::quantize(MxElement::Fp4E2M1, &x).unwrap();
    assert_eq!(q.scales(), [E8M0::from_exponent(-2).unwrap()]);
    assert_eq!(
        &q.codes()[..6],
        [0b0110, 0b0010, 0b1111, 0b0001, 0b0000, 0b0100]
    );
    assert_eq!(q.data().len(), 16);
    assert_eq!(q.data()[0], 0b0010_0110);
    assert_eq!(q.data()[1], 0b0001_1111);
    let y = q.dequantize();
    assert_eq!(&y[..6], [1.0, 0.25, -1.5, 0.125, 0.0, 0.5]);
}

#[test]
fn spec_example_fp8() {
    // E4M3: amax 1 → shared exponent 0 - 8 = -8.
    let mut x = vec![0.0f32; 32];
    x[0] = 1.0; // 256 = 2^8 → 0x78
    x[1] = 2f32.powi(-10); // 0.25 = 2^-2 → 0x28
    x[2] = -0.75; // -192 → 0xF0 | ... = 1.5·2^7 → 0b1_1110_100 = 0xF4
    let q = MxTensor::quantize(MxElement::Fp8E4M3, &x).unwrap();
    assert_eq!(q.scales()[0].exponent(), Some(-8));
    assert_eq!(&q.data()[..3], [0x78, 0x28, 0xF4]);
    assert_eq!(&q.dequantize()[..3], &x[..3]);
    // E5M2: amax 1000 → floor(log2) = 9, emax 15 → -6.
    let mut x = vec![0.0f32; 32];
    x[0] = 1000.0;
    let q = MxTensor::quantize(MxElement::Fp8E5M2, &x).unwrap();
    assert_eq!(q.scales()[0].exponent(), Some(-6));
    // 1000 · 2^6 = 64000 exceeds the E5M2 max: it saturates to 57344 · 2^-6.
    assert_eq!(q.dequantize()[0], 896.0);
}

#[test]
fn spec_example_fp6() {
    // E3M2: amax 28 → floor(log2 28) = 4 = emax → X = 1.
    let x: Vec<f32> = [28.0, 26.0, 0.0625, 0.03125, -3.3]
        .into_iter()
        .chain([0.0; 27])
        .collect();
    let q = MxTensor::quantize(MxElement::Fp6E3M2, &x).unwrap();
    assert_eq!(q.scales()[0], E8M0::ONE);
    assert_eq!(&q.dequantize()[..5], [28.0, 24.0, 0.0625, 0.0, -3.5]);
    assert_eq!(q.data().len(), 24);
    // E2M3: amax 7.9 → floor(log2) = 2 = emax → X = 1 and 7.9 saturates.
    let x: Vec<f32> = [7.9, -0.1].into_iter().chain([0.0; 30]).collect();
    let q = MxTensor::quantize(MxElement::Fp6E2M3, &x).unwrap();
    assert_eq!(q.scales()[0], E8M0::ONE);
    assert_eq!(&q.dequantize()[..2], [7.5, -0.125]);
}

#[test]
fn special_blocks() {
    let mut x = vec![1.0f32; 96];
    x[32..64].fill(0.0);
    x[70] = f32::NAN;
    let q = MxTensor::quantize(MxElement::Fp8E4M3, &x).unwrap();
    assert_eq!(q.scales()[1], E8M0::MIN); // all-zero block: smallest scale
    assert!(q.scales()[2].is_nan());
    let y = q.dequantize();
    assert!(y[..32].iter().all(|&v| v == 1.0));
    assert!(y[32..64].iter().all(|&v| v == 0.0));
    assert!(y[64..].iter().all(|v| v.is_nan()));
    // Infinity also poisons only its block.
    let mut x = vec![0.5f32; 64];
    x[0] = f32::NEG_INFINITY;
    let q = MxTensor::quantize(MxElement::Fp4E2M1, &x).unwrap();
    assert!(q.scales()[0].is_nan());
    assert_eq!(q.dequantize()[40], 0.5);
    // Tiny amax: the scale clamps at 2^-127; f32 subnormal inputs are handled.
    let x = vec![1e-40f32; 32];
    let q = MxTensor::quantize(MxElement::Fp8E4M3, &x).unwrap();
    assert_eq!(q.scales()[0], E8M0::MIN);
    let y = q.dequantize();
    assert!((y[0] - 1e-40).abs() <= 1e-40 / 8.0);
    // Huge values.
    let x = vec![f32::MAX; 32];
    let q = MxTensor::quantize(MxElement::Fp4E2M1, &x).unwrap();
    assert_eq!(q.scales()[0].exponent(), Some(125));
    assert_eq!(q.dequantize()[0], 6.0 * 2f32.powi(125));
}

#[test]
fn block_scale_helper() {
    assert_eq!(mx_block_scale(&[3.0, -5.0], MxElement::Fp4E2M1), E8M0::ONE);
    assert_eq!(mx_block_scale(&[448.0], MxElement::Fp8E4M3), E8M0::ONE);
    assert_eq!(
        mx_block_scale(&[512.0], MxElement::Fp8E4M3).exponent(),
        Some(1)
    );
    assert!(mx_block_scale(&[f32::NAN], MxElement::Fp8E5M2).is_nan());
}

/// Naive OCP MX quantization in f64: amax, floor(log2), nearest-even
/// element rounding with saturation.
fn reference_mx(element: MxElement, block: &[f32]) -> (Option<i32>, Vec<u16>) {
    let f = element.format();
    let table = positive_table(f);
    if block.iter().any(|v| !v.is_finite()) {
        return (None, vec![0; block.len()]);
    }
    let amax = block.iter().fold(0.0f64, |m, &v| m.max(f64::from(v).abs()));
    let shared = if amax == 0.0 {
        -127
    } else {
        (amax.log2().floor() as i32 - element.emax()).clamp(-127, 127)
    };
    let codes = block
        .iter()
        .map(|&v| {
            let scaled = f64::from(v) / 2f64.powi(shared);
            // Exact: scaled has at most 24 significant bits and is within the
            // f32 exponent range here.
            ref_encode(f, &table, scaled as f32, RefRound::NearestEven, true)
        })
        .collect();
    (Some(shared), codes)
}

#[test]
fn matches_naive_reference() {
    let mut rng = Rng(11);
    for element in MxElement::ALL {
        for trial in 0..60 {
            let cols = 1 + (rng.next_u32() % 100) as usize;
            let rows = 1 + (rng.next_u32() % 4) as usize;
            let center = (rng.next_u32() % 60) as i32 - 30;
            let x: Vec<f32> = (0..rows * cols)
                .map(|i| {
                    if (i + trial) % 17 == 0 {
                        0.0
                    } else {
                        rng.near_exponent(center, 6)
                    }
                })
                .collect();
            let q = MxTensor::quantize_rows(element, &x, rows, cols).unwrap();
            assert_eq!(q.row_bytes(), element.packed_len(cols));
            let codes = q.codes();
            let bpr = cols.div_ceil(MX_BLOCK_SIZE);
            for r in 0..rows {
                for b in 0..bpr {
                    let lo = r * cols + b * MX_BLOCK_SIZE;
                    let hi = (lo + MX_BLOCK_SIZE).min((r + 1) * cols);
                    let (shared, want) = reference_mx(element, &x[lo..hi]);
                    assert_eq!(q.scales()[r * bpr + b].exponent(), shared, "{element:?}");
                    let got: Vec<u16> = codes[lo..hi].iter().map(|&c| u16::from(c)).collect();
                    assert_eq!(got, want, "{element:?} row {r} block {b}");
                }
            }
            // Dequantization is P · X, exactly (no f32 underflow at these scales).
            let y = q.dequantize();
            for r in 0..rows {
                for c in 0..cols {
                    let i = r * cols + c;
                    let s = q.scales()[r * bpr + c / MX_BLOCK_SIZE].exponent().unwrap();
                    let want = ref_decode(element.format(), u16::from(codes[i])) * 2f64.powi(s);
                    assert_eq!(f64::from(y[i]), want);
                }
            }
        }
    }
}

#[test]
fn representable_tensors_round_trip_exactly() {
    let mut rng = Rng(3);
    for element in MxElement::ALL {
        let f = element.format();
        let finite: Vec<u16> = (0..f.code_count() as u16)
            .filter(|&c| f.decode(c).is_finite())
            .collect();
        for _ in 0..20 {
            let mut codes: Vec<u16> = (0..64)
                .map(|_| finite[(rng.next_u32() as usize) % finite.len()])
                .collect();
            // Make sure the block amax is a max-binade value so X is reproduced.
            codes[0] = f.max_code();
            codes[32] = f.max_code() | (1 << (f.bits() - 1));
            let k = (rng.next_u32() % 40) as i32 - 20;
            let x: Vec<f32> = codes.iter().map(|&c| f.decode(c) * 2f32.powi(k)).collect();
            let q = MxTensor::quantize(element, &x).unwrap();
            assert_eq!(q.dequantize(), x, "{element:?}");
        }
    }
}

#[test]
fn stochastic_mx_is_unbiased_and_keeps_scales() {
    let mut rng = Rng(8);
    let x: Vec<f32> = (0..32).map(|i| 0.1 + i as f32 * 0.137).collect();
    let nearest = MxTensor::quantize(MxElement::Fp4E2M1, &x).unwrap();
    let trials = 4000;
    let mut mean = vec![0.0f64; 32];
    for _ in 0..trials {
        let rand: Vec<u32> = (0..32).map(|_| rng.next_u32()).collect();
        let q = MxTensor::quantize_rows_stochastic(MxElement::Fp4E2M1, &x, 1, 32, &rand).unwrap();
        assert_eq!(q.scales(), nearest.scales());
        for (m, v) in mean.iter_mut().zip(q.dequantize()) {
            *m += f64::from(v) / f64::from(trials);
        }
    }
    assert_eq!(nearest.scales()[0], E8M0::ONE); // amax 4.35 → X = 1, nothing saturates
    for (i, (&m, &v)) in mean.iter().zip(&x).enumerate() {
        // Element step at most 2 here; 6 sigma of the mean.
        let tol = 6.0 * 2.0 / (2.0 * f64::from(trials).sqrt());
        assert!((m - f64::from(v)).abs() <= tol, "element {i}: {m} vs {v}");
    }
    assert!(MxTensor::quantize_rows_stochastic(MxElement::Fp4E2M1, &x, 1, 32, &[0; 3]).is_err());
}

#[test]
fn shapes_and_parts() {
    // 2 rows of 33: each row has 2 blocks and its own packed storage.
    let x: Vec<f32> = (0..66).map(|i| i as f32).collect();
    let q = MxTensor::quantize_rows(MxElement::Fp6E2M3, &x, 2, 33).unwrap();
    assert_eq!(q.blocks_per_row(), 2);
    assert_eq!(q.scales().len(), 4);
    assert_eq!(q.row_bytes(), 27);
    assert_eq!(q.data().len(), 54);
    // Row 1, block 1 is the single element 65.0.
    assert_eq!(q.scales()[3].exponent(), Some(6 - 2));
    let (scales, data) = q.clone().into_parts();
    let back =
        MxTensor::from_parts(MxElement::Fp6E2M3, 2, 33, scales.clone(), data.clone()).unwrap();
    assert_eq!(back, q);
    assert!(
        MxTensor::from_parts(
            MxElement::Fp6E2M3,
            2,
            33,
            scales[1..].to_vec(),
            data.clone()
        )
        .is_err()
    );
    assert!(MxTensor::from_parts(MxElement::Fp6E2M3, 2, 33, scales, data[1..].to_vec()).is_err());
    assert_eq!(
        MxTensor::quantize_rows(MxElement::Fp4E2M1, &x, 3, 33),
        Err(LowpError::LengthMismatch {
            expected: 99,
            found: 66
        })
    );
    assert!(MxTensor::quantize_rows(MxElement::Fp4E2M1, &x, 0, 66).is_err());
    assert!(MxTensor::quantize_rows(MxElement::Fp4E2M1, &x, usize::MAX, 2).is_err());
    let empty = MxTensor::quantize(MxElement::Fp4E2M1, &[]).unwrap();
    assert!(empty.is_empty());
    assert!(empty.dequantize().is_empty());
    let mut out = vec![0.0; 65];
    assert!(q.dequantize_into(&mut out).is_err());
}

#[test]
fn large_tensor_parallel_path_matches_rows() {
    // Above the parallel threshold, one long row and many short rows.
    let mut rng = Rng(21);
    let n = 1 << 17;
    let x: Vec<f32> = (0..n).map(|_| rng.uniform(-10.0, 10.0)).collect();
    let whole = MxTensor::quantize(MxElement::Fp8E5M2, &x).unwrap();
    let rows = MxTensor::quantize_rows(MxElement::Fp8E5M2, &x, n / 64, 64).unwrap();
    assert_eq!(whole.data(), rows.data());
    assert_eq!(whole.scales(), rows.scales());
    assert_eq!(whole.dequantize(), rows.dequantize());
}

#[test]
fn packing() {
    let mut rng = Rng(4);
    for n in [0usize, 1, 2, 3, 4, 5, 31, 32, 33, 100] {
        let c4: Vec<u8> = (0..n).map(|_| (rng.next_u32() & 0xF) as u8).collect();
        let p = pack_fp4(&c4);
        assert_eq!(p.len(), packed_len(4, n));
        assert_eq!(unpack_fp4(&p, n).unwrap(), c4);
        let c6: Vec<u8> = (0..n).map(|_| (rng.next_u32() & 0x3F) as u8).collect();
        let p = pack_fp6(&c6);
        assert_eq!(p.len(), packed_len(6, n));
        assert_eq!(unpack_fp6(&p, n).unwrap(), c6);
    }
    assert_eq!(pack_fp6(&[0x3F; 4]), [0xFF; 3]);
    assert_eq!(pack_fp6(&[0, 0, 0, 1]), [0x00, 0x00, 0x04]);
    assert!(unpack_fp4(&[0], 3).is_err());
    assert!(unpack_fp6(&[0; 3], 5).is_err());
}

// ---- 16-element FP4 with E4M3 block scales ------------------------------

#[test]
fn fp4x16_hand_example() {
    // Block 0: amax 6; block 1: amax 0.75.
    let mut x = vec![0.0f32; 32];
    x[0] = 6.0;
    x[1] = -3.0;
    x[2] = 1.25; // 1.25 → tie between 1 and 1.5 → 1
    x[16] = 0.75;
    x[17] = 0.1;
    let q = Fp4x16Tensor::quantize(&x).unwrap();
    // s_enc = 448 · 6 / 6 = 448.
    assert_eq!(q.tensor_scale(), 1.0 / 448.0);
    // Block scales: 6/6 · 448 = 448; 0.75/6 · 448 = 56.
    assert_eq!(q.scales()[0].to_f32(), 448.0);
    assert_eq!(q.scales()[1].to_f32(), 56.0);
    // Block 1 encode scale is 448 / 56 = 8: 0.75 → 6, 0.1 → 0.8 → 1.
    let codes = q.codes();
    assert_eq!(&codes[..3], [0b0111, 0b1101, 0b0010]);
    assert_eq!(&codes[16..18], [0b0111, 0b0010]);
    let y = q.dequantize();
    for (i, want) in [(0, 6.0f32), (1, -3.0), (2, 1.0), (16, 0.75), (17, 0.125)] {
        assert!(
            (y[i] - want).abs() <= want.abs() * 1e-6,
            "{i}: {} vs {want}",
            y[i]
        );
    }
}

#[test]
fn fp4x16_specials_and_validation() {
    let mut x = vec![1.0f32; 48];
    x[16..32].fill(0.0);
    x[40] = f32::NAN;
    let q = Fp4x16Tensor::quantize_rows(&x, 1, 48).unwrap();
    assert_eq!(q.scales()[1].to_f32(), 0.0);
    assert!(q.scales()[2].is_nan());
    let y = q.dequantize();
    assert!((y[0] - 1.0).abs() < 1e-6);
    assert!(y[16..32].iter().all(|&v| v == 0.0));
    assert!(y[32..].iter().all(|v| v.is_nan()));
    // A caller-provided amax smaller than the data saturates.
    let q = Fp4x16Tensor::quantize_rows_with_amax(&[12.0, 1.0], 1, 2, 6.0).unwrap();
    assert!((q.dequantize()[0] - 6.0).abs() < 1e-5);
    assert!(Fp4x16Tensor::quantize_rows_with_amax(&[1.0], 1, 1, f32::NAN).is_err());
    assert!(Fp4x16Tensor::quantize_rows_with_amax(&[1.0], 1, 1, -1.0).is_err());
    // All zeros: identity tensor scale, zero block scales.
    let q = Fp4x16Tensor::quantize(&[0.0; 20]).unwrap();
    assert_eq!(q.tensor_scale(), 1.0);
    assert_eq!(q.dequantize(), vec![0.0; 20]);
    // Parts.
    let q = Fp4x16Tensor::quantize_rows(&[0.5; 34], 2, 17).unwrap();
    assert_eq!(q.blocks_per_row(), 2);
    assert_eq!(q.data().len(), 18);
    let back = Fp4x16Tensor::from_parts(
        2,
        17,
        q.tensor_scale(),
        q.scales().to_vec(),
        q.data().to_vec(),
    )
    .unwrap();
    assert_eq!(back, q);
    assert!(Fp4x16Tensor::from_parts(2, 17, 0.0, q.scales().to_vec(), q.data().to_vec()).is_err());
    assert!(Fp4x16Tensor::from_parts(2, 17, 1.0, vec![F8E4M3::ONE; 3], q.data().to_vec()).is_err());
}

#[test]
fn fp4x16_error_is_bounded() {
    let mut rng = Rng(77);
    let x: Vec<f32> = (0..4096).map(|_| rng.uniform(-3.0, 3.0)).collect();
    let q = Fp4x16Tensor::quantize(&x).unwrap();
    let y = q.dequantize();
    for (blk_x, blk_y) in x.chunks(16).zip(y.chunks(16)) {
        let bamax = blk_x.iter().fold(0.0f32, |m, v| m.max(v.abs()));
        for (a, b) in blk_x.iter().zip(blk_y) {
            // FP4 step at the top of the block is bamax/6 · 2; allow the
            // E4M3 scale rounding (1/16 relative) on top.
            assert!(
                (a - b).abs() <= bamax / 6.0 * 1.07 + 1e-6,
                "{a} vs {b} (amax {bamax})"
            );
        }
    }
    // Stochastic variant keeps the scales.
    let rand: Vec<u32> = (0..4096).map(|_| rng.next_u32()).collect();
    let s = Fp4x16Tensor::quantize_rows_stochastic(&x, 1, 4096, &rand).unwrap();
    assert_eq!(s.scales(), q.scales());
    assert_eq!(s.tensor_scale(), q.tensor_scale());
}
