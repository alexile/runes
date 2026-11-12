//! Known vectors (cross-checked against an independent implementation of
//! the `ent` formulas) and property tests.

#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    clippy::float_cmp,
    reason = "test data generators truncate on purpose; exact 0.0 and 8.0 results are the point"
)]

use proptest::prelude::*;
use rune_entropy::{
    Analyzer, Confidence, Histogram, Verdict, analyze, entropy, entropy_profile,
    random_entropy_baseline, regions_where,
};

/// Deterministic xorshift64 byte stream.
fn xorshift(len: usize) -> Vec<u8> {
    let mut x = 0x2545_f491_4f6c_dd1d_u64;
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            (x >> 32) as u8
        })
        .collect()
}

fn close(actual: f64, expected: f64, tolerance: f64) {
    assert!(
        (actual - expected).abs() <= tolerance,
        "expected {expected}, got {actual}"
    );
}

#[test]
fn random_stream_vector() {
    let report = analyze(&xorshift(65_536));
    assert_eq!(report.len, 65_536);
    close(report.shannon, 7.997_238_446_784_997, 1e-12);
    close(report.min_entropy, 7.780_831_479_537_839, 1e-12);
    close(report.chi_square.unwrap(), 249.960_937_5, 1e-9);
    close(report.mean.unwrap(), 127.968_841_552_734_38, 1e-12);
    close(
        report.serial_correlation.unwrap(),
        -0.003_601_152_217_356_214_4,
        1e-12,
    );
    close(report.monte_carlo_pi.unwrap(), 3.135_689_434_169_566, 1e-12);
    let p = report.chi_square_p_value.unwrap();
    assert!(p > 0.3 && p < 0.7, "p = {p}");
    let assessment = report.assess();
    assert_eq!(assessment.verdict, Verdict::RandomLike);
    assert_eq!(assessment.confidence, Confidence::High);
}

#[test]
fn text_vector() {
    let text = b"The quick brown fox jumps over the lazy dog. ".repeat(100);
    let report = analyze(&text);
    close(report.shannon, 4.441_092_818_215_358, 1e-12);
    close(report.min_entropy, 2.321_928_094_887_362, 1e-12);
    close(report.chi_square.unwrap(), 75_713.333_333_333_33, 1e-6);
    close(report.mean.unwrap(), 91.888_888_888_888_89, 1e-12);
    close(
        report.serial_correlation.unwrap(),
        -0.125_575_238_577_661_4,
        1e-12,
    );
    assert_eq!(report.monte_carlo_pi, Some(4.0));
    assert_eq!(report.printable_ratio, Some(1.0));
    assert_eq!(report.assess().verdict, Verdict::Text);
}

#[test]
fn counter_is_high_entropy_but_not_random() {
    let ramp: Vec<u8> = (0..1000u32).map(|i| (i % 256) as u8).collect();
    let report = analyze(&ramp);
    close(report.shannon, 7.995_666_984_610_164, 1e-12);
    close(report.chi_square.unwrap(), 5.568, 1e-9);
    close(
        report.serial_correlation.unwrap(),
        0.976_291_876_333_524,
        1e-12,
    );
    close(
        report.monte_carlo_pi.unwrap(),
        2.915_662_650_602_409_5,
        1e-12,
    );
    assert_eq!(report.assess().verdict, Verdict::HighEntropy);
}

#[test]
fn verdicts_for_common_shapes() {
    assert_eq!(
        analyze(&[0u8; 10_000]).assess().verdict,
        Verdict::Repetitive
    );
    assert_eq!(analyze(&[0u8; 10]).assess().verdict, Verdict::Repetitive);
    let tiny = analyze(&xorshift(40)).assess();
    assert_eq!(tiny.verdict, Verdict::Inconclusive);
    assert_eq!(tiny.confidence, Confidence::Low);
    // Machine-code-like: biased toward a few opcodes plus random operands.
    let mut code = Vec::new();
    for (i, &r) in xorshift(8192).iter().enumerate() {
        code.push(match i % 4 {
            0 => 0x48,
            1 => [0x89, 0x8b, 0xe8, 0x0f][usize::from(r % 4)],
            _ => r,
        });
    }
    assert_eq!(analyze(&code).assess().verdict, Verdict::Binary);
}

#[test]
fn empty_input_is_well_defined() {
    let report = analyze(&[]);
    assert_eq!(report.shannon, 0.0);
    assert_eq!(report.min_entropy, 0.0);
    assert_eq!(report.chi_square, None);
    assert_eq!(report.serial_correlation, None);
    assert_eq!(report.monte_carlo_pi, None);
    assert_eq!(report.assess().verdict, Verdict::Empty);
}

#[test]
fn regions_locate_embedded_random_block() {
    let mut data = vec![0u8; 64 * 1024];
    data[20_000..40_000].copy_from_slice(&xorshift(20_000));
    let profile = entropy_profile(&data, 1024, 256).unwrap();
    let regions = regions_where(&profile, |e| e >= 7.0, 1024);
    assert_eq!(regions.len(), 1);
    let r = regions[0];
    // Boundaries are accurate to about one window either way.
    assert!((19_000..=21_000).contains(&r.start), "{r:?}");
    assert!((39_000..=41_000).contains(&r.end), "{r:?}");
    assert!(r.mean_entropy > 7.0 && r.max_entropy <= 8.0);
}

proptest! {
    #[test]
    fn entropy_is_bounded(data in prop::collection::vec(any::<u8>(), 0..4096)) {
        let report = analyze(&data);
        prop_assert!((0.0..=8.0).contains(&report.shannon));
        prop_assert!((0.0..=8.0).contains(&report.min_entropy));
        prop_assert!(report.min_entropy <= report.shannon + 1e-12);
        prop_assert!(!report.shannon.is_nan());
        if let Some(r) = report.serial_correlation {
            prop_assert!((-1.0..=1.0).contains(&r));
        }
        if let Some(p) = report.chi_square_p_value {
            prop_assert!((0.0..=1.0).contains(&p));
        }
        // Shannon entropy can never exceed log2 of the sample size.
        if data.len() > 1 {
            prop_assert!(report.shannon <= (data.len() as f64).log2() + 1e-9);
        }
    }

    #[test]
    fn constant_input_is_zero(byte in any::<u8>(), len in 1usize..5000) {
        let data = vec![byte; len];
        prop_assert_eq!(entropy(&data), 0.0);
        prop_assert_eq!(analyze(&data).min_entropy, 0.0);
        prop_assert_eq!(analyze(&data).serial_correlation, None);
    }

    #[test]
    fn uniform_cycle_is_eight(repeats in 1usize..40, start in any::<u8>()) {
        let data: Vec<u8> = (0..256 * repeats).map(|i| start.wrapping_add(i as u8)).collect();
        prop_assert_eq!(entropy(&data), 8.0);
        prop_assert_eq!(analyze(&data).min_entropy, 8.0);
        prop_assert_eq!(analyze(&data).chi_square, Some(0.0));
    }

    #[test]
    fn streaming_matches_one_shot(
        data in prop::collection::vec(any::<u8>(), 0..3000),
        cuts in prop::collection::vec(any::<prop::sample::Index>(), 0..8),
    ) {
        let mut points: Vec<usize> = cuts.iter().map(|c| c.index(data.len() + 1)).collect();
        points.sort_unstable();
        let mut analyzer = Analyzer::new();
        let mut last = 0;
        for point in points.into_iter().chain([data.len()]) {
            analyzer.update(&data[last..point]);
            last = point;
        }
        prop_assert_eq!(analyzer.analysis(), analyze(&data));
    }

    #[test]
    fn merged_histograms_match(a in prop::collection::vec(any::<u8>(), 0..1000),
                               b in prop::collection::vec(any::<u8>(), 0..1000)) {
        let mut merged = Histogram::from_bytes(&a);
        merged.merge(&Histogram::from_bytes(&b));
        let joined: Vec<u8> = a.iter().chain(&b).copied().collect();
        prop_assert_eq!(merged, Histogram::from_bytes(&joined));
    }

    #[test]
    fn profile_covers_input(
        data in prop::collection::vec(any::<u8>(), 0..3000),
        window in 1usize..600,
        step in 1usize..700,
    ) {
        let profile = entropy_profile(&data, window, step).unwrap();
        if data.is_empty() {
            prop_assert!(profile.is_empty());
            return Ok(());
        }
        let last = profile.last().unwrap();
        prop_assert_eq!(last.range().end, data.len() as u64);
        for (i, w) in profile.iter().enumerate() {
            prop_assert_eq!(w.len, window.min(data.len()));
            if i + 1 < profile.len() {
                prop_assert_eq!(w.offset, (i * step) as u64);
            }
            let start = w.offset as usize;
            let direct = entropy(&data[start..start + w.len]);
            prop_assert!((w.entropy - direct).abs() < 1e-12);
        }
        let regions = regions_where(&profile, |e| e >= 4.0, 0);
        for w in profile.iter().filter(|w| w.entropy >= 4.0) {
            let r = w.range();
            prop_assert!(regions.iter().any(|g| g.start <= r.start && r.end <= g.end));
        }
        for pair in regions.windows(2) {
            prop_assert!(pair[0].end < pair[1].start);
        }
        for r in &regions {
            prop_assert!(r.end <= data.len() as u64 && r.start < r.end);
        }
    }

    #[test]
    fn baseline_increases_with_size(n in 2u64..5000) {
        prop_assert!(random_entropy_baseline(n + 1) > random_entropy_baseline(n));
        prop_assert!(random_entropy_baseline(n) < 8.0);
    }
}
