//! Token analysis on generated samples: a good generator passes, weak ones
//! are caught where expected.

use rune_randomness::{TokenOptions, analyze_tokens};

const HEX: &str = "0123456789abcdef";

/// `SplitMix64`, a well-mixed deterministic generator for test data.
const fn splitmix(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^ (z >> 31)
}

fn hex_tokens(count: usize, mut next: impl FnMut(usize) -> u64) -> Vec<String> {
    (0..count).map(|i| format!("{:016x}", next(i))).collect()
}

#[test]
fn good_generator_passes() {
    let mut state = 42;
    let tokens = hex_tokens(500, |_| splitmix(&mut state));
    let options = TokenOptions::default().with_alphabet(HEX);
    let report = analyze_tokens(&tokens, &options).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(report.tokens, 500);
    assert_eq!(report.positions.len(), 16);
    assert_eq!(report.bit_positions.len(), 64);
    assert!(
        report.battery.passed(),
        "{:?}",
        report.battery.failures().collect::<Vec<_>>()
    );
    assert!(report.battery.fips.is_some());
    // 16 + 64 independent tests at α = 0.01: allow one chance rejection.
    let biased = report.biased_positions().count() + report.biased_bit_positions().count();
    assert!(biased <= 1, "{biased} biased positions");
    // Close to the 64 bits a 16-hex-digit token can hold, minus the
    // small-sample bias of the entropy estimate.
    assert!(report.estimated_entropy_bits > 60.0 && report.estimated_entropy_bits <= 64.0);
}

#[test]
fn timestamp_prefix_is_caught() {
    let mut state = 7;
    // High 24 bits a slowly increasing "timestamp", low 40 bits random.
    let tokens = hex_tokens(500, |i| {
        ((1_700_000 + i as u64 / 50) << 40) | (splitmix(&mut state) >> 24)
    });
    let options = TokenOptions::default().with_alphabet(HEX);
    let report = analyze_tokens(&tokens, &options).unwrap_or_else(|e| panic!("{e}"));
    let biased: Vec<usize> = report.biased_positions().map(|p| p.position).collect();
    assert!(biased.iter().all(|&p| p < 6), "{biased:?}");
    assert!(biased.contains(&0) && biased.contains(&4));
    assert!(report.biased_bit_positions().any(|b| b.position < 24));
    // 40 random bits at α = 0.01: allow one chance rejection among them.
    assert!(
        report
            .biased_bit_positions()
            .filter(|b| b.position >= 24)
            .count()
            <= 1
    );
    assert!(!report.passed());
}

#[test]
fn weak_lcg_low_bits_fail_the_battery() {
    // A power-of-two LCG: its low bits have tiny periods.
    let mut state: u32 = 1;
    let tokens = hex_tokens(400, |_| {
        state = state.wrapping_mul(1_103_515_245).wrapping_add(12_345);
        u64::from(state)
    });
    let options = TokenOptions::default().with_alphabet(HEX);
    let report = analyze_tokens(&tokens, &options).unwrap_or_else(|e| panic!("{e}"));
    assert!(!report.battery.passed());
    // The upper 32 bits are always zero.
    assert_eq!(report.positions[0].distinct, 1);
    // The low nibble cycles through all 16 values, so it looks uniform:
    // only the battery on the bit stream sees its period.
    assert!(report.biased_positions().all(|p| p.position < 8));
}
