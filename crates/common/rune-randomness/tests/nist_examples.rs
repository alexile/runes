//! Known-answer tests: the worked examples of NIST SP 800-22 Rev. 1a.
//!
//! Section numbers refer to the specification. The `.4` sections are the
//! small hand-worked examples, the `.8` sections the 100-bit examples on
//! the binary expansion of π, and Appendix B the results for the first
//! 1 000 000 bits of the binary expansion of `e` (`data.e`, vendored in
//! `tests/data/e_1m.bin`, most significant bit first). NIST prints
//! p-values to six decimals.

#![allow(
    clippy::unreadable_literal,
    reason = "values copied from the specification"
)]
#![allow(clippy::panic, reason = "test helpers fail the test on error")]

use rune_randomness::nist::{
    self, Direction, approximate_entropy, block_frequency, cumulative_sums, frequency,
    longest_run_of_ones, runs, serial,
};
use rune_randomness::{Bits, Options, Test, TestOutcome, fips_140_2, run};

/// SP 800-22 §2.x.8: the first 100 bits of π.
const PI_100: &str = "11001001000011111101101010100010001000010110100011\
                      00001000110100110001001100011001100010100010111000";

/// SP 800-22 §2.4.8.
const LONGEST_RUN_128: &str = "11001100000101010110110001001100111000000000001001\
                               00110101010001000100111101011010000000110101111100\
                               1100111001101101100010110010";

fn bits(text: &str) -> Bits {
    Bits::parse(text).unwrap_or_else(|e| panic!("{e}"))
}

fn e_1m() -> Bits {
    let e = Bits::from_bytes(include_bytes!("data/e_1m.bin"));
    assert_eq!(e.len(), 1_000_000);
    e
}

#[track_caller]
fn check(outcome: &TestOutcome, statistic: f64, p_value: f64) {
    assert!(
        (outcome.statistic - statistic).abs() <= 1e-6 * statistic.abs().max(1.0),
        "{}: statistic {} != {statistic}",
        outcome.test,
        outcome.statistic
    );
    assert!(
        (outcome.p_value - p_value).abs() <= 5e-7,
        "{}: p-value {} != {p_value}",
        outcome.test,
        outcome.p_value
    );
}

#[track_caller]
fn ok<T>(result: Result<T, rune_randomness::Error>) -> T {
    result.unwrap_or_else(|e| panic!("{e}"))
}

#[test]
fn frequency_examples() {
    check(&ok(frequency(&bits("1011010101"))), 0.632455532, 0.527089);
    check(&ok(frequency(&bits(PI_100))), 1.6, 0.109599);
}

#[test]
fn block_frequency_examples() {
    check(&ok(block_frequency(&bits("0110011010"), 3)), 1.0, 0.801252);
    check(&ok(block_frequency(&bits(PI_100), 10)), 7.2, 0.706438);
}

#[test]
fn runs_examples() {
    check(&ok(runs(&bits("1001101011"))), 7.0, 0.147232);
    check(&ok(runs(&bits(PI_100))), 52.0, 0.500798);
}

#[test]
fn longest_run_example() {
    let input = bits(LONGEST_RUN_128);
    assert_eq!(input.len(), 128);
    // The specification prints χ² = 4.882605 from probabilities rounded to
    // four decimals; with the exact M = 8 probabilities it is 4.882457.
    check(&ok(longest_run_of_ones(&input)), 4.882457, 0.180609);
}

#[test]
fn serial_example() {
    let [first, second] = ok(serial(&bits("0011011101"), 3));
    check(&first, 1.6, 0.808792);
    check(&second, 0.8, 0.670320);
}

#[test]
fn approximate_entropy_examples() {
    check(
        &ok(approximate_entropy(&bits("0100110101"), 3)),
        10.043859,
        0.261961,
    );
    check(
        &ok(approximate_entropy(&bits(PI_100), 2)),
        5.550792,
        0.235301,
    );
}

#[test]
fn cumulative_sums_examples() {
    check(
        &ok(cumulative_sums(&bits("1011010111"), Direction::Forward)),
        4.0,
        0.411659,
    );
    let pi = bits(PI_100);
    check(
        &ok(cumulative_sums(&pi, Direction::Forward)),
        16.0,
        0.219194,
    );
    check(
        &ok(cumulative_sums(&pi, Direction::Backward)),
        19.0,
        0.114866,
    );
}

/// SP 800-22 Appendix B and §2.11.8, on the first million bits of `e`.
#[test]
fn appendix_b_e() {
    let e = e_1m();
    assert!((ok(frequency(&e)).p_value - 0.953749).abs() <= 5e-7);
    assert!((ok(block_frequency(&e, 128)).p_value - 0.211072).abs() <= 5e-7);
    assert!((ok(cumulative_sums(&e, Direction::Forward)).p_value - 0.669887).abs() <= 1e-6);
    assert!((ok(cumulative_sums(&e, Direction::Backward)).p_value - 0.724266).abs() <= 1e-6);
    assert!((ok(runs(&e)).p_value - 0.561917).abs() <= 5e-7);
    assert!((ok(longest_run_of_ones(&e)).p_value - 0.718945).abs() <= 5e-7);
    assert!((ok(approximate_entropy(&e, 10)).p_value - 0.700073).abs() <= 5e-7);
    let [first, second] = ok(serial(&e, 2));
    check(&first, 0.339764, 0.843764);
    check(&second, 0.336400, 0.561915);
    let [first, second] = ok(nist::serial(&e, 16));
    assert!((first.p_value - 0.766182).abs() <= 5e-7);
    assert!((second.p_value - 0.462921).abs() <= 5e-7);
}

#[test]
fn e_passes_the_battery_and_fips() {
    let e = e_1m();
    let report = ok(run(&e, &Options::default()));
    assert!(report.skipped.is_empty(), "{:?}", report.skipped);
    assert_eq!(report.outcomes.len(), 9);
    assert!(
        report.passed(),
        "{:?}",
        report.failures().collect::<Vec<_>>()
    );
    assert!(report.get(Test::Serial2).is_some());

    let fips = ok(fips_140_2(&e));
    assert!(fips.passed());
    assert_eq!(fips.ones, 10_027);
    assert_eq!(fips.longest_run, 16);
    assert_eq!(report.fips, Some(fips));
}
