# rune-randomness

> NIST SP 800-22 and FIPS 140-2 statistical randomness tests for tokens and bit streams

[![crates.io](https://img.shields.io/crates/v/rune-randomness)](https://crates.io/crates/rune-randomness)
[![docs.rs](https://img.shields.io/docsrs/rune-randomness)](https://docs.rs/rune-randomness)
[![license](https://img.shields.io/crates/l/rune-randomness)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

Statistical randomness analysis for session tokens, identifiers and raw bit
streams, in the style of Burp Sequencer. Every test returns a typed result
with its statistic and p-value. You get numbers to act on, not prose.

| Area | API |
| --- | --- |
| NIST [SP 800-22 Rev. 1a](https://csrc.nist.gov/pubs/sp/800/22/r1/upd1/final), short-sample subset | `nist::frequency`, `block_frequency`, `runs`, `longest_run_of_ones`, `serial`, `approximate_entropy`, `cumulative_sums` |
| FIPS 140-2 power-up tests (monobit, poker, runs, long run) | `fips_140_2` |
| Everything that suits the sample size, with pass/fail at `α` | `run(&bits, &Options) -> Report` |
| Per-character-position χ² and entropy, per-bit bias, battery on the encoded bits | `analyze_tokens(&tokens, &TokenOptions) -> TokenReport` |

The p-values come from `rune-stats` (`erfc` and the regularized
incomplete gamma function `igamc`). Per-position entropy comes from
`rune-entropy`. The tests reproduce the worked examples of SP 800-22,
including the Appendix B results on the first million bits of `e`.

## Installation

```toml
[dependencies]
rune-randomness = "0.1"
```

Enable the `serde` feature to serialize reports.

## Usage

```rust
use rune_randomness::{Bits, Options, TokenOptions, analyze_tokens, nist, run};

fn main() -> Result<(), rune_randomness::Error> {
    // A single test on a bit string (SP 800-22 §2.1.4).
    let outcome = nist::frequency(&Bits::parse("1011010101")?)?;
    assert!((outcome.p_value - 0.527_089).abs() < 1e-6);

    // The whole battery on raw bytes.
    let bytes: Vec<u8> = (0u32..4096).map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8).collect();
    let report = run(&Bits::from_bytes(&bytes), &Options::default())?;
    for failure in report.failures() {
        println!("{}: p = {:.6}", failure.test, failure.p_value);
}

    // A sample of hex session tokens whose first digit never changes.
    let tokens: Vec<String> = (0u32..400)
        .map(|i| format!("0{:07x}", i.wrapping_mul(2_654_435_761) >> 4))
        .collect();
    let token_report = analyze_tokens(&tokens, &TokenOptions::default().with_alphabet("0123456789abcdef"))?;
    assert_eq!(token_report.biased_positions().next().map(|p| p.position), Some(0));
    println!("~{:.1} bits of entropy per token", token_report.estimated_entropy_bits);
    Ok(())
}
```

## Notes

- NIST recommends at least 100 bits for most tests and 128 for the
  longest-run test. `run` skips the tests a sample is too short for and
  lists them in `Report::skipped`. Set `Options::with_allow_short(true)` to
  run them anyway.
- Bit-level token analysis encodes each symbol as its index in the sorted
  alphabet, using `⌈log₂ |alphabet|⌉` bits. For an alphabet whose size is
  not a power of two, the encoding itself is biased. Prefer hex or base64
  alphabets for bit-level verdicts.
- With many positions, some will fall below `α` by chance. Apply your own
  multiple-comparison correction to the individual p-values when you need
  a family-wise error rate.

## License

MIT
