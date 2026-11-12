# rune-cvss

> CVSS v3.0, v3.1 and v4.0 vector parsing and scoring, exactly as the FIRST specifications and reference calculators define it

[![crates.io](https://img.shields.io/crates/v/rune-cvss)](https://crates.io/crates/rune-cvss)
[![docs.rs](https://img.shields.io/docsrs/rune-cvss)](https://docs.rs/rune-cvss)
[![license](https://img.shields.io/crates/l/rune-cvss)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

Parse a CVSS vector string, validate it, compute its scores and write it
back in canonical form. Scores are computed, never supplied, and match
FIRST's reference calculators bit for bit.

- **`Vector`** parses any `CVSS:3.0/`, `CVSS:3.1/` or `CVSS:4.0/` vector.
  `Vector3` and `Vector4` type every metric (base, temporal/threat,
  environmental and, for v4.0, supplemental).
- **v3.0 / v3.1**: base, temporal and environmental scores, with each
  version's `Roundup` (v3.1's is the Appendix A function that avoids
  floating-point artefacts) and Modified Impact formula. Metrics may come
  in any order, as the specification requires.
- **v4.0**: the MacroVector lookup and interpolation of the reference
  implementation, with FIRST's lookup table vendored; the CVSS-B base
  score, the nomenclature (CVSS-B, -BT, -BE, -BTE) and the MacroVector.
  Metrics must come in specification order, as the specification requires.
- **`Score`** keeps scores exactly as tenths (`9.8`, never
  `9.799999999999999`); **`Severity`** is the qualitative rating (None,
  Low, Medium, High, Critical). With `rune-finding`'s `cvss` feature it
  converts into `rune_finding::Severity`, and `rune_finding::Cvss` computes
  its score from the vector.
- **Canonical form**: `Display` writes the specification order without Not
  Defined (`X`) metrics. Every vector that parses round-trips.
- Sans-I/O, no `unsafe`, no panics on any input, and no platform-dependent
  maths (no `libm`): the result is the same on every target.

Specifications: [CVSS v4.0](https://www.first.org/cvss/v4.0/specification-document),
[v3.1](https://www.first.org/cvss/v3.1/specification-document) and
[v3.0](https://www.first.org/cvss/v3.0/specification-document).

## Installation

```toml
[dependencies]
rune-cvss = "0.1"
```

Features:

- `serde`: vectors (de)serialize as their string, `Score` as a number
  (`9.8`), `Severity` and `Version` as strings.

## Usage

```rust
use rune_cvss::{Severity, Vector, Vector3, Vector4};

fn main() -> Result<(), rune_cvss::Error> {
    // Any version.
    let vector: Vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N".parse()?;
    assert_eq!(vector.base_score().to_string(), "6.1");
    assert_eq!(vector.severity(), Severity::Medium);

    // v3: base, temporal and environmental scores.
    let v3: Vector3 = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:P/RL:O/CR:L".parse()?;
    assert_eq!(v3.base_score().value(), 9.8);
    assert_eq!(v3.temporal_score().value(), 8.8);
    assert_eq!(v3.environmental_score().value(), 8.5);

    // v4.0: one score for the whole vector, plus the CVSS-B base score.
    let v4: Vector4 = "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:P/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:U".parse()?;
    assert_eq!(v4.score().value(), 5.2);
    assert_eq!(v4.base_score().value(), 7.7);
    assert_eq!(v4.nomenclature().as_str(), "CVSS-BT");

    // Canonical form: specification order, no Not Defined metrics.
    let shuffled: Vector = "CVSS:3.1/S:U/AV:N/AC:L/PR:N/UI:N/C:H/I:H/A:H/E:X".parse()?;
    assert_eq!(shuffled.to_string(), "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

    // Invalid vectors are errors, never panics.
    assert!("CVSS:4.0/AC:L/AV:N".parse::<Vector>().is_err());
    Ok(())
}
```

## How correctness is checked

- The formulas run in `f64` with the same operations in the same order as
  FIRST's JavaScript calculators, so every intermediate value is identical.
  The one transcendental function, `Math.pow` in the v3 scope-changed
  impact, is replaced by a correctly rounded double-double power; it
  matches V8's `Math.pow` on all 138 inputs the formulas can produce.
- Known answers: every example in FIRST's v3.0, v3.1 and v4.0 example
  documents, and the specification's sample vectors.
- Differential corpora scored by the reference calculators (committed
  samples of 1,000 v3.0, 2,500 v3.1 and 3,000 v4.0 vectors). Pointing
  `RUNE_CVSS_CORPUS_DIR` at larger corpora checked every v3.0, v3.1 and
  v4.0 base vector (2,592, 2,592 and 104,976) and 1.5 million random
  vectors with temporal, threat and environmental metrics, with no
  difference.
- Property tests: parsing never panics, every parsed
  vector round-trips through its canonical form, and scores stay within
  0.0 to 10.0.

## Licence

`MIT AND BSD-2-Clause`: the crate is MIT, and the CVSS v4.0 lookup tables in `src/v4/lookup.rs` are copied from
FIRST's [cvss-v4-calculator](https://github.com/FIRSTdotorg/cvss-v4-calculator):

```text
Copyright (c) 2023 FIRST.ORG, Inc., Red Hat, and contributors

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
```

CVSS is owned by FIRST.Org, Inc. and used by permission.
