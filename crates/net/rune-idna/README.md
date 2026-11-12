# rune-idna

> Internationalized domain names: Punycode (RFC 3492), UTS #46 / IDNA2008 conversion, and UTS #39 confusable and mixed-script homograph detection

[![crates.io](https://img.shields.io/crates/v/rune-idna)](https://crates.io/crates/rune-idna)
[![docs.rs](https://img.shields.io/docsrs/rune-idna)](https://docs.rs/rune-idna)
[![license](https://img.shields.io/crates/l/rune-idna)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

Comparing host names correctly (certificate matching, scope checks, allow
lists) needs their canonical ASCII form, and showing them to people safely
needs a check for look-alikes such as `pаypal.com` with a Cyrillic `а`.
This crate does both, sans-I/O:

| Area | API | Specification |
| --- | --- | --- |
| Punycode | `punycode::encode`, `punycode::decode` | [RFC 3492](https://www.rfc-editor.org/rfc/rfc3492) |
| Domain conversion | `to_ascii`, `to_unicode`, `same_domain`, `Options` | [UTS #46](https://www.unicode.org/reports/tr46/), [IDNA2008](https://www.rfc-editor.org/rfc/rfc5890) |
| Confusables | `skeleton`, `is_confusable_with`, `confusable_kind` | [UTS #39](https://www.unicode.org/reports/tr39/) §4 |
| Mixed scripts | `resolved_script_set`, `is_mixed_script`, `restriction_level` | UTS #39 §5 |
| Homographs | `DomainReport`, `SpoofPolicy`, `LookalikeIndex` | |

UTS #46 processing (mapping, NFC, bidi and joiner rules) is delegated to the
[`idna`](https://crates.io/crates/idna) crate, normalization and script
properties to ICU4X. The UTS #39 data (`confusables.txt`,
`IdentifierStatus.txt`) and the IDNA2008 exclusions of
`IdnaMappingTable.txt` are embedded, Unicode 18.0.0.

## Installation

```toml
[dependencies]
rune-idna = "0.1"
```

The `rune-idna` command-line tool is behind the opt-in `cli` feature:

```bash
cargo install rune-idna --features cli
```

## Usage

### Library

```rust
use rune_idna::{
    DomainReport, LookalikeIndex, Options, SpoofPolicy, punycode, same_domain, to_ascii,
    to_unicode,
};

// Punycode, one label at a time.
assert_eq!(punycode::encode("bücher")?, "bcher-kva");

// Whole domain names. `Options::default()` is the lookup profile;
// `Options::registration()` adds hyphen checks and the IDNA2008 repertoire.
let options = Options::default();
assert_eq!(to_ascii("Bücher.Example", &options)?, "xn--bcher-kva.example");
assert_eq!(to_unicode("xn--bcher-kva.example", &options)?, "bücher.example");
assert!(same_domain("BÜCHER.example.", "xn--bcher-kva.example", &options));

// Homographs: Cyrillic а, р and ӏ spell a label that looks like `apple`.
let policy = SpoofPolicy::default();
let report = DomainReport::analyze("аррӏе.com", &options)?;
assert!(report.is_suspicious(&policy));
assert_eq!(report.display(&policy), "xn--80ak6aa92e.com"); // shown as Punycode

let report = DomainReport::analyze("bücher.de", &options)?;
assert_eq!(report.display(&policy), "bücher.de");

// Look-alikes of known names.
let mut index = LookalikeIndex::new(options);
index.insert("paypal.com")?;
assert_eq!(index.find("pаypal.com")?, ["paypal.com"]);
# Ok::<(), rune_idna::Error>(())
```

A label is suspicious under the default `SpoofPolicy` when its UTS #39
restriction level is below *Moderately Restrictive* (mixing Latin with
Cyrillic or Greek, three or more scripts, characters outside the
identifier profile), or when it is not ASCII but every character has an
ASCII look-alike (a whole-script confusable such as Cyrillic `ѕсоре`).

### CLI

```bash
rune-idna to-ascii Bücher.example
# xn--bcher-kva.example

rune-idna to-unicode xn--bcher-kva.example
# bücher.example

rune-idna check pаypal.com bücher.de --known paypal.com
# (tab-separated: input, verdict, ASCII form, display form, restriction level)
# pаypal.com  SUSPICIOUS  xn--pypal-4ve.com  xn--pypal-4ve.com  Minimally Restrictive
#   label "pаypal": Minimally Restrictive, scripts ∅, skeleton "paypal", looks like ASCII
#   looks like paypal.com
# bücher.de   ok          xn--bcher-kva.de   bücher.de          Single Script

rune-idna confusable scope ѕсоре
# confusable (WholeScript)
```

`check` exits with 1 if any name is suspicious, `confusable` if the strings
are not confusable, and 2 on invalid input. `--registration` selects the
registration profile and `--no-std3` allows `_` and other non-LDH ASCII.

## Updating the Unicode data

`src/data.rs` is generated. See `data/sources.toml` for the pinned files and
the command that regenerates it.

## License

MIT for the code. `src/data.rs` is derived from Unicode data files under the
Unicode License v3; see [NOTICE](NOTICE).
