# rune-taxonomy

> CWE, CAPEC, ATT&CK, OWASP Top 10 and ASVS reference data with typed, validated ids and cross-mappings

[![crates.io](https://img.shields.io/crates/v/rune-taxonomy)](https://crates.io/crates/rune-taxonomy)
[![docs.rs](https://img.shields.io/docsrs/rune-taxonomy)](https://docs.rs/rune-taxonomy)
[![license](https://img.shields.io/crates/l/rune-taxonomy)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

The security classifications that security tools tag findings with, embedded
as static tables and checked strictly. It builds on the `Taxonomy` and
`TaxonomyRef` types of [`rune-finding`](../rune-finding).

- **Typed ids**: `CweId` (`CWE-79`), `CapecId` (`CAPEC-66`), `AttackId`
  (`T1059.007`), `OwaspId` (`A03:2021`, `A05:2025`, `API1:2023`) and
  `AsvsId` (`V5.3.4`). Parsing accepts only the canonical notation: no
  surrounding whitespace, no lower case, no leading zeros, no empty string.
  A rule tagged `"CWE-79 "` or `""` is an error, not a silent miss.
- **Lookups** return `&'static` records: `cwe(79)` (name, description,
  abstraction, status, `ChildOf` parents, CAPEC, OWASP categories, CWE Top
  25 membership), `capec(66)`, `technique(id)` (name, tactics, deprecation),
  `owasp(id)`, `asvs(version, id)`.
- **Mappings**: `owasp_for_cwe`, `capec_for_cwe`, `attack_for_cwe`,
  `attack_for_capec`, `asvs_for_cwe`. CWE↔CAPEC and CAPEC↔ATT&CK links are
  the union of what both sides record; revoked ATT&CK techniques are mapped
  to their replacements (`revoked_technique`).
- **`rune-finding` integration**: `resolve(&TaxonomyRef)` and
  `resolve_id(&Taxonomy, &str)` validate a reference, `named` fills in its
  name, and every record has `to_taxonomy_ref`.

No I/O and no global state at run time: the data is `static`.

## Datasets

| Dataset | Version | What is embedded |
| --- | --- | --- |
| [MITRE CWE](https://cwe.mitre.org/) | 5.0 | 1,400+ weaknesses, categories and views: name, description, abstraction, status, `ChildOf` (view 1000), CAPEC links, CWE Top 25 (2025) |
| [MITRE CAPEC](https://capec.mitre.org/) | 3.9 | 600+ attack patterns, categories and views: name, abstraction, status, severity, likelihood, `ChildOf`, CWE and ATT&CK links |
| [MITRE ATT&CK Enterprise](https://attack.mitre.org/) | 20.1 | 15 tactics; 700+ techniques and sub-techniques with tactics, deprecation and CAPEC links; revoked ids with replacements |
| [OWASP Top 10](https://owasp.org/Top10/) | 2021, 2025 | Category titles and mapped CWEs (2021 from the CWE catalogue's OWASP categories, 2025 from the category pages) |
| [OWASP API Security Top 10](https://owasp.org/API-Security/) | 2023 | Category titles and the CWEs each page references |
| [OWASP ASVS](https://owasp.org/www-project-application-security-verification-standard/) | 4.0.3, 5.0.0 | Chapter and section titles, requirement ids and levels, 4.0.3 CWE mappings |

Size of the generated source (`src/data/`): CWE 580 KiB, CAPEC 174 KiB,
ATT&CK 111 KiB, ASVS 104 KiB, OWASP 8 KiB; about 1 MiB in all, and 166 KB
as a packaged `.crate`. That is under the 2 MB at which the datasets would
go behind per-dataset features, so all of them are always compiled in.

### Data sources

The upstream files are pinned by URL and SHA-256 in
[`data/sources.toml`](data/sources.toml) (GitHub sources at a commit), and
`src/data` is generated from exactly those files. To move to a new upstream
release, the dataset's `version`, URLs and checksums change together and the
data is regenerated from the new pins.
`sources()` reports the embedded versions at run time.

## Installation

```toml
[dependencies]
rune-taxonomy = "0.1"
```

Features: `serde` (`Serialize` for records, `Serialize`/`Deserialize` for
ids as canonical strings) and `cli`. The command-line tool is behind the
opt-in `cli` feature:

```bash
cargo install rune-taxonomy --features cli
```

## Usage

### Library

```rust
use rune_finding::{Taxonomy, TaxonomyRef};
use rune_taxonomy::{CweId, Error};

// Typed ids, parsed strictly.
let id: CweId = "CWE-89".parse()?;
let sqli = id.resolve()?;
assert!(sqli.name.contains("SQL"));
assert!("CWE-89 ".parse::<CweId>().is_err());

// Mappings.
let owasp: Vec<String> = rune_taxonomy::owasp_for_cwe(89).map(|c| c.id.to_string()).collect();
assert_eq!(owasp, ["A03:2021", "A05:2025"]);
let capec = rune_taxonomy::capec_for_cwe(89).find(|p| p.name == "SQL Injection").unwrap();
assert!(rune_taxonomy::attack_for_capec(capec.id).count() <= capec.attack.len());

// Validating free-text tags, e.g. from a rule file.
assert!(rune_taxonomy::resolve_id(&Taxonomy::Cwe, "CWE-79").is_ok());
assert!(matches!(rune_taxonomy::resolve_id(&Taxonomy::Cwe, ""), Err(Error::Empty { .. })));

// Naming rune-finding references.
let named = rune_taxonomy::named(&TaxonomyRef::owasp("A01:2025"))?;
assert_eq!(named.name.as_deref(), Some("Broken Access Control"));
# Ok::<(), Error>(())
```

### CLI

```bash
rune-taxonomy CWE-79 A03:2021 T1086
# CWE-79	Improper Neutralization of Input During Web Page Generation
#   parents: CWE-74
#   owasp: A03:2021, A05:2025
#   capec: CAPEC-63, CAPEC-85, CAPEC-209, CAPEC-588, CAPEC-591, CAPEC-592
# A03:2021	Injection
#   cwe: CWE-20, CWE-74, ...
# T1086: ATT&CK technique T1086 was revoked; use T1059.001   (exit status 1)

rune-taxonomy --asvs 4 V5.3.4   # ASVS ids need an edition; the default is 5
rune-taxonomy --sources         # embedded dataset versions
```

## Licence

The code is MIT. The CWE, CAPEC and ATT&CK data are © The MITRE Corporation,
reproduced under MITRE's terms of use, which require the copyright notice
and licence to travel with every copy. From the OWASP works (CC BY-SA 4.0)
only identifiers, titles, levels and CWE id mappings are embedded, with
attribution; no descriptive text. See [`NOTICE`](NOTICE), which ships in
the crate.
