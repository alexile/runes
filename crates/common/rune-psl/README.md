# rune-psl

> Public Suffix List: public suffix and registrable domain (eTLD+1) lookups over an embedded, pinned list

[![crates.io](https://img.shields.io/crates/v/rune-psl)](https://crates.io/crates/rune-psl)
[![docs.rs](https://img.shields.io/docsrs/rune-psl)](https://docs.rs/rune-psl)
[![license](https://img.shields.io/crates/l/rune-psl)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

"What is the registrable domain of this host?" `www.example.co.uk` belongs
to `example.co.uk`, `docs.rune.github.io` to `rune.github.io`, and
`co.uk` to nobody. The [Public Suffix List](https://publicsuffix.org/)
(PSL) answers it. The answer scopes a scan to a site, groups subdomains,
bounds cookie domains, and rejects certificate wildcards such as `*.co.uk`.

- **Embedded, pinned list.** `List::embedded()` holds both the ICANN and
  the private sections, pinned to a `publicsuffix/list` commit
  (`EMBEDDED_VERSION`). It is a sorted static table, so creating the list
  costs nothing and a lookup is one binary search per label.
- **`registrable_domain(host)`** (eTLD+1), **`public_suffix(host)`**, and
  **`lookup(host)`**, which returns a `Domain` with both parts, the
  subdomain, and the section of the deciding rule (`is_private()`,
  `is_icann()`, `is_listed()`).
- **ICANN only** on request: `List::embedded().with_private_rules(false)`
  ignores the private section, so `github.io` is an ordinary domain under
  `io`. That is the view browsers use to reject certificate wildcards.
- **Punycode-aware.** Hosts may use A-labels (`xn--85x722f.com.cn`),
  Unicode labels (`食狮.com.cn`) or both. `xn--` labels are decoded
  ([RFC 3492](https://www.rfc-editor.org/rfc/rfc3492)) before matching,
  and the result keeps the form it was given in. Full IDNA mapping
  (UTS #46) is out of scope. Letters are lowercased, but other Unicode
  normalization is not applied.
- **Runtime lists.** With the `runtime` feature, `List::parse` reads a
  `public_suffix_list.dat` the application fetched itself, or a custom list.
- **Conformance.** The crate passes the list's own test suite,
  [`tests/tests.txt`](https://github.com/publicsuffix/list/blob/main/tests/tests.txt).

Lookups follow the list's
[formal algorithm](https://github.com/publicsuffix/list/wiki/Format#formal-algorithm).
Invalid hosts are errors (`lookup`) or `None` (the other functions): an
empty name or label (`.com`), more than 253 characters or a label longer than 63, a
character that never occurs in a domain name (space, `/`, `:`), an invalid
`xn--` label, or an all-digit last label (an IPv4 address). One trailing
dot is dropped. A host under an unknown top-level domain gets that label
as its suffix (the implicit `*` rule): `example.internal` is registrable.

## Installation

```toml
[dependencies]
rune-psl = "0.1"
```

Features:

| Feature    | Default | What it adds                                                        |
| ---------- | ------- | ------------------------------------------------------------------- |
| `embedded` | yes     | `List::embedded`, `EMBEDDED_VERSION`, and the free functions         |
| `runtime`  | no      | `List::parse` / `FromStr`, to load a list at run time                |
| `cli`      | no      | the `rune-psl` command-line tool                                     |

To load lists only at run time and leave the embedded table out of the
binary, use `default-features = false, features = ["runtime"]`.

The `rune-psl` command-line tool is behind the opt-in `cli` feature:

```bash
cargo install rune-psl --features cli
```

## Usage

### Library

```rust
use rune_psl::{List, lookup, registrable_domain};

assert_eq!(registrable_domain("www.example.co.uk").as_deref(), Some("example.co.uk"));
assert_eq!(registrable_domain("co.uk"), None);
assert_eq!(registrable_domain("www.xn--85x722f.xn--55qx5d.cn").as_deref(),
           Some("xn--85x722f.xn--55qx5d.cn"));

let domain = lookup("docs.rune.github.io").unwrap();
assert_eq!(domain.public_suffix(), "github.io");
assert_eq!(domain.registrable_domain(), Some("rune.github.io"));
assert_eq!(domain.subdomain(), Some("docs"));
assert!(domain.is_private());

// ICANN section only.
let icann = List::embedded().with_private_rules(false);
assert_eq!(icann.registrable_domain("docs.rune.github.io").as_deref(), Some("github.io"));
```

A list fetched at run time (feature `runtime`):

```rust,ignore
let text = std::fs::read_to_string("public_suffix_list.dat")?;
let list = rune_psl::List::parse(&text)?;
assert!(list.is_public_suffix("co.uk"));
```

`rune-host-match` uses this crate in its `psl` feature, to reject
certificate wildcards such as `*.co.uk` and to flag allowlist patterns
that cover a whole public suffix.

### CLI

```bash
rune-psl www.example.co.uk a.b.github.io 食狮.公司.cn
# www.example.co.uk   co.uk      example.co.uk   icann
# a.b.github.io       github.io  b.github.io     private
# 食狮.公司.cn         公司.cn     食狮.公司.cn     icann

rune-psl --icann-only a.b.github.io
# a.b.github.io       io         github.io       icann

rune-psl --list ./public_suffix_list.dat example.co.uk
```

Columns are tab-separated: the host, its public suffix, its registrable
domain (`-` for a public suffix), and the section of the deciding rule
(`icann`, `private`, or `unlisted` for the implicit `*` rule).

## The embedded list

| | |
| --- | --- |
| Source | `public_suffix_list.dat` at [`publicsuffix/list@7786aac8931b`](https://github.com/publicsuffix/list/tree/7786aac8931b7069d6fe2174a7471a54d273d3e6) (2026-11-11) |
| Rules | 10,415: 6,951 ICANN and 3,464 private |
| Upstream file | 339 KB |
| Generated `src/data.rs` | 383 KiB of source |
| Size in the binary | about 460 KiB: 134 KiB of names and a 10,415-entry table of 32 bytes each |

### Refreshing it

The list and its test suite are pinned by commit and SHA-256 in
[`data/sources.toml`](data/sources.toml). `src/data.rs` and
`tests/tests.txt` are generated from exactly those files, with the list
parsed by this crate's own parser.

To move to a newer list, `commit`, `date`, both URLs and both `sha256`
values in `data/sources.toml` change together to a newer
`publicsuffix/list` commit, the data is regenerated from the new pins, and
the figures in the table above are updated.

Applications that need a fresher list than the last release can fetch
`https://publicsuffix.org/list/public_suffix_list.dat` themselves and use
`List::parse` (feature `runtime`).

## License

The code is MIT. `src/data.rs` is generated from the Public Suffix List,
which is published by the Mozilla Foundation under the
[Mozilla Public License 2.0](https://mozilla.org/MPL/2.0/). That file
carries the MPL-2.0 header, so the crate's licence is `MIT AND MPL-2.0`.
The MPL applies file by file: using the crate does not put your code
under it. The conformance suite `tests/tests.txt` is public domain (CC0)
and is not packaged. See [NOTICE](NOTICE).
