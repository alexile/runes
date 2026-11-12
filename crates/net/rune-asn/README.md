# rune-asn

> IP-to-ASN and ASN-to-prefix lookup over BGP/RIR datasets (RouteViews pfx2as, iptoasn, bgpdump, RIR delegated stats) with longest-prefix match

[![crates.io](https://img.shields.io/crates/v/rune-asn)](https://crates.io/crates/rune-asn)
[![docs.rs](https://img.shields.io/docsrs/rune-asn)](https://docs.rs/rune-asn)
[![license](https://img.shields.io/crates/l/rune-asn)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

Which AS announces this address, and what does that AS announce?
`rune-asn` answers both from routing data you supply. It parses the common
public dataset formats, loads them into an `AsnDb`, and looks addresses up
with longest-prefix match (built on `rune-cidr`), so a more specific
announcement wins over its covering aggregate, as it does in BGP.

| Format | Parser | Source |
| --- | --- | --- |
| CAIDA RouteViews prefix-to-AS | `parse_pfx2as` | <https://www.caida.org/catalog/datasets/routeviews-prefix2as/> |
| RIPE RIS `riswhoisdump` | `parse_riswhois` | <https://www.ris.ripe.net/dumps/> |
| `bgpdump -m` of an MRT RIB/update file | `parse_bgpdump` | RouteViews / RIPE RIS archives |
| iptoasn.com range table | `parse_ip2asn` | <https://iptoasn.com/> |
| RIR delegated(-extended) stats | `parse_delegated` | <https://www.nro.net/about/rirs/statistics/> |
| AS-name list (`13335 CLOUDFLARENET, US`) | `parse_asnames` | RIPE `asn.txt`, potaroo `asnames.txt` |

The library ships no data and does no I/O: download and decompress the
files yourself (they change daily), then pass their text to a parser. Each
parser is a lazy iterator with one `Result` per line, so you choose between
failing on the first bad line (`AsnDb::try_extend`) and skipping it.

## Installation

```toml
[dependencies]
rune-asn = "0.1"
```

The `rune-asn` command-line tool is behind the opt-in `cli` feature:

```bash
cargo install rune-asn --features cli
```

## Usage

### Library

```rust
use rune_asn::{parse_asnames, parse_pfx2as, Asn, AsnDb};

let pfx2as = "1.1.1.0\t24\t13335\n8.0.0.0\t9\t3356\n8.8.8.0\t24\t15169\n";
let mut db = AsnDb::new();
db.try_extend(parse_pfx2as(pfx2as))?;
for name in parse_asnames("15169 GOOGLE, US\n") {
    db.insert_name(name?);
}

// IP → ASN (longest-prefix match; IPv4-mapped IPv6 is unwrapped).
let hit = db.lookup("8.8.8.8".parse().unwrap()).unwrap();
assert_eq!(hit.prefix.to_string(), "8.8.8.0/24");
assert_eq!(hit.origin(), Some(Asn::new(15169)));
assert_eq!(db.info(Asn::new(15169)).unwrap().name, Some("GOOGLE"));

// ASN → announced prefixes.
assert_eq!(db.prefixes(Asn::new(3356)).count(), 1);
# Ok::<(), rune_asn::Error>(())
```

Multi-origin (MOAS) prefixes and `AS_SET` origins keep every origin AS.
`AsnDb::info` combines RIR delegation data (registry, country, date) with
AS names. `Asn` parses `AS13335`, `13335` and asdot (`1.10`), and flags
private, documentation and reserved ranges.

### CLI

```bash
rune-asn --pfx2as routeviews-rv2-20261111-1200.pfx2as --asnames asn.txt 8.8.8.8 AS13335
# 8.8.8.8	8.8.8.0/24	AS15169 GOOGLE [US]
# AS13335 CLOUDFLARENET [US]
#   1.0.0.0/24
#   ...
```

## License

MIT
