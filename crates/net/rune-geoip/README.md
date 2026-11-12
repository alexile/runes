# rune-geoip

> Pure-Rust MaxMind DB (MMDB) reader for GeoLite2/GeoIP2 and DB-IP databases: search tree, data decoder, typed city/country/ASN records

[![crates.io](https://img.shields.io/crates/v/rune-geoip)](https://crates.io/crates/rune-geoip)
[![docs.rs](https://img.shields.io/docsrs/rune-geoip)](https://docs.rs/rune-geoip)
[![license](https://img.shields.io/crates/l/rune-geoip)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

Offline IP geolocation and ASN lookup from [MaxMind DB] files: MaxMind
GeoLite2/GeoIP2 (City, Country, ASN) and the DB-IP "lite" databases, which
use the same format and record shapes.

- `Reader` opens a database from any `AsRef<[u8]>` buffer (a `Vec<u8>`,
  a memory map), validates the metadata, looks addresses up through the
  binary search tree (24-, 28- and 32-bit records) and decodes the data
  section into a `Value` (every MMDB type; pointers resolved).
- `CityRecord`, `CountryRecord` and `AsnRecord` are typed views of the
  common record shapes; `Value::path` reaches any other field.
- `Reader::networks` walks every network once (MaxMind's IPv4 aliases in
  IPv6 databases are skipped; IPv4 networks are reported as IPv4).
- `Writer` builds small databases: test fixtures or your own enrichment
  tables.

Addresses go through `rune_ip::canonical`, so `::ffff:1.2.3.4` looks up
`1.2.3.4`; networks are `rune_cidr::Cidr`s.

**No data ships with the crate.** The datasets are licensed: download them
from [MaxMind](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data)
or [DB-IP](https://db-ip.com/db/lite.php) and pass the bytes in. The
reader does no I/O, bounds-checks every read, and caps decoding depth and
size, so a corrupt or hostile file returns an error instead of panicking.

[MaxMind DB]: https://maxmind.github.io/MaxMind-DB/

## Installation

```toml
[dependencies]
rune-geoip = "0.1"
```

The `rune-geoip` command-line tool is behind the opt-in `cli` feature:

```bash
cargo install rune-geoip --features cli
```

## Usage

### Library

```rust,no_run
use rune_geoip::Reader;

let reader = Reader::from_source(std::fs::read("GeoLite2-City.mmdb")?)?;

if let Some(city) = reader.city("81.2.69.160".parse()?)? {
    println!(
        "{:?}, {:?} ({:?}, {:?})",
        city.city.names.en(),
        city.country.iso_code,
        city.location.latitude,
        city.location.longitude,
    );
}

// Any field, untyped, with the matching network.
if let Some(entry) = reader.lookup("2001:db8::1".parse()?)? {
    println!("{} {}", entry.network, entry.data); // data prints as JSON
}

let asn_db = Reader::from_source(std::fs::read("dbip-asn-lite.mmdb")?)?;
let asn = asn_db.asn("1.1.1.1".parse()?)?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

Building a fixture:

```rust
use std::collections::BTreeMap;
use rune_geoip::{Reader, Value, Writer};

let mut writer = Writer::new("My-Enrichment", 6);
writer.insert(
    "10.0.0.0/8".parse()?,
    &Value::Map(BTreeMap::from([("site".to_owned(), Value::from("hq"))])),
)?;
let reader = Reader::from_source(writer.to_bytes()?)?;
let hit = reader.lookup("10.1.2.3".parse()?)?.unwrap();
assert_eq!(hit.data.get("site").and_then(Value::as_str), Some("hq"));
# Ok::<(), Box<dyn std::error::Error>>(())
```

### CLI

```bash
rune-geoip GeoLite2-Country.mmdb 81.2.69.160 2001:db8::1
# 81.2.69.160  81.2.69.0/23  {"continent":{...},"country":{"iso_code":"GB",...}}
# 2001:db8::1  -             -

rune-geoip --metadata --dump my-enrichment.mmdb
```

## License

MIT
