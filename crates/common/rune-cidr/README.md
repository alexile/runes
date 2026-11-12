# rune-cidr

> CIDR (IPv4/IPv6) parsing, membership and range math (expand, split, aggregate, overlaps) — no dependencies beyond std.

[![crates.io](https://img.shields.io/crates/v/rune-cidr)](https://crates.io/crates/rune-cidr)
[![docs.rs](https://img.shields.io/docsrs/rune-cidr)](https://docs.rs/rune-cidr)
[![license](https://img.shields.io/crates/l/rune-cidr)](LICENSE)

## Usage

```rust
use rune_cidr::{aggregate, filter, Cidr};

let net: Cidr = "10.0.0.0/24".parse().unwrap();
assert!(net.contains("10.0.0.42".parse().unwrap()));
assert!(!net.contains("10.0.1.1".parse().unwrap()));

// A bare address (no `/prefix`) is treated as a full-length match.
let exact: Cidr = "10.0.0.5".parse().unwrap();
assert!(exact.contains("10.0.0.5".parse().unwrap()));

// Counting and bounded expansion: `expand` never walks more than `cap`
// addresses, so a /8 or an IPv6 /32 is safe to pass.
assert_eq!(net.address_count(), 256);
assert_eq!(net.host_count(), 254);
assert_eq!(net.expand(2).count(), 2);

// Splitting, supernets and overlap tests.
let halves: Vec<Cidr> = net.split(25).unwrap().collect();
assert_eq!(halves.len(), 2);
assert_eq!(net.supernet().unwrap().to_string(), "10.0.0.0/23");
assert!(net.overlaps(&"10.0.0.128/25".parse().unwrap()));

// Aggregation merges adjacent and contained ranges.
assert_eq!(aggregate(&halves), [net]);

// Filtering keeps the addresses inside any of the ranges.
let ips = ["10.0.0.9".parse().unwrap(), "8.8.8.8".parse().unwrap()];
assert_eq!(filter(ips, &[net]).count(), 1);
```

| API | What it does |
| --- | --- |
| `Cidr::parse`, `Cidr::new`, `From<IpAddr>`, `Display` | build and print ranges |
| `network`, `last`, `netmask`, `hostmask`, `trunc` | range bounds and masks |
| `address_count`, `host_count` | sizes (`u128`, saturating only for `::/0`) |
| `addresses`, `hosts`, `expand(cap)` | lazy, double-ended address iterators |
| `contains`, `contains_cidr`, `overlaps`, `contains_any` | membership |
| `split(prefix_len)`, `subnets`, `supernet` | resizing |
| `aggregate(&nets)`, `filter(ips, &ranges)` | set operations |

Both IPv4 and IPv6 are supported throughout; mismatched address families
never match. `hosts` follows the usual convention: IPv4 ranges wider than
`/31` skip the network and broadcast addresses, IPv6 ranges yield every
address.

## License

MIT
