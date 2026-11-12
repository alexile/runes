# rune-macaddr

> MAC address (EUI-48/EUI-64) parsing, formatting and classification with IEEE OUI vendor lookup over caller-supplied registry data

[![crates.io](https://img.shields.io/crates/v/rune-macaddr)](https://crates.io/crates/rune-macaddr)
[![docs.rs](https://img.shields.io/docsrs/rune-macaddr)](https://docs.rs/rune-macaddr)
[![license](https://img.shields.io/crates/l/rune-macaddr)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

A small layer-2 primitive for packet capture, ARP tables and device
inventory:

- **Parse and format** EUI-48 (`MacAddr`) and EUI-64 (`Eui64`) in colon
  (`00:1b:63:84:45:e6`, also `0:1b:…`), hyphen (`00-1B-63-84-45-E6`), Cisco
  dot (`001b.6384.45e6`) and bare-hex (`001b638445e6`) notation, upper or
  lower case.
- **Classify**: unicast/multicast (I/G bit), universal/locally administered
  (U/L bit), broadcast, nil.
- **Convert**: EUI-48 ↔ EUI-64, modified EUI-64 and the SLAAC IPv6
  link-local address ([RFC 4291, Appendix A](https://www.rfc-editor.org/rfc/rfc4291#appendix-A)),
  and back.
- **Vendor lookup** (`OuiDb`): longest-prefix match over MA-L (`/24`),
  MA-M (`/28`), MA-S/IAB (`/36`) and CID assignments, loaded from the IEEE
  RA CSV or text files or a Wireshark `manuf` file.
- **Well-known ranges** (`well_known`): broadcast, IEEE 802.1 reserved group
  addresses (STP, LLDP, LACP, PAUSE, 802.1X), PTP, IPv4/IPv6/MPLS
  multicast, VRRP and the IANA blocks, from the standards that define them.

## Vendor data

The crate embeds **no** IEEE vendor data. The IEEE Registration Authority
publishes the registry listings for download but does not state a licence
for redistributing them, so shipping a copy inside a published crate is not
clearly allowed. Load the files at run time instead:

| Registry | CSV | Text |
| --- | --- | --- |
| MA-L (OUI) | <https://standards-oui.ieee.org/oui/oui.csv> | `oui/oui.txt` |
| MA-M | <https://standards-oui.ieee.org/oui28/mam.csv> | `oui28/mam.txt` |
| MA-S | <https://standards-oui.ieee.org/oui36/oui36.csv> | `oui36/oui36.txt` |
| IAB | <https://standards-oui.ieee.org/iab/iab.csv> | `iab/iab.txt` |
| CID | <https://standards-oui.ieee.org/cid/cid.csv> | `cid/cid.txt` |

Debian/Ubuntu ship the same files in the `ieee-data` package
(`/usr/share/ieee-data/`), and Wireshark's `manuf` works too. Together the
registries are a few megabytes and some tens of thousands of assignments;
refreshing means loading a newer download. The built-in `well_known` table
is written from the protocol standards (IEEE 802.1Q, 802.3, 1588 and the
RFCs it cites), not copied from the registry.

## Installation

```toml
[dependencies]
rune-macaddr = "0.1"
```

The `rune-macaddr` command-line tool is behind the opt-in `cli` feature:

```bash
cargo install rune-macaddr --features cli
```

## Usage

### Library

```rust
use rune_macaddr::{Case, MacAddr, Notation, OuiDb, well_known};

let mac: MacAddr = "001B.6384.45E6".parse()?;
assert_eq!(mac.to_string(), "00:1b:63:84:45:e6");
assert_eq!(mac.format(Notation::Bare, Case::Upper), "001B638445E6");
assert!(mac.is_unicast() && mac.is_universal());

// Normally std::fs::read_to_string("oui.csv")?.
let csv = "Registry,Assignment,Organization Name,Organization Address\n\
           MA-L,001B63,\"Apple, Inc.\",1 Infinite Loop Cupertino CA US 95014\n";
let mut db = OuiDb::new();
db.load(csv)?;
assert_eq!(db.vendor(&mac), Some("Apple, Inc."));

let lldp: MacAddr = "01:80:c2:00:00:0e".parse()?;
assert!(lldp.is_multicast());
assert_eq!(well_known(&lldp).map(|w| w.reference), Some("IEEE 802.1AB"));
# Ok::<(), rune_macaddr::Error>(())
```

### CLI

```bash
rune-macaddr --oui oui.csv --oui mam.csv 001b.6384.45e6 01:00:5e:00:00:fb
# 00:1b:63:84:45:e6	unicast	universal	Apple, Inc.
# 01:00:5e:00:00:fb	multicast	universal	IPv4 multicast	ICANN, IANA Department

rune-macaddr --notation dot --upper 00-1b-63-84-45-e6
# 001B.6384.45E6	unicast	universal
```

## License

MIT
