# rune-dns-zone

> Sans-I/O DNS zone-file (RFC 1035 master format) parser and writer with AXFR/IXFR reassembly

[![crates.io](https://img.shields.io/crates/v/rune-dns-zone)](https://crates.io/crates/rune-dns-zone)
[![docs.rs](https://img.shields.io/docsrs/rune-dns-zone)](https://docs.rs/rune-dns-zone)
[![license](https://img.shields.io/crates/l/rune-dns-zone)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

`rune-dns-zone` reads and writes zone files and reassembles zone transfers,
on top of the message codec in [`rune-dns-wire`](../rune-dns-wire). It does
no I/O: hand it text and DNS messages, and bring your own files and sockets.

- **Zone files** ([RFC 1035 §5](https://www.rfc-editor.org/rfc/rfc1035#section-5)):
  `$ORIGIN`, `$TTL` ([RFC 2308](https://www.rfc-editor.org/rfc/rfc2308)),
  `$INCLUDE` through a loader you supply, relative and absolute names, `@`,
  blank owners, parentheses, comments, BIND TTL units (`1h30m`), RRSIG
  `YYYYMMDDHHmmSS` times and the RFC 3597 `\# <len> <hex>` generic form.
- **Writing** a zone back as master-file text that parses to the same
  records.
- **AXFR** ([RFC 5936](https://www.rfc-editor.org/rfc/rfc5936)) and **IXFR**
  ([RFC 1995](https://www.rfc-editor.org/rfc/rfc1995)) responses spread over
  any number of messages, with a DNS-over-TCP stream splitter. IXFR tells
  "up to date", a full zone and incremental differences apart.

Typed records: `A`, `AAAA`, `NS`, `CNAME`, `PTR`, `MX`, `TXT`, `SOA`, `SRV`,
`CAA`, `TLSA`, `DS`, `DNSKEY`, `RRSIG`. Also understood in presentation form,
and kept as opaque RDATA: `HINFO`, `MINFO`, `RP`, `AFSDB`, `LOC`, `KX`,
`CERT`, `DNAME`, `NAPTR`, `SSHFP`, `NSEC`, `NSEC3`, `NSEC3PARAM`, `SMIMEA`,
`CDS`, `CDNSKEY`, `OPENPGPKEY`, `ZONEMD`, `SPF`, `URI`. Any other type works
in the `\#` form.

The parsers are written for hostile input: they never panic, bound
`$INCLUDE` nesting and the total number of `$INCLUDE`s, and cap the number
of records (10 million by default; set a lower cap for servers you do not
trust). Transfers drop records whose owner lies outside the zone, so a
primary cannot plant names of other zones.

## Installation

```toml
[dependencies]
rune-dns-zone = "0.2"
```

## Usage

### Zone files

```rust
use rune_dns_wire::RecordType;
use rune_dns_zone::{ParseOptions, parse};

let text = "$ORIGIN example.com.\n$TTL 1h\n\
            @   IN SOA ns1 hostmaster ( 1 2h 15m 2w 5m )\n\
                IN NS  ns1\n\
            ns1 IN A   192.0.2.53\n";
let zone = parse(text, &ParseOptions::default())?;
assert_eq!(zone.records[2].rtype(), RecordType::A);
assert_eq!(zone.records[2].name.to_string(), "ns1.example.com");

// Back to text: parsing it again gives the same records.
assert_eq!(parse(&zone.to_master_file(), &ParseOptions::default())?, zone);
```

### Zone transfers

```rust
use rune_dns_wire::Name;
use rune_dns_zone::{Axfr, Error, Status, TcpFrames, axfr_query};

let zone: Name = "example.com".parse()?;
let query = axfr_query(0x4a7f, zone.clone()).encode()?;
let request = TcpFrames::frame(&query)?; // write this to the TCP socket

let mut frames = TcpFrames::new();
let mut axfr = Axfr::new(zone).with_id(0x4a7f);
frames.push(&bytes_read_from_socket); // as they arrive
while let Some(message) = frames.next_frame() {
    match axfr.push_bytes(&message) {
        Ok(Status::Done) => break,
        Ok(_) => {}
        // REFUSED or NOTAUTH: zone transfers are not exposed.
        Err(Error::Rcode(rcode)) => println!("transfer refused: {rcode}"),
        Err(error) => return Err(error.into()),
    }
}
if axfr.is_done() {
    let zone = axfr.finish()?;
    println!("{zone}");
}
```

## Migrating from 0.1

- `Axfr` and `Ixfr` now drop records whose owner lies outside the zone
  being transferred. 0.1 kept them.
- `parse_with_includes` reads at most 1024 `$INCLUDE`s in all by default
  (`ParseOptions::max_includes`) and returns `Error::TooManyIncludes` past
  that. Raise the limit with `ParseOptions::with_max_includes`.

## License

MIT
