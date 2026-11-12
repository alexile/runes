# rune-dns-wire

> Sans-I/O DNS message parser and builder (RFC 1035, EDNS0, name compression)

[![crates.io](https://img.shields.io/crates/v/rune-dns-wire)](https://crates.io/crates/rune-dns-wire)
[![docs.rs](https://img.shields.io/docsrs/rune-dns-wire)](https://docs.rs/rune-dns-wire)
[![license](https://img.shields.io/crates/l/rune-dns-wire)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

`rune-dns-wire` turns DNS messages into Rust values and back. It does no I/O:
bring your own UDP, TCP, DoH or DoT transport and hand it the bytes.

- **Decode** whole messages: header, all four sections, name decompression,
  and the EDNS(0) `OPT` record lifted into `Message::edns`.
- **Encode** with name compression where RFC 3597 allows it, or with a size
  limit that drops whole records and sets `TC`, as a UDP responder must.
- **Build** queries and responses: `Message::query`, `Message::response_to`
  and `with_*` methods.
- **Typed RDATA** for `A`, `AAAA`, `NS`, `CNAME`, `PTR`, `MX`, `TXT`, `SOA`,
  `SRV`, `CAA`, `TLSA`, `DS`, `DNSKEY` and `RRSIG`. Every other type is kept
  as opaque bytes (RFC 3597), so it still round-trips.

## Untrusted input

The decoder is built for hostile packets. It never panics, never reads past
the input, sizes its allocations by the input rather than by the counts in the
header, and returns an error for:

- compression pointers that do not point strictly backwards (so no loops),
  point into the header, or chain more than 128 times;
- names over 255 octets after decompression, and the reserved `0x40`/`0x80`
  label types;
- RDATA whose length does not match its type's layout, and names in RDATA
  that run past it;
- a second `OPT` record, an `OPT` outside the additional section or with a
  non-root owner;
- trailing bytes after the last record.

It is property-tested and tested against real responses captured from a public resolver, which all
re-encode byte for byte.

## Installation

```toml
[dependencies]
rune-dns-wire = "0.1"
```

## Usage

A minimal authoritative responder, the shape of an out-of-band interaction
server:

```rust
use std::net::Ipv4Addr;
use rune_dns_wire::{Message, Question, RData, Record, RecordType};

// What the socket received (built here for the example).
let query = Message::query(7, Question::new("c0ffee.oob.example".parse()?, RecordType::A));
let datagram = query.encode()?;

// Parse it, look at the question, answer with an A record.
let query = Message::decode(&datagram)?;
let question = &query.questions[0];
let correlation_id = question.name.labels().next().unwrap_or_default();
assert_eq!(correlation_id, b"c0ffee");

let response = Message::response_to(&query)
    .with_authoritative(true)
    .with_answer(Record::new(
        question.name.clone(),
        60,
        RData::A(Ipv4Addr::new(192, 0, 2, 1)),
    ));
// At most 512 octets for plain UDP; TC is set if records had to go.
let reply = response.encode_with_limit(512)?;
assert_eq!(Message::decode(&reply)?.answers.len(), 1);
# Ok::<(), rune_dns_wire::Error>(())
```

Messages print in a `dig`-like form:

```rust
use rune_dns_wire::{Edns, Message, Question, RecordType};

let query = Message::query(1, Question::new("example.com".parse()?, RecordType::MX))
    .with_edns(Edns::default().with_dnssec_ok(true));
assert!(query.to_string().contains("example.com IN MX"));
# Ok::<(), rune_dns_wire::Error>(())
```

## Specifications

[RFC 1035](https://www.rfc-editor.org/rfc/rfc1035) (messages, compression),
[RFC 3596](https://www.rfc-editor.org/rfc/rfc3596) (`AAAA`),
[RFC 2782](https://www.rfc-editor.org/rfc/rfc2782) (`SRV`),
[RFC 8659](https://www.rfc-editor.org/rfc/rfc8659) (`CAA`),
[RFC 6698](https://www.rfc-editor.org/rfc/rfc6698) (`TLSA`),
[RFC 4034](https://www.rfc-editor.org/rfc/rfc4034) (`DS`, `DNSKEY`, `RRSIG`),
[RFC 6891](https://www.rfc-editor.org/rfc/rfc6891) (EDNS(0)),
[RFC 3597](https://www.rfc-editor.org/rfc/rfc3597) (unknown types),
[RFC 2181](https://www.rfc-editor.org/rfc/rfc2181) (truncation).

## License

MIT
