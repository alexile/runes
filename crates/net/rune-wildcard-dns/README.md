# rune-wildcard-dns

> Wildcard DNS detection and filtering for subdomain enumeration, over a caller-supplied resolver

[![crates.io](https://img.shields.io/crates/v/rune-wildcard-dns)](https://crates.io/crates/rune-wildcard-dns)
[![docs.rs](https://img.shields.io/docsrs/rune-wildcard-dns)](https://docs.rs/rune-wildcard-dns)
[![license](https://img.shields.io/crates/l/rune-wildcard-dns)](LICENSE)
[![CI](https://github.com/alexile/runes/actions/workflows/ci.yml/badge.svg)](https://github.com/alexile/runes/actions)

A zone with a wildcard record (`*.example.com`, [RFC 4592](https://www.rfc-editor.org/rfc/rfc4592))
answers every name under it, so a brute-force or permutation enumerator would
report every guess as live. `rune-wildcard-dns` learns what the wildcard
answers by resolving random labels, and filters candidates whose answer is
just that.

- **Per-parent probing, cached.** To judge `a.b.example.com` it probes
  random siblings `<r>.b.example.com`, which by RFC 4592 are answered by the
  same wildcard as the candidate. Multi-level cases come out right:
  `*.dev.example.com` under a clean apex, `*.example.com` answering
  `a.b.example.com`, and no false wildcard below an existing node.
- **Rotating wildcards.** Learning keeps probing while answers still show new
  addresses, up to `max_probes`; a candidate that only partly overlaps the
  wildcard triggers more probes before it is judged.
- **CNAME wildcards** are matched by first-hop target, so the CDN behind
  them can rotate addresses freely.
- **Bring your own resolver.** No I/O in the crate: implement `Resolver`
  (blocking) or `AsyncResolver`. Answers are `rune-dns-wire` records.
- Unicode domains go through IDNA (`rune-idna`); nothing is probed under a
  public suffix (`rune-psl`).

## Installation

```toml
[dependencies]
rune-wildcard-dns = "0.1"
```

## Usage

```rust
use std::convert::Infallible;
use std::net::Ipv4Addr;
use rune_dns_wire::{Name, RData, Record, RecordType};
use rune_wildcard_dns::{Options, Response, Verdict, WildcardFilter, from_fn};

// Any transport works; here a closure stands in for a resolver where
// `*.example.com` answers 192.0.2.1 and `www` has its own address.
let mut resolver = from_fn(|name: &Name, rtype: RecordType| {
    let www: Name = "www.example.com".parse().unwrap();
    let addr = if name.eq_ignore_ascii_case(&www) {
        Ipv4Addr::new(192, 0, 2, 80)
    } else {
        Ipv4Addr::new(192, 0, 2, 1)
    };
    Ok::<_, Infallible>(if rtype == RecordType::A {
        Response::answer(vec![Record::new(name.clone(), 60, RData::A(addr))])
    } else {
        Response::answer(vec![])
    })
});

let mut filter = WildcardFilter::new(Options::default());
assert!(filter.detect(&mut resolver, "example.com").unwrap().is_wildcard());

let www: Name = "www.example.com".parse().unwrap();
let guess: Name = "staging-7.example.com".parse().unwrap();
assert_eq!(filter.check(&mut resolver, &www).unwrap(), Verdict::Genuine);
assert_eq!(filter.check(&mut resolver, &guess).unwrap(), Verdict::Wildcard);
```

Already have the candidate's answer? Use `classify` (probes the parent if
needed) or `cached_verdict` (pure, cache only). Every method has an `_async`
form over `AsyncResolver`.

## Limits

A real host that answers exactly what the wildcard answers is
indistinguishable from it and is filtered. A candidate still only partly
covered after `max_probes` probes is judged genuine.

## License

MIT
