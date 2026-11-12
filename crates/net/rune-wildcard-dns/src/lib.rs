//! Wildcard DNS detection and filtering for subdomain enumeration.
//!
//! A zone with a wildcard record (`*.example.com`, RFC 4592) answers every
//! name under it, so a brute-force or permutation enumerator would report
//! every guess as live. This crate learns what the wildcard answers, by
//! resolving random labels, and filters candidate answers that are just
//! that.
//!
//! - [`WildcardFilter::detect`] probes a domain at one or more depths and
//!   reports where wildcards are.
//! - [`WildcardFilter::check`] resolves a candidate and returns a
//!   [`Verdict`]: [`Genuine`](Verdict::Genuine),
//!   [`Wildcard`](Verdict::Wildcard) or [`Unresolved`](Verdict::Unresolved).
//!   [`WildcardFilter::classify`] does the same for an answer you already
//!   have.
//! - [`WildcardFilter::cached_verdict`] is the pure predicate: it judges an
//!   answer from what has been learned so far, with no I/O.
//!
//! Probing is per parent name and cached, so it handles multi-level
//! wildcards (`*.dev.example.com` under a clean `example.com`, or
//! `*.example.com` answering `a.b.example.com`) and costs one round of
//! probes per parent. Rotating wildcards, which answer from a pool of
//! addresses, are learned by probing until no new data appears, and a
//! candidate that only partly overlaps a wildcard triggers more probes
//! before it is judged. CNAME wildcards are matched by target, so the CDN
//! behind them can rotate addresses freely.
//!
//! # Bring your own resolver
//!
//! The crate does no I/O. Implement [`Resolver`] (blocking) or
//! [`AsyncResolver`] over your transport — a socket, the system resolver,
//! `rune-dns-resolver` — and every method has a matching `_async` form.
//! Answers are [`rune_dns_wire`] records. Domains given as text go through
//! IDNA (`rune-idna`), and by default nothing is ever probed under a public
//! suffix (`rune-psl`).
//!
//! # Example
//!
//! ```
//! use std::convert::Infallible;
//! use std::net::Ipv4Addr;
//! use rune_dns_wire::{Name, RData, Record, RecordType};
//! use rune_wildcard_dns::{Options, Response, Verdict, WildcardFilter, from_fn};
//!
//! // A toy zone: `*.example.com` answers 192.0.2.1, `www` has its own address.
//! let mut resolver = from_fn(|name: &Name, rtype: RecordType| {
//!     let www: Name = "www.example.com".parse().unwrap();
//!     let apex: Name = "example.com".parse().unwrap();
//!     let addr = if name.eq_ignore_ascii_case(&www) {
//!         Ipv4Addr::new(192, 0, 2, 80)
//!     } else if name.is_subdomain_of(&apex) {
//!         Ipv4Addr::new(192, 0, 2, 1)
//!     } else {
//!         return Ok::<_, Infallible>(Response::nxdomain());
//!     };
//!     Ok(if rtype == RecordType::A {
//!         Response::answer(vec![Record::new(name.clone(), 60, RData::A(addr))])
//!     } else {
//!         Response::answer(vec![]) // NODATA
//!     })
//! });
//!
//! let mut filter = WildcardFilter::new(Options::default());
//! let report = filter.detect(&mut resolver, "example.com")?;
//! assert!(report.is_wildcard());
//!
//! let www: Name = "www.example.com".parse()?;
//! let guess: Name = "does-not-exist.example.com".parse()?;
//! assert_eq!(filter.check(&mut resolver, &www)?, Verdict::Genuine);
//! assert_eq!(filter.check(&mut resolver, &guess)?, Verdict::Wildcard);
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! # Limits
//!
//! A host that exists but answers exactly what the wildcard answers cannot
//! be told apart from it and is filtered. A candidate still only partly
//! covered after [`Options::max_probes`] probes is judged genuine:
//! enumerators would rather report one host too many than miss one.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod error;
mod filter;
mod fingerprint;
mod resolver;

pub use error::{BoxError, Error};
pub use filter::{Level, LevelReport, Options, Report, Verdict, WildcardFilter, parse_domain};
pub use fingerprint::{Fingerprint, Match};
pub use resolver::{AsyncResolver, FromFn, Resolver, Response, from_fn};
