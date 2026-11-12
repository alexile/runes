//! An async DNS stub resolver over [`rune_dns_wire`].
//!
//! A stub resolver sends each question to recursive resolvers you choose
//! (the *upstreams*) and reads their answers; it does not recurse itself.
//! This crate keeps the transport small and in your control: which
//! upstreams, how long to wait, how often to retry, and how many queries
//! may be in flight.
//!
//! - **Transports**: UDP with fallback to TCP when an answer is truncated,
//!   TCP, DNS over TLS ([RFC 7858](https://www.rfc-editor.org/rfc/rfc7858),
//!   feature `tls`) and DNS over HTTPS
//!   ([RFC 8484](https://www.rfc-editor.org/rfc/rfc8484), feature `doh`,
//!   HTTP/2 or HTTP/1.1).
//! - **Policy** ([`ResolverOptions`]): upstreams tried in order, a timeout
//!   per exchange, a number of rounds over the upstreams, and a cap on
//!   concurrent queries. `SERVFAIL`, `REFUSED` and other failure codes move
//!   on to the next upstream; `NXDOMAIN` is an answer.
//! - **Typed lookups** (`A`, `AAAA`, `CNAME`, `MX`, `TXT`, `NS`, `SOA`,
//!   `SRV`, `PTR`, `CAA`) return `rune-dns-wire` record data, following
//!   `CNAME` chains inside the answer.
//!
//! # Features
//!
//! Without features the crate is the sans-I/O core: [`Upstream`] and
//! [`ResolverOptions`], [`build_query`], [`check_response`] (which rejects
//! answers that do not match the query, as off-path spoofing would produce),
//! [`Lookup`] for reading answers, [`reverse_name`] and
//! [`parse_resolv_conf`].
//!
//! - `tokio`: the async `Resolver` over UDP and TCP.
//! - `tls`: DNS over TLS with rustls (ring) and the webpki root store.
//! - `doh`: DNS over HTTPS with hyper.
//!
//! # Example
//!
//! The core works in memory: build a query, check the response, read the
//! answer.
//!
//! ```
//! use std::net::Ipv4Addr;
//! use rune_dns_wire::{Message, Question, RData, Record, RecordType};
//! use rune_dns_resolver::{Lookup, ResolverOptions, Upstream, build_query, check_response};
//!
//! let options = ResolverOptions::default().with_upstream("192.0.2.53".parse::<Upstream>()?);
//! let question = Question::new("www.example.com".parse()?, RecordType::A);
//! let query = build_query(0x1234, question.clone(), &options);
//!
//! // What a server might answer: a CNAME, then the address.
//! let response = Message::response_to(&query)
//!     .with_answer(Record::new("www.example.com".parse()?, 60,
//!         RData::Cname("web.example.net".parse()?)))
//!     .with_answer(Record::new("web.example.net".parse()?, 60,
//!         RData::A(Ipv4Addr::new(192, 0, 2, 80))));
//! check_response(&query, &response)?;
//!
//! let lookup = Lookup::new(question, response);
//! assert_eq!(lookup.ipv4(), [Ipv4Addr::new(192, 0, 2, 80)]);
//! assert_eq!(lookup.cname_chain()[0].to_string(), "web.example.net");
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! With the `tokio` feature, the resolver does the I/O:
//!
//! ```no_run
//! # #[cfg(feature = "doh")]
//! # async fn demo() -> Result<(), rune_dns_resolver::Error> {
//! use std::time::Duration;
//! use rune_dns_resolver::{Resolver, ResolverOptions, Upstream};
//!
//! let options = ResolverOptions::default()
//!     .with_upstream(Upstream::https("https://cloudflare-dns.com/dns-query")?)
//!     .with_upstream("tls://1.1.1.1#cloudflare-dns.com".parse()?)
//!     .with_upstream("8.8.8.8".parse()?)
//!     .with_timeout(Duration::from_secs(2))
//!     .with_attempts(2)
//!     .with_concurrency(32);
//! let resolver = Resolver::new(options)?;
//! for mx in resolver.lookup_mx("example.com").await? {
//!     println!("{} {}", mx.preference, mx.exchange);
//! }
//! # Ok(())
//! # }
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod lookup;
mod options;
#[cfg(feature = "tokio")]
mod resolver;
#[cfg(feature = "tokio")]
mod transport;
mod upstream;

pub use lookup::{Lookup, build_query, check_response, reverse_name};
pub use options::ResolverOptions;
#[cfg(feature = "tokio")]
pub use resolver::{IntoName, Resolver};
pub use upstream::{DohEndpoint, Upstream, parse_resolv_conf};

/// The rustls version this crate uses, for building a custom
/// [`ClientConfig`](rustls::ClientConfig) for `Resolver::with_tls_config`.
#[cfg(feature = "tls")]
pub use tokio_rustls::rustls;

use std::time::Duration;

use rune_dns_wire::{Name, Rcode};

/// Errors returned by this crate.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// A name, query or response could not be encoded or decoded.
    #[error("invalid DNS message: {0}")]
    Wire(#[from] rune_dns_wire::Error),
    /// An upstream specification is malformed.
    #[error("invalid upstream: {reason}")]
    InvalidUpstream {
        /// What is wrong with it.
        reason: &'static str,
    },
    /// [`ResolverOptions::upstreams`] is empty.
    #[error("no upstream servers configured")]
    NoUpstreams,
    /// The response does not answer the query: wrong id, question or flags.
    #[error("response does not match the query: {reason}")]
    Mismatch {
        /// What does not match.
        reason: &'static str,
    },
    /// Every upstream failed; this is the last failure code (`SERVFAIL`,
    /// `REFUSED`, ...).
    #[error("upstream answered {0}")]
    Rcode(Rcode),
    /// The name does not exist (`NXDOMAIN`). Typed lookups return this;
    /// `Resolver::query` returns the response instead.
    #[error("{name} does not exist (NXDOMAIN)")]
    NxDomain {
        /// The name looked up.
        name: Name,
    },
    /// A response over TCP, TLS or HTTPS has the `TC` bit set.
    #[error("truncated response over a stream transport")]
    Truncated,
    /// An exchange took longer than [`ResolverOptions::timeout`].
    #[error("query timed out after {0:?}")]
    Timeout(Duration),
    /// A socket error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    /// The TLS handshake failed.
    #[error("TLS error: {0}")]
    Tls(String),
    /// The HTTP exchange failed.
    #[error("HTTP error: {0}")]
    Http(String),
    /// The `DoH` server answered with a status other than 200.
    #[error("HTTP status {0}")]
    HttpStatus(u16),
}
