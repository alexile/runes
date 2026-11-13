//! Allowlisted, default-deny HTTP `CONNECT` egress proxy.
//!
//! A sandboxed process (an AI coding agent, a build, a test runner) gets one
//! way out: this proxy, which only opens tunnels to targets a [`Policy`]
//! allows.
//!
//! - **Host allowlist** ([`rune_host_match`]): exact names and `*.suffix`
//!   for subdomains, never the apex. `*.github.com` allows
//!   `api.github.com`, not `github.com` or `evilgithub.com`.
//! - **IP allowlist** ([`rune_cidr`]): bare addresses or CIDR ranges. An IP
//!   literal target is allowed only through this list; being a public
//!   address is not enough.
//! - **SSRF guard and DNS pinning** ([`rune_ip`]): an allowed hostname is
//!   resolved once, and the proxy connects to the first resolved address
//!   that is globally reachable or IP-allowlisted, never re-resolving. An
//!   allowed name whose DNS answer points at `169.254.169.254`, loopback,
//!   RFC 1918 or other non-global space is refused. Mapped and NAT64 forms
//!   (`::ffff:10.0.0.1`, `64:ff9b::a9fe:a9fe`) are unwrapped first.
//! - **Optional port allowlist**, request-head size and time limits.
//!
//! The decision logic is sans-I/O: [`parse_request`] reads a request head
//! from bytes and [`Policy::decide`] / [`Policy::pin`] decide on values.
//! [`Proxy`] wraps them in a blocking, thread-per-connection server over
//! TCP or Unix domain sockets. The proxy follows
//! [RFC 9110 §9.3.6](https://www.rfc-editor.org/rfc/rfc9110#section-9.3.6)
//! (`CONNECT`); every other method gets `501`.
//!
//! # Example
//!
//! ```
//! use rune_egress_proxy::{parse_request, Decision, Denial, Policy, DEFAULT_MAX_HEAD_LEN};
//!
//! let policy = Policy::new()
//!     .allow_hosts(["api.anthropic.com", "*.github.com"])?
//!     .allow_ip("10.0.0.0/8")?;
//!
//! let head = b"CONNECT api.github.com:443 HTTP/1.1\r\nHost: api.github.com:443\r\n\r\n";
//! let request = parse_request(head, DEFAULT_MAX_HEAD_LEN)?.unwrap();
//! let Decision::Resolve { host, port } = policy.decide(&request.target) else {
//!     unreachable!()
//! };
//! assert_eq!((host.as_str(), port), ("api.github.com", 443));
//!
//! // Pin the DNS answer: skip the non-global address, use the public one.
//! let answer = ["127.0.0.1:443".parse().unwrap(), "140.82.112.6:443".parse().unwrap()];
//! assert_eq!(policy.pin(answer), Ok("140.82.112.6:443".parse().unwrap()));
//!
//! // Default deny.
//! let head = b"CONNECT github.com:443 HTTP/1.1\r\n\r\n";
//! let request = parse_request(head, DEFAULT_MAX_HEAD_LEN)?.unwrap();
//! assert_eq!(policy.decide(&request.target), Decision::Deny(Denial::HostNotAllowed));
//! # Ok::<(), rune_egress_proxy::Error>(())
//! ```
//!
//! Serving it:
//!
//! ```no_run
//! use std::net::TcpListener;
//! use rune_egress_proxy::{Policy, Proxy};
//!
//! let proxy = Proxy::new(Policy::new().allow_host("*.crates.io")?)
//!     .with_observer(|event| eprintln!("egress: {event}"));
//! proxy.serve_tcp(&TcpListener::bind("127.0.0.1:3128")?);
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! # Limits
//!
//! This is a tunnel, not a firewall: it constrains only clients that use
//! it, and it cannot see inside TLS. For a hard boundary, give the client a
//! network namespace with no other route and expose the proxy through a
//! bind-mounted Unix socket ([`Proxy::serve_unix`]). Only the `CONNECT`
//! target is checked, not the TLS SNI or `Host` inside the tunnel, so an
//! allowed name served by a shared CDN can be used to reach other sites on
//! that CDN (domain fronting). Connections are served one thread each, with
//! no idle timeout once a tunnel is open.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod error;
mod policy;
mod proxy;
mod request;

pub use error::Error;
pub use policy::{Decision, Denial, Policy};
pub use proxy::{Event, Proxy, Resolve, Stream, SystemResolver};
pub use request::{ConnectRequest, DEFAULT_MAX_HEAD_LEN, Host, Target, parse_request};
pub use rune_cidr::Cidr;
pub use rune_host_match::{HostAllowlist, HostPattern, Hostname};
