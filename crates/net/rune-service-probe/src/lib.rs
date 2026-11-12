//! Read-only service probing: the trait every `rune-probe-*` crate
//! implements, the [`ServiceInfo`] they report, and a bounded runner.
//!
//! A protocol probe ([`ServiceProbe`]) is a sans-I/O state machine
//! ([`ProbeSession`]): it says what to send ([`Action::Send`]), when to wait
//! ([`Action::Receive`]) and when it is done, and it turns the bytes it is
//! fed into a [`ServiceInfo`] (product, version, banner, capabilities, TLS
//! and authentication requirements) plus [`rune_finding::Finding`]s. The
//! same probe then runs:
//!
//! - in memory against scripted replies with [`simulate`], for tests and
//!   fuzzing;
//! - over tokio TCP or UDP sockets with [`Runner`] (`tokio` feature), which
//!   adds connect, I/O and total timeouts and a concurrency bound;
//! - over any stream the caller opened (TLS for SMTPS or LDAPS) with
//!   [`Runner::probe_stream`];
//! - in the caller's own I/O loop around a [`Driver`].
//!
//! Every [`Driver`] enforces a read budget and a step budget, and refuses
//! [`Safety::Intrusive`] probes unless [`Options::allow_intrusive`] is set.
//! Which targets may be probed at all is the caller's policy: the runner
//! probes whatever it is given.
//!
//! [`banner`] has helpers for untrusted banners and a generic
//! [`BannerProbe`](banner::BannerProbe).
//!
//! # Example
//!
//! A minimal probe that reads the SSH identification string
//! ([RFC 4253 §4.2](https://www.rfc-editor.org/rfc/rfc4253#section-4.2)),
//! run against a scripted server:
//!
//! ```
//! use rune_finding::{Confidence, Severity};
//! use rune_service_probe::banner::{printable, split_line};
//! use rune_service_probe::{
//!     Action, AuthRequirement, End, Error, Options, ProbeSession, ServiceInfo, ServiceProbe,
//!     Target, simulate,
//! };
//!
//! struct SshIdent;
//!
//! impl ServiceProbe for SshIdent {
//!     fn id(&self) -> &str { "ssh" }
//!     fn default_ports(&self) -> &[u16] { &[22] }
//!     fn session(&self, target: &Target) -> Box<dyn ProbeSession> {
//!         Box::new(Session { target: target.clone(), buf: Vec::new() })
//!     }
//! }
//!
//! struct Session { target: Target, buf: Vec<u8> }
//!
//! impl ProbeSession for Session {
//!     // The server speaks first.
//!     fn start(&mut self) -> Action { Action::Receive }
//!
//!     fn on_data(&mut self, data: &[u8]) -> Action {
//!         self.buf.extend_from_slice(data);
//!         if split_line(&self.buf).is_some() { Action::Done } else { Action::Receive }
//!     }
//!
//!     fn finish(&mut self, _end: End) -> Result<ServiceInfo, Error> {
//!         let line = split_line(&self.buf).map_or(&self.buf[..], |(line, _)| line);
//!         let text = printable(line, 255);
//!         let Some(software) = text.strip_prefix("SSH-2.0-") else {
//!             return Err(Error::unrecognized("ssh", "no SSH-2.0 identification string"));
//!         };
//!         let mut info = ServiceInfo::new("ssh")
//!             .with_banner(text.clone())
//!             .with_auth(AuthRequirement::Required);
//!         if let Some(version) = software.strip_prefix("OpenSSH_") {
//!             info = info.with_product("OpenSSH").with_version(version);
//!             if version.starts_with('6') {
//!                 info = info.push_finding(self.target.finding(
//!                     "ssh.outdated",
//!                     "Outdated OpenSSH",
//!                     Severity::Low,
//!                     Confidence::Firm,
//!                 ));
//!             }
//!         }
//!         Ok(info)
//!     }
//! }
//!
//! let target = Target::new("bastion.test", 22);
//! let sim = simulate(&SshIdent, &target, &[b"SSH-2.0-Open", b"SSH_6.6\r\n"], &Options::default())?;
//! assert!(sim.sent.is_empty()); // read-only: the probe sent nothing
//! let info = sim.result?;
//! assert_eq!(info.product.as_deref(), Some("OpenSSH"));
//! assert_eq!(info.version.as_deref(), Some("6.6"));
//! assert_eq!(info.findings[0].check_id, "ssh.outdated");
//!
//! let http = simulate(&SshIdent, &target, &[b"HTTP/1.1 400 Bad Request\r\n"], &Options::default())?;
//! assert!(matches!(http.result, Err(Error::Unrecognized { .. })));
//! # Ok::<(), Error>(())
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![cfg_attr(docsrs, feature(doc_cfg))]

pub mod banner;
mod driver;
mod error;
mod info;
mod probe;
#[cfg(feature = "tokio")]
mod runner;
mod set;

pub use driver::{Driver, Next, Options, Simulation, simulate};
pub use error::Error;
pub use info::{AuthRequirement, ServiceInfo, TlsSupport};
pub use probe::{Action, End, ProbeSession, Safety, ServiceProbe, Target, Transport};
#[cfg(feature = "tokio")]
pub use runner::Runner;
pub use set::ProbeSet;

/// The finding model probes report in, re-exported for probe crates.
pub use rune_finding;
