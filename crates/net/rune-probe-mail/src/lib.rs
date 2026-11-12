//! Read-only SMTP/SMTPS and FTP/FTPS probes for
//! [`rune_service_probe`]: greeting banner and product, `EHLO` and `FEAT`
//! capabilities, and whether TLS is offered (`STARTTLS`, `AUTH TLS`).
//!
//! - [`SmtpProbe`] ([RFC 5321](https://www.rfc-editor.org/rfc/rfc5321),
//!   [RFC 3207](https://www.rfc-editor.org/rfc/rfc3207)): greeting, `EHLO`
//!   (or `HELO`), `QUIT`. [`SmtpProbe::smtps`] runs the same dialogue over a
//!   TLS stream the caller opened (port 465).
//! - [`FtpProbe`] ([RFC 959](https://www.rfc-editor.org/rfc/rfc959),
//!   [RFC 2389](https://www.rfc-editor.org/rfc/rfc2389),
//!   [RFC 4217](https://www.rfc-editor.org/rfc/rfc4217)): greeting, `FEAT`,
//!   `SYST`, `QUIT`. [`FtpProbe::ftps`] is the implicit-TLS variant (port 990).
//!
//! Neither probe logs in, sends mail or touches a mailbox. Both can
//! optionally confirm the TLS upgrade (`STARTTLS`, `AUTH TLS`) and hang up
//! before the handshake.
//!
//! [`parse_reply`] is the sans-I/O reply parser they share.
//!
//! # Example
//!
//! ```
//! use rune_probe_mail::SmtpProbe;
//! use rune_service_probe::{Options, Target, TlsSupport, simulate};
//!
//! let replies: [&[u8]; 3] = [
//!     b"220 mx.example.test ESMTP Postfix (Debian/GNU)\r\n",
//!     b"250-mx.example.test\r\n250-PIPELINING\r\n250-SIZE 10240000\r\n250-VRFY\r\n\
//!       250-AUTH PLAIN LOGIN\r\n250 8BITMIME\r\n",
//!     b"221 2.0.0 Bye\r\n",
//! ];
//! let target = Target::new("mx.example.test", 25);
//! let sim = simulate(&SmtpProbe::new(), &target, &replies, &Options::default())?;
//! assert_eq!(sim.sent, [b"EHLO probe.invalid\r\n".to_vec(), b"QUIT\r\n".to_vec()]);
//!
//! let info = sim.result?;
//! assert_eq!(info.product.as_deref(), Some("Postfix"));
//! assert_eq!(info.tls, TlsSupport::NotOffered);
//! assert_eq!(info.details["smtp.auth_mechanisms"], "PLAIN LOGIN");
//! let checks: Vec<&str> = info.findings.iter().map(|f| f.check_id.as_str()).collect();
//! assert_eq!(checks, ["smtp.user_enumeration", "smtp.starttls_missing", "smtp.auth_before_tls"]);
//! # Ok::<(), rune_service_probe::Error>(())
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod conversation;
mod error;
pub mod ftp;
mod reply;
pub mod smtp;

pub use error::Error;
pub use ftp::FtpProbe;
pub use reply::{MAX_LINE_BYTES, MAX_REPLY_LINES, Reply, parse_reply};
pub use smtp::SmtpProbe;
