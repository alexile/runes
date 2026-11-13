//! Read-only SSH probe and policy grader: the identification string, the
//! server's offered algorithms graded against a policy, the Terrapin
//! check, banner-based software detection, and the host-key fingerprint.
//!
//! [`SshProbe`] is a [`rune_service_probe::ServiceProbe`]: run it with the
//! `rune-service-probe` runner (or [`simulate`](rune_service_probe::simulate)
//! in memory). It
//!
//! 1. reads the identification string
//!    ([RFC 4253 §4.2](https://www.rfc-editor.org/rfc/rfc4253#section-4.2)),
//! 2. reads `SSH_MSG_KEXINIT`
//!    ([§7.1](https://www.rfc-editor.org/rfc/rfc4253#section-7.1)) and audits
//!    grades the offered key-exchange, host-key, cipher, MAC and
//!    compression algorithms ([`policy`]),
//! 3. starts a key exchange only far enough to read the server's public
//!    host key and report its SHA-256 fingerprint, as `ssh-keyscan` does.
//!
//! It never derives keys, sends `NEWKEYS` or attempts authentication.
//!
//! The parsers it is built from are public and sans-I/O:
//! [`Identification`], [`parse_packet`] / [`encode_packet`], [`KexInit`]
//! and [`HostKey`]. So is the grading:
//!
//! - [`policy`]: [`Policy`](policy::Policy) (profiles `modern` and
//!   `compatible`, plus your own allow/deny lists) judges each algorithm
//!   as fail, warn or info, and grades the server `A` to `F`;
//!   [`Report::findings`](policy::Report::findings) turns the result into
//!   `rune-finding` findings.
//! - [`algorithms`]: the table behind it, with the RFC, NIST and OpenSSH
//!   release-note sources for each entry.
//! - [`audit`]: the plain weak-algorithm list and the Terrapin
//!   (CVE-2023-48795) check.
//! - [`software`]: server software and version from the banner, with a
//!   small table of notable CVEs by version range. Heuristic: distribution
//!   builds backport fixes without changing the version.
//!
//! # Example
//!
//! A scripted server: its identification and KEXINIT, then its reply to
//! the probe's key-exchange init.
//!
//! ```
//! use rune_probe_ssh::{KexInit, SshProbe, encode_packet};
//! use rune_service_probe::{Options, Target, simulate};
//!
//! fn string(out: &mut Vec<u8>, s: &[u8]) {
//!     out.extend_from_slice(&(s.len() as u32).to_be_bytes());
//!     out.extend_from_slice(s);
//! }
//!
//! let mut offer = KexInit::default();
//! offer.kex_algorithms = vec!["curve25519-sha256".into(), "diffie-hellman-group1-sha1".into()];
//! offer.server_host_key_algorithms = vec!["ssh-ed25519".into()];
//! offer.encryption_client_to_server = vec!["aes128-ctr".into(), "aes128-cbc".into()];
//! offer.encryption_server_to_client = offer.encryption_client_to_server.clone();
//! offer.mac_client_to_server = vec!["hmac-sha2-256".into()];
//! offer.mac_server_to_client = offer.mac_client_to_server.clone();
//! offer.compression_client_to_server = vec!["none".into()];
//! offer.compression_server_to_client = vec!["none".into()];
//! let mut hello = b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3\r\n".to_vec();
//! hello.extend(encode_packet(&offer.encode()));
//!
//! let host_key = rune_base64::decode(
//!     "AAAAC3NzaC1lZDI1NTE5AAAAIOJv+0BnO5Sq9IS18Q8eLfxJL3GuLtonL4clXHHkg4EX",
//! ).unwrap();
//! let mut reply = vec![31]; // SSH_MSG_KEX_ECDH_REPLY
//! string(&mut reply, &host_key);
//! string(&mut reply, &[7; 32]);
//! string(&mut reply, b"signature");
//! let reply = encode_packet(&reply);
//!
//! let target = Target::new("bastion.test", 22);
//! let sim = simulate(&SshProbe::new(), &target, &[&hello, &reply], &Options::default())?;
//! assert!(sim.sent[0].starts_with(b"SSH-2.0-rune_probe_ssh\r\n"));
//!
//! let info = sim.result?;
//! assert_eq!(info.product.as_deref(), Some("OpenSSH"));
//! assert_eq!(info.version.as_deref(), Some("8.9p1"));
//! assert_eq!(
//!     info.details["ssh.host_key_fingerprint"],
//!     "SHA256:sy6hgZYNW2YfQFZt6xYCu+D96SlMGrevKRhp8XYPN74",
//! );
//! assert!(info.capabilities.contains(&"cipher:aes128-cbc".to_owned()));
//! let checks: Vec<&str> = info.findings.iter().map(|f| f.check_id.as_str()).collect();
//! assert_eq!(
//!     checks,
//!     ["ssh.weak_kex", "ssh.weak_cipher", "ssh.discouraged_mac", "ssh.cve-2024-6387"],
//! );
//! assert_eq!(info.details["ssh.grade"], "D");
//! # Ok::<(), rune_service_probe::Error>(())
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod algorithms;
pub mod audit;
mod error;
mod hostkey;
mod kexinit;
pub mod policy;
mod probe;
pub mod software;
mod wire;

pub use error::Error;
pub use hostkey::{HostKey, parse_kex_reply_host_key};
pub use kexinit::KexInit;
pub use probe::{DEFAULT_CLIENT_SOFTWARE, PROBE_ID, SUPPORTED_KEX, SshProbe};
pub use wire::{
    Identification, MAX_IDENTIFICATION_LEN, MAX_PACKET_LEN, MSG_DEBUG, MSG_DISCONNECT, MSG_IGNORE,
    MSG_KEX_INIT, MSG_KEX_REPLY, MSG_KEXINIT, MSG_UNIMPLEMENTED, encode_packet, parse_packet,
};
