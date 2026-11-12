//! Read-only handshake probes for Windows remote-access services, built on
//! [`rune_service_probe`]: SMB `NEGOTIATE` and RDP security-protocol
//! negotiation.
//!
//! | Probe          | Id     | Port      | Sends                                        | Learns                                                         |
//! | -------------- | ------ | --------- | -------------------------------------------- | -------------------------------------------------------------- |
//! | [`SmbProbe`]   | `smb`  | 445       | SMB 2/3 `NEGOTIATE`, dialects 2.0.2–3.1.1     | best dialect, signing policy, GUID, capabilities, ciphers, auth mechanisms |
//! | [`Smb1Probe`]  | `smb1` | 445, 139  | SMB1 `NEGOTIATE` offering only `NT LM 0.12`  | whether `SMBv1` is enabled, its signing policy, domain name      |
//! | [`RdpProbe`]   | `rdp`  | 3389      | X.224 Connection Request with `RDP_NEG_REQ`  | security protocol picked or required, NLA enforcement          |
//!
//! Every probe sends one request, reads one answer and disconnects: no
//! SMB session is set up and no RDP logon starts, so all are
//! [`Safety::ReadOnly`](rune_service_probe::Safety). Run them in memory with
//! [`simulate`](rune_service_probe::simulate), over tokio with
//! `rune_service_probe::Runner` (its `tokio` feature), or in any I/O loop
//! around a [`Driver`](rune_service_probe::Driver).
//!
//! The parsers ([`smb::parse_negotiate`], [`rdp::parse_confirm`]) and
//! request builders are public for callers that hold the bytes, e.g. from
//! a packet capture. Specifications:
//! [MS-SMB2](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/5606ad47-5ee0-437a-817e-70c366052962),
//! [MS-CIFS](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cifs/d416ff7c-c536-406e-a951-4f04b2fd1d2b),
//! [MS-RDPBCGR](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/5073f4ed-1e93-45e1-b039-6e30c385867c).
//!
//! Findings use check ids `<protocol>.<issue>` and carry a CWE:
//! `smb.signing_not_required` (345), `smb.no_encryption_dialect` (319),
//! `smb.smb1_enabled` (477), `rdp.nla_not_required` (306) and
//! `rdp.standard_security` (327).
//!
//! # Example
//!
//! ```
//! use rune_probe_ms::rdp::{Protocols, connection_request};
//! use rune_probe_ms::{RdpProbe, probe_set};
//! use rune_service_probe::{Options, Target, simulate};
//!
//! // An RDP server that accepts Standard RDP Security (RDP_NEG_RSP, PROTOCOL_RDP).
//! let confirm = [3, 0, 0, 19, 14, 0xd0, 0, 0, 0x12, 0x34, 0, 2, 0, 8, 0, 0, 0, 0, 0];
//! let target = Target::new("ts.internal", 3389);
//! let sim = simulate(&RdpProbe::new(), &target, &[&confirm], &Options::default())?;
//! assert_eq!(sim.sent, [connection_request(Protocols::RDP)]);
//! let info = sim.result?;
//! let ids: Vec<_> = info.findings.iter().map(|f| f.check_id.as_str()).collect();
//! assert_eq!(ids, ["rdp.nla_not_required", "rdp.standard_security"]);
//!
//! // Pick probes by port.
//! let probes = probe_set();
//! let ids: Vec<_> = probes.for_port(445).map(|p| p.id()).collect();
//! assert_eq!(ids, ["smb", "smb1"]);
//! # Ok::<(), rune_service_probe::Error>(())
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod error;
pub mod rdp;
pub mod smb;
mod wire;

pub use error::Error;
pub use rdp::RdpProbe;
pub use smb::{Smb1Probe, SmbProbe};

use rune_service_probe::{ProbeSet, ServiceProbe};

/// The probes of this crate, all read-only, as a [`ProbeSet`].
#[must_use]
pub fn probe_set() -> ProbeSet {
    let mut set = ProbeSet::new();
    set.push(SmbProbe::new())
        .push(Smb1Probe::new())
        .push(RdpProbe::new());
    set
}

/// The probes of this crate, boxed.
#[must_use]
pub fn all_probes() -> Vec<Box<dyn ServiceProbe>> {
    vec![
        Box::new(SmbProbe::new()),
        Box::new(Smb1Probe::new()),
        Box::new(RdpProbe::new()),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use rune_service_probe::Safety;

    #[test]
    fn probes_are_read_only() {
        assert!(all_probes().iter().all(|p| p.safety() == Safety::ReadOnly));
        assert_eq!(probe_set().len(), 3);
        assert_eq!(probe_set().for_port(139).count(), 1);
    }
}
