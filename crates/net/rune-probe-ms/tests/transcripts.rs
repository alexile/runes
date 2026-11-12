//! The probes against scripted server transcripts, in memory.

#![allow(clippy::unwrap_used, clippy::panic, reason = "test code")]

mod common;

use common::{WINDOWS_SPNEGO, netbios, smb1_response, smb2_response, windows_2022};
use rune_probe_ms::smb::{self, Dialect, Negotiate, Signing};
use rune_probe_ms::{Smb1Probe, SmbProbe};
use rune_service_probe::rune_finding::Severity;
use rune_service_probe::{End, Error, Options, ServiceInfo, Target, simulate};

fn target() -> Target {
    Target::new("fs01.corp.example", 445)
}

fn ids(info: &ServiceInfo) -> Vec<&str> {
    info.findings.iter().map(|f| f.check_id.as_str()).collect()
}

#[test]
fn request_is_well_formed() {
    let req = smb::negotiate_request();
    let (msg, used) = smb::split_message(&req).unwrap();
    assert_eq!(used, req.len());
    assert_eq!(&msg[..4], b"\xfeSMB");
    // DialectCount 5, SecurityMode signing enabled.
    assert_eq!(&msg[66..70], &[5, 0, 1, 0]);
    let ctx_offset = u32::from_le_bytes(msg[92..96].try_into().unwrap()) as usize;
    assert_eq!(ctx_offset % 8, 0);
    assert_eq!(&msg[96..98], &[3, 0]); // three contexts
    let dialects: Vec<u16> = msg[100..110]
        .chunks(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    assert_eq!(dialects, [0x0202, 0x0210, 0x0300, 0x0302, 0x0311]);
    assert_eq!(&msg[ctx_offset..ctx_offset + 2], &[1, 0]); // preauth first
}

#[test]
fn windows_server_2022_signing_not_required() {
    let reply = windows_2022(0x0001);
    let sim = simulate(
        &SmbProbe::new(),
        &target(),
        &[&reply[..3], &reply[3..100], &reply[100..]],
        &Options::default(),
    )
    .unwrap();
    assert_eq!(sim.sent, [smb::negotiate_request()]);
    assert_eq!(sim.end, End::Done);
    let info = sim.result.unwrap();
    assert_eq!(info.service, "smb");
    assert_eq!(info.details["smb.dialect"], "3.1.1");
    assert_eq!(info.details["smb.signing"], "enabled");
    assert_eq!(
        info.details["smb.server_guid"],
        "76543210-ba98-fedc-0123-456789abcdef"
    );
    assert_eq!(info.details["smb.cipher"], "AES-128-GCM");
    assert_eq!(info.details["smb.signing_algorithm"], "AES-GMAC");
    assert_eq!(info.details["smb.system_time"], "1794441600");
    assert!(!info.details.contains_key("smb.start_time"));
    for cap in [
        "dialect:3.1.1",
        "cap:dfs",
        "cap:leasing",
        "auth:kerberos",
        "auth:negoex",
        "auth:ntlmssp",
    ] {
        assert!(info.capabilities.iter().any(|c| c == cap), "{cap}");
    }
    assert_eq!(ids(&info), ["smb.signing_not_required"]);
    assert_eq!(info.findings[0].severity, Severity::Medium);
}

#[test]
fn domain_controller_requires_signing() {
    let info = simulate(
        &SmbProbe::new(),
        &target(),
        &[&windows_2022(0x0003)],
        &Options::default(),
    )
    .unwrap()
    .result
    .unwrap();
    assert_eq!(info.details["smb.signing"], "required");
    assert_eq!(info.findings.len(), 0);
}

#[test]
fn old_samba_on_smb_2_1() {
    let reply = smb2_response(0x0210, 0x0001, 0x05, [7; 16], &[], &[]);
    let Negotiate::Smb2(neg) = smb::parse_negotiate(&reply).unwrap() else {
        panic!("not smb2");
    };
    assert_eq!(neg.dialect(), Dialect::SMB_2_1);
    assert_eq!(neg.signing(), Signing::Enabled);
    assert_eq!(neg.mechanisms.len(), 0);
    let info = simulate(&SmbProbe::new(), &target(), &[&reply], &Options::default())
        .unwrap()
        .result
        .unwrap();
    assert_eq!(
        ids(&info),
        ["smb.signing_not_required", "smb.no_encryption_dialect"]
    );
}

#[test]
fn smb1_enabled_without_extended_security() {
    let sim = simulate(
        &Smb1Probe::new(),
        &target(),
        &[&smb1_response(0x03, false)],
        &Options::default(),
    )
    .unwrap();
    assert_eq!(sim.sent, [smb::smb1_negotiate_request()]);
    let info = sim.result.unwrap();
    assert_eq!(info.service, "smb1");
    assert_eq!(info.details["smb.smb1"], "enabled");
    assert_eq!(info.details["smb.domain"], "WORKGROUP");
    assert_eq!(info.details["smb.server_name"], "FILESRV");
    assert_eq!(info.details["smb.signing"], "disabled");
    assert_eq!(ids(&info), ["smb.smb1_enabled", "smb.signing_not_required"]);
}

#[test]
fn smb1_enabled_with_extended_security_and_signing() {
    let reply = smb1_response(0x0f, true);
    let Negotiate::Smb1(neg) = smb::parse_negotiate(&reply).unwrap() else {
        panic!("not smb1");
    };
    assert!(neg.accepted());
    assert_eq!(neg.signing(), Signing::Required);
    assert_eq!(neg.server_guid, Some(*b"0123456789abcdef"));
    assert_eq!(neg.mechanisms, ["kerberos", "negoex", "ntlmssp"]);
    let info = simulate(&Smb1Probe::new(), &target(), &[&reply], &Options::default())
        .unwrap()
        .result
        .unwrap();
    assert_eq!(ids(&info), ["smb.smb1_enabled"]);
    assert!(info.capabilities.iter().any(|c| c == "auth:ntlmssp"));
}

#[test]
fn smb1_refused_three_ways() {
    // No common dialect.
    let mut m = b"\xffSMB\x72".to_vec();
    m.extend_from_slice(&[0; 4]);
    m.extend_from_slice(&[0x98, 0x53, 0xc8]);
    m.extend_from_slice(&[0; 20]);
    m.extend_from_slice(&[1, 0xff, 0xff, 0, 0]);
    let info = simulate(
        &Smb1Probe::new(),
        &target(),
        &[&netbios(&m)],
        &Options::default(),
    )
    .unwrap()
    .result
    .unwrap();
    assert_eq!(info.details["smb.smb1"], "not_accepted");
    assert_eq!(info.findings.len(), 0);
    // An error status (STATUS_NOT_SUPPORTED).
    m[5..9].copy_from_slice(&0xc000_00bbu32.to_le_bytes());
    let info = simulate(
        &Smb1Probe::new(),
        &target(),
        &[&netbios(&m)],
        &Options::default(),
    )
    .unwrap()
    .result
    .unwrap();
    assert_eq!(info.details["smb.smb1"], "refused");
    assert_eq!(info.details["smb.negotiate_status"], "0xc00000bb");
    // A reset: no bytes at all.
    let sim = simulate(&Smb1Probe::new(), &target(), &[], &Options::default()).unwrap();
    assert!(matches!(sim.result, Err(Error::NoResponse { .. })));
}

#[test]
fn smb2_error_status() {
    let mut reply = smb2_response(0, 0, 0, [0; 16], &[], &[]);
    reply[12..16].copy_from_slice(&0xc000_00bbu32.to_le_bytes());
    assert_eq!(
        smb::parse_negotiate(&reply).unwrap(),
        Negotiate::Status {
            smb1: false,
            status: 0xc000_00bb
        }
    );
}

#[test]
fn rejects_other_protocols_and_bad_offsets() {
    let http = simulate(
        &SmbProbe::new(),
        &target(),
        &[b"HTTP/1.1 400 Bad Request\r\n\r\n"],
        &Options::default(),
    )
    .unwrap();
    assert!(matches!(http.result, Err(Error::Unrecognized { .. })));
    // NetBIOS negative session response.
    assert!(smb::parse_negotiate(&[0x83, 0, 0, 1, 0x8f]).is_err_and(|e| !e.is_truncated()));
    // Security buffer pointing past the message.
    let mut reply = smb2_response(0x0302, 1, 0, [0; 16], &WINDOWS_SPNEGO, &[]);
    reply[4 + 64 + 56..4 + 64 + 58].copy_from_slice(&0xfff0u16.to_le_bytes());
    assert!(smb::parse_negotiate(&reply).is_err_and(|e| !e.is_truncated()));
    // Incomplete NetBIOS message.
    let full = windows_2022(1);
    assert!(
        smb::parse_negotiate(&full[..full.len() - 1])
            .unwrap_err()
            .is_truncated()
    );
}
