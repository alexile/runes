//! The parsers recover what the replies encode, and the parsers and probe
//! sessions never panic on arbitrary server bytes.

#![allow(clippy::unwrap_used, reason = "test code")]

mod common;

use proptest::prelude::*;
use rune_probe_ms::rdp::{self, Negotiation, Protocols};
use rune_probe_ms::smb::{self, Negotiate};
use rune_service_probe::{Options, Target, simulate};

proptest! {
    #[test]
    fn parsers_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..512)) {
        let _ = smb::parse_negotiate(&bytes);
        let _ = smb::split_message(&bytes);
        let _ = rdp::parse_confirm(&bytes);
    }

    #[test]
    fn smb2_fields_round_trip(
        dialect in any::<u16>(),
        mode in any::<u16>(),
        caps in any::<u32>(),
        guid in any::<[u8; 16]>(),
        blob in proptest::collection::vec(any::<u8>(), 0..64),
    ) {
        let reply = common::smb2_response(dialect, mode, caps, guid, &blob, &[]);
        let Ok(Negotiate::Smb2(neg)) = smb::parse_negotiate(&reply) else {
            return Err(TestCaseError::fail("not parsed"));
        };
        prop_assert_eq!(neg.dialect, dialect);
        prop_assert_eq!(neg.security_mode, mode);
        prop_assert_eq!(neg.capabilities, caps);
        prop_assert_eq!(neg.server_guid, guid);
        for cut in [0, 3, reply.len() / 2, reply.len() - 1] {
            prop_assert!(smb::parse_negotiate(&reply[..cut]).unwrap_err().is_truncated());
        }
    }

    #[test]
    fn rdp_confirm_round_trips(protocol in any::<u32>(), flags in any::<u8>()) {
        let reply = common::rdp_confirm(2, flags, protocol);
        prop_assert_eq!(
            rdp::parse_confirm(&reply).unwrap(),
            Negotiation::Selected { protocol: Protocols(protocol), flags }
        );
        prop_assert!(rdp::parse_confirm(&reply[..18]).unwrap_err().is_truncated());
    }

    #[test]
    fn sessions_survive_arbitrary_replies(
        replies in proptest::collection::vec(proptest::collection::vec(any::<u8>(), 0..128), 0..8),
        max_read in 1usize..1024,
    ) {
        let replies: Vec<&[u8]> = replies.iter().map(Vec::as_slice).collect();
        let options = Options::default().with_max_read_bytes(max_read);
        let target = Target::new("fuzz", 445);
        for probe in rune_probe_ms::all_probes() {
            let sim = simulate(probe.as_ref(), &target, &replies, &options).unwrap();
            prop_assert!(sim.sent.len() <= 1);
            if let Ok(info) = sim.result {
                prop_assert_eq!(info.service, probe.id());
                for value in info.details.values() {
                    prop_assert!(value.len() <= 4 * 256);
                }
            }
        }
    }
}
