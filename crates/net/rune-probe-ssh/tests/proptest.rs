//! Round trips for the wire codecs, and no panics on arbitrary input.

#![allow(
    clippy::field_reassign_with_default,
    reason = "KexInit is non_exhaustive: other crates build it from Default"
)]
// Test helpers outside `#[test]` functions may unwrap too.
#![allow(clippy::unwrap_used, reason = "test code")]

use proptest::prelude::*;
use rune_probe_ssh::{
    HostKey, Identification, KexInit, SshProbe, encode_packet, parse_kex_reply_host_key,
    parse_packet,
};
use rune_service_probe::{Options, Target, simulate};

fn name_list() -> impl Strategy<Value = Vec<String>> {
    prop::collection::vec("[a-z0-9@.+=-]{1,24}", 0..8)
}

prop_compose! {
    fn kexinit()(
        cookie in any::<[u8; 16]>(),
        lists in prop::collection::vec(name_list(), 10),
        follows in any::<bool>(),
        reserved in any::<u32>(),
    ) -> KexInit {
        let mut k = KexInit::default();
        k.cookie = cookie;
        let mut lists = lists.into_iter();
        let mut next = || lists.next().unwrap_or_default();
        k.kex_algorithms = next();
        k.server_host_key_algorithms = next();
        k.encryption_client_to_server = next();
        k.encryption_server_to_client = next();
        k.mac_client_to_server = next();
        k.mac_server_to_client = next();
        k.compression_client_to_server = next();
        k.compression_server_to_client = next();
        k.languages_client_to_server = next();
        k.languages_server_to_client = next();
        k.first_kex_packet_follows = follows;
        k.reserved = reserved;
        k
    }
}

proptest! {
    #[test]
    fn kexinit_round_trip(k in kexinit()) {
        prop_assert_eq!(KexInit::parse(&k.encode()).unwrap(), k);
    }

    #[test]
    fn packet_round_trip(payload in prop::collection::vec(any::<u8>(), 1..2048)) {
        let packet = encode_packet(&payload);
        prop_assert_eq!(packet.len() % 8, 0);
        let (got, used) = parse_packet(&packet).unwrap().unwrap();
        prop_assert_eq!(got, &payload[..]);
        prop_assert_eq!(used, packet.len());
    }

    #[test]
    fn identification_round_trip(
        proto in "[0-9][0-9.]{0,4}",
        software in "[!-,.-~]{1,40}",
        comments in proptest::option::of("[ -~]{1,40}"),
    ) {
        let mut line = format!("SSH-{proto}-{software}");
        if let Some(c) = &comments {
            line.push(' ');
            line.push_str(c);
        }
        let id = Identification::parse(line.as_bytes()).unwrap();
        prop_assert_eq!(&id.proto_version, &proto);
        prop_assert_eq!(id.to_string().len() <= line.len(), true);
        let again = Identification::parse(id.to_string().as_bytes()).unwrap();
        prop_assert_eq!(again, id);
    }

    #[test]
    fn parsers_never_panic(data in prop::collection::vec(any::<u8>(), 0..512)) {
        let _ = Identification::parse(&data);
        let _ = parse_packet(&data);
        let _ = KexInit::parse(&data);
        let _ = HostKey::parse(&data);
        let _ = parse_kex_reply_host_key(&data);
    }

    #[test]
    fn probe_never_panics(
        prefix in prop::sample::select(vec![&b""[..], b"SSH-2.0-x\r\n", b"SSH-1.99-y\n"]),
        replies in prop::collection::vec(prop::collection::vec(any::<u8>(), 0..256), 0..8),
    ) {
        let mut replies = replies;
        if let Some(first) = replies.first_mut() {
            first.splice(0..0, prefix.iter().copied());
        }
        let refs: Vec<&[u8]> = replies.iter().map(Vec::as_slice).collect();
        let sim = simulate(&SshProbe::new(), &Target::new("fuzz", 22), &refs, &Options::default()).unwrap();
        if let Ok(info) = sim.result {
            let banner = info.banner.unwrap_or_default();
            prop_assert!(banner.bytes().all(|b| (0x20..=0x7e).contains(&b)));
        }
        prop_assert!(sim.sent.len() <= 2);
    }
}
