//! Round-trip and robustness properties for the v1 and v2 codecs.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};

use proptest::prelude::*;
use rune_proxy_protocol::{
    Addresses, Command, Error, Header, Tlv, Transport, Version, decode, tlv,
};

fn ip_addresses() -> impl Strategy<Value = Addresses> {
    prop_oneof![
        (any::<u32>(), any::<u16>(), any::<u32>(), any::<u16>()).prop_map(|(s, sp, d, dp)| {
            Addresses::Ipv4 {
                source: SocketAddrV4::new(Ipv4Addr::from(s), sp),
                destination: SocketAddrV4::new(Ipv4Addr::from(d), dp),
            }
        }),
        (any::<u128>(), any::<u16>(), any::<u128>(), any::<u16>()).prop_map(|(s, sp, d, dp)| {
            Addresses::Ipv6 {
                source: SocketAddrV6::new(Ipv6Addr::from(s), sp, 0, 0),
                destination: SocketAddrV6::new(Ipv6Addr::from(d), dp, 0, 0),
            }
        }),
    ]
}

/// UNIX paths as decoded: no trailing NUL.
fn unix_path() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 0..=108).prop_map(|mut p| {
        while p.last() == Some(&0) {
            p.pop();
        }
        p
    })
}

fn addresses() -> impl Strategy<Value = Addresses> {
    prop_oneof![
        Just(Addresses::Unspecified),
        ip_addresses(),
        (unix_path(), unix_path()).prop_map(|(source, destination)| Addresses::Unix {
            source,
            destination
        }),
    ]
}

fn transport() -> impl Strategy<Value = Transport> {
    prop_oneof![
        Just(Transport::Unspecified),
        Just(Transport::Stream),
        Just(Transport::Datagram)
    ]
}

fn tlvs() -> impl Strategy<Value = Vec<Tlv>> {
    prop::collection::vec(
        // Skip CRC32C: it is covered by `crc_round_trips`.
        (
            any::<u8>().prop_filter("not crc", |k| *k != tlv::PP2_TYPE_CRC32C),
            prop::collection::vec(any::<u8>(), 0..64),
        )
            .prop_map(|(k, v)| Tlv::new(k, v)),
        0..6,
    )
}

fn v2_header() -> impl Strategy<Value = Header> {
    (any::<bool>(), transport(), addresses(), tlvs()).prop_map(
        |(local, transport, addresses, tlvs)| {
            let command = if local {
                Command::Local
            } else {
                Command::Proxy
            };
            let mut header = Header::new(command, transport, addresses);
            for tlv in tlvs {
                header = header.with_tlv(tlv);
            }
            header
        },
    )
}

proptest! {
    #[test]
    fn v2_round_trips(header in v2_header(), trailer in prop::collection::vec(any::<u8>(), 0..16)) {
        let mut bytes = header.encode_v2().unwrap();
        let len = bytes.len();
        bytes.extend_from_slice(&trailer);
        let parsed = decode(&bytes).unwrap().unwrap();
        prop_assert_eq!(parsed.version, Version::V2);
        prop_assert_eq!(parsed.len, len);
        prop_assert_eq!(parsed.header, header);
    }

    #[test]
    fn crc_round_trips(addresses in ip_addresses(), tlvs in tlvs(), flip in any::<prop::sample::Index>()) {
        let mut header = Header::new(Command::Proxy, Transport::Stream, addresses);
        for tlv in tlvs {
            header = header.with_tlv(tlv);
        }
        let header = header.with_crc32c();
        let mut bytes = header.encode_v2().unwrap();
        let parsed = decode(&bytes).unwrap().unwrap();
        prop_assert_eq!(parsed.header.encode_v2().unwrap(), bytes.clone());
        // Corrupting an address byte is caught by the checksum. (A flipped
        // TLV type byte can hide the CRC TLV itself, so only the address
        // block is mutated here.)
        let addr_len = if bytes[13] >> 4 == 1 { 12 } else { 36 };
        let at = 16 + flip.index(addr_len);
        bytes[at] ^= 0x80;
        let is_mismatch = matches!(decode(&bytes), Err(Error::ChecksumMismatch { .. }));
        prop_assert!(is_mismatch);
    }

    #[test]
    fn v1_round_trips(addresses in ip_addresses(), trailer in prop::collection::vec(any::<u8>(), 0..16)) {
        let header = Header::new(Command::Proxy, Transport::Stream, addresses);
        let text = header.encode_v1().unwrap();
        prop_assert!(text.len() <= rune_proxy_protocol::v1::MAX_LEN);
        let mut bytes = text.clone().into_bytes();
        bytes.extend_from_slice(&trailer);
        let parsed = decode(&bytes).unwrap().unwrap();
        prop_assert_eq!(parsed.version, Version::V1);
        prop_assert_eq!(parsed.len, text.len());
        // Canonical: the decoded header re-encodes to the same line.
        prop_assert_eq!(parsed.header.encode_v1().unwrap(), text);
        prop_assert_eq!(parsed.header, header);
    }

    #[test]
    fn decoder_never_panics(bytes in prop::collection::vec(any::<u8>(), 0..300)) {
        if let Ok(Some(parsed)) = decode(&bytes) {
            prop_assert!(parsed.len <= bytes.len());
        }
    }

    #[test]
    fn decoder_never_panics_on_v2_prefix(rest in prop::collection::vec(any::<u8>(), 0..300)) {
        let mut bytes = rune_proxy_protocol::v2::SIGNATURE.to_vec();
        bytes.extend_from_slice(&rest);
        if let Ok(Some(parsed)) = decode(&bytes) {
            prop_assert!(parsed.len <= bytes.len());
            let again = parsed.header.encode_v2().unwrap();
            prop_assert_eq!(decode(&again).unwrap().unwrap().header, parsed.header);
        }
    }

    #[test]
    fn decoder_never_panics_on_v1_text(rest in "\\PC{0,120}") {
        let text = format!("PROXY {rest}\r\n");
        if let Ok(Some(parsed)) = decode(text.as_bytes()) {
            prop_assert!(parsed.len <= text.len());
        }
    }
}
