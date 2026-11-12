//! Round-trip and robustness properties for the SOCKS codecs.

#![allow(clippy::unwrap_used, reason = "test helpers fail loudly")]

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

use proptest::prelude::*;
use rune_socks::v4::{Socks4Command, Socks4Reply, Socks4Request};
use rune_socks::v5::{
    AuthMethod, Command, Credentials, Greeting, GssapiMessage, GssapiMessageType, Reply, ReplyCode,
    Request, UdpHeader,
};
use rune_socks::{Decoded, TargetAddr};

fn host() -> impl Strategy<Value = String> {
    "[a-z0-9.-]{1,60}"
}

fn target() -> impl Strategy<Value = TargetAddr> {
    prop_oneof![
        (any::<u32>(), any::<u16>()).prop_map(|(ip, port)| TargetAddr::Ip(
            SocketAddrV4::new(Ipv4Addr::from(ip), port).into()
        )),
        (any::<u128>(), any::<u16>()).prop_map(|(ip, port)| {
            TargetAddr::Ip(SocketAddrV6::new(Ipv6Addr::from(ip), port, 0, 0).into())
        }),
        (host(), any::<u16>()).prop_map(|(h, port)| TargetAddr::Domain(h, port)),
    ]
}

/// SOCKS4 targets: IPv4 outside 0.0.0.x, or host names.
fn socks4_target() -> impl Strategy<Value = TargetAddr> {
    prop_oneof![
        (256_u32.., any::<u16>()).prop_map(|(ip, port)| TargetAddr::Ip(
            SocketAddrV4::new(Ipv4Addr::from(ip), port).into()
        )),
        Just(TargetAddr::Ip(SocketAddr::from(([0, 0, 0, 0], 1)))),
        (host(), any::<u16>()).prop_map(|(h, port)| TargetAddr::Domain(h, port)),
    ]
}

/// Checks a complete decode and that every strict prefix is incomplete.
fn check<T: PartialEq + std::fmt::Debug>(
    wire: &[u8],
    value: &T,
    decode: impl Fn(&[u8]) -> Result<Decoded<T>, rune_socks::Error>,
) -> Result<(), TestCaseError> {
    let mut extended = wire.to_vec();
    extended.extend_from_slice(b"trailing");
    match decode(&extended).unwrap() {
        Decoded::Complete(back, len) => {
            prop_assert_eq!(&back, value);
            prop_assert_eq!(len, wire.len());
        }
        other => prop_assert!(false, "incomplete: {other:?}"),
    }
    for cut in 0..wire.len() {
        match decode(&wire[..cut]).unwrap() {
            Decoded::Incomplete(n) => prop_assert!(cut + n <= wire.len()),
            other => prop_assert!(false, "complete at {cut}: {other:?}"),
        }
    }
    Ok(())
}

proptest! {
    #[test]
    fn socks4_request_round_trips(
        target in socks4_target(),
        bind in any::<bool>(),
        user in "[ -~]{0,40}",
    ) {
        let command = if bind { Socks4Command::Bind } else { Socks4Command::Connect };
        let req = Socks4Request::connect(target).with_command(command).with_user_id(user);
        check(&req.encode().unwrap(), &req, Socks4Request::decode)?;
    }

    #[test]
    fn socks4_reply_round_trips(code in any::<u8>(), ip in any::<u32>(), port in any::<u16>()) {
        let reply = Socks4Reply::new(code.into(), SocketAddrV4::new(ip.into(), port));
        check(&reply.encode(), &reply, Socks4Reply::decode)?;
    }

    #[test]
    fn greeting_round_trips(methods in prop::collection::vec(any::<u8>(), 1..=255)) {
        let g = Greeting::new(methods.into_iter().map(AuthMethod::from).collect::<Vec<_>>());
        check(&g.encode().unwrap(), &g, Greeting::decode)?;
    }

    #[test]
    fn credentials_round_trip(
        user in prop::collection::vec(any::<u8>(), 0..=255),
        pass in prop::collection::vec(any::<u8>(), 0..=255),
    ) {
        let c = Credentials::new(user, pass);
        check(&c.encode().unwrap(), &c, Credentials::decode)?;
    }

    #[test]
    fn request_and_reply_round_trip(target in target(), cmd in 0_u8..3, code in any::<u8>()) {
        let command = [Command::Connect, Command::Bind, Command::UdpAssociate][usize::from(cmd)];
        let req = Request::new(command, target.clone());
        check(&req.encode().unwrap(), &req, Request::decode)?;
        let reply = Reply::new(ReplyCode::from(code), target);
        check(&reply.encode().unwrap(), &reply, Reply::decode)?;
    }

    #[test]
    fn udp_datagram_round_trips(target in target(), frag in any::<u8>(), payload in prop::collection::vec(any::<u8>(), 0..64)) {
        let mut header = UdpHeader::new(target);
        header.frag = frag;
        let datagram = header.encode_datagram(&payload).unwrap();
        let (back, rest) = UdpHeader::decode_datagram(&datagram).unwrap();
        prop_assert_eq!(back, header);
        prop_assert_eq!(rest, &payload[..]);
    }

    #[test]
    fn gssapi_round_trips(kind in any::<u8>(), token in prop::collection::vec(any::<u8>(), 0..300)) {
        let kind = GssapiMessageType::from(kind);
        let token = if kind == GssapiMessageType::Abort { Vec::new() } else { token };
        let m = GssapiMessage::new(kind, token);
        check(&m.encode().unwrap(), &m, GssapiMessage::decode)?;
    }

    #[test]
    fn decoders_never_panic(bytes in prop::collection::vec(any::<u8>(), 0..300)) {
        for result in [
            Socks4Request::decode(&bytes).map(|d| d.complete().map(|(_, n)| n)),
            Socks4Reply::decode(&bytes).map(|d| d.complete().map(|(_, n)| n)),
            Greeting::decode(&bytes).map(|d| d.complete().map(|(_, n)| n)),
            Credentials::decode(&bytes).map(|d| d.complete().map(|(_, n)| n)),
            Request::decode(&bytes).map(|d| d.complete().map(|(_, n)| n)),
            Reply::decode(&bytes).map(|d| d.complete().map(|(_, n)| n)),
            GssapiMessage::decode(&bytes).map(|d| d.complete().map(|(_, n)| n)),
            TargetAddr::decode(&bytes).map(|d| d.complete().map(|(_, n)| n)),
        ] {
            if let Ok(Some(n)) = result {
                prop_assert!(n <= bytes.len());
            }
        }
        let _ = UdpHeader::decode_datagram(&bytes);
    }
}
