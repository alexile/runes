//! Property tests: target round-trips, parser robustness, and the
//! default-deny / SSRF invariants of the policy.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use proptest::prelude::*;
use rune_egress_proxy::{
    DEFAULT_MAX_HEAD_LEN, Decision, Denial, Host, Hostname, Policy, Target, parse_request,
};

fn label() -> impl Strategy<Value = String> {
    "[a-z0-9_-]{1,8}".prop_filter("not all digits", |l| !l.bytes().all(|b| b.is_ascii_digit()))
}

fn hostname() -> impl Strategy<Value = Hostname> {
    prop::collection::vec(label(), 1..4)
        .prop_filter_map("valid", |labels| Hostname::parse(&labels.join(".")).ok())
}

fn ip() -> impl Strategy<Value = IpAddr> {
    prop_oneof![
        any::<u32>().prop_map(|v| IpAddr::V4(Ipv4Addr::from(v))),
        any::<u128>().prop_map(|v| IpAddr::V6(Ipv6Addr::from(v))),
    ]
}

fn target() -> impl Strategy<Value = Target> {
    let host = prop_oneof![hostname().prop_map(Host::Name), ip().prop_map(Host::Ip)];
    (host, 1..=u16::MAX).prop_map(|(host, port)| Target::new(host, port))
}

proptest! {
    #[test]
    fn target_display_round_trips(t in target()) {
        prop_assert_eq!(t.to_string().parse::<Target>(), Ok(t));
    }

    #[test]
    fn request_head_round_trips(t in target(), tail in prop::collection::vec(any::<u8>(), 0..32)) {
        let mut buf = format!("CONNECT {t} HTTP/1.1\r\nHost: {t}\r\n\r\n").into_bytes();
        let head_len = buf.len();
        buf.extend_from_slice(&tail);
        let req = parse_request(&buf, DEFAULT_MAX_HEAD_LEN).unwrap().unwrap();
        prop_assert_eq!(req.target, t);
        prop_assert_eq!(req.head_len, head_len);
        // Every strict prefix of the head is incomplete, not an error.
        for cut in 0..head_len - 1 {
            prop_assert_eq!(parse_request(&buf[..cut], DEFAULT_MAX_HEAD_LEN), Ok(None));
        }
    }

    #[test]
    fn parser_never_panics(data in prop::collection::vec(any::<u8>(), 0..512), max in 0usize..600) {
        if let Ok(Some(req)) = parse_request(&data, max) {
            prop_assert!(req.head_len <= data.len() && req.head_len <= max);
        }
    }

    #[test]
    fn target_parser_never_panics(s in "\\PC{0,64}") {
        let _ = s.parse::<Target>();
    }

    #[test]
    fn empty_policy_denies_everything(t in target()) {
        prop_assert!(matches!(Policy::new().decide(&t), Decision::Deny(_)));
    }

    #[test]
    fn ip_literals_need_an_allowlist_entry(addr in ip(), port in 1..=u16::MAX) {
        let policy = Policy::new().allow_host("*.example.com").unwrap();
        prop_assert_eq!(
            policy.decide(&Target::new(Host::Ip(addr), port)),
            Decision::Deny(Denial::IpNotAllowed)
        );
    }

    /// Without an IP allowlist, pinning only ever returns a global address.
    #[test]
    fn pin_never_returns_a_non_global_address(addrs in prop::collection::vec(ip(), 0..8)) {
        let candidates = addrs.iter().map(|&ip| SocketAddr::new(ip, 443));
        match Policy::new().pin(candidates) {
            Ok(addr) => prop_assert!(rune_ip::is_global(addr.ip())),
            Err(denial) => {
                prop_assert_eq!(denial, Denial::NoAllowedAddress);
                prop_assert!(!addrs.iter().any(|&ip| rune_ip::is_global(ip)));
            }
        }
    }
}
