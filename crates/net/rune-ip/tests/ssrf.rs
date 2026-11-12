//! SSRF-guard behaviour: private, loopback, link-local and the other
//! non-public ranges are rejected for both families, including when wrapped
//! in IPv4-mapped, IPv4-compatible, NAT64 or 6to4 IPv6 addresses.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "test helpers fail loudly on bad fixtures"
)]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use rune_ip::{is_global, is_link_local, is_loopback, is_private};

/// The guard under test: only globally reachable unicast passes.
fn allowed(ip: IpAddr) -> bool {
    is_global(ip)
}

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

/// IPv4 addresses an SSRF guard must refuse.
const BAD_V4: &[&str] = &[
    "0.0.0.0",
    "0.1.2.3",
    "10.0.0.1",
    "10.255.255.255",
    "100.64.0.1",
    "100.127.255.255",
    "127.0.0.1",
    "127.1.2.3",
    "169.254.169.254",
    "169.254.0.1",
    "172.16.0.1",
    "172.31.255.255",
    "192.0.0.1",
    "192.0.0.170",
    "192.0.2.1",
    "192.88.99.1",
    "192.168.1.1",
    "198.18.0.1",
    "198.19.255.255",
    "198.51.100.1",
    "203.0.113.1",
    "224.0.0.1",
    "239.255.255.250",
    "240.0.0.1",
    "255.255.255.255",
];

/// IPv6 addresses an SSRF guard must refuse.
const BAD_V6: &[&str] = &[
    "::",
    "::1",
    "fe80::1",
    "febf:ffff::1",
    "fc00::1",
    "fd00:ec2::254",
    "fec0::1",
    "ff02::1",
    "ff0e::1",
    "2001:db8::1",
    "3fff::1",
    "100::1",
    "2001:2::1",
    "2001::1",
    "64:ff9b:1::1",
    "5f00::1",
    "4000::1",
];

const GOOD: &[&str] = &[
    "1.1.1.1",
    "8.8.8.8",
    "93.184.216.34",
    "100.63.255.255",
    "100.128.0.0",
    "172.15.255.255",
    "172.32.0.0",
    "192.0.0.9",
    "192.0.0.10",
    "192.169.0.1",
    "2001:4860:4860::8888",
    "2606:4700::1111",
    "2001:1::1",
    "64:ff9b::808:808",
    "2002:0808:0808::1",
];

#[test]
fn rejects_non_public_v4() {
    for s in BAD_V4 {
        assert!(!allowed(ip(s)), "{s} must be rejected");
    }
}

#[test]
fn rejects_non_public_v6() {
    for s in BAD_V6 {
        assert!(!allowed(ip(s)), "{s} must be rejected");
    }
}

#[test]
fn allows_public() {
    for s in GOOD {
        assert!(allowed(ip(s)), "{s} must be allowed");
    }
}

#[test]
fn rejects_every_wrapped_v4_form() {
    for s in BAD_V4 {
        let v4: Ipv4Addr = s.parse().unwrap();
        let o = v4.octets();
        let hi = u16::from_be_bytes([o[0], o[1]]);
        let lo = u16::from_be_bytes([o[2], o[3]]);
        let wrapped = [
            v4.to_ipv6_mapped(),
            Ipv6Addr::new(0, 0, 0, 0, 0, 0, hi, lo),
            Ipv6Addr::new(0x64, 0xff9b, 0, 0, 0, 0, hi, lo),
            Ipv6Addr::new(0x2002, hi, lo, 0, 0, 0, 0, 1),
        ];
        for w in wrapped {
            assert!(
                !allowed(IpAddr::V6(w)),
                "{w} (wrapping {s}) must be rejected"
            );
        }
    }
}

#[test]
fn wrapped_public_v4_stays_public() {
    for s in GOOD.iter().filter(|s| !s.contains(':')) {
        let v4: Ipv4Addr = s.parse().unwrap();
        assert!(allowed(IpAddr::V6(v4.to_ipv6_mapped())), "::ffff:{s}");
    }
}

#[test]
fn named_helpers_see_through_mapping() {
    assert!(is_loopback(ip("::ffff:127.0.0.1")));
    assert!(is_loopback(ip("::127.0.0.1")));
    assert!(is_link_local(ip("::ffff:169.254.169.254")));
    assert!(is_private(ip("::ffff:10.0.0.1")));
    assert!(is_private(ip("::ffff:192.168.0.1")));
}
