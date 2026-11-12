//! Table-driven checks against the IANA special-purpose registries.
//!
//! Each row is transcribed from
//! <https://www.iana.org/assignments/iana-ipv4-special-registry/> and
//! <https://www.iana.org/assignments/iana-ipv6-special-registry/>:
//! block, source, destination, forwardable, globally reachable,
//! reserved-by-protocol (`None` = "N/A").

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "test helpers fail loudly on bad fixtures"
)]

use std::net::IpAddr;

use rune_ip::{Category, Registry, is_global, lookup, registry_v4, registry_v6};

const T: Option<bool> = Some(true);
const F: Option<bool> = Some(false);
const NA: Option<bool> = None;

type Row = (&'static str, [Option<bool>; 5]);

const IANA_V4: &[Row] = &[
    ("0.0.0.0/8", [T, F, F, F, T]),
    ("0.0.0.0/32", [T, F, F, F, T]),
    ("10.0.0.0/8", [T, T, T, F, F]),
    ("100.64.0.0/10", [T, T, T, F, F]),
    ("127.0.0.0/8", [F, F, F, F, T]),
    ("169.254.0.0/16", [T, T, F, F, T]),
    ("172.16.0.0/12", [T, T, T, F, F]),
    ("192.0.0.0/24", [F, F, F, F, F]),
    ("192.0.0.0/29", [T, T, T, F, F]),
    ("192.0.0.8/32", [T, F, F, F, F]),
    ("192.0.0.9/32", [T, T, T, T, F]),
    ("192.0.0.10/32", [T, T, T, T, F]),
    ("192.0.0.170/32", [F, F, F, F, T]),
    ("192.0.0.171/32", [F, F, F, F, T]),
    ("192.0.2.0/24", [F, F, F, F, F]),
    ("192.31.196.0/24", [T, T, T, T, F]),
    ("192.52.193.0/24", [T, T, T, T, F]),
    ("192.88.99.2/32", [T, T, T, F, F]),
    ("192.168.0.0/16", [T, T, T, F, F]),
    ("192.175.48.0/24", [T, T, T, T, F]),
    ("198.18.0.0/15", [T, T, T, F, F]),
    ("198.51.100.0/24", [F, F, F, F, F]),
    ("203.0.113.0/24", [F, F, F, F, F]),
    ("240.0.0.0/4", [F, F, F, F, T]),
    ("255.255.255.255/32", [F, T, F, F, T]),
];

const IANA_V6: &[Row] = &[
    ("::1/128", [F, F, F, F, T]),
    ("::/128", [T, F, F, F, T]),
    ("::ffff:0:0/96", [F, F, F, F, T]),
    ("64:ff9b::/96", [T, T, T, T, F]),
    ("64:ff9b:1::/48", [T, T, T, F, F]),
    ("100::/64", [T, T, T, F, F]),
    ("100:0:0:1::/64", [F, F, F, F, F]),
    ("2001::/23", [NA, NA, NA, F, F]),
    ("2001::/32", [T, T, T, NA, F]),
    ("2001:1::1/128", [T, T, T, T, F]),
    ("2001:1::2/128", [T, T, T, T, F]),
    ("2001:1::3/128", [T, T, T, T, F]),
    ("2001:2::/48", [T, T, T, F, F]),
    ("2001:3::/32", [T, T, T, T, F]),
    ("2001:4:112::/48", [T, T, T, T, F]),
    ("2001:20::/28", [T, T, T, T, F]),
    ("2001:30::/28", [T, T, T, T, F]),
    ("2001:db8::/32", [F, F, F, F, F]),
    ("2002::/16", [T, T, T, NA, F]),
    ("2620:4f:8000::/48", [T, T, T, T, F]),
    ("3fff::/20", [F, F, F, F, F]),
    ("5f00::/16", [T, T, T, F, F]),
    ("fc00::/7", [T, T, T, F, F]),
    ("fe80::/10", [T, T, F, F, T]),
];

fn parse(block: &str) -> (IpAddr, u8) {
    let (addr, len) = block.split_once('/').unwrap();
    (addr.parse().unwrap(), len.parse().unwrap())
}

fn check(rows: &[Row], table: &[rune_ip::SpecialRange]) {
    for &(block, [src, dst, fwd, glob, rsv]) in rows {
        let (net, len) = parse(block);
        let entry = table
            .iter()
            .find(|r| r.network() == net && r.prefix_len() == len)
            .unwrap_or_else(|| panic!("{block} missing from the table"));
        assert_eq!(entry.registry(), Registry::SpecialPurpose, "{block}");
        assert_eq!(entry.to_string(), format!("{net}/{len}"), "{block}");
        assert_eq!(
            [
                entry.source(),
                entry.destination(),
                entry.forwardable(),
                entry.globally_reachable(),
                entry.reserved_by_protocol(),
            ],
            [src, dst, fwd, glob, rsv],
            "{block} attributes"
        );
        assert!(entry.contains(net), "{block} contains its network");
        // The block's own network address resolves to it or to a more
        // specific block.
        let found = lookup(net).unwrap();
        assert!(found.prefix_len() >= len, "{block}: lookup gave {found}");
    }
}

#[test]
fn ipv4_special_registry() {
    check(IANA_V4, registry_v4());
}

#[test]
fn ipv6_special_registry() {
    check(IANA_V6, registry_v6());
}

#[test]
fn table_networks_are_aligned() {
    for r in registry_v4().iter().chain(registry_v6()) {
        let host_bits = match r.network() {
            IpAddr::V4(v4) => u128::from(u32::from(v4)) & (u128::from(u32::MAX) >> r.prefix_len()),
            IpAddr::V6(v6) => {
                u128::from(v6)
                    & (u128::MAX
                        .checked_shr(u32::from(r.prefix_len()))
                        .unwrap_or(0))
            }
        };
        assert_eq!(host_bits, 0, "{r} has host bits set");
    }
}

/// `(address, category, globally reachable)`: one or more addresses from
/// each block, including the edges and the more-specific exceptions.
const CASES: &[(&str, Category, bool)] = &[
    ("0.0.0.0", Category::Unspecified, false),
    ("0.255.255.255", Category::ThisNetwork, false),
    ("1.0.0.0", Category::Global, true),
    ("9.255.255.255", Category::Global, true),
    ("10.0.0.0", Category::Private, false),
    ("10.255.255.255", Category::Private, false),
    ("11.0.0.0", Category::Global, true),
    ("100.63.255.255", Category::Global, true),
    ("100.64.0.0", Category::Shared, false),
    ("100.127.255.255", Category::Shared, false),
    ("100.128.0.0", Category::Global, true),
    ("127.0.0.0", Category::Loopback, false),
    ("127.255.255.255", Category::Loopback, false),
    ("169.254.0.0", Category::LinkLocal, false),
    ("169.254.255.255", Category::LinkLocal, false),
    ("172.15.255.255", Category::Global, true),
    ("172.16.0.0", Category::Private, false),
    ("172.31.255.255", Category::Private, false),
    ("172.32.0.0", Category::Global, true),
    ("192.0.0.0", Category::ProtocolAssignment, false),
    ("192.0.0.7", Category::ProtocolAssignment, false),
    ("192.0.0.8", Category::ProtocolAssignment, false),
    ("192.0.0.9", Category::Anycast, true),
    ("192.0.0.10", Category::Anycast, true),
    ("192.0.0.11", Category::ProtocolAssignment, false),
    ("192.0.0.170", Category::ProtocolAssignment, false),
    ("192.0.0.255", Category::ProtocolAssignment, false),
    ("192.0.2.0", Category::Documentation, false),
    ("192.0.2.255", Category::Documentation, false),
    ("192.31.196.1", Category::Anycast, true),
    ("192.52.193.1", Category::Anycast, true),
    ("192.88.99.1", Category::Reserved, false),
    ("192.88.99.2", Category::ProtocolAssignment, false),
    ("192.168.0.0", Category::Private, false),
    ("192.168.255.255", Category::Private, false),
    ("192.175.48.1", Category::Anycast, true),
    ("198.17.255.255", Category::Global, true),
    ("198.18.0.0", Category::Benchmarking, false),
    ("198.19.255.255", Category::Benchmarking, false),
    ("198.20.0.0", Category::Global, true),
    ("198.51.100.1", Category::Documentation, false),
    ("203.0.113.1", Category::Documentation, false),
    ("223.255.255.255", Category::Global, true),
    ("224.0.0.0", Category::Multicast, false),
    ("239.255.255.255", Category::Multicast, false),
    ("240.0.0.0", Category::Reserved, false),
    ("255.255.255.254", Category::Reserved, false),
    ("255.255.255.255", Category::Broadcast, false),
    ("::", Category::Unspecified, false),
    ("::1", Category::Loopback, false),
    ("::2", Category::ThisNetwork, false), // ::0.0.0.2 -> 0.0.0.2
    ("::ffff:8.8.8.8", Category::Global, true),
    ("64:ff9b::1.1.1.1", Category::Translation, true),
    ("64:ff9b:1::1", Category::Translation, false),
    ("100::1", Category::Discard, false),
    ("100:0:0:1::1", Category::Discard, false),
    ("1fff:ffff::1", Category::Reserved, false),
    ("2000::1", Category::Global, true),
    ("2001::1", Category::Teredo, false),
    ("2001:1::1", Category::Anycast, true),
    ("2001:1::2", Category::Anycast, true),
    ("2001:1::3", Category::Anycast, true),
    ("2001:1::4", Category::ProtocolAssignment, false),
    ("2001:2::1", Category::Benchmarking, false),
    ("2001:3::1", Category::Anycast, true),
    ("2001:4:112::1", Category::Anycast, true),
    ("2001:10::1", Category::Reserved, false),
    ("2001:20::1", Category::Anycast, true),
    ("2001:30::1", Category::Anycast, true),
    ("2001:1ff::1", Category::ProtocolAssignment, false),
    ("2001:200::1", Category::Global, true),
    ("2001:db8::1", Category::Documentation, false),
    ("2002:808:808::1", Category::SixToFour, true),
    ("2620:4f:8000::1", Category::Anycast, true),
    ("3fff::1", Category::Documentation, false),
    ("3fff:1000::1", Category::Global, true),
    ("4000::1", Category::Reserved, false),
    ("5f00::1", Category::SegmentRouting, false),
    ("fc00::1", Category::UniqueLocal, false),
    ("fdff:ffff::1", Category::UniqueLocal, false),
    ("fe80::1", Category::LinkLocal, false),
    ("febf:ffff::1", Category::LinkLocal, false),
    ("fec0::1", Category::SiteLocal, false),
    ("ff00::1", Category::Multicast, false),
    ("ff0e::1", Category::Multicast, false),
];

#[test]
fn categories_and_reachability() {
    for &(s, cat, global) in CASES {
        let ip: IpAddr = s.parse().unwrap();
        assert_eq!(rune_ip::category(ip), cat, "category of {s}");
        assert_eq!(is_global(ip), global, "is_global({s})");
    }
}
