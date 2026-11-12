//! Properties: agreement with the stable `std::net` predicates, mapped-form
//! transparency, and internal consistency between the helpers.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use proptest::prelude::*;
use rune_ip::{
    Category, Scope, canonical, category, is_bogon, is_documentation, is_global, is_link_local,
    is_loopback, is_multicast, is_private, is_unspecified, scope,
};

fn any_v4() -> impl Strategy<Value = Ipv4Addr> {
    any::<u32>().prop_map(Ipv4Addr::from)
}

/// IPv6 addresses biased towards the interesting prefixes.
fn any_v6() -> impl Strategy<Value = Ipv6Addr> {
    let prefixes = prop_oneof![
        Just(0u16),
        Just(0x64),
        Just(0x100),
        Just(0x2001),
        Just(0x2002),
        Just(0x3fff),
        Just(0xfc00),
        Just(0xfd00),
        Just(0xfe80),
        Just(0xfec0),
        Just(0xff02),
        any::<u16>(),
    ];
    (prefixes, any::<u128>()).prop_map(|(p, rest)| {
        let bits = (u128::from(p) << 112) | (rest >> 16);
        Ipv6Addr::from(bits)
    })
}

proptest! {
    #[test]
    fn v4_agrees_with_std(v4 in any_v4()) {
        let ip = IpAddr::V4(v4);
        prop_assert_eq!(is_private(ip), v4.is_private());
        prop_assert_eq!(is_loopback(ip), v4.is_loopback());
        prop_assert_eq!(is_link_local(ip), v4.is_link_local());
        prop_assert_eq!(is_documentation(ip), v4.is_documentation());
        prop_assert_eq!(is_multicast(ip), v4.is_multicast());
        prop_assert_eq!(is_unspecified(ip), v4.is_unspecified());
    }

    #[test]
    fn mapped_v4_classifies_like_v4(v4 in any_v4()) {
        let plain = IpAddr::V4(v4);
        let mapped = IpAddr::V6(v4.to_ipv6_mapped());
        prop_assert_eq!(canonical(mapped), plain);
        prop_assert_eq!(category(mapped), category(plain));
        prop_assert_eq!(scope(mapped), scope(plain));
        prop_assert_eq!(is_global(mapped), is_global(plain));
        prop_assert_eq!(is_bogon(mapped), is_bogon(plain));
    }

    #[test]
    fn v6_agrees_with_std(v6 in any_v6()) {
        // std does not unwrap mapped/compatible forms; compare the rest.
        prop_assume!(canonical(v6).is_ipv6());
        let ip = IpAddr::V6(v6);
        prop_assert_eq!(is_loopback(ip), v6.is_loopback());
        prop_assert_eq!(is_unspecified(ip), v6.is_unspecified());
        prop_assert_eq!(is_multicast(ip), v6.is_multicast());
        prop_assert_eq!(is_link_local(ip), v6.is_unicast_link_local());
        prop_assert_eq!(category(ip) == Category::UniqueLocal, v6.is_unique_local());
    }

    #[test]
    fn helpers_are_consistent(v6 in any_v6(), v4 in any_v4()) {
        for ip in [IpAddr::V6(v6), IpAddr::V4(v4)] {
            let non_global = is_private(ip)
                || is_loopback(ip)
                || is_link_local(ip)
                || is_documentation(ip)
                || is_multicast(ip)
                || is_unspecified(ip);
            if non_global {
                prop_assert!(!is_global(ip), "{ip}");
            }
            prop_assert_eq!(is_global(ip), scope(ip) == Scope::Global && !is_multicast(ip), "{}", ip);
            prop_assert_eq!(canonical(canonical(ip)), canonical(ip));
        }
    }
}
