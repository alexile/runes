//! Property tests: longest-prefix match agrees with a linear scan, range
//! decomposition covers exactly its range, and no parser panics.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use proptest::prelude::*;
use rune_asn::{
    Asn, AsnDb, Route, parse_asnames, parse_bgpdump, parse_delegated, parse_ip2asn, parse_pfx2as,
    parse_riswhois,
};
use rune_cidr::Cidr;

/// Prefixes clustered in `10.0.0.0/8` and `2001:db8::/32` so they nest often.
fn prefix() -> impl Strategy<Value = Cidr> {
    prop_oneof![
        (0u32..=0xFFFF, 8u8..=32)
            .prop_map(|(low, len)| Cidr::V4(0x0A00_0000 | (low << 8), len).trunc()),
        (any::<u16>(), 32u8..=64).prop_map(|(x, len)| {
            Cidr::V6((0x2001_0db8_u128 << 96) | (u128::from(x) << 72), len).trunc()
        }),
    ]
}

fn addr() -> impl Strategy<Value = IpAddr> {
    prop_oneof![
        (0u32..=0x00FF_FFFF).prop_map(|x| IpAddr::V4(Ipv4Addr::from(0x0A00_0000 | x))),
        (any::<u16>(), any::<u64>()).prop_map(|(x, low)| IpAddr::V6(Ipv6Addr::from(
            (0x2001_0db8_u128 << 96) | (u128::from(x) << 72) | u128::from(low)
        ))),
    ]
}

proptest! {
    #[test]
    fn lookup_matches_a_linear_scan(
        routes in prop::collection::vec((prefix(), 1u32..100), 0..40),
        ips in prop::collection::vec(addr(), 1..20),
    ) {
        let db: AsnDb = routes
            .iter()
            .map(|&(p, a)| Route::new(p, [Asn::new(a)]))
            .collect();
        for ip in ips {
            let best = routes
                .iter()
                .filter(|(p, _)| p.contains(ip))
                .map(|(p, _)| *p)
                .max_by_key(Cidr::prefix_len);
            let hit = db.lookup(ip);
            prop_assert_eq!(hit.map(|m| m.prefix), best);
            if let Some(hit) = hit {
                let mut want: Vec<Asn> = routes
                    .iter()
                    .filter(|(p, _)| *p == hit.prefix)
                    .map(|&(_, a)| Asn::new(a))
                    .collect();
                want.sort_unstable();
                want.dedup();
                prop_assert_eq!(hit.origins, want.as_slice());
                for &origin in hit.origins {
                    prop_assert!(db.prefixes(origin).any(|p| p == hit.prefix));
                }
            }
            let all: Vec<Cidr> = db.lookup_all(ip).map(|m| m.prefix).collect();
            prop_assert!(all.windows(2).all(|w| w[0].prefix_len() < w[1].prefix_len()));
            prop_assert_eq!(all.last().copied(), best);
        }
    }

    #[test]
    fn ip2asn_ranges_become_exact_cidr_covers(a in any::<u32>(), b in any::<u32>()) {
        let (lo, hi) = (a.min(b), a.max(b));
        let line = format!("{}\t{}\t1\tUS\tX", Ipv4Addr::from(lo), Ipv4Addr::from(hi));
        let rec = parse_ip2asn(&line).next().unwrap().unwrap();
        let cidrs = rec.cidrs();
        prop_assert!(cidrs.len() <= 62);
        let mut next = u64::from(lo);
        for c in &cidrs {
            let Cidr::V4(net, len) = *c else { panic!("family changed") };
            prop_assert_eq!(u64::from(net), next);
            next += 1u64 << (32 - len);
        }
        prop_assert_eq!(next, u64::from(hi) + 1);
    }

    #[test]
    fn parsers_never_panic(text in "\\PC{0,200}") {
        let _ = parse_pfx2as(&text).count();
        let _ = parse_riswhois(&text).count();
        let _ = parse_bgpdump(&text).count();
        parse_ip2asn(&text).flatten().for_each(|r| drop(r.cidrs()));
        parse_delegated(&text).flatten().for_each(|r| drop(r.cidrs()));
        let _ = parse_asnames(&text).count();
        let _ = text.parse::<Asn>();
    }

    #[test]
    fn asn_display_round_trips(n in any::<u32>()) {
        let asn = Asn::new(n);
        prop_assert_eq!(asn.to_string().parse::<Asn>(), Ok(asn));
        prop_assert_eq!(n.to_string().parse::<Asn>(), Ok(asn));
        prop_assert_eq!(format!("{}.{}", n >> 16, n & 0xFFFF).parse::<Asn>(), Ok(asn));
    }
}
