//! Property tests: lookups agree with a linear scan over the loaded ranges,
//! and no parser panics on arbitrary text.

use std::net::{IpAddr, Ipv4Addr};

use proptest::prelude::*;
use rune_cidr::Cidr;
use rune_cloud_ranges::{
    CloudRanges, Provider, Range, parse_aws, parse_azure, parse_cidr_list, parse_digitalocean,
    parse_fastly, parse_google, parse_oracle,
};

fn provider() -> impl Strategy<Value = Provider> {
    prop_oneof![
        Just(Provider::Aws),
        Just(Provider::Cloudflare),
        Just(Provider::Fastly),
        Just(Provider::Google),
    ]
}

/// Ranges inside `10.0.0.0/8`, so they nest often.
fn range() -> impl Strategy<Value = Range> {
    (0u32..=0xFFFF, 8u8..=28, provider(), any::<bool>()).prop_map(|(low, len, p, cdn)| {
        Range::new(Cidr::V4(0x0A00_0000 | (low << 8), len), p).with_cdn(cdn)
    })
}

proptest! {
    #[test]
    fn lookups_match_a_linear_scan(
        ranges in prop::collection::vec(range(), 0..30),
        addrs in prop::collection::vec(0u32..=0x00FF_FFFF, 1..20),
    ) {
        let table: CloudRanges = ranges.iter().cloned().collect();
        for low in addrs {
            let ip = IpAddr::V4(Ipv4Addr::from(0x0A00_0000 | low));
            let covering: Vec<&Range> = ranges.iter().filter(|r| r.prefix.contains(ip)).collect();
            prop_assert_eq!(table.contains(ip), !covering.is_empty());
            prop_assert_eq!(table.is_cdn(ip), covering.iter().any(|r| r.cdn));
            let best = covering.iter().map(|r| r.prefix.prefix_len()).max();
            prop_assert_eq!(
                table.longest(ip).first().map(|r| r.prefix.prefix_len()),
                best
            );
            if let Some(p) = table.which_provider(ip) {
                prop_assert!(covering
                    .iter()
                    .any(|r| Some(r.prefix.prefix_len()) == best && &r.provider == p));
            }
            let lens: Vec<u8> = table.lookup(ip).map(|r| r.prefix.prefix_len()).collect();
            prop_assert!(lens.windows(2).all(|w| w[0] >= w[1]));
            let mut distinct: Vec<&Range> = Vec::new();
            for r in covering {
                if !distinct.contains(&r) {
                    distinct.push(r);
                }
            }
            prop_assert_eq!(table.lookup(ip).count(), distinct.len());
        }
    }

    #[test]
    fn parsers_never_panic(text in "\\PC{0,200}") {
        let _ = parse_aws(&text);
        let _ = parse_google(&text);
        let _ = parse_azure(&text);
        let _ = parse_fastly(&text);
        let _ = parse_oracle(&text);
        let _ = parse_digitalocean(&text);
        let _ = parse_cidr_list(&text, &Provider::Akamai);
    }

    #[test]
    fn cidr_lists_round_trip(ranges in prop::collection::vec(range(), 0..20)) {
        let text = ranges.iter().map(|r| r.prefix.to_string()).collect::<Vec<_>>().join("\n");
        let parsed = parse_cidr_list(&text, &Provider::Fastly).unwrap();
        let prefixes: Vec<Cidr> = parsed.ranges.iter().map(|r| r.prefix).collect();
        let want: Vec<Cidr> = ranges.iter().map(|r| r.prefix).collect();
        prop_assert_eq!(prefixes, want);
        prop_assert!(parsed.ranges.iter().all(|r| r.cdn));
    }
}
