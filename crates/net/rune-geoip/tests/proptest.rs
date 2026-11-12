//! Property tests: value encoding round-trips, lookups in a written
//! database agree with a last-insert-wins model, and nothing panics on
//! arbitrary bytes.

#![allow(
    clippy::unwrap_used,
    clippy::cast_possible_truncation,
    reason = "test helpers"
)]

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use proptest::prelude::*;
use rune_cidr::Cidr;
use rune_geoip::{Reader, Value, Writer};

fn value() -> impl Strategy<Value = Value> {
    let leaf = prop_oneof![
        ".{0,40}".prop_map(Value::String),
        any::<f64>()
            .prop_filter("comparable", |n| !n.is_nan())
            .prop_map(Value::Double),
        any::<f32>()
            .prop_filter("comparable", |n| !n.is_nan())
            .prop_map(Value::Float),
        proptest::collection::vec(any::<u8>(), 0..40).prop_map(Value::Bytes),
        any::<u16>().prop_map(Value::Uint16),
        any::<u32>().prop_map(Value::Uint32),
        any::<i32>().prop_map(Value::Int32),
        any::<u64>().prop_map(Value::Uint64),
        any::<u128>().prop_map(Value::Uint128),
        any::<bool>().prop_map(Value::Bool),
    ];
    leaf.prop_recursive(4, 64, 8, |inner| {
        prop_oneof![
            proptest::collection::vec(inner.clone(), 0..8).prop_map(Value::Array),
            proptest::collection::btree_map("[a-z_]{0,12}", inner, 0..8).prop_map(Value::Map),
        ]
    })
}

/// Prefixes clustered in `10.0.0.0/8` and `2001:db8::/32` so they nest.
fn prefix(v6: bool) -> BoxedStrategy<Cidr> {
    let v4 = (0u32..=0xFFFF, 8u8..=32)
        .prop_map(|(low, len)| Cidr::V4(0x0A00_0000 | (low << 8), len).trunc());
    if !v6 {
        return v4.boxed();
    }
    prop_oneof![
        v4,
        (any::<u16>(), 32u8..=64).prop_map(|(x, len)| {
            Cidr::V6((0x2001_0db8_u128 << 96) | (u128::from(x) << 72), len).trunc()
        }),
    ]
    .boxed()
}

fn addr(v6: bool) -> BoxedStrategy<IpAddr> {
    let v4 = (0u32..=0x00FF_FFFF).prop_map(|x| IpAddr::V4(Ipv4Addr::from(0x0A00_0000 | x)));
    if !v6 {
        return v4.boxed();
    }
    prop_oneof![
        v4,
        (any::<u16>(), any::<u64>()).prop_map(|(x, low)| IpAddr::V6(Ipv6Addr::from(
            (0x2001_0db8_u128 << 96) | (u128::from(x) << 72) | u128::from(low)
        ))),
    ]
    .boxed()
}

fn case() -> impl Strategy<Value = (bool, u16, Vec<Cidr>, Vec<IpAddr>)> {
    (any::<bool>(), prop_oneof![Just(24u16), Just(28), Just(32)]).prop_flat_map(|(v6, size)| {
        (
            Just(v6),
            Just(size),
            proptest::collection::vec(prefix(v6), 0..24),
            proptest::collection::vec(addr(v6), 1..24),
        )
    })
}

/// The index of the last inserted prefix containing `ip`.
fn model(prefixes: &[Cidr], ip: IpAddr) -> Option<u32> {
    prefixes
        .iter()
        .rposition(|p| p.contains(ip))
        .map(|i| u32::try_from(i).unwrap())
}

proptest! {
    #[test]
    fn values_round_trip(v in value()) {
        let bytes = v.encode().unwrap();
        prop_assert_eq!(Value::decode(&bytes).unwrap(), v);
    }

    #[test]
    fn decode_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..256)) {
        let _ = Value::decode(&bytes);
    }

    #[test]
    fn reader_never_panics(
        tree in proptest::collection::vec(any::<u8>(), 0..128),
        meta in proptest::collection::vec(any::<u8>(), 0..64),
        probe in any::<u128>(),
    ) {
        // Random bytes around a valid-looking metadata header.
        let mut db = tree;
        db.extend_from_slice(b"\xab\xcd\xefMaxMind.com\xe4");
        db.extend_from_slice(b"\x4anode_count\xc1\x04");
        db.extend_from_slice(b"\x4brecord_size\xa1\x18");
        db.extend_from_slice(b"\x4aip_version\xa1\x06");
        db.extend_from_slice(b"\x5bbinary_format_major_version\xa1\x02");
        db.extend_from_slice(&meta);
        if let Ok(reader) = Reader::from_source(&db) {
            let _ = reader.lookup(IpAddr::V6(Ipv6Addr::from(probe)));
            let _ = reader.lookup(IpAddr::V4(Ipv4Addr::from(probe as u32)));
            let _ = reader.networks().take(64).count();
        }
        let _ = Reader::from_source(&meta);
    }

    #[test]
    fn lookups_match_last_insert_wins((v6, size, prefixes, addrs) in case()) {
        let mut writer = Writer::new("Model", if v6 { 6 } else { 4 }).with_record_size(size);
        for (i, p) in prefixes.iter().enumerate() {
            let data = Value::Map(BTreeMap::from([(
                "i".to_owned(),
                Value::Uint32(u32::try_from(i).unwrap()),
            )]));
            writer.insert(*p, &data).unwrap();
        }
        let reader = Reader::from_source(writer.to_bytes().unwrap()).unwrap();
        let index = |v: &Value| v.get("i").and_then(Value::as_u64).map(|n| u32::try_from(n).unwrap());

        for ip in addrs {
            let want = model(&prefixes, ip);
            let got = reader.lookup(ip).unwrap();
            prop_assert_eq!(got.as_ref().and_then(|e| index(&e.data)), want);
            if let Some(entry) = got {
                prop_assert!(entry.network.contains(ip));
                // The whole network maps to the same record.
                for edge in [entry.network.network(), entry.network.last()] {
                    prop_assert_eq!(model(&prefixes, edge), want);
                }
            }
        }

        // Every listed network is homogeneous; networks are disjoint and
        // in order.
        let mut last_end: Option<IpAddr> = None;
        for entry in reader.networks() {
            let entry = entry.unwrap();
            let want = index(&entry.data);
            prop_assert_eq!(model(&prefixes, entry.network.network()), want);
            prop_assert_eq!(model(&prefixes, entry.network.last()), want);
            if let Some(end) = last_end {
                let same_family = end.is_ipv4() == entry.network.network().is_ipv4();
                prop_assert!(!same_family || end < entry.network.network());
            }
            last_end = Some(entry.network.last());
        }
    }
}
