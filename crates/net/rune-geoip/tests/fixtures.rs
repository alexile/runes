//! Known-answer tests over databases assembled byte by byte from the
//! specification (independently of this crate's `Writer`), plus typed
//! record tests over a GeoLite2-shaped fixture.

#![allow(
    clippy::unwrap_used,
    clippy::cast_possible_truncation,
    reason = "test helpers"
)]

use std::collections::BTreeMap;
use std::net::IpAddr;

use rune_cidr::Cidr;
use rune_geoip::{Error, Reader, Value, Writer};

const MARKER: &[u8] = b"\xab\xcd\xefMaxMind.com";

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

/// A hand-encoded metadata map.
fn metadata(node_count: u32, record_size: u8, ip_version: u8) -> Vec<u8> {
    let mut m = vec![0xe5];
    m.extend_from_slice(b"\x4anode_count\xc4");
    m.extend_from_slice(&node_count.to_be_bytes());
    m.extend_from_slice(b"\x4brecord_size\xa1");
    m.push(record_size);
    m.extend_from_slice(b"\x4aip_version\xa1");
    m.push(ip_version);
    m.extend_from_slice(b"\x5bbinary_format_major_version\xa1\x02");
    m.extend_from_slice(b"\x4ddatabase_type\x44Test");
    m
}

/// Encodes nodes by the layouts in the spec ("Search Tree Section").
fn tree(record_size: u8, nodes: &[(u32, u32)]) -> Vec<u8> {
    let mut out = Vec::new();
    for &(l, r) in nodes {
        match record_size {
            24 => {
                out.extend_from_slice(&l.to_be_bytes()[1..]);
                out.extend_from_slice(&r.to_be_bytes()[1..]);
            }
            28 => {
                out.extend_from_slice(&l.to_be_bytes()[1..]);
                out.push(((l >> 24) as u8) << 4 | (r >> 24) as u8);
                out.extend_from_slice(&r.to_be_bytes()[1..]);
            }
            _ => {
                out.extend_from_slice(&l.to_be_bytes());
                out.extend_from_slice(&r.to_be_bytes());
            }
        }
    }
    out
}

fn database(record_size: u8, ip_version: u8, nodes: &[(u32, u32)], data: &[u8]) -> Vec<u8> {
    let mut db = tree(record_size, nodes);
    db.extend_from_slice(&[0; 16]);
    db.extend_from_slice(data);
    db.extend_from_slice(MARKER);
    db.extend(metadata(
        u32::try_from(nodes.len()).unwrap(),
        record_size,
        ip_version,
    ));
    db
}

/// IPv4 tree: 0.0.0.0/2 → {"a": 1}, 64.0.0.0/2 → "b", 128.0.0.0/1 empty.
fn small_v4(record_size: u8) -> Vec<u8> {
    // node_count 2: data offset d is record 2 + 16 + d; 2 is "no data".
    let data = b"\xe1\x41a\xa1\x01\x41b";
    database(record_size, 4, &[(1, 2), (18, 23)], data)
}

#[test]
fn reads_hand_built_ipv4_trees() {
    for record_size in [24, 28, 32] {
        let reader = Reader::from_source(small_v4(record_size)).unwrap();
        let m = reader.metadata();
        assert_eq!(
            (m.node_count, m.record_size, m.ip_version),
            (2, record_size.into(), 4)
        );
        assert_eq!(m.database_type, "Test");

        let a = reader.lookup(ip("1.2.3.4")).unwrap().unwrap();
        assert_eq!(a.network, Cidr::V4(0, 2));
        assert_eq!(a.data.get("a"), Some(&Value::Uint16(1)));
        let b = reader.lookup(ip("127.255.255.255")).unwrap().unwrap();
        assert_eq!(b.network.to_string(), "64.0.0.0/2");
        assert_eq!(b.data, Value::from("b"));
        assert_eq!(reader.lookup(ip("200.0.0.1")), Ok(None));
        // Mapped IPv6 is unwrapped; real IPv6 is an error.
        assert_eq!(
            reader.lookup(ip("::ffff:100.0.0.1")).unwrap().unwrap().data,
            Value::from("b")
        );
        assert!(matches!(
            reader.lookup(ip("2001:db8::1")),
            Err(Error::Ipv6InIpv4Database(_))
        ));

        let networks: Vec<String> = reader
            .networks()
            .map(|e| e.unwrap().network.to_string())
            .collect();
        assert_eq!(networks, ["0.0.0.0/2", "64.0.0.0/2"]);
    }
}

#[test]
fn reads_28_and_32_bit_records_above_24_bits() {
    // The second value sits past 2^24 bytes into the data section, so its
    // record needs the high nibble (28-bit) or high byte (32-bit).
    let far = 0x0100_0005usize;
    let mut data = vec![0u8; far];
    data[..2].copy_from_slice(b"\x41a");
    data.extend_from_slice(b"\x43far");
    let far_record = u32::try_from(2 + 16 + far).unwrap();
    for record_size in [28, 32] {
        let db = database(record_size, 4, &[(1, 2), (18, far_record)], &data);
        let reader = Reader::from_source(db).unwrap();
        assert_eq!(
            reader.lookup(ip("64.0.0.0")).unwrap().unwrap().data,
            Value::from("far")
        );
        assert_eq!(
            reader.lookup(ip("0.0.0.1")).unwrap().unwrap().data,
            Value::from("a")
        );
    }
}

#[test]
fn ipv4_in_ipv6_tree_and_aliases() {
    // Nodes 0..96 walk ::/96 (left records); node 96 is the IPv4 root:
    // 0.0.0.0/1 → "A", 128.0.0.0/1 → "B". Node 0's right record aliases
    // 8000::/1 to the IPv4 root, as MaxMind does for ::ffff:0:0/96.
    let count = 97u32;
    let empty = count;
    let mut nodes: Vec<(u32, u32)> = (0..96).map(|i| (i + 1, empty)).collect();
    nodes[0].1 = 96;
    nodes.push((count + 16, count + 16 + 2));
    let reader = Reader::from_source(database(24, 6, &nodes, b"\x41A\x41B")).unwrap();

    let hit = reader.lookup(ip("10.0.0.1")).unwrap().unwrap();
    assert_eq!((hit.network, hit.data), (Cidr::V4(0, 1), Value::from("A")));
    let hit = reader.lookup(ip("::200.0.0.1")).unwrap().unwrap();
    assert_eq!(
        (hit.network, hit.data),
        (Cidr::V4(0x8000_0000, 1), Value::from("B"))
    );
    // Through the alias.
    let hit = reader.lookup(ip("8000::1")).unwrap().unwrap();
    assert_eq!(hit.network.to_string(), "8000::/2");
    assert_eq!(reader.lookup(ip("2001:db8::")), Ok(None));

    // The aliased subtree is listed once, as IPv4.
    let networks: Vec<String> = reader
        .networks()
        .map(|e| e.unwrap().network.to_string())
        .collect();
    assert_eq!(networks, ["0.0.0.0/1", "128.0.0.0/1"]);
}

#[test]
fn rejects_corrupt_files() {
    assert_eq!(
        Reader::from_source(b"not a database".as_slice()).err(),
        Some(Error::MissingMetadata)
    );

    // Tree larger than the file.
    let mut db = small_v4(24);
    let at = db.windows(11).position(|w| w == b"node_count\xc4").unwrap() + 11;
    db[at..at + 4].copy_from_slice(&1000u32.to_be_bytes());
    assert!(matches!(
        Reader::from_source(&db),
        Err(Error::InvalidTree(_))
    ));

    // Record into the separator, and past the data section.
    for bad in [5u32, 500] {
        let db = database(24, 4, &[(1, 2), (bad, 2)], b"\x41a");
        let reader = Reader::from_source(db).unwrap();
        assert!(matches!(
            reader.lookup(ip("0.0.0.0")),
            Err(Error::InvalidTree(_))
        ));
        assert!(reader.networks().last().unwrap().is_err());
    }

    // A cycle: node 1 points back to node 0 on every bit.
    let db = database(24, 4, &[(1, 1), (0, 0)], b"");
    let reader = Reader::from_source(db).unwrap();
    assert!(matches!(
        reader.lookup(ip("1.2.3.4")),
        Err(Error::InvalidTree(_))
    ));
    let items: Vec<_> = reader.networks().collect();
    assert_eq!(items.len(), 1);
    assert!(items[0].is_err());

    // Wrong format version, bad record size.
    let mut db = small_v4(24);
    let pos = db
        .windows(28)
        .position(|w| &w[1..] == b"binary_format_major_version")
        .unwrap();
    db[pos + 29] = 3;
    assert_eq!(
        Reader::from_source(&db).err(),
        Some(Error::UnsupportedVersion(3))
    );
    let db = database(24, 4, &[(1, 2), (18, 2)], b"\x41a");
    let mut db2 = db;
    let pos = db2.windows(11).position(|w| w == b"record_size").unwrap();
    db2[pos + 12] = 20;
    assert_eq!(
        Reader::from_source(&db2).err(),
        Some(Error::InvalidMetadata("record_size"))
    );
}

fn map(pairs: &[(&str, Value)]) -> Value {
    Value::Map(
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), v.clone()))
            .collect::<BTreeMap<_, _>>(),
    )
}

fn names(en: &str, de: &str) -> Value {
    map(&[("en", Value::from(en)), ("de", Value::from(de))])
}

/// A GeoLite2-City-shaped record (fields as in `MaxMind`'s test data).
fn london() -> Value {
    map(&[
        (
            "city",
            map(&[
                ("geoname_id", Value::Uint32(2_643_743)),
                ("names", names("London", "London")),
            ]),
        ),
        (
            "continent",
            map(&[
                ("code", Value::from("EU")),
                ("geoname_id", Value::Uint32(6_255_148)),
                ("names", names("Europe", "Europa")),
            ]),
        ),
        (
            "country",
            map(&[
                ("geoname_id", Value::Uint32(2_635_167)),
                ("iso_code", Value::from("GB")),
                ("is_in_european_union", Value::Bool(false)),
                ("names", names("United Kingdom", "Vereinigtes Königreich")),
            ]),
        ),
        (
            "location",
            map(&[
                ("accuracy_radius", Value::Uint16(100)),
                ("latitude", Value::Double(51.5142)),
                ("longitude", Value::Double(-0.0931)),
                ("time_zone", Value::from("Europe/London")),
            ]),
        ),
        ("postal", map(&[("code", Value::from("EC2V"))])),
        (
            "registered_country",
            map(&[
                ("geoname_id", Value::Uint32(6_252_001)),
                ("iso_code", Value::from("US")),
            ]),
        ),
        (
            "subdivisions",
            Value::Array(vec![map(&[
                ("geoname_id", Value::Uint32(6_269_131)),
                ("iso_code", Value::from("ENG")),
                ("names", names("England", "England")),
            ])]),
        ),
        ("traits", map(&[("is_anycast", Value::Bool(true))])),
    ])
}

#[test]
fn typed_city_country_and_asn_records() {
    let mut writer = Writer::new("GeoLite2-City", 6)
        .with_languages(["de", "en"])
        .with_description("en", "test fixture")
        .with_build_epoch(1_700_000_000)
        .with_record_size(24);
    writer
        .insert("81.2.69.0/24".parse().unwrap(), &london())
        .unwrap();
    writer
        .insert(
            "2001:db8::/32".parse().unwrap(),
            &map(&[
                ("autonomous_system_number", Value::Uint32(64_496)),
                ("autonomous_system_organization", Value::from("Example AS")),
            ]),
        )
        .unwrap();
    let reader = Reader::from_source(writer.to_bytes().unwrap()).unwrap();
    let m = reader.metadata();
    assert_eq!(m.languages, ["de", "en"]);
    assert_eq!(
        m.description.get("en").map(String::as_str),
        Some("test fixture")
    );
    assert_eq!(m.build_epoch, 1_700_000_000);

    let city = reader.city(ip("81.2.69.142")).unwrap().unwrap();
    assert_eq!(city.city.names.preferred(&["fr", "de"]), Some("London"));
    assert_eq!(city.city.geoname_id, Some(2_643_743));
    assert_eq!(city.country.iso_code.as_deref(), Some("GB"));
    assert_eq!(city.country.names.get("de"), Some("Vereinigtes Königreich"));
    assert!(!city.country.is_in_european_union);
    assert_eq!(city.registered_country.iso_code.as_deref(), Some("US"));
    assert_eq!(city.continent.code.as_deref(), Some("EU"));
    assert_eq!(city.subdivisions[0].iso_code.as_deref(), Some("ENG"));
    assert_eq!(city.postal_code.as_deref(), Some("EC2V"));
    assert_eq!(city.location.latitude, Some(51.5142));
    assert_eq!(city.location.accuracy_radius, Some(100));
    assert_eq!(city.location.time_zone.as_deref(), Some("Europe/London"));
    assert!(city.traits.is_anycast);
    assert_eq!(city.represented_country, None);

    let country = reader.country(ip("81.2.69.1")).unwrap().unwrap();
    assert_eq!(country.country, city.country);

    let asn = reader.asn(ip("2001:db8:1::1")).unwrap().unwrap();
    assert_eq!(asn.autonomous_system_number, Some(64_496));
    assert_eq!(
        asn.autonomous_system_organization.as_deref(),
        Some("Example AS")
    );
    // A record of another shape reads as empty, not as an error.
    let not_asn = reader.asn(ip("81.2.69.1")).unwrap().unwrap();
    assert_eq!(not_asn.autonomous_system_number, None);
    assert_eq!(reader.city(ip("192.0.2.1")), Ok(None));
}

#[test]
fn writer_rejects_ipv6_in_ipv4_database_and_handles_slash_zero() {
    let mut writer = Writer::new("v4", 4);
    assert!(matches!(
        writer.insert("::/0".parse().unwrap(), &Value::Bool(true)),
        Err(Error::Build(_))
    ));
    writer
        .insert("0.0.0.0/0".parse().unwrap(), &Value::from("all"))
        .unwrap();
    let reader = Reader::from_source(writer.to_bytes().unwrap()).unwrap();
    let hit = reader.lookup(ip("203.0.113.9")).unwrap().unwrap();
    assert_eq!(hit.data, Value::from("all"));
    assert_eq!(hit.network.prefix_len(), 1);

    let empty = Reader::from_source(Writer::new("empty", 6).to_bytes().unwrap()).unwrap();
    assert_eq!(empty.lookup(ip("1.1.1.1")), Ok(None));
    assert_eq!(empty.lookup(ip("2001:db8::")), Ok(None));
    assert_eq!(empty.networks().count(), 0);
}
