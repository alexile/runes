//! Property tests: writing a zone and parsing it back gives the same
//! records, and the parsers never panic.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "helpers outside #[test] functions fail the test on bad input"
)]

use std::net::{Ipv4Addr, Ipv6Addr};

use proptest::prelude::*;
use rune_dns_wire::{Caa, Class, Dnskey, Ds, Mx, Name, RData, Record, RecordType, Soa, Srv};
use rune_dns_zone::{Axfr, Ixfr, ParseOptions, TcpFrames, Zone, parse};

fn label() -> impl Strategy<Value = Vec<u8>> {
    prop_oneof![
        3 => "[a-zA-Z0-9-]{1,12}".prop_map(String::into_bytes),
        1 => proptest::collection::vec(any::<u8>(), 1..8),
    ]
}

fn name() -> impl Strategy<Value = Name> {
    proptest::collection::vec(label(), 0..4)
        .prop_map(|labels| Name::from_labels(labels).unwrap_or_else(|_| Name::root()))
}

fn under(origin: Name) -> impl Strategy<Value = Name> {
    proptest::collection::vec(label(), 0..3).prop_map(move |labels| {
        Name::from_labels(labels.iter().map(Vec::as_slice).chain(origin.labels()))
            .unwrap_or_else(|_| origin.clone())
    })
}

const fn opaque(rtype: u16, data: Vec<u8>) -> RData {
    RData::Unknown {
        rtype: RecordType(rtype),
        data,
    }
}

fn string() -> impl Strategy<Value = Vec<u8>> {
    proptest::collection::vec(any::<u8>(), 0..40)
}

fn rdata() -> impl Strategy<Value = RData> {
    prop_oneof![
        any::<u32>().prop_map(|ip| RData::A(Ipv4Addr::from(ip))),
        any::<u128>().prop_map(|ip| RData::Aaaa(Ipv6Addr::from(ip))),
        name().prop_map(RData::Ns),
        name().prop_map(RData::Cname),
        (any::<u16>(), name()).prop_map(|(preference, exchange)| RData::Mx(Mx {
            preference,
            exchange
        })),
        proptest::collection::vec(string(), 0..4).prop_map(RData::Txt),
        (name(), name(), any::<[u32; 5]>()).prop_map(|(mname, rname, n)| RData::Soa(Soa {
            mname,
            rname,
            serial: n[0],
            refresh: n[1],
            retry: n[2],
            expire: n[3],
            minimum: n[4],
        })),
        (any::<[u16; 3]>(), name()).prop_map(|(n, target)| RData::Srv(Srv {
            priority: n[0],
            weight: n[1],
            port: n[2],
            target,
        })),
        (any::<u8>(), "[a-z0-9]{1,15}", string())
            .prop_map(|(flags, tag, value)| { RData::Caa(Caa { flags, tag, value }) }),
        (any::<u16>(), any::<u8>(), any::<u8>(), string()).prop_map(|(key_tag, a, d, digest)| {
            RData::Ds(Ds {
                key_tag,
                algorithm: a,
                digest_type: d,
                digest,
            })
        }),
        (any::<u16>(), any::<u8>(), string()).prop_map(|(flags, algorithm, public_key)| {
            RData::Dnskey(Dnskey {
                flags,
                protocol: 3,
                algorithm,
                public_key,
            })
        }),
        (string(), string()).prop_map(|(cpu, os)| {
            let mut data = vec![u8::try_from(cpu.len()).unwrap_or(0)];
            data.extend(&cpu);
            data.push(u8::try_from(os.len()).unwrap_or(0));
            data.extend(&os);
            opaque(13, data)
        }),
        (any::<u16>(), name()).prop_map(|(subtype, host)| {
            let mut data = subtype.to_be_bytes().to_vec();
            data.extend(host.as_wire());
            opaque(18, data)
        }),
        (name(), proptest::collection::vec(any::<u16>(), 0..6)).prop_map(|(next, types)| {
            let mut data = next.as_wire().to_vec();
            // Encode a canonical bitmap by hand.
            let mut types = types;
            types.sort_unstable();
            types.dedup();
            let mut windows = std::collections::BTreeMap::<u8, [u8; 32]>::new();
            for t in types {
                let [window, low] = t.to_be_bytes();
                windows.entry(window).or_insert([0; 32])[usize::from(low / 8)] |= 0x80 >> (low % 8);
            }
            for (window, bits) in windows {
                let len = bits.iter().rposition(|&b| b != 0).map_or(0, |i| i + 1);
                data.push(window);
                data.push(u8::try_from(len).unwrap_or(0));
                data.extend(&bits[..len]);
            }
            opaque(47, data)
        }),
        (any::<u16>(), proptest::collection::vec(any::<u8>(), 0..20))
            .prop_map(|(rtype, data)| opaque(rtype.max(65_280), data)),
        // Any bytes under a type with a presentation format: written either
        // in that format or, when they do not fit it, in the `\#` form.
        (
            prop::sample::select(vec![13u16, 17, 29, 35, 37, 44, 47, 50, 51, 99, 256]),
            proptest::collection::vec(any::<u8>(), 0..24),
        )
            .prop_map(|(rtype, data)| opaque(rtype, data)),
    ]
}

fn zone() -> impl Strategy<Value = Zone> {
    let origin = name().prop_filter("non-root", |n| !n.is_root());
    origin.prop_flat_map(|origin| {
        let soa = (any::<u32>(), name(), name()).prop_map({
            let origin = origin.clone();
            move |(serial, mname, rname)| {
                Record::new(
                    origin.clone(),
                    3600,
                    RData::Soa(Soa {
                        mname,
                        rname,
                        serial,
                        refresh: 1,
                        retry: 2,
                        expire: 3,
                        minimum: 4,
                    }),
                )
            }
        });
        let record = (
            prop_oneof![under(origin), name()],
            any::<u32>(),
            prop::sample::select(vec![Class::IN, Class::CH, Class(9)]),
            rdata(),
        )
            .prop_map(|(owner, ttl, class, data)| Record::new(owner, ttl, data).with_class(class));
        (soa, proptest::collection::vec(record, 0..12)).prop_map(|(soa, records)| {
            let mut all = vec![soa];
            all.extend(records);
            Zone::new(all)
        })
    })
}

proptest! {
    #[test]
    fn write_then_parse_is_identity(zone in zone()) {
        let text = zone.to_master_file();
        let parsed = parse(&text, &ParseOptions::default());
        prop_assert_eq!(parsed.as_ref(), Ok(&zone), "{}", text);
    }

    #[test]
    fn parser_never_panics(text in "\\PC{0,200}") {
        if let Ok(zone) = parse(&text, &ParseOptions::default().with_default_ttl(1)) {
            let again = parse(&zone.to_master_file(), &ParseOptions::default());
            prop_assert_eq!(again, Ok(zone));
        }
    }

    #[test]
    fn zone_like_text_never_panics(
        lines in proptest::collection::vec(
            "(\\$(ORIGIN|TTL|INCLUDE) )?[@a-z0-9.\\\\ ();\"#-]{0,30}( (IN|CH|[0-9]{1,4}[hmsdw]?))? (A|NS|MX|TXT|SOA|LOC|NSEC|CAA|TYPE9) [a-z0-9.\\\\ ()\"#-]{0,30}",
            0..8,
        )
    ) {
        let text = lines.join("\n");
        let _ = parse(&text, &ParseOptions::default().with_origin(Name::root()));
    }

    #[test]
    fn transfers_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..300)) {
        let zone = Name::from_ascii("example.com").unwrap_or_else(|_| Name::root());
        let mut frames = TcpFrames::new();
        frames.push(&bytes);
        let mut axfr = Axfr::new(zone.clone());
        let mut ixfr = Ixfr::new(zone, 1);
        while let Some(frame) = frames.next_frame() {
            let _ = axfr.push_bytes(&frame);
            let _ = ixfr.push_bytes(&frame);
        }
        let _ = axfr.push_bytes(&bytes);
        let _ = ixfr.push_bytes(&bytes);
    }
}
