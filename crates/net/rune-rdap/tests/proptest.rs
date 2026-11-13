//! Properties: query text round-trips, and no parser panics on arbitrary
//! input.
#![allow(
    clippy::unwrap_used,
    reason = "test helpers outside #[test] fns: any failure fails the test"
)]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use proptest::prelude::*;
use rune_rdap::bootstrap::{Registry, RegistryKind};
use rune_rdap::response::{Response, interpret};
use rune_rdap::{Contact, Query, parse_object};

fn query() -> impl Strategy<Value = Query> {
    prop_oneof![
        any::<u32>().prop_map(Query::Autnum),
        any::<u32>().prop_map(|v| Query::Ip(IpAddr::V4(Ipv4Addr::from(v)))),
        any::<u128>().prop_map(|v| Query::Ip(IpAddr::V6(Ipv6Addr::from(v)))),
        (any::<u32>(), 0u8..=32)
            .prop_map(|(v, p)| Query::network(IpAddr::V4(v.into()), p).unwrap()),
        (any::<u128>(), 0u8..=128)
            .prop_map(|(v, p)| Query::network(IpAddr::V6(v.into()), p).unwrap()),
        "[a-z][a-z0-9]{0,20}(\\.[a-z][a-z0-9]{0,10}){1,3}".prop_map(|d| Query::domain(&d).unwrap()),
        "[A-Z0-9]{1,10}-[A-Z]{2,6}".prop_map(|h| Query::entity(&h).unwrap()),
    ]
}

proptest! {
    #[test]
    fn query_text_round_trips(q in query()) {
        prop_assert_eq!(Query::parse(&q.to_string()).unwrap(), q);
    }

    #[test]
    fn query_parse_never_panics(s in "\\PC{0,64}") {
        if let Ok(q) = Query::parse(&s) {
            let _ = q.path();
        }
    }

    #[test]
    fn parsers_never_panic(body in proptest::collection::vec(any::<u8>(), 0..512), status in 100u16..600) {
        let _ = parse_object(&body);
        let _ = interpret(&Response::new(status, body.clone()).with_header("Location", "/x"));
        for kind in RegistryKind::ALL {
            let _ = Registry::parse(kind, &body);
        }
    }

    #[test]
    fn json_shaped_input_never_panics(
        class in prop_oneof![Just("domain"), Just("ip network"), Just("autnum"), Just("nameserver"), Just("entity")],
        filler in "[\\[\\]{}\",:a-zA-Z0-9 ]{0,200}",
    ) {
        let body = format!(r#"{{"objectClassName":"{class}","entities":[{filler}],"vcardArray":["vcard",[{filler}]]}}"#);
        let _ = parse_object(body.as_bytes());
        if let Ok(v) = serde_json::from_str(&format!("[\"vcard\",[{filler}]]")) {
            let _ = Contact::from_jcard(&v);
        }
    }
}

const SEEDS: [&[u8]; 6] = [
    include_bytes!("fixtures/autnum-arin-15169.json"),
    include_bytes!("fixtures/domain-example.com.json"),
    include_bytes!("fixtures/error-arin-400.json"),
    include_bytes!("fixtures/ip-arin-8.8.8.8.json"),
    include_bytes!("fixtures/ip-ripe-193.0.6.139.json"),
    include_bytes!("fixtures/nameserver-a.iana-servers.net.json"),
];

const BOOTSTRAP: [(RegistryKind, &[u8]); 5] = [
    (
        RegistryKind::Asn,
        include_bytes!("fixtures/bootstrap-asn.json"),
    ),
    (
        RegistryKind::Dns,
        include_bytes!("fixtures/bootstrap-dns.json"),
    ),
    (
        RegistryKind::Ipv4,
        include_bytes!("fixtures/bootstrap-ipv4.json"),
    ),
    (
        RegistryKind::Ipv6,
        include_bytes!("fixtures/bootstrap-ipv6.json"),
    ),
    (
        RegistryKind::ObjectTags,
        include_bytes!("fixtures/bootstrap-object-tags.json"),
    ),
];

fn mutate(seed: &[u8], edits: &[(prop::sample::Index, u8)]) -> Vec<u8> {
    let mut bytes = seed.to_vec();
    for (at, byte) in edits {
        let i = at.index(bytes.len());
        bytes[i] = *byte;
    }
    bytes
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(128))]

    /// Real responses with a few bytes changed, read through every accessor.
    #[test]
    fn mutated_responses_never_panic(
        which in any::<prop::sample::Index>(),
        edits in proptest::collection::vec((any::<prop::sample::Index>(), any::<u8>()), 1..6),
    ) {
        let body = mutate(SEEDS[which.index(SEEDS.len())], &edits);
        if let Ok(object) = parse_object(&body) {
            let _ = (object.handle(), object.events().len(), object.status().len());
            let _ = object.entities().len();
            if let Some(domain) = object.as_domain() {
                let _ = (domain.name(), domain.nameserver_names().count(), domain.registrar_name());
                let _ = (domain.registrar_iana_id(), domain.registration(), domain.expiration());
                let _ = (domain.abuse_email(), domain.all_entities().len(), domain.last_changed());
            }
            if let Some(network) = object.as_ip_network() {
                let _ = (network.abuse_email(), network.all_entities().len());
            }
        }
        let _ = interpret(&Response::new(400, body));
    }

    /// Bootstrap files with a few bytes changed, then looked up.
    #[test]
    fn mutated_bootstrap_never_panics(
        which in 0usize..5,
        edits in proptest::collection::vec((any::<prop::sample::Index>(), any::<u8>()), 1..6),
        q in query(),
    ) {
        let (kind, seed) = BOOTSTRAP[which];
        if let Ok(registry) = Registry::parse(kind, &mutate(seed, &edits)) {
            let _ = registry.lookup(&q);
        }
    }
}
