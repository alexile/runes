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
