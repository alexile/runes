//! The text parsers and the response check never panic on hostile input.

#![allow(clippy::unwrap_used, reason = "test code")]

use proptest::prelude::*;
use rune_dns_resolver::{
    DohEndpoint, Lookup, ResolverOptions, Upstream, build_query, check_response, parse_resolv_conf,
};
use std::net::Ipv4Addr;

use rune_dns_wire::{Message, Name, Question, RData, Record, RecordType};

proptest! {
    #[test]
    fn upstream_text_never_panics(text in "\\PC{0,64}") {
        let _ = text.parse::<Upstream>();
        let _ = DohEndpoint::parse(&text);
        if let Ok(endpoint) = DohEndpoint::parse(&format!("https://{text}")) {
            let _ = (endpoint.url(), endpoint.authority());
        }
    }

    #[test]
    fn resolv_conf_never_panics(text in "(nameserver [0-9a-f:.%]{0,40}[ #;\\n]{0,3}|\\PC{0,20}\\n){0,8}") {
        for upstream in parse_resolv_conf(&text) {
            prop_assert!(matches!(upstream, Upstream::Udp(_)));
        }
    }

    #[test]
    fn any_decodable_response_is_checked_without_panicking(
        id in any::<u16>(),
        edits in proptest::collection::vec((any::<usize>(), any::<u8>()), 0..6),
    ) {
        // Corrupt a real answer, so the header and question checks see
        // near-misses rather than noise.
        let question = Question::new(Name::from_ascii("www.example.com").unwrap(), RecordType::A);
        let query = build_query(id, question.clone(), &ResolverOptions::default());
        let mut bytes = Message::response_to(&query)
            .with_answer(Record::new(
                question.name.clone(),
                60,
                RData::Cname(Name::from_ascii("www.example.com").unwrap()),
            ))
            .with_answer(Record::new(
                question.name.clone(),
                60,
                RData::A(Ipv4Addr::LOCALHOST),
            ))
            .encode()
            .unwrap();
        for (at, byte) in edits {
            let at = at % bytes.len();
            bytes[at] = byte;
        }
        if let Ok(response) = Message::decode(&bytes) {
            if check_response(&query, &response).is_ok() {
                prop_assert_eq!(response.header.id, id);
            }
            let lookup = Lookup::new(question, response).with_max_cname_chain(usize::MAX);
            let _ = (lookup.ipv4(), lookup.names(), lookup.cname_chain(), lookup.min_ttl());
        }
    }
}
