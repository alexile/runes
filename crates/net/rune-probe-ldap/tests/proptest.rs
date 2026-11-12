//! The codec round-trips, and the decoder and probe sessions never panic
//! on arbitrary server bytes.

use proptest::prelude::*;
use rune_probe_ldap::{
    Attribute, BindAuth, BindRequest, LdapAnonymousProbe, LdapProbe, LdapResult, Message, Op,
    ResultCode, Scope, SearchEntry, SearchRequest, parse_message,
};
use rune_service_probe::{Options, ServiceProbe, Target, simulate};

fn result() -> impl Strategy<Value = LdapResult> {
    (any::<i64>(), ".{0,40}")
        .prop_map(|(code, diag)| LdapResult::new(ResultCode(code)).with_diagnostic(diag))
}

fn op() -> impl Strategy<Value = Op> {
    prop_oneof![
        (
            any::<i64>(),
            ".{0,30}",
            proptest::collection::vec(any::<u8>(), 0..20)
        )
            .prop_map(|(version, name, pw)| {
                let mut bind = BindRequest::anonymous();
                bind.version = version;
                bind.name = name;
                bind.auth = BindAuth::Simple(pw);
                Op::BindRequest(bind)
            }),
        ".{0,20}".prop_map(|mech| {
            let mut bind = BindRequest::anonymous();
            bind.auth = BindAuth::Sasl(mech);
            Op::BindRequest(bind)
        }),
        result().prop_map(Op::BindResponse),
        Just(Op::UnbindRequest),
        (
            ".{0,40}",
            0i64..3,
            any::<i64>(),
            proptest::collection::vec("[a-zA-Z0-9.;-]{0,20}", 0..6)
        )
            .prop_map(|(base, scope, limit, attrs)| {
                let scope = [Scope::Base, Scope::OneLevel, Scope::Subtree]
                    [usize::try_from(scope).unwrap_or(0)];
                Op::SearchRequest(
                    SearchRequest::new(base, scope)
                        .with_size_limit(limit)
                        .with_attributes(attrs),
                )
            }),
        (
            ".{0,40}",
            proptest::collection::vec(
                (
                    "[a-zA-Z;-]{1,20}",
                    proptest::collection::vec(proptest::collection::vec(any::<u8>(), 0..300), 0..4)
                ),
                0..6
            )
        )
            .prop_map(|(dn, attrs)| {
                Op::SearchResultEntry(SearchEntry::new(
                    dn,
                    attrs
                        .into_iter()
                        .map(|(n, v)| Attribute::new(n, v))
                        .collect(),
                ))
            }),
        result().prop_map(Op::SearchResultDone),
        proptest::collection::vec(".{0,30}", 0..4).prop_map(Op::SearchResultReference),
        (
            result(),
            proptest::option::of(".{0,20}"),
            proptest::option::of(proptest::collection::vec(any::<u8>(), 0..20))
        )
            .prop_map(|(result, name, value)| Op::ExtendedResponse {
                result,
                name,
                value
            }),
    ]
}

proptest! {
    #[test]
    fn messages_round_trip(id in any::<i64>(), op in op()) {
        let msg = Message::new(id, op);
        let bytes = msg.encode();
        prop_assert_eq!(Message::decode(&bytes).unwrap(), msg);
        // Every strict prefix is truncated, never malformed or panicking.
        for cut in [0, 1, bytes.len() / 2, bytes.len() - 1] {
            prop_assert!(parse_message(&bytes[..cut]).unwrap_err().is_truncated());
        }
    }

    #[test]
    fn decoder_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..512)) {
        let _ = parse_message(&bytes);
        let _ = Message::decode(&bytes);
    }

    #[test]
    fn sessions_survive_arbitrary_replies(
        replies in proptest::collection::vec(proptest::collection::vec(any::<u8>(), 0..128), 0..8),
        max_read in 1usize..1024,
    ) {
        let replies: Vec<&[u8]> = replies.iter().map(Vec::as_slice).collect();
        let options = Options::default().with_max_read_bytes(max_read).with_allow_intrusive(true);
        let target = Target::new("fuzz", 389);
        let probes: [&dyn ServiceProbe; 2] = [&LdapProbe::new(), &LdapAnonymousProbe::new()];
        for probe in probes {
            let sim = simulate(probe, &target, &replies, &options).unwrap();
            prop_assert!(sim.sent.len() <= 4);
            if let Ok(info) = sim.result {
                prop_assert_eq!(info.service, probe.id());
                for value in info.details.values() {
                    prop_assert!(value.len() <= 32 * 4 * 256 + 64);
                }
            }
        }
    }
}
