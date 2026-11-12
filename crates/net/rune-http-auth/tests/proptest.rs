//! Property tests: round trips and no panics on arbitrary input.

#![allow(clippy::unwrap_used, reason = "test helpers")]

use proptest::prelude::*;
use rune_http_auth::{
    AuthenticateMessage, AvPair, BasicCredentials, Challenge, ChallengeMessage, DigestAlgorithm,
    DigestChallenge, DigestRequest, DigestResponse, NegotiateFlags, NtlmCredentials, NtlmMessage,
    NtlmScheme, Qop, authenticate, bearer, constant_time_eq, parse_bearer,
};

fn token() -> impl Strategy<Value = String> {
    "[A-Za-z0-9!#$%&'*+.^_`|~-]{1,10}"
}

/// Text a quoted string can carry.
fn text() -> impl Strategy<Value = String> {
    "[ -~\u{a0}-\u{17f}]{0,16}"
}

fn algorithm() -> impl Strategy<Value = DigestAlgorithm> {
    prop_oneof![
        Just(DigestAlgorithm::Md5),
        Just(DigestAlgorithm::Md5Sess),
        Just(DigestAlgorithm::Sha256),
        Just(DigestAlgorithm::Sha256Sess),
        Just(DigestAlgorithm::Sha512_256),
        Just(DigestAlgorithm::Sha512_256Sess),
    ]
}

proptest! {
    #[test]
    fn basic_round_trips(user in "[^:\\p{Cc}]{0,12}", pass in "[^\\p{Cc}]{0,12}") {
        let creds = BasicCredentials::new(user, pass).unwrap();
        let header = creds.to_string();
        prop_assert!(creds.verify(&header));
        prop_assert_eq!(BasicCredentials::parse(&header).unwrap(), creds);
    }

    #[test]
    fn bearer_round_trips(token in "[A-Za-z0-9._~+/-]{1,20}={0,2}") {
        prop_assert_eq!(parse_bearer(&bearer(&token).unwrap()).unwrap(), token);
    }

    #[test]
    fn constant_time_eq_matches_eq(a in prop::collection::vec(any::<u8>(), 0..8),
                                   b in prop::collection::vec(any::<u8>(), 0..8)) {
        prop_assert_eq!(constant_time_eq(&a, &b), a == b);
    }

    #[test]
    fn challenge_list_round_trips(
        challenges in prop::collection::vec(
            (token(), prop::collection::vec((token(), text()), 1..4)),
            1..4,
        ),
    ) {
        let challenges: Vec<Challenge> = challenges
            .into_iter()
            .map(|(scheme, params)| {
                params
                    .iter()
                    .fold(Challenge::new(scheme), |c, (n, v)| c.with_param(n, v.clone()))
            })
            .collect();
        let header = challenges.iter().map(ToString::to_string).collect::<Vec<_>>().join(", ");
        prop_assert_eq!(Challenge::parse_list(&header).unwrap(), challenges);
    }

    #[test]
    fn digest_respond_parse_verify(
        algorithm in algorithm(),
        auth_int in any::<bool>(),
        userhash in any::<bool>(),
        user in "[^\\p{Cc}]{1,10}",
        password in "[^\\p{Cc}]{0,10}",
        realm in text(),
        nonce in "[A-Za-z0-9+/=]{1,24}",
        body in prop::collection::vec(any::<u8>(), 0..32),
        nc in 1u32..,
    ) {
        let mut challenge = DigestChallenge::new(realm, nonce);
        challenge.algorithm = algorithm;
        challenge.userhash = userhash;
        if auth_int {
            challenge.qop = vec![Qop::AuthInt];
        }
        prop_assert_eq!(&DigestChallenge::parse(&challenge.to_string()).unwrap(), &challenge);
        let request = DigestRequest::new("POST", "/a?b=c").with_body(&body).with_cnonce("xyz").with_nc(nc);
        let response = challenge.respond(&user, &password, &request);
        let parsed = DigestResponse::parse(&response.to_string()).unwrap();
        prop_assert_eq!(&parsed, &response);
        prop_assert!(parsed.verify(&user, &password, "POST", &body));
        let wrong = format!("{password}!");
        prop_assert!(!parsed.verify(&user, &wrong, "POST", &body));
    }

    #[test]
    fn ntlm_authenticate_round_trips(
        domain in "\\PC{0,10}",
        user in "\\PC{0,10}",
        password in "\\PC{0,10}",
        workstation in "\\PC{0,10}",
        server in any::<[u8; 8]>(),
        client in any::<[u8; 8]>(),
        names in prop::collection::vec(("\\PC{0,8}", 1u16..6), 0..4),
    ) {
        let mut challenge = ChallengeMessage::new(
            NegotiateFlags::CLIENT_DEFAULT | NegotiateFlags::TARGET_INFO,
            server,
        );
        challenge.target_info = names.iter().map(|(n, id)| AvPair::text(*id, n)).collect();
        let message = NtlmMessage::Challenge(challenge.clone());
        prop_assert_eq!(NtlmMessage::decode(&message.encode().unwrap()).unwrap(), message);

        let creds = NtlmCredentials::new(domain, user, password);
        let auth: AuthenticateMessage = authenticate(&challenge, &creds, &workstation, client, 7);
        let message = NtlmMessage::Authenticate(auth);
        let header = message.to_header(NtlmScheme::Negotiate).unwrap();
        prop_assert_eq!(NtlmMessage::from_header(&header).unwrap(), (NtlmScheme::Negotiate, message));
    }

    #[test]
    fn ntlm_decode_never_panics(message_type in 0u32..5, rest in prop::collection::vec(any::<u8>(), 0..128)) {
        let mut bytes = b"NTLMSSP\0".to_vec();
        bytes.extend_from_slice(&message_type.to_le_bytes());
        bytes.extend_from_slice(&rest);
        if let Ok(message) = NtlmMessage::decode(&bytes) {
            // Whatever decodes re-encodes (lossy fields aside) without error.
            let _ = message.encode();
        }
    }

    #[test]
    fn parsers_never_panic(text in any::<String>()) {
        let _ = Challenge::parse_list(&text);
        let _ = BasicCredentials::parse(&text);
        let _ = parse_bearer(&text);
        let _ = DigestChallenge::parse(&text);
        let _ = DigestResponse::parse(&text);
        let _ = NtlmMessage::from_header(&text);
    }
}
